#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "core/sync.hpp"
#include "flan/fs.hpp"
#include "flan/http.hpp"
#include "flan/validate.hpp"
#include <ctime>
#include <iostream>
#include <set>
#include <vector>

namespace {

	const char* DEFAULT_REPO = "https://raw.githubusercontent.com/muirbil/flan-packages/main";

	// Источник индекса (DESIGN.md §5.1): FLAN_REPO — база, к которой дописывается /index.flan.
	// https:// — база URL; всё остальное — локальный каталог, например клон flan-packages.
	struct IndexSource {
		bool local = false;
		std::string location;							// URL или путь к файлу
	};

	bool resolveIndexSource(IndexSource& source, std::string& error) {
		std::string repo = DEFAULT_REPO;

		char buffer[2048];
		const DWORD length = GetEnvironmentVariableA("FLAN_REPO", buffer, sizeof(buffer));
		if (length >= sizeof(buffer)) {
			error = "FLAN_REPO is too long";
			return false;
		}
		if (length > 0) {
			repo.assign(buffer, length);
		}

		while (!repo.empty() && (repo.back() == '/' || repo.back() == '\\')) {
			repo.pop_back();
		}

		if (isHttpsUrl(repo + "/")) {
			source.local = false;
			source.location = repo + "/index.flan";
			return true;
		}

		// Любая другая схема (http://, ftp://) — почти наверняка ошибка, а не имя каталога.
		if (repo.empty() || repo.find("://") != std::string::npos) {
			error = "FLAN_REPO must be an https:// URL or a local directory";
			return false;
		}

		source.local = true;
		source.location = repo + "\\index.flan";
		return true;
	}

	bool replaceFile(const std::string& from, const std::string& to) {
		return MoveFileExA(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
	}
}

std::string formatUnixTime(uint64_t seconds) {
	const std::time_t value = (std::time_t)seconds;
	std::tm utc = {};
	if (gmtime_s(&utc, &value) != 0) {
		return std::to_string(seconds);
	}

	char text[32];
	std::strftime(text, sizeof(text), "%Y-%m-%d %H:%M UTC", &utc);
	return text;
}

ExitCode syncIndex(const FlanPaths& paths) {
	IndexSource source;
	std::string error;
	if (!resolveIndexSource(source, error)) {
		std::cerr << "Error: " << error << "." << std::endl;
		return ExitCode::Usage;
	}

	// Скачанное или скопированное сначала ложится рядом во временный файл (§6.1, шаг 7):
	// пока он не проверен, прежний state\index.flan остаётся рабочим.
	const std::string target = paths.state + "\\index.flan";
	const std::string candidate = paths.state + "\\index.flan.part";
	deleteFile(candidate.c_str());

	if (source.local) {
		std::cout << "Copying index from " << source.location << std::endl;
		if (!CopyFileA(source.location.c_str(), candidate.c_str(), FALSE)) {
			std::cerr << "Error: cannot copy " << source.location << " (code " << GetLastError() << ")." << std::endl;
			return ExitCode::Error;
		}
	}
	else {
		std::cout << "Downloading index from " << source.location << std::endl;
		if (!downloadFile(source.location, candidate)) {
			std::cerr << "Error: failed to download the index. Check your internet connection." << std::endl;
			return ExitCode::Network;
		}
	}

	std::vector<uint8_t> file;
	bool tooLarge = false;
	if (!readWholeFile(candidate, MAX_INDEX_FILE_SIZE, file, tooLarge)) {
		deleteFile(candidate.c_str());
		if (tooLarge) {
			std::cerr << "Error: the index is larger than " << (MAX_INDEX_FILE_SIZE / (1024 * 1024))
				<< " MB. The current index is kept." << std::endl;
			return ExitCode::Integrity;
		}
		std::cerr << "Error: cannot read the received index." << std::endl;
		return ExitCode::Error;
	}

	// Шаги 1, 2 и 5 §6.1 и полная проверка всех записей (§6.2). Подпись — с этапа 4,
	// распаковка — с этапа 2, защита от отката — с этапа 4.
	IndexView view;
	if (!view.open(std::move(file), error) || !view.validateAll(error)) {
		deleteFile(candidate.c_str());
		std::cerr << "Error: the received index is rejected: " << error << ". The current index is kept." << std::endl;
		return ExitCode::Integrity;
	}

	if (!replaceFile(candidate, target)) {
		std::cerr << "Error: cannot replace " << target << " (code " << GetLastError() << ")." << std::endl;
		deleteFile(candidate.c_str());
		return ExitCode::Error;
	}

	std::set<std::string> packages;
	for (uint32_t i = 0; i < view.count(); i++) {
		IndexRecord record;
		if (view.record(i, record, error)) {
			packages.insert(record.name);
		}
	}

	std::cout << "Index updated: " << packages.size() << " package(s), " << view.count() << " build(s), generated "
		<< formatUnixTime(view.generatedAt()) << "." << std::endl;
	return ExitCode::Ok;
}

bool loadLocalIndex(const FlanPaths& paths, IndexView& view, std::string& error) {
	const std::string path = paths.state + "\\index.flan";

	std::vector<uint8_t> file;
	bool tooLarge = false;
	if (!readWholeFile(path, MAX_INDEX_FILE_SIZE, file, tooLarge)) {
		const DWORD attributes = GetFileAttributesA(path.c_str());
		error = attributes == INVALID_FILE_ATTRIBUTES
			? "no package index yet. Run 'flan sync' first"
			: "cannot read " + path + ". Run 'flan sync' to fetch it again";
		return false;
	}

	if (!view.open(std::move(file), error)) {
		error = "the local index is corrupted (" + error + "). Run 'flan sync' to fetch it again";
		return false;
	}
	return true;
}
