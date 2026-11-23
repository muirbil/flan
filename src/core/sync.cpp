#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "core/sync.hpp"
#include "core/index_state.hpp"
#include "flan/fs.hpp"
#include "flan/http.hpp"
#include "flan/strings.hpp"
#include "flan/validate.hpp"
#include <ctime>
#include "flan/console.hpp"
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

		// W-функция: локальный путь в FLAN_REPO может быть кириллическим (DESIGN.md §7.1).
		wchar_t buffer[2048];
		const DWORD length = GetEnvironmentVariableW(L"FLAN_REPO", buffer, ARRAYSIZE(buffer));
		if (length >= ARRAYSIZE(buffer)) {
			error = "FLAN_REPO is too long";
			return false;
		}
		if (length > 0 && !toUtf8(std::wstring(buffer, length), repo)) {
			error = "FLAN_REPO is not a valid path";
			return false;
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
		return moveFile(from, to, true);
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
		con::err << "Error: " << error << "." << con::endl;
		return ExitCode::Usage;
	}

	// Скачанное или скопированное сначала ложится рядом во временный файл (§6.1, шаг 7):
	// пока он не проверен, прежний state\index.flan остаётся рабочим.
	const std::string target = paths.state + "\\index.flan";
	const std::string candidate = paths.state + "\\index.flan.part";
	deleteFile(candidate);

	IndexState accepted;
	accepted.source = source.location;
	uint64_t received = 0;

	if (source.local) {
		// Локальный FLAN_REPO копируется всегда: это дёшево (§7.2).
		con::out << "Copying index from " << source.location << con::endl;
		if (!copyFile(source.location, candidate, true)) {
			con::err << "Error: cannot copy " << source.location << " (code " << GetLastError() << ")." << con::endl;
			return ExitCode::Error;
		}
	}
	else {
		HttpRequest request;
		request.url = source.location;
		request.destination = candidate;
		request.maxSize = MAX_INDEX_FILE_SIZE;

		// ETag уходит, только если индекс взят из того же источника и локальная копия цела:
		// иначе 304 оставил бы нас без рабочего индекса (§7.2).
		IndexState previous;
		IndexView current;
		std::string ignored;
		if (loadIndexState(paths, previous) && previous.source == source.location && !previous.etag.empty() &&
			loadLocalIndex(paths, current, ignored) == ExitCode::Ok) {
			request.ifNoneMatch = previous.etag;
		}

		con::out << (request.ifNoneMatch.empty() ? "Downloading" : "Checking") << " index at " << source.location << con::endl;
		const HttpResult result = httpGet(request);

		switch (result.outcome) {
		case HttpOutcome::NotModified:
			deleteFile(candidate);
			con::out << "Index is up to date (304 Not Modified, " << result.bodyBytes << " bytes of body)." << con::endl;
			return ExitCode::Ok;
		case HttpOutcome::Ok:
			break;
		case HttpOutcome::SizeMismatch:
			deleteFile(candidate);
			con::err << "Error: the index is larger than " << (MAX_INDEX_FILE_SIZE / (1024 * 1024))
				<< " MB. The current index is kept." << con::endl;
			return ExitCode::Integrity;
		case HttpOutcome::LocalError:
			deleteFile(candidate);
			con::err << "Error: " << result.error << "." << con::endl;
			return ExitCode::Error;
		case HttpOutcome::NetworkError:
			deleteFile(candidate);
			con::err << "Error: failed to download the index: " << result.error << ". Check your internet connection." << con::endl;
			return ExitCode::Network;
		default:
			deleteFile(candidate);
			con::err << "Error: failed to download the index: " << result.error << "." << con::endl;
			return ExitCode::Network;
		}

		accepted.etag = result.etag;
		received = result.bodyBytes;
	}

	std::vector<uint8_t> file;
	bool tooLarge = false;
	if (!readWholeFile(candidate, MAX_INDEX_FILE_SIZE, file, tooLarge)) {
		deleteFile(candidate);
		if (tooLarge) {
			con::err << "Error: the index is larger than " << (MAX_INDEX_FILE_SIZE / (1024 * 1024))
				<< " MB. The current index is kept." << con::endl;
			return ExitCode::Integrity;
		}
		con::err << "Error: cannot read the received index." << con::endl;
		return ExitCode::Error;
	}

	// Шаги 1–5 §6.1 (размер, конверт, подпись, распаковка, разбор) и полная проверка всех записей (§6.2).
	IndexView view;
	if (!view.open(std::move(file), error) || !view.validateAll(error)) {
		deleteFile(candidate);
		con::err << "Error: the received index is rejected: " << error << ". The current index is kept." << con::endl;
		return ExitCode::Integrity;
	}

	// Шаг 6: защита от отката. Последнее принятое — более позднее из index.state и самого
	// локального индекса: удаление одного из файлов счётчик не сбрасывает.
	AcceptedIndex last;
	IndexState recorded;
	if (loadIndexState(paths, recorded)) {
		last.keyId = recorded.keyId;
		last.generatedAt = recorded.generatedAt;
	}
	IndexView local;
	std::string ignored;
	if (loadLocalIndex(paths, local, ignored) == ExitCode::Ok) {
		last = laterAccepted(last, AcceptedIndex{ local.keyId(), local.generatedAt() });
	}

	const AcceptedIndex incoming{ view.keyId(), view.generatedAt() };
	switch (checkRollback(last, incoming)) {
	case RollbackVerdict::Accept:
		break;
	case RollbackVerdict::RetiredKey:
		deleteFile(candidate);
		con::err << "Error: the received index is signed with key " << (int)incoming.keyId << ", but this flan has already accepted "
			<< "an index signed with key " << (int)last.keyId << ". Key " << (int)incoming.keyId
			<< " is retired. The current index is kept." << con::endl;
		return ExitCode::Integrity;
	case RollbackVerdict::Rollback:
		deleteFile(candidate);
		con::err << "Error: the received index is older than the current one (generated " << formatUnixTime(incoming.generatedAt)
			<< ", current " << formatUnixTime(last.generatedAt) << "). This looks like a rollback; the current index is kept." << con::endl;
		return ExitCode::Integrity;
	}

	if (!replaceFile(candidate, target)) {
		con::err << "Error: cannot replace " << target << " (code " << GetLastError() << ")." << con::endl;
		deleteFile(candidate);
		return ExitCode::Error;
	}

	std::set<std::string> packages;
	for (uint32_t i = 0; i < view.count(); i++) {
		IndexRecord record;
		if (view.record(i, record, error)) {
			packages.insert(record.name);
		}
	}

	// Состояние пишется после принятия индекса: ETag всегда описывает тот файл, что лежит в state\.
	accepted.generatedAt = view.generatedAt();
	accepted.keyId = view.keyId();
	if (!saveIndexState(paths, accepted)) {
		con::err << "Warning: cannot write " << paths.state << "\\index.state; the next sync will download the index in full." << con::endl;
	}

	con::out << "Index updated: " << packages.size() << " package(s), " << view.count() << " build(s), generated "
		<< formatUnixTime(view.generatedAt());
	if (!source.local) {
		con::out << "; " << received << " bytes downloaded";
	}
	con::out << "." << con::endl;
	return ExitCode::Ok;
}

ExitCode loadLocalIndex(const FlanPaths& paths, IndexView& view, std::string& error) {
	const std::string path = paths.state + "\\index.flan";

	std::vector<uint8_t> file;
	bool tooLarge = false;
	if (!readWholeFile(path, MAX_INDEX_FILE_SIZE, file, tooLarge)) {
		if (tooLarge) {
			error = "the local index is larger than allowed. Run 'flan sync' to fetch it again";
			return ExitCode::Integrity;
		}
		error = !pathExists(path)
			? "no package index yet. Run 'flan sync' first"
			: "cannot read " + path + ". Run 'flan sync' to fetch it again";
		return ExitCode::Error;
	}

	if (!view.open(std::move(file), error)) {
		error = "the local index is rejected (" + error + "). Run 'flan sync' to fetch it again";
		return ExitCode::Integrity;
	}
	return ExitCode::Ok;
}
