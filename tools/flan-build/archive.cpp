#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "build.hpp"
#include "flan/fs.hpp"
#include "flan/http.hpp"
#include "flan/sha256.hpp"
#include "flan/validate.hpp"
#include <set>

bool downloadToCache(const std::string& url, const fs::path& cacheDir, CachedArchive& out, std::string& error) {
	std::error_code ec;
	fs::create_directories(cacheDir, ec);
	if (ec) {
		error = "cannot create cache directory " + cacheDir.string() + ": " + ec.message();
		return false;
	}

	// Имя временного файла уникально для процесса: два flan-build не мешают друг другу.
	const fs::path temporary = cacheDir / ("download-" + std::to_string(GetCurrentProcessId()) + ".tmp");
	if (!downloadFile(url, temporary.string())) {
		error = "download failed: " + url;
		return false;
	}

	const std::string sha256 = crypto::calculateSHA256(temporary.string());
	const uintmax_t size = fs::file_size(temporary, ec);
	if (sha256.empty() || ec) {
		fs::remove(temporary, ec);
		error = "cannot hash the downloaded archive";
		return false;
	}

	// Кэш адресуется содержимым: файл с тем же именем — тот же самый архив.
	const fs::path cached = cacheDir / sha256;
	if (fs::exists(cached, ec)) {
		fs::remove(temporary, ec);
	}
	else if (!MoveFileExW(temporary.wstring().c_str(), cached.wstring().c_str(), MOVEFILE_REPLACE_EXISTING)) {
		error = "cannot move the archive into the cache (code " + std::to_string(GetLastError()) + ")";
		fs::remove(temporary, ec);
		return false;
	}

	out.path = cached.string();
	out.sha256 = sha256;
	out.size = size;
	return true;
}

bool findInCache(const fs::path& cacheDir, const std::string& sha256, CachedArchive& out) {
	std::error_code ec;
	const fs::path cached = cacheDir / sha256;
	if (!fs::is_regular_file(cached, ec)) {
		return false;
	}

	// Файл в кэше мог испортиться на диске: хэш пересчитывается, испорченный удаляется.
	if (crypto::calculateSHA256(cached.string()) != sha256) {
		fs::remove(cached, ec);
		return false;
	}

	out.path = cached.string();
	out.sha256 = sha256;
	out.size = fs::file_size(cached, ec);
	return !ec;
}

bool verifyArchiveContents(const std::string& archivePath, const ArchTarget& target,
	const std::vector<std::string>& bins, std::string& error) {

	std::vector<std::string> entries;
	if (!listArchive(archivePath, entries)) {
		error = "cannot list the archive";
		return false;
	}

	// Имена в zip — с '/', а сравниваем без учёта регистра: так их потом увидит
	// файловая система Windows после распаковки.
	auto normalize = [](std::string name) {
		for (char& c : name) {
			if (c == '\\') c = '/';
		}
		if (name.compare(0, 2, "./") == 0) {
			name.erase(0, 2);
		}
		return toLowerAscii(name);
	};

	std::set<std::string> files;
	std::vector<std::string> all;
	for (const std::string& entry : entries) {
		const std::string name = normalize(entry);
		all.push_back(name);
		if (!name.empty() && name.back() != '/') {
			files.insert(name);
		}
	}

	// В zip может не быть отдельных записей для каталогов, поэтому extract_dir ищется
	// как префикс любого имени, а не как собственная запись.
	std::string prefix;
	if (!target.extractDir.empty()) {
		prefix = normalize(target.extractDir) + "/";

		bool found = false;
		for (const std::string& name : all) {
			if (name.compare(0, prefix.size(), prefix) == 0) {
				found = true;
				break;
			}
		}

		if (!found) {
			error = "extract_dir '" + target.extractDir + "' is not in the archive";
			return false;
		}
	}

	for (const std::string& bin : bins) {
		const std::string wanted = prefix + normalize(bin);
		if (files.count(wanted) == 0) {
			error = "bin '" + bin + "' is not a file in the archive (looked for '" + wanted + "')";
			return false;
		}
	}

	return true;
}
