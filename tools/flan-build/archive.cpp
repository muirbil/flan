#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "build.hpp"
#include "flan/fs.hpp"
#include "flan/http.hpp"
#include "flan/sha256.hpp"
#include "flan/validate.hpp"
#include "flan/zip.hpp"
#include <fstream>

bool downloadToCache(const std::string& url, const fs::path& cacheDir, CachedArchive& out, std::string& error) {
	std::error_code ec;
	fs::create_directories(cacheDir, ec);
	if (ec) {
		error = "cannot create cache directory " + cacheDir.string() + ": " + ec.message();
		return false;
	}

	// Имя временного файла уникально для процесса: два flan-build не мешают друг другу.
	const fs::path temporary = cacheDir / ("download-" + std::to_string(GetCurrentProcessId()) + ".tmp");
	if (!downloadFile(url, temporary.u8string())) {
		error = "download failed: " + url;
		return false;
	}

	const std::string sha256 = crypto::calculateSHA256(temporary.u8string());
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

	out.path = cached.u8string();
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
	if (crypto::calculateSHA256(cached.u8string()) != sha256) {
		fs::remove(cached, ec);
		return false;
	}

	out.path = cached.u8string();
	out.sha256 = sha256;
	out.size = fs::file_size(cached, ec);
	return !ec;
}

namespace {

	// Одиночный .exe: проверяется заголовок PE. Заголовок лежит в начале файла,
	// поэтому хватает первых 64 КБ; e_lfanew дальше этого — заведомо не обычный .exe.
	bool verifyExecutable(const std::string& path, uint8_t arch, std::string& error) {
		std::ifstream in(fs::u8path(path), std::ios::binary);		// путь — UTF-8, как в слое fs
		if (!in) {
			error = "cannot open the downloaded file";
			return false;
		}

		std::vector<uint8_t> head(64 * 1024);
		in.read(reinterpret_cast<char*>(head.data()), (std::streamsize)head.size());
		return checkPeHeader(head.data(), (size_t)in.gcount(), arch, error);
	}
}

bool verifyPackageContents(const std::string& archivePath, const ArchTarget& target,
	const std::vector<std::string>& bins, std::string& error) {

	if (target.kind == KIND_EXE) {
		return verifyExecutable(archivePath, target.arch, error);
	}

	// Тот же zip.cpp, что у клиента (DESIGN.md §8): все запреты §7.3, в том числе предел
	// распакованного размера (§5.3), — уже в open.
	ZipArchive archive;
	if (!archive.open(archivePath, error)) {
		return false;
	}

	// В zip может не быть отдельных записей для каталогов, поэтому extract_dir ищется
	// и как префикс любого имени. Сравнение — без учёта регистра, как его увидит NTFS.
	if (!target.extractDir.empty() && !zipHasDirectory(archive.entries(), target.extractDir)) {
		error = "extract_dir '" + target.extractDir + "' is not in the archive";
		return false;
	}

	const std::string prefix = target.extractDir.empty() ? std::string() : target.extractDir + "\\";
	for (const std::string& bin : bins) {
		if (findZipFile(archive.entries(), prefix + bin) == nullptr) {
			error = "bin '" + bin + "' is not a file in the archive (looked for '" + prefix + bin + "')";
			return false;
		}
	}

	// Каждая запись распаковывается вхолостую: битый поток или CRC клиент увидел бы
	// только при установке, а генератор обязан отвергнуть такой архив до публикации.
	for (const ZipEntry& entry : archive.entries()) {
		if (!archive.readEntry(entry, nullptr, error)) {
			return false;
		}
	}

	return true;
}
