#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "core/install.hpp"
#include "core/receipt.hpp"
#include "core/shim.hpp"
#include "core/sync.hpp"
#include "flan/fs.hpp"
#include "flan/hex.hpp"
#include "flan/http.hpp"
#include "flan/index.hpp"
#include "flan/sha256.hpp"
#include "flan/validate.hpp"
#include <filesystem>
#include <iostream>
#include <vector>

namespace {

	constexpr uint64_t MAX_PENDING_DELETE_SIZE = 1024 * 1024;

	std::string pendingDeletePath(const FlanPaths& paths) {
		return paths.state + "\\pending-delete";
	}

	std::vector<std::string> readPendingDeletes(const FlanPaths& paths) {
		std::vector<std::string> entries;

		std::vector<uint8_t> bytes;
		bool tooLarge = false;
		if (!readWholeFile(pendingDeletePath(paths), MAX_PENDING_DELETE_SIZE, bytes, tooLarge)) {
			return entries;
		}

		const std::string text(bytes.begin(), bytes.end());
		size_t start = 0;
		while (start < text.size()) {
			size_t end = text.find('\n', start);
			if (end == std::string::npos) {
				end = text.size();
			}
			std::string line = text.substr(start, end - start);
			if (!line.empty() && line.back() == '\r') {
				line.pop_back();
			}
			if (!line.empty()) {
				entries.push_back(line);
			}
			start = end + 1;
		}
		return entries;
	}

	void writePendingDeletes(const FlanPaths& paths, const std::vector<std::string>& entries) {
		if (entries.empty()) {
			DeleteFileA(pendingDeletePath(paths).c_str());
			return;
		}

		std::string text;
		for (const std::string& entry : entries) {
			text += entry + "\n";
		}
		saveFileAtomically(pendingDeletePath(paths), text);
	}

	// "<name>" или "<name>\<dir>". Из файла на диске строится путь для удаления,
	// поэтому оба сегмента проверяются; непрошедшая строка — мусор и отбрасывается.
	bool parsePendingEntry(const std::string& entry, std::string& name, std::string& dir) {
		const size_t slash = entry.find('\\');
		name = entry.substr(0, slash);
		dir = slash == std::string::npos ? std::string() : entry.substr(slash + 1);
		return isSafePackageName(name) && (slash == std::string::npos || isSafeName(dir));
	}

	bool exists(const std::string& path) {
		return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
	}

	// Архитектуры ОС в порядке предпочтения (DESIGN.md §7.6, шаг 1). GetNativeSystemInfo
	// из x86/x64-процесса на ARM64 сообщает эмулируемую архитектуру — это ожидаемо и безвредно.
	bool preferredArchitectures(std::vector<uint8_t>& archs, std::string& error) {
		SYSTEM_INFO info = {};
		GetNativeSystemInfo(&info);

		switch (info.wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64:
			archs = { ARCH_X64, ARCH_X86 };
			return true;
		case PROCESSOR_ARCHITECTURE_INTEL:
			archs = { ARCH_X86 };
			return true;
		case PROCESSOR_ARCHITECTURE_ARM64:
			error = "ARM64 Windows is not supported yet";
			return false;
		default:
			error = "this processor architecture is not supported";
			return false;
		}
	}

	// Каталог версии (DESIGN.md §7.6, шаг 6). liveDir — каталог действующей квитанции или пусто.
	bool chooseVersionDir(const std::string& appDir, const std::string& version, const std::string& sha256,
		const std::string& liveDir, std::string& dir, std::string& error) {

		dir = version;
		const std::string primary = appDir + "\\" + dir;
		if (!exists(primary)) {
			return true;
		}

		// На каталог не указывает квитанция — это остаток прерванной установки.
		if (dir != liveDir && removeTreeIfUnused(primary)) {
			return true;
		}

		dir = version + "-" + sha256.substr(0, 8);
		if (!isSafeName(dir)) {
			error = "cannot choose a directory name for version " + version;
			return false;
		}

		const std::string secondary = appDir + "\\" + dir;
		if (!exists(secondary) || (dir != liveDir && removeTreeIfUnused(secondary))) {
			return true;
		}

		error = primary + " and " + secondary + " are both in use. Close the program and try again";
		return false;
	}

	// Остатки установок, прерванных падением или убийством процесса. Под блокировкой
	// другого flan нет, поэтому любой .staging-* и любой tmp\<name>-*.zip — мёртвый.
	void removeStaleLeftovers(const FlanPaths& paths, const std::string& name) {
		WIN32_FIND_DATAA found = {};

		const std::string appDir = paths.apps + "\\" + name;
		HANDLE search = FindFirstFileA((appDir + "\\.staging-*").c_str(), &found);
		if (search != INVALID_HANDLE_VALUE) {
			do {
				removeTree(appDir + "\\" + found.cFileName);
			} while (FindNextFileA(search, &found));
			FindClose(search);
		}

		search = FindFirstFileA((paths.tmp + "\\" + name + "-*.zip*").c_str(), &found);
		if (search != INVALID_HANDLE_VALUE) {
			do {
				DeleteFileA((paths.tmp + "\\" + found.cFileName).c_str());
			} while (FindNextFileA(search, &found));
			FindClose(search);
		}
	}
}

bool removeTree(const std::string& path) {
	std::error_code ec;
	std::filesystem::remove_all(std::filesystem::path(path), ec);
	return !ec && !exists(path);
}

namespace {

	// Занят ли хоть один файл в дереве. Признак — открытие на запись при полном совместном
	// доступе: работающий .exe и файл, открытый программой, дают ERROR_SHARING_VIOLATION.
	// Проверено: открытие на чтение без совместного доступа работающий .exe пропускает
	// (у образа нет открытого дескриптора), а каталог с ним Windows даёт переименовать,
	// так что переименование занятость тоже не показывает. Файлы не изменяются: OPEN_EXISTING.
	bool treeInUse(const std::string& dir) {
		WIN32_FIND_DATAA found = {};
		const HANDLE search = FindFirstFileA((dir + "\\*").c_str(), &found);
		if (search == INVALID_HANDLE_VALUE) {
			return false;
		}

		bool inUse = false;
		do {
			const std::string name = found.cFileName;
			if (name == "." || name == "..") {
				continue;
			}

			const std::string path = dir + "\\" + name;
			if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				// Точки повторного анализа (junction, symlink) не обходим: они ведут за пределы пакета.
				if (!(found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
					inUse = treeInUse(path);
				}
				continue;
			}

			const HANDLE file = CreateFileA(path.c_str(), GENERIC_WRITE,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (file != INVALID_HANDLE_VALUE) {
				CloseHandle(file);
			}
			else if (GetLastError() == ERROR_SHARING_VIOLATION) {
				inUse = true;
			}
		} while (!inUse && FindNextFileA(search, &found));

		FindClose(search);
		return inUse;
	}
}

bool removeTreeIfUnused(const std::string& path) {
	if (!exists(path)) {
		return true;
	}
	if (treeInUse(path)) {
		return false;
	}
	return removeTree(path);
}

void addPendingDelete(const FlanPaths& paths, const std::string& entry) {
	std::vector<std::string> entries = readPendingDeletes(paths);
	for (const std::string& existing : entries) {
		if (existing == entry) {
			return;
		}
	}
	entries.push_back(entry);
	writePendingDeletes(paths, entries);
}

void processPendingDeletes(const FlanPaths& paths) {
	const std::vector<std::string> entries = readPendingDeletes(paths);
	if (entries.empty()) {
		return;
	}

	std::vector<std::string> remaining;
	for (const std::string& entry : entries) {
		std::string name;
		std::string dir;
		if (!parsePendingEntry(entry, name, dir)) {
			continue;
		}

		// Каталог снова в деле — пакет переустановили (в тот же каталог или целиком).
		Receipt receipt;
		std::string error;
		const ReceiptState state = readReceipt(paths, name, receipt, error);
		const bool reused = dir.empty()
			? state != ReceiptState::Missing
			: state == ReceiptState::Valid && receipt.dir == dir;
		if (reused) {
			continue;
		}

		const std::string path = paths.apps + "\\" + name + (dir.empty() ? "" : "\\" + dir);
		if (!removeTreeIfUnused(path)) {
			remaining.push_back(entry);
		}
	}

	if (remaining != entries) {
		writePendingDeletes(paths, remaining);
	}
}

ExitCode uninstallPackage(const FlanPaths& paths, const std::string& requestedName) {
	const std::string name = toLowerAscii(requestedName);
	if (!isSafePackageName(name)) {
		std::cerr << "Error: '" << requestedName << "' is not a valid package name." << std::endl;
		return ExitCode::Usage;
	}

	Receipt receipt;
	std::string error;
	const ReceiptState state = readReceipt(paths, name, receipt, error);

	const std::string appDir = paths.apps + "\\" + name;
	const std::vector<std::string> commands = shimsOwnedBy(paths, name);

	if (state == ReceiptState::Missing && !exists(appDir) && commands.empty()) {
		std::cerr << "Error: package '" << name << "' is not installed." << std::endl;
		return ExitCode::NotFound;
	}

	if (state == ReceiptState::Corrupt) {
		std::cerr << "Warning: the receipt of " << name << " is corrupted (" << error << "); removing the package anyway." << std::endl;
	}

	// 1. Прослойки — по строке владельца, а не по квитанции: так uninstall работает
	//    и с повреждённой квитанцией, а чужие прослойки не трогает никогда.
	for (const std::string& command : commands) {
		if (!deleteFile(shimPath(paths, command).c_str())) {
			std::cerr << "Warning: cannot remove " << shimPath(paths, command) << "." << std::endl;
		}
	}

	// 2. Квитанция: с этого момента пакет считается удалённым.
	const std::string receiptFile = receiptPath(paths, name);
	if (exists(receiptFile) && !deleteFile(receiptFile.c_str())) {
		std::cerr << "Error: cannot remove " << receiptFile << " (code " << GetLastError() << ")." << std::endl;
		return ExitCode::Error;
	}

	// 3. Каталог целиком: все версии и остатки. Занят — остаётся нетронутым до следующего запуска.
	if (!removeTreeIfUnused(appDir)) {
		addPendingDelete(paths, name);
		std::cout << "Note: " << appDir << " is in use; it will be removed on the next flan run." << std::endl;
	}

	std::cout << "Uninstalled " << name;
	if (state == ReceiptState::Valid) {
		std::cout << " " << receipt.version;
	}
	std::cout << "." << std::endl;
	return ExitCode::Ok;
}

ExitCode installPackage(const FlanPaths& paths, const std::string& requestedName) {
	// Имена пакетов в индексе — строчные (DESIGN.md §5.2): "RipGrep" — тот же ripgrep.
	const std::string name = toLowerAscii(requestedName);
	if (!isSafePackageName(name)) {
		std::cerr << "Error: '" << requestedName << "' is not a valid package name." << std::endl;
		return ExitCode::Usage;
	}

	IndexView index;
	std::string error;
	if (!loadLocalIndex(paths, index, error)) {
		std::cerr << "Error: " << error << "." << std::endl;
		return ExitCode::Error;
	}

	// Шаг 1: запись для архитектуры ОС.
	std::vector<uint8_t> archs;
	if (!preferredArchitectures(archs, error)) {
		std::cerr << "Error: " << error << "." << std::endl;
		return ExitCode::Error;
	}

	IndexRecord entry;
	FindResult found = FindResult::NotFound;
	for (const uint8_t arch : archs) {
		found = index.find(name, arch, entry, error);
		if (found != FindResult::NotFound) {
			break;
		}
	}

	if (found == FindResult::Corrupt) {
		std::cerr << "Error: the local index is corrupted (" << error << "). Run 'flan sync' to fetch it again." << std::endl;
		return ExitCode::Integrity;
	}
	if (found == FindResult::NotFound) {
		std::cerr << "Error: package '" << name << "' is not in the index for this architecture." << std::endl;
		return ExitCode::NotFound;
	}

	const std::string sha256 = toHex(entry.sha256, sizeof(entry.sha256));
	const std::string label = name + " " + entry.version + " (" + archName(entry.arch) + ")";

	// Шаг 2: квитанция. Тот же sha256 — та же сборка, делать нечего.
	Receipt old;
	const ReceiptState receiptState = readReceipt(paths, name, old, error);
	if (receiptState == ReceiptState::Valid && old.sha256 == sha256) {
		std::cout << label << " is already installed." << std::endl;
		return ExitCode::Ok;
	}
	if (receiptState == ReceiptState::Corrupt) {
		std::cerr << "Warning: the receipt of " << name << " is corrupted (" << error << "); installing anew." << std::endl;
	}

	const bool upgrading = receiptState == ReceiptState::Valid;
	const std::string liveDir = upgrading ? old.dir : std::string();

	// Конфликт прослоек проверяется до загрузки: чужую команду не перезаписываем никогда.
	for (const std::string& bin : entry.bins) {
		const std::string command = commandNameFromBin(bin);
		std::string owner;
		const ShimOwner shim = readShimOwner(paths, command, owner);

		if (shim == ShimOwner::Foreign) {
			std::cerr << "Error: " << shimPath(paths, command) << " exists and was not created by flan. "
				<< "Remove it to install " << name << "." << std::endl;
			return ExitCode::Error;
		}
		if (shim == ShimOwner::Package && owner != name) {
			std::cerr << "Error: command '" << command << "' already belongs to package '" << owner << "'." << std::endl;
			return ExitCode::Error;
		}
	}

	removeStaleLeftovers(paths, name);

	// Шаг 3: загрузка и SHA-256. На этапе 1 без кэша: архив во tmp\, после установки удаляется.
	const std::string pid = std::to_string(GetCurrentProcessId());
	const std::string archive = paths.tmp + "\\" + name + "-" + pid + ".zip";

	std::cout << "Downloading " << label << " from " << entry.url << std::endl;
	if (!downloadFile(entry.url, archive)) {
		std::cerr << "Error: failed to download " << name << "." << std::endl;
		deleteFile(archive.c_str());
		return ExitCode::Network;
	}

	const std::string actual = crypto::calculateSHA256(archive);
	if (actual != sha256) {
		std::cerr << "Error: SHA-256 mismatch for " << name << ". The file may be corrupted or tampered with." << std::endl;
		std::cerr << "  expected: " << sha256 << std::endl;
		std::cerr << "  actual:   " << actual << std::endl;
		deleteFile(archive.c_str());
		return ExitCode::Integrity;
	}

	// Шаг 4: распаковка в staging. Сбой до шага 8 удаляет только staging:
	// прежняя версия и её прослойки продолжают работать.
	const std::string appDir = paths.apps + "\\" + name;
	const std::string staging = appDir + "\\.staging-" + pid;

	// Одиночный .exe (DESIGN.md §5.2) не распаковывается: проверенный файл переносится
	// в staging под единственным именем из bins, дальше — те же шаги, что и для zip.
	const bool exe = entry.kind == KIND_EXE;
	const bool staged = createDirectory(appDir.c_str()) && createDirectory(staging.c_str()) &&
		(exe ? MoveFileExA(archive.c_str(), (staging + "\\" + entry.bins[0]).c_str(), MOVEFILE_COPY_ALLOWED) != 0
			 : extractArchive(archive, staging));

	if (!staged) {
		std::cerr << "Error: failed to " << (exe ? "place" : "extract") << " " << name << "." << std::endl;
		deleteFile(archive.c_str());
		removeTree(staging);
		return ExitCode::Error;
	}
	deleteFile(archive.c_str());								// для exe его уже нет: перенесён

	auto abort = [&](ExitCode code) {
		removeTree(staging);
		return code;
	};

	// До этапа 3 tar.exe распаковывает архив целиком, а корень приложения — staging\<extract_dir>.
	const std::string root = entry.extractDir.empty() ? staging : staging + "\\" + entry.extractDir;
	if (!isDirectory(root)) {
		std::cerr << "Error: the archive has no folder '" << entry.extractDir << "'." << std::endl;
		return abort(ExitCode::Integrity);
	}

	// Шаг 5.
	for (const std::string& bin : entry.bins) {
		if (!isRegularFile(root + "\\" + bin)) {
			std::cerr << "Error: the archive has no file '" << bin << "'." << std::endl;
			return abort(ExitCode::Integrity);
		}
	}

	// Шаг 6.
	std::string dir;
	if (!chooseVersionDir(appDir, entry.version, sha256, liveDir, dir, error)) {
		std::cerr << "Error: " << error << "." << std::endl;
		return abort(ExitCode::Error);
	}

	const std::string versionDir = appDir + "\\" + dir;
	if (!MoveFileExA(root.c_str(), versionDir.c_str(), 0)) {
		std::cerr << "Error: cannot move the package into " << versionDir << " (code " << GetLastError() << ")." << std::endl;
		return abort(ExitCode::Error);
	}
	removeTree(staging);								// всё, что было вне extract_dir

	// Шаг 7: прослойки, затем — команды прежней версии, которых в новой больше нет.
	for (const std::string& bin : entry.bins) {
		const std::string command = commandNameFromBin(bin);
		if (!writeShim(paths, command, versionDir + "\\" + bin, name)) {
			std::cerr << "Error: cannot write " << shimPath(paths, command) << "." << std::endl;
			return ExitCode::Error;
		}
	}

	if (upgrading) {
		for (const std::string& oldBin : old.bins) {
			const std::string command = commandNameFromBin(oldBin);

			bool kept = false;
			for (const std::string& bin : entry.bins) {
				kept = kept || toLowerAscii(commandNameFromBin(bin)) == toLowerAscii(command);
			}

			std::string owner;
			if (!kept && readShimOwner(paths, command, owner) == ShimOwner::Package && owner == name) {
				deleteFile(shimPath(paths, command).c_str());
			}
		}
	}

	// Шаг 8: квитанция — точка фиксации.
	Receipt receipt;
	receipt.name = name;
	receipt.version = entry.version;
	receipt.dir = dir;
	receipt.arch = entry.arch;
	receipt.sha256 = sha256;
	receipt.bins = entry.bins;
	receipt.installedAt = currentUtcTimestamp();

	if (!writeReceipt(paths, receipt)) {
		std::cerr << "Error: cannot write " << receiptPath(paths, name) << "." << std::endl;
		return ExitCode::Error;
	}

	// Шаг 9: прежняя версия. Занята запущенной программой — удалится при следующем запуске flan.
	if (upgrading && old.dir != dir) {
		const std::string oldDir = appDir + "\\" + old.dir;
		if (!removeTreeIfUnused(oldDir)) {
			addPendingDelete(paths, name + "\\" + old.dir);
			std::cout << "Note: " << oldDir << " is in use; it will be removed on the next flan run." << std::endl;
		}
	}

	std::string commands;
	for (const std::string& bin : entry.bins) {
		commands += (commands.empty() ? "" : ", ") + commandNameFromBin(bin);
	}

	std::cout << (upgrading ? "Updated " : "Installed ") << label << " to " << versionDir << "." << std::endl;
	std::cout << "Commands: " << commands << " (in " << paths.bin << ")" << std::endl;
	return ExitCode::Ok;
}
