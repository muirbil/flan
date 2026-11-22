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
#include <fstream>
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
			deleteFile(pendingDeletePath(paths));
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
		return pathExists(path);
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
	// другого flan нет, поэтому любой apps\<name>\.staging-* — мёртвый. Обход — по "*"
	// с отбором в коде, на UTF-16 (DESIGN.md §7.1).
	void removeStaleLeftovers(const FlanPaths& paths, const std::string& name) {
		const std::wstring appDir = extendedPath(paths.apps + "\\" + name);

		std::vector<DirEntry> entries;
		if (!listDirectory(appDir, entries)) {
			return;
		}

		for (const DirEntry& entry : entries) {
			if (entry.name.compare(0, 9, L".staging-") == 0) {
				removeTreeW(appDir + L"\\" + entry.name);
			}
		}
	}
}

bool removeTreeIfUnused(const std::string& path) {
	if (!exists(path)) {
		return true;
	}
	const std::wstring wide = extendedPath(path);
	if (treeInUse(wide)) {
		return false;
	}
	return removeTreeW(wide);
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

namespace {

	// Запас свободного места сверх того, что осталось скачать (DESIGN.md §7.2, «Лимиты»).
	constexpr uint64_t FREE_SPACE_MARGIN = 16ull * 1024 * 1024;

	std::string formatSize(uint64_t bytes) {
		if (bytes < 1024 * 1024) {
			return std::to_string((bytes + 1023) / 1024) + " KB";
		}
		const uint64_t tenths = (bytes * 10 + 512 * 1024) / (1024 * 1024);
		return std::to_string(tenths / 10) + "." + std::to_string(tenths % 10) + " MB";
	}

	// Первые size байт уже скачанной части — в хэш, один раз перед продолжением (§7.2).
	bool hashExistingPart(const std::string& path, uint64_t size, crypto::Sha256& hasher) {
		std::ifstream in(extendedPath(path).c_str(), std::ios::binary);
		std::vector<char> buffer(64 * 1024);
		uint64_t left = size;
		while (in && left > 0) {
			const std::streamsize want = (std::streamsize)(left < buffer.size() ? left : buffer.size());
			in.read(buffer.data(), want);
			const std::streamsize got = in.gcount();
			if (got <= 0) {
				break;
			}
			hasher.update(buffer.data(), (size_t)got);
			left -= (uint64_t)got;
		}
		return left == 0 && hasher.ok();
	}

	// Шаг 3 транзакции (DESIGN.md §7.6, §7.2). Готовый и целый cache\<sha256> — без сети.
	// Иначе загрузка в cache\<sha256>.part: с Range от уже скачанного, с хэшем на лету,
	// не больше archive_size. Если после докачки хэш не сошёлся — один раз заново целиком.
	ExitCode fetchArchive(const FlanPaths& paths, const IndexRecord& entry, const std::string& sha256,
		const std::string& label, std::string& archive) {

		archive = paths.cache + "\\" + sha256;
		const std::string part = archive + ".part";

		uint64_t size = 0;
		if (fileSize(archive, size)) {
			if (size == entry.archiveSize && crypto::calculateSHA256(archive) == sha256) {
				std::cout << "Using the cached archive of " << label << "." << std::endl;
				return ExitCode::Ok;
			}
			deleteFile(archive);
		}

		for (int pass = 0; pass < 2; pass++) {
			uint64_t have = 0;
			if (fileSize(part, have) && have > entry.archiveSize) {
				deleteFile(part);
				have = 0;
			}

			crypto::Sha256 hasher;
			if (have > 0 && !hashExistingPart(part, have, hasher)) {
				deleteFile(part);
				hasher.reset();
				have = 0;
			}

			uint64_t freeBytes = 0;
			const uint64_t needed = entry.archiveSize - have + FREE_SPACE_MARGIN;
			if (freeDiskSpace(paths.cache, freeBytes) && freeBytes < needed) {
				std::cerr << "Error: not enough disk space for " << label << ": " << formatSize(needed)
					<< " needed, " << formatSize(freeBytes) << " free." << std::endl;
				return ExitCode::Error;
			}

			const bool resuming = have > 0;
			bool resumedAnywhere = resuming;					// с прошлого .part или после обрыва в этом запуске
			if (have == entry.archiveSize) {
				// Процесс убили после загрузки, до переименования: запрос не нужен, только хэш.
				std::cout << "The download of " << label << " is already complete; verifying." << std::endl;
			}
			else {
				if (resuming) {
					std::cout << "Resuming " << label << ": " << formatSize(entry.archiveSize - have) << " of "
						<< formatSize(entry.archiveSize) << " left, from " << entry.url << std::endl;
				}
				else {
					std::cout << "Downloading " << label << ": " << formatSize(entry.archiveSize) << " from " << entry.url << std::endl;
				}

				HttpRequest request;
				request.url = entry.url;
				request.destination = part;
				request.resumeFrom = have;
				request.expectedSize = entry.archiveSize;
				request.maxSize = entry.archiveSize;
				request.hasher = &hasher;

				const HttpResult result = httpGet(request);
				switch (result.outcome) {
				case HttpOutcome::Ok:
					resumedAnywhere = resumedAnywhere || result.resumed;
					if (resuming || result.resumed) {
						std::cout << "  received " << formatSize(result.bodyBytes) << " of " << formatSize(entry.archiveSize)
							<< (result.resumed ? " (resumed)" : " (the server restarted the download)") << std::endl;
					}
					break;
				case HttpOutcome::SizeMismatch:
					deleteFile(part);
					std::cerr << "Error: " << label << ": " << result.error << "." << std::endl;
					return ExitCode::Integrity;
				case HttpOutcome::LocalError:
					std::cerr << "Error: " << result.error << "." << std::endl;
					return ExitCode::Error;
				default:
					// .part остаётся: следующий install продолжит с него.
					std::cerr << "Error: failed to download " << label << ": " << result.error << "." << std::endl;
					return ExitCode::Network;
				}
			}

			const std::string actual = hasher.finishHex();
			if (actual == sha256) {
				if (!moveFile(part, archive, true)) {
					std::cerr << "Error: cannot move the archive into " << archive << " (code " << GetLastError() << ")." << std::endl;
					return ExitCode::Error;
				}
				return ExitCode::Ok;
			}

			deleteFile(part);
			if (resumedAnywhere && pass == 0) {
				std::cerr << "Warning: SHA-256 mismatch after resuming; downloading " << label << " again from scratch." << std::endl;
				continue;
			}

			std::cerr << "Error: SHA-256 mismatch for " << label << ". The file may be corrupted or tampered with." << std::endl;
			std::cerr << "  expected: " << sha256 << std::endl;
			std::cerr << "  actual:   " << actual << std::endl;
			return ExitCode::Integrity;
		}

		return ExitCode::Integrity;
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
		if (!deleteFile(shimPath(paths, command))) {
			std::cerr << "Warning: cannot remove " << shimPath(paths, command) << "." << std::endl;
		}
	}

	// 2. Квитанция: с этого момента пакет считается удалённым.
	const std::string receiptFile = receiptPath(paths, name);
	if (exists(receiptFile) && !deleteFile(receiptFile)) {
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

	// Шаг 3: архив в cache\<sha256> — из кэша или загрузкой с докачкой и хэшем на лету.
	std::string archive;
	const ExitCode fetched = fetchArchive(paths, entry, sha256, label, archive);
	if (fetched != ExitCode::Ok) {
		return fetched;
	}

	// Шаг 4: распаковка в staging. Сбой до шага 8 удаляет только staging: прежняя версия
	// и её прослойки продолжают работать, а проверенный архив остаётся в кэше для повтора.
	const std::string pid = std::to_string(GetCurrentProcessId());
	const std::string appDir = paths.apps + "\\" + name;
	const std::string staging = appDir + "\\.staging-" + pid;

	// Одиночный .exe (DESIGN.md §5.2) не распаковывается: проверенный файл копируется
	// в staging под единственным именем из bins, дальше — те же шаги, что и для zip.
	const bool exe = entry.kind == KIND_EXE;
	const bool staged = createDirectory(appDir) && createDirectory(staging) &&
		(exe ? copyFile(archive, staging + "\\" + entry.bins[0], false)
			 : extractArchive(archive, staging));

	if (!staged) {
		std::cerr << "Error: failed to " << (exe ? "place" : "extract") << " " << name << "." << std::endl;
		removeTree(staging);
		return ExitCode::Error;
	}

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
	if (!moveFile(root, versionDir, false)) {
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
				deleteFile(shimPath(paths, command));
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

	// Политика кэша (DESIGN.md §7.6): после фиксации архив не нужен — распакованное в apps\.
	deleteFile(archive);

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
