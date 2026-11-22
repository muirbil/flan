#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winioctl.h>
#include "test.hpp"
#include "core/paths.hpp"
#include "core/receipt.hpp"
#include "core/shim.hpp"
#include "flan/fs.hpp"
#include "flan/strings.hpp"
#include <string>
#include <vector>

namespace {

	void checkExtended(const std::string& input, const std::wstring& expected) {
		std::string shown;
		toUtf8(extendedPath(input), shown);
		check(extendedPath(input) == expected, "extendedPath(" + input + ")", shown);
	}

	void checkHomeOk(const std::string& value, const std::string& expected) {
		std::string home;
		std::string error;
		const bool ok = parseFlanHome(value, home, error);
		check(ok && home == expected, "FLAN_HOME accepted: " + value, ok ? home : error);
	}

	void checkHomeBad(const std::string& value) {
		std::string home;
		std::string error;
		check(!parseFlanHome(value, home, error) && home.empty(), "FLAN_HOME rejected: " + value, home);
	}

	// Временный каталог тестов: кириллица, пробел и полный путь длиннее 260 символов —
	// так проверяется и Unicode, и префикс \\?\ (DESIGN.md §7.1, §12, этап 3).
	std::string makeTestRoot() {
		wchar_t temp[MAX_PATH + 1];
		const DWORD length = GetTempPathW(ARRAYSIZE(temp), temp);
		std::string base;
		if (length == 0 || length > MAX_PATH || !toUtf8(std::wstring(temp, length), base)) {
			return std::string();
		}

		std::string root = base + "flan-tests-" + std::to_string(GetCurrentProcessId()) + "\\Проверка flan";
		while (root.size() < 300) {
			root += "\\длинный каталог";
		}
		return root;
	}

	void testPathsAndHome() {
		checkExtended("C:\\a\\b", L"\\\\?\\C:\\a\\b");
		checkExtended("C:/a/./b/../c", L"\\\\?\\C:\\a\\c");
		checkExtended("\\\\server\\share\\x", L"\\\\?\\UNC\\server\\share\\x");
		checkExtended("\\\\?\\C:\\x\\..\\y", L"\\\\?\\C:\\x\\..\\y");
		checkExtended("D:\\Проверка", L"\\\\?\\D:\\\x041F\x0440\x043E\x0432\x0435\x0440\x043A\x0430");

		const std::wstring relative = extendedPath("relative-name");
		check(relative.compare(0, 4, L"\\\\?\\") == 0 && relative.size() > 18 &&
			relative.compare(relative.size() - 14, 14, L"\\relative-name") == 0, "extendedPath makes a relative path absolute");

		checkHomeOk("D:\\flan", "D:\\flan");
		checkHomeOk("D:\\flan\\", "D:\\flan");
		checkHomeOk("d:/flan/x/", "d:\\flan\\x");
		checkHomeOk("D:\\a\\..\\b", "D:\\b");
		checkHomeOk("D:\\Проверка flan\\.flan", "D:\\Проверка flan\\.flan");
		checkHomeOk("\\\\server\\share\\flan", "\\\\server\\share\\flan");
		checkHomeOk("\\\\server\\share", "\\\\server\\share");

		checkHomeBad("");
		checkHomeBad("flan");
		checkHomeBad(".\\flan");
		checkHomeBad("\\flan");
		checkHomeBad("D:flan");
		checkHomeBad("D:\\");
		checkHomeBad("D:");
		checkHomeBad("\\\\server");
		checkHomeBad("\\\\server\\");
		checkHomeBad("\\\\?\\D:\\flan");
		checkHomeBad("\\\\.\\D:");
	}

	void testFileOperations(const std::string& root) {
		check(createDirectory(root + "\\a\\b"), "createDirectory: nested, long, Cyrillic");
		check(isDirectory(root + "\\a\\b"), "isDirectory");

		const std::string file = root + "\\a\\файл.txt";
		check(saveFileAtomically(file, "привет"), "saveFileAtomically");
		check(isRegularFile(file) && !isDirectory(file), "isRegularFile");
		check(!pathExists(file + ".tmp"), "saveFileAtomically leaves no .tmp");

		std::vector<uint8_t> bytes;
		bool tooLarge = false;
		check(readWholeFile(file, 1024, bytes, tooLarge) && std::string(bytes.begin(), bytes.end()) == "привет", "readWholeFile");
		check(!readWholeFile(file, 3, bytes, tooLarge) && tooLarge, "readWholeFile: limit");

		uint64_t size = 0;
		check(fileSize(file, size) && size == std::string("привет").size(), "fileSize");

		uint64_t free = 0;
		check(freeDiskSpace(root, free) && free > 0, "freeDiskSpace");

		const std::string copy = root + "\\a\\b\\копия.txt";
		check(copyFile(file, copy, false) && isRegularFile(copy), "copyFile");
		check(!copyFile(file, copy, false), "copyFile: no overwrite");
		check(copyFile(file, copy, true), "copyFile: overwrite");

		const std::string moved = root + "\\a\\перенесён.txt";
		check(moveFile(copy, moved, false) && !pathExists(copy) && pathExists(moved), "moveFile");
		check(!moveFile(file, moved, false), "moveFile: no replace");
		check(moveFile(file, moved, true) && !pathExists(file), "moveFile: replace");

		check(deleteFile(moved) && !pathExists(moved), "deleteFile");
		check(!deleteFile(moved), "deleteFile: missing file");
	}

	void writeText(const std::string& path, const std::string& text) {
		saveFileAtomically(path, text);
	}

	void testDirectoryWalks(const std::string& root) {
		const FlanPaths paths = FlanPaths::under(root + "\\home");
		createDirectory(paths.apps);
		createDirectory(paths.bin);

		// Квитанции: обходится только ASCII-имя по белому списку. Каталоги с кириллицей и с
		// непарным суррогатом пропускаются, и имя второго ни разу не проходит через UTF-8.
		Receipt receipt;
		receipt.name = "ripgrep";
		receipt.version = "15.2.0";
		receipt.dir = "15.2.0";
		receipt.arch = 2;
		receipt.sha256 = std::string(64, 'a');
		receipt.bins = { "rg.exe" };
		receipt.installedAt = "2026-11-22T00:00:00Z";
		createDirectory(paths.apps + "\\ripgrep");
		check(writeReceipt(paths, receipt), "writeReceipt");

		createDirectory(paths.apps + "\\пакет");
		writeText(paths.apps + "\\пакет\\receipt", formatReceipt(receipt));

		const std::wstring apps = extendedPath(paths.apps);
		const std::wstring surrogate = apps + L"\\bad" + std::wstring(1, (wchar_t)0xD800) + L"name";
		const bool surrogateMade = CreateDirectoryW(surrogate.c_str(), NULL) != 0;
		check(surrogateMade, "a directory with an unpaired surrogate can be created");

		std::vector<std::string> problems;
		const std::vector<Receipt> receipts = listReceipts(paths, problems);
		check(receipts.size() == 1 && receipts[0].name == "ripgrep" && problems.empty(),
			"listReceipts skips non-ASCII names", std::to_string(receipts.size()) + " receipt(s)");

		std::vector<DirEntry> entries;
		bool surrogateListed = false;
		if (listDirectory(apps, entries)) {
			for (const DirEntry& entry : entries) {
				surrogateListed = surrogateListed || apps + L"\\" + entry.name == surrogate;
			}
		}
		check(!surrogateMade || surrogateListed, "listDirectory returns the surrogate name unchanged");

		std::string ascii;
		check(!asciiName(L"bad" + std::wstring(1, (wchar_t)0xD800), ascii) && !asciiName(L"пакет", ascii) &&
			asciiName(L"ripgrep", ascii) && ascii == "ripgrep", "asciiName");

		// Прослойки: обход по "*", окончания .shim и .bat проверяются в коде. rg.batch с коротким
		// именем RG~1.BAT, x.shim.bak и кириллическая команда — не прослойки.
		const std::string bat = "@echo off\r\nrem package=pkg\r\n\"C:\\x\\a.exe\" %* & call exit /b %%errorlevel%%\r\n";
		const std::string batOther = "@echo off\r\nrem package=another\r\n\"C:\\x\\a.exe\" %*\r\n";
		writeText(batShimPath(paths, "legacy"), bat);
		writeText(paths.bin + "\\rg.batch", bat);
		writeText(paths.bin + "\\кмд.bat", bat);
		writeText(batShimPath(paths, "other"), batOther);
		writeText(shimFilePath(paths, "tool"), formatShimFile("..\\apps\\pkg\\1\\tool.exe", "pkg"));
		writeText(shimExePath(paths, "tool"), "MZ");
		writeText(paths.bin + "\\x.shim.bak", formatShimFile("..\\apps\\pkg\\1\\x.exe", "pkg"));

		std::vector<std::string> owned = shimsOwnedBy(paths, "pkg");
		check(owned.size() == 2 && ((owned[0] == "legacy" && owned[1] == "tool") || (owned[0] == "tool" && owned[1] == "legacy")),
			"shimsOwnedBy: tool.shim and legacy.bat only", std::to_string(owned.size()) + " shim(s)");

		// Владелец команды (DESIGN.md §7.4).
		std::string owner;
		check(readShimOwner(paths, "tool", owner) == ShimOwner::Package && owner == "pkg", "readShimOwner: .exe with .shim");
		check(readShimOwner(paths, "legacy", owner) == ShimOwner::Package && owner == "pkg", "readShimOwner: stage 1-2 .bat");
		check(readShimOwner(paths, "none", owner) == ShimOwner::None, "readShimOwner: nothing");
		writeText(shimExePath(paths, "lonely"), "MZ");
		check(readShimOwner(paths, "lonely", owner) == ShimOwner::Foreign, "readShimOwner: .exe without .shim is foreign");
		writeText(shimFilePath(paths, "half"), formatShimFile("..\\apps\\pkg\\1\\half.exe", "pkg"));
		check(readShimOwner(paths, "half", owner) == ShimOwner::Package && owner == "pkg", "readShimOwner: .shim without .exe is ours");
		writeText(shimFilePath(paths, "broken"), "garbage");
		check(readShimOwner(paths, "broken", owner) == ShimOwner::Foreign, "readShimOwner: broken .shim is foreign");
		writeText(shimFilePath(paths, "mixed"), formatShimFile("..\\apps\\pkg\\1\\mixed.exe", "pkg"));
		writeText(batShimPath(paths, "mixed"), batOther);
		check(readShimOwner(paths, "mixed", owner) == ShimOwner::Foreign, "readShimOwner: .shim and .bat of different packages");
		check(readShimOwner(paths, "flan", owner) == ShimOwner::Foreign && readShimOwner(paths, "FLAN", owner) == ShimOwner::Foreign,
			"readShimOwner: the name of flan itself");

		// Запись: эталон уже лежит (в тестах ресурса нет), команда — жёсткая ссылка на него;
		// своя .bat того же имени удаляется, чужая не трогается.
		std::string error;
		check(!writeShim(paths, "fresh", "..\\apps\\pkg\\1\\fresh.exe", "pkg", error) && !error.empty(),
			"writeShim without a reference and without the resource fails", error);
		writeText(shimReferencePath(paths), "MZ reference");
		writeText(batShimPath(paths, "legacy"), bat);
		check(writeShim(paths, "legacy", "..\\apps\\pkg\\2\\legacy.exe", "pkg", error), "writeShim", error);
		check(!pathExists(batShimPath(paths, "legacy")) && pathExists(shimExePath(paths, "legacy")), "writeShim replaces own .bat");

		const HANDLE link = CreateFileW(extendedPath(shimExePath(paths, "legacy")).c_str(), FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
		BY_HANDLE_FILE_INFORMATION info = {};
		const bool linked = link != INVALID_HANDLE_VALUE && GetFileInformationByHandle(link, &info) && info.nNumberOfLinks == 2;
		if (link != INVALID_HANDLE_VALUE) {
			CloseHandle(link);
		}
		check(linked, "the command is a hard link to .shim.exe");

		std::string text;
		std::vector<uint8_t> bytes;
		bool tooLarge = false;
		readWholeFile(shimFilePath(paths, "legacy"), 4096, bytes, tooLarge);
		check(std::string(bytes.begin(), bytes.end()) == formatShimFile("..\\apps\\pkg\\2\\legacy.exe", "pkg"), "writeShim: .shim content");

		check(removeShim(paths, "legacy", "pkg", error) && !pathExists(shimExePath(paths, "legacy")) &&
			!pathExists(shimFilePath(paths, "legacy")) && pathExists(shimReferencePath(paths)), "removeShim", error);
		check(!removeShim(paths, "other", "pkg", error) && pathExists(batShimPath(paths, "other")), "removeShim leaves another package's .bat", error);
		check(!removeShim(paths, "lonely", "pkg", error) && pathExists(shimExePath(paths, "lonely")), "removeShim leaves a foreign .exe", error);
		check(removeShim(paths, "absent", "pkg", error), "removeShim on a missing command");

		// tmp\ — перенесённые туда занятые прослойки; чистится целиком.
		createDirectory(paths.tmp);
		writeText(paths.tmp + "\\shim-1-2-3.exe", "MZ");
		cleanTemporary(paths);
		std::vector<DirEntry> left;
		check(listDirectory(extendedPath(paths.tmp), left) && left.empty(), "cleanTemporary");
		check(removeTree(root + "\\home") && !pathExists(root + "\\home"), "removeTree removes the surrogate name too");
	}
}

namespace {

	// Junction без прав администратора и без cmd.exe (mklink не понимает путей длиннее MAX_PATH):
	// каталог + точка повторного анализа IO_REPARSE_TAG_MOUNT_POINT. target — путь вида \\?\C:\…
	bool makeJunction(const std::wstring& link, const std::wstring& target) {
		if (!CreateDirectoryW(link.c_str(), NULL)) {
			return false;
		}

		const std::wstring substitute = L"\\??\\" + target.substr(4);		// \\?\C:\x -> \??\C:\x
		const std::wstring print = target.substr(4);
		const size_t subBytes = substitute.size() * sizeof(wchar_t);
		const size_t printBytes = print.size() * sizeof(wchar_t);

		// REPARSE_DATA_BUFFER для mount point: заголовок 8 байт, 4 смещения/длины, затем строки с '\0'.
		std::vector<uint8_t> buffer(8 + 8 + subBytes + 2 + printBytes + 2, 0);
		auto put16 = [&](size_t at, size_t value) { buffer[at] = (uint8_t)value; buffer[at + 1] = (uint8_t)(value >> 8); };
		const DWORD tag = IO_REPARSE_TAG_MOUNT_POINT;
		memcpy(buffer.data(), &tag, 4);
		put16(4, buffer.size() - 8);					// ReparseDataLength
		put16(8, 0);									// SubstituteNameOffset
		put16(10, subBytes);
		put16(12, subBytes + 2);						// PrintNameOffset
		put16(14, printBytes);
		memcpy(buffer.data() + 16, substitute.data(), subBytes);
		memcpy(buffer.data() + 16 + subBytes + 2, print.data(), printBytes);

		const HANDLE handle = CreateFileW(link.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			return false;
		}
		DWORD returned = 0;
		const bool ok = DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, buffer.data(), (DWORD)buffer.size(),
			NULL, 0, &returned, NULL) != 0;
		CloseHandle(handle);
		return ok;
	}

	bool writeFileW(const std::wstring& path, const char* text) {
		const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			return false;
		}
		DWORD written = 0;
		const bool ok = WriteFile(file, text, (DWORD)strlen(text), &written, NULL) != 0;
		CloseHandle(file);
		return ok;
	}

	bool existsW(const std::wstring& path) {
		return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
	}

	bool readOnlyW(const std::wstring& path) {
		const DWORD attributes = GetFileAttributesW(path.c_str());
		return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY);
	}

	// DESIGN.md §7.6, «Удаление дерева»: ссылки удаляются как ссылки, «только чтение» снимается.
	void testRemoveTree(const std::string& root) {
		const std::wstring base = extendedPath(root + "\\удаление");
		const std::wstring outside = base + L"\\снаружи";
		const std::wstring pkg = base + L"\\пакет";
		createDirectory(root + "\\удаление\\снаружи");
		createDirectory(root + "\\удаление\\пакет\\только чтение");

		writeFileW(outside + L"\\keep.txt", "keep");
		writeFileW(outside + L"\\hard.txt", "hard");
		writeFileW(pkg + L"\\a.txt", "a");
		writeFileW(pkg + L"\\только чтение\\b.txt", "b");
		writeFileW(pkg + L"\\name" + std::wstring(1, (wchar_t)0xDC00) + L".txt", "surrogate");
		SetFileAttributesW((pkg + L"\\a.txt").c_str(), FILE_ATTRIBUTE_READONLY);
		SetFileAttributesW((pkg + L"\\только чтение\\b.txt").c_str(), FILE_ATTRIBUTE_READONLY);
		SetFileAttributesW((pkg + L"\\только чтение").c_str(), FILE_ATTRIBUTE_READONLY);

		const bool junction = makeJunction(pkg + L"\\ссылка", outside);
		check(junction && existsW(pkg + L"\\ссылка\\keep.txt"), "a junction to a folder outside the tree");
		check(CreateHardLinkW((pkg + L"\\hard.txt").c_str(), (outside + L"\\hard.txt").c_str(), NULL) != 0,
			"a hard link to a file outside the tree");

		// Занятость: файл, открытый без совместной записи, — занят; у файла «только чтение»
		// атрибут на время проверки снимается и возвращается.
		check(!treeInUse(pkg), "treeInUse: nothing open");
		check(readOnlyW(pkg + L"\\a.txt"), "treeInUse keeps the read-only attribute");

		HANDLE held = CreateFileW((pkg + L"\\только чтение\\b.txt").c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, 0, NULL);
		check(held != INVALID_HANDLE_VALUE && treeInUse(pkg), "treeInUse: a read-only file held open is busy");
		check(readOnlyW(pkg + L"\\только чтение\\b.txt"), "treeInUse restores the read-only attribute");
		if (held != INVALID_HANDLE_VALUE) {
			CloseHandle(held);
		}

		held = CreateFileW((outside + L"\\keep.txt").c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		check(!treeInUse(pkg), "treeInUse does not follow the junction");
		if (held != INVALID_HANDLE_VALUE) {
			CloseHandle(held);
		}

		check(removeTreeW(pkg) && !existsW(pkg), "removeTree: read-only files and folders, surrogate name, links");
		check(existsW(outside + L"\\keep.txt") && existsW(outside + L"\\hard.txt"), "removeTree leaves link targets alone");
		check(removeTreeW(pkg), "removeTree: a missing path is already removed");

		// Занятый файл: удаляется всё остальное, а итог — false.
		createDirectory(root + "\\удаление\\занят");
		const std::wstring busy = base + L"\\занят";
		writeFileW(busy + L"\\open.txt", "open");
		writeFileW(busy + L"\\free.txt", "free");
		held = CreateFileW((busy + L"\\open.txt").c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		check(!removeTreeW(busy) && existsW(busy + L"\\open.txt") && !existsW(busy + L"\\free.txt"),
			"removeTree: reports a busy file and removes the rest");
		if (held != INVALID_HANDLE_VALUE) {
			CloseHandle(held);
		}

		check(removeTreeW(base) && !existsW(base), "removeTree: cleanup");
	}
}

void runFsTests() {
	beginSuite("fs");
	testPathsAndHome();

	const std::string root = makeTestRoot();
	check(!root.empty() && root.size() > 260, "test root is longer than MAX_PATH");
	if (root.empty()) {
		return;
	}

	testFileOperations(root);
	testDirectoryWalks(root);
	testRemoveTree(root);

	// Корень тестов — каталог flan-tests-<pid> во временной папке.
	const std::string top = root.substr(0, root.find("\\Проверка flan"));
	check(removeTree(top) && !pathExists(top), "removeTree: test root");
}
