#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
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

		// Прослойки: обход по "*", окончание .bat проверяется в коде. rg.batch с коротким
		// именем RG~1.BAT и кириллическая команда — не прослойки.
		writeText(shimPath(paths, "real"), formatShim("C:\\x\\real.exe", "pkg"));
		writeText(paths.bin + "\\rg.batch", formatShim("C:\\x\\rg.exe", "pkg"));
		writeText(paths.bin + "\\кмд.bat", formatShim("C:\\x\\k.exe", "pkg"));
		writeText(shimPath(paths, "other"), formatShim("C:\\x\\other.exe", "another"));

		const std::vector<std::string> owned = shimsOwnedBy(paths, "pkg");
		check(owned.size() == 1 && owned[0] == "real", "shimsOwnedBy: only real.bat",
			std::to_string(owned.size()) + " shim(s)");

		check(removeTree(root + "\\home") && !pathExists(root + "\\home"), "removeTree removes the surrogate name too");
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

	// Корень тестов — каталог flan-tests-<pid> во временной папке.
	const std::string top = root.substr(0, root.find("\\Проверка flan"));
	check(removeTree(top) && !pathExists(top), "removeTree: test root");
}
