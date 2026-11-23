#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "test.hpp"
#include "core/setup.hpp"
#include "core/upgrade.hpp"
#include <string>

// Правка PATH для flan setup (DESIGN.md §7.8): значение любой длины, остальное — байт в байт.
void runSetupTests() {
	beginSuite("setup");

	const std::wstring bin = L"C:\\Users\\Проверка\\.flan\\bin";
	SetEnvironmentVariableW(L"FLAN_TEST_PROFILE", L"C:\\Users\\Проверка");

	check(pathSegmentMatches(L"C:\\Users\\Проверка\\.flan\\bin", bin), "segment: exact");
	check(pathSegmentMatches(L"c:\\users\\ПРОВЕРКА\\.FLAN\\BIN", bin), "segment: ignoring case (Cyrillic too)");
	check(pathSegmentMatches(L"C:\\Users\\Проверка\\.flan\\bin\\", bin), "segment: trailing backslash");
	check(pathSegmentMatches(L"\"C:\\Users\\Проверка\\.flan\\bin\"", bin), "segment: quoted");
	check(pathSegmentMatches(L"%FLAN_TEST_PROFILE%\\.flan\\bin", bin), "segment: %VAR% expanded");
	check(!pathSegmentMatches(L"C:\\Users\\Проверка\\.flan\\bin2", bin), "segment: a longer name is not it");
	check(!pathSegmentMatches(L"C:\\Users\\Проверка\\.flan", bin), "segment: the parent is not it");
	check(!pathSegmentMatches(L"", bin), "segment: empty");

	check(pathHasDir(L"C:\\a;C:\\Users\\Проверка\\.flan\\bin\\;C:\\b", bin), "pathHasDir: in the middle");
	check(!pathHasDir(L"C:\\a;;C:\\b;", bin), "pathHasDir: absent, with empty segments");
	check(!pathHasDir(L"", bin), "pathHasDir: empty value");

	check(pathWithEntry(L"", L"X") == L"X", "pathWithEntry: empty value");
	check(pathWithEntry(L"C:\\a", L"X") == L"C:\\a;X", "pathWithEntry: plain");
	check(pathWithEntry(L"C:\\a;", L"X") == L"C:\\a;X", "pathWithEntry: value ending with ';'");

	size_t removed = 0;
	check(pathWithoutDir(L"C:\\a;C:\\Users\\Проверка\\.flan\\bin;C:\\b", bin, removed) == L"C:\\a;C:\\b" && removed == 1,
		"pathWithoutDir: in the middle");
	check(pathWithoutDir(L"%FLAN_TEST_PROFILE%\\.flan\\bin;C:\\b", bin, removed) == L"C:\\b" && removed == 1,
		"pathWithoutDir: first, as %VAR%");
	check(pathWithoutDir(L"C:\\a;;C:\\Users\\Проверка\\.flan\\bin\\;", bin, removed) == L"C:\\a;;" && removed == 1,
		"pathWithoutDir: keeps empty segments and the trailing ';'");
	check(pathWithoutDir(L"C:\\Users\\Проверка\\.flan\\bin;C:\\x;\"C:\\Users\\Проверка\\.flan\\bin\"", bin, removed) == L"C:\\x" &&
		removed == 2, "pathWithoutDir: every match");
	const std::wstring untouched = L"C:\\a;;C:\\b; C:\\c ;";
	check(pathWithoutDir(untouched, bin, removed) == untouched && removed == 0, "pathWithoutDir: nothing to remove");
	check(pathWithoutDir(L"C:\\Users\\Проверка\\.flan\\bin", bin, removed).empty() && removed == 1, "pathWithoutDir: the only entry");

	// Длиннее 2047 символов (такой PATH окно «Переменные среды» уже не сохраняет).
	std::wstring longPath;
	for (int i = 0; longPath.size() < 3000; i++) {
		longPath += L"C:\\Program Files\\Some Vendor\\Tool " + std::to_wstring(i) + L"\\bin;";
	}
	longPath += L"%SystemRoot%\\system32";
	check(longPath.size() > 2047, "the long PATH is longer than 2047 characters");
	check(!pathHasDir(longPath, bin), "long PATH: absent");
	const std::wstring entry = L"%FLAN_TEST_PROFILE%\\.flan\\bin";
	const std::wstring added = pathWithEntry(longPath, entry);
	check(added == longPath + L";" + entry, "long PATH: appended at the end only");
	check(pathHasDir(added, bin), "long PATH: found after adding");
	check(pathWithoutDir(added, bin, removed) == longPath && removed == 1, "long PATH: removing gives back the original byte for byte");

	SetEnvironmentVariableW(L"FLAN_TEST_PROFILE", NULL);

	// Путь запуска (§7.8, «Длинный путь bin\»): длина в символах UTF-16, предел — 259 включительно.
	check(launchPathLength(bin, "rg") == bin.size() + 7, "launch path: bin\\rg.exe", std::to_string(launchPathLength(bin, "rg")));
	check(launchRoom(LAUNCH_PATH_LIMIT - LAUNCH_PATH_MARGIN - 1) == LaunchRoom::Enough, "launch room: 239 is enough");
	check(launchRoom(LAUNCH_PATH_LIMIT - LAUNCH_PATH_MARGIN) == LaunchRoom::Tight, "launch room: 240 is tight");
	check(launchRoom(LAUNCH_PATH_LIMIT - 1) == LaunchRoom::Tight, "launch room: 259 still starts");
	check(launchRoom(LAUNCH_PATH_LIMIT) == LaunchRoom::TooLong, "launch room: 260 does not start");

	// Кириллица считается символами UTF-16, а не байтами UTF-8.
	std::wstring deep = L"C:\\Проверка";
	while (deep.size() < 240) {
		deep += L"\\длинный каталог";
	}
	const std::wstring deepBin = deep.substr(0, 240);
	check(launchPathLength(deepBin, "rg") == 247, "launch path: Cyrillic counted in UTF-16 units");
	check(longestLaunchableName(deepBin) == 14 && launchPathLength(deepBin, std::string(14, 'a')) == LAUNCH_PATH_LIMIT - 1,
		"longest launchable name: exactly up to 259", std::to_string(longestLaunchableName(deepBin)));
	check(longestLaunchableName(std::wstring(254, L'x')) == 0, "longest launchable name: none when bin\\ is too long");
	check(longestLaunchableName(std::wstring(253, L'x')) == 1, "longest launchable name: one character left");

	// Вывод `flan.exe.new --version` при самообновлении (§7.9, шаг 3).
	beginSuite("version line");
	check(parseVersionLine("flan 0.4.0 (x64)\r\n") == "0.4.0", "console line with CRLF");
	check(parseVersionLine("flan 0.4.1 (x86)") == "0.4.1", "without a line break");
	check(parseVersionLine("flan 1.0.0-rc1 (x64)\nextra\n") == "1.0.0-rc1", "only the first line counts");
	check(parseVersionLine("Flan 0.4.0 (x64)").empty(), "wrong case of the name");
	check(parseVersionLine("flan 0.4.0").empty(), "no architecture");
	check(parseVersionLine("flan 0.4.0 x64").empty(), "architecture without parentheses");
	check(parseVersionLine("flan .. (x64)").empty(), "unsafe version");
	check(parseVersionLine("Usage: flan <command> [options]").empty(), "usage text");
	check(parseVersionLine("").empty(), "empty output");
}
