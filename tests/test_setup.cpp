#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "test.hpp"
#include "core/setup.hpp"
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
}
