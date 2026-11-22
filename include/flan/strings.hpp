#pragma once

#include <string>
#include <windows.h>

// UTF-8 -> UTF-16. Нужен и сети, и запуску процессов, поэтому вынесен в общий заголовок.
inline std::wstring s2ws(const std::string& s) {
	if (s.empty()) return std::wstring();

	const int size_needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), NULL, 0);
	if (size_needed <= 0) return std::wstring();

	std::wstring result(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &result[0], size_needed);
	return result;
}

// UTF-16 -> UTF-8, строго: невалидный UTF-16 (непарный суррогат) — false, а не '?'.
// Имена из обхода каталогов сюда не попадают никогда (DESIGN.md §7.1): для них — asciiName.
inline bool toUtf8(const std::wstring& s, std::string& out) {
	out.clear();
	if (s.empty()) return true;

	const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), (int)s.size(), NULL, 0, NULL, NULL);
	if (size <= 0) return false;

	out.resize(size);
	return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), (int)s.size(), &out[0], size, NULL, NULL) == size;
}
