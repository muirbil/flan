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
