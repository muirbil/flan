#pragma once

// Общее для shim.exe (без CRT) и тестов: где в командной строке кончается argv[0].
// Правило то же, что у CommandLineToArgvW для имени программы: в кавычках — до следующей
// кавычки, без них — до первого пробела или табуляции. Хвост (вместе с ведущим пробелом)
// прослойка передаёт программе байт в байт, без повторного разбора (DESIGN.md §7.4).
inline const wchar_t* shimSkipArgv0(const wchar_t* line) {
	const wchar_t* p = line;
	if (*p == L'"') {
		p++;
		while (*p != L'\0' && *p != L'"') {
			p++;
		}
		if (*p == L'"') {
			p++;
		}
	}
	else {
		while (*p != L'\0' && *p != L' ' && *p != L'\t') {
			p++;
		}
	}
	return p;
}
