#pragma once

#include <string>
#include "core/exit_code.hpp"
#include "core/paths.hpp"

// flan setup (DESIGN.md §7.8): bin\ в PATH пользователя, копия себя в bin\flan.exe, обновление эталона
// прослоек и переход с .bat. --remove — убрать bin\ из PATH (файлы не трогаются). Под блокировкой.
ExitCode runSetup(const FlanPaths& paths, bool remove);

// Правка значения PATH — отдельно от реестра, ради тестов. Всё в UTF-16: значение сохраняется
// байт в байт, кроме добавленного или удалённых сегментов.

// Сегмент PATH указывает на dir: обрамляющие кавычки снимаются, %…% раскрываются,
// завершающие '\' отбрасываются, сравнение — без учёта регистра.
bool pathSegmentMatches(const std::wstring& segment, const std::wstring& dir);
bool pathHasDir(const std::wstring& value, const std::wstring& dir);

// value + ";" + entry (без лишнего ';', если value пуст или уже кончается на ';').
std::wstring pathWithEntry(const std::wstring& value, const std::wstring& entry);

// value без всех сегментов, указывающих на dir; removed — сколько убрано.
std::wstring pathWithoutDir(const std::wstring& value, const std::wstring& dir, size_t& removed);
