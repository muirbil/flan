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

// Длина пути запуска команд (§7.1, §7.8). Windows не запускает .exe по обычному пути в 260 символов
// UTF-16 и длиннее, а оболочки префикс \\?\ не ставят. «Приближается» — на имя команды длиннее
// нынешних остаётся меньше LAUNCH_PATH_MARGIN символов.
constexpr size_t LAUNCH_PATH_LIMIT = 260;
constexpr size_t LAUNCH_PATH_MARGIN = 20;

enum class LaunchRoom { Enough, Tight, TooLong };

// Длина bin\<command>.exe в символах UTF-16.
size_t launchPathLength(const std::wstring& bin, const std::string& command);
LaunchRoom launchRoom(size_t length);

// Самое длинное имя команды, которое ещё запустится из bin\ (0 — никакое).
size_t longestLaunchableName(const std::wstring& bin);
