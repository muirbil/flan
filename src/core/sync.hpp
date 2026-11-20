#pragma once

#include <string>
#include "core/exit_code.hpp"
#include "core/paths.hpp"
#include "flan/index.hpp"

// flan sync: скачать индекс (или скопировать из локального FLAN_REPO) и принять его
// по шагам DESIGN.md §6.1. Старый state\index.flan заменяется только проверенным файлом.
ExitCode syncIndex(const FlanPaths& paths);

// Уже принятый локальный индекс. Границы проверяются при каждом открытии;
// строки записей — при чтении конкретной записи (DESIGN.md §6.2).
bool loadLocalIndex(const FlanPaths& paths, IndexView& view, std::string& error);

// unix-время -> "2026-11-21 12:00 UTC" для вывода.
std::string formatUnixTime(uint64_t seconds);
