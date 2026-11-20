#pragma once

#include <string>
#include <vector>
#include "core/paths.hpp"

// .bat-прослойки этапов 1–2 (DESIGN.md §12). Вторая строка — "rem package=<name>":
// по ней установка видит конфликт с чужим пакетом, а uninstall не трогает чужие прослойки.
// На этапе 3 их заменят shim.exe и .shim-файлы (§7.4).

enum class ShimOwner {
	None,												// прослойки нет
	Package,											// прослойка flan, владелец — в owner
	Foreign,											// файл есть, но создан не flan (или повреждён)
};

std::string formatShim(const std::string& targetExe, const std::string& package);
ShimOwner parseShimOwner(const std::string& text, std::string& owner);

std::string shimPath(const FlanPaths& paths, const std::string& command);
ShimOwner readShimOwner(const FlanPaths& paths, const std::string& command, std::string& owner);
bool writeShim(const FlanPaths& paths, const std::string& command, const std::string& targetExe, const std::string& package);

// Имена команд всех прослоек, принадлежащих пакету.
std::vector<std::string> shimsOwnedBy(const FlanPaths& paths, const std::string& package);
