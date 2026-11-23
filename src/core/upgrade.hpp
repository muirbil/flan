#pragma once

#include <string>
#include <vector>
#include "core/exit_code.hpp"
#include "core/paths.hpp"
#include "flan/validate.hpp"

// flan upgrade [pkg…] (DESIGN.md §7.7). Без аргументов — все установленные пакеты с другим sha256 в индексе
// и последним — сам flan; с аргументами — указанные (flan среди них — тоже последним). Каждый пакет —
// транзакция installPackage; сбой одного не останавливает остальные, код возврата — первой неудачи.
// Вызывается под блокировкой.
ExitCode upgradePackages(const FlanPaths& paths, const std::vector<std::string>& requested);

// Версия из вывода `flan --version` ("flan 0.4.0 (x64)"); пусто — строка не такая.
inline std::string parseVersionLine(const std::string& output) {
	// "flan <версия> (<архитектура>)" первой строкой.
	std::string line = output.substr(0, output.find('\n'));
	if (!line.empty() && line.back() == '\r') {
		line.pop_back();
	}
	const std::string prefix = "flan ";
	if (line.compare(0, prefix.size(), prefix) != 0) {
		return std::string();
	}
	const size_t space = line.find(' ', prefix.size());
	if (space == std::string::npos || line.size() < space + 3 || line[space + 1] != '(' || line.back() != ')') {
		return std::string();
	}
	const std::string version = line.substr(prefix.size(), space - prefix.size());
	return isSafeName(version) ? version : std::string();
}
