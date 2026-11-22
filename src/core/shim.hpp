#pragma once

#include <string>
#include <vector>
#include "core/paths.hpp"

// Прослойки (DESIGN.md §7.4): bin\<cmd>.exe — жёсткая ссылка на эталон bin\.shim.exe (на не-NTFS
// и после 1023 ссылок — копия), bin\<cmd>.shim — куда вести и чья команда:
//   target=..\apps\ripgrep\15.2.0\rg.exe
//   package=ripgrep
// .bat этапов 1–2 больше не создаются; их код — только чтение и переход: .bat своего пакета
// считается его прослойкой и удаляется при установке и удалении.

enum class ShimOwner {
	None,												// прослойки нет
	Package,											// прослойка flan, владелец — в owner
	Foreign,											// файл есть, но создан не flan (или повреждён)
};

std::string formatShimFile(const std::string& target, const std::string& package);
bool parseShimFile(const std::string& text, std::string& target, std::string& package);

// Владелец .bat-прослойки этапов 1–2: вторая строка "rem package=<name>".
ShimOwner parseBatOwner(const std::string& text, std::string& owner);

std::string shimExePath(const FlanPaths& paths, const std::string& command);
std::string shimFilePath(const FlanPaths& paths, const std::string& command);
std::string batShimPath(const FlanPaths& paths, const std::string& command);
std::string shimReferencePath(const FlanPaths& paths);

// Кому принадлежит команда: .exe с .shim, .shim без .exe (прерванная запись — тоже наша) и .bat
// этапов 1–2. bin\<cmd>.exe без .shim, имя самого flan и расхождение владельцев — Foreign.
ShimOwner readShimOwner(const FlanPaths& paths, const std::string& command, std::string& owner);

// target — путь программы относительно bin\. Сначала атомарно пишется .shim, потом ссылка:
// оборвалось между ними — .shim без .exe остаётся нашим, а не чужим. Своя .bat удаляется.
bool writeShim(const FlanPaths& paths, const std::string& command, const std::string& target,
	const std::string& package, std::string& error);

// Удаляет прослойку пакета package: .exe (занятый работающей программой — переносит в tmp\), затем .shim
// и свою .bat. .shim удаляется после .exe: пока .exe на месте, команда остаётся нашей. Команду другого
// владельца не трогает вовсе (false с объяснением).
bool removeShim(const FlanPaths& paths, const std::string& command, const std::string& package, std::string& error);

// Занятый работающей программой .exe (удалить нельзя, переименовать можно) — в tmp\ под уникальным
// именем; его удалит cleanTemporary при следующей меняющей команде.
bool moveAside(const FlanPaths& paths, const std::string& path);

// Имена команд всех прослоек пакета (и .exe, и .bat).
std::vector<std::string> shimsOwnedBy(const FlanPaths& paths, const std::string& package);

// Эталон прослойки — ресурс работающего flan.exe. false — ресурса нет (например, в тестах).
bool embeddedShim(const void*& data, size_t& size);

// bin\.shim.exe из ресурса, если его ещё нет. Обновляет эталон только flan setup (§7.4).
bool ensureShimReference(const FlanPaths& paths, std::string& error);

// tmp\ — перенесённые туда занятые прослойки. Вызывается в начале меняющей команды под блокировкой.
void cleanTemporary(const FlanPaths& paths);
