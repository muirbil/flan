#pragma once

#include <string>
#include "core/exit_code.hpp"
#include "core/paths.hpp"

// Транзакция установки / обновления (DESIGN.md §7.6). Вызывается под блокировкой.
ExitCode installPackage(const FlanPaths& paths, const std::string& requestedName);

// Удаление: прослойки пакета, квитанция, затем каталог apps\<name>\ целиком.
// Вызывается под блокировкой.
ExitCode uninstallPackage(const FlanPaths& paths, const std::string& requestedName);

// state\pending-delete: каталоги, которые не удалось удалить, потому что программа
// из них была запущена. Строка — "<name>\<dir>" или "<name>" (весь пакет) относительно apps\.
void addPendingDelete(const FlanPaths& paths, const std::string& entry);

// Повторяет отложенные удаления; вызывается в начале каждой команды под блокировкой.
void processPendingDeletes(const FlanPaths& paths);

// Удаляет дерево каталогов целиком; false — что-то осталось (обычно занятый файл).
bool removeTree(const std::string& path);

// Удаляет каталог версии, только если в нём ничего не занято; иначе не трогает вовсе
// (DESIGN.md §7.6, шаг 9: «оставить»). Удалять по частям нельзя: у работающей программы
// пропали бы её незаблокированные файлы — например, .py рядом с python.exe.
bool removeTreeIfUnused(const std::string& path);
