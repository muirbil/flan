#pragma once

#include <string>
#include "core/exit_code.hpp"
#include "core/paths.hpp"
#include "flan/index.hpp"

// Шаг 1 транзакции (DESIGN.md §7.6): сборка для архитектуры ОС (на x64 — x64, иначе x86).
// Ok; NotFound; Integrity — индекс повреждён; Error — архитектура не поддерживается. error — для вывода.
ExitCode findBuildForThisSystem(const IndexView& index, const std::string& name, IndexRecord& entry, std::string& error);

// Шаг 3 (DESIGN.md §7.6, §7.2): файл пакета в cache\<sha256>. Готовый и целый — без сети; иначе загрузка
// в cache\<sha256>.part с Range от уже скачанного, с хэшем на лету, не больше archive_size. Если после
// докачки хэш не сошёлся — один раз заново целиком. Сообщения печатает сам.
ExitCode fetchArchive(const FlanPaths& paths, const IndexRecord& entry, const std::string& sha256,
	const std::string& label, std::string& archive);

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

// Удаляет каталог версии, только если в нём ничего не занято; иначе не трогает вовсе
// (DESIGN.md §7.6, шаг 9: «оставить»). Удалять по частям нельзя: у работающей программы
// пропали бы её незаблокированные файлы — например, .py рядом с python.exe.
bool removeTreeIfUnused(const std::string& path);
