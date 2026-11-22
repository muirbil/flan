#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Слой файловой системы (DESIGN.md §7.1). Пути снаружи — UTF-8; в UTF-16 с префиксом \\?\
// их переводит extendedPath прямо перед вызовом W-функции. A-функций в клиенте нет.

// UTF-8 путь -> UTF-16 для W-функций: абсолютный, с '\' вместо '/', без "." и "..",
// с префиксом \\?\ (сетевой путь — \\?\UNC\). Уже начинающийся с \\?\ путь не меняется.
std::wstring extendedPath(const std::string& path);

// То же без префикса \\?\ — для внешних программ (tar.exe), которые его не понимают.
std::wstring fullPath(const std::string& path);

// Корень flan (DESIGN.md §7.1): FLAN_HOME или %USERPROFILE%\.flan.
bool resolveFlanHome(std::string& home, std::string& error);

// Проверка и нормализация значения FLAN_HOME: абсолютный путь (X:\… или \\server\share\…),
// '/' -> '\', без "." и "..", без завершающего '\'. Отдельно от resolveFlanHome — ради тестов.
bool parseFlanHome(const std::string& value, std::string& home, std::string& error);

bool createDirectory(const std::string& path);
bool deleteFile(const std::string& path);
bool pathExists(const std::string& path);

// MoveFileExW с MOVEFILE_WRITE_THROUGH; replace — с MOVEFILE_REPLACE_EXISTING.
bool moveFile(const std::string& from, const std::string& to, bool replace);
bool copyFile(const std::string& from, const std::string& to, bool overwrite);

// Файл целиком, но не больше limit байт: размер проверяется до чтения,
// поэтому огромный файл не попадает в память. tooLarge различает «больше limit» и «не прочитать».
bool readWholeFile(const std::string& path, uint64_t limit, std::vector<uint8_t>& out, bool& tooLarge);

// Атомарная запись: <path>.tmp, затем MoveFileExW с заменой. Читатель без блокировки
// видит либо старый файл, либо новый, но не половину (DESIGN.md §7.6).
bool saveFileAtomically(const std::string& path, const std::string& data);

bool isDirectory(const std::string& path);
bool isRegularFile(const std::string& path);

// Размер файла; false — файла нет или он недоступен.
bool fileSize(const std::string& path, uint64_t& size);

// Сколько байт доступно текущему пользователю на томе, где лежит каталог.
bool freeDiskSpace(const std::string& directory, uint64_t& bytes);

// Обход каталога (DESIGN.md §7.1): только шаблон "*", FindExInfoBasic; "." и ".." пропускаются.
// Имена — UTF-16 как есть: в UTF-8 они не переводятся никогда.
struct DirEntry {
	std::wstring name;
	uint32_t attributes = 0;
};
bool listDirectory(const std::wstring& dir, std::vector<DirEntry>& entries);

// Имя из обхода -> строка, только если оно целиком из печатных ASCII-символов. Дальше вызывающий
// проверяет его белым списком (isSafePackageName, isSafeName); прочие имена пропускаются.
bool asciiName(const std::wstring& name, std::string& out);

// Удаление дерева и проверка занятости — целиком на UTF-16 (DESIGN.md §7.1, §7.6).
// false — что-то осталось (обычно занятый файл).
bool removeTree(const std::string& path);
bool removeTreeW(const std::wstring& path);

// Занят ли хоть один файл в дереве (DESIGN.md §7.6, «Занятость каталога»).
bool treeInUse(const std::wstring& dir);

bool extractArchive(const std::string& archivePath, const std::string& destinationDir);

// Имена внутри архива — через тот же System32\tar.exe, которым клиент распаковывает.
// Нужно генератору, чтобы до публикации убедиться, что extract_dir и bin в архиве есть.
bool listArchive(const std::string& archivePath, std::vector<std::string>& entries);
