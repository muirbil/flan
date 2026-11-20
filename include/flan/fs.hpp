#pragma once
#include <cstdint>
#include <string>
#include <vector>

std::string getUserDirectory();
bool createDirectory(const char* fullPath);
bool deleteFile(const char* fullPath);

// Файл целиком, но не больше limit байт: размер проверяется до чтения,
// поэтому огромный файл не попадает в память. tooLarge различает «больше limit» и «не прочитать».
bool readWholeFile(const std::string& path, uint64_t limit, std::vector<uint8_t>& out, bool& tooLarge);

// Атомарная запись: <path>.tmp, затем MoveFileExA с заменой. Читатель без блокировки
// видит либо старый файл, либо новый, но не половину (DESIGN.md §7.6).
bool saveFileAtomically(const std::string& path, const std::string& data);

bool isDirectory(const std::string& path);
bool isRegularFile(const std::string& path);
bool extractArchive(const std::string& archivePath, const std::string& destinationDir);

// Имена внутри архива — через тот же System32\tar.exe, которым клиент распаковывает.
// Нужно генератору, чтобы до публикации убедиться, что extract_dir и bin в архиве есть.
bool listArchive(const std::string& archivePath, std::vector<std::string>& entries);
