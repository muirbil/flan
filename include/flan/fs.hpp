#pragma once
#include <string>
#include <vector>

std::string getUserDirectory();
bool createDirectory(const char* fullPath);
bool deleteFile(const char* fullPath);
bool extractArchive(const std::string& archivePath, const std::string& destinationDir);

// Имена внутри архива — через тот же System32\tar.exe, которым клиент распаковывает.
// Нужно генератору, чтобы до публикации убедиться, что extract_dir и bin в архиве есть.
bool listArchive(const std::string& archivePath, std::vector<std::string>& entries);
