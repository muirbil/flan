#pragma once
#include <string>

std::string getUserDirectory();
bool createDirectory(const char* fullPath);
bool deleteFile(const char* fullPath);
bool extractArchive(const std::string& archivePath, const std::string& destinationDir);
