#include "utils/fileSystem.hpp"
#include <iostream>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <shlobj.h>

std::string getUserDirectory() {

    char user_path[MAX_PATH];

    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, SHGFP_TYPE_CURRENT,
        user_path))) {
        return std::string(user_path) + "\\.flan";
    }

    else {
        std::cerr << "Failed to get user directory." << std::endl;
        return "";
    }
}

bool createDirectory(const char* fullPath) {

    // Segmentation Faults
    if (fullPath == nullptr || fullPath[0] == '\0') {
        return false;
    }

    std::string pathCopy(fullPath);

    for (size_t i = 3; i < pathCopy.length(); i++) {
        if (pathCopy[i] == '\\') {
            pathCopy[i] = '\0';
            CreateDirectoryA(pathCopy.c_str(), NULL);
            pathCopy[i] = '\\';
        }
    }

    CreateDirectoryA(pathCopy.c_str(), NULL);

    return true;
}

bool deleteFile(const char* fullPath) {
    if (fullPath == nullptr || fullPath[0] == '\0') {
        return false;
    }
    return DeleteFileA(fullPath) != 0;
}