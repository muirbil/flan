#define WIN32_LEAN_AND_MEAN

#include <shlobj.h>
#include "utils/fileSystem.hpp"
#include "utils/strings.hpp"
#include <iostream>
#include <string>
#include <vector>

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

    // CreateDirectoryA возвращает FALSE и на уже существующем каталоге,
    // поэтому успехом считаем сам факт наличия директории.
    const DWORD attributes = GetFileAttributesA(pathCopy.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool deleteFile(const char* fullPath) {
    if (fullPath == nullptr || fullPath[0] == '\0') {
        return false;
    }
    return DeleteFileA(fullPath) != 0;
}

bool extractArchive(const std::string& archivePath, const std::string& destinationDir) {

    // Путь к tar.exe задаётся явно. Через system() строка уходила в cmd.exe, который
    // ищет исполняемый файл сначала в текущем каталоге: подложенный рядом tar.exe
    // выполнился бы вместо системного.
    wchar_t systemDir[MAX_PATH];
    const UINT systemDirLength = GetSystemDirectoryW(systemDir, MAX_PATH);
    if (systemDirLength == 0 || systemDirLength >= MAX_PATH) {
        std::cerr << "Error: could not locate the system directory." << std::endl;
        return false;
    }

    const std::wstring tarPath = std::wstring(systemDir) + L"\\tar.exe";

    // Командная строка собирается для процесса напрямую, без оболочки,
    // поэтому '&', '|' и прочая метасимволика в путях смысла не имеет.
    const std::wstring commandLine =
        L"\"" + tarPath + L"\" -xf \"" + s2ws(archivePath) + L"\" -C \"" + s2ws(destinationDir) + L"\"";

    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startupInfo = {};
    startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo = {};

    if (!CreateProcessW(tarPath.c_str(), mutableCommandLine.data(), NULL, NULL, FALSE,
        0, NULL, NULL, &startupInfo, &processInfo)) {
        std::cerr << "Error: failed to launch tar.exe (code " << GetLastError() << ")." << std::endl;
        return false;
    }

    WaitForSingleObject(processInfo.hProcess, INFINITE);

    DWORD exitCode = 1;
    GetExitCodeProcess(processInfo.hProcess, &exitCode);

    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    if (exitCode != 0) {
        std::cerr << "Error: tar exited with code " << exitCode << "." << std::endl;
        return false;
    }

    return true;
}
