#define WIN32_LEAN_AND_MEAN

#include <shlobj.h>
#include "flan/fs.hpp"
#include "flan/strings.hpp"
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

bool readWholeFile(const std::string& path, uint64_t limit, std::vector<uint8_t>& out, bool& tooLarge) {
    out.clear();
    tooLarge = false;

    const HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0) {
        CloseHandle(file);
        return false;
    }

    if ((uint64_t)size.QuadPart > limit) {
        tooLarge = true;
        CloseHandle(file);
        return false;
    }

    out.resize((size_t)size.QuadPart);

    size_t done = 0;
    while (done < out.size()) {
        const DWORD chunk = (DWORD)((out.size() - done) > (1u << 20) ? (1u << 20) : (out.size() - done));
        DWORD read = 0;
        if (!ReadFile(file, out.data() + done, chunk, &read, NULL) || read == 0) {
            CloseHandle(file);
            out.clear();
            return false;
        }
        done += read;
    }

    CloseHandle(file);
    return true;
}

bool saveFileAtomically(const std::string& path, const std::string& data) {
    const std::string temporary = path + ".tmp";

    const HANDLE file = CreateFileA(temporary.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    size_t done = 0;
    bool ok = true;
    while (ok && done < data.size()) {
        const DWORD chunk = (DWORD)((data.size() - done) > (1u << 20) ? (1u << 20) : (data.size() - done));
        DWORD written = 0;
        ok = WriteFile(file, data.data() + done, chunk, &written, NULL) && written == chunk;
        done += written;
    }

    // Данные должны быть на диске до переименования: иначе после сбоя питания
    // на месте файла может оказаться пустышка с правильным именем.
    ok = ok && FlushFileBuffers(file);
    CloseHandle(file);

    if (!ok || !MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileA(temporary.c_str());
        return false;
    }
    return true;
}

bool isDirectory(const std::string& path) {
    const DWORD attributes = GetFileAttributesA(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool isRegularFile(const std::string& path) {
    const DWORD attributes = GetFileAttributesA(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

namespace {

    // Путь к tar.exe задаётся явно. Через system() строка уходила в cmd.exe, который
    // ищет исполняемый файл сначала в текущем каталоге: подложенный рядом tar.exe
    // выполнился бы вместо системного.
    bool systemTarPath(std::wstring& tarPath) {
        wchar_t systemDir[MAX_PATH];
        const UINT systemDirLength = GetSystemDirectoryW(systemDir, MAX_PATH);
        if (systemDirLength == 0 || systemDirLength >= MAX_PATH) {
            std::cerr << "Error: could not locate the system directory." << std::endl;
            return false;
        }

        tarPath = std::wstring(systemDir) + L"\\tar.exe";
        return true;
    }

    // Список имён архива длиннее этого — заведомо не тот архив, который мы проверяем.
    constexpr size_t MAX_LISTING_SIZE = 64 * 1024 * 1024;
}

bool extractArchive(const std::string& archivePath, const std::string& destinationDir) {

    std::wstring tarPath;
    if (!systemTarPath(tarPath)) {
        return false;
    }

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

bool listArchive(const std::string& archivePath, std::vector<std::string>& entries) {
    entries.clear();

    std::wstring tarPath;
    if (!systemTarPath(tarPath)) {
        return false;
    }

    // Вывод tar.exe читаем через анонимный канал. Наследуется только конец для записи,
    // а свой конец для чтения закрыт от наследования, иначе ReadFile не дождался бы EOF.
    SECURITY_ATTRIBUTES pipeAttributes = {};
    pipeAttributes.nLength = sizeof(pipeAttributes);
    pipeAttributes.bInheritHandle = TRUE;

    HANDLE readEnd = NULL;
    HANDLE writeEnd = NULL;
    if (!CreatePipe(&readEnd, &writeEnd, &pipeAttributes, 0)) {
        std::cerr << "Error: failed to create a pipe for tar.exe (code " << GetLastError() << ")." << std::endl;
        return false;
    }
    SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);

    const std::wstring commandLine = L"\"" + tarPath + L"\" -tf \"" + s2ws(archivePath) + L"\"";
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW startupInfo = {};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startupInfo.hStdOutput = writeEnd;
    startupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION processInfo = {};

    const BOOL started = CreateProcessW(tarPath.c_str(), mutableCommandLine.data(), NULL, NULL, TRUE,
        0, NULL, NULL, &startupInfo, &processInfo);

    // Свой экземпляр конца для записи закрываем сразу: пока он открыт, канал не закроется
    // и после завершения tar.exe.
    CloseHandle(writeEnd);

    if (!started) {
        std::cerr << "Error: failed to launch tar.exe (code " << GetLastError() << ")." << std::endl;
        CloseHandle(readEnd);
        return false;
    }

    std::string output;
    bool tooLarge = false;
    char buffer[4096];
    DWORD bytesRead = 0;
    while (ReadFile(readEnd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (output.size() + bytesRead > MAX_LISTING_SIZE) {
            tooLarge = true;
            break;
        }
        output.append(buffer, bytesRead);
    }
    CloseHandle(readEnd);

    // Если вывод оборвали по лимиту, tar.exe может ждать на записи в закрытый канал;
    // он получит ошибку записи и завершится сам.
    WaitForSingleObject(processInfo.hProcess, INFINITE);

    DWORD exitCode = 1;
    GetExitCodeProcess(processInfo.hProcess, &exitCode);

    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    if (tooLarge) {
        std::cerr << "Error: archive listing is larger than " << (MAX_LISTING_SIZE / (1024 * 1024)) << " MB." << std::endl;
        return false;
    }

    if (exitCode != 0) {
        std::cerr << "Error: tar exited with code " << exitCode << " while listing the archive." << std::endl;
        return false;
    }

    size_t start = 0;
    while (start < output.size()) {
        size_t end = output.find('\n', start);
        if (end == std::string::npos) {
            end = output.size();
        }

        std::string line = output.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            entries.push_back(line);
        }

        start = end + 1;
    }

    return true;
}
