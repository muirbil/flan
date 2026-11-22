#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <shlobj.h>
#include <knownfolders.h>
#include "flan/fs.hpp"
#include "flan/strings.hpp"
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

    // GetFullPathNameW: абсолютный путь, '/' -> '\', без "." и "..". Длина не ограничена MAX_PATH.
    std::wstring fullPathW(const std::wstring& path) {
        if (path.empty()) {
            return std::wstring();
        }

        std::wstring buffer(MAX_PATH, L'\0');
        for (;;) {
            const DWORD length = GetFullPathNameW(path.c_str(), (DWORD)buffer.size(), &buffer[0], NULL);
            if (length == 0) {
                return std::wstring();
            }
            if (length < buffer.size()) {
                buffer.resize(length);
                return buffer;
            }
            buffer.resize(length);						// length — нужный размер вместе с '\0'
        }
    }

    bool startsWith(const std::wstring& text, const wchar_t* prefix) {
        return text.compare(0, wcslen(prefix), prefix) == 0;
    }

    bool isLetter(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }
}

std::wstring fullPath(const std::string& path) {
    return fullPathW(s2ws(path));
}

std::wstring extendedPath(const std::string& path) {
    const std::wstring wide = s2ws(path);
    if (startsWith(wide, L"\\\\?\\")) {
        return wide;
    }

    // С префиксом \\?\ система путь не нормализует, поэтому сначала — полный путь.
    const std::wstring full = fullPathW(wide);
    if (full.empty()) {
        return wide;									// вызов ФС с таким путём просто не удастся
    }

    if (startsWith(full, L"\\\\")) {
        // \\.\ — пространство устройств, его не трогаем; \\server\share -> \\?\UNC\server\share.
        if (full.size() > 2 && full[2] == L'.') {
            return full;
        }
        return L"\\\\?\\UNC\\" + full.substr(2);
    }
    return L"\\\\?\\" + full;
}

bool parseFlanHome(const std::string& value, std::string& home, std::string& error) {
    home.clear();

    std::string path = value;
    for (char& c : path) {
        if (c == '/') {
            c = '\\';
        }
    }

    if (path.compare(0, 4, "\\\\?\\") == 0 || path.compare(0, 4, "\\\\.\\") == 0) {
        error = "FLAN_HOME must be a plain path, without the \\\\?\\ or \\\\.\\ prefix";
        return false;
    }

    // Абсолютный — только X:\… или \\server\share…: относительный путь (и "X:flan" — относительно
    // текущего каталога диска X) зависел бы от того, откуда запущен flan.
    const bool drive = path.size() >= 3 && isLetter(path[0]) && path[1] == ':' && path[2] == '\\';
    bool unc = false;
    if (path.compare(0, 2, "\\\\") == 0) {
        const size_t server = path.find('\\', 2);
        unc = server != std::string::npos && server > 2 && server + 1 < path.size() && path[server + 1] != '\\';
    }
    if (!drive && !unc) {
        error = "FLAN_HOME must be an absolute path, like D:\\flan or \\\\server\\share\\flan";
        return false;
    }

    if (!toUtf8(fullPathW(s2ws(path)), home) || home.empty()) {
        error = "FLAN_HOME is not a valid path";
        return false;
    }

    while (home.size() > 1 && home.back() == '\\') {
        home.pop_back();
    }

    if (home.size() == 2 && home[1] == ':') {
        error = "FLAN_HOME must be a folder, not the root of a drive";
        home.clear();
        return false;
    }
    return true;
}

bool resolveFlanHome(std::string& home, std::string& error) {
    home.clear();

    const DWORD needed = GetEnvironmentVariableW(L"FLAN_HOME", NULL, 0);
    if (needed > 1) {
        std::wstring value(needed, L'\0');
        const DWORD length = GetEnvironmentVariableW(L"FLAN_HOME", &value[0], needed);
        value.resize(length < needed ? length : 0);

        std::string utf8;
        if (value.empty() || !toUtf8(value, utf8)) {
            error = "FLAN_HOME is not a valid path";
            return false;
        }
        return parseFlanHome(utf8, home, error);
    }

    // По умолчанию — %USERPROFILE%\.flan, через Unicode-API: SHGetFolderPathA портил кириллицу.
    PWSTR profile = NULL;
    const HRESULT result = SHGetKnownFolderPath(FOLDERID_Profile, 0, NULL, &profile);
    std::string utf8;
    const bool ok = SUCCEEDED(result) && profile != NULL && toUtf8(profile, utf8) && !utf8.empty();
    CoTaskMemFree(profile);

    if (!ok) {
        error = "could not determine the user profile directory";
        return false;
    }

    home = utf8 + "\\.flan";
    return true;
}

bool createDirectory(const std::string& path) {
    const std::wstring wide = extendedPath(path);
    if (!startsWith(wide, L"\\\\?\\")) {
        return false;
    }

    // Корень (\\?\X:\ или \\?\UNC\server\share\) не создаётся — с него начинаются промежуточные каталоги.
    size_t root = 4;
    if (startsWith(wide, L"\\\\?\\UNC\\")) {
        const size_t server = wide.find(L'\\', 8);
        const size_t share = server == std::wstring::npos ? std::wstring::npos : wide.find(L'\\', server + 1);
        root = share == std::wstring::npos ? wide.size() : share + 1;
    }
    else if (wide.size() >= 7 && wide[5] == L':' && wide[6] == L'\\') {
        root = 7;
    }

    for (size_t i = root; i < wide.size(); i++) {
        if (wide[i] == L'\\') {
            CreateDirectoryW(wide.substr(0, i).c_str(), NULL);
        }
    }
    CreateDirectoryW(wide.c_str(), NULL);

    // CreateDirectoryW возвращает FALSE и на уже существующем каталоге,
    // поэтому успехом считаем сам факт наличия директории.
    const DWORD attributes = GetFileAttributesW(wide.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool deleteFile(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    return DeleteFileW(extendedPath(path).c_str()) != 0;
}

bool pathExists(const std::string& path) {
    return !path.empty() && GetFileAttributesW(extendedPath(path).c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool moveFile(const std::string& from, const std::string& to, bool replace) {
    const DWORD flags = MOVEFILE_WRITE_THROUGH | (replace ? MOVEFILE_REPLACE_EXISTING : 0);
    return MoveFileExW(extendedPath(from).c_str(), extendedPath(to).c_str(), flags) != 0;
}

bool copyFile(const std::string& from, const std::string& to, bool overwrite) {
    return CopyFileW(extendedPath(from).c_str(), extendedPath(to).c_str(), overwrite ? FALSE : TRUE) != 0;
}

bool readWholeFile(const std::string& path, uint64_t limit, std::vector<uint8_t>& out, bool& tooLarge) {
    out.clear();
    tooLarge = false;

    const HANDLE file = CreateFileW(extendedPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
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
    const std::wstring target = extendedPath(path);
    const std::wstring temporary = target + L".tmp";

    const HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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

    if (!ok || !MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        return false;
    }
    return true;
}

bool isDirectory(const std::string& path) {
    const DWORD attributes = GetFileAttributesW(extendedPath(path).c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool isRegularFile(const std::string& path) {
    const DWORD attributes = GetFileAttributesW(extendedPath(path).c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool fileSize(const std::string& path, uint64_t& size) {
    WIN32_FILE_ATTRIBUTE_DATA data = {};
    if (!GetFileAttributesExW(extendedPath(path).c_str(), GetFileExInfoStandard, &data) || (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        return false;
    }
    size = ((uint64_t)data.nFileSizeHigh << 32) | data.nFileSizeLow;
    return true;
}

bool freeDiskSpace(const std::string& directory, uint64_t& bytes) {
    // Каталог — с завершающим '\': для сетевых путей GetDiskFreeSpaceExW этого требует.
    std::wstring wide = extendedPath(directory);
    if (!wide.empty() && wide.back() != L'\\') {
        wide += L'\\';
    }

    ULARGE_INTEGER available = {};
    if (!GetDiskFreeSpaceExW(wide.c_str(), &available, NULL, NULL)) {
        return false;
    }
    bytes = available.QuadPart;
    return true;
}

bool listDirectory(const std::wstring& dir, std::vector<DirEntry>& entries) {
    entries.clear();

    // Только "*": остальные шаблоны FindFirstFile сопоставляет по старым правилам
    // ("name.*" совпадает с "name", "*.bat" — с коротким именем FOO~1.BAT от "foo.batch").
    // FindExInfoBasic не возвращает коротких имён вовсе.
    std::wstring pattern = dir;
    if (!pattern.empty() && pattern.back() != L'\\') {
        pattern += L'\\';
    }
    pattern += L'*';

    WIN32_FIND_DATAW found = {};
    const HANDLE search = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &found, FindExSearchNameMatch, NULL,
        FIND_FIRST_EX_LARGE_FETCH);
    if (search == INVALID_HANDLE_VALUE) {
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    }

    do {
        const std::wstring name = found.cFileName;
        if (name == L"." || name == L"..") {
            continue;
        }

        DirEntry entry;
        entry.name = name;
        entry.attributes = found.dwFileAttributes;
        entries.push_back(entry);
    } while (FindNextFileW(search, &found));

    const bool complete = GetLastError() == ERROR_NO_MORE_FILES;
    FindClose(search);
    return complete;
}

bool asciiName(const std::wstring& name, std::string& out) {
    out.clear();
    for (const wchar_t c : name) {
        if (c < 0x20 || c > 0x7E) {
            out.clear();
            return false;
        }
        out += (char)c;
    }
    return !out.empty();
}

bool removeTreeW(const std::wstring& path) {
    std::error_code ec;
    std::filesystem::remove_all(std::filesystem::path(path), ec);
    return !ec && GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES;
}

bool removeTree(const std::string& path) {
    return removeTreeW(extendedPath(path));
}

// Занят ли хоть один файл в дереве. Признак — открытие на запись при полном совместном
// доступе: работающий .exe и файл, открытый программой, дают ERROR_SHARING_VIOLATION.
// Проверено: открытие на чтение без совместного доступа работающий .exe пропускает
// (у образа нет открытого дескриптора), а каталог с ним Windows даёт переименовать,
// так что переименование занятость тоже не показывает. Файлы не изменяются: OPEN_EXISTING.
bool treeInUse(const std::wstring& dir) {
    std::vector<DirEntry> entries;
    if (!listDirectory(dir, entries)) {
        return false;
    }

    for (const DirEntry& entry : entries) {
        const std::wstring path = dir + L"\\" + entry.name;

        if (entry.attributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Точки повторного анализа (junction, symlink) не обходим: они ведут за пределы пакета.
            if (!(entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT) && treeInUse(path)) {
                return true;
            }
            continue;
        }

        const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
        }
        else if (GetLastError() == ERROR_SHARING_VIOLATION) {
            return true;
        }
    }
    return false;
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
    // tar.exe префикс \\?\ не понимает — ему полные пути без него (до этапа 3, шаг 6).
    const std::wstring commandLine =
        L"\"" + tarPath + L"\" -xf \"" + fullPath(archivePath) + L"\" -C \"" + fullPath(destinationDir) + L"\"";

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

    const std::wstring commandLine = L"\"" + tarPath + L"\" -tf \"" + fullPath(archivePath) + L"\"";
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
