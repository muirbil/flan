#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <shlobj.h>
#include <knownfolders.h>
#include "flan/fs.hpp"
#include "flan/strings.hpp"
#include "flan/console.hpp"
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

namespace {

    // Атрибуты самой записи, не цели ссылки: дескриптор открывается с FILE_FLAG_OPEN_REPARSE_POINT.
    // Через него же снимается «только чтение» — SetFileAttributesW по пути на ссылке менял бы
    // неизвестно что (DESIGN.md §7.6, «Удаление дерева»).
    bool readOwnAttributes(const std::wstring& path, DWORD access, HANDLE& handle, DWORD& attributes) {
        handle = CreateFileW(path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (handle == INVALID_HANDLE_VALUE) {
            return false;
        }

        FILE_BASIC_INFO info = {};
        if (!GetFileInformationByHandleEx(handle, FileBasicInfo, &info, sizeof(info))) {
            CloseHandle(handle);
            handle = INVALID_HANDLE_VALUE;
            return false;
        }
        attributes = info.FileAttributes;
        return true;
    }

    bool setOwnAttributes(HANDLE handle, DWORD attributes) {
        FILE_BASIC_INFO info = {};
        if (!GetFileInformationByHandleEx(handle, FileBasicInfo, &info, sizeof(info))) {
            return false;
        }
        info.FileAttributes = attributes == 0 ? FILE_ATTRIBUTE_NORMAL : attributes;
        return SetFileInformationByHandle(handle, FileBasicInfo, &info, sizeof(info)) != 0;
    }

    bool clearReadOnly(const std::wstring& path) {
        HANDLE handle = INVALID_HANDLE_VALUE;
        DWORD attributes = 0;
        if (!readOwnAttributes(path, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, handle, attributes)) {
            return false;
        }
        const bool ok = !(attributes & FILE_ATTRIBUTE_READONLY) ||
            setOwnAttributes(handle, attributes & ~FILE_ATTRIBUTE_READONLY);
        CloseHandle(handle);
        return ok;
    }

    bool removeEntry(const std::wstring& path, DWORD attributes) {
        if (attributes & FILE_ATTRIBUTE_READONLY) {
            clearReadOnly(path);
        }

        // Ссылка удаляется как ссылка: DeleteFileW и RemoveDirectoryW на symlink и junction
        // убирают саму ссылку, а её цель не трогают.
        if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
            return RemoveDirectoryW(path.c_str()) != 0;
        }
        return DeleteFileW(path.c_str()) != 0;
    }
}

bool removeTreeW(const std::wstring& path) {
    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD attributes = 0;
    if (!readOwnAttributes(path, FILE_READ_ATTRIBUTES, handle, attributes)) {
        const DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    CloseHandle(handle);

    // Файл, файл-ссылка, каталог-ссылка или junction — внутрь не спускаемся. Признак взят
    // с дескриптора самой записи (FILE_FLAG_OPEN_REPARSE_POINT), а не из обхода родителя.
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        return removeEntry(path, attributes);
    }

    // Обычный каталог: сначала содержимое. Ошибка на одной записи не останавливает остальные —
    // удаляется всё, что можно, а итог честно сообщает, что что-то осталось.
    bool ok = true;
    std::vector<DirEntry> entries;
    if (!listDirectory(path, entries)) {
        ok = false;
    }
    for (const DirEntry& entry : entries) {
        ok = removeTreeW(path + L"\\" + entry.name) && ok;
    }

    return removeEntry(path, attributes) && ok;
}

bool removeTree(const std::string& path) {
    return removeTreeW(extendedPath(path));
}

namespace {

    // Открытие на запись при полном совместном доступе; 0 — открылся, иначе код ошибки.
    DWORD probeWrite(const std::wstring& path) {
        const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (file == INVALID_HANDLE_VALUE) {
            return GetLastError();
        }
        CloseHandle(file);
        return 0;
    }
}

// Занят ли хоть один файл в дереве. Признак — открытие на запись при полном совместном
// доступе: работающий .exe и файл, открытый программой, дают ERROR_SHARING_VIOLATION.
// Проверено: открытие на чтение без совместного доступа работающий .exe пропускает
// (у образа нет открытого дескриптора), а каталог с ним Windows даёт переименовать,
// так что переименование занятость тоже не показывает. Содержимое файлов не меняется (OPEN_EXISTING);
// у файла «только чтение» атрибут на время проверки снимается и возвращается.
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

        DWORD error = probeWrite(path);

        // Файл «только чтение» на запись не откроется вовсе (ERROR_ACCESS_DENIED), занят он или нет.
        // Атрибут снимается на время проверки и сразу возвращается: иначе removeTree, который
        // снимает его перед удалением, начал бы удалять каталог с запущенной программой.
        if (error == ERROR_ACCESS_DENIED && (entry.attributes & FILE_ATTRIBUTE_READONLY)) {
            HANDLE handle = INVALID_HANDLE_VALUE;
            DWORD attributes = 0;
            if (readOwnAttributes(path, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, handle, attributes)) {
                if (setOwnAttributes(handle, attributes & ~FILE_ATTRIBUTE_READONLY)) {
                    error = probeWrite(path);
                    setOwnAttributes(handle, attributes);
                }
                CloseHandle(handle);
            }
        }

        if (error == ERROR_SHARING_VIOLATION) {
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
            con::err << "Error: could not locate the system directory." << con::endl;
            return false;
        }

        tarPath = std::wstring(systemDir) + L"\\tar.exe";
        return true;
    }

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
        con::err << "Error: failed to launch tar.exe (code " << GetLastError() << ")." << con::endl;
        return false;
    }

    WaitForSingleObject(processInfo.hProcess, INFINITE);

    DWORD exitCode = 1;
    GetExitCodeProcess(processInfo.hProcess, &exitCode);

    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    if (exitCode != 0) {
        con::err << "Error: tar exited with code " << exitCode << "." << con::endl;
        return false;
    }

    return true;
}
