#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winhttp.h>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include "flan/http.hpp"
#include "flan/http_policy.hpp"
#include "flan/sha256.hpp"
#include "flan/strings.hpp"

#pragma comment(lib, "winhttp.lib")

// Флаги из новых SDK; на старых системах их установка просто не удастся (см. openSession).
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif
#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4
#endif

namespace {

    constexpr DWORD CHUNK_SIZE = 64 * 1024;

    // Таймауты §7.2: соединение 15 с, приём 60 с между пакетами — медленно не значит мёртво.
    constexpr int RESOLVE_TIMEOUT_MS = 15000;
    constexpr int CONNECT_TIMEOUT_MS = 15000;
    constexpr int SEND_TIMEOUT_MS = 60000;
    constexpr int RECEIVE_TIMEOUT_MS = 60000;

    // Сессия WinHTTP. Прокси — автоматический (Windows 8.1+), иначе системный по умолчанию.
    HINTERNET openSession() {
        const wchar_t* agent = L"flan/0.2";
        HINTERNET session = WinHttpOpen(agent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session) {
            session = WinHttpOpen(agent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        }
        if (!session) {
            return NULL;
        }

        // TLS 1.2 явно: на Windows 7 он иначе выключен. Где TLS 1.3 не поддерживается,
        // флаг ставится без него; если не ставится и TLS 1.2 (Windows 7 без KB3140245),
        // запрос упадёт с ошибкой TLS, и вызывающий подскажет это обновление.
        DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        if (!WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols))) {
            protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
            WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
        }

        // Переадресации разрешены (GitHub Releases ведёт на release-assets.githubusercontent.com),
        // но только HTTPS -> HTTPS.
        DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
        WinHttpSetOption(session, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));

        WinHttpSetTimeouts(session, RESOLVE_TIMEOUT_MS, CONNECT_TIMEOUT_MS, SEND_TIMEOUT_MS, RECEIVE_TIMEOUT_MS);
        return session;
    }

    // Заголовок ответа строкой. Значения заголовков — ASCII; прочее заменяется на '?'.
    bool queryHeader(HINTERNET request, DWORD info, std::string& out) {
        out.clear();
        DWORD size = 0;
        WinHttpQueryHeaders(request, info, WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
            return false;
        }

        std::wstring wide(size / sizeof(wchar_t), L'\0');
        if (!WinHttpQueryHeaders(request, info, WINHTTP_HEADER_NAME_BY_INDEX, &wide[0], &size, WINHTTP_NO_HEADER_INDEX)) {
            return false;
        }
        wide.resize(size / sizeof(wchar_t));

        for (const wchar_t c : wide) {
            out += (c >= 0x20 && c < 0x7F) ? (char)c : '?';
        }
        return true;
    }

    std::string describeNetworkError(DWORD error) {
        switch (error) {
        case ERROR_WINHTTP_TIMEOUT: return "timed out";
        case ERROR_WINHTTP_NAME_NOT_RESOLVED: return "cannot resolve the server name";
        case ERROR_WINHTTP_CANNOT_CONNECT: return "cannot connect to the server";
        case ERROR_WINHTTP_CONNECTION_ERROR: return "the connection was reset";
        case ERROR_WINHTTP_SECURE_FAILURE: return "TLS certificate check failed";
        case ERROR_WINHTTP_SECURE_CHANNEL_ERROR:
            return "TLS connection failed (on Windows 7, TLS 1.2 needs update KB3140245)";
        case ERROR_WINHTTP_REDIRECT_FAILED: return "the server redirected to a non-HTTPS address";
        default: return "network error " + std::to_string(error);
        }
    }

    // Прогресс (§7.2): полоса из ASCII, только если stdout — консоль; при перенаправлении —
    // одна строка в конце.
    class Progress {
    public:
        explicit Progress(uint64_t total) : total_(total) {
            DWORD mode = 0;
            console_ = GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) != 0;
        }

        void update(uint64_t done) {
            if (!console_) {
                return;
            }
            const ULONGLONG now = GetTickCount64();
            if (drawn_ && now - lastDraw_ < 100 && done != total_) {
                return;
            }
            lastDraw_ = now;
            drawn_ = true;

            std::string line = "\r  ";
            if (total_ > 0) {
                const int width = 30;
                const uint64_t shown = done > total_ ? total_ : done;
                const int filled = (int)(shown * width / total_);
                line += "[" + std::string(filled, '#') + std::string(width - filled, '-') + "] " +
                    std::to_string(shown * 100 / total_) + "% ";
            }
            line += std::to_string(done / 1024) + (total_ > 0 ? " / " + std::to_string(total_ / 1024) : "") + " KB  ";
            std::cout << line << std::flush;
        }

        // Перед сообщением посреди загрузки: закончить строку полосы, если она нарисована.
        void interrupt() {
            if (console_ && drawn_) {
                std::cout << std::endl;
                drawn_ = false;
            }
        }

        void finish(uint64_t done, uint64_t received) {
            if (console_) {
                if (drawn_) {
                    std::cout << std::endl;
                }
            }
            else if (received > 0) {
                std::cout << "  downloaded " << (received / 1024) << " KB" << std::endl;
            }
            (void)done;
        }

    private:
        uint64_t total_ = 0;
        bool console_ = false;
        bool drawn_ = false;
        ULONGLONG lastDraw_ = 0;
    };

    // Файл назначения: дописывание или запись с нуля.
    class BodyFile {
    public:
        ~BodyFile() {
            if (handle_ != INVALID_HANDLE_VALUE) {
                CloseHandle(handle_);
            }
        }

        bool open(const std::string& path) {
            handle_ = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, NULL);
            return handle_ != INVALID_HANDLE_VALUE;
        }

        uint64_t size() const {
            LARGE_INTEGER size = {};
            return GetFileSizeEx(handle_, &size) ? (uint64_t)size.QuadPart : 0;
        }

        bool seekToEnd() {
            LARGE_INTEGER zero = {};
            return SetFilePointerEx(handle_, zero, NULL, FILE_END) != 0;
        }

        bool truncate() {
            LARGE_INTEGER zero = {};
            return SetFilePointerEx(handle_, zero, NULL, FILE_BEGIN) && SetEndOfFile(handle_);
        }

        bool write(const void* data, DWORD size) {
            DWORD written = 0;
            return WriteFile(handle_, data, size, &written, NULL) && written == size;
        }

    private:
        HANDLE handle_ = INVALID_HANDLE_VALUE;
    };

#ifdef _DEBUG
    // §7.2: Debug-сборка один раз рвёт загрузку после FLAN_DEBUG_DROP_AFTER байт тела —
    // так повтор с докачкой проверяется на настоящем сервере. В Release этого кода нет.
    uint64_t debugDropAfter() {
        char value[32] = {};
        const DWORD length = GetEnvironmentVariableA("FLAN_DEBUG_DROP_AFTER", value, sizeof(value));
        uint64_t bytes = 0;
        return (length > 0 && length < sizeof(value) && parseUint64(value, bytes)) ? bytes : 0;
    }
#endif
}

HttpResult httpGet(const HttpRequest& request) {
    HttpResult result;

    const std::wstring wideUrl = s2ws(request.url);
    URL_COMPONENTS parts = {};
    parts.dwStructSize = sizeof(parts);
    wchar_t host[256];
    wchar_t path[2048];
    wchar_t extra[2048];
    parts.lpszHostName = host;
    parts.dwHostNameLength = ARRAYSIZE(host);
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = ARRAYSIZE(path);
    // Без собственного буфера query-string отбрасывалась бы, и подписанные ссылки ломались.
    parts.lpszExtraInfo = extra;
    parts.dwExtraInfoLength = ARRAYSIZE(extra);

    if (!WinHttpCrackUrl(wideUrl.c_str(), (DWORD)wideUrl.length(), 0, &parts) || parts.nScheme != INTERNET_SCHEME_HTTPS) {
        result.outcome = HttpOutcome::HttpError;
        result.error = "not a valid https:// URL: " + request.url;
        return result;
    }
    const std::wstring object = std::wstring(parts.lpszUrlPath) + parts.lpszExtraInfo;

    BodyFile file;
    if (!file.open(request.destination)) {
        result.outcome = HttpOutcome::LocalError;
        result.error = "cannot open " + request.destination + " (code " + std::to_string(GetLastError()) + ")";
        return result;
    }

    // Заявленное начало должно совпадать с тем, что реально лежит в файле; иначе пишем с нуля.
    uint64_t written = request.resumeFrom;
    if (written == 0 || file.size() != written || written > request.maxSize) {
        if (written != 0 && request.hasher) {
            request.hasher->reset();
        }
        written = 0;
        if (!file.truncate()) {
            result.outcome = HttpOutcome::LocalError;
            result.error = "cannot write " + request.destination;
            return result;
        }
    }
    else if (!file.seekToEnd()) {
        result.outcome = HttpOutcome::LocalError;
        result.error = "cannot write " + request.destination;
        return result;
    }

    HINTERNET session = openSession();
    if (!session) {
        result.outcome = HttpOutcome::NetworkError;
        result.error = "cannot initialize WinHTTP (code " + std::to_string(GetLastError()) + ")";
        return result;
    }

    Progress progress(request.expectedSize);
    std::vector<uint8_t> buffer(CHUNK_SIZE);
    unsigned retries = 0;
    bool restartedWithoutRange = false;

#ifdef _DEBUG
    const uint64_t dropAfter = debugDropAfter();
    bool dropped = false;
#endif

    auto fail = [&](HttpOutcome outcome, const std::string& error) {
        progress.finish(written, result.bodyBytes);
        WinHttpCloseHandle(session);
        result.outcome = outcome;
        result.error = error;
        result.fileSize = written;
        return result;
    };

    for (;;) {
        // Одна попытка. retryReason непуст — попытка не удалась так, что её стоит повторить.
        std::string retryReason;
        std::string retryAfter;

        HINTERNET connection = WinHttpConnect(session, parts.lpszHostName, parts.nPort, 0);
        HINTERNET handle = connection
            ? WinHttpOpenRequest(connection, L"GET", object.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)
            : NULL;

        auto closeAttempt = [&]() {
            if (handle) WinHttpCloseHandle(handle);
            if (connection) WinHttpCloseHandle(connection);
            handle = NULL;
            connection = NULL;
        };

        std::wstring headers;
        const uint64_t requestedFrom = written;
        if (requestedFrom > 0) {
            headers += L"Range: bytes=" + std::to_wstring(requestedFrom) + L"-\r\n";
        }
        if (!request.ifNoneMatch.empty()) {
            headers += L"If-None-Match: " + s2ws(request.ifNoneMatch) + L"\r\n";
        }

        const bool sent = handle &&
            WinHttpSendRequest(handle, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                headers.empty() ? 0 : (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(handle, NULL);

        if (!sent) {
            const DWORD error = GetLastError();
            closeAttempt();
            if (classifyNetworkError(error) == Retry::No) {
                return fail(HttpOutcome::NetworkError, describeNetworkError(error));
            }
            retryReason = describeNetworkError(error);
        }
        else {
            DWORD status = 0;
            DWORD statusSize = sizeof(status);
            WinHttpQueryHeaders(handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
            result.status = status;
            queryHeader(handle, WINHTTP_QUERY_ETAG, result.etag);

            if (status == 304 && !request.ifNoneMatch.empty()) {
                closeAttempt();
                WinHttpCloseHandle(session);
                result.outcome = HttpOutcome::NotModified;
                result.fileSize = written;
                return result;
            }

            // Все нужные заголовки читаются сразу, пока запрос открыт.
            std::string contentRange;
            queryHeader(handle, WINHTTP_QUERY_CONTENT_RANGE, contentRange);
            queryHeader(handle, WINHTTP_QUERY_RETRY_AFTER, retryAfter);
            const BodyAction action = (status == 200 || status == 206 || status == 416)
                ? decideBody(status, requestedFrom, contentRange, request.expectedSize)
                : BodyAction::Unexpected;

            if (action == BodyAction::RestartWithoutRange && !restartedWithoutRange) {
                // 416 или чужой диапазон: то, что скачано, не годится. Один раз — сразу заново
                // и без паузы; это не сбой сети, а несогласие с сервером о файле.
                closeAttempt();
                restartedWithoutRange = true;
                written = 0;
                if (request.hasher) request.hasher->reset();
                if (!file.truncate()) {
                    return fail(HttpOutcome::LocalError, "cannot write " + request.destination);
                }
                continue;
            }

            if (action == BodyAction::RestartWithoutRange || action == BodyAction::Unexpected) {
                closeAttempt();
                if (status != 200 && status != 206 && status != 416 && classifyStatus(status) == Retry::Yes) {
                    retryReason = "HTTP " + std::to_string(status);
                }
                else if (status == 403) {
                    return fail(HttpOutcome::HttpError, "HTTP 403 (forbidden; on GitHub this is usually the request rate limit, try again later)");
                }
                else {
                    return fail(HttpOutcome::HttpError, "HTTP " + std::to_string(status));
                }
            }
            else {
                // Тело. Replace — с нуля (200), Append — дописываем (206).
                if (action == BodyAction::Replace && written > 0) {
                    written = 0;
                    if (request.hasher) request.hasher->reset();
                    if (!file.truncate()) {
                        closeAttempt();
                        return fail(HttpOutcome::LocalError, "cannot write " + request.destination);
                    }
                }
                if (action == BodyAction::Append) {
                    result.resumed = true;
                }

                std::string lengthHeader;
                uint64_t contentLength = 0;
                const bool hasLength = queryHeader(handle, WINHTTP_QUERY_CONTENT_LENGTH, lengthHeader) &&
                    parseUint64(lengthHeader, contentLength);

                // Размер известен заранее (archive_size): полный ответ другого размера —
                // ошибка целостности сразу, без загрузки (§7.2, «Лимиты»).
                if (hasLength && action == BodyAction::Replace && request.expectedSize != 0 && contentLength != request.expectedSize) {
                    closeAttempt();
                    return fail(HttpOutcome::SizeMismatch, "the server reports " + std::to_string(contentLength) +
                        " bytes, the index says " + std::to_string(request.expectedSize));
                }
                if (hasLength && written + contentLength > request.maxSize) {
                    closeAttempt();
                    return fail(HttpOutcome::SizeMismatch, "the file is larger than the allowed " + std::to_string(request.maxSize) + " bytes");
                }

                const uint64_t limit = request.expectedSize != 0 ? request.expectedSize : request.maxSize;
                uint64_t receivedNow = 0;
                bool broken = false;

                for (;;) {
                    DWORD read = 0;
                    if (!WinHttpReadData(handle, buffer.data(), CHUNK_SIZE, &read)) {
                        const DWORD error = GetLastError();
                        if (classifyNetworkError(error) == Retry::No) {
                            closeAttempt();
                            return fail(HttpOutcome::NetworkError, describeNetworkError(error));
                        }
                        retryReason = describeNetworkError(error);
                        broken = true;
                        break;
                    }
                    if (read == 0) {
                        break;
                    }

                    // Больше потолка не принимаем ни байта (§7.2, «Лимиты»).
                    if (written + read > limit) {
                        closeAttempt();
                        return fail(HttpOutcome::SizeMismatch, "the server sent more than the expected " + std::to_string(limit) + " bytes");
                    }

                    if (!file.write(buffer.data(), read)) {
                        closeAttempt();
                        return fail(HttpOutcome::LocalError, "cannot write " + request.destination);
                    }
                    if (request.hasher) {
                        request.hasher->update(buffer.data(), read);
                    }

                    written += read;
                    receivedNow += read;
                    result.bodyBytes += read;
                    progress.update(written);

#ifdef _DEBUG
                    if (dropAfter != 0 && !dropped && result.bodyBytes >= dropAfter) {
                        dropped = true;
                        progress.interrupt();
                        std::cerr << "  [debug] dropping the connection after " << result.bodyBytes << " bytes" << std::endl;
                        retryReason = describeNetworkError(ERROR_WINHTTP_CONNECTION_ERROR);
                        broken = true;
                        break;
                    }
#endif
                }

                closeAttempt();

                // Соединение закрылось раньше, чем пришло обещанное: это обрыв, а не конец файла.
                if (!broken && ((hasLength && receivedNow != contentLength) ||
                    (request.expectedSize != 0 && written < request.expectedSize))) {
                    retryReason = "the connection closed early";
                    broken = true;
                }

                if (!broken) {
                    progress.finish(written, result.bodyBytes);
                    WinHttpCloseHandle(session);
                    result.outcome = HttpOutcome::Ok;
                    result.fileSize = written;
                    return result;
                }
            }
        }

        // Повтор. Уже записанное сохраняется: следующая попытка пойдёт с Range от него.
        if (retries >= MAX_RETRIES) {
            return fail(HttpOutcome::NetworkError, retryReason + " (gave up after " + std::to_string(MAX_RETRIES + 1) + " attempts)");
        }

        const unsigned delay = retryDelaySeconds(retries, retryAfter);
        retries++;
        progress.interrupt();
        std::cerr << "  " << retryReason << "; retrying in " << delay << " s (attempt "
            << (retries + 1) << " of " << (MAX_RETRIES + 1) << ")" << std::endl;
        Sleep(delay * 1000);
    }
}

bool downloadFile(const std::string& url, const std::string& destination) {
    // Пишем рядом и подменяем файл назначения только после полной загрузки:
    // оборванная загрузка не затирает прежний файл.
    const std::string partial = destination + ".part";

    HttpRequest request;
    request.url = url;
    request.destination = partial;

    const HttpResult result = httpGet(request);
    if (result.outcome != HttpOutcome::Ok) {
        std::cerr << "Error: " << result.error << "." << std::endl;
        DeleteFileW(s2ws(partial).c_str());
        return false;
    }

    if (!MoveFileExW(s2ws(partial).c_str(), s2ws(destination).c_str(), MOVEFILE_REPLACE_EXISTING)) {
        std::cerr << "Error: failed to finalize " << destination << " (code " << GetLastError() << ")." << std::endl;
        DeleteFileW(s2ws(partial).c_str());
        return false;
    }
    return true;
}
