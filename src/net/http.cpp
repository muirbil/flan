#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winhttp.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include "flan/http.hpp"
#include "flan/strings.hpp"

#pragma comment(lib, "winhttp.lib")

namespace {
    // Верхняя граница на объём загрузки: иначе хост может лить поток бесконечно
    // и забить диск пользователя.
    constexpr uint64_t MAX_DOWNLOAD_SIZE = 512ull * 1024 * 1024;

    // Верхняя граница на один буфер чтения.
    constexpr DWORD MAX_CHUNK_SIZE = 1024 * 1024;
}

bool downloadFile(const std::string& url, const std::string& destination) {
    std::wstring wUrl = s2ws(url);

    URL_COMPONENTS urlComp;
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t hostName[256];
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = ARRAYSIZE(hostName);

    wchar_t urlPath[2048];
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = ARRAYSIZE(urlPath);

    // Без собственного буфера query-string отбрасывалась, и подписанные ссылки
    // (S3, CDN с токеном) приходили бы битыми.
    wchar_t extraInfo[2048];
    urlComp.lpszExtraInfo = extraInfo;
    urlComp.dwExtraInfoLength = ARRAYSIZE(extraInfo);

    if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.length(), 0, &urlComp)) {
        std::cerr << "Error: Failed to parse URL." << std::endl;
        return false;
    }

    if (urlComp.nScheme != INTERNET_SCHEME_HTTPS) {
        std::cerr << "Error: refusing to download over a non-HTTPS URL." << std::endl;
        return false;
    }

    const std::wstring objectName = std::wstring(urlComp.lpszUrlPath) + urlComp.lpszExtraInfo;

    HINTERNET hSession = WinHttpOpen(L"Flan Package Manager/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", objectName.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    bool result = false;

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL)) {

		DWORD statusCode = 0;
		DWORD statusCodeSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);
        if (statusCode != 200) {
            std::cerr << "Error: HTTP request failed with status code " << statusCode << std::endl;
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        DWORD contentLength = 0;
        DWORD headerSize = sizeof(DWORD);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &contentLength, &headerSize, WINHTTP_NO_HEADER_INDEX);
        const uint64_t totalSize = contentLength;

        if (totalSize > MAX_DOWNLOAD_SIZE) {
            std::cerr << "Error: refusing to download " << (totalSize / (1024 * 1024)) << " MB (limit is "
                << (MAX_DOWNLOAD_SIZE / (1024 * 1024)) << " MB)." << std::endl;
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Пишем рядом, а подменяем файл назначения только после полной и проверенной
        // загрузки: оборванный sync больше не затирает рабочую базу.
        const std::string partialPath = destination + ".part";

        std::ofstream outFile(partialPath, std::ios::binary | std::ios::trunc);
        if (outFile.is_open()) {
            uint64_t downloadedTotal = 0;
            std::vector<char> buffer;
            const int barWidth = 40;
            bool transferOk = true;

            for (;;) {
                DWORD bytesAvailable = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) {
                    std::cerr << "\nError: connection lost while downloading." << std::endl;
                    transferOk = false;
                    break;
                }
                if (bytesAvailable == 0) break;

                if (bytesAvailable > MAX_CHUNK_SIZE) bytesAvailable = MAX_CHUNK_SIZE;
                if (buffer.size() < bytesAvailable) buffer.resize(bytesAvailable);

                DWORD bytesRead = 0;
                if (!WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
                    std::cerr << "\nError: failed to read response data." << std::endl;
                    transferOk = false;
                    break;
                }
                if (bytesRead == 0) break;

                downloadedTotal += bytesRead;
                if (downloadedTotal > MAX_DOWNLOAD_SIZE) {
                    std::cerr << "\nError: download exceeded the size limit of "
                        << (MAX_DOWNLOAD_SIZE / (1024 * 1024)) << " MB." << std::endl;
                    transferOk = false;
                    break;
                }

                outFile.write(buffer.data(), bytesRead);
                if (!outFile) {
                    std::cerr << "\nError: failed to write to " << partialPath << std::endl;
                    transferOk = false;
                    break;
                }

				// Display progress bar
                if (totalSize > 0) {
                    float progress = (float)downloadedTotal / (float)totalSize;
                    int pos = (int)(barWidth * progress);

                    std::cout << "\r[";
                    for (int i = 0; i < barWidth; ++i) {
                        if (i < pos) std::cout << "█";
                        else std::cout << "░";
                    }

                    std::cout << "] " << int(progress * 100.0) << "% ("
                        << (downloadedTotal / 1024) << " KB / "
                        << (totalSize / 1024) << " KB)";
                    std::cout.flush();
                }
                else {
                    std::cout << "\rDownloaded: " << (downloadedTotal / 1024) << " KB...";
                    std::cout.flush();
                }
            }

            std::cout << std::endl;
            outFile.close();

            // Сервер объявил длину — значит, недогруз обязан быть ошибкой,
            // а не молча принятым обрезанным файлом.
            if (transferOk && totalSize > 0 && downloadedTotal != totalSize) {
                std::cerr << "Error: incomplete download (" << downloadedTotal
                    << " of " << totalSize << " bytes)." << std::endl;
                transferOk = false;
            }

            if (transferOk) {
                if (MoveFileExW(s2ws(partialPath).c_str(), s2ws(destination).c_str(), MOVEFILE_REPLACE_EXISTING)) {
                    result = true;
                }
                else {
                    std::cerr << "Error: failed to finalize " << destination
                        << " (code " << GetLastError() << ")." << std::endl;
                }
            }

            if (!result) {
                DeleteFileW(s2ws(partialPath).c_str());
            }
        }
        else {
            std::cerr << "Error: Could not create local file " << partialPath << std::endl;
        }
    }
    else {
        std::cerr << "Error: Network request failed." << std::endl;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}
