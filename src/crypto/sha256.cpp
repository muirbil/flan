#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>
#include "flan/sha256.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

namespace crypto {

    std::string calculateSHA256(const std::string& filePath) {

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
        PBYTE pbHashObject = NULL;
        PBYTE pbHash = NULL;
        std::string calculated_hash = "";

        // Инициализация провайдера SHA256
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0) {

            // Узнаем размеры буферов для хэша и объекта хэша
            BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
            BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);

            pbHashObject = new BYTE[cbHashObject];
            pbHash = new BYTE[cbHash];

            if (BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0) >= 0) {

                // Открываем архив в бинарном режиме
                std::ifstream file(filePath, std::ios::binary);
                if (file) {
                    char buffer[8192]; // Читаем файл чанками по 8 КБ
                    while (file.read(buffer, sizeof(buffer))) {
                        BCryptHashData(hHash, (PBYTE)buffer, (ULONG)file.gcount(), 0);
                    }

                    // Добиваем последний (неполный) кусок
                    BCryptHashData(hHash, (PBYTE)buffer, (ULONG)file.gcount(), 0);

                    if (BCryptFinishHash(hHash, pbHash, cbHash, 0) >= 0) {

                        // Преобразуем байты в hex-строку
                        std::ostringstream oss;
                        for (DWORD i = 0; i < cbHash; ++i) {
                            oss << std::hex << std::setw(2) << std::setfill('0') << (int)pbHash[i];
                        }
                        calculated_hash = oss.str();
                    }
                }
            }
        }

        // Очистка ресурсов. Хэш-объект ссылается на провайдер, поэтому уничтожается первым:
        // обратный порядок — обращение к уже закрытому провайдеру.
        if (hHash) BCryptDestroyHash(hHash);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        if (pbHashObject) delete[] pbHashObject;
        if (pbHash) delete[] pbHash;

        return calculated_hash;
    }

}