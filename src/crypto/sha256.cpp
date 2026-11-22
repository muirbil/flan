#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>
#include "flan/sha256.hpp"
#include "flan/fs.hpp"
#include "flan/hex.hpp"
#include <fstream>

#pragma comment(lib, "bcrypt.lib")

namespace crypto {

    Sha256::Sha256() {
        open();
    }

    Sha256::~Sha256() {
        close();
    }

    void Sha256::open() {
        ok_ = false;

        BCRYPT_ALG_HANDLE algorithm = NULL;
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) {
            return;
        }
        algorithm_ = algorithm;

        DWORD objectLength = 0;
        DWORD written = 0;
        if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&objectLength, sizeof(objectLength), &written, 0) < 0) {
            return;
        }
        object_.assign(objectLength, 0);

        BCRYPT_HASH_HANDLE hash = NULL;
        if (BCryptCreateHash(algorithm, &hash, object_.data(), objectLength, NULL, 0, 0) < 0) {
            return;
        }
        hash_ = hash;
        ok_ = true;
    }

    void Sha256::close() {
        // Хэш-объект ссылается на провайдер, поэтому уничтожается первым:
        // обратный порядок — обращение к уже закрытому провайдеру.
        if (hash_) {
            BCryptDestroyHash((BCRYPT_HASH_HANDLE)hash_);
            hash_ = nullptr;
        }
        if (algorithm_) {
            BCryptCloseAlgorithmProvider((BCRYPT_ALG_HANDLE)algorithm_, 0);
            algorithm_ = nullptr;
        }
        ok_ = false;
    }

    bool Sha256::ok() const {
        return ok_;
    }

    void Sha256::update(const void* data, size_t size) {
        // BCryptHashData принимает ULONG: огромные куски подаются частями.
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        while (ok_ && size > 0) {
            const ULONG chunk = size > 0x40000000 ? 0x40000000 : (ULONG)size;
            if (BCryptHashData((BCRYPT_HASH_HANDLE)hash_, (PUCHAR)bytes, chunk, 0) < 0) {
                ok_ = false;
            }
            bytes += chunk;
            size -= chunk;
        }
    }

    void Sha256::reset() {
        close();
        open();
    }

    std::string Sha256::finishHex() {
        if (!ok_) {
            return std::string();
        }

        uint8_t digest[32];
        if (BCryptFinishHash((BCRYPT_HASH_HANDLE)hash_, digest, sizeof(digest), 0) < 0) {
            ok_ = false;
            return std::string();
        }

        // После BCryptFinishHash объект хэша больше не пригоден.
        ok_ = false;
        return toHex(digest, sizeof(digest));
    }

    std::string calculateSHA256(const std::string& filePath) {
        // Путь — UTF-8; ifstream получает его уже в UTF-16 (DESIGN.md §7.1).
        std::ifstream file(extendedPath(filePath).c_str(), std::ios::binary);
        if (!file) {
            return std::string();
        }

        Sha256 hash;
        std::vector<char> buffer(64 * 1024);
        while (file) {
            file.read(buffer.data(), (std::streamsize)buffer.size());
            if (file.gcount() > 0) {
                hash.update(buffer.data(), (size_t)file.gcount());
            }
        }

        if (file.bad()) {
            return std::string();
        }
        return hash.finishHex();
    }
}
