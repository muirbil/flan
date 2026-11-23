#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>
#include "flan/sha256.hpp"
#include "flan/fs.hpp"
#include "flan/hex.hpp"

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

    bool Sha256::finish(uint8_t digest[32]) {
        if (!ok_) {
            return false;
        }

        // После BCryptFinishHash объект хэша больше не пригоден, удачно он отработал или нет.
        ok_ = false;
        return BCryptFinishHash((BCRYPT_HASH_HANDLE)hash_, digest, 32, 0) >= 0;
    }

    std::string Sha256::finishHex() {
        uint8_t digest[32];
        return finish(digest) ? toHex(digest, sizeof(digest)) : std::string();
    }

    namespace {

        // Читает файл кусками по 64 КБ и подаёт в хэш. whole — до конца файла (bytes не важен),
        // иначе ровно bytes байт: файл короче — false.
        bool hashFile(const std::string& filePath, uint64_t bytes, bool whole, Sha256& hash) {
            const HANDLE file = CreateFileW(extendedPath(filePath).c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
            if (file == INVALID_HANDLE_VALUE) {
                return false;
            }

            std::vector<uint8_t> buffer(64 * 1024);
            uint64_t left = bytes;
            bool ok = true;
            while (whole || left > 0) {
                const DWORD want = (!whole && left < buffer.size()) ? (DWORD)left : (DWORD)buffer.size();
                DWORD got = 0;
                if (!ReadFile(file, buffer.data(), want, &got, NULL)) {
                    ok = false;
                    break;
                }
                if (got == 0) {
                    ok = whole;								// конец файла: для префикса — короче, чем нужно
                    break;
                }
                hash.update(buffer.data(), got);
                left -= whole ? 0 : got;
            }

            CloseHandle(file);
            return ok && hash.ok();
        }
    }

    bool hashFilePrefix(const std::string& filePath, uint64_t bytes, Sha256& hash) {
        return hashFile(filePath, bytes, false, hash);
    }

    std::string calculateSHA256(const std::string& filePath) {
        Sha256 hash;
        if (!hashFile(filePath, 0, true, hash)) {
            return std::string();
        }
        return hash.finishHex();
    }
}
