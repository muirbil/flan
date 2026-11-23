#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>
#include "flan/signature.hpp"
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

namespace crypto {

	bool verifyP256(const uint8_t publicKey[64], const uint8_t digest[32], const uint8_t signature[64]) {
		BCRYPT_ALG_HANDLE algorithm = NULL;
		if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) < 0) {
			return false;
		}

		// BCRYPT_ECCPUBLIC_BLOB: заголовок, затем X и Y по 32 байта.
		uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
		BCRYPT_ECCKEY_BLOB header = {};
		header.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
		header.cbKey = 32;
		std::memcpy(blob, &header, sizeof(header));
		std::memcpy(blob + sizeof(header), publicKey, 64);

		// Точку вне кривой CNG не импортирует — такой ключ ничего не подтверждает.
		BCRYPT_KEY_HANDLE key = NULL;
		bool valid = false;
		if (BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB, &key, blob, (ULONG)sizeof(blob), 0) >= 0) {
			valid = BCryptVerifySignature(key, NULL, const_cast<PUCHAR>(digest), 32, const_cast<PUCHAR>(signature), 64, 0) == 0;
			BCryptDestroyKey(key);
		}
		BCryptCloseAlgorithmProvider(algorithm, 0);
		return valid;
	}
}
