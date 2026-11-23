#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <bcrypt.h>
#include "signing.hpp"
#include "flan/format.hpp"
#include "flan/hex.hpp"
#include "flan/index.hpp"
#include "flan/sha256.hpp"
#include "flan/signature.hpp"
#include <cstdio>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

namespace {

	// BCRYPT_ECCPRIVATE_BLOB для P-256: заголовок, X, Y, d по 32 байта.
	constexpr size_t PRIVATE_BLOB_SIZE = sizeof(BCRYPT_ECCKEY_BLOB) + 96;

	// Провайдер ECDSA P-256 на время одного действия.
	struct Provider {
		BCRYPT_ALG_HANDLE handle = NULL;
		Provider() {
			if (BCryptOpenAlgorithmProvider(&handle, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) < 0) {
				handle = NULL;
			}
		}
		~Provider() {
			if (handle != NULL) {
				BCryptCloseAlgorithmProvider(handle, 0);
			}
		}
	};

	std::string status(const char* what, NTSTATUS code) {
		char text[16];
		std::snprintf(text, sizeof(text), "0x%08lX", (unsigned long)code);
		return std::string(what) + " (" + text + ")";
	}
}

SigningKey::SigningKey(const SigningKey& other) {
	*this = other;
}

SigningKey& SigningKey::operator=(const SigningKey& other) {
	if (this != &other) {
		id = other.id;
		std::memcpy(publicKey, other.publicKey, sizeof(publicKey));
		std::memcpy(privateKey, other.privateKey, sizeof(privateKey));
	}
	return *this;
}

SigningKey::~SigningKey() {
	wipe();
}

void SigningKey::wipe() {
	SecureZeroMemory(privateKey, sizeof(privateKey));
}

bool generateSigningKey(uint8_t id, SigningKey& out, std::string& error) {
	Provider provider;
	if (provider.handle == NULL) {
		error = "ECDSA P-256 is not available in CNG";
		return false;
	}

	BCRYPT_KEY_HANDLE key = NULL;
	NTSTATUS code = BCryptGenerateKeyPair(provider.handle, &key, 256, 0);
	if (code < 0) {
		error = status("cannot generate a key pair", code);
		return false;
	}
	code = BCryptFinalizeKeyPair(key, 0);

	uint8_t blob[PRIVATE_BLOB_SIZE];
	ULONG written = 0;
	if (code >= 0) {
		code = BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, blob, (ULONG)sizeof(blob), &written, 0);
	}
	BCryptDestroyKey(key);
	if (code < 0 || written != sizeof(blob)) {
		SecureZeroMemory(blob, sizeof(blob));
		error = status("cannot export the new key", code);
		return false;
	}

	out.id = id;
	std::memcpy(out.publicKey, blob + sizeof(BCRYPT_ECCKEY_BLOB), 64);
	std::memcpy(out.privateKey, blob + sizeof(BCRYPT_ECCKEY_BLOB) + 64, 32);
	SecureZeroMemory(blob, sizeof(blob));
	return true;
}

bool signDigest(const SigningKey& key, const uint8_t digest[32], uint8_t signature[64], std::string& error) {
	Provider provider;
	if (provider.handle == NULL) {
		error = "ECDSA P-256 is not available in CNG";
		return false;
	}

	uint8_t blob[PRIVATE_BLOB_SIZE];
	BCRYPT_ECCKEY_BLOB header = {};
	header.dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
	header.cbKey = 32;
	std::memcpy(blob, &header, sizeof(header));
	std::memcpy(blob + sizeof(header), key.publicKey, 64);
	std::memcpy(blob + sizeof(header) + 64, key.privateKey, 32);

	BCRYPT_KEY_HANDLE handle = NULL;
	NTSTATUS code = BCryptImportKeyPair(provider.handle, NULL, BCRYPT_ECCPRIVATE_BLOB, &handle, blob, (ULONG)sizeof(blob), 0);
	SecureZeroMemory(blob, sizeof(blob));
	if (code < 0) {
		error = status("the private key is not a valid P-256 key", code);
		return false;
	}

	ULONG written = 0;
	code = BCryptSignHash(handle, NULL, const_cast<PUCHAR>(digest), 32, signature, 64, &written, 0);
	BCryptDestroyKey(handle);
	if (code < 0 || written != 64) {
		error = status("cannot sign", code);
		return false;
	}
	return true;
}

bool resignIndexFile(std::vector<uint8_t>& file, const SigningKey& key, std::string& error) {
	if (file.size() < sizeof(Envelope)) {
		error = "the index is shorter than its envelope";
		return false;
	}

	uint8_t digest[32];
	if (!indexSignedDigest(file, digest)) {
		error = "cannot hash the index";
		return false;
	}
	uint8_t signature[64];
	if (!signDigest(key, digest, signature, error)) {
		return false;
	}
	std::memcpy(file.data() + offsetof(Envelope, signature), signature, sizeof(signature));
	return true;
}

bool signIndexFile(std::vector<uint8_t>& file, const SigningKey& key, std::string& error) {
	if (key.id == KEY_ID_UNSIGNED) {
		error = "key number 0 means 'unsigned'";
		return false;
	}
	if (file.size() < sizeof(Envelope)) {
		error = "the index is shorter than its envelope";
		return false;
	}
	// key_id лежит в первых 24 байтах конверта, поэтому сам покрыт подписью.
	file[offsetof(Envelope, key_id)] = key.id;
	return resignIndexFile(file, key, error);
}

bool matchesBuiltInKey(const SigningKey& key, std::string& error) {
	size_t count = 0;
	const IndexKey* keys = builtInKeys(count);
	const IndexKey* builtIn = nullptr;
	for (size_t i = 0; i < count; i++) {
		if (keys[i].id == key.id) {
			builtIn = &keys[i];
		}
	}
	if (builtIn == nullptr) {
		error = "key " + std::to_string(key.id) + " is not in keys.hpp of this flan-build; clients would reject what it signs";
		return false;
	}
	if (std::memcmp(builtIn->publicKey, key.publicKey, 64) != 0) {
		error = "key " + std::to_string(key.id) + " differs from the key with the same number in keys.hpp";
		return false;
	}

	// Пробная подпись: приватная часть действительно соответствует открытой из keys.hpp.
	uint8_t digest[32];
	uint8_t signature[64];
	crypto::Sha256 hash;
	hash.update("flan key check", 14);
	if (!hash.finish(digest) || !signDigest(key, digest, signature, error)) {
		return false;
	}
	if (!crypto::verifyP256(builtIn->publicKey, digest, signature)) {
		error = "a test signature of key " + std::to_string(key.id) + " does not verify against keys.hpp";
		return false;
	}
	return true;
}

std::string keyFingerprint(const uint8_t publicKey[64]) {
	crypto::Sha256 hash;
	hash.update(publicKey, 64);
	uint8_t digest[32];
	if (!hash.finish(digest)) {
		return "?";
	}
	const std::string hex = toHex(digest, 8);
	std::string out;
	for (size_t i = 0; i < hex.size(); i += 4) {
		out += (i == 0 ? "" : " ") + hex.substr(i, 4);
	}
	return out;
}

std::string keyAsCppEntry(uint8_t id, const uint8_t publicKey[64]) {
	static const char digits[] = "0123456789ABCDEF";
	std::string out = "\t\t{ " + std::to_string(id) + ", {\n";
	for (int i = 0; i < 64; i++) {
		if (i % 16 == 0) {
			out += "\t\t\t";
		}
		out += "0x";
		out += digits[publicKey[i] >> 4];
		out += digits[publicKey[i] & 15];
		out += (i == 63) ? "\n" : (i % 16 == 15 ? ",\n" : ", ");
	}
	out += "\t\t} },\n";
	return out;
}
