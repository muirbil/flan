#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "flan/keys.hpp"

// Подпись индекса в flan-build (DESIGN.md §6.3, §8). Клиенту это не нужно: он только проверяет.

// Пара ключей P-256 в памяти. Приватная часть стирается при разрушении.
struct SigningKey {
	uint8_t id = 0;
	uint8_t publicKey[64] = {};							// X||Y, big-endian — как в keys.hpp
	uint8_t privateKey[32] = {};						// d, big-endian

	SigningKey() = default;
	SigningKey(const SigningKey& other);
	SigningKey& operator=(const SigningKey& other);
	~SigningKey();
	void wipe();
};

// Новая пара из системного генератора случайных чисел CNG.
bool generateSigningKey(uint8_t id, SigningKey& out, std::string& error);

// Подпись r||s дайджеста SHA-256.
bool signDigest(const SigningKey& key, const uint8_t digest[32], uint8_t signature[64], std::string& error);

// Вписывает в конверт key_id ключа и подпись (DESIGN.md §6.1). file — собранный индекс целиком.
bool signIndexFile(std::vector<uint8_t>& file, const SigningKey& key, std::string& error);

// Подпись пересчитывается, а key_id в конверте остаётся каким есть — тестам нужны
// конверты с «неправильным» key_id, но с верной подписью.
bool resignIndexFile(std::vector<uint8_t>& file, const SigningKey& key, std::string& error);

// Тот же ли это ключ, что встроенный с тем же номером: пробная подпись проверяется
// открытым ключом из keys.hpp. false с понятной причиной в error.
bool matchesBuiltInKey(const SigningKey& key, std::string& error);

// Отпечаток открытого ключа для людей: первые 8 байт SHA-256 от X||Y, hex по группам.
std::string keyFingerprint(const uint8_t publicKey[64]);

// Открытый ключ как строка keys.hpp: { 1, { 0x.., ... } },
std::string keyAsCppEntry(uint8_t id, const uint8_t publicKey[64]);
