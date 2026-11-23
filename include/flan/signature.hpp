#pragma once
#include <cstdint>

namespace crypto {

	// ECDSA P-256 через CNG (DESIGN.md §6.3). publicKey — X||Y (64 байта, big-endian),
	// digest — SHA-256 подписанных данных, signature — r||s (64 байта).
	// false — подпись неверна, ключ не точка кривой или CNG недоступен.
	bool verifyP256(const uint8_t publicKey[64], const uint8_t digest[32], const uint8_t signature[64]);
}
