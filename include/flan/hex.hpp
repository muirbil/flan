#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// SHA-256 лежит в индексе в двоичном виде, а в манифестах, квитанциях и выводе — в hex.

inline std::string toHex(const uint8_t* data, size_t size) {
	static const char digits[] = "0123456789abcdef";

	std::string hex;
	hex.reserve(size * 2);
	for (size_t i = 0; i < size; i++) {
		hex += digits[data[i] >> 4];
		hex += digits[data[i] & 0x0F];
	}
	return hex;
}

// Ровно size * 2 hex-символа в любом регистре; всё остальное — false, и out не трогается.
inline bool fromHex(const std::string& hex, uint8_t* out, size_t size) {
	if (hex.length() != size * 2) {
		return false;
	}

	auto nibble = [](char c) -> int {
		if (c >= '0' && c <= '9') return c - '0';
		if (c >= 'a' && c <= 'f') return c - 'a' + 10;
		if (c >= 'A' && c <= 'F') return c - 'A' + 10;
		return -1;
	};

	for (size_t i = 0; i < hex.length(); i++) {
		if (nibble(hex[i]) < 0) {
			return false;
		}
	}

	for (size_t i = 0; i < size; i++) {
		out[i] = (uint8_t)((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
	}
	return true;
}
