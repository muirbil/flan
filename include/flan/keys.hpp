#pragma once
#include <cstddef>
#include <cstdint>
#include "flan/format.hpp"

// Встроенные открытые ключи подписи индекса (DESIGN.md §6.3). Общие для клиента и flan-build:
// генератор проверяет каждую свою подпись тем же ключом, которым её проверит клиент.

struct IndexKey {
	uint8_t id;											// номер ключа = key_id в конверте; только растёт
	uint8_t publicKey[64];								// X||Y точки P-256, big-endian
};

// Тестовые ключи — только в Debug-сборках; их приватные части лежат в tests\keys\ открыто.
constexpr uint8_t FIRST_TEST_KEY_ID = 240;

namespace keys_detail {

	constexpr IndexKey BUILT_IN[] = {
		// Настоящие ключи — рабочий и запасной, из вывода flan-build keygen (этап 4, шаг 8).
#ifdef _DEBUG
		// Тестовые ключи 240 и 241 появятся вместе с flan-build keygen.
#endif
		// Конец списка: ключа с номером 0 нет, KEY_ID_UNSIGNED — «без подписи».
		{ KEY_ID_UNSIGNED, {} },
	};

	constexpr bool releaseHasNoTestKeys() {
		for (const IndexKey& key : BUILT_IN) {
			if (key.id >= FIRST_TEST_KEY_ID) {
				return false;
			}
		}
		return true;
	}
}

#ifndef _DEBUG
static_assert(keys_detail::releaseHasNoTestKeys(), "Release builds must not trust the test keys!");
#endif

// Ключи без завершающей записи.
inline const IndexKey* builtInKeys(size_t& count) {
	count = sizeof(keys_detail::BUILT_IN) / sizeof(keys_detail::BUILT_IN[0]) - 1;
	return keys_detail::BUILT_IN;
}
