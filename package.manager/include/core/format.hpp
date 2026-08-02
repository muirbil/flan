#pragma once
#include <cstdint>

#pragma pack(push, 1)

constexpr uint64_t f_magic(char a, char b, char c, char d, char e, char f, char g) {
	return static_cast<uint64_t>(a)
		| (static_cast<uint64_t>(b) << 8)
		| (static_cast<uint64_t>(c) << 16)
		| (static_cast<uint64_t>(d) << 24)
		| (static_cast<uint64_t>(e) << 32)
		| (static_cast<uint64_t>(f) << 40)
		| (static_cast<uint64_t>(g) << 48);
}

constexpr uint64_t FLAN_MAGIC = f_magic('F', 'L', 'A', 'N', 'D', 'R', 'E');

// Заголовок файла db.flan
struct CoreHeader {
	uint64_t timestamp;									// временная метка бд: offset 0
	uint64_t magic;
	uint32_t db_version;								// версия формата базы: offset 12
	uint32_t package_count;								// кол-во пакетов в индексе: offset 16
	uint32_t string_pool_offset;						// смещение от начала файла, где начинается текст имен: offset 20
};

struct CoreEntry {
	uint64_t hash_v;									// хэш версии, offset 0
	uint32_t name_offset;								// смещение к имени в пуле строк в конце core.flan, offset 8
	uint32_t meta_id;									// уникальный ID пакета: по нему flan будет запрашивать, offset 12
};

static_assert(sizeof(CoreHeader) == 28, "CoreHeader layout changed!");
static_assert(sizeof(CoreEntry) == 16, "CoreEntry layout changed!");

#pragma pack(pop)