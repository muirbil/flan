#pragma once
#include <cstddef>
#include <cstdint>

// Раскладка index.flan, формат 2 (DESIGN.md §6).
// Все числа little-endian — как и на всех архитектурах Windows, поэтому структуры
// читаются из буфера простым memcpy. Размеры и смещения закреплены static_assert:
// случайно сдвинутое поле ломает сборку, а не совместимость с уже выпущенными индексами.

#pragma pack(push, 1)

// Конверт — то, что лежит на сервере.
struct Envelope {
	char     magic[8];									// "FLANIDX\0"
	uint16_t envelope_version;							// = ENVELOPE_VERSION
	uint8_t  key_id;									// какой встроенный ключ проверяет подпись; 0 = без подписи
	uint8_t  compression;								// COMPRESSION_*
	uint32_t payload_size;								// байт тела после конверта (сжатого)
	uint32_t raw_size;									// байт тела после распаковки
	uint32_t reserved;									// = 0
	uint8_t  signature[64];								// ECDSA P-256, r||s; при key_id = 0 — нули
};

// Заголовок тела. Таблица записей идёт сразу за ним.
struct IndexHeader {
	char     magic[8];									// "FLANBODY"
	uint16_t format;									// = INDEX_FORMAT
	uint16_t entry_size;								// >= sizeof(IndexEntry): новые поля дописываются в конец записи
	uint32_t entry_count;
	uint64_t generated_at;								// unix-время сборки; монотонно растёт
	uint32_t strings_offset;							// от начала тела
	uint32_t strings_size;
};

// Строка в пуле: off — от начала пула (strings_offset), без '\0'.
struct StrRef {
	uint32_t off;
	uint32_t len;
};

struct IndexEntry {
	StrRef   name;
	StrRef   version;
	StrRef   url;
	StrRef   extract_dir;								// len = 0 -> корень архива
	StrRef   bins;										// "rg.exe" или "bin\\a.exe;bin\\b.exe"
	StrRef   description;
	uint32_t archive_size;								// точный размер архива в байтах
	uint8_t  arch;										// ARCH_*
	uint8_t  kind;										// KIND_*
	uint16_t reserved;
	uint8_t  sha256[32];								// бинарный, не hex
};

#pragma pack(pop)

static_assert(sizeof(Envelope) == 88, "Envelope layout changed!");
// Подпись покрывает ровно первые 24 байта конверта.
static_assert(offsetof(Envelope, signature) == 24, "Envelope signature offset changed!");
static_assert(sizeof(IndexHeader) == 32, "IndexHeader layout changed!");
static_assert(sizeof(StrRef) == 8, "StrRef layout changed!");
static_assert(sizeof(IndexEntry) == 88, "IndexEntry layout changed!");

constexpr char ENVELOPE_MAGIC[8] = { 'F', 'L', 'A', 'N', 'I', 'D', 'X', '\0' };
constexpr char INDEX_BODY_MAGIC[8] = { 'F', 'L', 'A', 'N', 'B', 'O', 'D', 'Y' };

constexpr uint16_t ENVELOPE_VERSION = 1;
constexpr uint16_t INDEX_FORMAT = 2;

// Длина той части конверта, которую покрывает подпись (DESIGN.md §6.1).
constexpr size_t SIGNED_ENVELOPE_PREFIX = offsetof(Envelope, signature);

constexpr uint8_t KEY_ID_UNSIGNED = 0;

constexpr uint8_t COMPRESSION_NONE = 0;
constexpr uint8_t COMPRESSION_DEFLATE = 1;

constexpr uint8_t ARCH_X86 = 1;
constexpr uint8_t ARCH_X64 = 2;
constexpr uint8_t ARCH_ARM64 = 3;

constexpr uint8_t KIND_ZIP = 1;
constexpr uint8_t KIND_EXE = 2;

// Потолки из DESIGN.md §6.1 и §5.3.
constexpr uint64_t MAX_INDEX_FILE_SIZE = 8ull * 1024 * 1024;
constexpr uint64_t MAX_INDEX_RAW_SIZE = 32ull * 1024 * 1024;
constexpr uint32_t MAX_ARCHIVE_SIZE = 512u * 1024 * 1024;

// Запись длиннее этого — заведомо мусор, а не поля из будущих версий.
constexpr uint16_t MAX_ENTRY_SIZE = 4096;

// Самая длинная законная строка индекса — список bins (8 путей по 160 байт) или URL.
constexpr uint32_t MAX_INDEX_STRING_LENGTH = 4096;
