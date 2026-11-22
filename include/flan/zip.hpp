#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Свой zip (DESIGN.md §7.3) — общий для клиента и flan-build: генератор отвергает всё,
// что отверг бы клиент, тем же кодом. Только stored и deflate (tinfl), без ZIP64.
// Все имена проверяются в open, до записи хотя бы одного байта.

constexpr uint64_t MAX_UNPACKED_SIZE = 2ull * 1024 * 1024 * 1024;	// суммарно на архив
constexpr uint64_t MAX_COMPRESSION_RATIO = 1000;					// на одну запись

struct ZipEntry {
	std::string name;						// UTF-8, сегменты через '\', без '\' в конце
	std::wstring wideName;					// то же в UTF-16 — для ФС и сравнения без учёта регистра
	bool directory = false;
	uint16_t method = 0;					// 0 — stored, 8 — deflate
	uint32_t crc32 = 0;
	uint64_t compressedSize = 0;
	uint64_t size = 0;
	uint64_t localHeaderOffset = 0;
	uint64_t dataOffset = 0;				// начало данных, после локального заголовка
};

class ZipArchive {
public:
	ZipArchive() = default;
	~ZipArchive();
	ZipArchive(const ZipArchive&) = delete;
	ZipArchive& operator=(const ZipArchive&) = delete;

	// Центральный каталог, локальные заголовки и все запреты §7.3, кроме CRC
	// (его проверяет readEntry). path — UTF-8.
	bool open(const std::string& path, std::string& error);

	const std::vector<ZipEntry>& entries() const { return entries_; }
	uint64_t unpackedSize() const { return unpackedSize_; }

	// Распаковывает запись потоком (словарь 32 КБ) в открытый на запись файл outFile (HANDLE)
	// или, если outFile == nullptr, только проверяет: размер и CRC32 обязаны сойтись.
	bool readEntry(const ZipEntry& entry, void* outFile, std::string& error);

private:
	bool readAt(uint64_t offset, void* buffer, size_t size);

	void* file_ = nullptr;					// HANDLE
	uint64_t fileSize_ = 0;
	uint64_t unpackedSize_ = 0;
	std::vector<ZipEntry> entries_;
};

// Совпадают ли два пути без учёта регистра так, как его понимает NTFS (CompareStringOrdinal).
bool equalIgnoreCaseOrdinal(const std::wstring& a, const std::wstring& b);

// Ищет запись-файл по каноническому относительному пути (через '\') без учёта регистра.
const ZipEntry* findZipFile(const std::vector<ZipEntry>& entries, const std::string& path);

// Есть ли в архиве каталог dir — как запись-каталог или как префикс любого имени.
bool zipHasDirectory(const std::vector<ZipEntry>& entries, const std::string& dir);

// Распаковка в каталог destination (существующий и пустой): только записи внутри extractDir
// (пусто — весь архив), префикс срезается. Файлы создаются с CREATE_NEW и обычными атрибутами.
bool extractZip(ZipArchive& archive, const std::string& extractDir, const std::string& destination, std::string& error);
