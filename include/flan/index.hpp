#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "flan/format.hpp"

// Запись индекса после проверки: строки скопированы из пула и прошли validate.hpp.
struct IndexRecord {
	std::string name;
	std::string version;
	std::string url;
	std::string extractDir;
	std::vector<std::string> bins;
	std::string description;
	uint32_t archiveSize = 0;
	uint8_t arch = 0;
	uint8_t kind = 0;
	uint8_t sha256[32] = {};
};

// Порядок записей в индексе: имя побайтово, при равных именах — числовой arch.
// Генератор сортирует, а клиент проверяет порядок одной и той же функцией.
int compareIndexKeys(const std::string& nameA, uint8_t archA, const std::string& nameB, uint8_t archB);

// "x86" / "x64" / "arm64"; для неизвестного значения — nullptr.
const char* archName(uint8_t arch);
bool archFromName(const std::string& name, uint8_t& arch);

enum class FindResult {
	Found,
	NotFound,
	Corrupt,
};

// Индекс в памяти. Владеет буфером файла, поэтому записи из него не висят на чужой памяти.
class IndexView {
public:
	// Шаги приёма DESIGN.md §6.1, кроме подписи и защиты от отката (этап 4): размер файла,
	// конверт, распаковка тела, заголовок тела, границы таблицы и пула строк.
	bool open(std::vector<uint8_t> file, std::string& error);

	// Полная проверка всех записей и порядка сортировки. Вызывается при приёме индекса (sync).
	bool validateAll(std::string& error) const;

	uint32_t count() const;
	uint64_t generatedAt() const;

	// Запись i, полностью проверенная.
	bool record(uint32_t i, IndexRecord& out, std::string& error) const;

	// Двоичный поиск по (name, arch). Границы проверяются у каждой просмотренной записи,
	// строки целиком — только у найденной.
	FindResult find(const std::string& name, uint8_t arch, IndexRecord& out, std::string& error) const;

private:
	void entryAt(uint32_t i, IndexEntry& entry) const;
	bool stringAt(const StrRef& ref, std::string& out) const;
	bool decode(uint32_t i, const IndexEntry& entry, IndexRecord& out, std::string& error) const;

	std::vector<uint8_t> file_;							// нужен только внутри open
	std::vector<uint8_t> body_;							// тело индекса, уже распакованное
	IndexHeader header_ = {};

	// Смещения от начала тела, уже проверенные в open.
	size_t entriesOffset_ = 0;
	size_t stringsOffset_ = 0;
	size_t stringsSize_ = 0;
};
