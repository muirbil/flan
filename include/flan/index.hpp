#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "flan/format.hpp"
#include "flan/keys.hpp"

// Каким ключам верить при открытии индекса (DESIGN.md §6.1, шаги 2–3).
struct IndexTrust {
	const IndexKey* keys = nullptr;
	size_t count = 0;

	// Индекс без подписи (key_id = 0). Клиент не принимает его никогда; flan-build — только
	// как предыдущий индекс, поверх которого собирается первый подписанный (DESIGN.md §8).
	bool allowUnsigned = false;
};

// Встроенные ключи keys.hpp, без неподписанных индексов.
IndexTrust builtInTrust();

// SHA-256 того, что покрывает подпись: первые 24 байта конверта и тело (DESIGN.md §6.1).
// file — файл целиком, не короче конверта и согласованный с payload_size.
bool indexSignedDigest(const std::vector<uint8_t>& file, uint8_t digest[32]);

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
	// Шаги приёма DESIGN.md §6.1, кроме защиты от отката (её делает sync): размер файла,
	// конверт, подпись, распаковка тела, заголовок тела, границы таблицы и пула строк.
	// До проверки подписи ни один байт тела не попадает в распаковщик или разбор.
	bool open(std::vector<uint8_t> file, std::string& error, const IndexTrust& trust = builtInTrust());

	// Полная проверка всех записей и порядка сортировки. Вызывается при приёме индекса (sync).
	bool validateAll(std::string& error) const;

	uint32_t count() const;
	uint64_t generatedAt() const;
	uint8_t keyId() const;								// key_id конверта; KEY_ID_UNSIGNED — без подписи

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
	uint8_t keyId_ = KEY_ID_UNSIGNED;

	// Смещения от начала тела, уже проверенные в open.
	size_t entriesOffset_ = 0;
	size_t stringsOffset_ = 0;
	size_t stringsSize_ = 0;
};
