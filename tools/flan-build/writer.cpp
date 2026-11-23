#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "build.hpp"
#include "signing.hpp"
#include "flan/format.hpp"
#include "flan/index.hpp"

// Те же настройки, что в miniz_full.c.
#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#define MINIZ_NO_ZLIB_APIS
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#include "miniz.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>

bool buildIndexFile(std::vector<BuildEntry> entries, uint64_t generatedAt, const SigningKey& key,
	std::vector<uint8_t>& file, std::string& error) {
	file.clear();

	// Порядок — та же функция, которой клиент проверяет сортировку и ищет запись.
	std::sort(entries.begin(), entries.end(), [](const BuildEntry& a, const BuildEntry& b) {
		return compareIndexKeys(a.name, a.arch, b.name, b.arch) < 0;
	});

	for (size_t i = 1; i < entries.size(); i++) {
		if (compareIndexKeys(entries[i - 1].name, entries[i - 1].arch, entries[i].name, entries[i].arch) == 0) {
			error = "duplicate build " + entries[i].name + " / " + archName(entries[i].arch);
			return false;
		}
	}

	// Пул строк. Одинаковые строки (описание у сборок x86 и x64) хранятся один раз.
	std::string pool;
	std::map<std::string, StrRef> interned;
	bool poolTooLarge = false;

	auto intern = [&](const std::string& text) -> StrRef {
		if (text.empty()) {
			return StrRef{ 0, 0 };
		}

		const auto it = interned.find(text);
		if (it != interned.end()) {
			return it->second;
		}

		if (pool.size() + text.size() > MAX_INDEX_RAW_SIZE) {
			poolTooLarge = true;
			return StrRef{ 0, 0 };
		}

		const StrRef ref{ (uint32_t)pool.size(), (uint32_t)text.size() };
		pool += text;
		interned.emplace(text, ref);
		return ref;
	};

	if ((uint64_t)entries.size() * sizeof(IndexEntry) > MAX_INDEX_RAW_SIZE) {
		error = "too many builds for one index";
		return false;
	}

	std::vector<uint8_t> table(entries.size() * sizeof(IndexEntry), 0);
	for (size_t i = 0; i < entries.size(); i++) {
		const BuildEntry& source = entries[i];

		IndexEntry entry = {};
		entry.name = intern(source.name);
		entry.version = intern(source.version);
		entry.url = intern(source.url);
		entry.extract_dir = intern(source.extractDir);
		entry.bins = intern(source.binList);
		entry.description = intern(source.description);
		entry.archive_size = source.archiveSize;
		entry.arch = source.arch;
		entry.kind = source.kind;
		entry.reserved = 0;
		std::memcpy(entry.sha256, source.sha256, sizeof(entry.sha256));

		std::memcpy(table.data() + i * sizeof(IndexEntry), &entry, sizeof(IndexEntry));
	}

	const uint64_t bodySize = sizeof(IndexHeader) + (uint64_t)table.size() + pool.size();
	if (poolTooLarge || bodySize > MAX_INDEX_RAW_SIZE) {
		error = "index is larger than the format allows";
		return false;
	}

	IndexHeader header = {};
	std::memcpy(header.magic, INDEX_BODY_MAGIC, sizeof(header.magic));
	header.format = INDEX_FORMAT;
	header.entry_size = (uint16_t)sizeof(IndexEntry);
	header.entry_count = (uint32_t)entries.size();
	header.generated_at = generatedAt;
	header.strings_offset = (uint32_t)(sizeof(IndexHeader) + table.size());
	header.strings_size = (uint32_t)pool.size();

	std::vector<uint8_t> body(sizeof(header));
	std::memcpy(body.data(), &header, sizeof(header));
	body.insert(body.end(), table.begin(), table.end());
	body.insert(body.end(), pool.begin(), pool.end());

	// Тело сжимается raw deflate (DESIGN.md §6.1): на медленном канале индекс — самое
	// частое, что качается.
	std::vector<uint8_t> payload;
	if (!deflateRaw(body, payload)) {
		error = "cannot compress the index body";
		return false;
	}

	if (sizeof(Envelope) + (uint64_t)payload.size() > MAX_INDEX_FILE_SIZE) {
		error = "index is larger than the format allows";
		return false;
	}

	Envelope envelope = {};
	std::memcpy(envelope.magic, ENVELOPE_MAGIC, sizeof(envelope.magic));
	envelope.envelope_version = ENVELOPE_VERSION;
	envelope.key_id = KEY_ID_UNSIGNED;
	envelope.compression = COMPRESSION_DEFLATE;
	envelope.payload_size = (uint32_t)payload.size();
	envelope.raw_size = (uint32_t)body.size();
	envelope.reserved = 0;

	file.resize(sizeof(Envelope));
	std::memcpy(file.data(), &envelope, sizeof(envelope));
	file.insert(file.end(), payload.begin(), payload.end());

	// Подпись покрывает первые 24 байта конверта (с key_id) и тело (DESIGN.md §6.1).
	if (!signIndexFile(file, key, error)) {
		file.clear();
		return false;
	}
	return true;
}

bool deflateRaw(const std::vector<uint8_t>& data, std::vector<uint8_t>& out) {
	out.clear();

	// Уровень 10 (наибольшее сжатие miniz), окно -15 — raw deflate без заголовка zlib,
	// стратегия по умолчанию. Индекс собирается редко, поэтому время сжатия неважно.
	const int flags = (int)tdefl_create_comp_flags_from_zip_params(10, -15, 0);

	size_t size = 0;
	void* compressed = tdefl_compress_mem_to_heap(data.data(), data.size(), &size, flags);
	if (compressed == nullptr) {
		return false;
	}

	out.assign(static_cast<const uint8_t*>(compressed), static_cast<const uint8_t*>(compressed) + size);
	mz_free(compressed);
	return true;
}

bool writeFileAtomically(const fs::path& path, const void* data, size_t size, std::string& error) {
	fs::path temporary = path;
	temporary += ".tmp";

	std::error_code ec;
	{
		std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
		if (!out) {
			error = "cannot create " + temporary.string();
			return false;
		}

		out.write(static_cast<const char*>(data), (std::streamsize)size);
		out.close();
		if (!out) {
			fs::remove(temporary, ec);
			error = "cannot write " + temporary.string();
			return false;
		}
	}

	if (!MoveFileExW(temporary.wstring().c_str(), path.wstring().c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		error = "cannot replace " + path.string() + " (code " + std::to_string(GetLastError()) + ")";
		fs::remove(temporary, ec);
		return false;
	}

	return true;
}
