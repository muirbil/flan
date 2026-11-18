#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "build.hpp"
#include "flan/format.hpp"
#include "flan/index.hpp"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>

bool buildIndexFile(std::vector<BuildEntry> entries, uint64_t generatedAt, std::vector<uint8_t>& file, std::string& error) {
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
	if (poolTooLarge || bodySize > MAX_INDEX_RAW_SIZE || sizeof(Envelope) + bodySize > MAX_INDEX_FILE_SIZE) {
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

	// До этапа 4 индекс не подписан (key_id = 0, подпись — нули), до этапа 2 — не сжат.
	Envelope envelope = {};
	std::memcpy(envelope.magic, ENVELOPE_MAGIC, sizeof(envelope.magic));
	envelope.envelope_version = ENVELOPE_VERSION;
	envelope.key_id = KEY_ID_UNSIGNED;
	envelope.compression = COMPRESSION_NONE;
	envelope.payload_size = (uint32_t)bodySize;
	envelope.raw_size = (uint32_t)bodySize;
	envelope.reserved = 0;

	file.resize(sizeof(Envelope) + (size_t)bodySize);
	uint8_t* cursor = file.data();
	std::memcpy(cursor, &envelope, sizeof(envelope));
	cursor += sizeof(envelope);
	std::memcpy(cursor, &header, sizeof(header));
	cursor += sizeof(header);
	if (!table.empty()) {
		std::memcpy(cursor, table.data(), table.size());
		cursor += table.size();
	}
	if (!pool.empty()) {
		std::memcpy(cursor, pool.data(), pool.size());
	}

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
