#include "flan/index.hpp"
#include "flan/inflate.hpp"
#include "flan/sha256.hpp"
#include "flan/signature.hpp"
#include "flan/validate.hpp"
#include <cstring>
#include <utility>

IndexTrust builtInTrust() {
	IndexTrust trust;
	trust.keys = builtInKeys(trust.count);
	return trust;
}

bool indexSignedDigest(const std::vector<uint8_t>& file, uint8_t digest[32]) {
	if (file.size() < sizeof(Envelope)) {
		return false;
	}
	crypto::Sha256 hash;
	hash.update(file.data(), SIGNED_ENVELOPE_PREFIX);
	hash.update(file.data() + sizeof(Envelope), file.size() - sizeof(Envelope));
	return hash.finish(digest);
}

int compareIndexKeys(const std::string& nameA, uint8_t archA, const std::string& nameB, uint8_t archB) {
	// std::string::compare сравнивает char как unsigned char, то есть побайтово.
	const int byName = nameA.compare(nameB);
	if (byName != 0) {
		return byName < 0 ? -1 : 1;
	}

	if (archA != archB) {
		return archA < archB ? -1 : 1;
	}

	return 0;
}

const char* archName(uint8_t arch) {
	switch (arch) {
	case ARCH_X86: return "x86";
	case ARCH_X64: return "x64";
	case ARCH_ARM64: return "arm64";
	default: return nullptr;
	}
}

bool archFromName(const std::string& name, uint8_t& arch) {
	if (name == "x86") { arch = ARCH_X86; return true; }
	if (name == "x64") { arch = ARCH_X64; return true; }
	if (name == "arm64") { arch = ARCH_ARM64; return true; }
	return false;
}

bool IndexView::open(std::vector<uint8_t> file, std::string& error, const IndexTrust& trust) {
	file_ = std::move(file);
	body_.clear();
	header_ = {};
	keyId_ = KEY_ID_UNSIGNED;
	entriesOffset_ = stringsOffset_ = stringsSize_ = 0;

	// Вся арифметика смещений — в 64 битах: в 32-битной сборке произведения
	// вроде entry_count * entry_size переполнились бы и «уместились» в любой файл.
	const uint64_t fileSize = file_.size();

	// Шаг 1: размер.
	if (fileSize < sizeof(Envelope) || fileSize > MAX_INDEX_FILE_SIZE) {
		error = "index file size is out of bounds";
		return false;
	}

	Envelope envelope = {};
	std::memcpy(&envelope, file_.data(), sizeof(Envelope));

	if (std::memcmp(envelope.magic, ENVELOPE_MAGIC, sizeof(ENVELOPE_MAGIC)) != 0) {
		error = "not a flan index";
		return false;
	}

	if ((uint64_t)sizeof(Envelope) + envelope.payload_size != fileSize) {
		error = "index file size does not match its envelope";
		return false;
	}

	// Шаг 2: поля конверта.
	if (envelope.envelope_version != ENVELOPE_VERSION) {
		error = "unsupported index envelope version " + std::to_string(envelope.envelope_version);
		return false;
	}

	if (envelope.reserved != 0) {
		error = "index envelope is corrupted (reserved field is not zero)";
		return false;
	}

	// Шаги 2–3: известный ключ и подпись. Неподписанный индекс клиент не принимает безусловно —
	// без флагов и переменных окружения, иначе «снять подпись» было бы тривиально (§6.1).
	if (envelope.key_id == KEY_ID_UNSIGNED) {
		if (!trust.allowUnsigned) {
			error = "index is not signed; this version of flan accepts only signed indexes";
			return false;
		}
		for (const uint8_t b : envelope.signature) {
			if (b != 0) {
				error = "unsigned index carries a non-zero signature";
				return false;
			}
		}
	}
	else {
		const IndexKey* key = nullptr;
		for (size_t i = 0; i < trust.count && key == nullptr; i++) {
			if (trust.keys[i].id == envelope.key_id) {
				key = &trust.keys[i];
			}
		}
		if (key == nullptr) {
			error = "index is signed with key " + std::to_string(envelope.key_id) + ", unknown to this version of flan";
			return false;
		}

		uint8_t digest[32];
		if (!indexSignedDigest(file_, digest)) {
			error = "cannot hash the index";
			return false;
		}
		if (!crypto::verifyP256(key->publicKey, digest, envelope.signature)) {
			error = "index signature is invalid (the file is corrupted or tampered with)";
			return false;
		}
	}
	keyId_ = envelope.key_id;

	// Шаг 4: тело. Потолок raw_size проверяется до распаковки, а распакованное
	// обязано быть ровно raw_size байт (DESIGN.md §6.1).
	if (envelope.raw_size > MAX_INDEX_RAW_SIZE) {
		error = "index body is too large";
		return false;
	}

	const uint8_t* payload = file_.data() + sizeof(Envelope);
	if (envelope.compression == COMPRESSION_NONE) {
		if (envelope.payload_size != envelope.raw_size) {
			error = "uncompressed index has payload_size != raw_size";
			return false;
		}
		body_.assign(payload, payload + envelope.payload_size);
	}
	else if (envelope.compression == COMPRESSION_DEFLATE) {
		if (!inflateRawExact(payload, envelope.payload_size, envelope.raw_size, body_, error)) {
			error = "index body is corrupted (" + error + ")";
			return false;
		}
	}
	else {
		error = "index compression " + std::to_string(envelope.compression) + " is not supported by this version of flan";
		return false;
	}

	// Файл больше не нужен: дальше всё читается из тела.
	file_.clear();
	file_.shrink_to_fit();

	const uint64_t bodySize = body_.size();

	// Шаг 5: заголовок тела и границы.
	if (bodySize < sizeof(IndexHeader)) {
		error = "index body is truncated";
		return false;
	}

	std::memcpy(&header_, body_.data(), sizeof(IndexHeader));

	if (std::memcmp(header_.magic, INDEX_BODY_MAGIC, sizeof(INDEX_BODY_MAGIC)) != 0) {
		error = "index body is corrupted (bad magic)";
		return false;
	}

	if (header_.format != INDEX_FORMAT) {
		error = "index format " + std::to_string(header_.format) + " is not supported by this version of flan";
		return false;
	}

	// Длиннее известного — поля из будущих версий, их пропускаем; короче — повреждение.
	if (header_.entry_size < sizeof(IndexEntry) || header_.entry_size > MAX_ENTRY_SIZE) {
		error = "index body is corrupted (bad entry size)";
		return false;
	}

	const uint64_t tableEnd = sizeof(IndexHeader) + (uint64_t)header_.entry_count * header_.entry_size;
	if (tableEnd > bodySize) {
		error = "index body is corrupted (entry table is out of bounds)";
		return false;
	}

	if (header_.strings_offset < tableEnd ||
		(uint64_t)header_.strings_offset + header_.strings_size > bodySize) {
		error = "index body is corrupted (string pool is out of bounds)";
		return false;
	}

	entriesOffset_ = sizeof(IndexHeader);
	stringsOffset_ = header_.strings_offset;
	stringsSize_ = header_.strings_size;
	return true;
}

uint32_t IndexView::count() const {
	return header_.entry_count;
}

uint64_t IndexView::generatedAt() const {
	return header_.generated_at;
}

uint8_t IndexView::keyId() const {
	return keyId_;
}

void IndexView::entryAt(uint32_t i, IndexEntry& entry) const {
	// Границы всей таблицы проверены в open, а i < entry_count проверяют вызывающие.
	// Читается только известная часть записи: хвост из будущих версий пропускается.
	const size_t offset = entriesOffset_ + (size_t)((uint64_t)i * header_.entry_size);
	std::memcpy(&entry, body_.data() + offset, sizeof(IndexEntry));
}

bool IndexView::stringAt(const StrRef& ref, std::string& out) const {
	if (ref.len > MAX_INDEX_STRING_LENGTH || (uint64_t)ref.off + ref.len > stringsSize_) {
		return false;
	}

	out.assign(reinterpret_cast<const char*>(body_.data() + stringsOffset_ + ref.off), ref.len);
	return true;
}

bool IndexView::decode(uint32_t i, const IndexEntry& entry, IndexRecord& out, std::string& error) const {
	const std::string where = "index entry " + std::to_string(i) + ": ";

	std::string bins;
	if (!stringAt(entry.name, out.name) || !stringAt(entry.version, out.version) ||
		!stringAt(entry.url, out.url) || !stringAt(entry.extract_dir, out.extractDir) ||
		!stringAt(entry.bins, bins) || !stringAt(entry.description, out.description)) {
		error = where + "string is out of bounds";
		return false;
	}

	// Те же проверки, что и в генераторе. Индекс подписан, но двойная проверка
	// дешёвая и защищает от ошибки в самом генераторе (DESIGN.md §6.2).
	if (!isSafePackageName(out.name)) {
		error = where + "unsafe package name";
		return false;
	}

	if (!isSafeName(out.version)) {
		error = where + "unsafe version";
		return false;
	}

	if (!isSafePackageUrl(out.url)) {
		error = where + "unsafe URL";
		return false;
	}

	if (!out.extractDir.empty() && !isCanonicalRelativePath(out.extractDir)) {
		error = where + "unsafe extract_dir";
		return false;
	}

	if (!parseBinList(bins, out.bins)) {
		error = where + "unsafe bins";
		return false;
	}

	if (!isSafeDescription(out.description)) {
		error = where + "unsafe description";
		return false;
	}

	if (entry.archive_size == 0 || entry.archive_size > MAX_ARCHIVE_SIZE) {
		error = where + "archive size is out of bounds";
		return false;
	}

	if (archName(entry.arch) == nullptr) {
		error = where + "unknown architecture";
		return false;
	}

	if (entry.kind != KIND_ZIP && entry.kind != KIND_EXE) {
		error = where + "unknown package kind";
		return false;
	}

	// Одиночный .exe (DESIGN.md §5.2): файл ложится в каталог версии под единственным
	// именем из bins, поэтому подкаталогов в нём быть не может, а extract_dir не к чему применить.
	if (entry.kind == KIND_EXE &&
		(out.bins.size() != 1 || out.bins[0].find('\\') != std::string::npos || !out.extractDir.empty())) {
		error = where + "an exe package must have exactly one bin without folders and no extract_dir";
		return false;
	}

	// Пакет flan — сам flan (DESIGN.md §5.3, §7.9): один flan.exe. Команда flan зарезервирована за ним.
	if (out.name == "flan") {
		if (entry.kind != KIND_EXE || out.bins[0] != "flan.exe") {
			error = where + "the flan package must be a single flan.exe (kind exe)";
			return false;
		}
	}
	else {
		for (const std::string& bin : out.bins) {
			if (toLowerAscii(commandNameFromBin(bin)) == "flan") {
				error = where + "the command 'flan' is reserved for flan itself";
				return false;
			}
		}
	}

	out.archiveSize = entry.archive_size;
	out.arch = entry.arch;
	out.kind = entry.kind;
	std::memcpy(out.sha256, entry.sha256, sizeof(out.sha256));
	return true;
}

bool IndexView::record(uint32_t i, IndexRecord& out, std::string& error) const {
	if (i >= header_.entry_count) {
		error = "index entry " + std::to_string(i) + " does not exist";
		return false;
	}

	IndexEntry entry = {};
	entryAt(i, entry);
	return decode(i, entry, out, error);
}

bool IndexView::validateAll(std::string& error) const {
	IndexRecord previous;

	for (uint32_t i = 0; i < header_.entry_count; i++) {
		IndexRecord current;
		if (!record(i, current, error)) {
			return false;
		}

		// Строго по возрастанию: заодно исключает повтор пары (name, arch).
		if (i > 0 && compareIndexKeys(previous.name, previous.arch, current.name, current.arch) >= 0) {
			error = "index entry " + std::to_string(i) + ": entries are not sorted or duplicated";
			return false;
		}

		previous = std::move(current);
	}

	return true;
}

FindResult IndexView::find(const std::string& name, uint8_t arch, IndexRecord& out, std::string& error) const {
	uint32_t low = 0;
	uint32_t high = header_.entry_count;

	while (low < high) {
		const uint32_t middle = low + (high - low) / 2;

		IndexEntry entry = {};
		entryAt(middle, entry);

		std::string entryName;
		if (!stringAt(entry.name, entryName)) {
			error = "index entry " + std::to_string(middle) + ": string is out of bounds";
			return FindResult::Corrupt;
		}

		const int order = compareIndexKeys(entryName, entry.arch, name, arch);
		if (order == 0) {
			return decode(middle, entry, out, error) ? FindResult::Found : FindResult::Corrupt;
		}

		if (order < 0) {
			low = middle + 1;
		}
		else {
			high = middle;
		}
	}

	return FindResult::NotFound;
}
