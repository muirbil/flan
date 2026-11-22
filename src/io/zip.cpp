#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

// Те же настройки miniz, что в miniz_inflate.c: нужен только tinfl и mz_crc32.
#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#define MINIZ_NO_ZLIB_APIS
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_NO_DEFLATE_APIS

#include <windows.h>
#include "flan/zip.hpp"
#include "flan/format.hpp"
#include "flan/fs.hpp"
#include "flan/strings.hpp"
#include "flan/validate.hpp"
#include "miniz.h"
#include <algorithm>

namespace {

	constexpr uint32_t SIG_LOCAL = 0x04034b50;
	constexpr uint32_t SIG_CENTRAL = 0x02014b50;
	constexpr uint32_t SIG_END = 0x06054b50;
	constexpr uint32_t SIG_ZIP64_LOCATOR = 0x07064b50;

	constexpr size_t END_SIZE = 22;
	constexpr size_t CENTRAL_SIZE = 46;
	constexpr size_t LOCAL_SIZE = 30;
	constexpr uint64_t MAX_CENTRAL_DIRECTORY_SIZE = 64ull * 1024 * 1024;
	constexpr size_t MAX_ENTRY_NAME_LENGTH = 4096;		// символов UTF-16 на всё имя
	constexpr size_t MAX_SEGMENT_LENGTH = 255;			// предел NTFS на одно имя

	constexpr uint16_t FLAG_ENCRYPTED = 0x0001;
	constexpr uint16_t FLAG_DATA_DESCRIPTOR = 0x0008;
	constexpr uint16_t FLAG_STRONG_ENCRYPTION = 0x0040;
	constexpr uint16_t FLAG_UTF8 = 0x0800;
	constexpr uint16_t FLAG_MASKED_HEADERS = 0x2000;

	constexpr size_t CHUNK = 64 * 1024;

	uint16_t rd16(const uint8_t* p) {
		return (uint16_t)(p[0] | (p[1] << 8));
	}

	uint32_t rd32(const uint8_t* p) {
		return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	}

	// Имя для сообщения об ошибке. Сырое имя из архива может нести управляющие символы
	// (ESC — последовательность для терминала), поэтому они заменяются на '?'.
	std::string shown(const std::wstring& name) {
		std::wstring safe = name;
		for (wchar_t& c : safe) {
			if (c < 0x20 || c == 0x7F) {
				c = L'?';
			}
		}
		std::string utf8;
		return toUtf8(safe, utf8) ? utf8 : std::string("?");
	}

	// Имя записи: бит 11 — UTF-8 (строго), иначе CP437, как читает Проводник.
	bool decodeName(const uint8_t* bytes, size_t size, bool utf8, std::wstring& out) {
		out.clear();
		if (size == 0) {
			return false;
		}
		const UINT codePage = utf8 ? CP_UTF8 : 437;
		const DWORD flags = utf8 ? MB_ERR_INVALID_CHARS : 0;
		const int length = MultiByteToWideChar(codePage, flags, (const char*)bytes, (int)size, NULL, 0);
		if (length <= 0) {
			return false;
		}
		out.resize(length);
		return MultiByteToWideChar(codePage, flags, (const char*)bytes, (int)size, &out[0], length) == length;
	}

	// Запреты §7.3 на одно имя. Здесь не белый список (в архивах бывают пробелы, скобки, '+'),
	// а запреты: '..', абсолютные пути, ':', управляющие и недопустимые в Windows символы,
	// точка и пробел в конце сегмента, имена устройств. Сегменты "" и "." пропускаются.
	// На выходе — сегменты через '\'; directory — имя кончалось разделителем.
	bool normalizeEntryName(const std::wstring& raw, std::wstring& out, bool& directory, std::string& why) {
		out.clear();
		directory = false;

		if (raw.size() > MAX_ENTRY_NAME_LENGTH) {
			why = "the name is too long";
			return false;
		}
		if (raw[0] == L'/' || raw[0] == L'\\') {
			why = "absolute path";
			return false;
		}
		directory = raw.back() == L'/' || raw.back() == L'\\';

		size_t start = 0;
		while (start <= raw.size()) {
			size_t end = raw.find_first_of(L"/\\", start);
			if (end == std::wstring::npos) {
				end = raw.size();
			}
			const std::wstring segment = raw.substr(start, end - start);
			start = end + 1;

			if (segment.empty() || segment == L".") {
				continue;
			}
			if (segment == L"..") {
				why = "'..' in the path";
				return false;
			}
			if (segment.size() > MAX_SEGMENT_LENGTH) {
				why = "a path segment is longer than 255 characters";
				return false;
			}

			std::string ascii;
			bool allAscii = true;
			for (const wchar_t c : segment) {
				if (c < 0x20 || c == 0x7F) {
					why = "a control character in the name";
					return false;
				}
				if (c == L':') {
					why = "':' in the name (drive letter or alternate data stream)";
					return false;
				}
				if (c == L'<' || c == L'>' || c == L'"' || c == L'|' || c == L'?' || c == L'*') {
					why = "a character that Windows does not allow in names";
					return false;
				}
				allAscii = allAscii && c < 0x80;
				ascii += (char)c;
			}

			if (segment.back() == L'.' || segment.back() == L' ') {
				why = "a name ending with a dot or a space";
				return false;
			}
			if (allAscii && isReservedDeviceName(ascii)) {
				why = "a reserved device name";
				return false;
			}

			if (!out.empty()) {
				out += L'\\';
			}
			out += segment;
		}

		if (out.empty()) {
			why = "an empty name";
			return false;
		}
		return true;
	}

	bool lessIgnoreCase(const std::wstring& a, const std::wstring& b) {
		return CompareStringOrdinal(a.data(), (int)a.size(), b.data(), (int)b.size(), TRUE) == CSTR_LESS_THAN;
	}

	bool writeAll(HANDLE file, const uint8_t* data, size_t size) {
		while (size > 0) {
			DWORD written = 0;
			const DWORD chunk = (DWORD)(size > (1u << 20) ? (1u << 20) : size);
			if (!WriteFile(file, data, chunk, &written, NULL) || written == 0) {
				return false;
			}
			data += written;
			size -= written;
		}
		return true;
	}
}

bool equalIgnoreCaseOrdinal(const std::wstring& a, const std::wstring& b) {
	return CompareStringOrdinal(a.data(), (int)a.size(), b.data(), (int)b.size(), TRUE) == CSTR_EQUAL;
}

ZipArchive::~ZipArchive() {
	if (file_ != nullptr) {
		CloseHandle((HANDLE)file_);
	}
}

bool ZipArchive::readAt(uint64_t offset, void* buffer, size_t size) {
	if (offset > fileSize_ || size > fileSize_ - offset) {
		return false;
	}

	LARGE_INTEGER position = {};
	position.QuadPart = (LONGLONG)offset;
	if (!SetFilePointerEx((HANDLE)file_, position, NULL, FILE_BEGIN)) {
		return false;
	}

	uint8_t* out = static_cast<uint8_t*>(buffer);
	while (size > 0) {
		DWORD got = 0;
		const DWORD chunk = (DWORD)(size > (1u << 20) ? (1u << 20) : size);
		if (!ReadFile((HANDLE)file_, out, chunk, &got, NULL) || got == 0) {
			return false;
		}
		out += got;
		size -= got;
	}
	return true;
}

bool ZipArchive::open(const std::string& path, std::string& error) {
	if (file_ != nullptr) {
		CloseHandle((HANDLE)file_);
		file_ = nullptr;
	}
	entries_.clear();
	unpackedSize_ = 0;

	const HANDLE file = CreateFileW(extendedPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		error = "cannot open the archive (code " + std::to_string(GetLastError()) + ")";
		return false;
	}
	file_ = file;

	LARGE_INTEGER size = {};
	if (!GetFileSizeEx(file, &size)) {
		error = "cannot read the archive size";
		return false;
	}
	fileSize_ = (uint64_t)size.QuadPart;
	if (fileSize_ < END_SIZE) {
		error = "not a zip archive";
		return false;
	}
	if (fileSize_ > MAX_ARCHIVE_SIZE) {
		error = "the archive is larger than 512 MB";
		return false;
	}

	// Конец центрального каталога: последние 22 байта плюс комментарий до 64 КБ.
	const size_t tailSize = (size_t)std::min<uint64_t>(fileSize_, END_SIZE + 0xFFFF);
	std::vector<uint8_t> tail(tailSize);
	if (!readAt(fileSize_ - tailSize, tail.data(), tailSize)) {
		error = "cannot read the archive";
		return false;
	}

	size_t end = std::string::npos;
	for (size_t i = tailSize - END_SIZE + 1; i-- > 0;) {
		if (rd32(&tail[i]) == SIG_END && i + END_SIZE + rd16(&tail[i + 20]) == tailSize) {
			end = i;
			break;
		}
	}
	if (end == std::string::npos) {
		error = "not a zip archive (no end of central directory)";
		return false;
	}

	const uint8_t* eocd = &tail[end];
	const uint64_t endOffset = fileSize_ - tailSize + end;
	const uint16_t disk = rd16(eocd + 4);
	const uint16_t centralDisk = rd16(eocd + 6);
	const uint16_t entriesOnDisk = rd16(eocd + 8);
	const uint16_t count = rd16(eocd + 10);
	const uint32_t centralSize = rd32(eocd + 12);
	const uint32_t centralOffset = rd32(eocd + 16);

	uint8_t locator[4] = {};
	const bool zip64Locator = endOffset >= 20 && readAt(endOffset - 20, locator, 4) && rd32(locator) == SIG_ZIP64_LOCATOR;
	if (zip64Locator || count == 0xFFFF || centralSize == 0xFFFFFFFF || centralOffset == 0xFFFFFFFF) {
		error = "ZIP64 archives are not supported";
		return false;
	}
	if (disk != 0 || centralDisk != 0 || entriesOnDisk != count) {
		error = "multi-volume archives are not supported";
		return false;
	}
	// Ровно встык: данные перед архивом (самораспаковывающийся .exe) или дыры — отказ.
	if ((uint64_t)centralOffset + centralSize != endOffset) {
		error = "the central directory is not where the archive says (corrupted or self-extracting archive)";
		return false;
	}
	if (centralSize > MAX_CENTRAL_DIRECTORY_SIZE) {
		error = "the central directory is too large";
		return false;
	}

	std::vector<uint8_t> central(centralSize);
	if (centralSize > 0 && !readAt(centralOffset, central.data(), centralSize)) {
		error = "cannot read the central directory";
		return false;
	}

	std::vector<std::vector<uint8_t>> rawNames;
	size_t pos = 0;
	for (uint16_t index = 0; index < count; index++) {
		if (pos + CENTRAL_SIZE > central.size() || rd32(&central[pos]) != SIG_CENTRAL) {
			error = "the central directory is corrupted";
			return false;
		}
		const uint8_t* h = &central[pos];
		const uint16_t madeBy = rd16(h + 4);
		const uint16_t flags = rd16(h + 8);
		const uint16_t method = rd16(h + 10);
		const uint32_t crc = rd32(h + 16);
		const uint32_t compressed = rd32(h + 20);
		const uint32_t uncompressed = rd32(h + 24);
		const uint16_t nameLength = rd16(h + 28);
		const uint16_t extraLength = rd16(h + 30);
		const uint16_t commentLength = rd16(h + 32);
		const uint16_t diskStart = rd16(h + 34);
		const uint32_t external = rd32(h + 38);
		const uint32_t localOffset = rd32(h + 42);

		if (pos + CENTRAL_SIZE + nameLength + extraLength + commentLength > central.size()) {
			error = "the central directory is truncated";
			return false;
		}

		std::wstring rawName;
		if (!decodeName(h + CENTRAL_SIZE, nameLength, (flags & FLAG_UTF8) != 0, rawName)) {
			error = "entry " + std::to_string(index) + ": the name is empty or not valid UTF-8";
			return false;
		}
		const std::string where = "'" + shown(rawName) + "': ";

		if (flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION | FLAG_MASKED_HEADERS)) {
			error = where + "encrypted entries are not supported";
			return false;
		}
		if (method != 0 && method != 8) {
			error = where + "compression method " + std::to_string(method) + " is not supported (only stored and deflate)";
			return false;
		}
		if (compressed == 0xFFFFFFFF || uncompressed == 0xFFFFFFFF || localOffset == 0xFFFFFFFF || diskStart == 0xFFFF) {
			error = where + "ZIP64 entries are not supported";
			return false;
		}
		if (diskStart != 0) {
			error = where + "multi-volume archives are not supported";
			return false;
		}

		// Поля extra: 0x0001 — ZIP64.
		const uint8_t* extra = h + CENTRAL_SIZE + nameLength;
		for (size_t e = 0; e + 4 <= extraLength;) {
			const uint16_t id = rd16(extra + e);
			const uint16_t length = rd16(extra + e + 2);
			if (id == 0x0001) {
				error = where + "ZIP64 entries are not supported";
				return false;
			}
			e += 4 + (size_t)length;
		}

		ZipEntry entry;
		bool trailingSeparator = false;
		std::string why;
		if (!normalizeEntryName(rawName, entry.wideName, trailingSeparator, why)) {
			error = where + why;
			return false;
		}
		if (!toUtf8(entry.wideName, entry.name)) {
			error = where + "the name is not valid Unicode";
			return false;
		}

		// Тип записи. У архивов из Unix (3) и macOS (19) в старших 16 битах — режим файла.
		const uint16_t host = madeBy >> 8;
		const uint32_t format = (external >> 16) & 0xF000;
		const bool unixMode = host == 3 || host == 19;
		if (unixMode && format == 0xA000) {
			error = where + "symbolic links are not allowed";
			return false;
		}
		if (unixMode && format != 0 && format != 0x8000 && format != 0x4000) {
			error = where + "device files, pipes and sockets are not allowed";
			return false;
		}
		if (external & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) {
			error = where + "links and device entries are not allowed";
			return false;
		}

		entry.directory = trailingSeparator || (external & FILE_ATTRIBUTE_DIRECTORY) || (unixMode && format == 0x4000);
		entry.method = method;
		entry.crc32 = crc;
		entry.compressedSize = compressed;
		entry.size = uncompressed;
		entry.localHeaderOffset = localOffset;

		if (entry.directory && entry.size != 0) {
			error = where + "a directory entry with data";
			return false;
		}
		if (!entry.directory && method == 0 && compressed != uncompressed) {
			error = where + "a stored entry whose sizes differ";
			return false;
		}
		// Защита от zip-бомб: коэффициент отдельной записи и сумма по архиву.
		if (entry.size > MAX_COMPRESSION_RATIO * std::max<uint64_t>(entry.compressedSize, 1)) {
			error = where + "the compression ratio is above " + std::to_string(MAX_COMPRESSION_RATIO) + " (zip bomb?)";
			return false;
		}
		unpackedSize_ += entry.size;
		if (unpackedSize_ > MAX_UNPACKED_SIZE) {
			error = "the archive unpacks to more than 2 GB";
			return false;
		}

		entries_.push_back(entry);
		rawNames.emplace_back(h + CENTRAL_SIZE, h + CENTRAL_SIZE + nameLength);
		pos += CENTRAL_SIZE + nameLength + extraLength + commentLength;
	}

	if (pos != central.size()) {
		error = "the central directory has data after its last entry";
		return false;
	}

	// Локальные заголовки сверяются с центральным каталогом.
	for (size_t i = 0; i < entries_.size(); i++) {
		ZipEntry& entry = entries_[i];
		const std::string where = "'" + entry.name + "': ";

		uint8_t h[LOCAL_SIZE];
		if (entry.localHeaderOffset + LOCAL_SIZE > centralOffset || !readAt(entry.localHeaderOffset, h, LOCAL_SIZE) ||
			rd32(h) != SIG_LOCAL) {
			error = where + "the local header is missing or corrupted";
			return false;
		}

		const uint16_t flags = rd16(h + 6);
		const uint16_t nameLength = rd16(h + 26);
		const uint16_t extraLength = rd16(h + 28);
		if (rd16(h + 8) != entry.method || (flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION | FLAG_MASKED_HEADERS))) {
			error = where + "the local header does not match the central directory";
			return false;
		}
		// С дескриптором данных (бит 3) CRC и размеры в локальном заголовке могут быть нулями.
		if (!(flags & FLAG_DATA_DESCRIPTOR) &&
			(rd32(h + 14) != entry.crc32 || rd32(h + 18) != entry.compressedSize || rd32(h + 22) != entry.size)) {
			error = where + "the local header does not match the central directory";
			return false;
		}

		std::vector<uint8_t> local(nameLength + (size_t)extraLength);
		if (entry.localHeaderOffset + LOCAL_SIZE + local.size() > centralOffset ||
			(!local.empty() && !readAt(entry.localHeaderOffset + LOCAL_SIZE, local.data(), local.size())) ||
			nameLength != rawNames[i].size() || !std::equal(rawNames[i].begin(), rawNames[i].end(), local.begin())) {
			error = where + "the local header name does not match the central directory";
			return false;
		}
		for (size_t e = nameLength; e + 4 <= local.size();) {
			if (rd16(&local[e]) == 0x0001) {
				error = where + "ZIP64 entries are not supported";
				return false;
			}
			e += 4 + (size_t)rd16(&local[e + 2]);
		}

		entry.dataOffset = entry.localHeaderOffset + LOCAL_SIZE + local.size();
		if (entry.dataOffset + entry.compressedSize > centralOffset) {
			error = where + "the entry data runs past the central directory";
			return false;
		}
	}

	// Перекрытия: одни и те же байты архива под двумя именами — приём zip-бомб.
	std::vector<const ZipEntry*> byOffset;
	for (const ZipEntry& entry : entries_) {
		byOffset.push_back(&entry);
	}
	std::sort(byOffset.begin(), byOffset.end(), [](const ZipEntry* a, const ZipEntry* b) {
		return a->localHeaderOffset < b->localHeaderOffset;
	});
	for (size_t i = 1; i < byOffset.size(); i++) {
		if (byOffset[i]->localHeaderOffset < byOffset[i - 1]->dataOffset + byOffset[i - 1]->compressedSize) {
			error = "entries '" + byOffset[i - 1]->name + "' and '" + byOffset[i]->name + "' overlap";
			return false;
		}
	}

	// Совпадения без учёта регистра, как их видит NTFS: два файла с одним именем, файл и каталог
	// с одним именем (явный каталог или подразумеваемый путём другой записи).
	struct Key {
		std::wstring path;
		bool directory;
	};
	std::vector<Key> keys;
	for (const ZipEntry& entry : entries_) {
		keys.push_back({ entry.wideName, entry.directory });
		for (size_t slash = entry.wideName.find(L'\\'); slash != std::wstring::npos; slash = entry.wideName.find(L'\\', slash + 1)) {
			keys.push_back({ entry.wideName.substr(0, slash), true });
		}
	}
	std::sort(keys.begin(), keys.end(), [](const Key& a, const Key& b) { return lessIgnoreCase(a.path, b.path); });
	for (size_t i = 1; i < keys.size(); i++) {
		if (equalIgnoreCaseOrdinal(keys[i - 1].path, keys[i].path) && !(keys[i - 1].directory && keys[i].directory)) {
			error = "names '" + shown(keys[i - 1].path) + "' and '" + shown(keys[i].path) +
				"' are the same file in Windows (they differ only in case or a file clashes with a folder)";
			return false;
		}
	}

	return true;
}

bool ZipArchive::readEntry(const ZipEntry& entry, void* outFile, std::string& error) {
	const std::string where = "'" + entry.name + "': ";
	if (entry.directory) {
		return true;
	}

	const HANDLE out = (HANDLE)outFile;
	std::vector<uint8_t> input(CHUNK);
	uint64_t offset = entry.dataOffset;
	uint64_t left = entry.compressedSize;
	uint64_t produced = 0;
	mz_ulong crc = MZ_CRC32_INIT;

	auto emit = [&](const uint8_t* data, size_t size) {
		produced += size;
		if (produced > entry.size) {
			return false;
		}
		crc = mz_crc32(crc, data, size);
		return out == nullptr || writeAll(out, data, size);
	};

	if (entry.method == 0) {
		while (left > 0) {
			const size_t chunk = (size_t)std::min<uint64_t>(left, CHUNK);
			if (!readAt(offset, input.data(), chunk)) {
				error = where + "the archive is truncated";
				return false;
			}
			if (!emit(input.data(), chunk)) {
				error = where + "cannot write the file";
				return false;
			}
			offset += chunk;
			left -= chunk;
		}
	}
	else {
		// Поток deflate: вход кусками по 64 КБ, выход — в кольцевой словарь 32 КБ.
		tinfl_decompressor decompressor;
		tinfl_init(&decompressor);
		std::vector<uint8_t> dictionary(TINFL_LZ_DICT_SIZE);
		size_t dictionaryOffset = 0;
		size_t inputPos = 0;
		size_t inputSize = 0;

		for (;;) {
			if (inputPos == inputSize && left > 0) {
				inputSize = (size_t)std::min<uint64_t>(left, CHUNK);
				if (!readAt(offset, input.data(), inputSize)) {
					error = where + "the archive is truncated";
					return false;
				}
				offset += inputSize;
				left -= inputSize;
				inputPos = 0;
			}

			size_t inBytes = inputSize - inputPos;
			size_t outBytes = TINFL_LZ_DICT_SIZE - dictionaryOffset;
			const tinfl_status status = tinfl_decompress(&decompressor, input.data() + inputPos, &inBytes,
				dictionary.data(), dictionary.data() + dictionaryOffset, &outBytes, left > 0 ? TINFL_FLAG_HAS_MORE_INPUT : 0);
			inputPos += inBytes;

			if (outBytes > 0 && !emit(dictionary.data() + dictionaryOffset, outBytes)) {
				error = produced > entry.size ? where + "the entry unpacks to more than its declared size"
					: where + "cannot write the file";
				return false;
			}
			dictionaryOffset = (dictionaryOffset + outBytes) & (TINFL_LZ_DICT_SIZE - 1);

			if (status == TINFL_STATUS_DONE) {
				break;
			}
			if (status < 0 || (status == TINFL_STATUS_NEEDS_MORE_INPUT && left == 0 && inputPos == inputSize)) {
				error = where + "the compressed data is corrupted";
				return false;
			}
		}

		if (inputPos != inputSize || left != 0) {
			error = where + "data after the end of the compressed stream";
			return false;
		}
	}

	if (produced != entry.size) {
		error = where + "the entry unpacks to a different size than declared";
		return false;
	}
	if ((uint32_t)crc != entry.crc32) {
		error = where + "CRC-32 mismatch (the archive is corrupted)";
		return false;
	}
	return true;
}

const ZipEntry* findZipFile(const std::vector<ZipEntry>& entries, const std::string& path) {
	const std::wstring wide = s2ws(path);
	for (const ZipEntry& entry : entries) {
		if (!entry.directory && equalIgnoreCaseOrdinal(entry.wideName, wide)) {
			return &entry;
		}
	}
	return nullptr;
}

namespace {

	// rel внутри dir: "dir\..." без учёта регистра; rest — остаток после "dir\".
	bool insideDirectory(const std::wstring& rel, const std::wstring& dir, std::wstring& rest) {
		if (rel.size() <= dir.size() || rel[dir.size()] != L'\\' || !equalIgnoreCaseOrdinal(rel.substr(0, dir.size()), dir)) {
			return false;
		}
		rest = rel.substr(dir.size() + 1);
		return true;
	}
}

bool zipHasDirectory(const std::vector<ZipEntry>& entries, const std::string& dir) {
	const std::wstring wide = s2ws(dir);
	std::wstring rest;
	for (const ZipEntry& entry : entries) {
		if ((entry.directory && equalIgnoreCaseOrdinal(entry.wideName, wide)) || insideDirectory(entry.wideName, wide, rest)) {
			return true;
		}
	}
	return false;
}

bool extractZip(ZipArchive& archive, const std::string& extractDir, const std::string& destination, std::string& error) {
	const std::wstring prefix = s2ws(extractDir);
	if (!prefix.empty() && !zipHasDirectory(archive.entries(), extractDir)) {
		error = "the archive has no folder '" + extractDir + "'";
		return false;
	}

	for (const ZipEntry& entry : archive.entries()) {
		std::wstring rel = entry.wideName;
		if (!prefix.empty()) {
			std::wstring rest;
			if (!insideDirectory(entry.wideName, prefix, rest)) {
				if (!entry.directory && equalIgnoreCaseOrdinal(entry.wideName, prefix)) {
					error = "extract_dir '" + extractDir + "' is a file in the archive";
					return false;
				}
				continue;									// вне extract_dir — пропускается
			}
			rel = rest;
		}

		std::string relative;
		if (!toUtf8(rel, relative)) {
			error = "'" + entry.name + "': the name is not valid Unicode";
			return false;
		}
		const std::string target = destination + "\\" + relative;

		if (entry.directory) {
			if (!createDirectory(target)) {
				error = "cannot create folder " + target;
				return false;
			}
			continue;
		}

		const size_t slash = target.find_last_of('\\');
		if (!createDirectory(target.substr(0, slash))) {
			error = "cannot create folder " + target.substr(0, slash);
			return false;
		}

		// CREATE_NEW: файл с тем же именем уже есть — значит, проверка совпадений что-то упустила.
		const HANDLE file = CreateFileW(extendedPath(target).c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (file == INVALID_HANDLE_VALUE) {
			error = "cannot create " + target + " (code " + std::to_string(GetLastError()) + ")";
			return false;
		}

		const bool ok = archive.readEntry(entry, file, error);
		const bool closed = CloseHandle(file) != 0;
		if (!ok || !closed) {
			if (ok) {
				error = "cannot write " + target;
			}
			deleteFile(target);
			return false;
		}
	}

	return true;
}
