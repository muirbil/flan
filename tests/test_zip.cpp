#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "test.hpp"
#include "build.hpp"
#include "flan/fs.hpp"
#include "flan/strings.hpp"
#include "flan/zip.hpp"
#include <cstring>
#include <string>
#include <vector>

// zip.cpp (DESIGN.md §7.3, §11): архивы собираются здесь же, побайтово, — и правильные,
// и каждый вид вредоносного из §11.

namespace {

	uint32_t crc32Of(const std::string& data) {
		uint32_t crc = 0xFFFFFFFF;
		for (const unsigned char c : data) {
			crc ^= c;
			for (int k = 0; k < 8; k++) {
				crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1)));
			}
		}
		return ~crc;
	}

	struct TestEntry {
		std::string name;							// байты имени как есть
		std::string data;							// несжатые данные
		uint16_t method = 8;
		uint16_t flags = 0;
		uint16_t madeBy = 20;						// хост 0 (MS-DOS), версия 2.0
		uint32_t external = 0;
		bool descriptor = false;					// бит 3: нули в локальном заголовке, дескриптор после данных
		long long crc = -1;							// подмены для порчи
		long long size = -1;
		std::string localName;						// иное имя в локальном заголовке
		bool zip64Extra = false;
	};

	struct BuildOptions {
		std::string prefix;							// данные перед архивом (самораспаковывающийся)
		bool overlap = false;						// вторая запись центрального каталога — внутри данных первой
		uint16_t disk = 0;
		bool truncate = false;						// обрезать последние байты данных
		bool zip64End = false;
	};

	void put16(std::string& s, uint32_t v) {
		s += (char)(v & 0xFF);
		s += (char)((v >> 8) & 0xFF);
	}

	void put32(std::string& s, uint32_t v) {
		put16(s, v & 0xFFFF);
		put16(s, v >> 16);
	}

	std::string buildZip(const std::vector<TestEntry>& entries, const BuildOptions& options = BuildOptions()) {
		std::string out = options.prefix;
		std::string central;
		std::vector<uint32_t> offsets;

		for (const TestEntry& e : entries) {
			std::string payload = e.data;
			if (e.method == 8) {
				std::vector<uint8_t> raw(e.data.begin(), e.data.end());
				std::vector<uint8_t> packed;
				deflateRaw(raw, packed);
				payload.assign(packed.begin(), packed.end());
			}
			const uint32_t crc = e.crc >= 0 ? (uint32_t)e.crc : crc32Of(e.data);
			const uint32_t size = e.size >= 0 ? (uint32_t)e.size : (uint32_t)e.data.size();
			const uint32_t compressed = (uint32_t)payload.size();
			const uint16_t flags = (uint16_t)(e.flags | (e.descriptor ? 0x0008 : 0));
			const std::string localName = e.localName.empty() ? e.name : e.localName;

			std::string extra;
			if (e.zip64Extra) {
				put16(extra, 0x0001);
				put16(extra, 0);
			}

			const uint32_t offset = (uint32_t)(out.size() - options.prefix.size());
			offsets.push_back(offset);
			put32(out, 0x04034b50);
			put16(out, 20);
			put16(out, flags);
			put16(out, e.method);
			put32(out, 0);								// время и дата
			put32(out, e.descriptor ? 0 : crc);
			put32(out, e.descriptor ? 0 : compressed);
			put32(out, e.descriptor ? 0 : size);
			put16(out, (uint32_t)localName.size());
			put16(out, (uint32_t)extra.size());
			out += localName;
			out += extra;
			out += payload;
			if (e.descriptor) {
				put32(out, 0x08074b50);
				put32(out, crc);
				put32(out, compressed);
				put32(out, size);
			}

			const uint32_t centralOffset = options.overlap && offsets.size() == 2
				? offsets[0] + 30 + (uint32_t)entries[0].name.size() : offset;
			put32(central, 0x02014b50);
			put16(central, e.madeBy);
			put16(central, 20);
			put16(central, flags);
			put16(central, e.method);
			put32(central, 0);
			put32(central, crc);
			put32(central, compressed);
			put32(central, size);
			put16(central, (uint32_t)e.name.size());
			put16(central, (uint32_t)extra.size());
			put16(central, 0);
			put16(central, 0);
			put16(central, 0);
			put32(central, e.external);
			put32(central, centralOffset);
			central += e.name;
			central += extra;
		}

		if (options.truncate && !entries.empty()) {
			out.resize(out.size() - 3);
		}

		// Смещения считаются от начала архива, а не файла: префикс сдвигает всё — это и ловится.
		const uint32_t centralStart = (uint32_t)(out.size() - options.prefix.size());
		out += central;
		if (options.zip64End) {
			put32(out, 0x07064b50);
			put32(out, 0);
			put32(out, 0);
			put32(out, 0);
			put32(out, 1);
		}
		put32(out, 0x06054b50);
		put16(out, options.disk);
		put16(out, 0);
		put16(out, (uint32_t)entries.size());
		put16(out, (uint32_t)entries.size());
		put32(out, (uint32_t)central.size());
		put32(out, centralStart);
		put16(out, 0);
		return out;
	}

	TestEntry file(const std::string& name, const std::string& data, uint16_t method = 8) {
		TestEntry e;
		e.name = name;
		e.data = data;
		e.method = method;
		return e;
	}

	TestEntry dir(const std::string& name) {
		TestEntry e;
		e.name = name;
		e.method = 0;
		return e;
	}

	std::string testDir;
	int counter = 0;

	std::string writeZip(const std::string& bytes) {
		const std::string path = testDir + "\\a" + std::to_string(counter++) + ".zip";
		saveFileAtomically(path, bytes);
		return path;
	}

	// open + холостая распаковка всех записей, как в генераторе. Пусто — архив принят.
	std::string verify(const std::string& bytes) {
		ZipArchive archive;
		std::string error;
		if (!archive.open(writeZip(bytes), error)) {
			return error.empty() ? "rejected" : error;
		}
		for (const ZipEntry& entry : archive.entries()) {
			if (!archive.readEntry(entry, nullptr, error)) {
				return error.empty() ? "rejected" : error;
			}
		}
		return std::string();
	}

	void expectOk(const std::string& label, const std::string& bytes) {
		const std::string error = verify(bytes);
		check(error.empty(), "accepted: " + label, error);
	}

	// reason — кусок ожидаемого сообщения: архив должен быть отвергнут именно этим правилом.
	void expectRejected(const std::string& label, const std::string& bytes, const char* reason = nullptr) {
		const std::string error = verify(bytes);
		const bool right = !error.empty() && (reason == nullptr || error.find(reason) != std::string::npos);
		check(right, "rejected: " + label, error);
	}

	std::string readText(const std::string& path) {
		std::vector<uint8_t> bytes;
		bool tooLarge = false;
		readWholeFile(path, 1 << 20, bytes, tooLarge);
		return std::string(bytes.begin(), bytes.end());
	}

	void testValid() {
		const std::string big(200000, 'x');
		std::string mixed;
		for (int i = 0; i < 50000; i++) {
			mixed += std::to_string(i * 7919 % 10007) + ",";
		}

		std::vector<TestEntry> entries = {
			dir("app-1.0/"),
			file("app-1.0/bin/tool.exe", mixed),
			file("app-1.0/README.txt", "stored", 0),
			file("app-1.0/empty.txt", "", 0),
			file("app-1.0/big.dat", big.substr(0, 150000)),
			file("outside.txt", "skipped"),
		};
		TestEntry withDescriptor = file("app-1.0/desc.txt", "with a data descriptor");
		withDescriptor.descriptor = true;
		entries.push_back(withDescriptor);
		TestEntry cyrillic = file("app-1.0/\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82.txt", "utf8");	// "Привет.txt"
		cyrillic.flags = 0x0800;
		entries.push_back(cyrillic);
		entries.push_back(file("app-1.0/\x80" "cp437.txt", "cp437"));								// 0x80 в CP437 — 'Ç'
		TestEntry unixFile = file("app-1.0/unix.sh", "#!/bin/sh");
		unixFile.madeBy = (3 << 8) | 30;
		unixFile.external = 0100755u << 16;
		entries.push_back(unixFile);
		entries.push_back(file("./app-1.0//dots/./x.txt", "dots"));

		const std::string bytes = buildZip(entries);
		expectOk("stored, deflate, descriptor, UTF-8, CP437, Unix mode, '.' and empty segments", bytes);

		ZipArchive archive;
		std::string error;
		check(archive.open(writeZip(bytes), error), "open", error);
		check(findZipFile(archive.entries(), "APP-1.0\\BIN\\TOOL.EXE") != nullptr, "findZipFile ignores case");
		check(findZipFile(archive.entries(), "app-1.0\\bin") == nullptr, "findZipFile: a folder is not a file");
		check(zipHasDirectory(archive.entries(), "app-1.0\\bin") && zipHasDirectory(archive.entries(), "App-1.0") &&
			!zipHasDirectory(archive.entries(), "app"), "zipHasDirectory: by prefix, ignoring case");
		check(findZipFile(archive.entries(), "app-1.0\\\xC3\x87" "cp437.txt") != nullptr, "CP437 name decoded");
		check(archive.unpackedSize() > 300000, "unpackedSize");

		const std::string dest = testDir + "\\распаковка";
		createDirectory(dest);
		check(extractZip(archive, "APP-1.0", dest, error), "extractZip with extract_dir", error);
		check(readText(dest + "\\bin\\tool.exe") == mixed, "extracted deflate file");
		check(readText(dest + "\\README.txt") == "stored" && readText(dest + "\\desc.txt") == "with a data descriptor",
			"extracted stored and descriptor files");
		check(isRegularFile(dest + "\\empty.txt") && readText(dest + "\\Привет.txt") == "utf8" &&
			readText(dest + "\\dots\\x.txt") == "dots", "extracted empty, Cyrillic and dotted names");
		check(!pathExists(dest + "\\outside.txt") && !pathExists(dest + "\\app-1.0"), "entries outside extract_dir skipped, prefix cut");

		const std::string all = testDir + "\\целиком";
		createDirectory(all);
		check(extractZip(archive, "", all, error) && readText(all + "\\outside.txt") == "skipped" &&
			isDirectory(all + "\\app-1.0\\bin"), "extractZip without extract_dir", error);

		const std::string missing = testDir + "\\нет";
		createDirectory(missing);
		check(!extractZip(archive, "other", missing, error), "extractZip: missing extract_dir", error);
		check(!extractZip(archive, "outside.txt", missing, error), "extractZip: extract_dir is a file", error);
	}

	void testNames() {
		const char* bad[] = {
			"../evil.txt", "a/../../evil.txt", "a/..", "/abs.txt", "\\abs.txt", "C:/x.txt", "c:x.txt",
			"file.txt:stream", "con", "a/NUL.txt", "a/com1", "lpt9.log", "trail.", "a/trail /x.txt",
			"ctrl\x01.txt", "a<b", "a>b", "a\"b", "a|b", "a?b", "a*b", "./", "", "a\\..\\b",
		};
		for (const char* name : bad) {
			expectRejected(std::string("name '") + name + "'", buildZip({ file(name, "x") }));
		}

		// Сообщение об отказе не несёт управляющих символов из имени (ESC — последовательность терминала).
		const std::string escape = verify(buildZip({ file("evil\x1b[31m.txt", "x") }));
		check(!escape.empty() && escape.find('\x1b') == std::string::npos, "no control characters in the error message", escape);

		TestEntry invalidUtf8 = file("bad\xC3(.txt", "x");
		invalidUtf8.flags = 0x0800;
		expectRejected("invalid UTF-8 with bit 11", buildZip({ invalidUtf8 }));

		expectRejected("a segment longer than 255", buildZip({ file(std::string(256, 'a'), "x") }));
		expectOk("a segment of 255", buildZip({ file(std::string(255, 'a'), "x") }));
		expectOk("spaces, brackets, plus", buildZip({ file("My App (x64)/c++ notes + more.txt", "x") }));
	}

	void testTypes() {
		TestEntry link = file("link", "target");
		link.madeBy = (3 << 8) | 30;
		link.external = 0120777u << 16;
		expectRejected("Unix symlink", buildZip({ link }), "symbolic link");

		TestEntry mac = link;
		mac.madeBy = (19 << 8) | 30;
		expectRejected("macOS symlink", buildZip({ mac }), "symbolic link");

		TestEntry device = file("dev", "x");
		device.madeBy = (3 << 8) | 30;
		device.external = 0020644u << 16;
		expectRejected("Unix character device", buildZip({ device }));

		TestEntry fifo = device;
		fifo.external = 0010644u << 16;
		expectRejected("Unix FIFO", buildZip({ fifo }));

		TestEntry reparse = file("r", "x");
		reparse.external = FILE_ATTRIBUTE_REPARSE_POINT;
		expectRejected("Windows reparse point attribute", buildZip({ reparse }));

		TestEntry dirWithData = file("d/", "data", 0);
		expectRejected("a directory entry with data", buildZip({ dirWithData }));
	}

	void testCollisions() {
		expectRejected("names differing only in case", buildZip({ file("Readme.txt", "1"), file("README.TXT", "2") }), "same file");
		expectRejected("the same name twice", buildZip({ file("a.txt", "1"), file("a.txt", "2") }));
		TestEntry upper = file("\xD0\xAF.txt", "1");			// "Я.txt"
		upper.flags = 0x0800;
		TestEntry lower = file("\xD1\x8F.txt", "2");			// "я.txt"
		lower.flags = 0x0800;
		expectRejected("Cyrillic names differing only in case", buildZip({ upper, lower }), "same file");
		expectRejected("a file and a folder with one name", buildZip({ file("a", "1"), file("A/b.txt", "2") }), "same file");
		expectRejected("a file and an explicit folder", buildZip({ file("a", "1"), dir("a/") }));
		expectOk("a folder entry and files inside it", buildZip({ dir("a/"), file("a/b.txt", "1"), dir("A/") }));
		expectRejected("same name via '.' segments", buildZip({ file("a/b.txt", "1"), file("a/./b.txt", "2") }));
	}

	void testLimits() {
		// Сумма > 2 ГБ: размеры в центральном каталоге подделаны, данные короткие.
		// Данные несжимаемые (~1.6 МБ сжатыми), так что коэффициент ~940 не срабатывает,
		// а сумма заявленных размеров — 2.8 ГБ.
		std::string noise(1600000, '\0');
		uint32_t state = 12345;
		for (char& c : noise) {
			state = state * 1103515245u + 12345u;
			c = (char)(state >> 24);
		}
		TestEntry huge1 = file("1", noise);
		TestEntry huge2 = file("2", noise);
		huge1.size = huge2.size = 0x5A000000;					// по 1.4 ГБ, вместе 2.8 ГБ
		expectRejected("more than 2 GB unpacked in total", buildZip({ huge1, huge2 }), "2 GB");

		const std::string zeros(3000000, '\0');
		expectRejected("compression ratio above 1000", buildZip({ file("zeros.bin", zeros) }), "ratio");
		expectOk("compression ratio below 1000", buildZip({ file("zeros.bin", zeros.substr(0, 500)) }));

		TestEntry liar = file("liar.txt", "only these bytes");
		liar.size = 5;
		expectRejected("unpacks to more than declared", buildZip({ liar }), "more than its declared size");
		TestEntry shortSize = file("short.txt", "abc");
		shortSize.size = 10;
		expectRejected("unpacks to less than declared", buildZip({ shortSize }), "different size");
	}

	void testCorruption() {
		TestEntry badCrc = file("crc.txt", "some data");
		badCrc.crc = 0x12345678;
		expectRejected("CRC mismatch (deflate)", buildZip({ badCrc }), "CRC-32");
		TestEntry badCrcStored = file("crc.txt", "some data", 0);
		badCrcStored.crc = 0x12345678;
		expectRejected("CRC mismatch (stored)", buildZip({ badCrcStored }), "CRC-32");

		BuildOptions truncated;
		truncated.truncate = true;
		expectRejected("truncated data", buildZip({ file("t.txt", std::string(5000, 'q') + "end") }, truncated));

		const std::string whole = buildZip({ file("t.txt", "abc") });
		expectRejected("cut in the end record", whole.substr(0, whole.size() - 5));
		expectRejected("not a zip at all", std::string("hello, this is not an archive at all"));
		expectRejected("empty file", std::string());

		// Перекрытие: первая запись (stored) несёт в своих данных целый локальный заголовок второй,
		// и центральный каталог указывает на него — те же байты под двумя именами.
		std::string inner;
		put32(inner, 0x04034b50);
		put16(inner, 20);
		put16(inner, 0);
		put16(inner, 0);
		put32(inner, 0);
		put32(inner, crc32Of("inner"));
		put32(inner, 5);
		put32(inner, 5);
		put16(inner, 5);
		put16(inner, 0);
		inner += "b.txt";
		inner += "inner";
		BuildOptions overlap;
		overlap.overlap = true;
		expectRejected("two names over the same bytes", buildZip({ file("a.txt", inner, 0), file("b.txt", "inner", 0) }, overlap), "overlap");

		BuildOptions sfx;
		sfx.prefix = "MZ fake self-extractor stub";
		expectRejected("data before the archive", buildZip({ file("a.txt", "x") }, sfx), "self-extracting");

		TestEntry mismatch = file("name.txt", "x");
		mismatch.localName = "other.txt";
		expectRejected("local name differs from central", buildZip({ mismatch }), "local header name");
	}

	void testUnsupported() {
		TestEntry encrypted = file("e.txt", "x");
		encrypted.flags = 0x0001;
		expectRejected("encrypted entry", buildZip({ encrypted }), "encrypted");

		TestEntry bzip2 = file("b.txt", "x", 0);
		bzip2.method = 12;
		expectRejected("compression method 12 (bzip2)", buildZip({ bzip2 }), "method 12");

		TestEntry zip64 = file("z.txt", "x");
		zip64.zip64Extra = true;
		expectRejected("ZIP64 extra field", buildZip({ zip64 }), "ZIP64");

		BuildOptions zip64End;
		zip64End.zip64End = true;
		expectRejected("ZIP64 end locator", buildZip({ file("z.txt", "x") }, zip64End), "ZIP64");

		BuildOptions multi;
		multi.disk = 1;
		expectRejected("multi-volume archive", buildZip({ file("m.txt", "x") }, multi), "multi-volume");
	}
}

void runZipTests() {
	beginSuite("zip");

	wchar_t temp[MAX_PATH + 1];
	const DWORD length = GetTempPathW(ARRAYSIZE(temp), temp);
	std::string base;
	if (length == 0 || length > MAX_PATH || !toUtf8(std::wstring(temp, length), base)) {
		check(false, "temp directory");
		return;
	}
	testDir = base + "flan-zip-tests-" + std::to_string(GetCurrentProcessId()) + "\\архивы";
	check(createDirectory(testDir), "test directory");

	testValid();
	testNames();
	testTypes();
	testCollisions();
	testLimits();
	testCorruption();
	testUnsupported();

	removeTree(base + "flan-zip-tests-" + std::to_string(GetCurrentProcessId()));
}
