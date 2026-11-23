#include "test.hpp"
#include "build.hpp"
#include "signing.hpp"
#include "flan/index.hpp"
#include "flan/validate.hpp"
#include <cstring>
#include <functional>
#include <string>
#include <vector>

// Разбор index.flan (формат 2). Испорченные файлы собирает свой «сырой» писатель:
// настоящий (buildIndexFile) не умеет писать неотсортированный или битый индекс,
// а именно такие клиент обязан отвергать.
//
// Все индексы подписаны ключом, созданным при запуске тестов (DESIGN.md §6.3). После каждой
// порчи подпись пересчитывается: иначе файл отвергался бы подписью, а не той проверкой,
// которую тест хочет увидеть.

namespace {

	constexpr uint8_t TEST_INDEX_KEY = 7;

	const SigningKey& testKey() {
		static SigningKey key;
		static bool made = false;
		if (!made) {
			std::string error;
			made = generateSigningKey(TEST_INDEX_KEY, key, error);
		}
		return key;
	}

	IndexTrust testTrust() {
		static IndexKey keys[1];
		keys[0].id = testKey().id;
		std::memcpy(keys[0].publicKey, testKey().publicKey, 64);
		IndexTrust trust;
		trust.keys = keys;
		trust.count = 1;
		return trust;
	}

	IndexTrust unsignedTrust() {
		IndexTrust trust = testTrust();
		trust.allowUnsigned = true;
		return trust;
	}

	// Подписать тестовым ключом (key_id = 7).
	std::vector<uint8_t> sealed(std::vector<uint8_t> file) {
		std::string error;
		signIndexFile(file, testKey(), error);
		return file;
	}

	// Пересчитать подпись, не трогая key_id.
	void reseal(std::vector<uint8_t>& file) {
		std::string error;
		resignIndexFile(file, testKey(), error);
	}

	struct Pkg {
		std::string name, version, url, extractDir, bins, description;
		uint32_t archiveSize;
		uint8_t arch, kind;
	};

	std::vector<uint8_t> rawIndex(const std::vector<Pkg>& pkgs, uint16_t entrySize = sizeof(IndexEntry)) {
		std::string pool;
		auto add = [&](const std::string& s) {
			const StrRef r{ (uint32_t)pool.size(), (uint32_t)s.size() };
			pool += s;
			return r;
		};

		std::vector<uint8_t> table(pkgs.size() * entrySize, 0);
		for (size_t i = 0; i < pkgs.size(); i++) {
			IndexEntry e = {};
			e.name = add(pkgs[i].name);
			e.version = add(pkgs[i].version);
			e.url = add(pkgs[i].url);
			e.extract_dir = add(pkgs[i].extractDir);
			e.bins = add(pkgs[i].bins);
			e.description = add(pkgs[i].description);
			e.archive_size = pkgs[i].archiveSize;
			e.arch = pkgs[i].arch;
			e.kind = pkgs[i].kind;
			for (int b = 0; b < 32; b++) e.sha256[b] = (uint8_t)(i * 32 + b);
			std::memcpy(table.data() + i * entrySize, &e, sizeof(e));
		}

		IndexHeader h = {};
		std::memcpy(h.magic, INDEX_BODY_MAGIC, 8);
		h.format = INDEX_FORMAT;
		h.entry_size = entrySize;
		h.entry_count = (uint32_t)pkgs.size();
		h.generated_at = 1763500000;
		h.strings_offset = (uint32_t)(sizeof(IndexHeader) + table.size());
		h.strings_size = (uint32_t)pool.size();

		std::vector<uint8_t> body(sizeof(h));
		std::memcpy(body.data(), &h, sizeof(h));
		body.insert(body.end(), table.begin(), table.end());
		body.insert(body.end(), pool.begin(), pool.end());

		Envelope env = {};
		std::memcpy(env.magic, ENVELOPE_MAGIC, 8);
		env.envelope_version = ENVELOPE_VERSION;
		env.payload_size = env.raw_size = (uint32_t)body.size();

		std::vector<uint8_t> file(sizeof(env));
		std::memcpy(file.data(), &env, sizeof(env));
		file.insert(file.end(), body.begin(), body.end());
		return sealed(file);
	}

	const char* RG_URL = "https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-pc-windows-msvc.zip";

	std::vector<Pkg> goodPkgs() {
		return {
			{ "fd", "10.2.0", "https://example.com/fd.zip", "", "fd.exe", "Find files", 1000, ARCH_X64, KIND_ZIP },
			{ "ripgrep", "15.2.0", RG_URL, "ripgrep-15.2.0-i686-pc-windows-msvc", "rg.exe", "Search", 1642641, ARCH_X86, KIND_ZIP },
			{ "ripgrep", "15.2.0", RG_URL, "ripgrep-15.2.0-x86_64-pc-windows-msvc", "rg.exe", "Search", 1789611, ARCH_X64, KIND_ZIP },
			{ "tools", "1.0", "https://example.com/t.zip", "", "bin\\a.exe;bin\\b.exe", "", 5, ARCH_X64, KIND_ZIP },
		};
	}

	// Индекс должен быть отвергнут на open или на validateAll.
	void expectRejected(const char* label, std::vector<uint8_t> file) {
		IndexView v;
		std::string err;
		const bool accepted = v.open(std::move(file), err, testTrust()) && v.validateAll(err);
		check(!accepted, label, accepted ? "ACCEPTED" : err);
	}

	void mutateEnvelope(const char* label, std::function<void(Envelope&)> f) {
		auto file = rawIndex(goodPkgs());
		Envelope e;
		std::memcpy(&e, file.data(), sizeof(e));
		f(e);
		std::memcpy(file.data(), &e, sizeof(e));
		reseal(file);
		expectRejected(label, file);
	}

	void mutateHeader(const char* label, std::function<void(IndexHeader&)> f) {
		auto file = rawIndex(goodPkgs());
		IndexHeader h;
		std::memcpy(&h, file.data() + sizeof(Envelope), sizeof(h));
		f(h);
		std::memcpy(file.data() + sizeof(Envelope), &h, sizeof(h));
		reseal(file);
		expectRejected(label, file);
	}

	void mutateEntry(const char* label, size_t i, std::function<void(IndexEntry&)> f) {
		auto file = rawIndex(goodPkgs());
		const size_t off = sizeof(Envelope) + sizeof(IndexHeader) + i * sizeof(IndexEntry);
		IndexEntry e;
		std::memcpy(&e, file.data() + off, sizeof(e));
		f(e);
		std::memcpy(file.data() + off, &e, sizeof(e));
		reseal(file);
		expectRejected(label, file);
	}

	void badPkg(const char* label, std::function<void(Pkg&)> f) {
		auto pkgs = goodPkgs();
		f(pkgs[2]);
		expectRejected(label, rawIndex(pkgs));
	}

	// Конверт с compression = 1 вокруг уже сжатого тела; rawSize — что заявлено в конверте.
	std::vector<uint8_t> envelopeAround(const std::vector<uint8_t>& payload, uint32_t rawSize) {
		Envelope env = {};
		std::memcpy(env.magic, ENVELOPE_MAGIC, 8);
		env.envelope_version = ENVELOPE_VERSION;
		env.compression = COMPRESSION_DEFLATE;
		env.payload_size = (uint32_t)payload.size();
		env.raw_size = rawSize;

		std::vector<uint8_t> file(sizeof(env));
		std::memcpy(file.data(), &env, sizeof(env));
		file.insert(file.end(), payload.begin(), payload.end());
		return sealed(file);
	}

	// Тот же индекс, что rawIndex, но с телом, сжатым настоящим deflateRaw генератора.
	// rawDelta сдвигает заявленный raw_size относительно настоящего.
	std::vector<uint8_t> compressedIndex(const std::vector<Pkg>& pkgs, int rawDelta = 0) {
		const std::vector<uint8_t> plain = rawIndex(pkgs);
		const std::vector<uint8_t> body(plain.begin() + sizeof(Envelope), plain.end());
		std::vector<uint8_t> packed;
		deflateRaw(body, packed);
		return envelopeAround(packed, (uint32_t)((int64_t)body.size() + rawDelta));
	}

	// После правки сжатого тела payload_size должен снова совпадать с размером файла,
	// иначе отказ случится на шаге 1, а не на распаковке, которую хотим проверить. Подпись — заново.
	void setPayloadSize(std::vector<uint8_t>& file) {
		Envelope env;
		std::memcpy(&env, file.data(), sizeof(env));
		env.payload_size = (uint32_t)(file.size() - sizeof(Envelope));
		std::memcpy(file.data(), &env, sizeof(env));
		reseal(file);
	}

	// Минимальный заголовок PE: MZ, e_lfanew, "PE\0\0", Machine и Characteristics.
	std::vector<uint8_t> fakePe(uint16_t machine, uint16_t characteristics, uint32_t peOffset = 0x80) {
		std::vector<uint8_t> bytes(512, 0);
		bytes[0] = 'M';
		bytes[1] = 'Z';
		std::memcpy(&bytes[0x3C], &peOffset, sizeof(peOffset));
		if ((uint64_t)peOffset + 24 <= bytes.size()) {
			std::memcpy(&bytes[peOffset], "PE\0\0", 4);
			std::memcpy(&bytes[peOffset + 4], &machine, sizeof(machine));
			std::memcpy(&bytes[peOffset + 22], &characteristics, sizeof(characteristics));
		}
		return bytes;
	}

	void expectPe(const char* label, const std::vector<uint8_t>& bytes, uint8_t arch, bool ok) {
		std::string error;
		const bool accepted = checkPeHeader(bytes.data(), bytes.size(), arch, error);
		check(accepted == ok, label, accepted ? "accepted" : error);
	}

	BuildEntry buildEntry(const char* name, uint8_t arch, const char* url, uint32_t size) {
		BuildEntry e;
		e.name = name;
		e.version = "1.0";
		e.url = url;
		e.binList = "bin\\tool.exe";
		e.description = "Shared description";
		e.archiveSize = size;
		e.arch = arch;
		e.kind = KIND_ZIP;
		e.sha256[0] = (uint8_t)size;
		return e;
	}
}

void runIndexTests() {
	beginSuite("index: valid");
	{
		IndexView v;
		std::string err;
		const bool ok = v.open(rawIndex(goodPkgs()), err, testTrust()) && v.validateAll(err);
		check(ok, "valid index accepted", err);
		check(v.count() == 4, "count = 4");
		check(v.generatedAt() == 1763500000, "generated_at read");

		IndexRecord r;
		check(v.find("ripgrep", ARCH_X64, r, err) == FindResult::Found &&
			r.extractDir == "ripgrep-15.2.0-x86_64-pc-windows-msvc" && r.archiveSize == 1789611 && r.sha256[0] == 64,
			"find ripgrep/x64", err);
		check(v.find("ripgrep", ARCH_X86, r, err) == FindResult::Found && r.archiveSize == 1642641, "find ripgrep/x86", err);
		check(v.find("ripgrep", ARCH_ARM64, r, err) == FindResult::NotFound, "find ripgrep/arm64 -> not found");
		check(v.find("zzz", ARCH_X64, r, err) == FindResult::NotFound, "find absent package -> not found");
		check(v.find("fd", ARCH_X64, r, err) == FindResult::Found, "find first entry");
		check(v.find("tools", ARCH_X64, r, err) == FindResult::Found &&
			r.bins.size() == 2 && r.bins[0] == "bin\\a.exe" && r.bins[1] == "bin\\b.exe", "bins split", err);
	}
	{
		IndexView v;
		std::string err;
		IndexRecord r;
		const bool ok = v.open(rawIndex({}), err, testTrust()) && v.validateAll(err);
		check(ok && v.find("x", ARCH_X64, r, err) == FindResult::NotFound, "empty index accepted, find -> not found", err);
	}
	{
		// Записи длиннее известного: поля из будущих версий пропускаются.
		IndexView v;
		std::string err;
		IndexRecord r;
		const bool ok = v.open(rawIndex(goodPkgs(), sizeof(IndexEntry) + 24), err, testTrust()) && v.validateAll(err) &&
			v.find("ripgrep", ARCH_X64, r, err) == FindResult::Found && r.archiveSize == 1789611;
		check(ok, "longer entry_size accepted", err);
	}

	beginSuite("index: envelope");
	expectRejected("too small", std::vector<uint8_t>(10, 0));
	expectRejected("too large (> 8 MB)", std::vector<uint8_t>(8 * 1024 * 1024 + 1, 0));
	{ auto f = rawIndex(goodPkgs()); f.pop_back(); expectRejected("truncated by one byte", f); }
	{ auto f = rawIndex(goodPkgs()); f.push_back(0); expectRejected("one extra byte", f); }
	mutateEnvelope("bad magic", [](Envelope& e) { e.magic[0] = 'X'; });
	mutateEnvelope("envelope_version 2", [](Envelope& e) { e.envelope_version = 2; });
	mutateEnvelope("reserved != 0", [](Envelope& e) { e.reserved = 1; });
	mutateEnvelope("key_id 1 (unknown key)", [](Envelope& e) { e.key_id = 1; });
	mutateEnvelope("compression 1 over an uncompressed body", [](Envelope& e) { e.compression = COMPRESSION_DEFLATE; });
	mutateEnvelope("compression 2 (unknown)", [](Envelope& e) { e.compression = 2; });
	mutateEnvelope("raw_size != payload_size", [](Envelope& e) { e.raw_size -= 1; });
	mutateEnvelope("payload_size = 0xFFFFFFFF", [](Envelope& e) { e.payload_size = 0xFFFFFFFFu; });

	// Сжатое тело (DESIGN.md §6.1, шаг 4): ровно raw_size байт, вход израсходован целиком,
	// потолок 32 МБ — до распаковки.
	beginSuite("index: compressed body");
	{
		IndexView v;
		std::string err;
		IndexRecord r;
		check(v.open(compressedIndex(goodPkgs()), err, testTrust()) && v.validateAll(err) &&
			v.find("ripgrep", ARCH_X64, r, err) == FindResult::Found && r.archiveSize == 1789611, "valid compressed index", err);
	}
	expectRejected("raw_size one byte too small", compressedIndex(goodPkgs(), -1));
	expectRejected("raw_size one byte too large", compressedIndex(goodPkgs(), +1));
	{ auto f = compressedIndex(goodPkgs()); f.push_back(0x42); setPayloadSize(f); expectRejected("data after the deflate stream", f); }
	{ auto f = compressedIndex(goodPkgs()); f.resize(f.size() - 5); setPayloadSize(f); expectRejected("truncated deflate stream", f); }
	{ auto f = compressedIndex(goodPkgs()); for (size_t i = sizeof(Envelope); i < f.size(); i++) f[i] ^= 0x5A; reseal(f); expectRejected("garbage deflate stream", f); }
	{
		// «Бомба»: 20 МБ нулей сжимаются в десятки килобайт, а raw_size заявлен 1 МБ —
		// распаковка обязана остановиться на 1 МБ, а не раздуть память.
		std::vector<uint8_t> zeros(20 * 1024 * 1024, 0);
		std::vector<uint8_t> packed;
		deflateRaw(zeros, packed);
		expectRejected("expands far beyond raw_size", envelopeAround(packed, 1024 * 1024));
	}
	{
		std::vector<uint8_t> packed;
		deflateRaw(std::vector<uint8_t>(64, 0), packed);
		expectRejected("raw_size over 32 MB", envelopeAround(packed, 33u * 1024 * 1024));
	}

	// Подпись (DESIGN.md §6.1, шаги 2–3): неподписанный индекс клиент не принимает никогда,
	// а любой изменённый байт подписанного даёт отказ — до распаковки и разбора.
	beginSuite("index: signature");
	{
		IndexView v;
		std::string err;
		check(v.open(rawIndex(goodPkgs()), err, testTrust()) && v.keyId() == TEST_INDEX_KEY, "signed index: key_id read", err);
	}
	{
		auto unsignedFile = rawIndex(goodPkgs());
		unsignedFile[offsetof(Envelope, key_id)] = KEY_ID_UNSIGNED;
		std::memset(unsignedFile.data() + offsetof(Envelope, signature), 0, 64);

		IndexView v;
		std::string err;
		check(!v.open(unsignedFile, err, testTrust()) && err.find("not signed") != std::string::npos,
			"unsigned index rejected by the client", err);
		check(v.open(unsignedFile, err, unsignedTrust()) && v.keyId() == KEY_ID_UNSIGNED,
			"unsigned index accepted only with allowUnsigned (flan-build, previous index)", err);

		auto withSignature = unsignedFile;
		withSignature[offsetof(Envelope, signature) + 63] = 1;
		check(!v.open(withSignature, err, unsignedTrust()) && err.find("non-zero signature") != std::string::npos,
			"unsigned index with a non-zero signature rejected even with allowUnsigned", err);
	}
	{
		IndexView v;
		std::string err;
		check(!v.open(rawIndex(goodPkgs()), err) && err.find("unknown to this version") != std::string::npos,
			"built-in trust does not know the runtime test key", err);
	}
	{
		auto file = rawIndex(goodPkgs());
		auto other = file;
		SigningKey stranger;
		std::string err;
		generateSigningKey(TEST_INDEX_KEY, stranger, err);
		signIndexFile(other, stranger, err);
		IndexView v;
		check(!v.open(other, err, testTrust()) && err.find("signature is invalid") != std::string::npos,
			"same key number, different key: rejected", err);
	}
	for (const bool compressed : { false, true }) {
		// Каждый байт файла по очереди: подпись покрывает всё, кроме самой себя, а сама она
		// без закрытого ключа не подбирается. Байты тела и подписи отвергаются именно подписью.
		const std::vector<uint8_t> good = compressed ? compressedIndex(goodPkgs()) : rawIndex(goodPkgs());
		size_t accepted = 0;
		size_t notBySignature = 0;
		std::string firstAccepted;
		for (size_t i = 0; i < good.size(); i++) {
			for (const uint8_t bit : { (uint8_t)0x01, (uint8_t)0x80 }) {
				auto file = good;
				file[i] ^= bit;
				IndexView v;
				std::string err;
				if (v.open(file, err, testTrust())) {
					accepted++;
					if (firstAccepted.empty()) {
						firstAccepted = "byte " + std::to_string(i);
					}
				}
				else if (i >= SIGNED_ENVELOPE_PREFIX && err.find("signature is invalid") == std::string::npos) {
					notBySignature++;
				}
			}
		}
		const std::string kind = compressed ? "compressed" : "uncompressed";
		check(accepted == 0, kind + ": every changed byte is rejected", firstAccepted);
		check(notBySignature == 0, kind + ": changes after the first 24 bytes are rejected by the signature",
			std::to_string(notBySignature) + " other reason(s)");
	}

	beginSuite("index: body header");
	mutateHeader("bad body magic", [](IndexHeader& h) { h.magic[7] = 'X'; });
	mutateHeader("format 1", [](IndexHeader& h) { h.format = 1; });
	mutateHeader("format 3", [](IndexHeader& h) { h.format = 3; });
	mutateHeader("entry_size < 88", [](IndexHeader& h) { h.entry_size = 87; });
	mutateHeader("entry_size huge", [](IndexHeader& h) { h.entry_size = 60000; });
	mutateHeader("entry_count = 0xFFFFFFFF (overflow)", [](IndexHeader& h) { h.entry_count = 0xFFFFFFFFu; });
	mutateHeader("entry_count + 1 (table overlaps pool)", [](IndexHeader& h) { h.entry_count += 1; });
	mutateHeader("strings_offset inside table", [](IndexHeader& h) { h.strings_offset -= 1; });
	mutateHeader("strings_size past end", [](IndexHeader& h) { h.strings_size += 1; });
	mutateHeader("strings_offset+size overflow", [](IndexHeader& h) { h.strings_offset = 0xFFFFFFF0u; h.strings_size = 0x20; });

	beginSuite("index: entry structure");
	mutateEntry("string off past pool", 2, [](IndexEntry& e) { e.url.off = 0x7FFFFFFF; });
	mutateEntry("string off+len overflow", 2, [](IndexEntry& e) { e.url.off = 0xFFFFFFFFu; e.url.len = 2; });
	mutateEntry("string len > 4096", 2, [](IndexEntry& e) { e.url.len = 5000; });
	mutateEntry("archive_size 0", 2, [](IndexEntry& e) { e.archive_size = 0; });
	mutateEntry("archive_size > 512 MB", 2, [](IndexEntry& e) { e.archive_size = 512u * 1024 * 1024 + 1; });
	mutateEntry("arch 4", 2, [](IndexEntry& e) { e.arch = 4; });
	mutateEntry("arch 0", 2, [](IndexEntry& e) { e.arch = 0; });
	mutateEntry("kind 3", 2, [](IndexEntry& e) { e.kind = 3; });
	{ auto p = goodPkgs(); std::swap(p[0], p[1]); expectRejected("not sorted", rawIndex(p)); }
	{ auto p = goodPkgs(); p[1] = p[2]; expectRejected("duplicate (name, arch)", rawIndex(p)); }
	{ auto p = goodPkgs(); std::swap(p[1], p[2]); expectRejected("same name, arch order wrong", rawIndex(p)); }

	beginSuite("index: entry strings");
	badPkg("uppercase name", [](Pkg& p) { p.name = "RipGrep"; });
	badPkg("traversal name", [](Pkg& p) { p.name = "..\\evil"; });
	badPkg("device name", [](Pkg& p) { p.name = "con"; });
	badPkg("version with '+'", [](Pkg& p) { p.version = "1.0+build"; });
	badPkg("version traversal", [](Pkg& p) { p.version = ".."; });
	badPkg("http url", [](Pkg& p) { p.url = "http://example.com/a.zip"; });
	badPkg("url /latest/", [](Pkg& p) { p.url = "https://github.com/a/b/releases/latest/download/a.zip"; });
	badPkg("url with space", [](Pkg& p) { p.url = "https://example.com/a b.zip"; });
	badPkg("url with control char", [](Pkg& p) { p.url = std::string("https://example.com/a\x01.zip"); });
	badPkg("extract_dir traversal", [](Pkg& p) { p.extractDir = "..\\..\\Startup"; });
	badPkg("extract_dir non-canonical '/'", [](Pkg& p) { p.extractDir = "a/b"; });
	badPkg("bins empty", [](Pkg& p) { p.bins = ""; });
	badPkg("bins traversal", [](Pkg& p) { p.bins = "..\\evil.exe"; });
	badPkg("bins absolute", [](Pkg& p) { p.bins = "C:\\Windows\\evil.exe"; });
	badPkg("bins .bat", [](Pkg& p) { p.bins = "rg.bat"; });
	badPkg("bins without extension", [](Pkg& p) { p.bins = "rg"; });
	badPkg("bins non-canonical '/'", [](Pkg& p) { p.bins = "bin/rg.exe"; });
	badPkg("bins duplicate command", [](Pkg& p) { p.bins = "a\\rg.exe;b\\RG.EXE"; });
	badPkg("bins trailing ';'", [](Pkg& p) { p.bins = "rg.exe;"; });
	badPkg("bins 9 entries", [](Pkg& p) { p.bins = "a.exe;b.exe;c.exe;d.exe;e.exe;f.exe;g.exe;h.exe;i.exe"; });
	badPkg("bins quote injection", [](Pkg& p) { p.bins = "a\" & calc & \".exe"; });
	badPkg("description > 100 bytes", [](Pkg& p) { p.description = std::string(101, 'x'); });
	badPkg("description with ESC", [](Pkg& p) { p.description = "red \x1b[31m text"; });
	{
		auto p = goodPkgs();
		p[2].bins = "a.exe;b.exe;c.exe;d.exe;e.exe;f.exe;g.exe;h.exe";
		IndexView v;
		std::string err;
		check(v.open(rawIndex(p), err, testTrust()) && v.validateAll(err), "bins 8 entries accepted", err);
	}

	// kind = exe (DESIGN.md §5.2): ровно один bin без подкаталогов, без extract_dir.
	beginSuite("index: kind exe");
	{
		auto p = goodPkgs();
		p.push_back({ "zz", "1.8.2", "https://example.com/jq-windows-amd64.exe", "", "jq.exe", "JSON", 1035264, ARCH_X64, KIND_EXE });
		IndexView v;
		std::string err;
		IndexRecord r;
		check(v.open(rawIndex(p), err, testTrust()) && v.validateAll(err) && v.find("zz", ARCH_X64, r, err) == FindResult::Found &&
			r.kind == KIND_EXE && r.bins.size() == 1 && r.bins[0] == "jq.exe" && r.extractDir.empty(), "exe entry accepted", err);
	}
	badPkg("exe with two bins", [](Pkg& p) { p.kind = KIND_EXE; p.extractDir = ""; p.bins = "a.exe;b.exe"; });
	badPkg("exe with a folder in bin", [](Pkg& p) { p.kind = KIND_EXE; p.extractDir = ""; p.bins = "bin\\jq.exe"; });
	badPkg("exe with extract_dir", [](Pkg& p) { p.kind = KIND_EXE; p.bins = "rg.exe"; });

	beginSuite("pe header");
	expectPe("x64 executable as x64", fakePe(0x8664, 0x0022), ARCH_X64, true);
	expectPe("x86 executable as x86", fakePe(0x014C, 0x0102), ARCH_X86, true);
	expectPe("arm64 executable as arm64", fakePe(0xAA64, 0x0022), ARCH_ARM64, true);
	expectPe("x64 executable listed as x86", fakePe(0x8664, 0x0022), ARCH_X86, false);
	expectPe("x86 executable listed as x64", fakePe(0x014C, 0x0102), ARCH_X64, false);
	expectPe("DLL", fakePe(0x8664, 0x2022), ARCH_X64, false);
	expectPe("not an executable image", fakePe(0x8664, 0x0020), ARCH_X64, false);
	expectPe("e_lfanew out of bounds", fakePe(0x8664, 0x0022, 0xFFFFFFF0u), ARCH_X64, false);
	expectPe("e_lfanew too close to the end", fakePe(0x8664, 0x0022, 512 - 23), ARCH_X64, false);
	{
		auto bytes = fakePe(0x8664, 0x0022);
		bytes[0x80] = 'X';
		expectPe("no PE signature", bytes, ARCH_X64, false);
	}
	{
		auto bytes = fakePe(0x8664, 0x0022);
		bytes[0] = 'P';
		bytes[1] = 'K';
		expectPe("zip instead of exe", bytes, ARCH_X64, false);
	}
	expectPe("too short", std::vector<uint8_t>(10, 'M'), ARCH_X64, false);
	expectPe("empty", std::vector<uint8_t>(), ARCH_X64, false);

	beginSuite("index: find re-validates");
	{
		// Испорченная запись, которую find найдёт по имени: open проходит, find отвергает.
		auto p = goodPkgs();
		p[2].url = "http://evil.example/a.zip";
		IndexView v;
		std::string err;
		IndexRecord r;
		const bool opened = v.open(rawIndex(p), err, testTrust());
		const FindResult fr = v.find("ripgrep", ARCH_X64, r, err);
		check(opened && fr == FindResult::Corrupt, "open ok, find -> Corrupt", err);
	}

	// Настоящий писатель генератора и клиентский разбор должны сходиться.
	beginSuite("writer: round trip");
	{
		std::vector<BuildEntry> entries = {
			buildEntry("zeta", ARCH_X64, "https://example.com/zeta-x64.zip", 30),
			buildEntry("alpha", ARCH_X64, "https://example.com/alpha-x64.zip", 20),
			buildEntry("alpha", ARCH_X86, "https://example.com/alpha-x86.zip", 10),
		};
		entries[1].extractDir = "alpha-1.0";

		std::vector<uint8_t> file;
		std::string err;
		check(buildIndexFile(entries, 1795000000, testKey(), file, err), "buildIndexFile on unsorted input", err);

		IndexView v;
		const bool ok = v.open(file, err, testTrust()) && v.validateAll(err);
		check(ok, "client accepts generated index", err);
		check(v.count() == 3 && v.generatedAt() == 1795000000, "count and generated_at");

		IndexRecord first;
		check(v.record(0, first, err) && first.name == "alpha" && first.arch == ARCH_X86, "sorted: alpha/x86 first", err);

		IndexRecord r;
		check(v.find("alpha", ARCH_X64, r, err) == FindResult::Found && r.extractDir == "alpha-1.0" &&
			r.archiveSize == 20 && r.sha256[0] == 20 && r.bins.size() == 1 && r.bins[0] == "bin\\tool.exe" &&
			r.description == "Shared description", "alpha/x64 fields", err);
		check(v.find("zeta", ARCH_X64, r, err) == FindResult::Found && r.url == "https://example.com/zeta-x64.zip", "zeta/x64", err);

		Envelope env;
		std::memcpy(&env, file.data(), sizeof(env));
		bool zeroSignature = true;
		for (const uint8_t b : env.signature) zeroSignature = zeroSignature && b == 0;
		check(env.key_id == TEST_INDEX_KEY && env.compression == COMPRESSION_DEFLATE && !zeroSignature &&
			env.payload_size + sizeof(Envelope) == file.size(), "signed (key_id 7), deflate-compressed envelope");
	}
	{
		std::vector<uint8_t> file;
		std::string err;
		std::vector<BuildEntry> duplicate = {
			buildEntry("alpha", ARCH_X64, "https://example.com/a.zip", 1),
			buildEntry("alpha", ARCH_X64, "https://example.com/b.zip", 2),
		};
		check(!buildIndexFile(duplicate, 1, testKey(), file, err), "duplicate (name, arch) rejected by writer", err);

		IndexView v;
		check(buildIndexFile({}, 1, testKey(), file, err) && v.open(file, err, testTrust()) && v.validateAll(err) && v.count() == 0,
			"empty index round trip", err);
	}
}
