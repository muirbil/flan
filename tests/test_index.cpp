#include "test.hpp"
#include "build.hpp"
#include "flan/index.hpp"
#include "flan/validate.hpp"
#include <cstring>
#include <functional>
#include <string>
#include <vector>

// Разбор index.flan (формат 2). Испорченные файлы собирает свой «сырой» писатель:
// настоящий (buildIndexFile) не умеет писать неотсортированный или битый индекс,
// а именно такие клиент обязан отвергать.

namespace {

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
		return file;
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
		const bool accepted = v.open(std::move(file), err) && v.validateAll(err);
		check(!accepted, label, accepted ? "ACCEPTED" : err);
	}

	void mutateEnvelope(const char* label, std::function<void(Envelope&)> f) {
		auto file = rawIndex(goodPkgs());
		Envelope e;
		std::memcpy(&e, file.data(), sizeof(e));
		f(e);
		std::memcpy(file.data(), &e, sizeof(e));
		expectRejected(label, file);
	}

	void mutateHeader(const char* label, std::function<void(IndexHeader&)> f) {
		auto file = rawIndex(goodPkgs());
		IndexHeader h;
		std::memcpy(&h, file.data() + sizeof(Envelope), sizeof(h));
		f(h);
		std::memcpy(file.data() + sizeof(Envelope), &h, sizeof(h));
		expectRejected(label, file);
	}

	void mutateEntry(const char* label, size_t i, std::function<void(IndexEntry&)> f) {
		auto file = rawIndex(goodPkgs());
		const size_t off = sizeof(Envelope) + sizeof(IndexHeader) + i * sizeof(IndexEntry);
		IndexEntry e;
		std::memcpy(&e, file.data() + off, sizeof(e));
		f(e);
		std::memcpy(file.data() + off, &e, sizeof(e));
		expectRejected(label, file);
	}

	void badPkg(const char* label, std::function<void(Pkg&)> f) {
		auto pkgs = goodPkgs();
		f(pkgs[2]);
		expectRejected(label, rawIndex(pkgs));
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
		const bool ok = v.open(rawIndex(goodPkgs()), err) && v.validateAll(err);
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
		const bool ok = v.open(rawIndex({}), err) && v.validateAll(err);
		check(ok && v.find("x", ARCH_X64, r, err) == FindResult::NotFound, "empty index accepted, find -> not found", err);
	}
	{
		// Записи длиннее известного: поля из будущих версий пропускаются.
		IndexView v;
		std::string err;
		IndexRecord r;
		const bool ok = v.open(rawIndex(goodPkgs(), sizeof(IndexEntry) + 24), err) && v.validateAll(err) &&
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
	mutateEnvelope("key_id 0 with non-zero signature", [](Envelope& e) { e.signature[63] = 1; });
	mutateEnvelope("compression 1 (deflate)", [](Envelope& e) { e.compression = COMPRESSION_DEFLATE; });
	mutateEnvelope("raw_size != payload_size", [](Envelope& e) { e.raw_size -= 1; });
	mutateEnvelope("payload_size = 0xFFFFFFFF", [](Envelope& e) { e.payload_size = 0xFFFFFFFFu; });

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
		check(v.open(rawIndex(p), err) && v.validateAll(err), "bins 8 entries accepted", err);
	}

	beginSuite("index: find re-validates");
	{
		// Испорченная запись, которую find найдёт по имени: open проходит, find отвергает.
		auto p = goodPkgs();
		p[2].url = "http://evil.example/a.zip";
		IndexView v;
		std::string err;
		IndexRecord r;
		const bool opened = v.open(rawIndex(p), err);
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
		check(buildIndexFile(entries, 1795000000, file, err), "buildIndexFile on unsorted input", err);

		IndexView v;
		const bool ok = v.open(file, err) && v.validateAll(err);
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
		check(env.key_id == KEY_ID_UNSIGNED && env.compression == COMPRESSION_NONE && zeroSignature &&
			env.payload_size == env.raw_size, "unsigned, uncompressed envelope");
	}
	{
		std::vector<uint8_t> file;
		std::string err;
		std::vector<BuildEntry> duplicate = {
			buildEntry("alpha", ARCH_X64, "https://example.com/a.zip", 1),
			buildEntry("alpha", ARCH_X64, "https://example.com/b.zip", 2),
		};
		check(!buildIndexFile(duplicate, 1, file, err), "duplicate (name, arch) rejected by writer", err);

		IndexView v;
		check(buildIndexFile({}, 1, file, err) && v.open(file, err) && v.validateAll(err) && v.count() == 0,
			"empty index round trip", err);
	}
}
