#include "test.hpp"
#include "flan/hex.hpp"
#include "flan/validate.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace {

	struct NameCase {
		const char* input;
		bool ok;
	};

	void nameTable(const char* function, bool (*validator)(const std::string&), const std::vector<NameCase>& cases) {
		for (const NameCase& c : cases) {
			check(validator(c.input) == c.ok, std::string(function) + "(\"" + c.input + "\")", c.ok ? "expected ok" : "expected deny");
		}
	}

	struct PathCase {
		const char* input;
		bool ok;
		const char* expected;
	};
}

void runValidateTests() {
	beginSuite("isSafeName");
	nameTable("isSafeName", isSafeName, {
		{ "ripgrep", true }, { "rg.exe", true }, { "a_b-c.1", true }, { "15.2.0", true }, { "UPPER", true },
		{ "", false }, { ".hidden", false }, { "-flag", false }, { "dot.", false }, { "..", false }, { ".", false },
		{ "a/b", false }, { "a\\b", false }, { "a b", false }, { "a\"b", false }, { "a&b", false }, { "a:b", false },
		{ "a;b", false }, { "a+b", false }, { "a*b", false },
		{ "CON", false }, { "con", false }, { "Nul.txt", false }, { "COM1", false }, { "lpt9.log", false },
		{ "COM0", true }, { "COM10", true }, { "CONSOLE", true },
	});
	check(isSafeName(std::string(MAX_NAME_LENGTH, 'a')), "isSafeName(64 chars)");
	check(!isSafeName(std::string(MAX_NAME_LENGTH + 1, 'a')), "isSafeName(65 chars) denied");
	check(!isSafeName(std::string("a\0b", 3)), "isSafeName(embedded NUL) denied");

	beginSuite("isSafePackageName");
	nameTable("isSafePackageName", isSafePackageName, {
		{ "ripgrep", true }, { "7zip", true }, { "python3.12", true },
		{ "RipGrep", false }, { "A", false }, { "con", false }, { "..", false },
	});

	beginSuite("normalizeRelativePath");
	const std::vector<PathCase> paths = {
		{ "rg.exe", true, "rg.exe" },
		{ "ripgrep-13.0.0-x86_64-pc-windows-msvc/rg.exe", true, "ripgrep-13.0.0-x86_64-pc-windows-msvc\\rg.exe" },
		{ "bin\\tool.exe", true, "bin\\tool.exe" },
		{ "../evil.exe", false, "" },
		{ "a/../../evil.exe", false, "" },
		{ "..\\..\\Startup\\evil.exe", false, "" },
		{ "C:\\Windows\\evil.exe", false, "" },
		{ "/abs/evil.exe", false, "" },
		{ "\\\\server\\share\\evil.exe", false, "" },
		{ "dir/", false, "" },
		{ "a//b.exe", false, "" },
		{ "dir/CON", false, "" },
		{ "dir/evil.exe.", false, "" },
		{ "a\" & calc & \"", false, "" },
		{ "1/2/3/4/5/6/7/8/9.exe", false, "" },
		{ "", false, "" },
	};
	for (const PathCase& c : paths) {
		std::string normalized;
		const bool ok = normalizeRelativePath(c.input, normalized);
		check(ok == c.ok && (!ok || normalized == c.expected), std::string("normalizeRelativePath(\"") + c.input + "\")",
			"got " + std::string(ok ? "ok \"" + normalized + "\"" : "deny"));
	}
	std::string tooLong;
	check(!normalizeRelativePath(std::string(MAX_RELATIVE_PATH_LENGTH + 1, 'a'), tooLong), "normalizeRelativePath(too long) denied");

	beginSuite("isCanonicalRelativePath");
	check(isCanonicalRelativePath("a\\b.exe"), "canonical a\\b.exe");
	check(!isCanonicalRelativePath("a/b.exe"), "non-canonical a/b.exe");
	check(!isCanonicalRelativePath(""), "empty is not canonical");

	beginSuite("isSafeDescription");
	check(isSafeDescription(""), "empty ok");
	check(isSafeDescription("Recursively search directories"), "plain text ok");
	check(isSafeDescription("\xD0\x9F\xD0\xBE\xD0\xB8\xD1\x81\xD0\xBA"), "UTF-8 Cyrillic ok");
	check(isSafeDescription(std::string(MAX_DESCRIPTION_LENGTH, 'x')), "100 bytes ok");
	check(!isSafeDescription(std::string(MAX_DESCRIPTION_LENGTH + 1, 'x')), "101 bytes denied");
	check(!isSafeDescription("red \x1b[31m"), "ESC denied");
	check(!isSafeDescription("line\nbreak"), "newline denied");
	check(!isSafeDescription(std::string("a\x7f")), "DEL denied");

	beginSuite("isSafePackageUrl");
	nameTable("isSafePackageUrl", isSafePackageUrl, {
		{ "https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/a.zip", true },
		{ "HTTPS://example.com/a.zip", true },
		{ "https://example.com/a.zip?token=abc&x=1", true },
		{ "http://example.com/a.zip", false },
		{ "https://", false },
		{ "ftp://example.com/a.zip", false },
		{ "https://example.com/a b.zip", false },
		{ "https://github.com/a/b/releases/latest/download/a.zip", false },
		{ "https://github.com/a/b/releases/LATEST/download/a.zip", false },
		{ "https://example.com/\xD0\xBF.zip", false },
	});
	check(!isSafePackageUrl("https://example.com/" + std::string(MAX_URL_LENGTH, 'a')), "isSafePackageUrl(too long) denied");

	beginSuite("commandNameFromBin");
	check(commandNameFromBin("rg.exe") == "rg", "rg.exe -> rg");
	check(commandNameFromBin("bin\\Tool.EXE") == "Tool", "bin\\Tool.EXE -> Tool");
	check(commandNameFromBin("rg.bat").empty(), "rg.bat -> none");
	check(commandNameFromBin(".exe").empty(), ".exe -> none");
	check(commandNameFromBin("a..exe").empty(), "a..exe -> none (trailing dot)");
	check(commandNameFromBin("con.exe").empty(), "con.exe -> none (device)");

	beginSuite("parseBinList");
	std::vector<std::string> bins;
	check(parseBinList("rg.exe", bins) && bins.size() == 1, "single");
	check(parseBinList("bin\\a.exe;bin\\b.exe", bins) && bins.size() == 2 && bins[1] == "bin\\b.exe", "two");
	check(parseBinList("a.exe;b.exe;c.exe;d.exe;e.exe;f.exe;g.exe;h.exe", bins) && bins.size() == 8, "eight");
	check(!parseBinList("a.exe;b.exe;c.exe;d.exe;e.exe;f.exe;g.exe;h.exe;i.exe", bins) && bins.empty(), "nine denied");
	check(!parseBinList("", bins), "empty denied");
	check(!parseBinList("rg.exe;", bins), "trailing ';' denied");
	check(!parseBinList("a\\rg.exe;b\\RG.EXE", bins), "duplicate command (case-insensitive) denied");
	check(!parseBinList("bin/rg.exe", bins), "non-canonical denied");
	check(!parseBinList("rg", bins), "no .exe denied");

	beginSuite("hex");
	const uint8_t bytes[4] = { 0x00, 0x7f, 0xab, 0xff };
	check(toHex(bytes, 4) == "007fabff", "toHex");
	uint8_t out[4] = {};
	check(fromHex("007FABff", out, 4) && out[2] == 0xab && out[3] == 0xff, "fromHex mixed case");
	uint8_t untouched[2] = { 1, 2 };
	check(!fromHex("0g", untouched, 1) && untouched[0] == 1, "fromHex bad digit denied, output untouched");
	check(!fromHex("abc", untouched, 2), "fromHex wrong length denied");
}
