#include "test.hpp"
#include "core/index_state.hpp"
#include "core/receipt.hpp"
#include "core/shim.hpp"
#include "flan/format.hpp"
#include <functional>
#include <string>

// Квитанции (DESIGN.md §7.5) и .bat-прослойки этапа 1: из обоих файлов на диске
// строятся пути для удаления, поэтому всё, что не проходит проверку, — повреждение.

namespace {

	Receipt sampleReceipt() {
		Receipt r;
		r.name = "ripgrep";
		r.version = "15.2.0";
		r.dir = "15.2.0";
		r.arch = ARCH_X64;
		r.sha256 = "71b2fef860abe467217a538ff31de02f5258807c0129f771846f87bd029aafc5";
		r.bins = { "rg.exe" };
		r.installedAt = "2026-11-21T12:00:00Z";
		return r;
	}

	// Текст квитанции с одной изменённой строкой "key=..." (или без неё, если value пусто).
	std::string withLine(const std::string& key, const std::string& value, bool remove = false) {
		const std::string text = formatReceipt(sampleReceipt());
		std::string out;
		size_t start = 0;
		while (start < text.size()) {
			const size_t end = text.find('\n', start);
			const std::string line = text.substr(start, end - start);
			if (line.compare(0, key.size() + 1, key + "=") == 0) {
				if (!remove) out += key + "=" + value + "\n";
			}
			else {
				out += line + "\n";
			}
			start = end + 1;
		}
		return out;
	}

	void expectCorrupt(const std::string& label, const std::string& text) {
		Receipt r;
		std::string error;
		const bool ok = parseReceipt(text, r, error);
		check(!ok, label, ok ? "ACCEPTED" : error);
	}
}

void runReceiptTests() {
	beginSuite("receipt");
	{
		const Receipt original = sampleReceipt();
		Receipt parsed;
		std::string error;
		const bool ok = parseReceipt(formatReceipt(original), parsed, error);
		check(ok && parsed.name == original.name && parsed.version == original.version && parsed.dir == original.dir &&
			parsed.arch == original.arch && parsed.sha256 == original.sha256 && parsed.bins == original.bins &&
			parsed.installedAt == original.installedAt, "round trip", error);
	}
	{
		Receipt r = sampleReceipt();
		r.dir = "15.2.0-71b2fef8";
		r.bins = { "bin\\a.exe", "b.exe" };
		Receipt parsed;
		std::string error;
		check(parseReceipt(formatReceipt(r), parsed, error) && parsed.dir == "15.2.0-71b2fef8" &&
			parsed.bins.size() == 2 && parsed.bins[0] == "bin\\a.exe", "suffixed dir and two bins", error);
	}
	{
		std::string crlf;
		for (const char c : formatReceipt(sampleReceipt())) {
			if (c == '\n') crlf += '\r';
			crlf += c;
		}
		Receipt parsed;
		std::string error;
		check(parseReceipt(crlf, parsed, error) && parsed.installedAt == "2026-11-21T12:00:00Z", "CRLF line endings", error);
	}
	{
		Receipt parsed;
		std::string error;
		check(parseReceipt(formatReceipt(sampleReceipt()) + "future_field=whatever\n", parsed, error), "unknown key ignored", error);
		check(parseReceipt(withLine("sha256", "71B2FEF860ABE467217A538FF31DE02F5258807C0129F771846F87BD029AAFC5"), parsed, error) &&
			parsed.sha256 == sampleReceipt().sha256, "uppercase sha256 normalized", error);
		check(parseReceipt(withLine("installed_at", "", true), parsed, error) && parsed.installedAt.empty(),
			"installed_at is optional", error);
	}

	for (const char* key : { "name", "version", "dir", "arch", "sha256", "bins" }) {
		expectCorrupt(std::string("missing ") + key, withLine(key, "", true));
	}
	expectCorrupt("duplicate key", formatReceipt(sampleReceipt()) + "dir=other\n");
	expectCorrupt("line without '='", formatReceipt(sampleReceipt()) + "garbage\n");
	expectCorrupt("empty key", formatReceipt(sampleReceipt()) + "=value\n");
	expectCorrupt("uppercase name", withLine("name", "RipGrep"));
	expectCorrupt("traversal name", withLine("name", "..\\evil"));
	expectCorrupt("dir '..'", withLine("dir", ".."));
	expectCorrupt("dir with separator", withLine("dir", "a\\b"));
	expectCorrupt("dir absolute", withLine("dir", "C:\\Windows"));
	expectCorrupt("dir device name", withLine("dir", "CON"));
	expectCorrupt("version with '+'", withLine("version", "1.0+build"));
	expectCorrupt("unknown arch", withLine("arch", "arm"));
	expectCorrupt("short sha256", withLine("sha256", "abc"));
	expectCorrupt("non-hex sha256", withLine("sha256", std::string(64, 'g')));
	expectCorrupt("bins traversal", withLine("bins", "..\\evil.exe"));
	expectCorrupt("bins .bat", withLine("bins", "rg.bat"));
	expectCorrupt("bins empty", withLine("bins", ""));
	expectCorrupt("installed_at with ESC", withLine("installed_at", "2026\x1b[31m"));
	expectCorrupt("empty text", "");

	// state\index.state: повреждённое состояние — не ошибка, а «без условного запроса».
	beginSuite("index state");
	{
		IndexState state;
		state.source = "https://raw.githubusercontent.com/muirbil/flan-packages/main/index.flan";
		state.etag = "\"87100af0bc297c89f656b23a5151f69980ac2c94707289605dc6ff92baea6d61\"";
		state.generatedAt = 1795269156;
		IndexState parsed;
		check(parseIndexState(formatIndexState(state), parsed) && parsed.source == state.source &&
			parsed.etag == state.etag && parsed.generatedAt == state.generatedAt, "round trip with a strong ETag");

		state.etag = "W/\"abc\"";
		check(parseIndexState(formatIndexState(state), parsed) && parsed.etag == "W/\"abc\"", "weak ETag kept verbatim");

		state.etag.clear();
		check(parseIndexState(formatIndexState(state), parsed) && parsed.etag.empty(), "no ETag");
	}
	{
		IndexState parsed;
		check(parseIndexState("source=C:\\repo\\index.flan\r\netag=\r\ngenerated_at=5\r\nfuture=1\r\n", parsed) &&
			parsed.source == "C:\\repo\\index.flan" && parsed.generatedAt == 5, "CRLF and unknown key");
		check(!parseIndexState("etag=\"x\"\n", parsed), "missing source");
		check(!parseIndexState("source=\n", parsed), "empty source");
		check(!parseIndexState("source=a\nnoequals\n", parsed), "line without '='");
		check(!parseIndexState("source=a\ngenerated_at=-1\n", parsed), "negative generated_at");
		check(!parseIndexState("source=a\netag=\"x\x01y\"\n", parsed), "control character in ETag");
		check(!parseIndexState("source=a\tb\n", parsed), "control character in source");
		check(!parseIndexState("source=a\netag=" + std::string(300, 'x') + "\n", parsed), "overlong ETag");
		check(!parseIndexState("", parsed), "empty file");
	}

	beginSuite("shim");
	{
		const std::string text = formatShim("C:\\Users\\me\\.flan\\apps\\ripgrep\\15.2.0\\rg.exe", "ripgrep");
		check(text == "@echo off\r\nrem package=ripgrep\r\n"
			"\"C:\\Users\\me\\.flan\\apps\\ripgrep\\15.2.0\\rg.exe\" %* & call exit /b %%errorlevel%%\r\n",
			"exact content");

		std::string owner;
		check(parseShimOwner(text, owner) == ShimOwner::Package && owner == "ripgrep", "owner of own shim");
	}
	check(formatShim("C:\\Users\\50%off\\a.exe", "a").find("\"C:\\Users\\50%%off\\a.exe\"") != std::string::npos,
		"percent sign escaped");
	{
		std::string owner;
		check(parseShimOwner("@echo off\nrem package=fd\n\"x.exe\" %*\n", owner) == ShimOwner::Package && owner == "fd",
			"LF line endings");
		check(parseShimOwner("@ECHO OFF\r\nrem package=fd\r\n", owner) == ShimOwner::Package, "@ECHO OFF in upper case");
		check(parseShimOwner("@echo off\r\n\"C:\\x\\rg.exe\" %*\r\n", owner) == ShimOwner::Foreign,
			"old flan shim without owner line is foreign");
		check(parseShimOwner("", owner) == ShimOwner::Foreign, "empty file is foreign");
		check(parseShimOwner("@echo off\r\nrem package=..\\evil\r\n", owner) == ShimOwner::Foreign && owner.empty(),
			"unsafe owner name is foreign");
		check(parseShimOwner("@echo off\r\nrem package=RipGrep\r\n", owner) == ShimOwner::Foreign, "uppercase owner is foreign");
		check(parseShimOwner("echo hi\r\nrem package=fd\r\n", owner) == ShimOwner::Foreign, "user script is foreign");
	}
}
