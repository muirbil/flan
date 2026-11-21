#include "test.hpp"
#include "flan/http_policy.hpp"
#include <string>

// Решения сетевого слоя (DESIGN.md §7.2) без сети: что повторять, как ждать,
// как понимать ответ на запрос с Range.

namespace {

	const char* actionName(BodyAction action) {
		switch (action) {
		case BodyAction::Append: return "Append";
		case BodyAction::Replace: return "Replace";
		case BodyAction::RestartWithoutRange: return "RestartWithoutRange";
		default: return "Unexpected";
		}
	}

	void expectAction(const char* label, unsigned status, uint64_t from, const char* range, uint64_t expected, BodyAction want) {
		const BodyAction got = decideBody(status, from, range, expected);
		check(got == want, label, std::string("got ") + actionName(got));
	}
}

void runHttpTests() {
	beginSuite("http: retry");
	for (const unsigned status : { 408u, 429u, 500u, 502u, 503u, 599u }) {
		check(classifyStatus(status) == Retry::Yes, "status " + std::to_string(status) + " is retried");
	}
	for (const unsigned status : { 301u, 400u, 401u, 403u, 404u, 410u, 600u }) {
		check(classifyStatus(status) == Retry::No, "status " + std::to_string(status) + " is not retried");
	}
	for (const unsigned long error : { 12002ul, 12007ul, 12029ul, 12030ul, 12152ul, 99999ul }) {
		check(classifyNetworkError(error) == Retry::Yes, "network error " + std::to_string(error) + " is retried");
	}
	for (const unsigned long error : { 12005ul, 12006ul, 12156ul, 12157ul, 12175ul }) {
		check(classifyNetworkError(error) == Retry::No, "network error " + std::to_string(error) + " is not retried");
	}

	beginSuite("http: delays");
	check(retryDelaySeconds(0, "") == 2 && retryDelaySeconds(1, "") == 5 && retryDelaySeconds(2, "") == 10, "2/5/10 s");
	check(retryDelaySeconds(7, "") == 10, "beyond the schedule stays at 10 s");
	check(retryDelaySeconds(0, "30") == 30, "Retry-After: 30");
	check(retryDelaySeconds(0, " 7 ") == 7, "Retry-After with spaces");
	check(retryDelaySeconds(0, "3600") == 60, "Retry-After capped at 60 s");
	check(retryDelaySeconds(1, "Wed, 21 Oct 2015 07:28:00 GMT") == 5, "Retry-After date is ignored");
	check(retryDelaySeconds(0, "-3") == 2, "negative Retry-After is ignored");

	beginSuite("http: numbers and ranges");
	uint64_t n = 0;
	check(parseUint64("0", n) && n == 0, "0");
	check(parseUint64("18446744073709551615", n) && n == UINT64_MAX, "UINT64_MAX");
	check(!parseUint64("18446744073709551616", n), "overflow denied");
	check(!parseUint64("", n) && !parseUint64("-1", n) && !parseUint64("1 ", n) && !parseUint64("0x10", n), "malformed denied");

	ContentRange r;
	check(parseContentRange("bytes 1000000-1789610/1789611", r) && !r.unsatisfied && r.first == 1000000 && r.last == 1789610 && r.total == 1789611,
		"GitHub 206 Content-Range");
	check(parseContentRange("bytes */1789611", r) && r.unsatisfied && r.total == 1789611, "GitHub 416 Content-Range");
	check(parseContentRange("BYTES 0-0/1", r) && r.first == 0 && r.last == 0, "case-insensitive unit");
	check(!parseContentRange("bytes 5-4/10", r), "first > last denied");
	check(!parseContentRange("bytes 0-10/10", r), "last beyond total denied");
	check(!parseContentRange("bytes 0-9/*", r), "unknown total denied");
	check(!parseContentRange("items 0-1/2", r), "other unit denied");
	check(!parseContentRange("bytes 1-2", r) && !parseContentRange("", r), "malformed denied");
	check(!parseContentRange("bytes 0-1/99999999999999999999999", r), "overflowing total denied");

	beginSuite("http: body decisions");
	expectAction("200 without Range", 200, 0, "", 0, BodyAction::Replace);
	expectAction("200 to a Range request (server ignored it)", 200, 500, "", 1000, BodyAction::Replace);
	expectAction("206 with the requested range", 206, 500, "bytes 500-999/1000", 1000, BodyAction::Append);
	expectAction("206 with the requested range, size unknown", 206, 500, "bytes 500-999/1000", 0, BodyAction::Append);
	expectAction("206 starting elsewhere", 206, 500, "bytes 400-999/1000", 1000, BodyAction::RestartWithoutRange);
	expectAction("206 not up to the end", 206, 500, "bytes 500-998/1000", 1000, BodyAction::RestartWithoutRange);
	expectAction("206 for a file of another size", 206, 500, "bytes 500-1999/2000", 1000, BodyAction::RestartWithoutRange);
	expectAction("206 with a garbled Content-Range", 206, 500, "garbage", 1000, BodyAction::RestartWithoutRange);
	expectAction("206 to a request without Range", 206, 0, "bytes 0-9/10", 10, BodyAction::Unexpected);
	expectAction("416 to a Range request", 416, 500, "bytes */1000", 1000, BodyAction::RestartWithoutRange);
	expectAction("416 without Range", 416, 0, "bytes */1000", 1000, BodyAction::Unexpected);
	expectAction("404", 404, 500, "", 1000, BodyAction::Unexpected);
}
