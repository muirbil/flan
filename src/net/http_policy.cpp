#include "flan/http_policy.hpp"
#include <cctype>

namespace {

	// Коды из winhttp.h — здесь числами, чтобы решения не тянули за собой WinHTTP.
	constexpr unsigned long WINHTTP_TIMEOUT = 12002;
	constexpr unsigned long WINHTTP_INVALID_URL = 12005;
	constexpr unsigned long WINHTTP_UNRECOGNIZED_SCHEME = 12006;
	constexpr unsigned long WINHTTP_LOGIN_FAILURE = 12015;
	constexpr unsigned long WINHTTP_CLIENT_AUTH_CERT_NEEDED = 12044;
	constexpr unsigned long WINHTTP_REDIRECT_FAILED = 12156;
	constexpr unsigned long WINHTTP_SECURE_CHANNEL_ERROR = 12157;
	constexpr unsigned long WINHTTP_SECURE_FAILURE = 12175;

	bool startsWithIgnoreCase(const std::string& text, const char* prefix) {
		for (size_t i = 0; prefix[i] != '\0'; i++) {
			if (i >= text.size() || std::tolower((unsigned char)text[i]) != std::tolower((unsigned char)prefix[i])) {
				return false;
			}
		}
		return true;
	}

	std::string trim(const std::string& text) {
		size_t begin = 0;
		size_t end = text.size();
		while (begin < end && (text[begin] == ' ' || text[begin] == '\t')) begin++;
		while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t')) end--;
		return text.substr(begin, end - begin);
	}
}

Retry classifyStatus(unsigned status) {
	if (status == 408 || status == 429 || (status >= 500 && status <= 599)) {
		return Retry::Yes;
	}
	return Retry::No;
}

Retry classifyNetworkError(unsigned long error) {
	switch (error) {
	case WINHTTP_INVALID_URL:
	case WINHTTP_UNRECOGNIZED_SCHEME:
	case WINHTTP_LOGIN_FAILURE:
	case WINHTTP_CLIENT_AUTH_CERT_NEEDED:
	case WINHTTP_REDIRECT_FAILED:
	case WINHTTP_SECURE_CHANNEL_ERROR:
	case WINHTTP_SECURE_FAILURE:
		return Retry::No;
	case WINHTTP_TIMEOUT:
	default:
		// Прочее (обрыв, отказ в соединении, DNS, неожиданный ответ) — сеть, которая
		// на медленном канале «медленно, но не мёртво»: повторяем.
		return Retry::Yes;
	}
}

unsigned retryDelaySeconds(unsigned retryIndex, const std::string& retryAfter) {
	static const unsigned DELAYS[MAX_RETRIES] = { 2, 5, 10 };

	// Retry-After бывает и датой — её не разбираем и ждём по своему расписанию.
	uint64_t seconds = 0;
	if (parseUint64(trim(retryAfter), seconds)) {
		return seconds > MAX_RETRY_AFTER_SECONDS ? MAX_RETRY_AFTER_SECONDS : (unsigned)seconds;
	}

	return DELAYS[retryIndex < MAX_RETRIES ? retryIndex : MAX_RETRIES - 1];
}

bool parseUint64(const std::string& text, uint64_t& value) {
	if (text.empty() || text.size() > 20) {
		return false;
	}

	uint64_t result = 0;
	for (const char c : text) {
		if (c < '0' || c > '9') {
			return false;
		}
		const uint64_t digit = (uint64_t)(c - '0');
		if (result > (UINT64_MAX - digit) / 10) {
			return false;
		}
		result = result * 10 + digit;
	}

	value = result;
	return true;
}

bool parseContentRange(const std::string& value, ContentRange& out) {
	out = ContentRange();
	const std::string text = trim(value);
	if (!startsWithIgnoreCase(text, "bytes ")) {
		return false;
	}

	const std::string spec = trim(text.substr(6));
	const size_t slash = spec.find('/');
	if (slash == std::string::npos || !parseUint64(spec.substr(slash + 1), out.total)) {
		return false;
	}

	const std::string range = spec.substr(0, slash);
	if (range == "*") {
		out.unsatisfied = true;
		return true;
	}

	const size_t dash = range.find('-');
	return dash != std::string::npos &&
		parseUint64(range.substr(0, dash), out.first) &&
		parseUint64(range.substr(dash + 1), out.last) &&
		out.first <= out.last && out.last < out.total;
}

BodyAction decideBody(unsigned status, uint64_t requestedFrom, const std::string& contentRange, uint64_t expectedSize) {
	if (status == 200) {
		// И без Range, и в ответ на Range (сервер его не понял, как codeload.github.com):
		// это тело целиком, пишется с нуля.
		return BodyAction::Replace;
	}

	if (status == 206) {
		if (requestedFrom == 0) {
			return BodyAction::Unexpected;
		}

		ContentRange range;
		if (!parseContentRange(contentRange, range) || range.unsatisfied ||
			range.first != requestedFrom || range.last + 1 != range.total ||
			(expectedSize != 0 && range.total != expectedSize)) {
			return BodyAction::RestartWithoutRange;
		}
		return BodyAction::Append;
	}

	if (status == 416) {
		return requestedFrom > 0 ? BodyAction::RestartWithoutRange : BodyAction::Unexpected;
	}

	return BodyAction::Unexpected;
}
