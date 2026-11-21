#pragma once

#include <cstdint>
#include <string>

// Решения сетевого слоя без самой сети (DESIGN.md §7.2): что повторять, сколько ждать,
// как понимать ответ на запрос с Range. Отдельно от WinHTTP — чтобы их проверяли тесты.

// 1 + 3 попытки, паузы 2/5/10 с.
constexpr unsigned MAX_RETRIES = 3;

// Retry-After учитывается, но не дольше этого.
constexpr unsigned MAX_RETRY_AFTER_SECONDS = 60;

enum class Retry {
	No,
	Yes,
};

// Статус, который не является ответом с телом (200/206/416) и не 304:
// 408, 429 и 5xx повторяются, прочие — сразу ошибка.
Retry classifyStatus(unsigned status);

// Код ошибки WinHTTP (ERROR_WINHTTP_*): сетевые сбои и таймауты повторяются,
// ошибки TLS, сертификата, URL и отказ в переадресации — нет.
Retry classifyNetworkError(unsigned long error);

// Пауза перед повтором с номером retryIndex (0, 1, 2): 2/5/10 с. Retry-After в секундах,
// если сервер его прислал, заменяет её, но не больше 60 с.
unsigned retryDelaySeconds(unsigned retryIndex, const std::string& retryAfter);

struct ContentRange {
	bool unsatisfied = false;							// "bytes */total" — так отвечают на 416
	uint64_t first = 0;
	uint64_t last = 0;
	uint64_t total = 0;
};

bool parseContentRange(const std::string& value, ContentRange& out);

// Десятичное число без знака и пробелов, без переполнения.
bool parseUint64(const std::string& text, uint64_t& value);

enum class BodyAction {
	Append,												// 206 с нужным диапазоном: дописать к уже скачанному
	Replace,											// 200: тело целиком, писать с нуля
	RestartWithoutRange,								// 416 или чужой диапазон: выбросить скачанное, запросить без Range
	Unexpected,											// такого ответа на такой запрос быть не должно
};

// requestedFrom — с какого байта просили (0 — без Range); expectedSize — известный полный
// размер файла (archive_size) или 0.
BodyAction decideBody(unsigned status, uint64_t requestedFrom, const std::string& contentRange, uint64_t expectedSize);
