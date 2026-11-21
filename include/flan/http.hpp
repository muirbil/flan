#pragma once
#include <cstdint>
#include <string>

namespace crypto {
	class Sha256;
}

// Сетевой слой (DESIGN.md §7.2): TLS 1.2/1.3, прокси, таймауты, переадресации только
// HTTPS -> HTTPS, повторы, докачка через Range, условный запрос через If-None-Match.

enum class HttpOutcome {
	Ok,													// тело получено целиком
	NotModified,										// 304 на If-None-Match: файл назначения не тронут
	HttpError,											// сервер ответил статусом, который не повторяется
	NetworkError,										// сеть не ответила и после всех повторов
	SizeMismatch,										// тело не того размера, что ожидался, или длиннее потолка
	LocalError,											// не открыть или не записать файл назначения
};

struct HttpRequest {
	std::string url;									// только https://
	std::string destination;							// файл тела

	// Сколько байт тела уже лежит в destination: запрос пойдёт с Range: bytes=N-.
	// 0 — файл пишется с нуля.
	uint64_t resumeFrom = 0;

	// Точный размер всего файла, если известен (archive_size), иначе 0.
	uint64_t expectedSize = 0;

	// Потолок всего файла: больше этого не принимаем ни байта.
	uint64_t maxSize = 512ull * 1024 * 1024;

	// Непустой — условный запрос; на 304 файл назначения не трогается.
	std::string ifNoneMatch;

	// Хэш на лету. Если задан, он уже содержит первые resumeFrom байт файла; когда
	// загрузка начинается заново, слой сам делает reset().
	crypto::Sha256* hasher = nullptr;
};

struct HttpResult {
	HttpOutcome outcome = HttpOutcome::NetworkError;
	unsigned status = 0;								// последний HTTP-статус (0 — ответа не было)
	std::string etag;									// дословно, как прислал сервер
	uint64_t fileSize = 0;								// сколько байт в destination по итогу
	uint64_t bodyBytes = 0;								// сколько байт тела пришло по сети за вызов
	bool resumed = false;								// хотя бы раз дописали через 206
	std::string error;									// текст для пользователя, если не Ok и не NotModified
};

HttpResult httpGet(const HttpRequest& request);

// Скачать целиком в destination (через destination.part и переименование).
// Ошибку печатает сам. Для генератора и мест, где докачка не нужна.
bool downloadFile(const std::string& url, const std::string& destination);
