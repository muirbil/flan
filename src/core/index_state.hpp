#pragma once

#include <cstdint>
#include <string>
#include "core/paths.hpp"

// state\index.state (DESIGN.md §7.1, §7.2): откуда взят принятый индекс, его ETag,
// generated_at и номер ключа. ETag уходит в If-None-Match, только если источник тот же;
// generated_at и key_id — защита от отката (§6.1, шаг 6).
struct IndexState {
	std::string source;									// URL или путь, откуда взят индекс
	std::string etag;									// дословно; пусто — сервер не прислал
	uint64_t generatedAt = 0;
	uint8_t keyId = 0;									// 0 — индекс этапов 1–3 без подписи или не записан
};

// Последний принятый индекс: номер ключа и generated_at.
struct AcceptedIndex {
	uint8_t keyId = 0;
	uint64_t generatedAt = 0;
};

// Из двух сведений о последнем принятом (index.state и сам state\index.flan) — более позднее:
// с бо́льшим номером ключа, а при равных — с бо́льшим generated_at. Удаление одного из файлов
// счётчик не сбрасывает, а смена ключа не тянет за собой «замороженный» generated_at старого.
AcceptedIndex laterAccepted(const AcceptedIndex& a, const AcceptedIndex& b);

enum class RollbackVerdict {
	Accept,
	RetiredKey,											// ключ старше последнего принятого
	Rollback,											// тот же ключ, generated_at меньше
};

// Шаг 6 §6.1: новый ключ — принять без сравнения времени; старый — отказ; тот же — время не убывает.
RollbackVerdict checkRollback(const AcceptedIndex& last, const AcceptedIndex& received);

std::string formatIndexState(const IndexState& state);

// Повреждённое состояние — не ошибка: тогда просто нет условного запроса.
bool parseIndexState(const std::string& text, IndexState& out);

bool loadIndexState(const FlanPaths& paths, IndexState& out);
bool saveIndexState(const FlanPaths& paths, const IndexState& state);
