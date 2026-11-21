#pragma once

#include <cstdint>
#include <string>
#include "core/paths.hpp"

// state\index.state (DESIGN.md §7.1, §7.2): откуда взят принятый индекс, его ETag и
// generated_at. ETag уходит в If-None-Match, только если источник тот же.
// generated_at понадобится защите от отката на этапе 4.
struct IndexState {
	std::string source;									// URL или путь, откуда взят индекс
	std::string etag;									// дословно; пусто — сервер не прислал
	uint64_t generatedAt = 0;
};

std::string formatIndexState(const IndexState& state);

// Повреждённое состояние — не ошибка: тогда просто нет условного запроса.
bool parseIndexState(const std::string& text, IndexState& out);

bool loadIndexState(const FlanPaths& paths, IndexState& out);
bool saveIndexState(const FlanPaths& paths, const IndexState& state);
