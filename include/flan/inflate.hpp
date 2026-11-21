#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Распаковка сжатого тела индекса (raw deflate, DESIGN.md §6.1, шаг 4). Результат обязан
// быть ровно rawSize байт, а вход — израсходован целиком: длиннее, короче или с хвостом
// после конца потока — повреждение. Потолок rawSize проверяет вызывающий.
bool inflateRawExact(const uint8_t* data, size_t size, size_t rawSize, std::vector<uint8_t>& out, std::string& error);
