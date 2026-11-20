#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "core/paths.hpp"

// Квитанция установки apps\<name>\receipt (DESIGN.md §7.5): key=value в UTF-8, без JSON.
// Точка фиксации транзакции: пока её нет, установка не состоялась.
struct Receipt {
	std::string name;
	std::string version;
	std::string dir;									// фактический каталог версии; пути берутся только отсюда
	uint8_t arch = 0;									// ARCH_*
	std::string sha256;									// hex в нижнем регистре — идентичность сборки
	std::vector<std::string> bins;						// канонические пути
	std::string installedAt;							// 2026-11-21T12:00:00Z
};

std::string formatReceipt(const Receipt& receipt);

// Каждое значение проходит ту же проверку, что и при записи; хоть одно не прошло —
// квитанция повреждена, и пути из неё не берутся.
bool parseReceipt(const std::string& text, Receipt& out, std::string& error);

enum class ReceiptState {
	Missing,
	Valid,
	Corrupt,
};

std::string receiptPath(const FlanPaths& paths, const std::string& name);

// name — уже проверенное имя пакета; квитанция с другим name внутри считается повреждённой.
ReceiptState readReceipt(const FlanPaths& paths, const std::string& name, Receipt& out, std::string& error);
bool writeReceipt(const FlanPaths& paths, const Receipt& receipt);

std::string currentUtcTimestamp();
