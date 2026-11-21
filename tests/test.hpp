#pragma once

#include <string>

// Минимальный каркас тестов: без сторонних библиотек, итог — код возврата процесса.

// Начинает именованный набор проверок (для вывода).
void beginSuite(const char* name);

// Одна проверка. Провалы печатаются всегда, успехи — только с ключом -v.
void check(bool ok, const std::string& label, const std::string& detail = std::string());

// Наборы. Каждый живёт в своём файле.
void runValidateTests();
void runIndexTests();
void runReceiptTests();
void runCryptoTests();
