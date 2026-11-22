#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "test.hpp"
#include "flan/console.hpp"
#include <string>

// Вывод при перенаправлении (DESIGN.md §7.10): UTF-8 байт в байт, концы строк — CRLF.
// stderr тестов подменяется анонимным каналом на время проверки.
void runConsoleTests() {
	beginSuite("console");

	HANDLE readEnd = NULL;
	HANDLE writeEnd = NULL;
	if (!CreatePipe(&readEnd, &writeEnd, NULL, 1 << 16)) {
		check(false, "CreatePipe");
		return;
	}

	const HANDLE saved = GetStdHandle(STD_ERROR_HANDLE);
	SetStdHandle(STD_ERROR_HANDLE, writeEnd);
	const bool console = con::err.isConsole();
	con::err << "Проверка " << 42 << ' ' << 18446744073709551615ull << con::endl;
	con::err << "без перевода строки" << con::flush;
	con::err << "-" << -7 << con::endl;
	SetStdHandle(STD_ERROR_HANDLE, saved);
	CloseHandle(writeEnd);

	std::string received;
	char buffer[512];
	DWORD got = 0;
	while (ReadFile(readEnd, buffer, sizeof(buffer), &got, NULL) && got > 0) {
		received.append(buffer, got);
	}
	CloseHandle(readEnd);

	check(!console, "a pipe is not a console");
	check(received == "Проверка 42 18446744073709551615\r\nбез перевода строки--7\r\n", "redirected output: UTF-8 and CRLF", received);
}
