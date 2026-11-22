#pragma once

#include <string>

// Вывод без <iostream> (DESIGN.md §7.10): в консоль — WriteConsoleW (UTF-16, кодовая страница
// консоли не важна и не меняется), при перенаправлении — WriteFile с UTF-8 как есть.
// Строки внутри flan — UTF-8. Буфер сбрасывается на con::endl и con::flush.
namespace con {

	class Stream {
	public:
		explicit Stream(unsigned long which);			// STD_OUTPUT_HANDLE или STD_ERROR_HANDLE
		~Stream();
		Stream(const Stream&) = delete;
		Stream& operator=(const Stream&) = delete;

		Stream& operator<<(const char* text);
		Stream& operator<<(const std::string& text);
		Stream& operator<<(char c);
		Stream& operator<<(int value);
		Stream& operator<<(unsigned int value);
		Stream& operator<<(long value);
		Stream& operator<<(unsigned long value);
		Stream& operator<<(long long value);
		Stream& operator<<(unsigned long long value);
		Stream& operator<<(Stream& (*manipulator)(Stream&));

		void flush();

		// Консоль ли это (GetConsoleMode): прогресс рисуется только в консоли (§7.2).
		bool isConsole() const;

	private:
		unsigned long which_;
		std::string buffer_;
	};

	extern Stream out;
	extern Stream err;

	// Конец строки и сброс буфера.
	Stream& endl(Stream& stream);
	Stream& flush(Stream& stream);
}
