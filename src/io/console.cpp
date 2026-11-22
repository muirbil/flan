#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "flan/console.hpp"
#include "flan/strings.hpp"

namespace con {

	Stream out(STD_OUTPUT_HANDLE);
	Stream err(STD_ERROR_HANDLE);

	Stream::Stream(unsigned long which) : which_(which) {
	}

	Stream::~Stream() {
		flush();
	}

	Stream& Stream::operator<<(const char* text) {
		buffer_ += text ? text : "";
		return *this;
	}

	Stream& Stream::operator<<(const std::string& text) {
		buffer_ += text;
		return *this;
	}

	Stream& Stream::operator<<(char c) {
		buffer_ += c;
		return *this;
	}

	Stream& Stream::operator<<(int value) {
		buffer_ += std::to_string(value);
		return *this;
	}

	Stream& Stream::operator<<(unsigned int value) {
		buffer_ += std::to_string(value);
		return *this;
	}

	Stream& Stream::operator<<(long value) {
		buffer_ += std::to_string(value);
		return *this;
	}

	Stream& Stream::operator<<(unsigned long value) {
		buffer_ += std::to_string(value);
		return *this;
	}

	Stream& Stream::operator<<(long long value) {
		buffer_ += std::to_string(value);
		return *this;
	}

	Stream& Stream::operator<<(unsigned long long value) {
		buffer_ += std::to_string(value);
		return *this;
	}

	Stream& Stream::operator<<(Stream& (*manipulator)(Stream&)) {
		return manipulator(*this);
	}

	bool Stream::isConsole() const {
		DWORD mode = 0;
		return GetConsoleMode(GetStdHandle(which_), &mode) != 0;
	}

	void Stream::flush() {
		if (buffer_.empty()) {
			return;
		}

		const HANDLE handle = GetStdHandle(which_);
		if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
			buffer_.clear();
			return;
		}

		DWORD mode = 0;
		if (GetConsoleMode(handle, &mode)) {
			// Консоль: UTF-16 через WriteConsoleW, частями — старые консоли не любят длинных вызовов.
			const std::wstring wide = s2ws(buffer_);
			size_t done = 0;
			while (done < wide.size()) {
				const DWORD chunk = (DWORD)((wide.size() - done) > 8192 ? 8192 : (wide.size() - done));
				DWORD written = 0;
				if (!WriteConsoleW(handle, wide.data() + done, chunk, &written, NULL) || written == 0) {
					break;
				}
				done += written;
			}
		}
		else {
			// Файл или канал: байты UTF-8 как есть, концы строк — CRLF, как писал прежний
			// std::cout в текстовом режиме.
			std::string bytes;
			bytes.reserve(buffer_.size() + buffer_.size() / 16);
			for (const char c : buffer_) {
				if (c == '\n') {
					bytes += '\r';
				}
				bytes += c;
			}

			size_t done = 0;
			while (done < bytes.size()) {
				DWORD written = 0;
				if (!WriteFile(handle, bytes.data() + done, (DWORD)(bytes.size() - done), &written, NULL) || written == 0) {
					break;
				}
				done += written;
			}
		}
		buffer_.clear();
	}

	Stream& endl(Stream& stream) {
		stream << '\n';
		stream.flush();
		return stream;
	}

	Stream& flush(Stream& stream) {
		stream.flush();
		return stream;
	}
}
