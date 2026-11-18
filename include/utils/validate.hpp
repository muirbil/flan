#pragma once

#include <cctype>
#include <cstddef>
#include <string>

// Имена пакетов приходят из скачанных метаданных, из скомпилированной БД и из argv.
// Всё это недоверенные данные, а попадают они в пути файлов, в имена .bat-прослоек
// и в аргументы запускаемых процессов. Поэтому единая строгая проверка на входе.

constexpr size_t MAX_NAME_LENGTH = 64;
constexpr size_t MAX_VERSION_LENGTH = 64;
constexpr size_t MAX_URL_LENGTH = 2048;

// Вместе с путём профиля должно укладываться в MAX_PATH, иначе ANSI-функции ФС откажут.
constexpr size_t MAX_RELATIVE_PATH_LENGTH = 160;
constexpr size_t MAX_PATH_SEGMENTS = 8;

// CON, PRN, AUX, NUL, COM1..9, LPT1..9 остаются устройствами с любым расширением:
// открытие "CON.txt" обращается к консоли, а не к файлу.
inline bool isReservedDeviceName(const std::string& name) {
	std::string stem = name.substr(0, name.find('.'));
	for (char& c : stem) {
		c = (char)std::toupper((unsigned char)c);
	}

	if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL") {
		return true;
	}

	if (stem.size() == 4 && stem[3] >= '1' && stem[3] <= '9' &&
		(stem.compare(0, 3, "COM") == 0 || stem.compare(0, 3, "LPT") == 0)) {
		return true;
	}

	return false;
}

// Белый список: только [A-Za-z0-9._-]. Разделители путей, "..", кавычки и
// управляющие символы отсекаются самим набором, а не отдельными проверками.
inline bool isSafeName(const std::string& name) {
	if (name.empty() || name.length() > MAX_NAME_LENGTH) {
		return false;
	}

	// Ведущие '.' и '-' дают скрытые файлы и строки, похожие на ключи командной строки.
	if (name.front() == '.' || name.front() == '-') {
		return false;
	}

	// Windows молча отбрасывает точку в конце имени, из-за чего "evil.exe." и "evil.exe"
	// указывают на один файл при разных строках проверки.
	if (name.back() == '.') {
		return false;
	}

	for (const char c : name) {
		const bool allowed =
			(c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-';

		if (!allowed) {
			return false;
		}
	}

	return !isReservedDeviceName(name);
}

// Исполняемый файл часто лежит во вложенной папке архива (ripgrep-13.0.0-.../rg.exe).
// Каждый сегмент проходит ту же проверку, что и имя, поэтому "..", буквы дисков и
// абсолютные пути невозможны по построению. На выходе разделители приведены к '\'.
inline bool normalizeRelativePath(const std::string& path, std::string& normalized) {
	normalized.clear();

	if (path.empty() || path.length() > MAX_RELATIVE_PATH_LENGTH) {
		return false;
	}

	size_t segments = 0;
	size_t start = 0;

	while (start <= path.length()) {
		size_t end = path.find_first_of("/\\", start);
		if (end == std::string::npos) {
			end = path.length();
		}

		const std::string segment = path.substr(start, end - start);
		if (!isSafeName(segment) || ++segments > MAX_PATH_SEGMENTS) {
			normalized.clear();
			return false;
		}

		if (!normalized.empty()) {
			normalized += '\\';
		}
		normalized += segment;

		start = end + 1;
	}

	return true;
}

// Версия в пути не используется, но печатается и пишется в реестр,
// поэтому достаточно отсечь управляющие символы (в том числе ESC-последовательности).
inline bool isSafeVersion(const std::string& version) {
	if (version.empty() || version.length() > MAX_VERSION_LENGTH) {
		return false;
	}

	for (const unsigned char c : version) {
		if (c < 0x20 || c == 0x7F) {
			return false;
		}
	}

	return true;
}

inline bool isHttpsUrl(const std::string& url) {
	if (url.length() > MAX_URL_LENGTH) {
		return false;
	}

	const std::string prefix = "https://";
	if (url.length() <= prefix.length()) {
		return false;
	}

	for (size_t i = 0; i < prefix.length(); i++) {
		if (std::tolower((unsigned char)url[i]) != prefix[i]) {
			return false;
		}
	}

	return true;
}

// Hex-строки из метаданных могут прийти в любом регистре.
inline bool equalsIgnoreAsciiCase(const std::string& a, const std::string& b) {
	if (a.length() != b.length()) {
		return false;
	}

	for (size_t i = 0; i < a.length(); i++) {
		if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) {
			return false;
		}
	}

	return true;
}
