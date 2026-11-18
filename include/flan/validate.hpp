#pragma once

#include <cctype>
#include <cstddef>
#include <string>
#include <vector>

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

// ---------------------------------------------------------------------------
// Поля индекса формата 2 и манифестов (DESIGN.md §5.2). Генератор и клиент
// проверяют их одним и тем же кодом.

constexpr size_t MAX_DESCRIPTION_LENGTH = 100;
constexpr size_t MAX_BINS = 8;

inline std::string toLowerAscii(std::string s) {
	for (char& c : s) {
		c = (char)std::tolower((unsigned char)c);
	}
	return s;
}

// Имена каталогов в Windows нечувствительны к регистру: "RipGrep" и "ripgrep"
// разошлись бы в индексе, но столкнулись бы на диске. Поэтому только строчные.
inline bool isSafePackageName(const std::string& name) {
	if (!isSafeName(name)) {
		return false;
	}

	for (const char c : name) {
		if (c >= 'A' && c <= 'Z') {
			return false;
		}
	}

	return true;
}

// Описание только печатается: достаточно ограничить длину и отсечь управляющие символы.
inline bool isSafeDescription(const std::string& description) {
	if (description.length() > MAX_DESCRIPTION_LENGTH) {
		return false;
	}

	for (const unsigned char c : description) {
		if (c < 0x20 || c == 0x7F) {
			return false;
		}
	}

	return true;
}

// Сверх isHttpsUrl: только печатные ASCII без пробелов (строка уходит в WinHttpCrackUrl
// и в вывод) и без «плавающих» ссылок /latest/ — их содержимое меняется,
// и хэш однажды перестал бы совпадать.
inline bool isSafePackageUrl(const std::string& url) {
	if (!isHttpsUrl(url)) {
		return false;
	}

	for (const unsigned char c : url) {
		if (c <= 0x20 || c >= 0x7F) {
			return false;
		}
	}

	return toLowerAscii(url).find("/latest/") == std::string::npos;
}

// В индексе и квитанциях пути хранятся только в каноническом виде, который выдаёт
// normalizeRelativePath. Любой другой вид ("a/b", "a\\\\b") там означает повреждение.
inline bool isCanonicalRelativePath(const std::string& path) {
	std::string normalized;
	return normalizeRelativePath(path, normalized) && normalized == path;
}

// Имя команды — последний сегмент без ".exe" (в любом регистре).
// Пустая строка — из этого пути команду не получить.
inline std::string commandNameFromBin(const std::string& bin) {
	const size_t slash = bin.find_last_of("\\/");
	std::string last = bin.substr(slash == std::string::npos ? 0 : slash + 1);

	if (last.length() <= 4 || !equalsIgnoreAsciiCase(last.substr(last.length() - 4), ".exe")) {
		return std::string();
	}

	last.resize(last.length() - 4);
	return isSafeName(last) ? last : std::string();
}

// Список bins: 1–8 канонических путей через ';', каждый оканчивается на .exe,
// имена команд не повторяются без учёта регистра — как и файлы прослоек в bin\.
// ';' в путях недопустим самим белым списком, поэтому разделитель однозначен.
inline bool parseBinList(const std::string& list, std::vector<std::string>& bins) {
	bins.clear();

	size_t start = 0;
	while (start <= list.length()) {
		size_t end = list.find(';', start);
		if (end == std::string::npos) {
			end = list.length();
		}

		const std::string bin = list.substr(start, end - start);
		const std::string command = toLowerAscii(commandNameFromBin(bin));

		if (!isCanonicalRelativePath(bin) || command.empty() || bins.size() == MAX_BINS) {
			bins.clear();
			return false;
		}

		for (const std::string& previous : bins) {
			if (toLowerAscii(commandNameFromBin(previous)) == command) {
				bins.clear();
				return false;
			}
		}

		bins.push_back(bin);
		start = end + 1;
	}

	return true;
}
