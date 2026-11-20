#pragma once

// Коды возврата flan (DESIGN.md §7.7). По ним скрипты отличают «нет сети» от «подменён архив».
enum class ExitCode : int {
	Ok = 0,
	Error = 1,											// прочая ошибка
	Usage = 2,											// неверные аргументы
	Network = 3,
	Integrity = 4,										// хэш, подпись, откат индекса, недопустимые данные репозитория
	NotFound = 5,										// пакет не найден
	Locked = 6,											// работает другой flan
};

inline int exitWith(ExitCode code) {
	return static_cast<int>(code);
}
