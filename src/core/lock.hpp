#pragma once

#include <string>

// Сколько второй flan ждёт первого, прежде чем выйти с кодом 6 (DESIGN.md §7.6).
constexpr unsigned LOCK_TIMEOUT_MS = 10000;

// Файловая блокировка %FLAN_HOME%\lock: одновременно состояние меняет только один flan.
// Файл лежит постоянно; блокировка — это его открытие с нулевым share mode. Снимается
// в деструкторе, а при падении процесса — самой системой вместе с дескриптором.
class FlanLock {
public:
	enum class Result {
		Acquired,
		Busy,											// держит другой flan, время ожидания вышло
		Failed,											// файл не открыть: нет прав или другая ошибка; сообщение уже выведено
	};

	FlanLock() = default;
	~FlanLock();
	FlanLock(const FlanLock&) = delete;
	FlanLock& operator=(const FlanLock&) = delete;

	Result acquire(const std::string& path, unsigned timeoutMs);

private:
	void* handle_ = nullptr;							// HANDLE; <windows.h> в заголовок не тянем
};
