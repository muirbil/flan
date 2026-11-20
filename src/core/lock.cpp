#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "core/lock.hpp"
#include "flan/strings.hpp"
#include <iostream>

namespace {
	constexpr DWORD RETRY_INTERVAL_MS = 200;
}

FlanLock::~FlanLock() {
	if (handle_ != nullptr) {
		CloseHandle(handle_);
	}
}

FlanLock::Result FlanLock::acquire(const std::string& path, unsigned timeoutMs) {
	const std::wstring widePath = s2ws(path);
	const ULONGLONG deadline = GetTickCount64() + timeoutMs;
	bool announced = false;

	for (;;) {
		// Нулевой share mode: пока файл открыт, второй flan получает ERROR_SHARING_VIOLATION.
		// FILE_FLAG_DELETE_ON_CLOSE: файл исчезает, как только закрыт последний дескриптор, —
		// в том числе когда процесс убит, — поэтому «зависшей» блокировки не бывает.
		const HANDLE handle = CreateFileW(widePath.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, 0, NULL,
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);

		if (handle != INVALID_HANDLE_VALUE) {
			handle_ = handle;
			return Result::Acquired;
		}

		// ERROR_ACCESS_DENIED приходит и тогда, когда предыдущий flan только что закрыл файл
		// и система его ещё удаляет: это тоже «занято», а не настоящая ошибка доступа.
		const DWORD error = GetLastError();
		if (error != ERROR_SHARING_VIOLATION && error != ERROR_ACCESS_DENIED) {
			std::cerr << "Error: cannot open the lock file " << path << " (code " << error << ")." << std::endl;
			return Result::Failed;
		}

		if (GetTickCount64() >= deadline) {
			return Result::Busy;
		}

		if (!announced) {
			std::cerr << "Waiting for another flan process to finish..." << std::endl;
			announced = true;
		}

		Sleep(RETRY_INTERVAL_MS);
	}
}
