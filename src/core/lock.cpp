#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "core/lock.hpp"
#include "flan/fs.hpp"
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
	const std::wstring widePath = extendedPath(path);
	const ULONGLONG deadline = GetTickCount64() + timeoutMs;
	bool announced = false;

	for (;;) {
		// Нулевой share mode: пока файл открыт, второй flan получает ERROR_SHARING_VIOLATION.
		// Файл не удаляется при закрытии (без FILE_FLAG_DELETE_ON_CLOSE): иначе в окне
		// «удаление ещё не завершено» система отвечает ERROR_ACCESS_DENIED, и «занято»
		// становится неотличимо от настоящей ошибки прав.
		const HANDLE handle = CreateFileW(widePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL,
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (handle != INVALID_HANDLE_VALUE) {
			handle_ = handle;
			return Result::Acquired;
		}

		const DWORD error = GetLastError();
		if (error == ERROR_ACCESS_DENIED) {
			std::cerr << "Error: access denied to the lock file " << path
				<< ". Check the permissions and the read-only attribute of this file and its folder." << std::endl;
			return Result::Failed;
		}

		if (error != ERROR_SHARING_VIOLATION) {
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
