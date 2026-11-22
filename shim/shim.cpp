// shim.exe — прослойка flan (DESIGN.md §7.4). Без CRT: только kernel32, точка входа ShimMain,
// /GS- (инициализировать защитную метку стека некому), memset/memcpy свои.
//
// 1. Своё имя (GetModuleFileNameW) -> соседний <имя>.shim, строка target= (путь относительно bin\).
// 2. CreateProcessW(target, "<target>" + хвост GetCommandLineW() после argv[0]) — аргументы байт в байт.
// 3. Job Object с KILL_ON_JOB_CLOSE и SILENT_BREAKAWAY_OK: убили прослойку — умер и ребёнок,
//    а то, что программа запустила и оставила работать, живёт дальше.
// 4. Ctrl+C у себя игнорируется обработчиком, возвращающим TRUE. Не SetConsoleCtrlHandler(NULL, TRUE):
//    этот признак наследуется дочерним процессом, и программа тоже перестала бы реагировать на Ctrl+C.
// 5. Код выхода — тот же, что у программы.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include "flan/shim_cmdline.h"

extern "C" {
#pragma function(memset)
	void* __cdecl memset(void* destination, int value, size_t size) {
		__stosb(static_cast<unsigned char*>(destination), (unsigned char)value, size);
		return destination;
	}

#pragma function(memcpy)
	void* __cdecl memcpy(void* destination, const void* source, size_t size) {
		__movsb(static_cast<unsigned char*>(destination), static_cast<const unsigned char*>(source), size);
		return destination;
	}
}

namespace {

	constexpr DWORD MAX_LONG_PATH = 32768;
	constexpr DWORD MAX_SHIM_FILE = 64 * 1024;
	constexpr UINT SHIM_FAILED = 1;

	void* allocate(SIZE_T bytes) {
		return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
	}

	int length(const wchar_t* text) {
		return lstrlenW(text);
	}

	// Сообщение в stderr: в консоль — UTF-16, при перенаправлении — UTF-8.
	void writeError(const wchar_t* text) {
		const HANDLE handle = GetStdHandle(STD_ERROR_HANDLE);
		if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
			return;
		}
		DWORD written = 0;
		DWORD mode = 0;
		if (GetConsoleMode(handle, &mode)) {
			WriteConsoleW(handle, text, (DWORD)length(text), &written, NULL);
			return;
		}
		const int size = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
		char* utf8 = static_cast<char*>(allocate(size > 0 ? size : 1));
		if (utf8 != NULL && size > 1 && WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, size, NULL, NULL) == size) {
			WriteFile(handle, utf8, (DWORD)(size - 1), &written, NULL);
		}
	}

	[[noreturn]] void fail(const wchar_t* what, const wchar_t* detail, DWORD code) {
		writeError(L"flan shim: ");
		writeError(what);
		if (detail != NULL) {
			writeError(L" ");
			writeError(detail);
		}
		if (code != 0) {
			wchar_t number[16];
			int i = 15;
			number[i] = L'\0';
			do {
				number[--i] = (wchar_t)(L'0' + code % 10);
				code /= 10;
			} while (code != 0 && i > 0);
			writeError(L" (code ");
			writeError(number + i);
			writeError(L")");
		}
		writeError(L"\r\n");
		ExitProcess(SHIM_FAILED);
	}

	BOOL WINAPI onConsoleControl(DWORD type) {
		// Ctrl+C и Ctrl+Break получает и обрабатывает сама программа; прослойка ждёт её кода выхода.
		return type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT;
	}

	bool endsWithExe(const wchar_t* path, int size) {
		return size >= 4 && lstrcmpiW(path + size - 4, L".exe") == 0;
	}

	// Значение target= из содержимого .shim (UTF-8, строки через LF или CRLF, BOM допустим).
	wchar_t* parseTarget(const char* text, DWORD size) {
		DWORD pos = 0;
		if (size >= 3 && (unsigned char)text[0] == 0xEF && (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF) {
			pos = 3;
		}

		while (pos < size) {
			DWORD end = pos;
			while (end < size && text[end] != '\n') {
				end++;
			}
			DWORD lineEnd = end;
			if (lineEnd > pos && text[lineEnd - 1] == '\r') {
				lineEnd--;
			}

			const char key[] = "target=";
			const DWORD keyLength = sizeof(key) - 1;
			bool match = lineEnd - pos > keyLength;
			for (DWORD k = 0; match && k < keyLength; k++) {
				match = text[pos + k] == key[k];
			}
			if (match) {
				const int bytes = (int)(lineEnd - pos - keyLength);
				const int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text + pos + keyLength, bytes, NULL, 0);
				if (chars <= 0) {
					return NULL;
				}
				wchar_t* value = static_cast<wchar_t*>(allocate(((SIZE_T)chars + 1) * sizeof(wchar_t)));
				if (value == NULL ||
					MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text + pos + keyLength, bytes, value, chars) != chars) {
					return NULL;
				}
				return value;
			}
			pos = end + 1;
		}
		return NULL;
	}
}

extern "C" void ShimMain() {
	// 1. Своё имя и соседний .shim.
	wchar_t* self = static_cast<wchar_t*>(allocate(MAX_LONG_PATH * sizeof(wchar_t)));
	if (self == NULL) {
		fail(L"out of memory", NULL, 0);
	}
	const DWORD selfLength = GetModuleFileNameW(NULL, self, MAX_LONG_PATH);
	if (selfLength == 0 || selfLength >= MAX_LONG_PATH) {
		fail(L"cannot get its own path", NULL, GetLastError());
	}

	wchar_t* shimFile = static_cast<wchar_t*>(allocate((MAX_LONG_PATH + 8) * sizeof(wchar_t)));
	if (shimFile == NULL) {
		fail(L"out of memory", NULL, 0);
	}
	lstrcpynW(shimFile, self, (int)MAX_LONG_PATH);
	const int stem = endsWithExe(self, (int)selfLength) ? (int)selfLength - 4 : (int)selfLength;
	lstrcpyW(shimFile + stem, L".shim");

	const HANDLE file = CreateFileW(shimFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		fail(L"cannot open", shimFile, GetLastError());
	}
	char* text = static_cast<char*>(allocate(MAX_SHIM_FILE));
	DWORD textSize = 0;
	if (text == NULL || !ReadFile(file, text, MAX_SHIM_FILE, &textSize, NULL)) {
		fail(L"cannot read", shimFile, GetLastError());
	}
	CloseHandle(file);

	const wchar_t* target = parseTarget(text, textSize);
	if (target == NULL) {
		fail(L"no valid target= line in", shimFile, 0);
	}

	// 2. Полный путь программы: target относителен каталогу самой прослойки (bin\), поэтому
	//    перенос FLAN_HOME ничего не ломает. Абсолютный target тоже допустим.
	wchar_t* combined = static_cast<wchar_t*>(allocate((MAX_LONG_PATH * 2 + 2) * sizeof(wchar_t)));
	wchar_t* program = static_cast<wchar_t*>(allocate(MAX_LONG_PATH * sizeof(wchar_t)));
	if (combined == NULL || program == NULL) {
		fail(L"out of memory", NULL, 0);
	}
	const bool absolute = target[0] == L'\\' || (target[0] != L'\0' && target[1] == L':');
	if (absolute) {
		lstrcpynW(combined, target, (int)MAX_LONG_PATH);
	}
	else {
		lstrcpynW(combined, self, (int)MAX_LONG_PATH);
		int slash = (int)selfLength;
		while (slash > 0 && combined[slash - 1] != L'\\') {
			slash--;
		}
		combined[slash] = L'\0';
		lstrcpynW(combined + slash, target, (int)MAX_LONG_PATH);
	}
	const DWORD programLength = GetFullPathNameW(combined, MAX_LONG_PATH, program, NULL);
	if (programLength == 0 || programLength >= MAX_LONG_PATH) {
		fail(L"bad target path in", shimFile, GetLastError());
	}

	// 3. Командная строка: "<программа>" + хвост своей строки после argv[0], как есть.
	const wchar_t* tail = shimSkipArgv0(GetCommandLineW());
	const int tailLength = length(tail);
	wchar_t* commandLine = static_cast<wchar_t*>(allocate(((SIZE_T)programLength + tailLength + 3) * sizeof(wchar_t)));
	if (commandLine == NULL) {
		fail(L"out of memory", NULL, 0);
	}
	commandLine[0] = L'"';
	lstrcpyW(commandLine + 1, program);
	commandLine[programLength + 1] = L'"';
	lstrcpyW(commandLine + programLength + 2, tail);

	// 4. Задание: ребёнок умирает вместе с прослойкой; его собственные потомки в задание не входят.
	const HANDLE job = CreateJobObjectW(NULL, NULL);
	if (job != NULL) {
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
		memset(&limits, 0, sizeof(limits));
		limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
		SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
	}

	STARTUPINFOW startup;
	memset(&startup, 0, sizeof(startup));
	startup.cb = sizeof(startup);
	PROCESS_INFORMATION process;
	memset(&process, 0, sizeof(process));

	if (!CreateProcessW(program, commandLine, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &startup, &process)) {
		fail(L"cannot start", program, GetLastError());
	}

	// Не удалось включить в задание (Windows 7: прослойка уже в чужом задании) — работаем без него.
	if (job != NULL) {
		AssignProcessToJobObject(job, process.hProcess);
	}
	SetConsoleCtrlHandler(onConsoleControl, TRUE);
	ResumeThread(process.hThread);
	CloseHandle(process.hThread);

	// 5. Тот же код выхода.
	WaitForSingleObject(process.hProcess, INFINITE);
	DWORD exitCode = SHIM_FAILED;
	GetExitCodeProcess(process.hProcess, &exitCode);
	ExitProcess(exitCode);
}
