#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "test.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {
	int passed = 0;
	int failed = 0;
	bool verbose = false;
	const char* currentSuite = "";
}

void beginSuite(const char* name) {
	currentSuite = name;
	if (verbose) {
		std::printf("\n[%s]\n", name);
	}
}

void check(bool ok, const std::string& label, const std::string& detail) {
	if (ok) {
		passed++;
	}
	else {
		failed++;
	}

	if (!ok || verbose) {
		std::printf("%s  %s: %s%s%s\n", ok ? "PASS" : "FAIL", currentSuite, label.c_str(),
			detail.empty() ? "" : "  -- ", detail.c_str());
	}
}

// Служебные режимы для сквозных проверок shim.exe (DESIGN.md §7.4); тестов они не запускают.
namespace {

	BOOL WINAPI onCtrl(DWORD type) {
		if (type == CTRL_C_EVENT) {
			std::printf("child: Ctrl+C received\n");
			std::fflush(stdout);
			ExitProcess(130);
		}
		return FALSE;
	}

	int runHelper(int argc, char* argv[]) {
		const std::string mode = argv[1];

		// --print-cmdline <код>: командная строка как есть (UTF-8) и выход с этим кодом.
		if (mode == "--print-cmdline") {
			const wchar_t* line = GetCommandLineW();
			const int size = WideCharToMultiByte(CP_UTF8, 0, line, -1, NULL, 0, NULL, NULL);
			std::string utf8(size > 0 ? size - 1 : 0, '\0');
			if (size > 1) {
				WideCharToMultiByte(CP_UTF8, 0, line, -1, &utf8[0], size, NULL, NULL);
			}
			std::printf("cmdline: %s\n", utf8.c_str());
			return argc > 2 ? std::atoi(argv[2]) : 0;
		}

		// --wait-ctrl: ждать Ctrl+C до 15 с.
		if (mode == "--wait-ctrl") {
			SetConsoleCtrlHandler(onCtrl, TRUE);
			std::printf("child: waiting for Ctrl+C\n");
			std::fflush(stdout);
			Sleep(15000);
			std::printf("child: no Ctrl+C within 15 s\n");
			return 0;
		}

		// --spawn-ignoring <exe>: SetConsoleCtrlHandler(NULL, TRUE), затем <exe> --wait-ctrl.
		// Показывает, наследует ли ребёнок признак «игнорировать Ctrl+C».
		// --spawn-detached <exe> <файл>: запустить <exe> --touch-later <файл> и сразу выйти.
		if ((mode == "--spawn-ignoring" || mode == "--spawn-detached") && argc > 2) {
			if (mode == "--spawn-ignoring") {
				SetConsoleCtrlHandler(NULL, TRUE);
			}
			std::string line = std::string("\"") + argv[2] + "\" " +
				(mode == "--spawn-ignoring" ? std::string("--wait-ctrl") : std::string("--touch-later \"") + (argc > 3 ? argv[3] : "") + "\"");
			STARTUPINFOA startup = {};
			startup.cb = sizeof(startup);
			PROCESS_INFORMATION process = {};
			if (!CreateProcessA(argv[2], &line[0], NULL, NULL, TRUE, 0, NULL, NULL, &startup, &process)) {
				std::printf("cannot start the child (%lu)\n", GetLastError());
				return 1;
			}
			CloseHandle(process.hThread);
			if (mode == "--spawn-detached") {
				CloseHandle(process.hProcess);
				return 0;
			}
			WaitForSingleObject(process.hProcess, INFINITE);
			DWORD code = 0;
			GetExitCodeProcess(process.hProcess, &code);
			std::printf("parent: child exited with %lu\n", code);
			return (int)code;
		}

		// --hold-image <exe> <секунды>: держать exe загруженным как образ — для ФС это то же, что
		// запущенная программа: файл не удалить и не перезаписать, а переименовать можно.
		if (mode == "--hold-image" && argc > 3) {
			const HMODULE image = LoadLibraryExA(argv[2], NULL, DONT_RESOLVE_DLL_REFERENCES);
			std::printf(image != NULL ? "holding the image\n" : "cannot load the image\n");
			std::fflush(stdout);
			Sleep((DWORD)std::atoi(argv[3]) * 1000);
			return image != NULL ? 0 : 1;
		}

		// --touch-later <файл>: через 3 с создать файл (жив ли «внук» после выхода прослойки).
		if (mode == "--touch-later" && argc > 2) {
			Sleep(3000);
			const HANDLE file = CreateFileA(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
			if (file != INVALID_HANDLE_VALUE) {
				CloseHandle(file);
			}
			return 0;
		}
		return -1;
	}
}

int main(int argc, char* argv[]) {
	if (argc > 1 && std::strncmp(argv[1], "--", 2) == 0) {
		const int code = runHelper(argc, argv);
		if (code >= 0) {
			return code;
		}
	}

	verbose = argc > 1 && std::strcmp(argv[1], "-v") == 0;

	runValidateTests();
	runIndexTests();
	runReceiptTests();
	runCryptoTests();
	runHttpTests();
	runFsTests();
	runConsoleTests();
	runZipTests();
	runSetupTests();
	runSignatureTests();
	runKeystoreTests();

	// Разрядность в выводе: переполнения смещений проверяются осмысленно только в 32 битах.
	std::printf("%d passed, %d failed (%d-bit)\n", passed, failed, (int)(sizeof(void*) * 8));
	return failed == 0 ? 0 : 1;
}
