#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "core/upgrade.hpp"
#include "core/install.hpp"
#include "core/receipt.hpp"
#include "core/setup.hpp"
#include "core/sync.hpp"
#include "flan/console.hpp"
#include "flan/fs.hpp"
#include "flan/hex.hpp"
#include "flan/index.hpp"
#include "flan/sha256.hpp"
#include "flan/validate.hpp"
#include <algorithm>

namespace {

	constexpr DWORD VERSION_TIMEOUT_MS = 10000;
	constexpr DWORD MAX_VERSION_OUTPUT = 4096;

	// Первая неудача — код всей команды (§7.7).
	void remember(ExitCode& result, ExitCode code) {
		if (result == ExitCode::Ok && code != ExitCode::Ok) {
			result = code;
		}
	}

	// `<exe> --version` с таймаутом (§7.9, шаг 3): вывод (stdout и stderr вместе) и код выхода.
	// false — не запустился или не уложился в таймаут (тогда процесс убит).
	bool runVersion(const std::string& exe, std::string& output, DWORD& exitCode, std::string& error) {
		SECURITY_ATTRIBUTES inherit = { sizeof(inherit), NULL, TRUE };
		HANDLE readEnd = NULL;
		HANDLE writeEnd = NULL;
		if (!CreatePipe(&readEnd, &writeEnd, &inherit, 0)) {
			error = "cannot create a pipe (code " + std::to_string(GetLastError()) + ")";
			return false;
		}
		SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);

		STARTUPINFOW startup = {};
		startup.cb = sizeof(startup);
		startup.dwFlags = STARTF_USESTDHANDLES;
		startup.hStdInput = NULL;
		startup.hStdOutput = writeEnd;
		startup.hStdError = writeEnd;

		// Путь программы — с \\?\: так CreateProcessW запускает и по пути длиннее MAX_PATH (§7.1).
		const std::wstring application = extendedPath(exe);
		std::wstring commandLine = L"\"flan.exe.new\" --version";
		PROCESS_INFORMATION process = {};
		const BOOL started = CreateProcessW(application.c_str(), &commandLine[0], NULL, NULL, TRUE, CREATE_NO_WINDOW,
			NULL, NULL, &startup, &process);
		CloseHandle(writeEnd);
		if (!started) {
			error = "cannot start it (code " + std::to_string(GetLastError()) + ")";
			CloseHandle(readEnd);
			return false;
		}
		CloseHandle(process.hThread);

		// Вывод крошечный: читаем, пока ребёнок не закроет свою сторону канала, но не дольше таймаута.
		const ULONGLONG deadline = GetTickCount64() + VERSION_TIMEOUT_MS;
		bool timedOut = false;
		for (;;) {
			DWORD available = 0;
			if (!PeekNamedPipe(readEnd, NULL, 0, NULL, &available, NULL)) {
				break;										// ребёнок закрыл канал — всё прочитано
			}
			if (available > 0) {
				char buffer[512];
				DWORD got = 0;
				if (!ReadFile(readEnd, buffer, std::min<DWORD>(available, sizeof(buffer)), &got, NULL) || got == 0) {
					break;
				}
				if (output.size() < MAX_VERSION_OUTPUT) {
					output.append(buffer, got);
				}
				continue;
			}
			if (WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0) {
				continue;									// вышел: дочитать остаток, PeekNamedPipe скажет, когда пусто
			}
			if (GetTickCount64() > deadline) {
				timedOut = true;
				break;
			}
			Sleep(20);
		}
		CloseHandle(readEnd);

		if (timedOut || WaitForSingleObject(process.hProcess, timedOut ? 0 : VERSION_TIMEOUT_MS) != WAIT_OBJECT_0) {
			TerminateProcess(process.hProcess, 1);
			WaitForSingleObject(process.hProcess, 2000);
			CloseHandle(process.hProcess);
			error = "it did not finish within " + std::to_string(VERSION_TIMEOUT_MS / 1000) + " seconds";
			return false;
		}
		exitCode = 1;
		GetExitCodeProcess(process.hProcess, &exitCode);
		CloseHandle(process.hProcess);
		return true;
	}

	// Самообновление (§7.9). entry — запись flan для этой ОС.
	ExitCode upgradeSelf(const FlanPaths& paths, const IndexRecord& entry) {
		const std::string target = paths.bin + "\\flan.exe";
		const std::string sha256 = toHex(entry.sha256, sizeof(entry.sha256));
		const std::string label = std::string("flan ") + entry.version + " (" + archName(entry.arch) + ")";

		// Шаг 1: сравнивается файл bin\flan.exe, а не запущенный образ.
		if (!pathExists(target)) {
			con::err << "Error: " << target << " does not exist. Run 'flan setup' from a flan.exe first." << con::endl;
			return ExitCode::Error;
		}
		const std::string current = crypto::calculateSHA256(target);
		if (current.empty()) {
			con::err << "Error: cannot read " << target << "." << con::endl;
			return ExitCode::Error;
		}
		if (current == sha256) {
			con::out << label << " is up to date." << con::endl;
			return ExitCode::Ok;
		}

		// Шаг 2: файл в cache\<sha256>, как у любого пакета.
		std::string file;
		const ExitCode fetched = fetchArchive(paths, entry, sha256, label, file);
		if (fetched != ExitCode::Ok) {
			return fetched;
		}

		// Шаг 3: bin\flan.exe.new и его --version.
		const std::string fresh = flanExeNewPath(paths);
		deleteFile(fresh);
		if (!copyFile(file, fresh, false)) {
			con::err << "Error: cannot write " << fresh << " (code " << GetLastError() << ")." << con::endl;
			return ExitCode::Error;
		}

		std::string output;
		DWORD exitCode = 1;
		std::string error;
		if (!runVersion(fresh, output, exitCode, error)) {
			deleteFile(fresh);
			con::err << "Error: the downloaded " << label << " does not work: " << error << ". The current flan is kept." << con::endl;
			return ExitCode::Integrity;
		}
		const std::string reported = parseVersionLine(output);
		if (exitCode != 0 || reported != entry.version) {
			deleteFile(fresh);
			con::err << "Error: the downloaded flan.exe reports " << (reported.empty() ? std::string("no version") : "version " + reported)
				<< " (exit code " << (unsigned long)exitCode << "), but the index says " << entry.version << ". The current flan is kept." << con::endl;
			return ExitCode::Integrity;
		}

		// Шаг 4: замена той же функцией, что у flan setup.
		bool replaced = false;
		if (!putFlanExeInPlace(paths, "flan upgrade flan", replaced)) {
			return ExitCode::Error;
		}

		// Шаг 5: архив не нужен; flan.exe.old удалит следующий запуск.
		deleteFile(file);
		con::out << "Updated flan to " << entry.version << " (" << archName(entry.arch) << ") in " << target
			<< (replaced ? "; the previous one stays as flan.exe.old until the next flan run." : ".") << con::endl;
		return ExitCode::Ok;
	}
}

ExitCode upgradePackages(const FlanPaths& paths, const std::vector<std::string>& requested) {
	IndexView index;
	std::string error;
	const ExitCode loaded = loadLocalIndex(paths, index, error);
	if (loaded != ExitCode::Ok) {
		con::err << "Error: " << error << "." << con::endl;
		return loaded;
	}

	ExitCode result = ExitCode::Ok;
	std::vector<std::string> packages;
	bool self = false;

	if (requested.empty()) {
		// Все установленные, у которых sha256 в индексе другой (§6.2: идентичность сборки — её sha256).
		std::vector<std::string> problems;
		for (const Receipt& receipt : listReceipts(paths, problems)) {
			IndexRecord entry;
			const ExitCode found = findBuildForThisSystem(index, receipt.name, entry, error);
			if (found == ExitCode::NotFound) {
				con::err << "Warning: " << receipt.name << " is no longer in the index; it is kept as is." << con::endl;
				continue;
			}
			if (found != ExitCode::Ok) {
				con::err << "Error: " << error << "." << con::endl;
				remember(result, found);
				continue;
			}
			if (toHex(entry.sha256, sizeof(entry.sha256)) != receipt.sha256) {
				packages.push_back(receipt.name);
			}
		}
		for (const std::string& problem : problems) {
			con::err << "Warning: " << problem << "." << con::endl;
		}

		// Сам flan — если он есть в индексе и в bin\.
		IndexRecord flanEntry;
		self = findBuildForThisSystem(index, "flan", flanEntry, error) == ExitCode::Ok && pathExists(paths.bin + "\\flan.exe") &&
			crypto::calculateSHA256(paths.bin + "\\flan.exe") != toHex(flanEntry.sha256, sizeof(flanEntry.sha256));

		if (packages.empty() && !self) {
			con::out << "Everything is up to date." << con::endl;
			return result;
		}
	}
	else {
		for (const std::string& raw : requested) {
			const std::string name = toLowerAscii(raw);
			if (!isSafePackageName(name)) {
				con::err << "Error: '" << raw << "' is not a valid package name." << con::endl;
				remember(result, ExitCode::Usage);
				continue;
			}
			if (name == "flan") {
				self = true;
				continue;
			}
			if (std::find(packages.begin(), packages.end(), name) != packages.end()) {
				continue;
			}
			Receipt receipt;
			if (readReceipt(paths, name, receipt, error) == ReceiptState::Missing) {
				con::err << "Error: package '" << name << "' is not installed. Use 'flan install " << name << "'." << con::endl;
				remember(result, ExitCode::NotFound);
				continue;
			}
			packages.push_back(name);
		}
	}

	for (const std::string& name : packages) {
		remember(result, installPackage(paths, name));
	}

	// Сам flan — последним: новые пакеты уже стоят, даже если с ним что-то не так.
	if (self) {
		IndexRecord entry;
		const ExitCode found = findBuildForThisSystem(index, "flan", entry, error);
		if (found != ExitCode::Ok) {
			con::err << "Error: " << (found == ExitCode::NotFound ? std::string("flan is not in the index for this architecture") : error)
				<< "." << con::endl;
			remember(result, found);
		}
		else {
			remember(result, upgradeSelf(paths, entry));
		}
	}
	return result;
}
