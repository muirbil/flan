#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include "flan/console.hpp"
#include <string>
#include <vector>
#include "flan/fs.hpp"
#include "flan/index.hpp"
#include "flan/strings.hpp"
#include "flan/validate.hpp"
#include "core/exit_code.hpp"
#include "core/install.hpp"
#include "core/lock.hpp"
#include "core/paths.hpp"
#include "core/receipt.hpp"
#include "core/setup.hpp"
#include "core/shim.hpp"
#include "core/sync.hpp"
#include "core/upgrade.hpp"
#include "flan/version.h"

// cli — разбор аргументов, вывод и коды возврата (DESIGN.md §4); вся работа — в core/.

namespace {

	void printUsage() {
		con::out << "Usage: flan <command> [options]" << con::endl;
		con::out << "Commands:" << con::endl;
		con::out << "  sync                  update the package index" << con::endl;
		con::out << "  list                  available packages" << con::endl;
		con::out << "  install <package>...  install or update packages" << con::endl;
		con::out << "  upgrade [package...]  update the given packages, or all that changed (flan itself last)" << con::endl;
		con::out << "  uninstall <package>... remove packages" << con::endl;
		con::out << "  installed             installed packages" << con::endl;
		con::out << "  setup [--remove]      put flan in bin\\ and bin\\ in your PATH (--remove: take it out of PATH)" << con::endl;
		con::out << "Options: --version, --help" << con::endl;
	}

	// "flan 0.4.0 (x64)" (DESIGN.md §7.7). Самообновление разбирает эту строку у flan.exe.new (§7.9).
	void printVersion() {
		con::out << "flan " << FLAN_VERSION_STRING << (sizeof(void*) == 8 ? " (x64)" : " (x86)") << con::endl;
	}

	// Запущен ли процесс с повышенными правами (DESIGN.md §1): flan они не нужны.
	bool isElevated() {
		HANDLE token = NULL;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return false;
		}
		TOKEN_ELEVATION elevation = {};
		DWORD size = 0;
		const bool elevated = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) &&
			elevation.TokenIsElevated != 0;
		CloseHandle(token);
		return elevated;
	}

	// До этапа 5 list показывает доступные пакеты, а установленные — installed (DESIGN.md §7.7).
	ExitCode listAvailable(const FlanPaths& paths) {
		IndexView index;
		std::string error;
		const ExitCode loaded = loadLocalIndex(paths, index, error);
		if (loaded != ExitCode::Ok) {
			con::err << "Error: " << error << "." << con::endl;
			return loaded;
		}

		con::out << "Available packages (index generated " << formatUnixTime(index.generatedAt()) << "):" << con::endl;

		// Записи отсортированы по (name, arch): сборки одного пакета идут подряд.
		IndexRecord current;
		std::string archs;
		for (uint32_t i = 0; i <= index.count(); i++) {
			IndexRecord record;
			if (i < index.count() && !index.record(i, record, error)) {
				con::err << "Error: the local index is corrupted (" << error << "). Run 'flan sync' to fetch it again." << con::endl;
				return ExitCode::Integrity;
			}

			if (i > 0 && (i == index.count() || record.name != current.name)) {
				con::out << "  " << current.name << "  " << current.version << "  [" << archs << "]";
				if (!current.description.empty()) {
					con::out << "  " << current.description;
				}
				con::out << con::endl;
				archs.clear();
			}

			if (i < index.count()) {
				archs += (archs.empty() ? "" : ", ") + std::string(archName(record.arch));
				current = record;
			}
		}

		if (index.count() == 0) {
			con::out << "  (none)" << con::endl;
		}
		return ExitCode::Ok;
	}

	ExitCode listInstalled(const FlanPaths& paths) {
		std::vector<std::string> problems;
		const std::vector<Receipt> receipts = listReceipts(paths, problems);

		for (const std::string& problem : problems) {
			con::err << "Warning: " << problem << "." << con::endl;
		}

		if (receipts.empty()) {
			con::out << "No packages installed yet." << con::endl;
			return ExitCode::Ok;
		}

		con::out << "Installed packages:" << con::endl;
		for (const Receipt& receipt : receipts) {
			std::string commands;
			for (const std::string& bin : receipt.bins) {
				commands += (commands.empty() ? "" : ", ") + commandNameFromBin(bin);
			}
			con::out << "  " << receipt.name << "  " << receipt.version << "  [" << archName(receipt.arch) << "]  " << commands << con::endl;
		}
		return ExitCode::Ok;
	}
}

int wmain(int argc, wchar_t* argv[]) {
	// Кодовая страница консоли не меняется: вывод идёт через WriteConsoleW (DESIGN.md §7.10),
	// а SetConsoleOutputCP оставлял бы её изменённой и после выхода flan.

	if (argc < 2) {
		printUsage();
		return exitWith(ExitCode::Usage);
	}

	// Аргументы — в UTF-8, как и всё внутри flan (DESIGN.md §7.1). Невалидный UTF-16
	// в аргументе — заведомо не имя пакета и не команда.
	std::vector<std::string> args;
	for (int i = 0; i < argc; i++) {
		std::string arg;
		if (!toUtf8(argv[i], arg)) {
			con::err << "Error: argument " << i << " is not valid Unicode." << con::endl;
			return exitWith(ExitCode::Usage);
		}
		args.push_back(arg);
	}

	const std::string command = args[1];

	// До FLAN_HOME и любых действий с диском: `flan.exe.new --version` при самообновлении (§7.9)
	// не должен ни удалять flan.exe.old, ни создавать каталоги.
	if (command == "--version" && argc == 2) {
		printVersion();
		return exitWith(ExitCode::Ok);
	}
	if (command == "--help" || command == "-h" || command == "/?") {
		printUsage();
		return exitWith(ExitCode::Ok);
	}

	const bool knownCommand = command == "sync" || command == "list" || command == "install" || command == "upgrade" ||
		command == "uninstall" || command == "installed" || command == "setup";
	if (!knownCommand) {
		con::err << "Unknown command: " << command << con::endl;
		printUsage();
		return exitWith(ExitCode::Usage);
	}

	if ((command == "install" || command == "uninstall") && argc < 3) {
		con::err << "Error: specify at least one package." << con::endl;
		con::err << "Usage: flan " << command << " <package>..." << con::endl;
		return exitWith(ExitCode::Usage);
	}

	const bool setupRemove = command == "setup" && argc == 3 && args[2] == "--remove";
	if (command == "setup" && argc > 2 && !setupRemove) {
		con::err << "Error: unknown option " << args[2] << "." << con::endl;
		con::err << "Usage: flan setup [--remove]" << con::endl;
		return exitWith(ExitCode::Usage);
	}

	// Корень — FLAN_HOME или %USERPROFILE%\.flan (DESIGN.md §7.1). Без него дальше нельзя:
	// пустой путь превратил бы все пути в "\apps", "\bin" — каталоги в корне текущего диска.
	std::string userDir;
	std::string error;
	if (!resolveFlanHome(userDir, error)) {
		con::err << "Fatal: " << error << "." << con::endl;
		return exitWith(ExitCode::Error);
	}

	const FlanPaths paths = FlanPaths::under(userDir);

	// Права администратора flan не нужны, а файлы, созданные повышенным процессом, потом могут
	// мешать обычному (DESIGN.md §1). Это предупреждение, а не отказ.
	if (isElevated()) {
		con::err << "Warning: flan is running as administrator. It does not need that, and files it creates now "
			"may later get in the way of normal runs." << con::endl;
	}

	// Прежний bin\flan.exe, отодвинутый flan setup (§7.8, «Копия себя»): удаляется при любом
	// следующем запуске. Если он ещё работает, удалится в другой раз.
	deleteFile(paths.bin + "\\flan.exe.old");

	// Раскладка DESIGN.md §7.1.
	if (!createDirectory(paths.apps) || !createDirectory(paths.bin) || !createDirectory(paths.cache) ||
		!createDirectory(paths.state) || !createDirectory(paths.tmp)) {
		con::err << "Fatal: could not create the flan directories under " << userDir << con::endl;
		return exitWith(ExitCode::Error);
	}

	// Команды, меняющие состояние, работают под блокировкой (DESIGN.md §7.6).
	// list и installed только читают атомарно записанные файлы и обходятся без неё.
	FlanLock lock;
	if (command == "sync" || command == "install" || command == "upgrade" || command == "uninstall" || command == "setup") {
		switch (lock.acquire(paths.lock, LOCK_TIMEOUT_MS)) {
		case FlanLock::Result::Acquired:
			break;
		case FlanLock::Result::Busy:
			con::err << "Error: another flan process is running (" << paths.lock << " is held for more than "
				<< (LOCK_TIMEOUT_MS / 1000) << " seconds)." << con::endl;
			return exitWith(ExitCode::Locked);
		case FlanLock::Result::Failed:
			return exitWith(ExitCode::Error);
		}

		// Каталоги старых версий, занятые в прошлый раз запущенной программой (§7.6, шаг 9).
		processPendingDeletes(paths);

		// Прослойки, перенесённые в tmp\, потому что их программа тогда работала (§7.4).
		cleanTemporary(paths);

		// Эталон прослоек от прежнего flan — после самообновления (§7.9). setup делает это сам.
		if (command != "setup" && shimReferenceIsStale(paths)) {
			refreshShims(paths);
		}
	}

	if (command == "sync") {
		return exitWith(syncIndex(paths));
	}
	// install и uninstall с несколькими пакетами (DESIGN.md §7.7): каждый — своя транзакция, сбой одного
	// не останавливает остальные, код возврата — первой неудачи.
	if (command == "install" || command == "uninstall") {
		ExitCode result = ExitCode::Ok;
		for (size_t i = 2; i < args.size(); i++) {
			const ExitCode code = command == "install" ? installPackage(paths, args[i]) : uninstallPackage(paths, args[i]);
			if (result == ExitCode::Ok && code != ExitCode::Ok) {
				result = code;
			}
		}
		return exitWith(result);
	}
	if (command == "upgrade") {
		return exitWith(upgradePackages(paths, std::vector<std::string>(args.begin() + 2, args.end())));
	}
	if (command == "setup") {
		return exitWith(runSetup(paths, setupRemove));
	}
	if (command == "list") {
		return exitWith(listAvailable(paths));
	}
	return exitWith(listInstalled(paths));
}
