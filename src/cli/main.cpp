#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <iostream>
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
#include "core/sync.hpp"

// cli — разбор аргументов, вывод и коды возврата (DESIGN.md §4); вся работа — в core/.

namespace {

	void printUsage() {
		std::cout << "Usage: flan <command> [options]" << std::endl;
		std::cout << "Commands:" << std::endl;
		std::cout << "  sync                  update the package index" << std::endl;
		std::cout << "  list                  available packages" << std::endl;
		std::cout << "  install <package>     install or update a package" << std::endl;
		std::cout << "  uninstall <package>   remove a package" << std::endl;
		std::cout << "  installed             installed packages" << std::endl;
	}

	// До этапа 5 list показывает доступные пакеты, а установленные — installed (DESIGN.md §7.7).
	ExitCode listAvailable(const FlanPaths& paths) {
		IndexView index;
		std::string error;
		if (!loadLocalIndex(paths, index, error)) {
			std::cerr << "Error: " << error << "." << std::endl;
			return ExitCode::Error;
		}

		std::cout << "Available packages (index generated " << formatUnixTime(index.generatedAt()) << "):" << std::endl;

		// Записи отсортированы по (name, arch): сборки одного пакета идут подряд.
		IndexRecord current;
		std::string archs;
		for (uint32_t i = 0; i <= index.count(); i++) {
			IndexRecord record;
			if (i < index.count() && !index.record(i, record, error)) {
				std::cerr << "Error: the local index is corrupted (" << error << "). Run 'flan sync' to fetch it again." << std::endl;
				return ExitCode::Integrity;
			}

			if (i > 0 && (i == index.count() || record.name != current.name)) {
				std::cout << "  " << current.name << "  " << current.version << "  [" << archs << "]";
				if (!current.description.empty()) {
					std::cout << "  " << current.description;
				}
				std::cout << std::endl;
				archs.clear();
			}

			if (i < index.count()) {
				archs += (archs.empty() ? "" : ", ") + std::string(archName(record.arch));
				current = record;
			}
		}

		if (index.count() == 0) {
			std::cout << "  (none)" << std::endl;
		}
		return ExitCode::Ok;
	}

	ExitCode listInstalled(const FlanPaths& paths) {
		std::vector<std::string> problems;
		const std::vector<Receipt> receipts = listReceipts(paths, problems);

		for (const std::string& problem : problems) {
			std::cerr << "Warning: " << problem << "." << std::endl;
		}

		if (receipts.empty()) {
			std::cout << "No packages installed yet." << std::endl;
			return ExitCode::Ok;
		}

		std::cout << "Installed packages:" << std::endl;
		for (const Receipt& receipt : receipts) {
			std::string commands;
			for (const std::string& bin : receipt.bins) {
				commands += (commands.empty() ? "" : ", ") + commandNameFromBin(bin);
			}
			std::cout << "  " << receipt.name << "  " << receipt.version << "  [" << archName(receipt.arch) << "]  " << commands << std::endl;
		}
		return ExitCode::Ok;
	}
}

int wmain(int argc, wchar_t* argv[]) {
	SetConsoleOutputCP(CP_UTF8);

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
			std::cerr << "Error: argument " << i << " is not valid Unicode." << std::endl;
			return exitWith(ExitCode::Usage);
		}
		args.push_back(arg);
	}

	const std::string command = args[1];

	const bool knownCommand = command == "sync" || command == "list" || command == "install" ||
		command == "uninstall" || command == "installed";
	if (!knownCommand) {
		std::cerr << "Unknown command: " << command << std::endl;
		printUsage();
		return exitWith(ExitCode::Usage);
	}

	if ((command == "install" || command == "uninstall") && argc < 3) {
		std::cerr << "Error: specify a package." << std::endl;
		std::cerr << "Usage: flan " << command << " <package>" << std::endl;
		return exitWith(ExitCode::Usage);
	}

	// Корень — FLAN_HOME или %USERPROFILE%\.flan (DESIGN.md §7.1). Без него дальше нельзя:
	// пустой путь превратил бы все пути в "\apps", "\bin" — каталоги в корне текущего диска.
	std::string userDir;
	std::string error;
	if (!resolveFlanHome(userDir, error)) {
		std::cerr << "Fatal: " << error << "." << std::endl;
		return exitWith(ExitCode::Error);
	}

	const FlanPaths paths = FlanPaths::under(userDir);

	// Раскладка DESIGN.md §7.1.
	if (!createDirectory(paths.apps) || !createDirectory(paths.bin) || !createDirectory(paths.cache) ||
		!createDirectory(paths.state) || !createDirectory(paths.tmp)) {
		std::cerr << "Fatal: could not create the flan directories under " << userDir << std::endl;
		return exitWith(ExitCode::Error);
	}

	// Команды, меняющие состояние, работают под блокировкой (DESIGN.md §7.6).
	// list и installed только читают атомарно записанные файлы и обходятся без неё.
	FlanLock lock;
	if (command == "sync" || command == "install" || command == "uninstall") {
		switch (lock.acquire(paths.lock, LOCK_TIMEOUT_MS)) {
		case FlanLock::Result::Acquired:
			break;
		case FlanLock::Result::Busy:
			std::cerr << "Error: another flan process is running (" << paths.lock << " is held for more than "
				<< (LOCK_TIMEOUT_MS / 1000) << " seconds)." << std::endl;
			return exitWith(ExitCode::Locked);
		case FlanLock::Result::Failed:
			return exitWith(ExitCode::Error);
		}

		// Каталоги старых версий, занятые в прошлый раз запущенной программой (§7.6, шаг 9).
		processPendingDeletes(paths);
	}

	if (command == "sync") {
		return exitWith(syncIndex(paths));
	}
	if (command == "install") {
		return exitWith(installPackage(paths, args[2]));
	}
	if (command == "uninstall") {
		return exitWith(uninstallPackage(paths, args[2]));
	}
	if (command == "list") {
		return exitWith(listAvailable(paths));
	}
	return exitWith(listInstalled(paths));
}
