#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include "flan/fs.hpp"
#include "flan/index.hpp"
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

int main(int argc, char* argv[]) {
	SetConsoleOutputCP(CP_UTF8);

	if (argc < 2) {
		printUsage();
		return exitWith(ExitCode::Usage);
	}

	const std::string command = argv[1];

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

	const std::string userDir = getUserDirectory();

	// Пустой путь превратил бы все дальнейшие пути в "\apps", "\bin" и т. д.,
	// то есть в каталоги в корне текущего диска.
	if (userDir.empty()) {
		std::cerr << "Fatal: could not determine the user profile directory." << std::endl;
		return exitWith(ExitCode::Error);
	}

	const FlanPaths paths = FlanPaths::under(userDir);

	// Раскладка DESIGN.md §7.1. cache\ появится на этапе 2 вместе с кэшем по sha256.
	if (!createDirectory(paths.apps.c_str()) || !createDirectory(paths.bin.c_str()) ||
		!createDirectory(paths.state.c_str()) || !createDirectory(paths.tmp.c_str())) {
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
		return exitWith(installPackage(paths, argv[2]));
	}
	if (command == "uninstall") {
		return exitWith(uninstallPackage(paths, argv[2]));
	}
	if (command == "list") {
		return exitWith(listAvailable(paths));
	}
	return exitWith(listInstalled(paths));
}
