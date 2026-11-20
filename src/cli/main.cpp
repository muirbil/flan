#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include "flan/http.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include "flan/fs.hpp"
#include <fstream>
#include "flan/format.hpp"
#include "nlohmann/json.hpp"
#include <filesystem>
#include "flan/sha256.hpp"
#include "flan/validate.hpp"
#include "core/exit_code.hpp"
#include "core/install.hpp"
#include "core/lock.hpp"
#include "core/paths.hpp"
#include "core/sync.hpp"
#include "flan/index.hpp"

using json = nlohmann::json;

namespace {

	const std::string REPO_BASE = "https://raw.githubusercontent.com/muirbil/flan-packages/main";

	struct PackageRecord {
		std::string name;
		uint64_t hash_v;
		uint32_t meta_id;
	};

	void printUsage() {
		std::cout << "Usage: flan <command> [options]" << std::endl;
		std::cout << "Commands: sync, install, uninstall, list, installed" << std::endl;
	}

	// Поля метаданных — недоверенный ввод, поэтому ни одно не извлекается без проверки типа.
	// Прежний metadata["name"] бросал json::type_error на любом неожиданном документе,
	// а исключение никто не ловил — процесс падал через std::terminate.
	bool readString(const json& document, const char* key, std::string& out) {
		const auto it = document.find(key);
		if (it == document.end() || !it->is_string()) {
			std::cerr << "Error: metadata field '" << key << "' is missing or is not a string." << std::endl;
			return false;
		}
		out = it->get<std::string>();
		return true;
	}

	bool readJsonFile(const std::string& path, json& out) {
		std::ifstream in(path, std::ios::binary);
		if (!in.is_open()) {
			return false;
		}

		try {
			in >> out;
		}
		catch (const json::exception&) {
			return false;
		}

		return true;
	}

	// Все смещения из файла проверяются по его реальному размеру, а арифметика ведётся
	// в 64 битах: в 32-битной сборке package_count * sizeof(CoreEntry) переполнялся,
	// и таблица любого размера "помещалась" в любой файл.
	bool loadDatabase(const std::string& dbFile, CoreHeader& header, std::vector<PackageRecord>& packages) {

		std::ifstream in(dbFile, std::ios::binary);
		if (!in) {
			std::cerr << "Database not found! Please run 'flan sync' first." << std::endl;
			return false;
		}

		in.seekg(0, std::ios::end);
		const std::streamoff rawSize = in.tellg();
		if (rawSize < 0) {
			std::cerr << "Database file is unreadable!" << std::endl;
			return false;
		}
		const uint64_t fileSize = (uint64_t)rawSize;
		in.seekg(0, std::ios::beg);

		header = {};
		in.read(reinterpret_cast<char*>(&header), sizeof(CoreHeader));

		if (in.gcount() != (std::streamsize)sizeof(CoreHeader) || header.magic != FLAN_MAGIC) {
			std::cerr << "Database file is corrupted!" << std::endl;
			return false;
		}

		if (header.db_version > FLAN_DB_VERSION) {
			std::cerr << "Database format v" << header.db_version << " is newer than this build supports (v"
				<< FLAN_DB_VERSION << "). Please update flan." << std::endl;
			return false;
		}

		const uint64_t tableEnd = sizeof(CoreHeader) + (uint64_t)header.package_count * sizeof(CoreEntry);
		if (tableEnd > fileSize || header.string_pool_offset < tableEnd || header.string_pool_offset > fileSize) {
			std::cerr << "Database file is corrupted!" << std::endl;
			return false;
		}

		packages.reserve(header.package_count);

		for (uint32_t i = 0; i < header.package_count; i++) {

			CoreEntry entry = {};
			in.seekg((std::streamoff)(sizeof(CoreHeader) + (uint64_t)i * sizeof(CoreEntry)), std::ios::beg);
			in.read(reinterpret_cast<char*>(&entry), sizeof(CoreEntry));

			if (in.gcount() != (std::streamsize)sizeof(CoreEntry)) {
				std::cerr << "Database file is corrupted!" << std::endl;
				return false;
			}

			const uint64_t namePos = (uint64_t)header.string_pool_offset + entry.name_offset;
			if (namePos >= fileSize) {
				std::cerr << "Database file is corrupted!" << std::endl;
				return false;
			}

			// Читаем ограниченное окно. Прежний getline(in, name, '\0') без терминатора
			// утягивал в строку остаток файла целиком.
			char nameBuf[MAX_NAME_LENGTH + 1] = {};
			const uint64_t window = (std::min)((uint64_t)sizeof(nameBuf), fileSize - namePos);

			in.seekg((std::streamoff)namePos, std::ios::beg);
			in.read(nameBuf, (std::streamsize)window);

			const size_t readCount = (size_t)in.gcount();
			const size_t nameLength = strnlen(nameBuf, readCount);

			if (nameLength == readCount) {
				std::cerr << "Database file is corrupted!" << std::endl;
				return false;
			}

			PackageRecord record;
			record.name.assign(nameBuf, nameLength);
			record.hash_v = entry.hash_v;
			record.meta_id = entry.meta_id;

			// Имя из базы становится именем каталога и ключом реестра.
			if (!isSafeName(record.name)) {
				std::cerr << "Database file contains an unsafe package name. Aborting." << std::endl;
				return false;
			}

			packages.push_back(std::move(record));
		}

		return true;
	}
}

int main(int argc, char* argv[]) {
	SetConsoleOutputCP(CP_UTF8);

	if (argc < 2) {
		printUsage();
		return exitWith(ExitCode::Usage);
	}

	std::string command = argv[1];
	std::string userDir = getUserDirectory();

	// Пустой путь превращал все дальнейшие пути в "\db", "\apps" и т. д.,
	// то есть в каталоги в корне текущего диска.
	if (userDir.empty()) {
		std::cerr << "Fatal: could not determine the user profile directory." << std::endl;
		return exitWith(ExitCode::Error);
	}

	const FlanPaths paths = FlanPaths::under(userDir);

	std::string dbPath = userDir + "\\db";
	std::string appsPath = paths.apps;
	std::string binPath = paths.bin;
	std::string tempPath = paths.tmp;

	// Раскладка DESIGN.md §7.1. cache\ появится на этапе 2 вместе с кэшем по sha256.
	if (!createDirectory(paths.apps.c_str()) || !createDirectory(paths.bin.c_str()) ||
		!createDirectory(paths.state.c_str()) || !createDirectory(paths.tmp.c_str())) {
		std::cerr << "Fatal: could not create the flan directories under " << userDir << std::endl;
		return exitWith(ExitCode::Error);
	}

	// Команды, меняющие состояние, работают под блокировкой (DESIGN.md §7.6): два flan
	// одновременно перезаписали бы друг другу базу, архивы и реестр. list и installed только читают.
	FlanLock lock;
	if (command == "sync" || command == "install" || command == "uninstall") {
		switch (lock.acquire(paths.lock, LOCK_TIMEOUT_MS)) {
		case FlanLock::Result::Acquired:
			break;
		case FlanLock::Result::Busy:
			std::cerr << "Error: another flan process is running (" << userDir << "\\lock is held for more than "
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

	else if (command == "install") {
		if (argc < 3) {
			std::cerr << "Please specify a package to install." << std::endl;
			std::cerr << "Usage: flan install <package_name>" << std::endl;
			return exitWith(ExitCode::Usage);
		}

		return exitWith(installPackage(paths, argv[2]));
	}

	else if (command == "uninstall") {

		if (argc < 3) {
			std::cerr << "Error: Specify a package to uninstall." << std::endl;
			std::cerr << "Usage: flan uninstall <package_name>" << std::endl;
			return exitWith(ExitCode::Usage);
		}

		std::string target_pkg = argv[2];

		// Без этой проверки 'flan uninstall ..\..\..\Documents' уходило прямо
		// в std::filesystem::remove_all.
		if (!isSafeName(target_pkg)) {
			std::cerr << "Error: '" << target_pkg << "' is not a valid package name." << std::endl;
			return exitWith(ExitCode::Usage);
		}

		std::cout << "Uninstalling package: " << target_pkg << std::endl;

		std::string registry_path = userDir + "\\installed.json";
		json registry;

		if (!readJsonFile(registry_path, registry)) {
			std::cerr << "Error: No installed packages found, or the registry is corrupted." << std::endl;
			return exitWith(ExitCode::Error);
		}

		// Проверка установленного пакета в реестре
		if (!registry.is_object() || !registry.contains(target_pkg)) {
			std::cerr << "Error: Package '" << target_pkg << "' is not installed." << std::endl;
			return exitWith(ExitCode::NotFound);
		}

		// Достаем имя прослойки из реестра, если запись вообще её содержит.
		std::string shim_name = target_pkg;
		const json& record = registry[target_pkg];
		if (record.is_object()) {
			const auto it = record.find("shim");
			if (it != record.end() && it->is_string()) {
				shim_name = it->get<std::string>();
			}
		}

		std::string app_dir = appsPath + "\\" + target_pkg;
		std::error_code ec; // The error will be logged here

		if (std::filesystem::remove_all(app_dir, ec) > 0) {
			std::cout << "- Removed application directory: " << app_dir << std::endl;
		}
		else {
			std::cerr << "Warning: Failed to remove application directory: " << app_dir << ". Error: " << ec.message() << std::endl;
		}

		// Удаляем shim прослойку. Имя пришло из файла на диске, поэтому проверяется так же,
		// как и всё остальное, что попадает в путь.
		if (isSafeName(shim_name)) {
			std::string shim_path = binPath + "\\" + shim_name + ".bat";
			if (std::filesystem::remove(shim_path, ec)) {
				std::cout << "- Removed global shim (" << shim_name << ")" << std::endl;
			}
			else {
				std::cerr << "Warning: Failed to remove shim: " << shim_path << ". Error: " << ec.message() << std::endl;
			}
		}
		else {
			std::cerr << "Warning: registry holds an unsafe shim name; skipping shim removal." << std::endl;
		}

		// Удаляем запись из JSON реестра
		registry.erase(target_pkg);

		std::ofstream reg_out(registry_path);
		if (reg_out.is_open()) {
			reg_out << registry.dump(4);
			reg_out.close();
			std::cout << "Success! Package '" << target_pkg << "' has been uninstalled." << std::endl;
		}
		else {
			std::cerr << "Warning: Failed to update local registry after uninstalling." << std::endl;
		}
	}

	// До этапа 5 list показывает доступные пакеты, а установленные — installed (DESIGN.md §7.7).
	else if (command == "list") {
		IndexView index;
		std::string error;
		if (!loadLocalIndex(paths, index, error)) {
			std::cerr << "Error: " << error << "." << std::endl;
			return exitWith(ExitCode::Error);
		}

		std::cout << "Available packages (index generated " << formatUnixTime(index.generatedAt()) << "):" << std::endl;

		// Записи отсортированы по (name, arch): сборки одного пакета идут подряд.
		IndexRecord current;
		std::string archs;
		for (uint32_t i = 0; i <= index.count(); i++) {
			IndexRecord record;
			if (i < index.count() && !index.record(i, record, error)) {
				std::cerr << "Error: the local index is corrupted (" << error << "). Run 'flan sync' to fetch it again." << std::endl;
				return exitWith(ExitCode::Integrity);
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
	}

	else if (command == "installed") {
		std::string registry_path = userDir + "\\installed.json";
		json registry;

		if (!readJsonFile(registry_path, registry)) {
			std::cout << "No packages installed yet." << std::endl;
			return exitWith(ExitCode::Ok);
		}

		if (!registry.is_object() || registry.empty()) {
			std::cout << "No packages installed yet." << std::endl;
			return exitWith(ExitCode::Ok);
		}

		std::cout << "Installed packages:" << std::endl;
		std::cout << "───────────────────────────────────" << std::endl;

		// Итерируемся по всем именам программ и их значениям используя nlohmann\json
		for (auto& el : registry.items())
		{
			std::string pkg_version = "unknown";

			if (el.value().is_object()) {
				const auto it = el.value().find("version");
				if (it != el.value().end() && it->is_string()) {
					pkg_version = it->get<std::string>();
				}
			}

			std::cout << "- " << el.key() << " (v" << pkg_version << ")" << std::endl;
		}
		std::cout << "───────────────────────────────────" << std::endl;
	}

	else {
		std::cerr << "Unknown command: " << command << std::endl;
		printUsage();
		return exitWith(ExitCode::Usage);
	}

	return exitWith(ExitCode::Ok);
}
