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
#include "cli/exit_code.hpp"
#include "core/lock.hpp"

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

	std::string dbPath = userDir + "\\db";
	std::string cachePath = userDir + "\\cache";
	std::string appsPath = userDir + "\\apps";
	std::string binPath = userDir + "\\bin";
	std::string tempPath = userDir + "\\temp";

	// Что-бы папки создавались при любой команде.
	if (!createDirectory(dbPath.c_str()) || !createDirectory(cachePath.c_str()) ||
		!createDirectory(appsPath.c_str()) || !createDirectory(binPath.c_str()) ||
		!createDirectory(tempPath.c_str())) {
		std::cerr << "Fatal: could not create the flan directories under " << userDir << std::endl;
		return exitWith(ExitCode::Error);
	}

	// Команды, меняющие состояние, работают под блокировкой (DESIGN.md §7.6): два flan
	// одновременно перезаписали бы друг другу базу, архивы и реестр. list и installed только читают.
	FlanLock lock;
	if (command == "sync" || command == "install" || command == "uninstall") {
		switch (lock.acquire(userDir + "\\lock", LOCK_TIMEOUT_MS)) {
		case FlanLock::Result::Acquired:
			break;
		case FlanLock::Result::Busy:
			std::cerr << "Error: another flan process is running (" << userDir << "\\lock is held for more than "
				<< (LOCK_TIMEOUT_MS / 1000) << " seconds)." << std::endl;
			return exitWith(ExitCode::Locked);
		case FlanLock::Result::Failed:
			return exitWith(ExitCode::Error);
		}
	}

	if (command == "sync") {
		std::cout << "Syncing package database from remote repository..." << std::endl;

		std::string dbFile = dbPath + "\\core.flan";
		std::string dbUrl = REPO_BASE + "/core.flan";

		std::cout << "Downloading database from: " << dbUrl << std::endl;

		if (downloadFile(dbUrl, dbFile))
		{
			std::cout << "Success! Database synced and updated." << std::endl;
		}
		else {
			std::cerr << "Failed to download database. Check your internet connection." << std::endl;
			return exitWith(ExitCode::Network);
		}
	}

	else if (command == "install") {
		if (argc < 3)
		{
			std::cerr << "Please specify a package to install." << std::endl;
			std::cerr << "Usage: flan install <package_name>" << std::endl;
			return exitWith(ExitCode::Usage);
		}

		std::string target_pkg = argv[2];
		if (!isSafeName(target_pkg)) {
			std::cerr << "Error: '" << target_pkg << "' is not a valid package name." << std::endl;
			return exitWith(ExitCode::Usage);
		}

		std::cout << "Looking for '" << target_pkg << "' in the database..." << std::endl;

		CoreHeader header = {};
		std::vector<PackageRecord> packages;
		if (!loadDatabase(dbPath + "\\core.flan", header, packages)) {
			return exitWith(ExitCode::Error);
		}

		const PackageRecord* targetEntry = nullptr;
		for (const PackageRecord& record : packages) {
			if (record.name == target_pkg) {
				targetEntry = &record;
				break;
			}
		}

		if (!targetEntry) {
			std::cerr << "Package '" << target_pkg << "' not found in the database." << std::endl;
			return exitWith(ExitCode::NotFound);
		}

		std::cout << "Package [" << targetEntry->meta_id << "] '" << target_pkg << "' found in the database." << std::endl;
		std::cout << "Fetching metadata from remote repository..." << std::endl;

		std::string meta_filename = std::to_string(targetEntry->meta_id) + ".json";
		std::string metadataUrl = REPO_BASE + "/meta/" + meta_filename;
		std::string temp_meta_path = tempPath + "\\" + meta_filename;

		if (!downloadFile(metadataUrl, temp_meta_path)) {
			std::cerr << "Error: Failed to fetch metadata from the repository." << std::endl;
			return exitWith(ExitCode::Network);
		}

		json metadata;
		const bool metadataRead = readJsonFile(temp_meta_path, metadata);
		deleteFile(temp_meta_path.c_str());

		if (!metadataRead || !metadata.is_object()) {
			std::cerr << "Error: Failed to parse metadata JSON." << std::endl;
			return exitWith(ExitCode::Integrity);
		}

		std::cout << "Metadata successfully downloaded!" << std::endl;

		std::string package_name;
		std::string package_version;
		std::string download_url;
		std::string bin_name;
		std::string expected_hash;

		if (!readString(metadata, "name", package_name) ||
			!readString(metadata, "version", package_version) ||
			!readString(metadata, "url", download_url) ||
			!readString(metadata, "bin", bin_name) ||
			!readString(metadata, "hash", expected_hash)) {
			return exitWith(ExitCode::Integrity);
		}

		// name и bin становятся частями путей и именем .bat-прослойки.
		std::string bin_relative;
		if (!isSafeName(package_name) || !normalizeRelativePath(bin_name, bin_relative) || !isSafeVersion(package_version)) {
			std::cerr << "Error: metadata contains an unsafe name. Refusing to install." << std::endl;
			return exitWith(ExitCode::Integrity);
		}

		// База — доверенный индекс, метаданные — отдельный документ. Если они расходятся,
		// под именем одного пакета подставлен другой.
		if (package_name != target_pkg) {
			std::cerr << "Error: metadata declares package '" << package_name
				<< "' but the database entry is '" << target_pkg << "'. Aborting." << std::endl;
			return exitWith(ExitCode::Integrity);
		}

		if (!isHttpsUrl(download_url)) {
			std::cerr << "Error: package URL must use https://. Refusing to download over an insecure channel." << std::endl;
			return exitWith(ExitCode::Integrity);
		}

		std::cout << "Version: " << package_version << std::endl;
		std::cout << "Downloading package from: " << download_url << std::endl;

		std::string app_dir = appsPath + "\\" + package_name;
		std::string temp_archive = tempPath + "\\" + package_name + ".zip";

		if (!downloadFile(download_url, temp_archive)) {
			std::cerr << "Failed to download the package archive." << std::endl;
			return exitWith(ExitCode::Network);
		}

		std::cout << "Archive downloaded. Verifying integrity..." << std::endl;

		// Verify the integrity of the downloaded archive using SHA256 hash
		std::string actual_hash = crypto::calculateSHA256(temp_archive);

		if (actual_hash.empty() || !equalsIgnoreAsciiCase(actual_hash, expected_hash)) {
			std::cerr << "Hash mismatch! The downloaded file may be corrupted or tampered with." << std::endl;
			std::cerr << "Expected: " << expected_hash << std::endl;
			std::cerr << "Actual:   " << actual_hash << std::endl;
			std::cerr << "The file might be corrupted or compromised. Aborting installation." << std::endl;

			deleteFile(temp_archive.c_str());
			return exitWith(ExitCode::Integrity);
		}

		std::cout << "Integrity verified. Extracting package..." << std::endl;

		if (!createDirectory(app_dir.c_str())) {
			std::cerr << "Error: could not create " << app_dir << std::endl;
			deleteFile(temp_archive.c_str());
			return exitWith(ExitCode::Error);
		}

		if (!extractArchive(temp_archive, app_dir)) {
			std::cerr << "Failed to extract package." << std::endl;
			deleteFile(temp_archive.c_str());
			return exitWith(ExitCode::Error);
		}

		deleteFile(temp_archive.c_str());
		std::cout << "Package " << package_name << " extracted successfully." << std::endl;

		// Запускается именно то, что было распаковано из проверенного архива.
		// Повторная загрузка download_url прямо в exe_path обходила проверку хэша целиком.
		std::error_code ec;
		std::string exe_path = app_dir + "\\" + bin_relative;

		if (!std::filesystem::is_regular_file(exe_path, ec)) {
			std::cerr << "Error: the archive does not contain '" << bin_name << "'. Aborting installation." << std::endl;
			std::filesystem::remove_all(app_dir, ec);
			return exitWith(ExitCode::Integrity);
		}

		std::cout << "Package successfully installed to: " << exe_path << std::endl;

		// Имя команды — последний сегмент пути без расширения .exe (в любом регистре).
		std::string command_name = bin_relative.substr(bin_relative.find_last_of('\\') + 1);
		if (command_name.length() > 4 &&
			equalsIgnoreAsciiCase(command_name.substr(command_name.length() - 4), ".exe")) {
			command_name = command_name.substr(0, command_name.length() - 4);
		}

		if (!isSafeName(command_name)) {
			std::cerr << "Error: '" << bin_name << "' does not yield a valid command name." << std::endl;
			std::filesystem::remove_all(app_dir, ec);
			return exitWith(ExitCode::Integrity);
		}

		// temporary band-aid solution for creating a shim for the executable
		std::string shim_path = binPath + "\\" + command_name + ".bat";
		std::ofstream shim_file(shim_path);

		if (shim_file.is_open()) {
			shim_file << "@echo off\n";
			shim_file << "\"" << exe_path << "\" %*\n";
			shim_file.close();
			std::cout << "Shim created. Now you can use '" << command_name << "' in your terminal!" << std::endl;
		}
		else {
			std::cerr << "Warning: failed to create shim file for " << command_name << std::endl;
		}

		// Трекинг установленного пакета через локальный реестр
		std::string registry_path = userDir + "\\installed.json";
		json registry;

		// Попытка его прочитать. Повреждённый файл — не повод падать: начинаем с чистого листа.
		if (!readJsonFile(registry_path, registry) || !registry.is_object()) {
			registry = json::object();
		}

		registry[package_name] = {
			{"id", targetEntry->meta_id},
			{"version", package_version},
			{"shim", command_name}
		};

		std::ofstream reg_out(registry_path);
		if (reg_out.is_open())
		{
			reg_out << registry.dump(4);
			reg_out.close();
			std::cout << "Registry updated. " << package_name << " is now tracked by flan." << std::endl;
		}
		else {
			std::cerr << "Warning: Failed to update local registry." << std::endl;
		}
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

	else if (command == "list") {
		CoreHeader header = {};
		std::vector<PackageRecord> packages;

		if (!loadDatabase(dbPath + "\\core.flan", header, packages)) {
			return exitWith(ExitCode::Error);
		}

		std::cout << "Database version: " << header.db_version << std::endl;
		std::cout << "Available packages: " << header.package_count << std::endl;
		std::cout << "------------------------------" << std::endl;

		for (const PackageRecord& record : packages) {
			std::cout << "[" << record.meta_id << "] " << record.name
				<< " (Hash: " << std::hex << record.hash_v << std::dec << ")" << std::endl;
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
