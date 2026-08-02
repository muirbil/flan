#include "network/WinHTTP.hpp"
#include <iostream>
#include <string>
#include "utils/fileSystem.hpp"
#include <fstream>
#include "core/format.hpp"
#include "utils/json.hpp"

using json = nlohmann::json;

int main(int argc, char* argv[]) {

	if (argc < 2) {
		std::cout << "Usage: flan <command> [options]" << std::endl;
		std::cout << "Commands: sync, install, uninstall" << std::endl;
		return 1;
	}

	std::string command = argv[1];
	std::string userDir = getUserDirectory();

	std::string dbPath = userDir + "\\db";
	std::string cachePath = userDir + "\\cache";
	std::string appsPath = userDir + "\\apps";
	std::string binPath = userDir + "\\bin";
	std::string tempPath = userDir + "\\temp";

	if (command == "sync") {
		std::cout << "Synchronizing database..." << std::endl;

		createDirectory(dbPath.c_str());
		createDirectory(cachePath.c_str());
		createDirectory(appsPath.c_str());
		createDirectory(binPath.c_str());
		createDirectory(tempPath.c_str());

		std::cout << "Synchronized successfully." << std::endl;

		// File to DB
		std::string dbFile = dbPath + "\\core.flan";

		std::string testUrl = "https://raw.githubusercontent.com/microsoft/winget-cli/master/README.md";
		std::cout << "Downloading database from: " << testUrl << std::endl;

		if (downloadFile(testUrl, dbFile))
		{
			std::cout << "Database successfully downloaded to: " << dbFile << std::endl;
		}
		else {
			std::cerr << "Failed to download database." << std::endl;
		}
	}

	else if (command == "install") {
		if (argc < 3)
		{
			std::cerr << "Please specify a package to install." << std::endl;
			std::cerr << "Usage: flan install <package_name>" << std::endl;
			return 1;
		}

		std::string target_pkg = argv[2];
		std::cout << "Looking for '" << target_pkg << "' in the database..." << std::endl;

		std::string dbFile = userDir + "\\db\\core.flan";
		std::ifstream in(dbFile, std::ios::binary);
		if (!in) {
			std::cerr << "Database not found! Please run 'flan sync' first." << std::endl;
			return 1;
		}

		CoreHeader header = {};
		in.read(reinterpret_cast<char*>(&header), sizeof(CoreHeader));

		if (header.magic != FLAN_MAGIC) {
			std::cerr << "Database file is corrupted!" << std::endl;
			return 1;
		}

		bool found = false;
		CoreEntry targetEntry = {};

		for (uint32_t i = 0; i < header.package_count; i++)
		{
			CoreEntry entry = {};
			std::streampos entryPos = sizeof(CoreHeader) + (i * sizeof(CoreEntry));
			in.seekg(entryPos, std::ios::beg);
			in.read(reinterpret_cast<char*>(&entry), sizeof(CoreEntry));

			std::streampos namePos = header.string_pool_offset + entry.name_offset;
			in.seekg(namePos, std::ios::beg);

			std::string pkg_name;
			std::getline(in, pkg_name, '\0');

			if (pkg_name == target_pkg) {
				found = true;
				targetEntry = entry;
				break;
			}

		}
		in.close();

		if (found) {
			std::cout << "Package [" << targetEntry.meta_id << "] '" << target_pkg << "' found in the database." << std::endl;
			std::cout << "Fetching Metadata..." << std::endl;

			std::string metadataUrl = "file:///C:/Users/equi/.flan/cache/101.meta";
			std::string metadataFile = cachePath + "\\" + std::to_string(targetEntry.meta_id) + ".meta";

			if (downloadFile(metadataUrl, metadataFile)) {
				std::cout << "Metadata successfully downloaded!" << std::endl;

				std::ifstream metaIn(metadataFile);
				if (!metaIn) {
					std::cerr << "Failed to open metadata file." << std::endl;
					return 1;
				}

				json metadata;
				try {
					metaIn >> metadata; // Читаем весь файл прямо в объект
				} catch (const json::parse_error& e) {
					std::cerr << "Failed to parse metadata JSON: " << e.what() << std::endl;
					return 1;
				}
				metaIn.close();

				std::string package_name = metadata["name"];
				std::string package_version = metadata["version"];
				std::string download_url = metadata["url"];
				std::string bin_name = metadata["bin"];

				std::cout << "Version: " << package_version << std::endl;
				std::cout << "Downloading package from: " << download_url << std::endl;

				std::string app_dir = userDir + "\\apps\\" + package_name; // change it later
				createDirectory(app_dir.c_str());

				std::string temp_dir = userDir + "\\temp";
				createDirectory(temp_dir.c_str());

				std::string temp_archive = temp_dir + "\\" + package_name + ".zip";

				if (downloadFile(download_url, temp_archive)) {
					std::cout << "Archive downloaded. Extracting..." << std::endl;

					// -x (extract), -f (file), -C (change directory to destination)
					std::string tar_cmd = "tar -xf \"" + temp_archive + "\" -C \"" + app_dir + "\"";

					int result = system(tar_cmd.c_str());

					if (result == 0) {
						std::string exe_path = app_dir + "\\" + bin_name;
						std::cout << "Package " + package_name + "extracted successfully." << std::endl;

						deleteFile(temp_archive.c_str());

					} else {
						std::cerr << "Failed to extract package. Error code: " << result << std::endl;
						return 1;
					}
				} else {
					std::cerr << "Failed to download the package archive." << std::endl;
					return 1;
				}

				std::string exe_path = app_dir + "\\" + bin_name;

				if (downloadFile(download_url, exe_path)) {
					std::cout << "Package successfully installed to: " << exe_path << std::endl;

					std::string bin_dir = userDir + "\\bin";
					createDirectory(bin_dir.c_str());

					std::string command_name = bin_name;
					if (command_name.length() >= 4 && command_name.substr(command_name.length() - 4) == ".exe") {
						command_name = command_name.substr(0, command_name.length() - 4);
					}

					// temporary band-aid solution for creating a shim for the executable
					std::string shim_path = bin_dir + "\\" + command_name + ".bat";
					std::ofstream shim_file(shim_path);

					if (shim_file.is_open()) {
						shim_file << "@echo off\n";
						shim_file << "\"" << exe_path << "\" %*\n";
						shim_file.close();
						std::cout << "Shim created. Now you can use '" << command_name << "' in your terminal!" << std::endl;

					} else {
						std::cerr << "Warning: failed to create shim file for" << command_name <<  std::endl;
					}

				} else {
					std::cerr << "Failed to download package." << std::endl;
				}

			} else {
				std::cerr << "Failed to fetch metadata for package." << std::endl;
			}

		} else {
			std::cerr << "Package '" << target_pkg << "' not found in the database." << std::endl;
			return 1;
		}

		std::cout << "Installing package..." << std::endl;

	}

	else if (command == "uninstall") {
		std::cout << "Uninstalling package..." << std::endl;
	}

	else if (command == "list") {
		std::string dbFile = userDir + "\\db\\core.flan";

		std::ifstream in(dbFile, std::ios::binary);
		if (!in) {
			std::cerr << "Database not found! Please run 'flan sync' first." << std::endl;
			return 1;
		}

		CoreHeader header = {};
		in.read(reinterpret_cast<char*>(&header), sizeof(CoreHeader));

		if (header.magic != FLAN_MAGIC) {
			std::cerr << "Database file is corrupted!" << std::endl;
			return 1;
		}

		std::cout << "Database version: " << header.db_version << std::endl;
		std::cout << "Available packages: " << header.package_count << std::endl;
		std::cout << "------------------------------" << std::endl;

		// Read package entries
		for  (uint32_t i = 0; i < header.package_count; i++) {
			CoreEntry entry = {};

			std::streampos entryPos = sizeof(CoreHeader) + (i * sizeof(CoreEntry));

			in.seekg(entryPos, std::ios::beg);
			in.read(reinterpret_cast<char*>(&entry), sizeof(CoreEntry));

			std::streampos namePos = header.string_pool_offset + entry.name_offset;
			
			in.seekg(namePos, std::ios::beg);

			std::string pkg_name;
			std::getline(in, pkg_name, '\0');
			std::cout << "[" << entry.meta_id << "] " << pkg_name
				<< " (Hash: " << std::hex << entry.hash_v << std::dec << ")" << std::endl;
		}

		in.close();

	}

	else if (command == "generate") {
		std::cout << "Generating database..." << std::endl;

		CoreHeader header;
		header.timestamp = 1680000000;
		header.magic = FLAN_MAGIC;
		header.db_version = 1;
		header.package_count = 2;

		header.string_pool_offset = sizeof(CoreHeader) + (sizeof(CoreEntry) * header.package_count);

		CoreEntry pkg1;
		pkg1.hash_v = 1234567890123456789;
		pkg1.name_offset = 0;
		pkg1.meta_id = 1;

		CoreEntry pkg2;
		pkg2.hash_v = 9876543210987654321;
		pkg2.name_offset = 8;
		pkg2.meta_id = 2;

		const char string_pool[] = "Package1\0Package2\0";
		size_t pool_size = sizeof(string_pool);

		std::string dbPath = userDir + "\\db";
		std::string dbFile = dbPath + "\\core.flan";

		std::ofstream out(dbFile, std::ios::binary);
		if (!out) {
			std::cerr << "Couldn't create db file!" << std::endl;
			return 1;
		}

		out.write(reinterpret_cast<const char*>(&header), sizeof(CoreHeader));
		out.write(reinterpret_cast<const char*>(&pkg1), sizeof(CoreEntry));
		out.write(reinterpret_cast<const char*>(&pkg2), sizeof(CoreEntry));
		out.write(string_pool, pool_size);
		out.close();

		std::cout << "Database generated successfully at: " << dbFile << std::endl;
	} else {
		std::cerr << "Unknown command: " << command << std::endl;
	}
}
