#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "build.hpp"
#include "flan/format.hpp"
#include "flan/hex.hpp"
#include "flan/index.hpp"
#include "flan/validate.hpp"
#include <algorithm>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>

// flan-build — генератор индекса (DESIGN.md §8). До этапа 4 индекс не подписан, до этапа 2 — не сжат.

namespace {

	void printUsage() {
		std::cout << "Usage:" << std::endl;
		std::cout << "  flan-build check <packages-dir>" << std::endl;
		std::cout << "  flan-build hash <manifest.json> [--force]" << std::endl;
		std::cout << "  flan-build index <packages-dir> -o <index.flan>" << std::endl;
	}

	fs::path absoluteNormal(const fs::path& path) {
		fs::path result = fs::absolute(path).lexically_normal();
		if (!result.has_filename()) {
			result = result.parent_path();							// "packages\" -> "packages"
		}
		return result;
	}

	// Корень репозитория пакетов — каталог над packages\: там лежат index.flan и .cache\.
	fs::path repositoryRootOf(const fs::path& packagesDir) {
		return absoluteNormal(packagesDir).parent_path();
	}

	bool readFile(const fs::path& path, uint64_t limit, std::vector<uint8_t>& out, std::string& error) {
		std::ifstream in(path, std::ios::binary);
		if (!in) {
			error = "cannot open " + path.string();
			return false;
		}

		in.seekg(0, std::ios::end);
		const std::streamoff size = in.tellg();
		if (size < 0 || (uint64_t)size > limit) {
			error = path.string() + " is too large";
			return false;
		}
		in.seekg(0, std::ios::beg);

		out.resize((size_t)size);
		if (size > 0 && !in.read(reinterpret_cast<char*>(out.data()), size)) {
			error = "cannot read " + path.string();
			return false;
		}
		return true;
	}

	// Предыдущий индекс: файла нет — не ошибка; есть, но не проходит проверку — ошибка,
	// потому что на нём держатся правила hash и монотонность generated_at.
	bool loadPreviousIndex(const fs::path& path, IndexView& view, bool& exists, std::string& error) {
		std::error_code ec;
		exists = fs::exists(path, ec);
		if (!exists) {
			return true;
		}

		std::vector<uint8_t> file;
		if (!readFile(path, MAX_INDEX_FILE_SIZE, file, error)) {
			return false;
		}

		// Подписанный предыдущий индекс проверяется подписью; неподписанный допустим только здесь —
		// поверх него собирается первый подписанный (DESIGN.md §8, «Подпись индекса»).
		IndexTrust trust = builtInTrust();
		trust.allowUnsigned = true;
		if (!view.open(std::move(file), error, trust) || !view.validateAll(error)) {
			error = "previous index " + path.string() + " is invalid: " + error;
			return false;
		}
		return true;
	}

	bool loadManifests(const fs::path& packagesDir, bool requireHash, std::vector<Manifest>& manifests) {
		std::error_code ec;
		if (!fs::is_directory(packagesDir, ec)) {
			std::cerr << "Error: " << packagesDir.string() << " is not a directory." << std::endl;
			return false;
		}

		std::vector<fs::path> files;
		for (const fs::directory_entry& entry : fs::directory_iterator(packagesDir, ec)) {
			if (!entry.is_regular_file()) {
				continue;
			}
			if (entry.path().extension() == ".json") {
				files.push_back(entry.path());
			}
			else {
				std::cerr << "Warning: ignoring " << entry.path().filename().string() << " (not a .json manifest)" << std::endl;
			}
		}
		if (ec) {
			std::cerr << "Error: cannot list " << packagesDir.string() << ": " << ec.message() << std::endl;
			return false;
		}

		if (files.empty()) {
			std::cerr << "Error: no manifests in " << packagesDir.string() << std::endl;
			return false;
		}

		std::sort(files.begin(), files.end());

		std::vector<std::string> errors;
		std::set<std::string> names;
		for (const fs::path& file : files) {
			Manifest manifest;
			if (!loadManifest(file, requireHash, manifest, errors)) {
				continue;
			}
			if (!names.insert(manifest.name).second) {
				errors.push_back(file.filename().string() + ": duplicate package name '" + manifest.name + "'");
				continue;
			}
			manifests.push_back(std::move(manifest));
		}

		for (const std::string& error : errors) {
			std::cerr << "Error: " << error << std::endl;
		}
		return errors.empty();
	}

	int commandCheck(const fs::path& packagesDir) {
		std::vector<Manifest> manifests;
		if (!loadManifests(packagesDir, true, manifests)) {
			return 1;
		}

		size_t builds = 0;
		for (const Manifest& manifest : manifests) {
			builds += manifest.targets.size();
		}

		std::cout << "OK: " << manifests.size() << " manifest(s), " << builds << " build(s)." << std::endl;
		return 0;
	}

	int commandHash(const fs::path& manifestPath, bool force) {
		Manifest manifest;
		std::vector<std::string> errors;
		if (!loadManifest(manifestPath, false, manifest, errors)) {
			for (const std::string& error : errors) {
				std::cerr << "Error: " << error << std::endl;
			}
			return 1;
		}

		const fs::path root = absoluteNormal(manifestPath).parent_path().parent_path();
		const fs::path cacheDir = root / ".cache";

		IndexView previous;
		bool hasPrevious = false;
		std::string error;
		if (!loadPreviousIndex(root / "index.flan", previous, hasPrevious, error)) {
			std::cerr << "Error: " << error << std::endl;
			return 1;
		}

		struct Decision {
			std::string archKey;
			std::string oldHash;								// из манифеста; может быть пустым
			std::string newHash;
		};
		std::vector<Decision> decisions;
		std::vector<std::string> warnings;
		bool failed = false;

		for (const ArchTarget& target : manifest.targets) {
			const std::string label = manifest.name + " " + target.archKey + ": ";
			std::cout << label << "downloading " << target.url << std::endl;

			CachedArchive archive;
			if (!downloadToCache(target.url, cacheDir, archive, error) ||
				!verifyPackageContents(archive.path, target, manifest.bins, error)) {
				std::cerr << "Error: " << label << error << std::endl;
				failed = true;
				continue;
			}

			// Правило DESIGN.md §8: тот же URL, что в предыдущем индексе, но другой хэш —
			// апстрим подменил файл под той же ссылкой. Без --force это ошибка.
			if (hasPrevious) {
				IndexRecord old;
				const FindResult found = previous.find(manifest.name, target.arch, old, error);
				if (found == FindResult::Corrupt) {
					std::cerr << "Error: previous index: " << error << std::endl;
					return 1;
				}

				const std::string oldHash = found == FindResult::Found ? toHex(old.sha256, sizeof(old.sha256)) : "";
				if (found == FindResult::Found && old.url == target.url && oldHash != archive.sha256) {
					if (!force) {
						std::cerr << "Error: " << label << "the file at the same URL has changed since the previous index." << std::endl;
						std::cerr << "  url:      " << target.url << std::endl;
						std::cerr << "  index:    " << oldHash << std::endl;
						std::cerr << "  download: " << archive.sha256 << std::endl;
						std::cerr << "  If the upstream re-uploaded it legitimately, run again with --force." << std::endl;
						failed = true;
						continue;
					}

					warnings.push_back(label + "accepted a NEW hash for an UNCHANGED URL (--force)\n"
						"  url: " + target.url + "\n  old: " + oldHash + "\n  new: " + archive.sha256);
				}
			}

			decisions.push_back(Decision{ target.archKey, target.sha256, archive.sha256 });
		}

		if (failed) {
			std::cerr << "Nothing was written to " << manifestPath.filename().string() << "." << std::endl;
			return 1;
		}

		// Повторный hash без изменений не трогает файл вовсе: ни байты, ни время изменения.
		const bool changed = std::any_of(decisions.begin(), decisions.end(),
			[](const Decision& decision) { return decision.oldHash != decision.newHash; });

		if (changed) {
			for (const Decision& decision : decisions) {
				manifest.document["arch"][decision.archKey]["sha256"] = decision.newHash;
			}

			if (!saveManifest(manifest, error)) {
				std::cerr << "Error: " << error << std::endl;
				return 1;
			}
		}

		for (const Decision& decision : decisions) {
			std::cout << manifest.name << " " << decision.archKey << ": sha256 " << decision.newHash;
			if (decision.oldHash.empty()) {
				std::cout << " (filled in)";
			}
			else if (decision.oldHash == decision.newHash) {
				std::cout << " (unchanged)";
			}
			else {
				std::cout << " (was " << decision.oldHash << ")";
			}
			std::cout << std::endl;
		}

		for (const std::string& warning : warnings) {
			std::cerr << "WARNING: " << warning << std::endl;
		}

		if (changed) {
			std::cout << "Updated " << manifestPath.filename().string() << "." << std::endl;
		}
		else {
			std::cout << manifestPath.filename().string() << " is up to date; nothing written." << std::endl;
		}
		return 0;
	}

	int commandIndex(const fs::path& packagesDir, const fs::path& outputPath) {
		std::vector<Manifest> manifests;
		if (!loadManifests(packagesDir, true, manifests)) {
			return 1;
		}

		const fs::path cacheDir = repositoryRootOf(packagesDir) / ".cache";
		std::vector<BuildEntry> entries;
		std::string error;
		bool failed = false;

		for (const Manifest& manifest : manifests) {
			for (const ArchTarget& target : manifest.targets) {
				const std::string label = manifest.name + " " + target.archKey + ": ";

				// Кэш по sha256 — сеть нужна только для того, чего в кэше ещё нет.
				CachedArchive archive;
				if (!findInCache(cacheDir, target.sha256, archive)) {
					std::cout << label << "downloading " << target.url << std::endl;
					if (!downloadToCache(target.url, cacheDir, archive, error)) {
						std::cerr << "Error: " << label << error << std::endl;
						failed = true;
						continue;
					}
					if (archive.sha256 != target.sha256) {
						std::cerr << "Error: " << label << "the archive does not match sha256 in the manifest" << std::endl;
						std::cerr << "  manifest: " << target.sha256 << std::endl;
						std::cerr << "  download: " << archive.sha256 << std::endl;
						std::cerr << "  Run flan-build hash " << manifest.path.filename().string() << " to review the change." << std::endl;
						failed = true;
						continue;
					}
				}

				if (!verifyPackageContents(archive.path, target, manifest.bins, error)) {
					std::cerr << "Error: " << label << error << std::endl;
					failed = true;
					continue;
				}

				if (archive.size == 0 || archive.size > MAX_ARCHIVE_SIZE) {
					std::cerr << "Error: " << label << "archive size " << archive.size << " is out of bounds" << std::endl;
					failed = true;
					continue;
				}

				BuildEntry entry;
				entry.name = manifest.name;
				entry.version = manifest.version;
				entry.url = target.url;
				entry.extractDir = target.extractDir;
				entry.binList = manifest.binList;
				entry.description = manifest.description;
				entry.archiveSize = (uint32_t)archive.size;
				entry.arch = target.arch;
				entry.kind = target.kind;
				fromHex(target.sha256, entry.sha256, sizeof(entry.sha256));
				entries.push_back(entry);
			}
		}

		if (failed) {
			std::cerr << "Index was not written." << std::endl;
			return 1;
		}

		// generated_at — текущее время, но не меньше, чем в предыдущем индексе + 1 (DESIGN.md §8).
		IndexView previous;
		bool hasPrevious = false;
		if (!loadPreviousIndex(outputPath, previous, hasPrevious, error)) {
			std::cerr << "Error: " << error << std::endl;
			return 1;
		}

		uint64_t generatedAt = (uint64_t)std::time(nullptr);
		if (hasPrevious && generatedAt <= previous.generatedAt()) {
			generatedAt = previous.generatedAt() + 1;
		}

		std::vector<uint8_t> file;
		if (!buildIndexFile(entries, generatedAt, file, error)) {
			std::cerr << "Error: " << error << std::endl;
			return 1;
		}

		// Самопроверка: собранный файл читается тем же кодом, что и в клиенте,
		// и каждая сборка находится с теми же данными, что ушли в запись.
		// До подписи в генераторе (этап 4, шаг 4) индекс ещё не подписан и клиентом не принимается.
		IndexTrust unsignedForNow = builtInTrust();
		unsignedForNow.allowUnsigned = true;
		IndexView check;
		if (!check.open(file, error, unsignedForNow) || !check.validateAll(error)) {
			std::cerr << "Error: the generated index is rejected by the client validator: " << error << std::endl;
			return 1;
		}

		for (const BuildEntry& entry : entries) {
			IndexRecord found;
			if (check.find(entry.name, entry.arch, found, error) != FindResult::Found ||
				found.url != entry.url || found.archiveSize != entry.archiveSize ||
				std::memcmp(found.sha256, entry.sha256, sizeof(entry.sha256)) != 0) {
				std::cerr << "Error: the generated index does not round-trip " << entry.name << " / " << archName(entry.arch) << std::endl;
				return 1;
			}
		}

		if (!writeFileAtomically(outputPath, file.data(), file.size(), error)) {
			std::cerr << "Error: " << error << std::endl;
			return 1;
		}

		std::cout << "Wrote " << outputPath.string() << ": " << manifests.size() << " package(s), "
			<< entries.size() << " build(s), " << file.size() << " bytes, generated_at " << generatedAt << "." << std::endl;
		return 0;
	}
}

int main(int argc, char* argv[]) {
	SetConsoleOutputCP(CP_UTF8);

	if (argc < 2) {
		printUsage();
		return 2;
	}

	const std::string command = argv[1];
	std::vector<std::string> positional;
	bool force = false;
	std::string output;

	for (int i = 2; i < argc; i++) {
		const std::string arg = argv[i];
		if (arg == "--force" && command == "hash") {
			force = true;
		}
		else if (arg == "-o" && command == "index" && i + 1 < argc) {
			output = argv[++i];
		}
		else if (!arg.empty() && arg[0] == '-') {
			std::cerr << "Error: unknown option " << arg << std::endl;
			printUsage();
			return 2;
		}
		else {
			positional.push_back(arg);
		}
	}

	try {
		if (command == "check" && positional.size() == 1) {
			return commandCheck(positional[0]);
		}
		if (command == "hash" && positional.size() == 1) {
			return commandHash(positional[0], force);
		}
		if (command == "index" && positional.size() == 1 && !output.empty()) {
			return commandIndex(positional[0], output);
		}
	}
	catch (const std::exception& e) {
		// nlohmann и <filesystem> бросают исключения; генератору они разрешены (DESIGN.md §8),
		// но выходить он должен понятной ошибкой, а не через std::terminate.
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}

	printUsage();
	return 2;
}
