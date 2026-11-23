#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "build.hpp"
#include "keystore.hpp"
#include "signing.hpp"
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

// flan-build — генератор индекса и его ключей (DESIGN.md §8, §6.3).

namespace {

	void printUsage() {
		std::cout << "Usage:" << std::endl;
		std::cout << "  flan-build check <packages-dir>" << std::endl;
		std::cout << "  flan-build hash <manifest.json> [--force]" << std::endl;
		std::cout << "  flan-build index <packages-dir> -o <index.flan> [--key <working-key>]" << std::endl;
		std::cout << "  flan-build keygen --backup <dir> [--id N] [--key <working-key>]" << std::endl;
		std::cout << "  flan-build key restore <backup> [--key <working-key>]" << std::endl;
		std::cout << "  flan-build key check [--key <working-key>] [--backup <backup>]" << std::endl;
	}

	// ----- Ключи (DESIGN.md §6.3) -----

	// Рабочая копия: --key или самая новая в %LOCALAPPDATA%\flan-build. Ключ обязан быть в keys.hpp.
	bool loadSigningKey(const std::string& option, SigningKey& key, fs::path& path, bool requireBuiltIn) {
		std::string error;
		if (!option.empty()) {
			path = fs::u8path(option);
		}
		else {
			fs::path directory;
			if (!defaultKeyDirectory(directory, error)) {
				std::cerr << "Error: " << error << std::endl;
				return false;
			}
			if (!findNewestWorkingKey(directory, path)) {
				std::cerr << "Error: no signing key in " << directory.u8string()
					<< ". Create one with 'flan-build keygen' or restore it with 'flan-build key restore'." << std::endl;
				return false;
			}
		}

		if (!loadWorkingKey(path, key, error)) {
			std::cerr << "Error: " << error << "." << std::endl;
			return false;
		}
		if (requireBuiltIn && !matchesBuiltInKey(key, error)) {
			std::cerr << "Error: " << path.u8string() << ": " << error << "." << std::endl;
			return false;
		}
		return true;
	}

	// Ключ и резервные копии — только вне рабочих деревьев git (§6.3, «Защита от промахов»).
	bool outsideGit(const fs::path& path) {
		fs::path repo;
		if (insideGitWorkTree(path, repo)) {
			std::cerr << "Error: " << path.u8string() << " is inside the git work tree " << repo.u8string()
				<< ". Keys and their backups are never written there." << std::endl;
			return false;
		}
		return true;
	}

	bool askPassphrase(bool twice, std::wstring& passphrase) {
		std::string error;
		if (!readPassphrase(twice ? "New passphrase (at least 12 characters; 5-6 random words are best): " : "Passphrase: ",
			passphrase, error)) {
			std::cerr << "Error: " << error << "." << std::endl;
			return false;
		}
		if (!twice) {
			return true;
		}
		if (passphrase.size() < MIN_PASSPHRASE_LENGTH) {
			std::cerr << "Error: the passphrase is shorter than " << MIN_PASSPHRASE_LENGTH << " characters." << std::endl;
			wipe(passphrase);
			return false;
		}
		std::wstring repeat;
		if (!readPassphrase("Repeat the passphrase: ", repeat, error)) {
			std::cerr << "Error: " << error << "." << std::endl;
			wipe(passphrase);
			return false;
		}
		const bool same = repeat == passphrase;
		wipe(repeat);
		if (!same) {
			std::cerr << "Error: the passphrases differ." << std::endl;
			wipe(passphrase);
			return false;
		}
		return true;
	}

	bool isTestKeyId(int id) {
		return id >= FIRST_TEST_KEY_ID;
	}

	// Резервная копия записывается и сразу читается обратно той же фразой.
	bool writeBackup(const fs::path& path, const SigningKey& key, const std::wstring& passphrase) {
		std::vector<uint8_t> bytes;
		std::string error;
		if (!encodeBackup(key, passphrase, BACKUP_ITERATIONS, bytes, error) || !writeNewFile(path, bytes, error)) {
			std::cerr << "Error: " << error << "." << std::endl;
			return false;
		}
		std::vector<uint8_t> back;
		SigningKey check;
		if (!readSmallFile(path, back, error) || !decodeBackup(back, passphrase, check, error) ||
			std::memcmp(check.privateKey, key.privateKey, 32) != 0 || std::memcmp(check.publicKey, key.publicKey, 64) != 0) {
			std::cerr << "Error: the backup " << path.u8string() << " does not read back: " << error << "." << std::endl;
			return false;
		}
		return true;
	}

	int commandKeygen(const std::string& backupOption, int id, const std::string& keyOption) {
		if (id < 1 || id > 254) {
			std::cerr << "Error: --id must be 1..254 (the next number is the reserve key)." << std::endl;
			return 2;
		}
#ifndef _DEBUG
		if (isTestKeyId(id) || isTestKeyId(id + 1)) {
			std::cerr << "Error: key numbers " << (int)FIRST_TEST_KEY_ID << " and up are test keys, known only to Debug builds." << std::endl;
			return 2;
		}
#endif
		std::error_code ec;
		const fs::path backupDir = fs::absolute(fs::u8path(backupOption), ec);
		if (backupOption.empty() || !fs::is_directory(backupDir, ec)) {
			std::cerr << "Error: --backup must name an existing folder, for example a USB stick." << std::endl;
			return 2;
		}

		std::string error;
		fs::path workingPath;
		if (!keyOption.empty()) {
			workingPath = fs::absolute(fs::u8path(keyOption), ec);
		}
		else {
			fs::path directory;
			if (!defaultKeyDirectory(directory, error)) {
				std::cerr << "Error: " << error << std::endl;
				return 1;
			}
			workingPath = defaultWorkingKeyPath(directory, (uint8_t)id);
		}

		const fs::path backupWorking = backupDir / backupFileName((uint8_t)id);
		const fs::path backupReserve = backupDir / backupFileName((uint8_t)(id + 1));
		if (!outsideGit(workingPath) || !outsideGit(backupDir)) {
			return 1;
		}
		for (const fs::path& path : { workingPath, backupWorking, backupReserve }) {
			if (fs::exists(path, ec)) {
				std::cerr << "Error: " << path.u8string() << " already exists; key files are never overwritten." << std::endl;
				return 1;
			}
		}

		std::wstring passphrase;
		if (!askPassphrase(true, passphrase)) {
			return 1;
		}

		SigningKey working;
		SigningKey reserve;
		if (!generateSigningKey((uint8_t)id, working, error) || !generateSigningKey((uint8_t)(id + 1), reserve, error)) {
			wipe(passphrase);
			std::cerr << "Error: " << error << "." << std::endl;
			return 1;
		}

		const bool backedUp = writeBackup(backupWorking, working, passphrase) && writeBackup(backupReserve, reserve, passphrase);
		wipe(passphrase);
		if (!backedUp) {
			return 1;
		}

		fs::create_directories(workingPath.parent_path(), ec);
		SigningKey check;
		if (!saveWorkingKey(workingPath, working, error) || !loadWorkingKey(workingPath, check, error) ||
			std::memcmp(check.privateKey, working.privateKey, 32) != 0) {
			std::cerr << "Error: " << error << "." << std::endl;
			return 1;
		}

		if (isTestKeyId(id)) {
			std::cout << "These are TEST keys: only Debug builds know numbers " << (int)FIRST_TEST_KEY_ID << " and up." << std::endl;
		}
		std::cout << "Key " << id << " (working), fingerprint " << keyFingerprint(working.publicKey) << std::endl;
		std::cout << "  working copy (DPAPI, this Windows user only): " << workingPath.u8string() << std::endl;
		std::cout << "  backup (passphrase):                          " << backupWorking.u8string() << std::endl;
		std::cout << "Key " << (id + 1) << " (reserve), fingerprint " << keyFingerprint(reserve.publicKey) << std::endl;
		std::cout << "  backup only (passphrase):                     " << backupReserve.u8string() << std::endl;
		std::cout << std::endl << "Public keys for include/flan/keys.hpp:" << std::endl;
		std::cout << keyAsCppEntry(working.id, working.publicKey) << keyAsCppEntry(reserve.id, reserve.publicKey);
		std::cout << std::endl << "Both backups were read back with the passphrase. Copy them to a second place, keep the passphrase"
			" apart from them, and check them with 'flan-build key check --backup <file>'." << std::endl;
		return 0;
	}

	int commandKeyRestore(const std::string& backupOption, const std::string& keyOption) {
		const fs::path backupPath = fs::u8path(backupOption);
		std::vector<uint8_t> bytes;
		std::string error;
		uint8_t id = 0;
		uint8_t publicKey[64];
		if (!readSmallFile(backupPath, bytes, error) || !peekBackup(bytes, id, publicKey, error)) {
			std::cerr << "Error: " << backupPath.u8string() << ": " << error << "." << std::endl;
			return 1;
		}

		std::error_code ec;
		fs::path workingPath;
		if (!keyOption.empty()) {
			workingPath = fs::absolute(fs::u8path(keyOption), ec);
		}
		else {
			fs::path directory;
			if (!defaultKeyDirectory(directory, error)) {
				std::cerr << "Error: " << error << std::endl;
				return 1;
			}
			workingPath = defaultWorkingKeyPath(directory, id);
		}
		if (!outsideGit(workingPath)) {
			return 1;
		}
		if (fs::exists(workingPath, ec)) {
			std::cerr << "Error: " << workingPath.u8string() << " already exists; key files are never overwritten." << std::endl;
			return 1;
		}

		std::cout << "Restoring key " << (int)id << ", fingerprint " << keyFingerprint(publicKey) << std::endl;
		std::wstring passphrase;
		if (!askPassphrase(false, passphrase)) {
			return 1;
		}
		SigningKey key;
		const bool decoded = decodeBackup(bytes, passphrase, key, error);
		wipe(passphrase);
		if (!decoded) {
			std::cerr << "Error: " << error << "." << std::endl;
			return 1;
		}

		fs::create_directories(workingPath.parent_path(), ec);
		SigningKey check;
		if (!saveWorkingKey(workingPath, key, error) || !loadWorkingKey(workingPath, check, error)) {
			std::cerr << "Error: " << error << "." << std::endl;
			return 1;
		}
		std::cout << "Wrote the working copy (DPAPI): " << workingPath.u8string() << std::endl;
		if (!matchesBuiltInKey(key, error)) {
			std::cout << "Note: " << error << "." << std::endl;
		}
		return 0;
	}

	int commandKeyCheck(const std::string& keyOption, const std::string& backupOption) {
		bool failed = false;
		bool checkedSomething = false;
		std::string error;

		// Рабочая копия — если указана или есть в каталоге по умолчанию.
		fs::path directory;
		fs::path newest;
		const bool haveDefault = keyOption.empty() && defaultKeyDirectory(directory, error) && findNewestWorkingKey(directory, newest);
		if (!keyOption.empty() || haveDefault || backupOption.empty()) {
			SigningKey key;
			fs::path path;
			if (loadSigningKey(keyOption, key, path, true)) {
				std::cout << "OK: working copy " << path.u8string() << ": key " << (int)key.id << ", fingerprint "
					<< keyFingerprint(key.publicKey) << ", matches keys.hpp." << std::endl;
			}
			else {
				failed = true;
			}
			checkedSomething = true;
		}

		if (!backupOption.empty()) {
			const fs::path backupPath = fs::u8path(backupOption);
			std::vector<uint8_t> bytes;
			uint8_t id = 0;
			uint8_t publicKey[64];
			if (!readSmallFile(backupPath, bytes, error) || !peekBackup(bytes, id, publicKey, error)) {
				std::cerr << "Error: " << backupPath.u8string() << ": " << error << "." << std::endl;
				return 1;
			}
			std::cout << "Backup " << backupPath.u8string() << ": key " << (int)id << ", fingerprint " << keyFingerprint(publicKey) << std::endl;
			std::wstring passphrase;
			if (!askPassphrase(false, passphrase)) {
				return 1;
			}
			SigningKey key;
			const bool decoded = decodeBackup(bytes, passphrase, key, error);
			wipe(passphrase);
			if (!decoded || !matchesBuiltInKey(key, error)) {
				std::cerr << "Error: " << backupPath.u8string() << ": " << error << "." << std::endl;
				failed = true;
			}
			else {
				std::cout << "OK: the backup decrypts and matches keys.hpp." << std::endl;
			}
			checkedSomething = true;
		}
		return failed || !checkedSomething ? 1 : 0;
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

			// Пакет flan и зарезервированная команда flan (DESIGN.md §5.3) — те же правила, что в клиенте.
			bool claimsFlan = false;
			for (const std::string& bin : manifest.bins) {
				claimsFlan = claimsFlan || toLowerAscii(commandNameFromBin(bin)) == "flan";
			}
			if (manifest.name == "flan") {
				bool allExe = !manifest.targets.empty();
				for (const ArchTarget& target : manifest.targets) {
					allExe = allExe && target.kind == KIND_EXE;
				}
				if (manifest.bins.size() != 1 || manifest.bins[0] != "flan.exe" || !allExe) {
					errors.push_back(file.filename().string() + ": the flan package must be a single flan.exe with kind exe for every arch");
					continue;
				}
			}
			else if (claimsFlan) {
				errors.push_back(file.filename().string() + ": the command 'flan' is reserved for flan itself");
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

	int commandIndex(const fs::path& packagesDir, const fs::path& outputPath, const std::string& keyOption) {
		std::vector<Manifest> manifests;
		if (!loadManifests(packagesDir, true, manifests)) {
			return 1;
		}

		// Ключ — до загрузок: без него индекс всё равно не выйдет (DESIGN.md §8, «Подпись индекса»).
		SigningKey key;
		fs::path keyPath;
		if (!loadSigningKey(keyOption, key, keyPath, true)) {
			return 1;
		}
		std::cout << "Signing with key " << (int)key.id << " (" << keyPath.u8string() << "), fingerprint "
			<< keyFingerprint(key.publicKey) << "." << std::endl;

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

		// Номер ключа не убывает: клиенты, принявшие предыдущий индекс, отвергли бы старый ключ (§6.1, шаг 6).
		if (hasPrevious && previous.keyId() > key.id) {
			std::cerr << "Error: the previous index is signed with key " << (int)previous.keyId() << "; clients that accepted it "
				"reject key " << (int)key.id << ". Sign with key " << (int)previous.keyId() << " or newer." << std::endl;
			return 1;
		}

		uint64_t generatedAt = (uint64_t)std::time(nullptr);
		if (hasPrevious && generatedAt <= previous.generatedAt()) {
			generatedAt = previous.generatedAt() + 1;
		}

		std::vector<uint8_t> file;
		if (!buildIndexFile(entries, generatedAt, key, file, error)) {
			std::cerr << "Error: " << error << std::endl;
			return 1;
		}

		// Самопроверка: собранный файл читается тем же кодом и с теми же встроенными ключами,
		// что и в клиенте, и каждая сборка находится с теми же данными, что ушли в запись.
		IndexView check;
		if (!check.open(file, error) || !check.validateAll(error)) {
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
			<< entries.size() << " build(s), " << file.size() << " bytes, generated_at " << generatedAt
			<< ", signed with key " << (int)key.id << "." << std::endl;
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
	std::string keyOption;
	std::string backupOption;
	std::string idOption;
	const bool keyCommand = command == "keygen" || command == "key";

	for (int i = 2; i < argc; i++) {
		const std::string arg = argv[i];
		if (arg == "--force" && command == "hash") {
			force = true;
		}
		else if (arg == "-o" && command == "index" && i + 1 < argc) {
			output = argv[++i];
		}
		else if (arg == "--key" && (command == "index" || keyCommand) && i + 1 < argc) {
			keyOption = argv[++i];
		}
		else if (arg == "--backup" && keyCommand && i + 1 < argc) {
			backupOption = argv[++i];
		}
		else if (arg == "--id" && command == "keygen" && i + 1 < argc) {
			idOption = argv[++i];
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
			return commandIndex(positional[0], output, keyOption);
		}
		if (command == "keygen" && positional.empty() && !backupOption.empty()) {
			int id = 1;
			if (!idOption.empty()) {
				if (idOption.size() > 3 || idOption.find_first_not_of("0123456789") != std::string::npos) {
					std::cerr << "Error: --id must be a number." << std::endl;
					return 2;
				}
				id = std::stoi(idOption);
			}
			return commandKeygen(backupOption, id, keyOption);
		}
		if (command == "key" && positional.size() == 2 && positional[0] == "restore") {
			return commandKeyRestore(positional[1], keyOption);
		}
		if (command == "key" && positional.size() == 1 && positional[0] == "check") {
			return commandKeyCheck(keyOption, backupOption);
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
