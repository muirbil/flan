#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "test.hpp"
#include "keystore.hpp"
#include "signing.hpp"
#include <cstring>
#include <string>
#include <vector>

// Хранение ключа подписи (DESIGN.md §6.3): резервная копия под фразой, рабочая копия под DPAPI,
// отказ перезаписывать и писать внутрь рабочего дерева git. Число итераций PBKDF2 в тестах
// маленькое: формат хранит его в файле, а настоящие копии пишутся с BACKUP_ITERATIONS.

namespace {

	constexpr uint32_t FAST_ITERATIONS = 1000;

	fs::path freshDirectory(const wchar_t* name) {
		wchar_t temp[MAX_PATH];
		GetTempPathW(MAX_PATH, temp);
		const fs::path dir = fs::path(temp) / (std::wstring(L"flan-keystore-test-") + std::to_wstring(GetCurrentProcessId())) / name;
		std::error_code ec;
		fs::remove_all(dir, ec);
		fs::create_directories(dir, ec);
		return dir;
	}

	bool sameKey(const SigningKey& a, const SigningKey& b) {
		return a.id == b.id && std::memcmp(a.publicKey, b.publicKey, 64) == 0 && std::memcmp(a.privateKey, b.privateKey, 32) == 0;
	}

	void expectBackupRejected(const char* label, std::vector<uint8_t> file, const std::wstring& passphrase) {
		SigningKey key;
		std::string error;
		const bool accepted = decodeBackup(file, passphrase, key, error);
		check(!accepted, label, accepted ? "ACCEPTED" : error);
	}
}

void runKeystoreTests() {
	beginSuite("keystore: backup");

	SigningKey key;
	std::string error;
	check(generateSigningKey(5, key, error), "key generated", error);
	const std::wstring passphrase = L"корова мост лампа ветер 42";

	std::vector<uint8_t> backup;
	check(encodeBackup(key, passphrase, FAST_ITERATIONS, backup, error) && backup.size() == 156, "backup encoded (156 bytes)",
		error + " size " + std::to_string(backup.size()));
	{
		SigningKey restored;
		check(decodeBackup(backup, passphrase, restored, error) && sameKey(restored, key), "round trip with a Cyrillic passphrase", error);

		uint8_t id = 0;
		uint8_t publicKey[64];
		check(peekBackup(backup, id, publicKey, error) && id == 5 && std::memcmp(publicKey, key.publicKey, 64) == 0,
			"number and public key readable without the passphrase", error);

		std::vector<uint8_t> second;
		encodeBackup(key, passphrase, FAST_ITERATIONS, second, error);
		check(second != backup, "two backups of one key differ (random salt and nonce)");
	}
	expectBackupRejected("wrong passphrase", backup, L"корова мост лампа ветер 43");
	expectBackupRejected("empty passphrase", backup, L"");
	{
		// Каждое поле покрыто GCM: номер, открытый ключ, итерации, соль, nonce, шифротекст, тег.
		size_t accepted = 0;
		for (size_t i = 0; i < backup.size(); i++) {
			auto changed = backup;
			changed[i] ^= 0x01;
			SigningKey restored;
			if (decodeBackup(changed, passphrase, restored, error)) {
				accepted++;
			}
		}
		check(accepted == 0, "every changed byte of the backup is rejected", std::to_string(accepted) + " accepted");
	}
	{
		auto shorter = backup;
		shorter.pop_back();
		expectBackupRejected("truncated backup", shorter, passphrase);
		auto zeroIterations = backup;
		std::memset(zeroIterations.data() + 76, 0, 4);
		expectBackupRejected("zero iterations", zeroIterations, passphrase);
		std::vector<uint8_t> working(backup.begin(), backup.end());
		std::memcpy(working.data(), "FLANKEY1", 8);
		expectBackupRejected("a working-copy header is not a backup", working, passphrase);
	}

	beginSuite("keystore: working copy");
	{
		const fs::path dir = freshDirectory(L"working");
		const fs::path path = defaultWorkingKeyPath(dir, key.id);
		check(path.filename() == L"key-5.flankey", "default working copy name");

		check(saveWorkingKey(path, key, error), "saved under DPAPI", error);
		SigningKey loaded;
		check(loadWorkingKey(path, loaded, error) && sameKey(loaded, key), "loaded back", error);

		std::vector<uint8_t> bytes;
		readSmallFile(path, bytes, error);
		bool hasPlainKey = false;
		for (size_t i = 0; i + 32 <= bytes.size(); i++) {
			hasPlainKey = hasPlainKey || std::memcmp(bytes.data() + i, key.privateKey, 32) == 0;
		}
		check(!hasPlainKey, "the private key is not in the file in plain form");

		check(!saveWorkingKey(path, key, error) && error.find("never overwritten") != std::string::npos,
			"an existing working copy is not overwritten", error);

		// Подменённый открытый ключ: энтропия DPAPI — открытый ключ, блоб не расшифруется.
		auto swapped = bytes;
		swapped[12] ^= 0x01;
		const fs::path swappedPath = dir / L"key-6.flankey";
		writeNewFile(swappedPath, swapped, error);
		SigningKey bad;
		check(!loadWorkingKey(swappedPath, bad, error), "a changed public key in the working copy is rejected", error);

		auto truncated = bytes;
		truncated.resize(truncated.size() - 3);
		const fs::path truncatedPath = dir / L"key-7.flankey";
		writeNewFile(truncatedPath, truncated, error);
		check(!loadWorkingKey(truncatedPath, bad, error) && error.find("truncated") != std::string::npos,
			"a truncated working copy is rejected", error);

		fs::path newest;
		check(findNewestWorkingKey(dir, newest) && newest.filename() == L"key-7.flankey", "the newest working copy is the highest number",
			newest.u8string());
		writeNewFile(dir / L"key-300.flankey", bytes, error);
		writeNewFile(dir / L"key-x.flankey", bytes, error);
		writeNewFile(dir / L"key-9.flankey.bak", bytes, error);
		check(findNewestWorkingKey(dir, newest) && newest.filename() == L"key-7.flankey", "names that are not key-1..255 are ignored",
			newest.u8string());

		const fs::path empty = freshDirectory(L"empty");
		check(!findNewestWorkingKey(empty, newest), "no working copy in an empty folder");
	}

	beginSuite("keystore: git work tree");
	{
		const fs::path root = freshDirectory(L"git");
		std::error_code ec;
		fs::create_directories(root / L"repo" / L".git", ec);
		fs::create_directories(root / L"repo" / L"deep" / L"keys", ec);
		fs::create_directories(root / L"worktree", ec);
		writeNewFile(root / L"worktree" / L".git", std::vector<uint8_t>{ 'g', 'i', 't' }, error);
		fs::create_directories(root / L"outside", ec);

		fs::path repo;
		check(insideGitWorkTree(root / L"repo" / L"deep" / L"keys" / L"key-1.flankey", repo) && repo == root / L"repo",
			"a path deep inside a repository", repo.u8string());
		check(insideGitWorkTree(root / L"worktree" / L"key-1.flankey", repo), "a worktree with a .git file");
		check(!insideGitWorkTree(root / L"outside" / L"key-1.flankey", repo), "a folder outside any repository");
	}

	{
		std::error_code ec;
		wchar_t temp[MAX_PATH];
		GetTempPathW(MAX_PATH, temp);
		fs::remove_all(fs::path(temp) / (std::wstring(L"flan-keystore-test-") + std::to_wstring(GetCurrentProcessId())), ec);
	}
}
