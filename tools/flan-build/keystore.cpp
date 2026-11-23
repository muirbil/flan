#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <shlobj.h>
#include "keystore.hpp"
#include "flan/signature.hpp"
#include "flan/sha256.hpp"
#include <cstring>
#include <fstream>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace {

	constexpr char WORKING_MAGIC[8] = { 'F', 'L', 'A', 'N', 'K', 'E', 'Y', '1' };
	constexpr char BACKUP_MAGIC[8] = { 'F', 'L', 'A', 'N', 'B', 'A', 'K', '1' };
	constexpr size_t HEADER_SIZE = 8 + 4 + 64;					// магия, номер с тремя нулями, X||Y
	constexpr size_t SALT_SIZE = 16;
	constexpr size_t NONCE_SIZE = 12;
	constexpr size_t TAG_SIZE = 16;
	constexpr size_t BACKUP_SIZE = HEADER_SIZE + 4 + SALT_SIZE + NONCE_SIZE + 32 + TAG_SIZE;
	constexpr uint32_t MAX_ITERATIONS = 10000000;
	constexpr size_t MAX_KEY_FILE = 64 * 1024;

	void putHeader(std::vector<uint8_t>& out, const char magic[8], const SigningKey& key) {
		out.insert(out.end(), magic, magic + 8);
		out.push_back(key.id);
		out.insert(out.end(), 3, 0);
		out.insert(out.end(), key.publicKey, key.publicKey + 64);
	}

	bool readHeader(const std::vector<uint8_t>& file, const char magic[8], uint8_t& id, uint8_t publicKey[64], std::string& error) {
		if (file.size() < HEADER_SIZE || std::memcmp(file.data(), magic, 8) != 0) {
			error = "not a flan key file of this kind";
			return false;
		}
		if (file[9] != 0 || file[10] != 0 || file[11] != 0 || file[8] == 0) {
			error = "the key file header is corrupted";
			return false;
		}
		id = file[8];
		std::memcpy(publicKey, file.data() + 12, 64);
		return true;
	}

	void putUint32(std::vector<uint8_t>& out, uint32_t value) {
		for (int i = 0; i < 4; i++) {
			out.push_back((uint8_t)(value >> (8 * i)));
		}
	}

	uint32_t getUint32(const uint8_t* data) {
		return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
	}

	// Приватная часть подходит к открытой: пробная подпись проверяется открытым ключом.
	bool pairMatches(const SigningKey& key, std::string& error) {
		uint8_t digest[32];
		uint8_t signature[64];
		crypto::Sha256 hash;
		hash.update("flan key pair check", 19);
		if (!hash.finish(digest) || !signDigest(key, digest, signature, error)) {
			return false;
		}
		if (!crypto::verifyP256(key.publicKey, digest, signature)) {
			error = "the private key does not match the public key in the file";
			return false;
		}
		return true;
	}

	std::string narrowPassphraseError() {
		return "the passphrase cannot be converted to UTF-8";
	}

	// PBKDF2-HMAC-SHA256 -> 32 байта ключа AES.
	bool deriveKey(const std::wstring& passphrase, const uint8_t* salt, uint32_t iterations, uint8_t key[32], std::string& error) {
		const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, passphrase.data(), (int)passphrase.size(), NULL, 0, NULL, NULL);
		if (size <= 0) {
			error = narrowPassphraseError();
			return false;
		}
		std::vector<uint8_t> utf8((size_t)size);
		WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, passphrase.data(), (int)passphrase.size(), (LPSTR)utf8.data(), size, NULL, NULL);

		BCRYPT_ALG_HANDLE hmac = NULL;
		NTSTATUS code = BCryptOpenAlgorithmProvider(&hmac, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
		if (code >= 0) {
			code = BCryptDeriveKeyPBKDF2(hmac, utf8.data(), (ULONG)utf8.size(), const_cast<PUCHAR>(salt), (ULONG)SALT_SIZE,
				iterations, key, 32, 0);
			BCryptCloseAlgorithmProvider(hmac, 0);
		}
		SecureZeroMemory(utf8.data(), utf8.size());
		if (code < 0) {
			error = "PBKDF2 failed";
			return false;
		}
		return true;
	}

	// AES-256-GCM. encrypt: data -> out + tag; иначе out <- data, tag проверяется.
	bool aesGcm(bool encrypt, const uint8_t key[32], const uint8_t* nonce, const uint8_t* aad, size_t aadSize,
		const uint8_t* data, size_t size, uint8_t* out, uint8_t* tag) {
		BCRYPT_ALG_HANDLE aes = NULL;
		if (BCryptOpenAlgorithmProvider(&aes, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) {
			return false;
		}
		bool ok = BCryptSetProperty(aes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
			(ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0) >= 0;

		BCRYPT_KEY_HANDLE handle = NULL;
		ok = ok && BCryptGenerateSymmetricKey(aes, &handle, NULL, 0, const_cast<PUCHAR>(key), 32, 0) >= 0;
		if (ok) {
			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
			BCRYPT_INIT_AUTH_MODE_INFO(info);
			info.pbNonce = const_cast<PUCHAR>(nonce);
			info.cbNonce = (ULONG)NONCE_SIZE;
			info.pbAuthData = const_cast<PUCHAR>(aad);
			info.cbAuthData = (ULONG)aadSize;
			info.pbTag = tag;
			info.cbTag = (ULONG)TAG_SIZE;
			ULONG written = 0;
			const NTSTATUS code = encrypt
				? BCryptEncrypt(handle, const_cast<PUCHAR>(data), (ULONG)size, &info, NULL, 0, out, (ULONG)size, &written, 0)
				: BCryptDecrypt(handle, const_cast<PUCHAR>(data), (ULONG)size, &info, NULL, 0, out, (ULONG)size, &written, 0);
			ok = code >= 0 && written == size;
			BCryptDestroyKey(handle);
		}
		BCryptCloseAlgorithmProvider(aes, 0);
		return ok;
	}
}

bool defaultKeyDirectory(fs::path& out, std::string& error) {
	PWSTR folder = nullptr;
	if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, NULL, &folder))) {
		error = "cannot find %LOCALAPPDATA%";
		return false;
	}
	out = fs::path(folder) / L"flan-build";
	CoTaskMemFree(folder);
	return true;
}

fs::path defaultWorkingKeyPath(const fs::path& directory, uint8_t id) {
	return directory / (L"key-" + std::to_wstring(id) + L".flankey");
}

fs::path backupFileName(uint8_t id) {
	return fs::path(L"flan-key-" + std::to_wstring(id) + L".flankey-backup");
}

bool findNewestWorkingKey(const fs::path& directory, fs::path& out) {
	std::error_code ec;
	int best = -1;
	for (const fs::directory_entry& entry : fs::directory_iterator(directory, ec)) {
		const std::wstring name = entry.path().filename().wstring();
		if (name.size() <= 12 || name.compare(0, 4, L"key-") != 0 || name.compare(name.size() - 8, 8, L".flankey") != 0) {
			continue;
		}
		const std::wstring digits = name.substr(4, name.size() - 12);
		if (digits.empty() || digits.size() > 3 || digits.find_first_not_of(L"0123456789") != std::wstring::npos) {
			continue;
		}
		const int id = std::stoi(digits);
		if (id >= 1 && id <= 255 && id > best) {
			best = id;
			out = entry.path();
		}
	}
	return best > 0;
}

bool insideGitWorkTree(const fs::path& path, fs::path& repo) {
	std::error_code ec;
	fs::path current = fs::absolute(path, ec).lexically_normal();
	while (!current.empty()) {
		if (fs::exists(current / L".git", ec)) {
			repo = current;
			return true;
		}
		const fs::path parent = current.parent_path();
		if (parent == current) {
			break;
		}
		current = parent;
	}
	return false;
}

bool writeNewFile(const fs::path& path, const std::vector<uint8_t>& data, std::string& error) {
	const HANDLE file = CreateFileW(path.wstring().c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		const DWORD code = GetLastError();
		error = code == ERROR_FILE_EXISTS
			? path.u8string() + " already exists; it is never overwritten"
			: "cannot create " + path.u8string() + " (code " + std::to_string(code) + ")";
		return false;
	}
	DWORD written = 0;
	const bool ok = WriteFile(file, data.data(), (DWORD)data.size(), &written, NULL) && written == data.size() && FlushFileBuffers(file);
	CloseHandle(file);
	if (!ok) {
		DeleteFileW(path.wstring().c_str());
		error = "cannot write " + path.u8string();
		return false;
	}
	return true;
}

bool readSmallFile(const fs::path& path, std::vector<uint8_t>& out, std::string& error) {
	std::ifstream in(path, std::ios::binary);
	if (!in) {
		error = "cannot open " + path.u8string();
		return false;
	}
	out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
	if (out.size() > MAX_KEY_FILE) {
		error = path.u8string() + " is too large for a key file";
		return false;
	}
	return true;
}

bool saveWorkingKey(const fs::path& path, const SigningKey& key, std::string& error) {
	DATA_BLOB plain = { 32, const_cast<BYTE*>(key.privateKey) };
	DATA_BLOB entropy = { 64, const_cast<BYTE*>(key.publicKey) };		// блоб привязан к своему открытому ключу
	DATA_BLOB sealed = {};
	const std::wstring description = L"flan signing key " + std::to_wstring(key.id);
	if (!CryptProtectData(&plain, description.c_str(), &entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &sealed)) {
		error = "DPAPI cannot protect the key (code " + std::to_string(GetLastError()) + ")";
		return false;
	}

	std::vector<uint8_t> file;
	putHeader(file, WORKING_MAGIC, key);
	putUint32(file, sealed.cbData);
	file.insert(file.end(), sealed.pbData, sealed.pbData + sealed.cbData);
	LocalFree(sealed.pbData);
	return writeNewFile(path, file, error);
}

bool loadWorkingKey(const fs::path& path, SigningKey& key, std::string& error) {
	std::vector<uint8_t> file;
	if (!readSmallFile(path, file, error)) {
		return false;
	}
	uint8_t id = 0;
	uint8_t publicKey[64];
	if (!readHeader(file, WORKING_MAGIC, id, publicKey, error)) {
		error = path.u8string() + ": " + error;
		return false;
	}
	if (file.size() < HEADER_SIZE + 4 || getUint32(file.data() + HEADER_SIZE) != file.size() - HEADER_SIZE - 4) {
		error = path.u8string() + ": the key file is truncated";
		return false;
	}

	DATA_BLOB sealed = { (DWORD)(file.size() - HEADER_SIZE - 4), file.data() + HEADER_SIZE + 4 };
	DATA_BLOB entropy = { 64, publicKey };
	DATA_BLOB plain = {};
	if (!CryptUnprotectData(&sealed, NULL, &entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
		error = path.u8string() + ": DPAPI cannot decrypt the key (code " + std::to_string(GetLastError()) +
			"). It opens only for the Windows user and installation that created it; restore it from a backup with 'flan-build key restore'";
		return false;
	}
	const bool sized = plain.cbData == 32;
	key.id = id;
	std::memcpy(key.publicKey, publicKey, 64);
	if (sized) {
		std::memcpy(key.privateKey, plain.pbData, 32);
	}
	SecureZeroMemory(plain.pbData, plain.cbData);
	LocalFree(plain.pbData);
	if (!sized) {
		error = path.u8string() + ": the decrypted key has a wrong size";
		return false;
	}
	if (!pairMatches(key, error)) {
		key.wipe();
		error = path.u8string() + ": " + error;
		return false;
	}
	return true;
}

bool encodeBackup(const SigningKey& key, const std::wstring& passphrase, uint32_t iterations,
	std::vector<uint8_t>& out, std::string& error) {
	out.clear();
	uint8_t random[SALT_SIZE + NONCE_SIZE];
	if (BCryptGenRandom(NULL, random, (ULONG)sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
		error = "the system random number generator failed";
		return false;
	}

	putHeader(out, BACKUP_MAGIC, key);
	putUint32(out, iterations);
	out.insert(out.end(), random, random + sizeof(random));
	const size_t aadSize = out.size();

	uint8_t aesKey[32];
	if (!deriveKey(passphrase, random, iterations, aesKey, error)) {
		return false;
	}
	uint8_t cipher[32];
	uint8_t tag[TAG_SIZE];
	const bool ok = aesGcm(true, aesKey, random + SALT_SIZE, out.data(), aadSize, key.privateKey, 32, cipher, tag);
	SecureZeroMemory(aesKey, sizeof(aesKey));
	if (!ok) {
		error = "AES-GCM encryption failed";
		return false;
	}
	out.insert(out.end(), cipher, cipher + 32);
	out.insert(out.end(), tag, tag + TAG_SIZE);
	return true;
}

bool peekBackup(const std::vector<uint8_t>& file, uint8_t& id, uint8_t publicKey[64], std::string& error) {
	if (!readHeader(file, BACKUP_MAGIC, id, publicKey, error)) {
		return false;
	}
	if (file.size() != BACKUP_SIZE) {
		error = "the backup has a wrong size";
		return false;
	}
	return true;
}

bool decodeBackup(const std::vector<uint8_t>& file, const std::wstring& passphrase, SigningKey& key, std::string& error) {
	uint8_t id = 0;
	uint8_t publicKey[64];
	if (!peekBackup(file, id, publicKey, error)) {
		return false;
	}
	const uint32_t iterations = getUint32(file.data() + HEADER_SIZE);
	if (iterations == 0 || iterations > MAX_ITERATIONS) {
		error = "the backup is corrupted (iteration count)";
		return false;
	}
	const uint8_t* salt = file.data() + HEADER_SIZE + 4;
	const uint8_t* nonce = salt + SALT_SIZE;
	const uint8_t* cipher = nonce + NONCE_SIZE;
	const uint8_t* tag = cipher + 32;
	const size_t aadSize = (size_t)(cipher - file.data());

	uint8_t aesKey[32];
	if (!deriveKey(passphrase, salt, iterations, aesKey, error)) {
		return false;
	}
	uint8_t plain[32];
	uint8_t tagCopy[TAG_SIZE];
	std::memcpy(tagCopy, tag, TAG_SIZE);
	const bool ok = aesGcm(false, aesKey, nonce, file.data(), aadSize, cipher, 32, plain, tagCopy);
	SecureZeroMemory(aesKey, sizeof(aesKey));
	if (!ok) {
		SecureZeroMemory(plain, sizeof(plain));
		error = "wrong passphrase, or the backup is damaged";
		return false;
	}

	key.id = id;
	std::memcpy(key.publicKey, publicKey, 64);
	std::memcpy(key.privateKey, plain, 32);
	SecureZeroMemory(plain, sizeof(plain));
	if (!pairMatches(key, error)) {
		key.wipe();
		return false;
	}
	return true;
}

void wipe(std::wstring& text) {
	if (!text.empty()) {
		SecureZeroMemory(&text[0], text.size() * sizeof(wchar_t));
	}
	text.clear();
}

namespace {

	HANDLE consoleInput = NULL;
	DWORD savedMode = 0;

	// Ctrl+C во время ввода: вернуть эхо, иначе консоль останется «немой» и после выхода.
	BOOL WINAPI restoreEcho(DWORD) {
		if (consoleInput != NULL) {
			SetConsoleMode(consoleInput, savedMode);
		}
		return FALSE;
	}
}

bool readPassphrase(const char* prompt, std::wstring& out, std::string& error) {
	out.clear();
	const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
	const HANDLE output = GetStdHandle(STD_ERROR_HANDLE);
	DWORD mode = 0;

	if (input == NULL || input == INVALID_HANDLE_VALUE || !GetConsoleMode(input, &mode)) {
#ifdef _DEBUG
		// Debug: строка из перенаправленного ввода (UTF-8, до LF) — только для сквозных проверок.
		std::string line;
		char c = 0;
		DWORD got = 0;
		while (ReadFile(input, &c, 1, &got, NULL) && got == 1 && c != '\n') {
			line += c;
		}
		if (!line.empty() && line.back() == '\r') {
			line.pop_back();
		}
		const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, line.data(), (int)line.size(), NULL, 0);
		if (size > 0) {
			out.resize((size_t)size);
			MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, line.data(), (int)line.size(), &out[0], size);
		}
		SecureZeroMemory(&line[0], line.size());
		if (out.empty()) {
			error = "no passphrase on the redirected standard input";
			return false;
		}
		return true;
#else
		error = "enter the passphrase in a console window; standard input is redirected";
		return false;
#endif
	}

	DWORD written = 0;
	WriteConsoleA(output, prompt, (DWORD)std::strlen(prompt), &written, NULL);

	consoleInput = input;
	savedMode = mode;
	SetConsoleCtrlHandler(restoreEcho, TRUE);
	SetConsoleMode(input, (mode | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) & ~ENABLE_ECHO_INPUT);

	wchar_t buffer[512];
	DWORD read = 0;
	const BOOL ok = ReadConsoleW(input, buffer, ARRAYSIZE(buffer), &read, NULL);
	SetConsoleMode(input, mode);
	SetConsoleCtrlHandler(restoreEcho, FALSE);
	consoleInput = NULL;
	WriteConsoleA(output, "\r\n", 2, &written, NULL);

	if (!ok) {
		SecureZeroMemory(buffer, sizeof(buffer));
		error = "cannot read the passphrase from the console";
		return false;
	}
	size_t length = read;
	while (length > 0 && (buffer[length - 1] == L'\n' || buffer[length - 1] == L'\r')) {
		length--;
	}
	if (read == ARRAYSIZE(buffer) && length == read) {
		SecureZeroMemory(buffer, sizeof(buffer));
		error = "the passphrase is too long";
		return false;
	}
	out.assign(buffer, length);
	SecureZeroMemory(buffer, sizeof(buffer));
	return true;
}
