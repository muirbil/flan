#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
#include "signing.hpp"

namespace fs = std::filesystem;

// Хранение ключа подписи (DESIGN.md §6.3, «Где лежит приватный ключ»).
//
// Рабочая копия key-<N>.flankey:
//   "FLANKEY1" | id | 3 нуля | X||Y (64) | uint32 длина | блоб CryptProtectData (DPAPI, текущий пользователь)
// Резервная копия flan-key-<N>.flankey-backup:
//   "FLANBAK1" | id | 3 нуля | X||Y (64) | uint32 итерации | соль (16) | nonce (12) | шифротекст d (32) | тег (16)
//   Ключ AES-256 — PBKDF2-HMAC-SHA256 от фразы (UTF-8); всё до шифротекста — дополнительные данные GCM,
//   так что подменить в копии номер ключа, открытый ключ или число итераций незаметно нельзя.

constexpr uint32_t BACKUP_ITERATIONS = 600000;
constexpr size_t MIN_PASSPHRASE_LENGTH = 12;			// символов UTF-16; советуется 5–6 случайных слов

// Каталог рабочих копий по умолчанию: %LOCALAPPDATA%\flan-build.
bool defaultKeyDirectory(fs::path& out, std::string& error);
fs::path defaultWorkingKeyPath(const fs::path& directory, uint8_t id);
fs::path backupFileName(uint8_t id);

// Рабочая копия с наибольшим номером в каталоге; false — ни одной.
bool findNewestWorkingKey(const fs::path& directory, fs::path& out);

// Путь внутри рабочего дерева git (есть .git в нём или выше)? Тогда repo — корень дерева.
bool insideGitWorkTree(const fs::path& path, fs::path& repo);

// Рабочая копия под DPAPI. load расшифровывает и проверяет, что приватная часть подходит к открытой.
bool saveWorkingKey(const fs::path& path, const SigningKey& key, std::string& error);
bool loadWorkingKey(const fs::path& path, SigningKey& key, std::string& error);

// Резервная копия под фразой. iterations — только ради быстрых тестов; в файлы идёт BACKUP_ITERATIONS.
bool encodeBackup(const SigningKey& key, const std::wstring& passphrase, uint32_t iterations,
	std::vector<uint8_t>& out, std::string& error);
bool decodeBackup(const std::vector<uint8_t>& file, const std::wstring& passphrase, SigningKey& key, std::string& error);

// Номер ключа и открытая часть из резервной копии — без фразы.
bool peekBackup(const std::vector<uint8_t>& file, uint8_t& id, uint8_t publicKey[64], std::string& error);

// Запись нового файла: существующий не перезаписывается никогда.
bool writeNewFile(const fs::path& path, const std::vector<uint8_t>& data, std::string& error);
bool readSmallFile(const fs::path& path, std::vector<uint8_t>& out, std::string& error);

// Фраза из консоли без эха (prompt — в stderr). Стандартный ввод перенаправлен: Release отказывает,
// Debug читает строку из него — только для сквозных проверок на тестовых ключах (§8).
bool readPassphrase(const char* prompt, std::wstring& out, std::string& error);

// Стереть строку с фразой.
void wipe(std::wstring& text);
