#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
#include "flan/format.hpp"
#include "nlohmann/json.hpp"

namespace fs = std::filesystem;
using ordered_json = nlohmann::ordered_json;

// Сборка под одну архитектуру из манифеста — будущая запись индекса.
struct ArchTarget {
	std::string archKey;								// ключ в манифесте: "x64", "x86", "arm64"
	uint8_t arch = 0;									// ARCH_*
	uint8_t kind = KIND_ZIP;							// KIND_ZIP или KIND_EXE (DESIGN.md §5.2)
	std::string url;									// после подстановки {version}
	std::string extractDir;								// канонический путь; пусто — корень архива
	std::string sha256;									// hex в нижнем регистре; пусто — ещё не посчитан
};

struct Manifest {
	fs::path path;
	std::string name;
	std::string version;
	std::string description;
	std::vector<std::string> bins;						// канонические пути
	std::string binList;								// те же пути через ';', как в индексе
	std::vector<ArchTarget> targets;
	ordered_json document;								// исходный документ: hash вписывает в него хэши

	// Как был записан исходный файл. При перезаписи сохраняется, иначе при core.autocrlf
	// каждый hash превращал бы CRLF рабочей копии в LF.
	bool crlf = false;
	bool bom = false;
};

// Читает и проверяет манифест (DESIGN.md §5.2). Все найденные ошибки — в errors,
// чтобы check показал их разом. requireHash: true для check и index, false для hash.
bool loadManifest(const fs::path& file, bool requireHash, Manifest& out, std::vector<std::string>& errors);

// Записывает документ манифеста обратно атомарно (временный файл -> MoveFileExW).
bool saveManifest(const Manifest& manifest, std::string& error);

// Кэш скачанных архивов: <репозиторий пакетов>\.cache\<sha256>. Адресуется содержимым,
// поэтому повторная сборка индекса сеть не трогает.
struct CachedArchive {
	std::string path;
	std::string sha256;
	uint64_t size = 0;
};

bool downloadToCache(const std::string& url, const fs::path& cacheDir, CachedArchive& out, std::string& error);
bool findInCache(const fs::path& cacheDir, const std::string& sha256, CachedArchive& out);

// Проверяет скачанный файл (DESIGN.md §8): у zip — что extract_dir в архиве есть, а каждый bin —
// файл внутри него; у exe — заголовок PE и его архитектуру.
bool verifyPackageContents(const std::string& path, const ArchTarget& target,
	const std::vector<std::string>& bins, std::string& error);

// Заголовок PE одиночного .exe: MZ, PE\0\0, исполняемый образ, не DLL, Machine == arch.
// data — начало файла; size — сколько байт прочитано.
bool checkPeHeader(const uint8_t* data, size_t size, uint8_t arch, std::string& error);

// Запись индекса, готовая к сериализации.
struct BuildEntry {
	std::string name;
	std::string version;
	std::string url;
	std::string extractDir;
	std::string binList;
	std::string description;
	uint32_t archiveSize = 0;
	uint8_t arch = 0;
	uint8_t kind = 0;
	uint8_t sha256[32] = {};
};

// Собирает index.flan: сортировка, пул строк, тело, сжатие raw deflate, конверт без подписи.
bool buildIndexFile(std::vector<BuildEntry> entries, uint64_t generatedAt, std::vector<uint8_t>& file, std::string& error);

// Raw deflate (без заголовка zlib) — так тело индекса хранится при compression = 1.
bool deflateRaw(const std::vector<uint8_t>& data, std::vector<uint8_t>& out);

// Атомарная запись произвольного файла: временный файл рядом -> MoveFileExW.
bool writeFileAtomically(const fs::path& path, const void* data, size_t size, std::string& error);
