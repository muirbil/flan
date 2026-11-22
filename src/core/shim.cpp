#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "core/shim.hpp"
#include "flan/fs.hpp"
#include "flan/resource.h"
#include "flan/validate.hpp"

namespace {
	constexpr uint64_t MAX_SHIM_SIZE = 4096;
	const char* BAT_OWNER_PREFIX = "rem package=";
	const char* TARGET_KEY = "target=";
	const char* PACKAGE_KEY = "package=";

	std::vector<std::string> splitLines(const std::string& text, size_t limit) {
		std::vector<std::string> lines;
		size_t start = 0;
		while (start < text.size() && lines.size() < limit) {
			size_t end = text.find('\n', start);
			if (end == std::string::npos) {
				end = text.size();
			}
			std::string line = text.substr(start, end - start);
			if (!line.empty() && line.back() == '\r') {
				line.pop_back();
			}
			lines.push_back(line);
			start = end + 1;
		}
		return lines;
	}

	bool startsWith(const std::string& text, const char* prefix) {
		return text.compare(0, std::char_traits<char>::length(prefix), prefix) == 0;
	}

	bool readSmallFile(const std::string& path, std::string& text) {
		std::vector<uint8_t> bytes;
		bool tooLarge = false;
		if (!readWholeFile(path, MAX_SHIM_SIZE, bytes, tooLarge)) {
			return false;
		}
		text.assign(bytes.begin(), bytes.end());
		return true;
	}

	// Владелец по .shim: Package — файл цел и имя пакета по правилам, иначе Foreign.
	ShimOwner ownerFromShimFile(const std::string& path, std::string& owner) {
		std::string text;
		std::string target;
		if (!readSmallFile(path, text) || !parseShimFile(text, target, owner)) {
			owner.clear();
			return ShimOwner::Foreign;
		}
		return ShimOwner::Package;
	}

	ShimOwner ownerFromBat(const std::string& path, std::string& owner) {
		std::string text;
		if (!readSmallFile(path, text)) {
			owner.clear();
			return ShimOwner::Foreign;
		}
		return parseBatOwner(text, owner);
	}
}

std::string formatShimFile(const std::string& target, const std::string& package) {
	return std::string(TARGET_KEY) + target + "\n" + PACKAGE_KEY + package + "\n";
}

bool parseShimFile(const std::string& text, std::string& target, std::string& package) {
	target.clear();
	package.clear();

	bool haveTarget = false;
	bool havePackage = false;
	for (const std::string& line : splitLines(text, 64)) {
		if (startsWith(line, TARGET_KEY) && !haveTarget) {
			target = line.substr(std::char_traits<char>::length(TARGET_KEY));
			haveTarget = true;
		}
		else if (startsWith(line, PACKAGE_KEY) && !havePackage) {
			package = line.substr(std::char_traits<char>::length(PACKAGE_KEY));
			havePackage = true;
		}
	}

	if (!haveTarget || target.empty() || !havePackage || !isSafePackageName(package)) {
		target.clear();
		package.clear();
		return false;
	}
	return true;
}

ShimOwner parseBatOwner(const std::string& text, std::string& owner) {
	owner.clear();

	const std::vector<std::string> lines = splitLines(text, 2);
	if (lines.size() < 2 || toLowerAscii(lines[0]) != "@echo off" || !startsWith(lines[1], BAT_OWNER_PREFIX)) {
		return ShimOwner::Foreign;
	}

	const std::string name = lines[1].substr(std::char_traits<char>::length(BAT_OWNER_PREFIX));
	if (!isSafePackageName(name)) {
		return ShimOwner::Foreign;
	}

	owner = name;
	return ShimOwner::Package;
}

std::string shimExePath(const FlanPaths& paths, const std::string& command) {
	return paths.bin + "\\" + command + ".exe";
}

std::string shimFilePath(const FlanPaths& paths, const std::string& command) {
	return paths.bin + "\\" + command + ".shim";
}

std::string batShimPath(const FlanPaths& paths, const std::string& command) {
	return paths.bin + "\\" + command + ".bat";
}

std::string shimReferencePath(const FlanPaths& paths) {
	return paths.bin + "\\.shim.exe";
}

ShimOwner readShimOwner(const FlanPaths& paths, const std::string& command, std::string& owner) {
	owner.clear();

	// bin\flan.exe — сам клиент (§7.1, 7.4): команда пакета с этим именем — всегда конфликт.
	if (toLowerAscii(command) == "flan") {
		return ShimOwner::Foreign;
	}

	const bool exe = pathExists(shimExePath(paths, command));
	const bool shim = pathExists(shimFilePath(paths, command));
	const bool bat = pathExists(batShimPath(paths, command));

	std::string exeOwner;
	if (shim) {
		if (ownerFromShimFile(shimFilePath(paths, command), exeOwner) != ShimOwner::Package) {
			return ShimOwner::Foreign;
		}
	}
	else if (exe) {
		return ShimOwner::Foreign;							// .exe без .shim создан не flan
	}

	std::string batOwner;
	if (bat && ownerFromBat(batShimPath(paths, command), batOwner) != ShimOwner::Package) {
		return ShimOwner::Foreign;
	}

	if (!exeOwner.empty() && !batOwner.empty() && exeOwner != batOwner) {
		return ShimOwner::Foreign;							// две прослойки разных пакетов — не наша ситуация
	}

	owner = !exeOwner.empty() ? exeOwner : batOwner;
	return owner.empty() ? ShimOwner::None : ShimOwner::Package;
}

bool embeddedShim(const void*& data, size_t& size) {
	data = nullptr;
	size = 0;
	const HRSRC resource = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_SHIM), MAKEINTRESOURCEW(10));	// RT_RCDATA
	if (resource == NULL) {
		return false;
	}
	const HGLOBAL loaded = LoadResource(NULL, resource);
	const DWORD bytes = SizeofResource(NULL, resource);
	if (loaded == NULL || bytes == 0) {
		return false;
	}
	data = LockResource(loaded);
	size = bytes;
	return data != nullptr;
}

bool ensureShimReference(const FlanPaths& paths, std::string& error) {
	const std::string reference = shimReferencePath(paths);
	if (isRegularFile(reference)) {
		return true;
	}

	const void* data = nullptr;
	size_t size = 0;
	if (!embeddedShim(data, size)) {
		error = "this flan.exe carries no shim (built without its resource)";
		return false;
	}
	if (!saveFileAtomically(reference, std::string(static_cast<const char*>(data), size))) {
		error = "cannot write " + reference;
		return false;
	}
	return true;
}

bool writeShim(const FlanPaths& paths, const std::string& command, const std::string& target,
	const std::string& package, std::string& error) {

	if (!ensureShimReference(paths, error)) {
		return false;
	}

	const std::string shimFile = shimFilePath(paths, command);
	if (!saveFileAtomically(shimFile, formatShimFile(target, package))) {
		error = "cannot write " + shimFile;
		return false;
	}

	// Ссылка уже есть — это наша прослойка (владельца проверил вызывающий), она лишь прочитает новый .shim.
	const std::string exe = shimExePath(paths, command);
	if (!pathExists(exe)) {
		const std::string reference = shimReferencePath(paths);
		if (!CreateHardLinkW(extendedPath(exe).c_str(), extendedPath(reference).c_str(), NULL) &&
			!copyFile(reference, exe, false)) {
			error = "cannot create " + exe + " (code " + std::to_string(GetLastError()) + ")";
			return false;
		}
	}

	// Переход с этапов 1–2: своя .bat больше не нужна (rg.exe и так находится раньше rg.bat).
	std::string owner;
	const std::string bat = batShimPath(paths, command);
	if (pathExists(bat) && ownerFromBat(bat, owner) == ShimOwner::Package && owner == package) {
		deleteFile(bat);
	}
	return true;
}

bool moveAside(const FlanPaths& paths, const std::string& path) {
	static unsigned counter = 0;
	const std::string aside = paths.tmp + "\\shim-" + std::to_string(GetCurrentProcessId()) + "-" +
		std::to_string(GetTickCount64()) + "-" + std::to_string(counter++) + ".exe";
	return moveFile(path, aside, false);
}

bool removeShim(const FlanPaths& paths, const std::string& command, const std::string& package, std::string& error) {
	std::string owner;
	const ShimOwner state = readShimOwner(paths, command, owner);
	if (state == ShimOwner::None) {
		return true;
	}
	if (state != ShimOwner::Package || owner != package) {
		error = "command '" + command + "' does not belong to " + package + "; left as is";
		return false;
	}

	// Имя .exe, через которое сейчас работает программа, не удалить, но переименовать можно:
	// такая прослойка уезжает в tmp\ и удаляется при следующей меняющей команде (§7.4).
	const std::string exe = shimExePath(paths, command);
	if (pathExists(exe) && !deleteFile(exe) && !moveAside(paths, exe)) {
		error = "cannot remove " + exe + " (code " + std::to_string(GetLastError()) + ")";
		return false;
	}

	const std::string shimFile = shimFilePath(paths, command);
	if (pathExists(shimFile) && !deleteFile(shimFile)) {
		error = "cannot remove " + shimFile + " (code " + std::to_string(GetLastError()) + ")";
		return false;
	}

	const std::string bat = batShimPath(paths, command);
	if (pathExists(bat) && !deleteFile(bat)) {
		error = "cannot remove " + bat + " (code " + std::to_string(GetLastError()) + ")";
		return false;
	}
	return true;
}

std::vector<std::string> shimsOwnedBy(const FlanPaths& paths, const std::string& package) {
	std::vector<std::string> commands;

	std::vector<DirEntry> entries;
	if (!listDirectory(extendedPath(paths.bin), entries)) {
		return commands;
	}

	for (const DirEntry& entry : entries) {
		if (entry.attributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}

		// Обход — по "*", окончания проверяются в коде: маска *.bat совпала бы и с коротким
		// именем 8.3 ("foo.batch" -> FOO~1.BAT). Не-ASCII имена прослойками flan не бывают.
		std::string name;
		if (!asciiName(entry.name, name)) {
			continue;
		}
		const std::string lower = toLowerAscii(name);
		const bool shim = lower.size() > 5 && lower.compare(lower.size() - 5, 5, ".shim") == 0;
		const bool bat = lower.size() > 4 && lower.compare(lower.size() - 4, 4, ".bat") == 0;
		if (!shim && !bat) {
			continue;
		}

		const std::string command = name.substr(0, name.size() - (shim ? 5 : 4));
		if (!isSafeName(command)) {
			continue;
		}

		std::string owner;
		const ShimOwner state = shim ? ownerFromShimFile(paths.bin + "\\" + name, owner)
			: ownerFromBat(paths.bin + "\\" + name, owner);
		if (state != ShimOwner::Package || owner != package) {
			continue;
		}

		bool seen = false;
		for (const std::string& existing : commands) {
			seen = seen || toLowerAscii(existing) == toLowerAscii(command);
		}
		if (!seen) {
			commands.push_back(command);
		}
	}

	return commands;
}

void cleanTemporary(const FlanPaths& paths) {
	const std::wstring tmp = extendedPath(paths.tmp);
	std::vector<DirEntry> entries;
	if (!listDirectory(tmp, entries)) {
		return;
	}
	// Под блокировкой другого flan нет: всё в tmp\ — наши остатки. Занятое останется до следующего раза.
	for (const DirEntry& entry : entries) {
		removeTreeW(tmp + L"\\" + entry.name);
	}
}
