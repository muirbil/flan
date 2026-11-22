#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "core/shim.hpp"
#include "flan/fs.hpp"
#include "flan/validate.hpp"
#include <cctype>

namespace {
	constexpr uint64_t MAX_SHIM_SIZE = 4096;
	const char* OWNER_PREFIX = "rem package=";
}

std::string formatShim(const std::string& targetExe, const std::string& package) {
	// Внутри кавычек cmd.exe не трогает & и ^, но раскрывает %: путь профиля вида
	// C:\Users\50%off\ превратился бы в переменную. Поэтому % удваивается.
	std::string escaped;
	for (const char c : targetExe) {
		escaped += c;
		if (c == '%') {
			escaped += '%';
		}
	}

	// cmd.exe перечитывает .bat с прежнего смещения после возврата из дочерней программы.
	// Если install обновит прослойку, пока она работает, хвост новой (более длинной) строки
	// выполнится как команда — проверено. Поэтому выход стоит на той же строке: cmd разбирает
	// её целиком заранее и файл больше не читает.
	// Просто "& exit /b" теряет код возврата, а %errorlevel% раскрылся бы при разборе строки,
	// ещё до запуска. "call" раскрывает %%errorlevel%% повторно — уже после завершения программы.
	// CRLF: с LF-окончаниями cmd.exe ведёт себя ненадёжно.
	return "@echo off\r\n"
		"rem package=" + package + "\r\n"
		"\"" + escaped + "\" %* & call exit /b %%errorlevel%%\r\n";
}

ShimOwner parseShimOwner(const std::string& text, std::string& owner) {
	owner.clear();

	std::vector<std::string> lines;
	size_t start = 0;
	while (start < text.size() && lines.size() < 2) {
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

	if (lines.size() < 2 || toLowerAscii(lines[0]) != "@echo off" ||
		lines[1].compare(0, std::char_traits<char>::length(OWNER_PREFIX), OWNER_PREFIX) != 0) {
		return ShimOwner::Foreign;
	}

	const std::string name = lines[1].substr(std::char_traits<char>::length(OWNER_PREFIX));
	if (!isSafePackageName(name)) {
		return ShimOwner::Foreign;
	}

	owner = name;
	return ShimOwner::Package;
}

std::string shimPath(const FlanPaths& paths, const std::string& command) {
	return paths.bin + "\\" + command + ".bat";
}

ShimOwner readShimOwner(const FlanPaths& paths, const std::string& command, std::string& owner) {
	owner.clear();
	const std::string path = shimPath(paths, command);
	if (!pathExists(path)) {
		return ShimOwner::None;
	}

	std::vector<uint8_t> bytes;
	bool tooLarge = false;
	if (!readWholeFile(path, MAX_SHIM_SIZE, bytes, tooLarge)) {
		return ShimOwner::Foreign;
	}

	return parseShimOwner(std::string(bytes.begin(), bytes.end()), owner);
}

bool writeShim(const FlanPaths& paths, const std::string& command, const std::string& targetExe, const std::string& package) {
	return saveFileAtomically(shimPath(paths, command), formatShim(targetExe, package));
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

		// Обход — по "*", окончание .bat проверяется в коде: маска *.bat совпала бы и с коротким
		// именем 8.3 ("foo.batch" -> FOO~1.BAT). Не-ASCII имена прослойками flan не бывают.
		std::string command;
		if (!asciiName(entry.name, command) || command.size() <= 4 ||
			toLowerAscii(command.substr(command.size() - 4)) != ".bat") {
			continue;
		}
		command.resize(command.size() - 4);

		std::string owner;
		if (isSafeName(command) && readShimOwner(paths, command, owner) == ShimOwner::Package && owner == package) {
			commands.push_back(command);
		}
	}

	return commands;
}
