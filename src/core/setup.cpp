#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "core/setup.hpp"
#include "core/receipt.hpp"
#include "core/shim.hpp"
#include "flan/console.hpp"
#include "flan/fs.hpp"
#include "flan/strings.hpp"
#include "flan/validate.hpp"
#include <algorithm>
#include <vector>

namespace {

	std::wstring expand(const std::wstring& text) {
		const DWORD needed = ExpandEnvironmentStringsW(text.c_str(), NULL, 0);
		if (needed == 0) {
			return text;
		}
		std::wstring out(needed, L'\0');
		const DWORD written = ExpandEnvironmentStringsW(text.c_str(), &out[0], needed);
		if (written == 0 || written > needed) {
			return text;
		}
		out.resize(written - 1);
		return out;
	}

	std::wstring withoutTrailingSlashes(std::wstring path) {
		while (!path.empty() && (path.back() == L'\\' || path.back() == L'/')) {
			path.pop_back();
		}
		return path;
	}

	std::string narrow(const std::wstring& text) {
		std::string out;
		return toUtf8(text, out) ? out : std::string("?");
	}
}

bool pathSegmentMatches(const std::wstring& segment, const std::wstring& dir) {
	std::wstring value = segment;
	if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"') {
		value = value.substr(1, value.size() - 2);
	}
	value = withoutTrailingSlashes(expand(value));
	const std::wstring wanted = withoutTrailingSlashes(dir);
	return !value.empty() && CompareStringOrdinal(value.data(), (int)value.size(), wanted.data(), (int)wanted.size(), TRUE) == CSTR_EQUAL;
}

namespace {

	// Сегменты через ';' как есть, вместе с пустыми: при сборке обратно значение не меняется.
	std::vector<std::wstring> splitPath(const std::wstring& value) {
		std::vector<std::wstring> segments;
		size_t start = 0;
		for (;;) {
			const size_t end = value.find(L';', start);
			segments.push_back(value.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start));
			if (end == std::wstring::npos) {
				return segments;
			}
			start = end + 1;
		}
	}
}

bool pathHasDir(const std::wstring& value, const std::wstring& dir) {
	for (const std::wstring& segment : splitPath(value)) {
		if (pathSegmentMatches(segment, dir)) {
			return true;
		}
	}
	return false;
}

std::wstring pathWithEntry(const std::wstring& value, const std::wstring& entry) {
	if (value.empty()) {
		return entry;
	}
	return value.back() == L';' ? value + entry : value + L";" + entry;
}

std::wstring pathWithoutDir(const std::wstring& value, const std::wstring& dir, size_t& removed) {
	removed = 0;
	std::wstring out;
	bool first = true;
	for (const std::wstring& segment : splitPath(value)) {
		if (pathSegmentMatches(segment, dir)) {
			removed++;
			continue;
		}
		if (!first) {
			out += L';';
		}
		out += segment;
		first = false;
	}
	return removed == 0 ? value : out;
}

size_t launchPathLength(const std::wstring& bin, const std::string& command) {
	return bin.size() + 1 + s2ws(command).size() + 4;
}

LaunchRoom launchRoom(size_t length) {
	if (length >= LAUNCH_PATH_LIMIT) {
		return LaunchRoom::TooLong;
	}
	return length + LAUNCH_PATH_MARGIN >= LAUNCH_PATH_LIMIT ? LaunchRoom::Tight : LaunchRoom::Enough;
}

size_t longestLaunchableName(const std::wstring& bin) {
	const size_t used = bin.size() + 1 + 4;
	return used + 1 >= LAUNCH_PATH_LIMIT ? 0 : LAUNCH_PATH_LIMIT - 1 - used;
}

namespace {

	// ----- Реестр: HKCU\Environment\Path, целиком, без раскрытия переменных (§7.8) -----

	struct EnvironmentKey {
		HKEY key = NULL;
		HKEY hive = NULL;								// только Debug: частный куст вместо HKCU
		bool redirected = false;

		~EnvironmentKey() {
			if (key != NULL) {
				RegCloseKey(key);
			}
			if (hive != NULL) {
				RegCloseKey(hive);
			}
		}
	};

	bool openEnvironment(EnvironmentKey& env, std::string& error) {
#ifdef _DEBUG
		// Debug: FLAN_DEBUG_ENV_HIVE=<файл> — Environment\Path живёт в частном кусте RegLoadAppKeyW,
		// а настоящий реестр не трогается вовсе. В Release этого кода нет.
		wchar_t hiveFile[MAX_PATH];
		const DWORD length = GetEnvironmentVariableW(L"FLAN_DEBUG_ENV_HIVE", hiveFile, MAX_PATH);
		if (length > 0 && length < MAX_PATH) {
			const LSTATUS loaded = RegLoadAppKeyW(hiveFile, &env.hive, KEY_ALL_ACCESS, 0, 0);
			if (loaded != ERROR_SUCCESS) {
				error = "cannot load the debug registry hive (code " + std::to_string(loaded) + ")";
				return false;
			}
			env.redirected = true;
			const LSTATUS created = RegCreateKeyExW(env.hive, L"Environment", 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE,
				NULL, &env.key, NULL);
			if (created != ERROR_SUCCESS) {
				error = "cannot open Environment in the debug hive (code " + std::to_string(created) + ")";
				return false;
			}
			return true;
		}
#endif
		const LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, L"Environment", 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE,
			NULL, &env.key, NULL);
		if (status != ERROR_SUCCESS) {
			error = "cannot open HKCU\\Environment (code " + std::to_string(status) + ")";
			return false;
		}
		return true;
	}

	struct UserPath {
		std::wstring value;
		DWORD type = REG_EXPAND_SZ;						// значения нет — создаётся REG_EXPAND_SZ
		bool exists = false;
	};

	bool readUserPath(HKEY key, UserPath& path, std::string& error) {
		path = UserPath();
		std::vector<wchar_t> buffer(4096);
		for (;;) {
			DWORD type = 0;
			DWORD bytes = (DWORD)(buffer.size() * sizeof(wchar_t));
			const LSTATUS status = RegQueryValueExW(key, L"Path", NULL, &type, reinterpret_cast<BYTE*>(buffer.data()), &bytes);
			if (status == ERROR_FILE_NOT_FOUND) {
				return true;
			}
			if (status == ERROR_MORE_DATA) {
				buffer.resize(bytes / sizeof(wchar_t) + 2);
				continue;
			}
			if (status != ERROR_SUCCESS) {
				error = "cannot read the user PATH (code " + std::to_string(status) + ")";
				return false;
			}
			if (type != REG_SZ && type != REG_EXPAND_SZ) {
				error = "the user PATH has an unexpected registry type " + std::to_string(type) + "; it is left as is";
				return false;
			}
			size_t length = bytes / sizeof(wchar_t);
			while (length > 0 && buffer[length - 1] == L'\0') {
				length--;
			}
			path.value.assign(buffer.data(), length);
			path.type = type;
			path.exists = true;
			return true;
		}
	}

	bool writeUserPath(HKEY key, const UserPath& path, std::string& error) {
		const DWORD bytes = (DWORD)((path.value.size() + 1) * sizeof(wchar_t));
		const LSTATUS status = RegSetValueExW(key, L"Path", 0, path.type, reinterpret_cast<const BYTE*>(path.value.c_str()), bytes);
		if (status != ERROR_SUCCESS) {
			error = "cannot write the user PATH (code " + std::to_string(status) + ")";
			return false;
		}
		return true;
	}

	void broadcastEnvironmentChange() {
		DWORD_PTR result = 0;
		SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, reinterpret_cast<LPARAM>(L"Environment"),
			SMTO_ABORTIFHUNG, 5000, &result);
	}

	bool flanHomeIsSet() {
		wchar_t value[4];
		return GetEnvironmentVariableW(L"FLAN_HOME", value, ARRAYSIZE(value)) > 0;
	}

	bool updatePath(const FlanPaths& paths, bool remove) {
		EnvironmentKey env;
		std::string error;
		UserPath path;
		if (!openEnvironment(env, error) || !readUserPath(env.key, path, error)) {
			con::err << "Error: " << error << "." << con::endl;
			return false;
		}

		const std::wstring dir = s2ws(paths.bin);
		const std::string where = env.redirected ? "the debug PATH" : "your user PATH";

		if (remove) {
			size_t removed = 0;
			UserPath updated = path;
			updated.value = pathWithoutDir(path.value, dir, removed);
			if (removed == 0) {
				con::out << paths.bin << " is not in " << where << "; nothing to remove." << con::endl;
				return true;
			}
			if (!writeUserPath(env.key, updated, error)) {
				con::err << "Error: " << error << "." << con::endl;
				return false;
			}
			if (!env.redirected) {
				broadcastEnvironmentChange();
			}
			con::out << "Removed " << removed << " entr" << (removed == 1 ? "y" : "ies") << " for " << paths.bin << " from " << where
				<< " (" << path.value.size() << " -> " << updated.value.size() << " characters). New console windows will not see it." << con::endl;
			return true;
		}

		if (pathHasDir(path.value, dir)) {
			con::out << paths.bin << " is already in " << where << " (" << path.value.size() << " characters); not changed." << con::endl;
			return true;
		}

		// REG_EXPAND_SZ и корень по умолчанию — %USERPROFILE%\.flan\bin (переживёт переименование профиля);
		// FLAN_HOME или REG_SZ, где %…% не раскрывается, — абсолютный путь.
		std::wstring entry = dir;
		const std::wstring portable = L"%USERPROFILE%\\.flan\\bin";
		if (path.type == REG_EXPAND_SZ && !flanHomeIsSet() && pathSegmentMatches(portable, dir)) {
			entry = portable;
		}

		UserPath updated = path;
		updated.value = pathWithEntry(path.value, entry);
		if (!writeUserPath(env.key, updated, error)) {
			con::err << "Error: " << error << "." << con::endl;
			return false;
		}
		if (!env.redirected) {
			broadcastEnvironmentChange();
		}
		con::out << "Added " << narrow(entry) << " to " << where << " (" << (path.type == REG_SZ ? "REG_SZ" : "REG_EXPAND_SZ") << ", "
			<< path.value.size() << " -> " << updated.value.size() << " characters). Open a new console window to use it." << con::endl;
		return true;
	}

}

std::string flanExeNewPath(const FlanPaths& paths) {
	return paths.bin + "\\flan.exe.new";
}

bool putFlanExeInPlace(const FlanPaths& paths, const char* retry, bool& replaced) {
	const std::string target = paths.bin + "\\flan.exe";
	const std::string fresh = flanExeNewPath(paths);
	const std::string old = paths.bin + "\\flan.exe.old";

	// Работающий bin\flan.exe перезаписать нельзя, а переименовать можно: он уходит в flan.exe.old
	// и удаляется при следующем запуске любой команды.
	replaced = pathExists(target);
	if (replaced) {
		if (pathExists(old) && !deleteFile(old)) {
			con::err << "Error: " << old << " is still running (an older flan). Close it and run '" << retry << "' again." << con::endl;
			deleteFile(fresh);
			return false;
		}
		if (!moveFile(target, old, false)) {
			con::err << "Error: cannot move " << target << " aside (code " << GetLastError() << ")." << con::endl;
			deleteFile(fresh);
			return false;
		}
	}
	if (!moveFile(fresh, target, false)) {
		con::err << "Error: cannot put the new flan.exe in place (code " << GetLastError() << ")." << con::endl;
		if (replaced) {
			moveFile(old, target, false);
		}
		deleteFile(fresh);
		return false;
	}
	return true;
}

namespace {

	// ----- Копия себя в bin\flan.exe (§7.8, «Копия себя»; тот же приём, что в §7.9) -----

	// Один ли это файл: сравниваются идентификаторы, а не строки путей (регистр, 8.3, жёсткие ссылки).
	bool sameFile(const std::string& a, const std::string& b) {
		auto identify = [](const std::string& path, BY_HANDLE_FILE_INFORMATION& info) {
			const HANDLE handle = CreateFileW(extendedPath(path).c_str(), FILE_READ_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
			if (handle == INVALID_HANDLE_VALUE) {
				return false;
			}
			const bool ok = GetFileInformationByHandle(handle, &info) != 0;
			CloseHandle(handle);
			return ok;
		};
		BY_HANDLE_FILE_INFORMATION first = {};
		BY_HANDLE_FILE_INFORMATION second = {};
		return identify(a, first) && identify(b, second) && first.dwVolumeSerialNumber == second.dwVolumeSerialNumber &&
			first.nFileIndexHigh == second.nFileIndexHigh && first.nFileIndexLow == second.nFileIndexLow;
	}

	bool installSelf(const FlanPaths& paths) {
		std::wstring self(32768, L'\0');
		const DWORD length = GetModuleFileNameW(NULL, &self[0], (DWORD)self.size());
		std::string selfPath;
		if (length == 0 || length >= self.size() || !toUtf8(self.substr(0, length), selfPath)) {
			con::err << "Error: cannot get the path of the running flan.exe." << con::endl;
			return false;
		}

		const std::string target = paths.bin + "\\flan.exe";
		if (sameFile(selfPath, target)) {
			con::out << target << " is this flan.exe already." << con::endl;
			return true;
		}

		const std::string fresh = flanExeNewPath(paths);
		deleteFile(fresh);
		if (!copyFile(selfPath, fresh, true)) {
			con::err << "Error: cannot copy flan.exe to " << fresh << " (code " << GetLastError() << ")." << con::endl;
			return false;
		}

		bool replaced = false;
		if (!putFlanExeInPlace(paths, "flan setup", replaced)) {
			return false;
		}
		con::out << (replaced ? "Updated " : "Copied flan.exe to ") << target
			<< (replaced ? " (the previous one stays as flan.exe.old until the next flan run)." : ".") << con::endl;
		return true;
	}

	// ----- Эталон прослоек и переход с .bat (§7.4) -----

	bool sameContent(const std::string& path, const std::string& bytes) {
		std::vector<uint8_t> current;
		bool tooLarge = false;
		return readWholeFile(path, bytes.size(), current, tooLarge) && current.size() == bytes.size() &&
			std::equal(current.begin(), current.end(), bytes.begin(), [](uint8_t a, char b) { return a == (uint8_t)b; });
	}

}

bool refreshShims(const FlanPaths& paths) {
	const void* data = nullptr;
	size_t size = 0;
	if (!embeddedShim(data, size)) {
		con::err << "Error: this flan.exe carries no shim." << con::endl;
		return false;
	}
	const std::string bytes(static_cast<const char*>(data), size);
	const std::string reference = shimReferencePath(paths);

	// Новый эталон. Старое имя удаляется (у жёсткой ссылки — можно и при запущенной прослойке)
	// или уезжает в tmp\; прослойки на старом эталоне продолжают работать до перевешивания.
	bool ok = true;
	const bool newReference = !sameContent(reference, bytes);
	if (newReference) {
		if (pathExists(reference) && !deleteFile(reference) && !moveAside(paths, reference)) {
			con::err << "Error: cannot replace " << reference << "." << con::endl;
			return false;
		}
		if (!saveFileAtomically(reference, bytes)) {
			con::err << "Error: cannot write " << reference << "." << con::endl;
			return false;
		}
	}

	// Каждая прослойка — тот же файл, что эталон (или копия с тем же содержимым на не-NTFS).
	size_t relinked = 0;
	std::vector<DirEntry> entries;
	listDirectory(extendedPath(paths.bin), entries);
	for (const DirEntry& entry : entries) {
		std::string name;
		if ((entry.attributes & FILE_ATTRIBUTE_DIRECTORY) || !asciiName(entry.name, name) || name.size() <= 5 ||
			toLowerAscii(name.substr(name.size() - 5)) != ".shim") {
			continue;
		}
		const std::string command = name.substr(0, name.size() - 5);
		std::string owner;
		if (!isSafeName(command) || readShimOwner(paths, command, owner) != ShimOwner::Package) {
			continue;
		}

		const std::string exe = shimExePath(paths, command);
		if (pathExists(exe) && (sameFile(exe, reference) || sameContent(exe, bytes))) {
			continue;
		}

		const std::string fresh = exe + ".new";
		deleteFile(fresh);
		const bool made = CreateHardLinkW(extendedPath(fresh).c_str(), extendedPath(reference).c_str(), NULL) ||
			copyFile(reference, fresh, false);
		const bool cleared = made && (!pathExists(exe) || deleteFile(exe) || moveAside(paths, exe));
		if (!cleared || !moveFile(fresh, exe, false)) {
			con::err << "Error: cannot update " << exe << "." << con::endl;
			deleteFile(fresh);
			ok = false;
			continue;
		}
		relinked++;
	}

	// .bat этапов 1–2 и недостающие прослойки установленных пакетов — по их квитанциям.
	size_t converted = 0;
	std::vector<std::string> problems;
	for (const Receipt& receipt : listReceipts(paths, problems)) {
		for (const std::string& bin : receipt.bins) {
			const std::string command = commandNameFromBin(bin);
			std::string owner;
			if (readShimOwner(paths, command, owner) != ShimOwner::Package || owner != receipt.name) {
				continue;
			}
			const bool bat = pathExists(batShimPath(paths, command));
			if (!bat && pathExists(shimExePath(paths, command)) && pathExists(shimFilePath(paths, command))) {
				continue;
			}
			std::string error;
			const std::string target = "..\\apps\\" + receipt.name + "\\" + receipt.dir + "\\" + bin;
			if (!writeShim(paths, command, target, receipt.name, error)) {
				con::err << "Error: " << error << "." << con::endl;
				ok = false;
				continue;
			}
			converted++;
		}
	}

	if (newReference) {
		con::out << "Wrote the shim of this flan to " << reference << "." << con::endl;
	}
	if (relinked > 0) {
		con::out << "Updated " << relinked << " command(s) to the new shim." << con::endl;
	}
	if (converted > 0) {
		con::out << "Converted " << converted << " command(s) to shim.exe (from .bat or missing files)." << con::endl;
	}
	return ok;
}

bool shimReferenceIsStale(const FlanPaths& paths) {
	const void* data = nullptr;
	size_t size = 0;
	const std::string reference = shimReferencePath(paths);
	return embeddedShim(data, size) && pathExists(reference) &&
		!sameContent(reference, std::string(static_cast<const char*>(data), size));
}

namespace {
	// ----- Длина пути запуска (§7.8, «Длинный путь bin\») -----

	// Только предупреждение: файлы flan по длинным путям работают, не запускаются лишь сами команды.
	void warnAboutLaunchPaths(const FlanPaths& paths) {
		const std::wstring bin = s2ws(paths.bin);
		std::vector<std::string> commands{ "flan" };
		std::vector<std::string> problems;
		for (const Receipt& receipt : listReceipts(paths, problems)) {
			for (const std::string& file : receipt.bins) {
				const std::string command = commandNameFromBin(file);
				if (!command.empty()) {
					commands.push_back(command);
				}
			}
		}

		std::string longest;
		std::string tooLong;
		size_t tooLongCount = 0;
		for (const std::string& command : commands) {
			const size_t length = launchPathLength(bin, command);
			if (longest.empty() || length > launchPathLength(bin, longest)) {
				longest = command;
			}
			if (launchRoom(length) == LaunchRoom::TooLong) {
				tooLong += (tooLongCount++ == 0 ? "" : ", ") + command;
			}
		}

		const size_t length = launchPathLength(bin, longest);
		const LaunchRoom room = launchRoom(length);
		if (room == LaunchRoom::Enough) {
			return;
		}
		if (room == LaunchRoom::TooLong) {
			con::err << "Warning: Windows does not start programs from paths of " << LAUNCH_PATH_LIMIT
				<< " characters or more, so these commands will not run from a console: " << tooLong
				<< " (" << paths.bin << "\\" << longest << ".exe is " << length << " characters)." << con::endl;
		}
		else {
			con::err << "Warning: " << paths.bin << "\\" << longest << ".exe is " << length << " characters long. Windows does not start "
				<< "programs from paths of " << LAUNCH_PATH_LIMIT << " characters or more, so a command with a name longer than "
				<< longestLaunchableName(bin) << " characters will not run from a console." << con::endl;
		}
		con::err << "To fix it, use a shorter FLAN_HOME: run 'flan setup --remove', move " << paths.home
			<< " to a short folder such as C:\\flan, set the FLAN_HOME user variable to that folder and run 'flan setup' from its bin\\."
			<< con::endl;
	}
}

ExitCode runSetup(const FlanPaths& paths, bool remove) {
	if (remove) {
		return updatePath(paths, true) ? ExitCode::Ok : ExitCode::Error;
	}

	bool ok = installSelf(paths);
	ok = refreshShims(paths) && ok;
	ok = updatePath(paths, false) && ok;
	warnAboutLaunchPaths(paths);
	return ok ? ExitCode::Ok : ExitCode::Error;
}
