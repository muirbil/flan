#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "build.hpp"
#include "flan/hex.hpp"
#include "flan/index.hpp"
#include "flan/validate.hpp"
#include <fstream>
#include <iterator>
#include <set>

namespace {

	const std::set<std::string> TOP_LEVEL_KEYS = { "name", "version", "description", "homepage", "license", "bin", "arch" };
	const std::set<std::string> ARCH_KEYS = { "url", "extract_dir", "sha256", "kind" };

	// {version} — единственная подстановка (DESIGN.md §5.2).
	std::string expandVersion(const std::string& text, const std::string& version) {
		static const std::string token = "{version}";

		std::string result;
		size_t position = 0;
		for (;;) {
			const size_t found = text.find(token, position);
			if (found == std::string::npos) {
				result.append(text, position, std::string::npos);
				return result;
			}
			result.append(text, position, found - position);
			result += version;
			position = found + token.size();
		}
	}

	// Строковое поле: отсутствует — ok и present = false; не строка — ошибка.
	bool readOptionalString(const ordered_json& object, const char* key, std::string& out, bool& present,
		const std::string& where, std::vector<std::string>& errors) {
		present = false;
		const auto it = object.find(key);
		if (it == object.end()) {
			return true;
		}
		if (!it->is_string()) {
			errors.push_back(where + "'" + key + "' must be a string");
			return false;
		}
		out = it->get<std::string>();
		present = true;
		return true;
	}

	// Обязательное строковое поле: одна ошибка на одну проблему.
	bool readRequiredString(const ordered_json& object, const char* key, std::string& out,
		const std::string& where, std::vector<std::string>& errors) {
		bool present = false;
		if (!readOptionalString(object, key, out, present, where, errors)) {
			return false;
		}
		if (!present) {
			errors.push_back(where + "'" + key + "' is required");
			return false;
		}
		return true;
	}
}

bool loadManifest(const fs::path& file, bool requireHash, Manifest& out, std::vector<std::string>& errors) {
	out = Manifest();
	out.path = file;

	const std::string fileName = file.filename().string();
	const std::string where = fileName + ": ";
	const size_t errorsBefore = errors.size();

	std::ifstream in(file, std::ios::binary);
	if (!in) {
		errors.push_back(where + "cannot open file");
		return false;
	}

	const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	out.crlf = text.find("\r\n") != std::string::npos;
	out.bom = text.compare(0, 3, "\xEF\xBB\xBF") == 0;

	try {
		out.document = ordered_json::parse(text);
	}
	catch (const nlohmann::json::exception& e) {
		errors.push_back(where + "invalid JSON: " + e.what());
		return false;
	}

	const ordered_json& doc = out.document;
	if (!doc.is_object()) {
		errors.push_back(where + "manifest must be a JSON object");
		return false;
	}

	// Неизвестные поля — почти всегда опечатка ("extractdir"), которая иначе молча потерялась бы.
	for (auto it = doc.begin(); it != doc.end(); ++it) {
		if (TOP_LEVEL_KEYS.count(it.key()) == 0) {
			errors.push_back(where + "unknown field '" + it.key() + "'");
		}
	}

	bool present = false;

	if (readRequiredString(doc, "name", out.name, where, errors)) {
		if (!isSafePackageName(out.name)) {
			errors.push_back(where + "'name' must be lowercase [a-z0-9._-], without a leading '.' or '-'");
		}
		else if (out.name + ".json" != fileName) {
			errors.push_back(where + "'name' must match the file name (expected '" + out.name + ".json')");
		}
	}

	if (readRequiredString(doc, "version", out.version, where, errors) && !isSafeName(out.version)) {
		errors.push_back(where + "'version' must be [A-Za-z0-9._-] (it becomes a directory name)");
	}

	if (readOptionalString(doc, "description", out.description, present, where, errors) && present &&
		!isSafeDescription(out.description)) {
		errors.push_back(where + "'description' must be at most " + std::to_string(MAX_DESCRIPTION_LENGTH) +
			" bytes without control characters");
	}

	// Только для людей: в индекс не попадают, проверяется лишь тип.
	std::string ignored;
	readOptionalString(doc, "homepage", ignored, present, where, errors);
	readOptionalString(doc, "license", ignored, present, where, errors);

	// bin: канонические пути, .exe, без повторов имён команд.
	const auto binIt = doc.find("bin");
	if (binIt == doc.end()) {
		errors.push_back(where + "'bin' is required");
	}
	else if (!binIt->is_array() || binIt->empty() || binIt->size() > MAX_BINS) {
		errors.push_back(where + "'bin' must be an array of 1 to " + std::to_string(MAX_BINS) + " paths");
	}
	else {
		const size_t binErrorsBefore = errors.size();
		std::set<std::string> commands;
		for (size_t i = 0; i < binIt->size(); i++) {
			const std::string label = where + "bin[" + std::to_string(i) + "]: ";
			const ordered_json& item = (*binIt)[i];
			if (!item.is_string()) {
				errors.push_back(label + "must be a string");
				continue;
			}

			std::string canonical;
			if (!normalizeRelativePath(item.get<std::string>(), canonical)) {
				errors.push_back(label + "not a safe relative path");
				continue;
			}

			const std::string command = toLowerAscii(commandNameFromBin(canonical));
			if (command.empty()) {
				errors.push_back(label + "must end with .exe");
				continue;
			}

			if (!commands.insert(command).second) {
				errors.push_back(label + "duplicate command name '" + command + "'");
				continue;
			}

			out.bins.push_back(canonical);
			out.binList += (out.binList.empty() ? "" : ";") + canonical;
		}

		// Окончательное слово — у той же функции, которой список проверяет клиент.
		std::vector<std::string> parsed;
		if (errors.size() == binErrorsBefore && !parseBinList(out.binList, parsed)) {
			errors.push_back(where + "'bin' list is rejected by the client validator");
		}
	}

	// arch: хотя бы одна сборка, у каждой url, sha256 и необязательные extract_dir, kind.
	const auto archIt = doc.find("arch");
	if (archIt == doc.end()) {
		errors.push_back(where + "'arch' is required");
	}
	else if (!archIt->is_object() || archIt->empty()) {
		errors.push_back(where + "'arch' must be a non-empty object");
	}
	else {
		for (auto it = archIt->begin(); it != archIt->end(); ++it) {
			const std::string label = where + "arch." + it.key() + ": ";

			ArchTarget target;
			target.archKey = it.key();
			if (!archFromName(it.key(), target.arch)) {
				errors.push_back(label + "unknown architecture (expected x64, x86 or arm64)");
				continue;
			}

			const ordered_json& build = it.value();
			if (!build.is_object()) {
				errors.push_back(label + "must be an object");
				continue;
			}

			for (auto field = build.begin(); field != build.end(); ++field) {
				if (ARCH_KEYS.count(field.key()) == 0) {
					errors.push_back(label + "unknown field '" + field.key() + "'");
				}
			}

			std::string url;
			if (readRequiredString(build, "url", url, label, errors)) {
				target.url = expandVersion(url, out.version);
				if (target.url.find_first_of("{}") != std::string::npos) {
					errors.push_back(label + "'url' has an unknown placeholder (only {version} is supported)");
				}
				else if (!isSafePackageUrl(target.url)) {
					errors.push_back(label + "'url' must be https://, printable ASCII, and not a floating /latest/ link");
				}
			}

			std::string kind;
			if (readOptionalString(build, "kind", kind, present, label, errors) && present) {
				if (kind == "exe") {
					target.kind = KIND_EXE;
				}
				else if (kind != "zip") {
					errors.push_back(label + "'kind' must be \"zip\" or \"exe\"");
				}
			}

			std::string extractDir;
			if (readOptionalString(build, "extract_dir", extractDir, present, label, errors) && present) {
				const std::string expanded = expandVersion(extractDir, out.version);
				if (target.kind == KIND_EXE) {
					errors.push_back(label + "'extract_dir' is not allowed for kind \"exe\"");
				}
				else if (expanded.find_first_of("{}") != std::string::npos) {
					errors.push_back(label + "'extract_dir' has an unknown placeholder (only {version} is supported)");
				}
				else if (!expanded.empty() && !normalizeRelativePath(expanded, target.extractDir)) {
					errors.push_back(label + "'extract_dir' is not a safe relative path");
				}
			}

			// kind = exe (DESIGN.md §5.2): скачанный файл ложится под единственным именем из bin.
			if (target.kind == KIND_EXE &&
				(out.bins.size() != 1 || out.bins[0].find('\\') != std::string::npos)) {
				errors.push_back(label + "kind \"exe\" needs exactly one 'bin' that is a plain file name");
			}

			// Пока hash не отработал, на месте хэша может быть что угодно, например заглушка.
			std::string hash;
			uint8_t bytes[32];
			if (readOptionalString(build, "sha256", hash, present, label, errors) && present && fromHex(hash, bytes, sizeof(bytes))) {
				target.sha256 = toLowerAscii(hash);
			}
			else if (requireHash) {
				errors.push_back(label + "'sha256' must be 64 hex characters (run: flan-build hash " + fileName + ")");
			}

			out.targets.push_back(target);
		}
	}

	return errors.size() == errorsBefore;
}

bool saveManifest(const Manifest& manifest, std::string& error) {
	// ordered_json сохраняет порядок полей, каким его написал автор. Отступ — 2 пробела,
	// как в примере DESIGN.md §5.2; UTF-8 в описании остаётся как есть.
	const std::string json = manifest.document.dump(2) + "\n";

	// Переводы строк и BOM — как в исходном файле. Внутри JSON-строк сырых '\n' не бывает
	// (они экранируются), поэтому заменяются только переводы строк самой разметки.
	std::string text = manifest.bom ? "\xEF\xBB\xBF" : "";
	for (const char c : json) {
		if (c == '\n' && manifest.crlf) {
			text += '\r';
		}
		text += c;
	}

	return writeFileAtomically(manifest.path, text.data(), text.size(), error);
}
