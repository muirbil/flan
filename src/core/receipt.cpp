#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include "core/receipt.hpp"
#include "flan/fs.hpp"
#include "flan/hex.hpp"
#include "flan/index.hpp"
#include "flan/validate.hpp"
#include <ctime>
#include <map>

namespace {
	// Квитанция в несколько сотен байт; всё, что больше, — заведомо не она.
	constexpr uint64_t MAX_RECEIPT_SIZE = 64 * 1024;

	constexpr size_t MAX_TIMESTAMP_LENGTH = 32;
}

std::string formatReceipt(const Receipt& receipt) {
	std::string bins;
	for (const std::string& bin : receipt.bins) {
		bins += (bins.empty() ? "" : ";") + bin;
	}

	const char* arch = archName(receipt.arch);

	return "name=" + receipt.name + "\n" +
		"version=" + receipt.version + "\n" +
		"dir=" + receipt.dir + "\n" +
		"arch=" + (arch ? arch : "") + "\n" +
		"sha256=" + receipt.sha256 + "\n" +
		"bins=" + bins + "\n" +
		"installed_at=" + receipt.installedAt + "\n";
}

bool parseReceipt(const std::string& text, Receipt& out, std::string& error) {
	out = Receipt();

	std::map<std::string, std::string> fields;
	size_t start = 0;
	while (start < text.size()) {
		size_t end = text.find('\n', start);
		if (end == std::string::npos) {
			end = text.size();
		}

		std::string line = text.substr(start, end - start);
		if (!line.empty() && line.back() == '\r') {
			line.pop_back();
		}
		start = end + 1;

		if (line.empty()) {
			continue;
		}

		const size_t equals = line.find('=');
		if (equals == std::string::npos || equals == 0) {
			error = "malformed line";
			return false;
		}

		// Неизвестные ключи пропускаются: их может дописать будущая версия flan.
		// Повтор известного ключа — повреждение: неясно, какому значению верить.
		if (!fields.emplace(line.substr(0, equals), line.substr(equals + 1)).second) {
			error = "duplicate key '" + line.substr(0, equals) + "'";
			return false;
		}
	}

	for (const char* key : { "name", "version", "dir", "arch", "sha256", "bins" }) {
		if (fields.count(key) == 0) {
			error = std::string("missing '") + key + "'";
			return false;
		}
	}

	out.name = fields["name"];
	out.version = fields["version"];
	out.dir = fields["dir"];
	out.installedAt = fields["installed_at"];

	if (!isSafePackageName(out.name)) {
		error = "unsafe name";
		return false;
	}
	if (!isSafeName(out.version)) {
		error = "unsafe version";
		return false;
	}
	if (!isSafeName(out.dir)) {
		error = "unsafe dir";
		return false;
	}
	if (!archFromName(fields["arch"], out.arch)) {
		error = "unknown arch";
		return false;
	}

	uint8_t sha256[32];
	if (!fromHex(fields["sha256"], sha256, sizeof(sha256))) {
		error = "malformed sha256";
		return false;
	}
	out.sha256 = toHex(sha256, sizeof(sha256));

	if (!parseBinList(fields["bins"], out.bins)) {
		error = "unsafe bins";
		return false;
	}

	if (out.installedAt.size() > MAX_TIMESTAMP_LENGTH || !isSafeDescription(out.installedAt)) {
		error = "malformed installed_at";
		return false;
	}

	return true;
}

std::string receiptPath(const FlanPaths& paths, const std::string& name) {
	return paths.apps + "\\" + name + "\\receipt";
}

ReceiptState readReceipt(const FlanPaths& paths, const std::string& name, Receipt& out, std::string& error) {
	const std::string path = receiptPath(paths, name);
	if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
		return ReceiptState::Missing;
	}

	std::vector<uint8_t> bytes;
	bool tooLarge = false;
	if (!readWholeFile(path, MAX_RECEIPT_SIZE, bytes, tooLarge)) {
		error = tooLarge ? "receipt is too large" : "cannot read the receipt";
		return ReceiptState::Corrupt;
	}

	if (!parseReceipt(std::string(bytes.begin(), bytes.end()), out, error)) {
		return ReceiptState::Corrupt;
	}

	// Квитанция в apps\ripgrep\ с name=fd внутри — подмена или ошибка: путям из неё не верим.
	if (out.name != name) {
		error = "receipt belongs to '" + out.name + "'";
		return ReceiptState::Corrupt;
	}

	return ReceiptState::Valid;
}

bool writeReceipt(const FlanPaths& paths, const Receipt& receipt) {
	return saveFileAtomically(receiptPath(paths, receipt.name), formatReceipt(receipt));
}

std::string currentUtcTimestamp() {
	const std::time_t now = std::time(nullptr);
	std::tm utc = {};
	if (gmtime_s(&utc, &now) != 0) {
		return std::string();
	}

	char text[MAX_TIMESTAMP_LENGTH];
	std::strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &utc);
	return text;
}
