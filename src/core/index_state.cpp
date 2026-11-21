#include "core/index_state.hpp"
#include "flan/fs.hpp"
#include "flan/http_policy.hpp"
#include <vector>

namespace {
	constexpr size_t MAX_SOURCE_LENGTH = 2048;
	constexpr size_t MAX_ETAG_LENGTH = 256;
	constexpr uint64_t MAX_STATE_SIZE = 8 * 1024;

	// Источник и ETag уходят в заголовок запроса и в вывод: только печатные ASCII.
	bool isPrintable(const std::string& text, size_t maxLength) {
		if (text.size() > maxLength) {
			return false;
		}
		for (const unsigned char c : text) {
			if (c < 0x20 || c >= 0x7F) {
				return false;
			}
		}
		return true;
	}

	std::string statePath(const FlanPaths& paths) {
		return paths.state + "\\index.state";
	}
}

std::string formatIndexState(const IndexState& state) {
	return "source=" + state.source + "\n" +
		"etag=" + state.etag + "\n" +
		"generated_at=" + std::to_string(state.generatedAt) + "\n";
}

bool parseIndexState(const std::string& text, IndexState& out) {
	out = IndexState();
	bool hasSource = false;

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
		if (equals == std::string::npos) {
			return false;
		}

		const std::string key = line.substr(0, equals);
		const std::string value = line.substr(equals + 1);

		if (key == "source") {
			if (!isPrintable(value, MAX_SOURCE_LENGTH) || value.empty()) {
				return false;
			}
			out.source = value;
			hasSource = true;
		}
		else if (key == "etag") {
			if (!isPrintable(value, MAX_ETAG_LENGTH)) {
				return false;
			}
			out.etag = value;
		}
		else if (key == "generated_at") {
			if (!parseUint64(value, out.generatedAt)) {
				return false;
			}
		}
		// Неизвестные ключи пропускаются: их может дописать будущая версия flan.
	}

	return hasSource;
}

bool loadIndexState(const FlanPaths& paths, IndexState& out) {
	std::vector<uint8_t> bytes;
	bool tooLarge = false;
	if (!readWholeFile(statePath(paths), MAX_STATE_SIZE, bytes, tooLarge)) {
		out = IndexState();
		return false;
	}
	return parseIndexState(std::string(bytes.begin(), bytes.end()), out);
}

bool saveIndexState(const FlanPaths& paths, const IndexState& state) {
	return saveFileAtomically(statePath(paths), formatIndexState(state));
}
