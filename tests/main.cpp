#include "test.hpp"
#include <cstdio>
#include <cstring>

namespace {
	int passed = 0;
	int failed = 0;
	bool verbose = false;
	const char* currentSuite = "";
}

void beginSuite(const char* name) {
	currentSuite = name;
	if (verbose) {
		std::printf("\n[%s]\n", name);
	}
}

void check(bool ok, const std::string& label, const std::string& detail) {
	if (ok) {
		passed++;
	}
	else {
		failed++;
	}

	if (!ok || verbose) {
		std::printf("%s  %s: %s%s%s\n", ok ? "PASS" : "FAIL", currentSuite, label.c_str(),
			detail.empty() ? "" : "  -- ", detail.c_str());
	}
}

int main(int argc, char* argv[]) {
	verbose = argc > 1 && std::strcmp(argv[1], "-v") == 0;

	runValidateTests();
	runIndexTests();
	runReceiptTests();

	// Разрядность в выводе: переполнения смещений проверяются осмысленно только в 32 битах.
	std::printf("%d passed, %d failed (%d-bit)\n", passed, failed, (int)(sizeof(void*) * 8));
	return failed == 0 ? 0 : 1;
}
