#pragma once

#include <string>

// Каталоги %FLAN_HOME% (DESIGN.md §7.1). До этапа 3 корень — %USERPROFILE%\.flan,
// а пути — ANSI-строки; Unicode и FLAN_HOME появятся вместе с io/fs.cpp на W-функциях.
struct FlanPaths {
	std::string home;
	std::string apps;									// apps\<name>\<dir>\, apps\<name>\receipt
	std::string bin;									// прослойки; единственное, что добавляется в PATH
	std::string state;									// state\index.flan, state\pending-delete
	std::string tmp;									// загрузки и прочее временное
	std::string lock;

	static FlanPaths under(const std::string& home) {
		FlanPaths paths;
		paths.home = home;
		paths.apps = home + "\\apps";
		paths.bin = home + "\\bin";
		paths.state = home + "\\state";
		paths.tmp = home + "\\tmp";
		paths.lock = home + "\\lock";
		return paths;
	}
};
