#pragma once

#include <string>

// Каталоги %FLAN_HOME% (DESIGN.md §7.1). Корень — FLAN_HOME или %USERPROFILE%\.flan
// (resolveFlanHome). Пути — UTF-8; в UTF-16 с \\?\ их переводит io/fs прямо перед вызовом ФС.
struct FlanPaths {
	std::string home;
	std::string apps;									// apps\<name>\<dir>\, apps\<name>\receipt
	std::string bin;									// прослойки; единственное, что добавляется в PATH
	std::string cache;									// cache\<sha256>.part и cache\<sha256> — архивы по содержимому
	std::string state;									// state\index.flan, state\pending-delete
	std::string tmp;									// прочее временное
	std::string lock;

	static FlanPaths under(const std::string& home) {
		FlanPaths paths;
		paths.home = home;
		paths.apps = home + "\\apps";
		paths.bin = home + "\\bin";
		paths.cache = home + "\\cache";
		paths.state = home + "\\state";
		paths.tmp = home + "\\tmp";
		paths.lock = home + "\\lock";
		return paths;
	}
};
