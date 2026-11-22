#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {

	// Потоковый SHA-256 (DESIGN.md §7.2, «хэш на лету»): данные подаются кусками
	// прямо из цикла загрузки, второго прохода по файлу нет.
	class Sha256 {
	public:
		Sha256();
		~Sha256();
		Sha256(const Sha256&) = delete;
		Sha256& operator=(const Sha256&) = delete;

		// false — CNG недоступен; тогда и finishHex вернёт пустую строку.
		bool ok() const;

		void update(const void* data, size_t size);

		// Начать заново: загрузка пошла с нуля (сервер не понял Range).
		void reset();

		// Hex в нижнем регистре; после вызова объект нужно reset() перед новым использованием.
		std::string finishHex();

	private:
		void open();
		void close();

		void* algorithm_ = nullptr;					// BCRYPT_ALG_HANDLE
		void* hash_ = nullptr;							// BCRYPT_HASH_HANDLE
		std::vector<uint8_t> object_;
		bool ok_ = false;
	};

	// Первые bytes байт файла — в хэш (докачка, DESIGN.md §7.2: уже скачанная часть хэшируется
	// один раз перед продолжением). false — файл не прочитать или он короче bytes.
	bool hashFilePrefix(const std::string& filePath, uint64_t bytes, Sha256& hash);

	// Хэш файла целиком (hex в нижнем регистре); пусто — файл не прочитать.
	std::string calculateSHA256(const std::string& filePath);
}
