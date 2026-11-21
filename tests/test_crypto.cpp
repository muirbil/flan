#include "test.hpp"
#include "flan/sha256.hpp"
#include <string>
#include <vector>

// Потоковый SHA-256: эталонные векторы FIPS 180-2 и независимость результата
// от того, какими кусками подаются данные (так их подаёт цикл загрузки).

namespace {
	std::string sha(const std::string& text) {
		crypto::Sha256 hash;
		hash.update(text.data(), text.size());
		return hash.finishHex();
	}
}

void runCryptoTests() {
	beginSuite("sha256");

	check(sha("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty");
	check(sha("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");
	check(sha("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
		"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "448-bit message");

	{
		// Миллион 'a' кусками по 1000 — эталон из FIPS 180-2.
		crypto::Sha256 hash;
		const std::string chunk(1000, 'a');
		for (int i = 0; i < 1000; i++) {
			hash.update(chunk.data(), chunk.size());
		}
		check(hash.finishHex() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "one million 'a' in chunks");
	}

	{
		// Любое разбиение даёт тот же хэш, что и один кусок.
		std::vector<uint8_t> data(100003);
		for (size_t i = 0; i < data.size(); i++) data[i] = (uint8_t)(i * 31 + 7);

		crypto::Sha256 whole;
		whole.update(data.data(), data.size());
		const std::string expected = whole.finishHex();

		bool allMatch = true;
		for (const size_t step : { (size_t)1, (size_t)7, (size_t)4096, (size_t)65536, (size_t)99999 }) {
			crypto::Sha256 parts;
			for (size_t offset = 0; offset < data.size(); offset += step) {
				parts.update(data.data() + offset, (data.size() - offset) < step ? data.size() - offset : step);
			}
			allMatch = allMatch && parts.finishHex() == expected;
		}
		check(allMatch, "chunking does not change the hash");
	}

	{
		// reset начинает с нуля: так загрузка «забывает» отброшенный .part.
		crypto::Sha256 hash;
		hash.update("garbage", 7);
		hash.reset();
		hash.update("abc", 3);
		check(hash.finishHex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "reset starts over");
	}

	{
		crypto::Sha256 hash;
		check(hash.ok(), "CNG provider available");
		hash.finishHex();
		check(hash.finishHex().empty(), "second finish without reset gives nothing");
	}
}
