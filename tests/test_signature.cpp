#include "test.hpp"
#include "signing.hpp"
#include "flan/hex.hpp"
#include "flan/keys.hpp"
#include "flan/sha256.hpp"
#include "flan/signature.hpp"
#include <cstring>
#include <string>

// ECDSA P-256 (DESIGN.md §6.3): эталонный вектор RFC 6979, приложение A.2.5 (SHA-256, сообщения
// "sample" и "test"), — им же проверен формат r||s и порядок байт ключа; затем подпись генератора.

namespace {

	const char* RFC_X = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
	const char* RFC_Y = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
	const char* RFC_D = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
	const char* RFC_SAMPLE = "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
		"F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
	const char* RFC_TEST = "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"
		"019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083";

	struct Bytes64 { uint8_t b[64]; };
	struct Bytes32 { uint8_t b[32]; };

	Bytes64 hex64(const std::string& hex) { Bytes64 out = {}; fromHex(hex, out.b, 64); return out; }
	Bytes32 hex32(const std::string& hex) { Bytes32 out = {}; fromHex(hex, out.b, 32); return out; }

	Bytes32 sha(const std::string& text) {
		Bytes32 out = {};
		crypto::Sha256 hash;
		hash.update(text.data(), text.size());
		hash.finish(out.b);
		return out;
	}
}

void runSignatureTests() {
	beginSuite("signature: RFC 6979 vector");

	const Bytes64 publicKey = hex64(std::string(RFC_X) + RFC_Y);
	const Bytes32 sample = sha("sample");
	const Bytes32 test = sha("test");
	const Bytes64 sampleSig = hex64(RFC_SAMPLE);
	const Bytes64 testSig = hex64(RFC_TEST);

	check(crypto::verifyP256(publicKey.b, sample.b, sampleSig.b), "'sample' verifies");
	check(crypto::verifyP256(publicKey.b, test.b, testSig.b), "'test' verifies");
	check(!crypto::verifyP256(publicKey.b, test.b, sampleSig.b), "signature of another message is rejected");

	{
		bool allRejected = true;
		std::string failedAt;
		for (int i = 0; i < 64; i++) {
			for (const uint8_t bit : { (uint8_t)0x01, (uint8_t)0x80 }) {
				Bytes64 changed = sampleSig;
				changed.b[i] ^= bit;
				if (crypto::verifyP256(publicKey.b, sample.b, changed.b)) {
					allRejected = false;
					failedAt = std::to_string(i);
				}
			}
		}
		check(allRejected, "every flipped bit in r||s is rejected", failedAt);
	}
	{
		bool allRejected = true;
		for (int i = 0; i < 32; i++) {
			Bytes32 changed = sample;
			changed.b[i] ^= 0x01;
			allRejected = allRejected && !crypto::verifyP256(publicKey.b, changed.b, sampleSig.b);
		}
		check(allRejected, "every flipped bit in the digest is rejected");
	}
	{
		Bytes64 offCurve = publicKey;
		offCurve.b[63] ^= 0x01;
		check(!crypto::verifyP256(offCurve.b, sample.b, sampleSig.b), "a public key off the curve is rejected");

		const Bytes64 zeros = {};
		check(!crypto::verifyP256(publicKey.b, sample.b, zeros.b), "r = s = 0 is rejected");
		check(!crypto::verifyP256(zeros.b, sample.b, sampleSig.b), "an all-zero public key is rejected");

		Bytes64 sOnly = sampleSig;
		std::memset(sOnly.b, 0, 32);
		check(!crypto::verifyP256(publicKey.b, sample.b, sOnly.b), "r = 0 is rejected");
	}

	beginSuite("signature: flan-build signing");
	{
		// Приватный ключ из RFC: подпись генератора проверяется открытым ключом из RFC.
		SigningKey rfc;
		rfc.id = 9;
		std::memcpy(rfc.publicKey, publicKey.b, 64);
		const Bytes32 d = hex32(RFC_D);
		std::memcpy(rfc.privateKey, d.b, 32);

		uint8_t signature[64];
		std::string error;
		check(signDigest(rfc, sample.b, signature, error) && crypto::verifyP256(publicKey.b, sample.b, signature),
			"a signature with the RFC private key verifies", error);

		// ECDSA в CNG берёт случайное k: две подписи одного сообщения различаются, обе верны.
		uint8_t again[64];
		check(signDigest(rfc, sample.b, again, error) && std::memcmp(signature, again, 64) != 0 &&
			crypto::verifyP256(publicKey.b, sample.b, again), "a second signature differs and also verifies", error);

		SigningKey broken = rfc;
		broken.privateKey[31] ^= 0x01;
		uint8_t wrong[64];
		check(!signDigest(broken, sample.b, wrong, error) || !crypto::verifyP256(publicKey.b, sample.b, wrong),
			"a wrong private key does not produce a valid signature");
	}
	{
		SigningKey a;
		SigningKey b;
		std::string error;
		const bool made = generateSigningKey(1, a, error) && generateSigningKey(2, b, error);
		check(made, "two key pairs generated", error);
		check(made && std::memcmp(a.publicKey, b.publicKey, 64) != 0 && std::memcmp(a.privateKey, b.privateKey, 32) != 0,
			"the two pairs differ");

		uint8_t signature[64];
		check(signDigest(a, test.b, signature, error) && crypto::verifyP256(a.publicKey, test.b, signature) &&
			!crypto::verifyP256(b.publicKey, test.b, signature), "a signature verifies only with its own public key", error);

		SigningKey copy = a;
		copy.wipe();
		const Bytes32 zeros = {};
		check(std::memcmp(copy.privateKey, zeros.b, 32) == 0 && std::memcmp(a.privateKey, zeros.b, 32) != 0,
			"wipe clears only its own copy of the private key");

		// a — номер 1, как у настоящего рабочего ключа, но другой ключ.
		std::string differs;
		check(!matchesBuiltInKey(a, differs) && differs.find("differs from the key with the same number") != std::string::npos,
			"a random key numbered 1 is not the built-in key 1", differs);
		SigningKey stranger = a;
		stranger.id = 99;
		std::string notBuiltIn;
		check(!matchesBuiltInKey(stranger, notBuiltIn) && notBuiltIn.find("not in keys.hpp") != std::string::npos,
			"a key numbered 99 is not in keys.hpp", notBuiltIn);
	}

	beginSuite("signature: built-in keys");
	{
		size_t count = 0;
		const IndexKey* keys = builtInKeys(count);
		bool has1 = false;
		bool has2 = false;
		bool testKeys = false;
		bool nonZero = true;
		const Bytes64 zeros = {};
		for (size_t i = 0; i < count; i++) {
			has1 = has1 || keys[i].id == 1;
			has2 = has2 || keys[i].id == 2;
			testKeys = testKeys || keys[i].id >= FIRST_TEST_KEY_ID;
			nonZero = nonZero && std::memcmp(keys[i].publicKey, zeros.b, 64) != 0;
		}
		check(has1 && has2, "the working key 1 and the reserve key 2 are built in");
#ifdef _DEBUG
		check(testKeys, "Debug: test keys 240 and 241 are built in");
#else
		check(!testKeys, "Release: no test keys");
#endif
		check(nonZero, "built-in keys are non-zero");
	}

	beginSuite("signature: key output");
	{
		const std::string entry = keyAsCppEntry(1, publicKey.b);
		check(entry.find("{ 1, {") != std::string::npos && entry.find("0x60, 0xFE, 0xD4") != std::string::npos &&
			entry.find("0x22, 0x99\n") != std::string::npos, "keys.hpp entry: number and bytes in order", entry);

		const std::string fingerprint = keyFingerprint(publicKey.b);
		check(fingerprint.size() == 19 && fingerprint[4] == ' ' && fingerprint[9] == ' ' && fingerprint[14] == ' ',
			"fingerprint: four groups of four hex digits", fingerprint);
	}
}
