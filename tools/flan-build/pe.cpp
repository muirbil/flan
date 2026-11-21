#include "build.hpp"
#include "flan/index.hpp"
#include <cstring>

namespace {

	// Поля COFF-заголовка (сразу за сигнатурой PE\0\0).
	constexpr size_t COFF_MACHINE = 4;
	constexpr size_t COFF_CHARACTERISTICS = 22;
	constexpr size_t COFF_END = 24;

	constexpr uint16_t IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
	constexpr uint16_t IMAGE_FILE_DLL = 0x2000;

	uint16_t machineFor(uint8_t arch) {
		switch (arch) {
		case ARCH_X86: return 0x014C;
		case ARCH_X64: return 0x8664;
		case ARCH_ARM64: return 0xAA64;
		default: return 0;
		}
	}

	std::string machineName(uint16_t machine) {
		switch (machine) {
		case 0x014C: return "x86";
		case 0x8664: return "x64";
		case 0xAA64: return "arm64";
		default: {
			static const char digits[] = "0123456789ABCDEF";
			std::string hex = "machine 0x";
			for (int shift = 12; shift >= 0; shift -= 4) {
				hex += digits[(machine >> shift) & 0xF];
			}
			return hex;
		}
		}
	}
}

bool checkPeHeader(const uint8_t* data, size_t size, uint8_t arch, std::string& error) {
	if (size < 0x40 || data[0] != 'M' || data[1] != 'Z') {
		error = "not a Windows executable (no MZ header)";
		return false;
	}

	// e_lfanew — смещение заголовка PE; проверяется по размеру прочитанного, как любое
	// смещение из недоверенного файла.
	uint32_t peOffset = 0;
	std::memcpy(&peOffset, data + 0x3C, sizeof(peOffset));
	if ((uint64_t)peOffset + COFF_END > size) {
		error = "PE header is out of bounds";
		return false;
	}

	if (std::memcmp(data + peOffset, "PE\0\0", 4) != 0) {
		error = "no PE signature";
		return false;
	}

	uint16_t machine = 0;
	uint16_t characteristics = 0;
	std::memcpy(&machine, data + peOffset + COFF_MACHINE, sizeof(machine));
	std::memcpy(&characteristics, data + peOffset + COFF_CHARACTERISTICS, sizeof(characteristics));

	if (!(characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
		error = "not an executable image";
		return false;
	}
	if (characteristics & IMAGE_FILE_DLL) {
		error = "a DLL, not an executable";
		return false;
	}

	// Ловит и опечатку «в x86 положили ссылку на amd64-сборку».
	if (machine != machineFor(arch)) {
		const char* listed = archName(arch);
		error = "the executable is built for " + machineName(machine) + ", but listed under " + (listed ? listed : "an unknown architecture");
		return false;
	}

	return true;
}
