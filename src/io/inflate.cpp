// Те же настройки, что в miniz_inflate.c: без zlib-совместимых имён, которые
// иначе определились бы макросами (crc32, compress, ...) во всём этом файле.
#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#define MINIZ_NO_ZLIB_APIS
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_NO_DEFLATE_APIS

#include "flan/inflate.hpp"
#include "miniz.h"

bool inflateRawExact(const uint8_t* data, size_t size, size_t rawSize, std::vector<uint8_t>& out, std::string& error) {
	out.clear();
	if (rawSize == 0 || size == 0) {
		error = "empty compressed body";
		return false;
	}

	// Буфер ровно на rawSize: поток, который хочет вывести больше, остановится на
	// TINFL_STATUS_HAS_MORE_OUTPUT, а не раздует память (защита от «бомбы»).
	out.assign(rawSize, 0);

	tinfl_decompressor decompressor;
	tinfl_init(&decompressor);

	size_t consumed = size;
	size_t produced = rawSize;
	const tinfl_status status = tinfl_decompress(&decompressor, data, &consumed, out.data(), out.data(), &produced,
		TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);

	if (status == TINFL_STATUS_DONE && produced == rawSize && consumed == size) {
		return true;
	}

	out.clear();
	if (status == TINFL_STATUS_HAS_MORE_OUTPUT) {
		error = "the compressed body expands beyond raw_size";
	}
	else if (status == TINFL_STATUS_DONE && produced != rawSize) {
		error = "the compressed body expands to less than raw_size";
	}
	else if (status == TINFL_STATUS_DONE) {
		error = "data after the end of the compressed body";
	}
	else {
		error = "the compressed body is corrupted";
	}
	return false;
}
