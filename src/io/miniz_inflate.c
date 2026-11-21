/* miniz для клиента (DESIGN.md §4): только tinfl — распаковка сжатого индекса.
   Сжатие, zip-архивы, stdio, время и zlib-обёртки клиенту не нужны и не собираются. */

#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#define MINIZ_NO_ZLIB_APIS
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_NO_DEFLATE_APIS

#include "miniz.c"
