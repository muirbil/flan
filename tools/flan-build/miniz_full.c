/* miniz для генератора и тестов: tdefl (сжатие индекса) и tinfl (самопроверка
   собранного индекса тем же разбором, что в клиенте). zip-архивы, stdio, время
   и zlib-обёртки не нужны и не собираются. */

#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#define MINIZ_NO_ZLIB_APIS
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES

#include "miniz.c"
