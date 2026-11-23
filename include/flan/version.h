#pragma once

// Версия flan (DESIGN.md §7.7, --version): та же — в VERSIONINFO ресурсов flan.exe и в индексе
// у пакета flan. Самообновление сверяет вывод `flan.exe.new --version` с версией из индекса (§7.9).
// Заголовок на чистом C-препроцессоре: его читает и компилятор ресурсов.

#define FLAN_VERSION_MAJOR 0
#define FLAN_VERSION_MINOR 4
#define FLAN_VERSION_PATCH 0
#define FLAN_VERSION_STRING "0.4.0"
