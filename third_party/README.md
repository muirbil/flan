# third_party

Сторонний код, вендоренный в репозиторий. Файлы не правятся вручную: обновление —
это замена файлов из нового релиза и обновление таблиц ниже.

## miniz 3.1.2 — MIT

- Источник: https://github.com/richgel999/miniz/releases/download/3.1.2/miniz-3.1.2.zip
- SHA-256 архива релиза: `f0446d863f9c19926ad9483c523fdc42e42b8d4a6a431d27e09d49c79a140d9a`
- Взяты без изменений (объединённая сборка из релиза):

| Файл | SHA-256 |
|---|---|
| `miniz/miniz.c` | `e2c1aeb66eef9191d8c3feb164db2def2335a61d039bf04ed849f6b042433b30` |
| `miniz/miniz.h` | `b53b62ed122e559b8f679e3cb787a0b0035fe87a58f909da0e44931678f4e85f` |
| `miniz/LICENSE` | `0115478d567121238cf6cc1c0c361926cf07a49d9e4c9e66da97fac6a01646b3` |

Как используется (DESIGN.md §4):

- **клиент** — только `tinfl` (распаковка сжатого индекса): `miniz.c` собирается
  с `MINIZ_NO_DEFLATE_APIS`, без архивов, stdio, времени и zlib-обёрток;
- **flan-build и тесты** — ещё и `tdefl` (сжатие индекса).

В `.gitattributes` для `third_party/miniz/` отключено преобразование переводов строк,
поэтому хэши выше совпадают и в свежем клоне при `core.autocrlf`.

## nlohmann/json 3.12.0 — MIT

- Только для flan-build: клиент JSON не разбирает (DESIGN.md §3), и пути к
  `third_party/nlohmann` в его проекте нет.
- `nlohmann/json.hpp`, SHA-256 копии в репозитории:
  `aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63`.
