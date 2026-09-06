# zvolrescue

**Відкрита утиліта для forensic-аналізу та відновлення даних ZFS**

`zvolrescue` читає пули ZFS напряму з дисків або образів дисків — без
імпорту в ядро і без жодного запису в них — та відновлює dataset-и, з
основним фокусом на **zvol** (диски bhyve/VM, iSCSI-таргети, томи
контейнерів), на будь-якій transaction group (TXG), яка ще є на диску.
Також формує forensic-звіти: історію міток та uberblock-ів, часову шкалу
створення/знищення dataset-ів і хеш-верифіковані логи витягання.

**Мова:** Rust | **Ліцензія:** BSD 3-Clause | **Статус:** етап проєктування (pre-alpha) — див. [ТЗ](docs/SPEC.uk.md)

[English version](README.md) | [ТЗ українською](docs/SPEC.uk.md) | [Technical specification](docs/SPEC.md)

> **Щойно втратили zvol?** *Негайно* припиніть будь-який запис у пул
> (`zpool export` або вимкніть хост), потім зніміть образи дисків. ZFS
> швидко перевикористовує звільнені блоки; кожен запис звужує вікно
> відновлення.

## Навіщо

У ZFS немає `undelete`. Коли dataset знищено помилково або пул не
імпортується після апаратного збою, наявні варіанти не влаштовують:

| Інструмент | Обмеження |
|---|---|
| `zpool import -F` / `-T <txg>` | Відкочує **весь пул**, змінює його і працює лише поки живі старі uberblock-и (хвилини). |
| `zdb` | Налагоджувач, а не процес відновлення; падає на пошкоджених метаданих. |
| Скрипти типу `zfs_revert` | Перезаписують uberblock-и **на місці** на живих пристроях. |
| Klennet ZFS Recovery, UFS Explorer, ReclaiMe | Закритий код, лише Windows, дорого, не аудитується. |

`zvolrescue` задуманий як інструмент, який можна запустити на
rescue-системі над read-only доказами і результат якого можна захистити
у звіті.

## Заплановані можливості

* **Read-only за побудовою** — evidence відкривається `O_RDONLY`; вивід ніколи не потрапить на вхідний пристрій.
* **Без ядрового ZFS** — чистий userland; працює там, де `zfs.ko` не завантажено або пул не імпортується.
* **Будь-який стан пулу** — здоровий, degraded, знищений, пошкоджені мітки, відсутні vdev (поки дозволяє надлишковість).
* **Будь-який TXG** — вибір явно, за часом або «останній, де цей dataset ще був».
* **Повне покриття on-disk можливостей** — реконструкція stripe/mirror/RAIDZ1-3/dRAID; `lz4`, `zstd`, `gzip`, `lzjb`, `zle`; `fletcher`, `sha256/512`, `skein`, `edonr`, `blake3`; embedded та gang-блоки; шифровані dataset-и з наданим ключем.
* **Sparse-aware витягання** zvol у сирі образи з поблочною перевіркою checksum, продовженням та режимом `--strict`.
* **Carving** від'єднаних zvol, uberblock-и яких уже зникли.
* **Forensic-вивід** — `-f json` усюди, часова шкала TXG, append-only лог evidence, зведений звіт із ланцюжком SHA-256.

## Запланований CLI

```
zvolrescue scan       DEV...                         виявити мітки ZFS
zvolrescue labels     DEV [--all]                    дамп nvlist міток
zvolrescue uberblocks DEV|POOL [--all]               кільце uberblock-ів
zvolrescue pool       POOLSPEC                       зведення зібраного пулу
zvolrescue list       POOLSPEC [--txg N|--before TS] [--diff TXG2] [-r]
zvolrescue timeline   POOLSPEC                       TXG ↔ час ↔ події dataset-ів
zvolrescue dump       POOLSPEC DATASET -o OUT.img [--txg N] [--strict] [--key KEYSPEC]
zvolrescue carve      POOLSPEC [--type zvol] [-o DIR]
zvolrescue verify     POOLSPEC DATASET [--txg N]
zvolrescue report     POOLSPEC -o report.json
```

```sh
# Які TXG ще доступні на цих дисках?
zvolrescue uberblocks /dev/ada0p3

# Коли зник pool/vm/disk0?
zvolrescue timeline /dev/ada0p3 /dev/ada1p3 | grep disk0

# Витягти його з останнього TXG, де він ще був, з перевіркою кожного блоку.
zvolrescue dump /dev/ada0p3 /dev/ada1p3 pool/vm/disk0 --txg 4816230 \
    --strict -o /mnt/rescue/disk0.img --evidence-log case42.jsonl
```

## Дорожня карта

| Етап | Обсяг |
|---|---|
| 0 — Bootstrap | Скелет репо, ТЗ, CI (FreeBSD + Linux), генератор fixture-пулів, `scan`/`labels`/`uberblocks` |
| 1 — MVP | `list`, `timeline`, `dump` на single/mirror пулах; поширені стиснення та checksum-и; JSON-вивід |
| 2 — Надлишковість та цілісність | Реконструкція RAIDZ/dRAID, усі checksum-и, `verify`, `--strict`, продовження, масове витягання |
| 3 — Forensics | Шифровані dataset-и, carving від'єднаних zvol, `report`, ланцюжок хешів |
| 4 — Файлові системи | Дампи об'єктів, потім файлове відновлення ZPL |

Деталі, вимоги та критерії приймання: [docs/SPEC.uk.md](docs/SPEC.uk.md).

## Структура репозиторію

```
README.md, README_UK.md     цей файл (EN / UK)
docs/SPEC.md                технічне завдання (ТЗ), англійською — джерело істини
docs/SPEC.uk.md             те саме українською
docs/research/              аналізи схожих інструментів, нотатки про on-disk формат
Cargo.toml                  cargo workspace
crates/zvolrescue/          бінарник CLI
crates/zvolrescue-io/       read-only доступ до пристроїв/образів (єдиний crate з `unsafe`)
crates/zfs-ondisk/          чисті парсери on-disk структур (мітки, nvlist, uberblock-и, blkptr, dnode, ZAP)
crates/zfs-read/            обхід пулу: реконструкція vdev, zio, dmu, dsl, витягання zvol, carving
crates/edonr/               порт checksum Edon-R з OpenZFS (CDDL), ізольований
fuzz/                       cargo-fuzz target-и
tests/                      інтеграційні тести на fixture-пулах
```

## Збірка

```sh
cargo build --release          # бінарник у target/release/zvolrescue
cargo test
cargo clippy --all-targets -- -D warnings
```

Rust stable (`lang/rust` з портів FreeBSD або `rustup`). C-toolchain і
системні бібліотеки не потрібні: увесь стек декодування — чистий Rust.

## Платформи

FreeBSD 13.x–15.x — цілі першого класу. Linux — підтримувана платформа
збірки та тестування. macOS — best-effort.

## Участь

Проєкт на етапі специфікації. Найкорисніше зараз — рецензії
[docs/SPEC.uk.md](docs/SPEC.uk.md), особливо відкритих питань у §12, та
реальні сценарії відновлення, які має покрити тестовий набір на
fixture-пулах.

## Пов'язане

* [crate](https://github.com/click0/crate) — контейнеризатор для FreeBSD того ж автора; `zvolrescue` наслідує його CI-конвенції та двомовний стиль документації.

## Ліцензія

BSD 3-Clause. Див. [LICENSE](LICENSE).
Порт Edon-R у `crates/edonr/` зберігає свою оригінальну ліцензію CDDL.

## Автор

Владислав В. Продан — [support.od.ua](https://support.od.ua/)
