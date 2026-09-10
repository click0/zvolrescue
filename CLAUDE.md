# CLAUDE.md — інструкції для сесій Claude Code у цьому репозиторії

## Перше, що зробити в новому клоні

```bash
git config core.hooksPath .githooks        # хук додає трейлери атрибуції до комітів із Claude Code
rustup update stable                        # CI ганяє clippy на найновішому stable; локальний старіший
                                            # rustc пропускає лінти, які CI потім ловить
sudo apt-get install -y zfsutils-linux zfs-test   # ztest + zdb для tests/crosscheck-ztest.sh (ядро не потрібне)
cargo build --release && cargo build --release -p zfs-read --examples
```

## Мова спілкування

Відповідати користувачу **українською**. Код, коміти, CHANGELOG — англійською.
Документація в `docs/` і README — двомовна: кожен `X.md` має пару `X.uk.md`
(README — `README_UK.md`); зміни вносити в обидва.

## Правила комітів

- **Маленькі коміти, по одному на модуль/етап, пуш після кожного** — так
  просив користувач. Не накопичувати кілька етапів в одному коміті.
- Перед кожним комітом (усе має бути зеленим, інакше користувач отримує
  листи про червоний CI):
  ```bash
  cargo fmt --all
  cargo clippy --workspace --all-targets --release -- -D warnings
  cargo test --workspace --release
  ```
  Якщо змінювався парсер on-disk формату, читач чи контрольні суми — ще й
  `tests/crosscheck-ztest.sh ./target/release/zvolrescue /tmp/xc` (≈6 хв,
  п'ять ztest-пулів, вісім кроків) або хоча б `walk-objects` на наявних
  пулах у `/tmp/xc*`.
- Трейлери в кінці повідомлення (хук додає сам, якщо `core.hooksPath`
  увімкнено; інакше — вручну):
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_<id>
  ```
  (`<id>` — `CLAUDE_CODE_REMOTE_SESSION_ID` без префікса `cse_`.)
- Ніяких ідентифікаторів моделі в коді, коментарях, доках чи PR-описах —
  лише в трейлері.
- Версія (`version` у кореневому `Cargo.toml`, одна на весь workspace) і
  `CHANGELOG.md`/`CHANGELOG.uk.md` бампаються **на реліз**, не на коміт.
  Схема тегів: перший — `v0.1.0-alpha.1`, далі **лише мінорні без суфіксів**:
  `v0.2.0`, `v0.3.0`, …; patch — для виправлень випущеного мінору. Перед
  тим, як користувач ставить тег, у `main` мають бути: нова `version`,
  секція `## vX.Y.Z — дата` в обох CHANGELOG, зелений CI.

## Робочий процес

1. Розробка йде **прямо в `main`** (так склалося з першого дня; PR не
   використовуються). Перед роботою — `git pull origin main`.
2. Після пушу перевірити CI (три джоби: Linux e2e на фікстурах, crosscheck
   проти OpenZFS userland, FreeBSD 14.2). Червоний CI — виправляти негайно,
   наступним комітом; не лишати на потім.
3. Стежити за CI через GitHub API за run-ом; лог падіння читати повністю —
   crosscheck друкує причину на кроці, а не в кінці.
4. **Теги через проксі не пушаться** — реліз створює користувач вручну:
   тег `vX.Y.Z` запускає `release.yml`, який збирає статичні бінарники
   (x86_64/aarch64 musl, FreeBSD amd64), `SHA256SUMS` і публікує реліз із
   секцією CHANGELOG. Заголовок релізу (`zvolrescue vX.Y.Z`) і нотатки
   (англійською: що це, таблиця артефактів, секція CHANGELOG, застереження
   для pre-release) формує сам workflow — після завершення пайплайна
   перевірити сторінку релізу і, якщо треба, доправити текст через API.
   Процедура — `docs/RELEASING.md`.
5. Кожен новий факт про on-disk формат, знайдений на реальних даних, —
   рядок у `docs/REALWORLD-TESTS.md` (+ `.uk.md`) і, якщо змінює
   архітектурне рішення, — у журнал рішень `docs/SPEC.md` §13.

## Архітектура (коротко)

Cargo workspace, чистий Rust, без `unsafe` (workspace lint `forbid`), без
C-тулчейна і системних бібліотек, **без лінкування з OpenZFS** (рішення D-4
у SPEC: `ztest`/`zdb` — лише оракул у тестах).

- `crates/zvolrescue-io` — `BlockSource` (лише `O_RDONLY`), `SparseFile`,
  `refuse_if_evidence`, трасування (`trace!`, `hexdump`).
- `crates/zfs-ondisk` — парсери формату без I/O: `label`, `uberblock`,
  `nvlist`, `blkptr`, `dmu`, `dsl`, `zap`, `checksum` (усі алгоритми),
  `compress`, `raidz`, `draid`, `skein`.
- `crates/edonr` — порт Edon-R з OpenZFS, **CDDL**, навмисно окремий crate.
- `crates/zfs-read` — читання пулу: `vdev` (скан), `pool` (збирання),
  `zio` (`PoolReader`: дерево vdev-ів, mirror/raidz/draid, gang, embedded,
  розшифрування), `dmu`, `zap`, `dsl` (у т.ч. метадані шифрування), `crypt`
  (ключі), `zvol` (витягання), `fixture` (синтетичні пули для тестів);
  приклади `mkfixture`, `walk-objects`, `unwrap-key`.
- `crates/zvolrescue` — CLI, **атомарний**: лише `scan`, `list`, `dump`.
  Усе форензичне — супутні інструменти (`docs/COMPANIONS.md`).
- `crates/zvol-common` — спільний контракт бінарників: прапорці (`Global`,
  `PoolSpec` з `--hints`/`--search-order`/`--assume-member`), коди виходу,
  відкриття членів і вибір пулу, лог evidence, формат часу.
- `crates/zvoltimeline` — перший супутник: історія пулу з транзакційних
  груп, що вціліли (COMPANIONS §2).
- `crates/zvolreport` — другий супутник: логи evidence, зведені в один
  документ із ланцюжком SHA-256, і його перевірка (COMPANIONS §4).
- `crates/zvolcarve` — третій супутник: скан сирого простору vdev по
  dnode-ах, на які вже не вказує жоден уберблок, профіль пошуку і
  видобування через ту саму трубу, що й `zvolrescue dump` (COMPANIONS §3).
- `crates/zvolfiles` — четвертий супутник: ZFS POSIX layer (майстер-нода,
  каталоги, системні атрибути), видобування дерева з маніфестом і
  запасний дамп по об'єктах (COMPANIONS §5).
- `tests/crosscheck-ztest.sh` — звірка з OpenZFS userland; ключ шифрування
  ztest — рядок `abcdefghijklmnopqrstuvwxyz012345` (keyformat raw).

Новий супутній інструмент = новий член workspace `crates/<tool>/`, CLI
через `zvol-common`, крок у `ci.yml` на fixture-пулі з `mkfixture`,
рядок у README/README_UK і секція стану в `docs/COMPANIONS*.md`.

## Інваріанти — не ламати

- Лише читання: члени відкриваються `O_RDONLY`; вивід на член пулу
  відхиляється (`refuse_if_evidence`); тул нічого не пише в пул ніколи.
- Ворожий вхід: парсери повертають `Result`, жодних panic на сміття
  (fuzz-цілі й тести на обрізані/зіпсовані буфери).
- Коди виходу: 0 успіх, 1 usage (у т.ч. нема/хибний ключ), 2 evidence,
  3 unrecoverable, 4 partial, 5 refused, 64 not implemented.
- JSON-вивід (`-f json`) — стабільний контракт; поля лише додаються.
- Кожна нова on-disk можливість перевіряється на **справжньому** пулі
  (ztest), не лише на власних фікстурах: фікстури пише той самий код, тож
  вони не ловлять помилок порядку байтів/слів.

## Пастки формату, що вже коштували часу (не повторювати)

- `sha512` зберігає слова дайджесту в рідному порядку записувача (як
  blake3/skein/edonr), `sha256` — big-endian.
- `edonr` не має прапорця DEDUP → під шифруванням його слова згортаються
  xor-ом, як у fletcher; `skein`/`blake3`/`sha*` — ні.
- Gang-заголовок шифрованого блока несе *згорнуту* контрольну суму.
- zstd-кадри OpenZFS без magic; рівень у старшому байті другого слова заголовка.
- Таблиця `dmu_ot`: other-ZAP, zvol-prop, znode, master-node, FUID-size —
  лише автентифіковані, не шифровані (колонка `ot_encrypt`).
- `keyformat`/`pbkdf2*` лежать у крипто-ZAP, `keylocation` — у props каталогу.
- AAD dnode-блока: `dn_used` на зсуві 24; bonus починається після *всіх*
  `dn_nblkptr` blkptr-ів.
- Парність dRAID рахується по всій ширині групи (порожні хвостові колонки
  зсувають Q/R); у RAIDZ — лише по зайнятих колонках.
- Мітка з `txg 0` (пристрій у процесі attach/replace) не описує топологію.

## Файли, яких не має бути в репо

`target/`, тестові пули (`/tmp/xc*`, `ztest.*`), ключі (`*.key`), образи
`*.img`, `*.resume.json`, `manifest.json` від `dump -r`. Усе в `.gitignore`.
