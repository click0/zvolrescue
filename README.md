# zvolrescue

**Open-Source ZFS Forensic & Recovery Utility**

`zvolrescue` reads ZFS pools directly from disks or disk images — without
importing them into the kernel and without ever writing to them — and
recovers datasets, with a first-class focus on **zvols** (bhyve/VM disks,
iSCSI targets, container volumes), at any transaction group (TXG) that is
still present on disk. It also produces forensic reports: label and
uberblock history, dataset creation/destruction timeline, and
hash-verified extraction logs.

**Language:** Rust | **License:** BSD 3-Clause | **Status:** Phase 1 MVP (pre-alpha) — `scan`, `list` and `dump` work on stripe, mirror, RAIDZ1/2/3 and dRAID pools (parity reconstruction of missing and silently corrupted columns, distributed spares), gang blocks, fletcher/sha256/sha512/blake3/skein/edonr checksums (every OpenZFS algorithm), lz4/zstd/gzip/lzjb/zle, with `--resume` and bulk `-r`; encrypted datasets: `list` reports the suite and key format, `dump --key` (raw/hex/passphrase/prompt) decrypts (phase 3; ZIL excluded). Cross-checked against OpenZFS userland (`ztest`/`zdb`) in CI; not yet run on a real kernel-imported pool. See the [specification](docs/SPEC.md).

[Українська версія](README_UK.md) | [Technical specification (ТЗ)](docs/SPEC.md) | [ТЗ українською](docs/SPEC.uk.md) | [Companion tools spec](docs/COMPANIONS.md) | [Debugging on a test pool](docs/DEBUGGING.md) | [Real-world test matrix](docs/REALWORLD-TESTS.md)

> **Lost a zvol just now?** Stop all writes to the pool *immediately*
> (`zpool export`, or power the host down), then image the disks. ZFS
> reuses freed blocks quickly; every write shrinks the recovery window.

## Why

ZFS has no `undelete`. When a dataset is destroyed by mistake or a pool
refuses to import after a hardware fault, the existing options are all
unsatisfying:

| Tool | Limitation |
|---|---|
| `zpool import -F` / `-T <txg>` | Rolls back the **whole pool**, modifies it, and only works while the old uberblocks survive (minutes). |
| `zdb` | A debugger, not a recovery workflow; panics on damaged metadata. |
| `zfs_revert`-style scripts | Overwrite uberblocks **in place** on live devices. |
| Klennet ZFS Recovery, UFS Explorer, ReclaiMe | Closed source, Windows-only, expensive, not auditable. |

`zvolrescue` is meant to be the tool you can run on a rescue system, on
read-only evidence, and defend the result of in a report.

## One atomic utility

`zvolrescue` does one job: turn ZFS on-disk structures into a plain image
of one dataset. It is a single static binary with three commands, no
configuration, no daemon, no plugins, no network. The same arguments over
the same evidence always produce the same bytes. Forensic timelines,
carving, reports and file-level recovery are *companion tools* that share
the libraries — they never become modes of the main binary.

## Planned features

* **Read-only by construction** — evidence is opened `O_RDONLY`; output can never land on an input device.
* **No kernel ZFS needed** — pure userland; runs where `zfs.ko` is not loaded or the pool cannot be imported.
* **Any pool state** — healthy, degraded, destroyed, damaged labels, missing vdevs (as long as redundancy allows).
* **Any TXG** — pick a transaction group explicitly, by timestamp, or "last one that still had this dataset".
* **Full on-disk feature coverage** — stripe/mirror/RAIDZ1-3/dRAID reconstruction; `lz4`, `zstd`, `gzip`, `lzjb`, `zle`; `fletcher`, `sha256/512`, `skein`, `edonr`, `blake3`; embedded and gang blocks; encrypted datasets with a supplied key.
* **Sparse-aware extraction** of zvols to raw images, with per-block checksum verification, resume, and `--strict` mode.
* **Machine-readable output** — `-f json` everywhere, append-only evidence log, SHA-256 of every input and output.
* **`--debug`** — a trace of every read decision with hex dumps of what went wrong, for [verifying against a real pool](docs/DEBUGGING.md).

## Planned CLI

```
zvolrescue scan  DEV...                                    what is here: labels, pool, TXG window, topology
zvolrescue list  POOLSPEC [--txg N|--before TS] [--diff TXG2] [-r]
                                                           datasets / zvols / snapshots at a TXG
zvolrescue dump  DATASET POOLSPEC -o OUT.img [--txg N] [--strict] [--key KEYSPEC] [--resume] [-r]
                                                           extract, verify every block, print SHA-256; -r: every volume under DATASET into a directory
```

```sh
# Which TXGs are still available on these disks?
zvolrescue scan -v /dev/ada0p3 /dev/ada1p3

# When did pool/vm/disk0 disappear, and which TXG still had it?
zvolrescue list /dev/ada0p3 /dev/ada1p3 -r | grep disk0

# Extract it from that TXG, verifying every block.
zvolrescue dump pool/vm/disk0 /dev/ada0p3 /dev/ada1p3 --txg 4816230 \
    --strict -o /mnt/rescue/disk0.img --evidence-log case42.jsonl
```

### Companion tools (later, separate binaries in the same workspace)

Specified in [docs/COMPANIONS.md](docs/COMPANIONS.md).

| Tool | Job |
|---|---|
| `zvoltimeline` | TXG ↔ time ↔ dataset created/destroyed, pending deletions |
| `zvolcarve` | find unlinked zvols whose uberblocks are gone, hand them to `dump` |
| `zvolreport` | consolidated forensic report with a SHA-256 chain of custody |
| `zvolfiles` | file-level recovery from filesystem datasets |

## Roadmap

| Phase | Scope |
|---|---|
| 0 — Bootstrap | Repo skeleton, spec, CI (FreeBSD + Linux), fixture-pool generator, `scan` |
| 1 — MVP | `list`, `dump` on single/mirror pools; common compression & checksums; JSON output |
| 2 — Redundancy & integrity | RAIDZ/dRAID reconstruction, all checksums, `--strict`, `--resume`, bulk extraction |
| 3 — Forensics | Encrypted datasets; companion tools `zvoltimeline`, `zvolcarve`, `zvolreport` |
| 4 — Filesystems | Companion tool `zvolfiles`: object dumps, then ZPL file-level recovery |

Details, requirements and acceptance criteria: [docs/SPEC.md](docs/SPEC.md).

## Repository layout

```
README.md, README_UK.md     this file (EN / UK)
docs/SPEC.md                technical specification (ТЗ), English — the source of truth
docs/SPEC.uk.md             the same in Ukrainian
docs/COMPANIONS.md          companion tools specification (EN); COMPANIONS.uk.md in Ukrainian
docs/DEBUGGING.md           how to verify against a test pool in a VM with zdb and --debug
docs/research/              analyses of related tools, on-disk format notes
Cargo.toml                  cargo workspace
crates/zvolrescue/          the main binary (scan / list / dump)
crates/zvol*/               companion binaries, one crate each (phases 3–4)
crates/zvol-common/         shared CLI plumbing (evidence log, exit codes, POOLSPEC)
crates/zvolrescue-io/       read-only device/image access (the only crate allowed `unsafe`)
crates/zfs-ondisk/          pure on-disk structure parsers (labels, nvlist, uberblocks, blkptr, dnode, ZAP)
crates/zfs-read/            pool walking: vdev reconstruction, zio, dmu, dsl, zvol extraction, carving
crates/edonr/               Edon-R checksum port from OpenZFS (CDDL), isolated
fuzz/                       cargo-fuzz targets
tests/                      fixture-pool integration tests
```

## Building

```sh
cargo build --release          # binary in target/release/zvolrescue
cargo test
cargo clippy --all-targets -- -D warnings
```

Rust stable (`lang/rust` from FreeBSD ports, or `rustup`). No C toolchain
and no system libraries are required: the whole decode stack is pure Rust.

## Platforms

FreeBSD 13.x–15.x are first-class targets. Linux is a supported build and
test platform. macOS is best-effort.

## Contributing

The project is at the specification stage. The most useful contributions
right now are reviews of [docs/SPEC.md](docs/SPEC.md) — especially the
open questions in §12 — and real-world recovery scenarios that the
fixture-pool test suite should cover.


## License

BSD 3-Clause. See [LICENSE](LICENSE).
The Edon-R port in `crates/edonr/` keeps its original CDDL license.

## Author

Vladyslav V. Prodan — [support.od.ua](https://support.od.ua/)
