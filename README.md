# zvolrescue

**Open-Source ZFS Forensic & Recovery Utility**

`zvolrescue` reads ZFS pools directly from disks or disk images — without
importing them into the kernel and without ever writing to them — and
recovers datasets, with a first-class focus on **zvols** (bhyve/VM disks,
iSCSI targets, container volumes), at any transaction group (TXG) that is
still present on disk. It also produces forensic reports: label and
uberblock history, dataset creation/destruction timeline, and
hash-verified extraction logs.

**Language:** Rust | **License:** BSD 3-Clause | **Status:** v0.2.0 (see [CHANGELOG.md](CHANGELOG.md)) — `scan`, `list` and `dump` work on stripe, mirror, RAIDZ1/2/3 and dRAID pools (parity reconstruction of missing and silently corrupted columns, distributed spares), gang blocks, fletcher/sha256/sha512/blake3/skein/edonr checksums (every OpenZFS algorithm), lz4/zstd/gzip/lzjb/zle, with `--resume` and bulk `-r`; encrypted datasets: `list` reports the suite and key format, `dump --key` (raw/hex/passphrase/prompt) decrypts (phase 3; ZIL excluded). Pools whose labels are gone are read too: the zero point from a surviving uberblock, a member bound to the leaf its siblings name, a layout given by hand, and the confirmed layout written back out as a label. Cross-checked against OpenZFS userland (`ztest`/`zdb`) in CI; not yet run on a real kernel-imported pool. See the [specification](docs/SPEC.md).

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

* **Whole disks or partitions** — given an image of a whole disk, the GPT or MBR says where the ZFS partition began and how long it was; nothing is taken from it until a label checksum verifies there.
* **Read-only by construction** — evidence is opened `O_RDONLY`; output can never land on an input device.
* **No kernel ZFS needed** — pure userland; runs where `zfs.ko` is not loaded or the pool cannot be imported.
* **Any pool state** — healthy, degraded, destroyed, damaged labels, missing vdevs (as long as redundancy allows).
* **Any TXG** — pick a transaction group explicitly, by timestamp, or "last one that still had this dataset".
* **Labels gone** — when every `vdev_phys` has been overwritten, one surviving uberblock still fixes the vdev's zero point: its checksum verifier is its own offset, so `scan` recovers the base (and the old vdev size) even after the partition was re-created somewhere else.
* **A member with no labels at all** — the siblings' configuration still names the leaf it must be, and `--assume-member PATH` works out which one by reading the pool through it; every block is verified by its checksum, so a device that is not this pool's is refused rather than believed.
* **No labels anywhere** — `--hints FILE` describes the layout the way a `vdev_phys` template would (ashift, vdev type, members in order) and the tool reads through it; the TXG history and root pointers come from the uberblocks, which verify against their own offsets. `--search-order` works out the member order the checksums accept, and `scan --emit-label` writes the confirmed layout back out as a label to place on a *copy* of the disk.
* **Full on-disk feature coverage** — stripe/mirror/RAIDZ1-3/dRAID reconstruction; `lz4`, `zstd`, `gzip`, `lzjb`, `zle`; `fletcher`, `sha256/512`, `skein`, `edonr`, `blake3`; embedded and gang blocks; encrypted datasets with a supplied key.
* **Sparse-aware extraction** of zvols to raw images, with per-block checksum verification, resume, and `--strict` mode.
* **Machine-readable output** — `-f json` everywhere, append-only evidence log, SHA-256 of every input and output.
* **`--debug`** — a trace of every read decision with hex dumps of what went wrong, for [verifying against a real pool](docs/DEBUGGING.md).

## Planned CLI

```
zvolrescue scan  DEV... [--zero-point] [--psize BYTES]      what is here: labels, pool, TXG window, topology
zvolrescue list  POOLSPEC [--txg N|--before TS] [--diff TXG2] [-r]
                                                           datasets / zvols / snapshots at a TXG
zvolrescue dump  DATASET POOLSPEC -o OUT.img [--txg N] [--strict] [--key KEYSPEC] [--resume] [-r]
                                                           extract, verify every block, print SHA-256; -r: every volume under DATASET into a directory
```

```sh
# Which TXGs are still available on these disks?
zvolrescue scan -v /dev/ada0p3 /dev/ada1p3

# All four labels overwritten: where does this vdev actually start?
zvolrescue scan --zero-point /dev/ada0p3

# When did pool/vm/disk0 disappear, and which TXG still had it?
zvolrescue list /dev/ada0p3 /dev/ada1p3 -r | grep disk0

# Extract it from that TXG, verifying every block.
zvolrescue dump pool/vm/disk0 /dev/ada0p3 /dev/ada1p3 --txg 4816230 \
    --strict -o /mnt/rescue/disk0.img --evidence-log case42.jsonl
```

```
zvoltimeline POOLSPEC [--from TXG] [--to TXG] [--dataset NAME|GUID]
                                                           the pool's history: what existed at each TXG, and what the destroyed ones need
```

```sh
# What happened to this pool, and which TXG still had the volume?
zvoltimeline /dev/ada0p3 /dev/ada1p3 --dataset pool/vm/disk0
```

Each `destroyed` line carries the last transaction group that still
referenced the object and the exact `zvolrescue dump` command that gets
it back — with this run's own `--hints`, `--image` and `--assume-member`
carried over, so it works where the timeline worked.

```
zvolcarve scan    POOLSPEC -o DIR [--volblocksize BYTES] [--levels N] [--txg FROM..TO]
                                  [--size MIN..MAX] [--like DATASET] [--strict-profile] [--resume]
zvolcarve list    DIR
zvolcarve dump    DIR CANDIDATE POOLSPEC -o OUT.img [--size BYTES] [--strict]
                                                           volumes no uberblock points at any more
```

```sh
# The volume is gone from every transaction group the ring still has.
# Its blocks are not. Scan raw space for them, describing what was lost.
zvolcarve scan /dev/ada0p3 /dev/ada1p3 -o /case42/carve --like pool/vm/disk1
zvolcarve list /case42/carve
zvolcarve dump /case42/carve c0001 /dev/ada0p3 /dev/ada1p3 -o disk0.img --size 34359738368
```

The profile is a filter, never an assumption: a candidate that matched
everything asked for ranks above 0.5 and one that did not ranks below
it, and an empty list says which field emptied it. Nothing is trusted
for having matched — every block `dump` reads is verified by its own
checksum, exactly as in the main binary.

```
zvolfiles list    DATASET POOLSPEC [--txg N] [--key KEYSPEC] [--path PATH] [-R]
zvolfiles extract DATASET POOLSPEC [--txg N] [--key KEYSPEC] [--path PATH]... -o DIR [--strict]
zvolfiles objects DATASET POOLSPEC [--txg N] [--key KEYSPEC] -o DIR
                                                           files out of a filesystem dataset
```

```sh
# What is in there, and what came out of it.
zvolfiles list pool/home /dev/ada0p3 /dev/ada1p3 -R --txg 4816229
zvolfiles extract pool/home /dev/ada0p3 /dev/ada1p3 -o /mnt/rescue/home

# The POSIX metadata is too damaged to walk: take the objects instead.
zvolfiles objects pool/home /dev/ada0p3 -o /mnt/rescue/objects
```

```
zvolreport build  LOG... -o report.json [--md report.md] [--case ID] [--examiner NAME]
zvolreport verify report.json [--evidence-root DIR] [--outputs-root DIR]
                                                           the evidence logs as one document, and that document checked back
```

```sh
# Every tool appends to one log; the report consolidates them.
zvolrescue --hash-inputs --evidence-log case42.jsonl scan /dev/ada0p3 /dev/ada1p3
zvolrescue --evidence-log case42.jsonl dump pool/vm/disk0 /dev/ada0p3 /dev/ada1p3 -o disk0.img
zvolreport build case42.jsonl -o report.json --md report.md --case 42 --examiner "…"

# Later, on another machine: is everything still what the report says?
zvolreport verify report.json --outputs-root /mnt/case42
```

### Companion tools (separate binaries in the same workspace)

Specified in [docs/COMPANIONS.md](docs/COMPANIONS.md).

| Tool | Job |
|---|---|
| `zvoltimeline` | **shipping** — TXG ↔ time ↔ dataset created/destroyed |
| `zvolcarve` | **shipping** — find volumes whose uberblocks are gone, and extract them |
| `zvolreport` | **shipping** — consolidated report with a SHA-256 chain of custody |
| `zvolfiles` | **shipping** — file-level recovery from filesystem datasets |

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
crates/zvoltimeline/        the pool's history from its transaction groups
crates/zvolreport/          the evidence logs consolidated into one checkable document
crates/zvolcarve/           raw-space scan for volumes nothing points at any more
crates/zvolfiles/           the ZFS POSIX layer: directories, files, symlinks, or a raw object dump
crates/zvol*/               the remaining companion binaries, one crate each (phases 3–4)
crates/zvol-common/         shared CLI plumbing (evidence log, exit codes, POOLSPEC)
crates/zvolrescue-io/       read-only device/image access (the only crate allowed `unsafe`)
crates/zfs-ondisk/          pure on-disk structure parsers (labels, nvlist, uberblocks, blkptr, dnode, ZAP)
crates/zfs-read/            pool walking: vdev reconstruction, zio, dmu, dsl, zvol extraction, carving
crates/edonr/               Edon-R checksum port from OpenZFS (CDDL), isolated
fuzz/                       cargo-fuzz targets
tests/                      fixture-pool integration tests
```

## Installing

Every tagged release ships static binaries with no runtime dependencies
(see [Releases](https://github.com/click0/zvolrescue/releases)):
`zvolrescue-<version>-x86_64-linux-musl`, `…-aarch64-linux-musl`,
`…-amd64-freebsd`, the same three for `zvoltimeline`, `zvolreport`,
`zvolcarve` and `zvolfiles`, plus `SHA256SUMS`. Drop the binary on the rescue
medium and run it; nothing to install. Verify with `sha256sum -c SHA256SUMS`.
The pre-releases (`-alpha`, `-beta`) have been validated against OpenZFS
userland pools only; see [CHANGELOG.md](CHANGELOG.md) for what each one
covers.

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
