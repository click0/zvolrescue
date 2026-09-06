# zvolrescue

**Open-Source ZFS Forensic & Recovery Utility**

`zvolrescue` reads ZFS pools directly from disks or disk images — without
importing them into the kernel and without ever writing to them — and
recovers datasets, with a first-class focus on **zvols** (bhyve/VM disks,
iSCSI targets, container volumes), at any transaction group (TXG) that is
still present on disk. It also produces forensic reports: label and
uberblock history, dataset creation/destruction timeline, and
hash-verified extraction logs.

**Language:** Rust | **License:** BSD 3-Clause | **Status:** Design stage (pre-alpha) — see the [specification](docs/SPEC.md)

[Українська версія](README_UK.md) | [Technical specification (ТЗ)](docs/SPEC.md) | [ТЗ українською](docs/SPEC.uk.md)

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

## Planned features

* **Read-only by construction** — evidence is opened `O_RDONLY`; output can never land on an input device.
* **No kernel ZFS needed** — pure userland; runs where `zfs.ko` is not loaded or the pool cannot be imported.
* **Any pool state** — healthy, degraded, destroyed, damaged labels, missing vdevs (as long as redundancy allows).
* **Any TXG** — pick a transaction group explicitly, by timestamp, or "last one that still had this dataset".
* **Full on-disk feature coverage** — stripe/mirror/RAIDZ1-3/dRAID reconstruction; `lz4`, `zstd`, `gzip`, `lzjb`, `zle`; `fletcher`, `sha256/512`, `skein`, `edonr`, `blake3`; embedded and gang blocks; encrypted datasets with a supplied key.
* **Sparse-aware extraction** of zvols to raw images, with per-block checksum verification, resume, and `--strict` mode.
* **Carving** of unlinked zvols whose uberblocks are already gone.
* **Forensic output** — `-f json` everywhere, TXG timeline, append-only evidence log, consolidated report with SHA-256 chain of custody.

## Planned CLI

```
zvolrescue scan       DEV...                         detect ZFS labels
zvolrescue labels     DEV [--all]                    dump label nvlists
zvolrescue uberblocks DEV|POOL [--all]               uberblock ring
zvolrescue pool       POOLSPEC                       assembled pool summary
zvolrescue list       POOLSPEC [--txg N|--before TS] [--diff TXG2] [-r]
zvolrescue timeline   POOLSPEC                       TXG ↔ time ↔ dataset events
zvolrescue dump       POOLSPEC DATASET -o OUT.img [--txg N] [--strict] [--key KEYSPEC]
zvolrescue carve      POOLSPEC [--type zvol] [-o DIR]
zvolrescue verify     POOLSPEC DATASET [--txg N]
zvolrescue report     POOLSPEC -o report.json
```

```sh
# Which TXGs are still available on these disks?
zvolrescue uberblocks /dev/ada0p3

# When did pool/vm/disk0 disappear?
zvolrescue timeline /dev/ada0p3 /dev/ada1p3 | grep disk0

# Extract it from the last TXG that still had it, verifying every block.
zvolrescue dump /dev/ada0p3 /dev/ada1p3 pool/vm/disk0 --txg 4816230 \
    --strict -o /mnt/rescue/disk0.img --evidence-log case42.jsonl
```

## Roadmap

| Phase | Scope |
|---|---|
| 0 — Bootstrap | Repo skeleton, spec, CI (FreeBSD + Linux), fixture-pool generator, `scan`/`labels`/`uberblocks` |
| 1 — MVP | `list`, `timeline`, `dump` on single/mirror pools; common compression & checksums; JSON output |
| 2 — Redundancy & integrity | RAIDZ/dRAID reconstruction, all checksums, `verify`, `--strict`, resume, bulk extraction |
| 3 — Forensics | Encrypted datasets, carving of unlinked zvols, `report`, hash chain |
| 4 — Filesystems | Object dumps, then ZPL file-level recovery |

Details, requirements and acceptance criteria: [docs/SPEC.md](docs/SPEC.md).

## Repository layout

```
README.md, README_UK.md     this file (EN / UK)
docs/SPEC.md                technical specification (ТЗ), English — the source of truth
docs/SPEC.uk.md             the same in Ukrainian
docs/research/              analyses of related tools, on-disk format notes
Cargo.toml                  cargo workspace
crates/zvolrescue/          the CLI binary
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

## Related

* [crate](https://github.com/click0/crate) — FreeBSD containerizer by the same author; `zvolrescue` follows its CI conventions and bilingual documentation style.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
The Edon-R port in `crates/edonr/` keeps its original CDDL license.

## Author

Vladyslav V. Prodan — [support.od.ua](https://support.od.ua/)
