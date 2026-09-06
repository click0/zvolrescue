# zvolrescue — Technical Specification (ТЗ)

**Status:** Draft v0.1 · **Date:** 2026-09-06 · **Owner:** Vladyslav V. Prodan
**Ukrainian version:** [SPEC.uk.md](SPEC.uk.md) · **Companion tools:** [COMPANIONS.md](COMPANIONS.md)

This document is the founding requirements specification for `zvolrescue`,
an open-source ZFS forensic and recovery utility. It defines the problem,
the scope, functional and non-functional requirements, the CLI surface,
the architecture, the delivery phases and the acceptance criteria.
Everything here is a proposal until the first tagged release; edit freely.

---

## 1. Purpose

ZFS has no `undelete`. Once a dataset or zvol is destroyed, or a pool refuses
to import after a hardware fault, the only options today are:

| Option | Problem |
|---|---|
| `zpool import -F` / `-T <txg>` | Requires a *whole-pool* rollback, touches the pool, works only while the old uberblocks still exist (a few TXGs / minutes). |
| `zdb` | Debugging tool, not a recovery tool: no data extraction workflow, panics on damaged metadata, writes nothing usable. |
| `zfs_revert`-style scripts | Overwrite uberblocks **in place** on the live devices — destructive, single-disk only, no checksums. |
| Commercial tools (Klennet ZFS Recovery, UFS Explorer, ReclaiMe) | Closed source, Windows-only, expensive, cannot be audited for a forensic chain of custody. |

`zvolrescue` fills the gap: a **read-only, userland, auditable** tool that
reads ZFS on-disk structures directly, reconstructs datasets — with a
first-class focus on **zvols** (bhyve/VM disks, iSCSI targets, container
volumes) — at any TXG still present on disk, and extracts them to
plain images with verifiable checksums.

## 2. Terms

| Term | Meaning |
|---|---|
| **zvol** | ZFS volume: a dataset exposed as a block device (`/dev/zvol/<pool>/<name>`). |
| **TXG** | Transaction group; every on-disk change is tagged with the TXG in which it was born. |
| **Uberblock** | Root pointer of the pool for a given TXG; 128 kept per label in a ring. |
| **Label** | 256 KiB structure, 4 copies per vdev (2 front, 2 back), holds the nvlist config and the uberblock ring. |
| **MOS** | Meta Object Set: the pool-wide object set that describes all datasets. |
| **Block pointer (blkptr)** | 128-byte structure addressing up to 3 DVA copies of a block plus checksum/compression metadata. |
| **Carving** | Recovering data by scanning raw space for recognisable structures rather than following live pointers. |
| **Evidence** | Any input device or image; must never be modified by the tool. |

## 3. Scope

### 3.0 Design principle: one atomic utility

`zvolrescue` is a single-purpose tool, not a platform. The principle is
binding for every later decision in this document:

* **One job.** Take ZFS on-disk structures from a set of devices or images
  and produce a plain image of one dataset (a zvol first of all). Discovery
  (`scan`) and selection (`list`) exist only because that job needs them.
* **One static binary.** No configuration files, no daemon, no plugins, no
  environment lookups, no network, no shelling out. Everything the run needs
  is on the command line and on the evidence.
* **Pure runs.** The same arguments over the same evidence produce
  byte-identical output and identical JSON. Nothing is cached between runs.
* **Composable, not comprehensive.** Text for humans, JSON for machines,
  images to files. Anything that is not required to get a dataset out —
  forensic timelines, carving of unlinked data, consolidated reports,
  file-level recovery — is a *companion tool* (§7.1) that reuses the same
  libraries, never a new mode of the main binary.

### 3.1 In scope

* Reading ZFS pools **without importing them** into the kernel.
* Pools in any state: healthy, degraded, faulted, destroyed (`zpool destroy`), with damaged labels/uberblocks, or with missing vdevs where redundancy still allows reconstruction.
* Recovering **zvols** (primary) and **filesystem datasets** (secondary, as raw object dumps first, file-level later).
* Operating on physical devices, partitions, and raw image files (`dd`, `.img`, sparse), including images of *individual* vdev members assembled into a virtual pool.
* Forensic inspection: TXG timeline, label/uberblock history, dataset creation/destruction history, block-level checksum verification.

### 3.2 Out of scope (v1)

* Writing to or repairing the pool in place. `zvolrescue` **never writes to evidence.**
* Mounting recovered filesystems (use `mdconfig(8)`/`losetup(8)` on the extracted image).
* Recovery of pools whose encryption keys are unavailable (encrypted data is extracted as ciphertext with metadata only).
* A GUI. A TUI is a possible later addition (see §10).
* Generating `zfs send` streams (possible later phase).

## 4. Users and use cases

| ID | Actor | Scenario |
|---|---|---|
| UC-1 | Sysadmin | Ran `zfs destroy pool/vm/disk0` on the wrong host. Needs the zvol back as an image within hours, before free blocks are reused. |
| UC-2 | Sysadmin | Pool does not import after a controller failure (`zpool import` → "I/O error" / "corrupted data"). Needs to salvage the VM disks from the surviving vdevs. |
| UC-3 | Forensic analyst | Received a set of disk images from a ZFS server. Must list all datasets that ever existed in the retained TXG window, when they were created/destroyed, and extract specific zvols with a hash-verified chain of custody. |
| UC-4 | Sysadmin | A VM guest filesystem inside a zvol got corrupted at time T. Needs the zvol *as it was* at an earlier TXG, even though no snapshot exists. |
| UC-5 | Operator of bhyve / container hosts | Bulk-export all zvols under a dataset tree from an offline pool to another storage for migration or audit. |
| UC-6 | Developer / QA | Verify that a test pool's on-disk structures are consistent (every blkptr checksum matches) after a fault-injection run. |

## 5. Functional requirements

Priority: **M** = must (v1), **S** = should (v1 if time permits), **C** = could (later).
◇ = belongs to a companion tool (§7.1), never to the main binary.

### 5.1 Device and pool discovery

| ID | Pri | Requirement |
|---|---|---|
| F-01 | M | Scan a list of devices/partitions/image files and detect ZFS vdev labels at any of the 4 label positions. |
| F-02 | M | Parse the label nvlist: pool name, pool GUID, vdev GUID, vdev tree, `txg`, `state`, `hostid`, `hostname`, feature flags. |
| F-03 | M | Reassemble a pool from an arbitrary set of vdev members by GUID; report missing members and whether the topology is still readable. |
| F-04 | M | Decode the uberblock ring of every label: TXG, timestamp, checksum validity, root blkptr, MMP fields. |
| F-05 | S | Detect partially overwritten labels and fall back to the best surviving copy, per vdev. |
| F-06 | S | Support GPT/MBR partition tables inside whole-disk images (locate ZFS partitions automatically). |

### 5.2 Reading pool metadata at a chosen TXG

| ID | Pri | Requirement |
|---|---|---|
| F-10 | M | Select a TXG explicitly (`--txg N`), by timestamp (`--before "2026-09-01 12:00"`), or "latest valid" (default). |
| F-11 | M | Walk the MOS from the chosen uberblock: object directory, DSL directories, DSL datasets, snapshots, bookmarks, clones. |
| F-12 | M | List datasets with type (filesystem / zvol / snapshot), GUID, creation TXG and time, referenced size, `volsize`/`volblocksize` for zvols, compression, checksum, encryption, dedup properties. |
| F-13 | M | Diff dataset lists between two TXGs to show what was created or destroyed in between. |
| F-14 | S | Read dataset properties (ZAP) including user properties. |
| F-15 | S ◇ | List pending deletions (`dp_free_bpobj`, deadlists) so the user can judge whether destroyed data is still on disk. |

### 5.3 Data extraction

| ID | Pri | Requirement |
|---|---|---|
| F-20 | M | Extract a zvol object at a chosen TXG to a raw image file, preserving holes as sparse regions. |
| F-21 | M | Support all standard checksums: `fletcher2`, `fletcher4`, `sha256`, `sha512`, `skein`, `edonr`, `blake3`; verify every block and record mismatches. |
| F-22 | M | Support all standard compression algorithms: `lzjb`, `lz4`, `gzip-1..9`, `zle`, `zstd` (all levels), `off`. |
| F-23 | M | Read from stripe and mirror vdevs, trying all DVA copies on checksum failure. |
| F-24 | M | Read from RAIDZ1/2/3 with parity reconstruction of a missing or corrupted column. |
| F-25 | S | Read from dRAID with reconstruction. |
| F-26 | S | Embedded block pointers (`embedded_data`), gang blocks, `large_blocks`, `large_dnode`. |
| F-27 | S | Encrypted datasets: decrypt with a user-supplied raw/hex/passphrase key (`aes-128/192/256-ccm/gcm`); without a key, extract ciphertext and metadata only. |
| F-28 | S | Dedup: resolve DDT-referenced blocks transparently (they are just blkptrs) — no special handling required beyond checksum handling. |
| F-29 | S ◇ | Extract a filesystem dataset as a raw dump of all objects (per-object files + metadata JSON) as a stepping stone before file-level recovery. |
| F-30 | C ◇ | File-level extraction from filesystem datasets (ZPL: directories, files, symlinks, xattrs). |
| F-31 | S | Bulk extraction: `--recursive pool/vm` dumps every zvol under a tree with a manifest. |
| F-32 | S | Resume interrupted extractions (block-level progress file). |
| F-33 | M | Partial-result policy: on unreadable blocks write zeros (default) or abort (`--strict`), always logging the LBA range and reason. |

### 5.4 Carving (destroyed and unlinked data)

| ID | Pri | Requirement |
|---|---|---|
| F-40 | M | Locate a destroyed dataset by walking **older** uberblocks/TXGs that still reference it (fast path, exact). |
| F-41 | S ◇ | Scan raw vdev space for dnode blocks and indirect blocks that reference zvol data (`DMU_OT_ZVOL`), reconstruct candidate zvols when no uberblock still points to them. |
| F-42 | S ◇ | Score carved candidates by checksum agreement, contiguity and birth-TXG consistency; present them for the user to choose. |
| F-43 | C ◇ | Signature-based carving of guest filesystems inside zvol data (UFS/ext4/NTFS superblocks) to bound an extraction when metadata is gone. |

### 5.5 Forensic reporting

| ID | Pri | Requirement |
|---|---|---|
| F-50 | M | Every command supports `-f text` (default) and `-f json` output. |
| F-51 | M ◇ | `zvolreport` produces a single document: evidence list with SHA-256 of every input, labels, uberblock ring, dataset history, extraction log with output hashes, tool version and command line. |
| F-52 | M ◇ | TXG timeline: TXG → uberblock timestamp → datasets born/destroyed → hostname/hostid seen. |
| F-53 | S | Hash outputs on the fly (SHA-256, optionally MD5/SHA-1 for compatibility with existing forensic toolchains). |
| F-54 | S | Machine-readable evidence log (`--evidence-log FILE`) in JSON Lines, append-only. |

## 6. Non-functional requirements

| ID | Requirement |
|---|---|
| N-01 | **Read-only by construction.** Evidence is opened `O_RDONLY`; there is no code path that opens an input for writing. Output paths are refused if they resolve onto an input device. |
| N-02 | **No kernel ZFS dependency.** Runs on a host with no ZFS module loaded and never calls `zpool`/`zfs`. |
| N-03 | **Scales to multi-TB pools.** Streaming extraction with bounded memory (target: ≤ 512 MiB RSS regardless of pool size, excluding optional caches). |
| N-04 | **Fail soft.** Corrupted metadata produces warnings and partial results, never a crash; every abort has a clear reason and an exit code. |
| N-05 | **Reproducible.** Same inputs + same arguments → byte-identical outputs and reports (timestamps only in designated fields). |
| N-06 | **Portable.** FreeBSD 13.x–15.x are first-class; Linux (glibc/musl) builds and passes the test suite; macOS is best-effort. |
| N-07 | **Auditable.** Small dependency footprint, no network access, deterministic builds, signed release tarballs. |
| N-08 | **Performance target.** Sequential zvol extraction ≥ 70 % of raw device read throughput on a mirror; ≥ 40 % on RAIDZ2 (single thread), with an optional worker pool for parallel checksum/decompression. |
| N-09 | **Localisation.** UI strings are English; documentation is maintained in English and Ukrainian. |

## 7. CLI surface (proposal)

The main binary has exactly three commands. Label and uberblock detail,
pool assembly and topology are verbosity levels of `scan`, not commands.

```
zvolrescue [global options] <command> [options] [args]

Global:
  -f, --format text|json      output format (default: text)
  -v, --verbose               repeatable: -v adds uberblock rings, -vv adds label nvlists
  -q, --quiet
      --evidence-log FILE     append JSON Lines evidence log
      --no-color

Commands:
  scan  DEV...                          what is on these devices/images: labels, pool
                                        name/GUID, vdev GUIDs, TXG window, assembled
                                        topology, missing members
  list  POOLSPEC [--txg N|--before TS] [--diff TXG2] [-r]
                                        datasets/zvols/snapshots at a TXG; for each
                                        destroyed one, the last TXG that still had it
  dump  POOLSPEC DATASET -o OUT.img [--txg N] [--strict] [--key KEYSPEC] [--resume]
                                        extract a zvol (or object dump of a fs) to a raw
                                        sparse image, verifying every block; prints the
                                        SHA-256 of the output

POOLSPEC:  one or more vdev members, e.g.
           /dev/ada0p3 /dev/ada1p3
           --image disk0.img --image disk1.img
           --pool-guid 0x1234…  (pick among several pools found)
KEYSPEC:   raw:FILE | hex:HEX | passphrase:FILE | prompt
```

Exit codes: `0` success, `1` usage error, `2` evidence unreadable, `3` pool
unrecoverable at requested TXG, `4` extraction completed with errors
(`--strict` only), `5` refused (would write to evidence).

Example (UC-1):

```sh
# 1. What is on these disks, and which TXGs are still available?
zvolrescue scan -v /dev/ada0p3 /dev/ada1p3

# 2. When did pool/vm/disk0 disappear, and which TXG still had it?
zvolrescue list /dev/ada0p3 /dev/ada1p3 -r | grep disk0

# 3. Extract it from that TXG, verifying checksums.
zvolrescue dump /dev/ada0p3 /dev/ada1p3 pool/vm/disk0 --txg 4816230 \
    --strict -o /mnt/rescue/disk0.img --evidence-log case42.jsonl
```

### 7.1 Companion tools

Everything marked ◇ in §5 ships as a separate binary that links the same
workspace libraries. Names are provisional; each one is as atomic as the
main tool:

| Tool | Job | Requirements |
|---|---|---|
| `zvoltimeline` | TXG ↔ time ↔ dataset created/destroyed ↔ hostname/hostid; pending-deletion analysis | F-15, F-52 |
| `zvolcarve` | scan raw vdev space for unlinked zvols, score candidates, hand them to `dump` | F-41…F-43 |
| `zvolreport` | consolidated forensic report over the evidence logs of the other tools | F-51 |
| `zvolfiles` | object dump and ZPL file-level recovery from filesystem datasets | F-29, F-30 |

The main binary never gains these as modes. Shared behaviour (evidence
log, JSON output, exit codes, read-only invariants) lives in the
`zvol-common` library so the companions inherit it for free. Each tool is
specified in [COMPANIONS.md](COMPANIONS.md); all of them live in this
repository and workspace (decision D-3, §13).

## 8. Architecture

### 8.1 Language and dependencies

* **Rust** (stable, edition 2021; MSRV = the stable release current at the start of phase 0, bumped deliberately). Rationale: the input is hostile by definition — corrupted metadata must never crash the tool or read out of bounds (N-04), and bounds-checked slice parsing with `Result`-based error propagation gives that by default. `cargo fuzz` covers the §9 fuzzing requirement with one target per parser. A single static binary (`-C target-feature=+crt-static`, or a musl target on Linux) is trivial to drop onto a rescue medium. `rayon` gives data-race-free parallel checksum/decompression (N-08).
* **Pure-Rust decode stack**, so building needs no C toolchain or system libraries: `lz4_flex` (lz4), `ruzstd` (zstd, decode-only), `flate2` with the `miniz_oxide` backend (gzip); `lzjb` and `zle` are reimplemented (trivial).
* Checksums: `fletcher2/4` reimplemented; `sha2`, `blake3`, `skein` from the RustCrypto family; `edonr` has no Rust implementation and is ported from OpenZFS (~300 lines, CDDL) into its own isolated crate.
* Encryption: `aes-gcm`, `ccm`, `pbkdf2` (RustCrypto); OpenZFS key-wrapping and IV/MAC layout reimplemented.
* On-disk structures: `zerocopy` views over `#[repr(C)]` definitions of `blkptr_t`, `dnode_phys_t`, `uberblock_t` etc. — no copying and no `unsafe` in project code; the nvlist (XDR) parser is hand-written.
* CLI: `clap` (derive); JSON: `serde` / `serde_json`; diagnostics: `tracing`.
* Toolchain: `lang/rust` from ports on FreeBSD, `rustup` elsewhere. `#![forbid(unsafe_code)]` in every crate except `zvolrescue-io`, where the few `libc` calls needed for device access are individually reviewed and commented.
* Cross-checking against OpenZFS userland (`zdb`) is done by the integration-test harness running the `zdb` binary and diffing output. There is no FFI to `libzpool`.

### 8.2 Layers (cargo workspace)

```
Cargo.toml              workspace
crates/
  zvolrescue/           the main binary: scan / list / dump
  zvoltimeline/         companion binaries (COMPANIONS.md), one crate each,
  zvolcarve/            added in phases 3–4
  zvolreport/
  zvolfiles/
  zvol-common/          shared CLI plumbing: POOLSPEC parsing, -f/-v/-q, evidence-log
                        records, exit codes, output-path-vs-evidence check
  zvolrescue-io/        read-only device & image access (`BlockSource` trait), partition
                        tables, sparse output writer — the only crate allowed `unsafe`
  zfs-ondisk/           pure parsers: labels, nvlist, uberblocks, blkptr, dnode, ZAP —
                        no I/O, fuzzable in isolation
  zfs-read/             everything that walks a pool through a `BlockSource`:
                          vdev/   vdev tree, mirror/RAIDZ/dRAID reconstruction
                          zio/    DVA resolution, checksums, decompression, decryption
                          dmu/    object sets, dnodes, indirect block walking
                          dsl/    MOS, DSL dirs/datasets, snapshots, TXG selection, diff
                          zvol/   zvol extraction, hole detection, resume
                          zpl/    (later) ZPL file-level recovery
                          carve/  raw scanning and candidate scoring
  edonr/                Edon-R port from OpenZFS (CDDL), isolated with its own LICENSE
fuzz/                   cargo-fuzz targets for every parser in zfs-ondisk
tests/                  fixture-pool integration tests (shell + Rust), one subdirectory per binary
docs/                   SPEC.md, SPEC.uk.md, COMPANIONS.md, COMPANIONS.uk.md, research/
```

Phase 0 creates `zvolrescue`, `zvolrescue-io`, `zfs-ondisk` and an empty
`zfs-read`; `zvol-common` is split out of the main binary when the first
companion tool arrives; modules split into further crates only when
compile times or ownership make it worthwhile.

Every crate above `zvolrescue-io` is pure: it takes a `BlockSource` trait
object and never touches the OS, which makes the reader trivially testable
on in-memory fixtures and portable.

### 8.3 Safety invariants

1. The `BlockSource` trait has read methods only. Its single on-disk implementation lives in `zvolrescue-io`, opens with `O_RDONLY` (plus `O_EXCL` on platforms that honour it for block devices), and is the only place where an input path becomes a file descriptor.
2. Output paths are canonicalised and compared against every input's `st_dev/st_ino`; a match aborts with exit code 5.
3. No `std::process::Command`, no shelling out, no network: `cargo deny` bans networking crates, and a test inspects the release binary's imports for `socket`/`connect`/`execve`.
4. `#![forbid(unsafe_code)]` in every crate except `zvolrescue-io`; each `unsafe` block there carries a `// SAFETY:` comment and is covered by a test.

## 9. Testing strategy

* **Unit tests** for every on-disk structure parser using golden byte arrays taken from real pools.
* **Fixture pools**, generated in CI on a FreeBSD runner (GitHub Actions `vmactions/freebsd-vm`, or a self-hosted FreeBSD host) and on Linux with OpenZFS:
  * topologies: single, mirror-2, raidz1-3, raidz2-4, raidz3-5, draid1;
  * datasets: zvols with known pseudo-random content and every compression/checksum combination, sparse zvols, encrypted zvols, deduplicated zvols, snapshots and clones;
  * scenarios: `zfs destroy` then recover at older TXG; `zpool destroy` then recover; one member missing; one member zeroed at the labels; random 1 MiB corruption in data; random corruption in metadata.
  * assertion: SHA-256 of extracted image equals the SHA-256 recorded before destruction.
* **Cross-check**: on hosts with OpenZFS userland, compare `zvolrescue scan -v`/`list` output with `zdb -l`/`zdb -u`/`zdb -d`.
* **Fuzzing**: `cargo fuzz` targets for the nvlist, blkptr, dnode and ZAP parsers, run for a bounded time in CI on every push.
* **Static analysis**: `cargo clippy -D warnings`, `cargo fmt --check`, `cargo deny` (licences, advisories, banned crates); Miri on the `zfs-ondisk` unit tests.

## 10. Delivery phases

| Phase | Deliverable | Requirements | Acceptance |
|---|---|---|---|
| **0 — Bootstrap** | Repo skeleton, this spec, CI on FreeBSD + Linux, fixture-pool generator, `scan` (labels, uberblocks, pool assembly) | F-01…F-04, N-01, N-02 | Correct label/uberblock/topology output for all fixture topologies; matches `zdb -l/-u`. |
| **1 — MVP** | `list`, `dump` for single/mirror pools; lz4/zstd/gzip/lzjb/zle/off; fletcher/sha256; JSON output; evidence log; output hashes | F-10…F-13, F-20…F-23, F-33, F-40, F-50, F-53, F-54 | UC-1 and UC-4 pass on mirror fixtures: destroyed zvol recovered bit-exact from an older TXG. |
| **2 — Redundancy & integrity** | RAIDZ1/2/3 reconstruction, dRAID, all checksums, gang/embedded blocks, `--strict`, `--resume`, bulk `-r` | F-24…F-26, F-31, F-32, F-05, F-06 | UC-2 passes: zvols recovered from a raidz2 fixture with one member missing and another corrupted. |
| **3 — Forensics** | Encrypted datasets with key (main binary); first companion tools: `zvoltimeline`, `zvolcarve`, `zvolreport` | F-27; ◇ F-15, F-41, F-42, F-51, F-52 | UC-3 passes: full report with hash chain; carved zvol recovered after uberblocks were rolled past it. |
| **4 — Filesystems** | Companion tool `zvolfiles`: object dump of fs datasets, then ZPL file-level recovery | ◇ F-29, F-30, F-43 | Files from a destroyed filesystem dataset recovered with correct names, sizes and hashes. |
| **Later** | TUI, `zfs send` stream output, plugins for guest-fs carving, packaging in FreeBSD ports | — | — |

Version numbering: phase N ships as `0.N.x`; `1.0.0` after phase 3 has
been used on at least three real-world incidents with documented outcomes.

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| On-disk format details are under-documented; only source of truth is OpenZFS source. | Keep a `docs/research/ondisk-notes.md` with references to OpenZFS source lines per structure; cross-check with `zdb` in CI. |
| Feature flags evolve (e.g. new compression, `raidz_expansion`, `blake3`). | Feature-flag matrix in `scan`/`list` output; refuse gracefully on unknown *read-incompatible* features, warn on unknown read-compatible ones. |
| Edon-R has no Rust implementation; porting it brings CDDL code into a BSD-3 repository. | Isolate the port in `crates/edonr/` with its own LICENSE file, expose it behind a cargo feature, document it in `LICENSE.third_party`. |
| Recovery window is short (freed blocks get reused). | Documentation front-page instruction: *stop writing to the pool now, export it, image the disks*. `scan` prints the age of the oldest usable uberblock immediately. |
| Feature pressure turns the main binary into a Swiss-army knife. | §3.0 is binding: a new capability that is not needed to get a dataset out becomes a companion binary, reviewed against the ◇ list in §5. |
| Users expect in-place repair. | The tool name, README and `--help` state clearly that it never writes to the pool; point to `zpool import -F/-T` for that use case. |

## 12. Open questions

1. Should phase 1 target FreeBSD *only* to move faster, with Linux CI added in phase 2? (Proposal: Linux CI from phase 0 — fixture generation is easier there and it keeps the code portable from day one.)
2. RAIDZ expansion (`raidz_expansion` feature) reflowed layouts — support in phase 2 or defer?
3. `ruzstd` (pure Rust, decode-only) vs. `zstd` (bindings to libzstd): pure Rust keeps the static build trivial but is slower. Benchmark on phase 1 fixtures; a cargo feature can offer both.
4. Crate naming and publication: keep `zfs-ondisk` / `zfs-read` as internal workspace members, or publish them to crates.io as reusable libraries once the API settles?

## 13. Decision log

Decisions taken during the draft phase, so the open questions in §12 do
not have to be re-argued.

| ID | Date | Decision | Why |
|---|---|---|---|
| D-1 | 2026-09-06 | Implementation language is **Rust**. | Hostile input (N-04), fuzzing, static single binary, pure-Rust decode stack; see §8.1. |
| D-2 | 2026-09-06 | The main binary is **atomic**: `scan` / `list` / `dump` only (§3.0). | One job, composable; everything else is a companion tool. |
| D-3 | 2026-09-06 | Companion tools live in the **same repository and cargo workspace**, one crate per binary. | One version, one release, one CI, one port; shared `zvol-common`; specified in [COMPANIONS.md](COMPANIONS.md). |

## 14. References

* OpenZFS source: `module/zfs/`, `include/sys/{spa,vdev,zio,dmu,dsl_*,zap}*.h`
* *ZFS On-Disk Specification* (Sun, 2006) — outdated but still the only prose description of labels, uberblocks, DMU and DSL.
* `zdb(8)`, `zpool-import(8)` (`-F`, `-T`, `-X` semantics)
* Related tools to compare against in `docs/research/`: `zfs_revert`, Klennet ZFS Recovery, UFS Explorer, ReclaiMe, `zfs-fuse`.
