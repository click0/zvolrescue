# zvolrescue — Technical Specification (ТЗ)

**Status:** Draft v0.1 · **Date:** 2026-09-06 · **Owner:** Vladyslav V. Prodan
**Ukrainian version:** [SPEC.uk.md](SPEC.uk.md)

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
first-class focus on **zvols** (bhyve/VM disks, iSCSI targets, `crate`
container volumes) — at any TXG still present on disk, and extracts them to
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
| UC-5 | Operator of `crate` / bhyve hosts | Bulk-export all zvols under a dataset tree from an offline pool to another storage for migration or audit. |
| UC-6 | Developer / QA | Verify that a test pool's on-disk structures are consistent (every blkptr checksum matches) after a fault-injection run. |

## 5. Functional requirements

Priority: **M** = must (v1), **S** = should (v1 if time permits), **C** = could (later).

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
| F-15 | S | List pending deletions (`dp_free_bpobj`, deadlists) so the user can judge whether destroyed data is still on disk. |

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
| F-29 | S | Extract a filesystem dataset as a raw dump of all objects (per-object files + metadata JSON) as a stepping stone before file-level recovery. |
| F-30 | C | File-level extraction from filesystem datasets (ZPL: directories, files, symlinks, xattrs). |
| F-31 | S | Bulk extraction: `--recursive pool/vm` dumps every zvol under a tree with a manifest. |
| F-32 | S | Resume interrupted extractions (block-level progress file). |
| F-33 | M | Partial-result policy: on unreadable blocks write zeros (default) or abort (`--strict`), always logging the LBA range and reason. |

### 5.4 Carving (destroyed and unlinked data)

| ID | Pri | Requirement |
|---|---|---|
| F-40 | M | Locate a destroyed dataset by walking **older** uberblocks/TXGs that still reference it (fast path, exact). |
| F-41 | S | Scan raw vdev space for dnode blocks and indirect blocks that reference zvol data (`DMU_OT_ZVOL`), reconstruct candidate zvols when no uberblock still points to them. |
| F-42 | S | Score carved candidates by checksum agreement, contiguity and birth-TXG consistency; present them for the user to choose. |
| F-43 | C | Signature-based carving of guest filesystems inside zvol data (UFS/ext4/NTFS superblocks) to bound an extraction when metadata is gone. |

### 5.5 Forensic reporting

| ID | Pri | Requirement |
|---|---|---|
| F-50 | M | Every command supports `-f text` (default) and `-f json` output. |
| F-51 | M | `report` command produces a single document: evidence list with SHA-256 of every input, labels, uberblock ring, dataset history, extraction log with output hashes, tool version and command line. |
| F-52 | M | TXG timeline: TXG → uberblock timestamp → datasets born/destroyed → hostname/hostid seen. |
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

```
zvolrescue [global options] <command> [options] [args]

Global:
  -f, --format text|json      output format (default: text)
  -v, --verbose               repeatable
  -q, --quiet
      --evidence-log FILE     append JSON Lines evidence log
      --no-color

Commands:
  scan      DEV...                     detect ZFS labels on devices/images
  labels    DEV [--all]                dump label nvlists (best copy or all 4)
  uberblocks DEV|POOL [--all]          uberblock ring with validity
  pool      POOLSPEC                   assembled pool summary and health
  list      POOLSPEC [--txg N|--before TS] [--diff TXG2] [-r]
                                       datasets/zvols/snapshots at a TXG
  timeline  POOLSPEC                   TXG ↔ time ↔ dataset events
  dump      POOLSPEC DATASET -o OUT.img [--txg N] [--strict] [--key KEYSPEC]
                                       extract a zvol (or object dump of a fs)
  carve     POOLSPEC [--type zvol] [-o DIR]
                                       find and reconstruct unlinked datasets
  verify    POOLSPEC DATASET [--txg N] check every blkptr checksum, no output
  report    POOLSPEC -o report.json    consolidated forensic report

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
zvolrescue scan /dev/ada0p3 /dev/ada1p3
zvolrescue uberblocks /dev/ada0p3

# 2. When did pool/vm/disk0 disappear?
zvolrescue timeline /dev/ada0p3 /dev/ada1p3 | grep disk0

# 3. Extract it from the last TXG that still had it, verifying checksums.
zvolrescue dump /dev/ada0p3 /dev/ada1p3 pool/vm/disk0 --txg 4816230 \
    --strict -o /mnt/rescue/disk0.img --evidence-log case42.jsonl
```

## 8. Architecture

### 8.1 Language and dependencies

* **C++17**, same toolchain and CI conventions as [`crate`](https://github.com/click0/crate) (clang on FreeBSD base, GCC/clang on Linux). Rationale: performance for multi-TB streaming, direct use of C ZFS headers, no runtime to ship on a rescue system.
* Compression: `liblz4`, `libzstd`, `zlib`; `lzjb` and `zle` are reimplemented (trivial).
* Checksums: `fletcher2/4` reimplemented; `sha256/512` via OpenSSL/LibreSSL; `skein`, `edonr`, `blake3` vendored from OpenZFS (CDDL) under `third_party/`, kept isolated so the BSD-3 core stays clean.
* Encryption: OpenSSL `EVP` (AES-CCM/GCM), OpenZFS key derivation (PBKDF2) reimplemented.
* CLI: no framework beyond `getopt_long(3)`; JSON via a single-header library.
* Optional build flag `--with-libzpool` to cross-check results against OpenZFS userland (`zdb`) in tests. Not a runtime dependency.

### 8.2 Layers

```
cli/            command parsing, output formatting, evidence logging
lib/
  io/           read-only device & image access, sparse output writer, partition tables
  vdev/         label parsing, vdev tree, mirror/RAIDZ/dRAID reconstruction
  zio/          blkptr, DVA resolution, checksums, decompression, decryption
  dmu/          objsets, dnodes, indirect block walking
  dsl/          MOS, DSL dirs/datasets, snapshots, TXG selection, dataset diff
  zvol/         zvol extraction, hole detection, resume
  zpl/          (later) ZPL file-level recovery
  carve/        raw scanning and candidate scoring
  report/       JSON/text report model
third_party/    vendored CDDL code (skein, edonr, blake3), isolated
tests/          unit tests + fixture-pool integration tests
docs/           SPEC.md, SPEC.uk.md, research/, design notes
```

Every layer above `io/` is pure: it takes a `BlockSource` interface and
never touches the OS, which makes the reader trivially testable on
fixtures and portable.

### 8.3 Safety invariants

1. There is exactly one function that opens evidence, and it hard-codes `O_RDONLY` (plus `O_EXCL` on platforms that honour it for block devices).
2. Output paths are canonicalised and compared against every input's `st_dev/st_ino`; a match aborts with exit code 5.
3. No `system()`, no shelling out, no network sockets (enforced by a test that greps the binary's imports).

## 9. Testing strategy

* **Unit tests** for every on-disk structure parser using golden byte arrays taken from real pools.
* **Fixture pools**, generated in CI on a FreeBSD runner (see `crate`'s [freebsd-runner-setup](https://github.com/click0/crate/blob/main/docs/freebsd-runner-setup.md)) and on Linux with OpenZFS:
  * topologies: single, mirror-2, raidz1-3, raidz2-4, raidz3-5, draid1;
  * datasets: zvols with known pseudo-random content and every compression/checksum combination, sparse zvols, encrypted zvols, deduplicated zvols, snapshots and clones;
  * scenarios: `zfs destroy` then recover at older TXG; `zpool destroy` then recover; one member missing; one member zeroed at the labels; random 1 MiB corruption in data; random corruption in metadata.
  * assertion: SHA-256 of extracted image equals the SHA-256 recorded before destruction.
* **Cross-check**: on hosts with OpenZFS userland, compare `zvolrescue list`/`uberblocks` output with `zdb -l`/`zdb -u`/`zdb -d`.
* **Fuzzing**: libFuzzer harnesses for nvlist, blkptr, dnode and ZAP parsers.
* **Static analysis**: `-Wall -Wextra -Werror`, clang-tidy, ASan/UBSan job.

## 10. Delivery phases

| Phase | Deliverable | Requirements | Acceptance |
|---|---|---|---|
| **0 — Bootstrap** | Repo skeleton, this spec, CI on FreeBSD + Linux, fixture-pool generator, `scan`/`labels`/`uberblocks` | F-01…F-04, N-01, N-02 | Correct label/uberblock output for all fixture topologies; matches `zdb -l/-u`. |
| **1 — MVP** | `list`, `timeline`, `dump` for single/mirror pools; lz4/zstd/gzip/lzjb/zle/off; fletcher/sha256; JSON output; evidence log | F-10…F-13, F-20…F-23, F-33, F-40, F-50…F-52 | UC-1 and UC-4 pass on mirror fixtures: destroyed zvol recovered bit-exact from an older TXG. |
| **2 — Redundancy & integrity** | RAIDZ1/2/3 reconstruction, dRAID, all checksums, gang/embedded blocks, `verify`, `--strict`, resume, bulk `-r` | F-24…F-26, F-31, F-32, F-05, F-06 | UC-2 passes: zvols recovered from a raidz2 fixture with one member missing and another corrupted. |
| **3 — Forensics** | Encrypted datasets with key, carving of unlinked zvols, `report`, hashes, pending-deletion analysis | F-27, F-41, F-42, F-15, F-53, F-54 | UC-3 passes: full report with hash chain; carved zvol recovered after uberblocks were rolled past it. |
| **4 — Filesystems** | Object dump of fs datasets, then ZPL file-level recovery | F-29, F-30, F-43 | Files from a destroyed filesystem dataset recovered with correct names, sizes and hashes. |
| **Later** | TUI, `zfs send` stream output, plugins for guest-fs carving, packaging in FreeBSD ports | — | — |

Version numbering: phase N ships as `0.N.x`; `1.0.0` after phase 3 has
been used on at least three real-world incidents with documented outcomes.

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| On-disk format details are under-documented; only source of truth is OpenZFS source. | Keep a `docs/research/ondisk-notes.md` with references to OpenZFS source lines per structure; cross-check with `zdb` in CI. |
| Feature flags evolve (e.g. new compression, `raidz_expansion`, `blake3`). | Feature-flag matrix in `list`/`pool` output; refuse gracefully on unknown *read-incompatible* features, warn on unknown read-compatible ones. |
| CDDL code vendoring vs BSD-3 licence. | Isolate under `third_party/` with its own licence file; keep the core free of it; document in `LICENSE.third_party`. |
| Recovery window is short (freed blocks get reused). | Documentation front-page instruction: *stop writing to the pool now, export it, image the disks*. `scan` prints the age of the oldest usable uberblock immediately. |
| Users expect in-place repair. | The tool name, README and `--help` state clearly that it never writes to the pool; point to `zpool import -F/-T` for that use case. |

## 12. Open questions

1. Should phase 1 target FreeBSD *only* to move faster, with Linux CI added in phase 2? (Proposal: Linux CI from phase 0 — fixture generation is easier there and it keeps the code portable from day one.)
2. RAIDZ expansion (`raidz_expansion` feature) reflowed layouts — support in phase 2 or defer?
3. Vendoring `skein/edonr/blake3` vs. depending on an external library — decide when phase 2 starts.
4. Name of the library target: `libzvolrescue` or `libzfsread`? The latter is more honest about its scope if file-level recovery lands.

## 13. References

* OpenZFS source: `module/zfs/`, `include/sys/{spa,vdev,zio,dmu,dsl_*,zap}*.h`
* *ZFS On-Disk Specification* (Sun, 2006) — outdated but still the only prose description of labels, uberblocks, DMU and DSL.
* `zdb(8)`, `zpool-import(8)` (`-F`, `-T`, `-X` semantics)
* Related tools to compare against in `docs/research/`: `zfs_revert`, Klennet ZFS Recovery, UFS Explorer, ReclaiMe, `zfs-fuse`.
