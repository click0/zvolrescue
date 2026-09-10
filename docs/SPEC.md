# zvolrescue — Technical Specification (ТЗ)

**Status:** living document, revised 2026-09-09 (tool at v0.1.0-alpha.1) · **Owner:** Vladyslav V. Prodan

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
| F-25 | S | Read from dRAID with reconstruction. *Status: done — permutation maps regenerated from OpenZFS's seeds and verified against its checksums; rows, group wrap, two-row blocks, empty columns and distributed spares implemented; validated on `ztest` draid1 (4d:6c:1s) and draid2 (5d:9c:2s) pools, including reads with every combination of up to `nparity` members missing.* |
| F-26 | S | Embedded block pointers (`embedded_data`), gang blocks, `large_blocks`, `large_dnode`. |
| F-27 | S | Encrypted datasets: decrypt with a user-supplied raw/hex/passphrase key (`aes-128/192/256-ccm/gcm`); without a key, extract ciphertext and metadata only. *Status: done for data and dnode blocks — metadata (cross-checked against `zdb`), wrapping-key derivation (raw/hex/PBKDF2 passphrase/prompt), master-key unwrap (AES-GCM/CCM, key versions 0 and 1), per-block HKDF-SHA512 key, AES-GCM/CCM decryption of data blocks and of the bonus buffers of dnode blocks with the dnode/blkptr associated data; every encrypted block of `ztest` pools decrypts and every object is accounted for. Not decrypted: ZIL blocks (not needed for extraction). Objset MACs are not re-verified (the block checksum already is).* |
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

### 5.6 Recovering the vdev zero point when the labels are gone

Every DVA in a pool is relative: *physical = vdev start + 4 MiB (two front
labels and the boot area) + offset*. When all four labels of a member are
overwritten — `vdev_phys` and the uberblock rings alike — three things go
with them: the base (the "zero point"), the geometry (`ashift`, children and
their order, top-level id) and the root pointer. The tool must treat these
as three separate recoveries, and the base must never be *assumed*: it is
accepted only after a cryptographic check against on-disk content.

Anchors for the base, cheapest first; each later one is only needed when
the earlier ones are unavailable:

| ID | Pri | Requirement |
|---|---|---|
| F-60 | S | **Partition tables** (F-06): primary and backup GPT, MBR, plus layout conventions (1 MiB alignment; Linux whole-disk `-part9` 8 MiB tail; FreeBSD `freebsd-boot`/swap/`freebsd-zfs` order) yield base *candidates*, never a base. |
| F-61 | S | **Any surviving uberblock** (F-05): each uberblock carries a `ZIO_CHECKSUM_LABEL` embedded checksum whose verifier is its own vdev-relative offset. An uberblock found by magic at physical `P` confirms base `B` iff the checksum verifies with verifier `P − B`; one hit fixes the base exactly, tells which of L0–L3 the slot belonged to and so recovers the old vdev size even after the partition was re-created with another size. Works with all four `vdev_phys` gone as long as one ring slot survives. |
| F-62 | S | **Sibling labels**: in a mirror or RAIDZ the other members' configs give the lost member's `guid`, `asize` and `ashift`; `asize` plus alignment leaves a handful of base candidates to confirm with F-61/F-63. |
| F-63 | C ◇ | **Pointer self-consistency, fully automatic** (the worst case, all rings gone and no hints): scan for structures recognisable without a base (dnode arrays — type ≤ 54, `indblkshift` 9..17, small `nlevels`/`nblkptr`, 512-byte period; indirect blocks; objset headers), collect their block pointers, and confirm a candidate base `B` by checking that the block at `B + 4 MiB + offset` has the pointer's checksum. Candidates step by `1 << ashift` (`ashift` itself follows from the smallest DVA offset step and `asize` granularity) inside the alignment window. A wrong base passes no check; the right one passes all. Gang headers (verifier `[vdev, offset, birth]`) and ZIL chains (`zc_next_blk` vs. the physical position of the next block) are extra anchors. |
| F-64 | S ◇ | **Root without uberblocks**: once the base is known and no uberblock survives, find the MOS by scanning for `objset_phys` candidates of type META, rank them by the highest `birth` in their pointers and by how complete a MOS walk they yield, then continue through the DSL as usual. This is `zvolcarve` territory (F-41/F-42), not the atomic binary's. |

**Implemented so far.** F-61 is in the tool: `scan` searches a member for
uberblock magic, confirms each hit against its own embedded checksum and
reports every base that verified, with the number of confirmations, the
labels they came from, the TXG range and the vdev size a rear-label hit
implies. It runs by itself on a member with no readable label
configuration, and on request with `--zero-point` (`--zero-point-whole`,
`--psize BYTES`). The front label pair needs no hypothesis; the rear pair
is placed against the vdev's size, so it confirms a base only together
with one. The base is also used for reading: a member whose labels
verify only at that base is scanned there, and every DVA on it resolves
to `base + 4 MiB + offset`, so `list` and `dump` work on a partition that
was re-created with a different start. F-62 is half done: a member whose own
labels are gone can be bound to a leaf its siblings' configuration names
but no scanned device carries, through `--assume-member PATH[=GUID]`.
The assertion buys nothing but a slot — every block read through it is
still checksum-verified, so a wrong binding is refused rather than
believed. What is left of F-62 is making that binding *automatic*:
trying each vacant leaf and letting the checksums pick the one that
works. Supplying a whole topology by hand is F-65.

Two regimes follow:

* **Damage inside known bounds** (first N MiB zeroed, partition table
  rewritten, tail cut off): not a hard case. Everything outside the bounds
  reads normally; L2/L3 or their slots are found by magic and confirmed by
  F-61; the root comes from the newest surviving uberblock. F-60–F-62
  cover it.
* **Bounds unknown and all four labels gone**: the base comes from F-63,
  which needs a full pass over the device — the same pass carving needs
  anyway — and the root from F-64.

`scan` reports where the base came from (label, partition table, sibling,
uberblock verifier, pointer consistency, user hints) and how many
independent checks confirmed it, so the evidence log records the provenance
of every address the extraction used.

**The practitioner's route: a label template, not an algorithm.** People who
do this by hand in a hex editor report that the bare-device case was rarely
hard in practice: they *know* the layout (disk count, RAIDZ level, ashift,
roughly where the partition sat) from the other members or from the case
file, edit a `vdev_phys` template accordingly, and from then on ordinary
import or the professional recovery suites walk the metadata with their
usual means. What resists reliable automation is the topology *guess*;
everything after it is mechanical. The tool therefore keeps the human where
the human is better and automates what is mechanical and verifiable:

| ID | Pri | Requirement |
|---|---|---|
| F-65 | S | **Layout hints = a virtual label.** The user can supply what a `vdev_phys` template would carry — top-level type, member list and order, `nparity`, `ashift`, base-offset candidates, pool/vdev GUIDs if known — and `scan`/`list`/`dump` use it exactly as they would use a real label. The template lives in memory and in the evidence log only; nothing is written to the device (N-01). |
| F-66 | S | **Search inside the hint space, confirm by checksum.** Whatever the hint leaves open is enumerated and verified rather than guessed: member order (6 members of a RAIDZ2 = 720 permutations, each settled by the checksum of one block), `ashift` (a handful of values), base (the alignment window), `nparity`. A candidate is accepted only when block checksums agree (D-5); the search stops at the first fully consistent template and reports every alternative that also passed. |
| F-67 | S | **Export the confirmed label.** `scan --emit-label FILE` writes the reconstructed `vdev_phys` nvlist (and the geometry as JSON) to a file, so it can be placed on a *copy* of the disk for `zpool import` or loaded into another recovery tool. The tool itself never places it on the evidence. |

Reading order for the bare case is thus: F-65 hints → F-66 search →
F-61/F-62 confirmation where any label material survives → F-64 for the
root → F-67 to hand the result on. F-63 (no hints at all) stays optional.

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
      --debug                 trace every read decision to stderr (docs/DEBUGGING.md)
      --debug-log FILE        the same trace to FILE

Commands:
  scan  DEV...                          what is on these devices/images: labels, pool
                                        name/GUID, vdev GUIDs, TXG window, assembled
                                        topology, missing members
  list  POOLSPEC [--txg N|--before TS] [--diff TXG2] [-r]
                                        datasets/zvols/snapshots at a TXG; for each
                                        destroyed one, the last TXG that still had it
  dump  DATASET POOLSPEC -o OUT.img [--txg N] [--strict] [--key KEYSPEC] [--resume] [-r]
                                        extract a zvol (or object dump of a fs) to a raw
                                        sparse image, verifying every block; prints the
                                        SHA-256 of the output

POOLSPEC:  one or more vdev members, e.g.
           /dev/ada0p3 /dev/ada1p3
           --image disk0.img --image disk1.img
           --pool-guid 0x1234…  (pick among several pools found)
KEYSPEC:   raw:FILE | hex:HEX | hex:@FILE | passphrase:FILE | prompt   (prompt reads stdin; echo is not disabled)
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
zvolrescue dump pool/vm/disk0 /dev/ada0p3 /dev/ada1p3 --txg 4816230 \
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
* Checksums: `fletcher2/4` reimplemented; `sha2`, `blake3` from the RustCrypto family; `skein` (Skein-512-256 MAC keyed with the pool salt) reimplemented in `zfs-ondisk::skein` (~200 lines) because the RustCrypto crate has no keyed mode; `edonr` has no Rust implementation and is ported from OpenZFS (`crates/edonr`, ~250 lines, CDDL, isolated crate); validated against an edonr block of a real `ztest` pool.
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
5. The vdev base (zero point) is never taken on trust from a partition table, a sibling's label or a heuristic: it is used only after at least one on-disk checksum confirmed it (§5.6), and `scan` names the confirming evidence.

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

### 9.1 The golden image and the damage matrix

The tests above prove that the reader understands the on-disk format. They
do not prove that recovery is *right*, and nothing does unless the correct
answer is known in advance. The recovery test that counts is therefore
built on one principle: **a known-good reference first, damage second, and
the tool's output compared against the reference — never against the
tool's own earlier output.** This also guards against the failure mode of
an implementation developed largely by an AI: without an independent
ground truth, an algorithm is easily tuned to the one case at hand and
mistaken for general.

**Quality over quantity.** One golden image, not many. What must vary is
the *kind of damage and its combinations*, not the data: more images with
different content add build time and no new failure modes. The one image
is made rich enough that every failure mode has something to hit:

* **One pool, several geometries.** A single pool may carry top-level vdevs
  of different kinds (mirror, RAIDZ2, dRAID1 side by side, `zpool create
  -f`); ZFS stripes every dataset across all of them, so one image
  exercises every reconstruction path without three pools.
* **Metadata worth damaging**: zvols of several `volblocksize`s, sparse
  and dense, snapshots, clones, a renamed volume, a destroyed volume and a
  destroyed snapshot, an encrypted dataset with a raw key and one with a
  passphrase, every checksum and compression, gang blocks (low threshold),
  large dnodes, pending deletions.
* **Many versions**: hundreds of TXGs with writes to the volumes between
  snapshots, so the uberblock rings are full, older TXGs point at data
  that has since changed, and `--txg`, `--diff` and carving have history
  to work on.
* **The oracle**, recorded next to the image at build time: SHA-256 of
  every volume at every snapshot and at export, `zdb -d` of every TXG,
  `zdb -l` of every member, `zpool status`, the keys. This is the
  "how it should be" that every comparison is made against.

The image is built by a script in a real kernel environment (one of the
VMs in [REALWORLD-TESTS.md](REALWORLD-TESTS.md)) and is then immutable:
it is an artifact identified by its SHA-256, regenerable from the script,
and never edited by hand.

**Damage is applied, not stored.** Every damage case is a declarative
manifest — member, byte range, pattern (zeros, random bytes, a shift by N
sectors, an older copy of the same structure written over the newer one,
single bit flips), possibly several ranges on several members — applied to
a temporary copy at test time. What a practitioner would do in a hex
editor is thereby written down once and reproduced exactly. The catalogue
of damage classes (labels: one, the front pair, the rear pair, all four,
only `vdev_phys`, only the rings, partial rings with a forged txg;
partition: rewritten GPT, shifted start, truncated tail, re-created with
another size; metadata: MOS, dnode blocks, indirect blocks, property ZAPs,
the crypto key object; data: a RAIDZ column, both mirror halves in
different places, a gang header, an encrypted block; whole member missing;
a member replaced by an *older copy of itself*) is authored from ZFS's
redundancy semantics, independently of the tool's current code.

**Combinatorics.** Classes are run singly, then in pairs and triples across
members and geometries; hundreds of runs at seconds each. Each run lands
in exactly one of four outcomes, and the expected outcome is derived from
the redundancy that ZFS itself guarantees for that combination, not from
what the tool happens to do:

1. recovered bit-exact (hash equals the oracle);
2. recovered through reconstruction, with the reconstruction visible in the
   evidence log;
3. refused cleanly (exit 3) with no partial output presented as good;
4. anything else — a tool defect.

The read-only invariant is asserted on every run: the hashes of the damaged
input copies are unchanged afterwards. A held-out subset of combinations is
kept out of development and run only at release time.

**Separate repository.** The image, its oracle and the damage manifests
live in their own repository (`zvolrescue-testdata`), so that multi-GiB
artifacts never enter this one. This repository holds the build script,
the expected SHA-256 of the image, and the CI job that fetches the image
and runs the matrix.

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
| D-4 | 2026-09-07 | The binary does **not link OpenZFS** (`libzpool`, `libzfs`, `libzfs_core`); on-disk primitives are reimplemented, and OpenZFS userland (`ztest`, `zdb`) is used only as an **oracle in tests**. | `libzpool` is the kernel SPA built for userland: no stable ABI (soname bumps, private headers), it drags in the whole pool machinery instead of raw reads, needs a C toolchain and a matching OpenZFS version on every target (mfsBSD, FreeBSD 14/15, Debian, Ubuntu ship different ones), and a forensic reader should not depend on the code whose failure it is investigating. `libzfs_core` only speaks to a running kernel. The duplicated code is small (skein ≈200 lines, edonr ≈250, lzjb/zle ≈100) and each piece is validated against real `ztest` pools in CI. |
| D-5 | 2026-09-08 | The vdev base is a **verified** quantity, not a configured one: labels, partition tables and sibling configs only propose it; an on-disk checksum (uberblock label verifier, pointer→block checksum, gang verifier) must confirm it before any address is resolved (§5.6, F-60–F-67). | A wrong base silently produces plausible garbage; a checksum makes it impossible. Only the truly bare case (all rings gone) needs a full scan, and that scan is shared with carving. |
| D-6 | 2026-09-08 | The bare-device case is solved as a **semi-automatic** workflow — user-supplied layout hints (a virtual `vdev_phys`), enumeration of what the hints leave open, checksum confirmation, export of the confirmed label (F-65–F-67) — and fully automatic topology inference (F-63) is only a "could". | Practitioner feedback: by hand the case reduces to editing a label template, after which standard tooling walks the metadata; the topology guess is what resists reliable automation. Keeping the human there and automating the enumeration (hundreds of permutations settled by checksums in seconds) is where a tool beats a hex editor. |
| D-7 | 2026-09-08 | Recovery correctness is tested against **one golden image with a recorded oracle and a catalogue of damage manifests** applied combinatorially (§9.1); test data lives in a separate repository (`zvolrescue-testdata`). | A recovery test is only meaningful when the right answer is known beforehand; comparing against the tool's own output tunes the algorithm to the case at hand. Diversity must come from the kinds and combinations of damage, not from more images with different content, which add time and no failure modes. Multi-GiB artifacts do not belong in the source repository. |

## 14. References

* OpenZFS source: `module/zfs/`, `include/sys/{spa,vdev,zio,dmu,dsl_*,zap}*.h`
* *ZFS On-Disk Specification* (Sun, 2006) — outdated but still the only prose description of labels, uberblocks, DMU and DSL.
* `zdb(8)`, `zpool-import(8)` (`-F`, `-T`, `-X` semantics)
* Related tools to compare against in `docs/research/`: `zfs_revert`, Klennet ZFS Recovery, UFS Explorer, ReclaiMe, `zfs-fuse`.
