# Changelog

All notable changes to zvolrescue. Versions: `v0.1.0-alpha.1` first, then
plain minor bumps (`v0.2.0`, `v0.3.0`, …) until 1.0. Every 0.x release is
validated against OpenZFS **userland** pools (`ztest` + `zdb`, no kernel)
in CI; what was tried on real environments is logged in
[docs/REALWORLD-TESTS.md](docs/REALWORLD-TESTS.md).

## Unreleased

### Added
* **Zero-point recovery from uberblocks (SPEC F-61).** A member whose four
  `vdev_phys` areas have been overwritten no longer scans as a blank disk:
  every uberblock is a self-checksumming block whose verifier is its own
  vdev-relative offset, so one surviving ring slot fixes where the vdev
  starts. `scan` runs the search by itself when no label configuration is
  readable, and on request with `--zero-point` (`--zero-point-whole` to
  search the whole member, `--psize BYTES` to name the vdev's size for the
  rear label pair). It reports the base, how many checksums confirmed it,
  which labels they came from, the TXG range and the vdev size the rear
  labels imply. Verified against a real ztest member with all four
  configurations zeroed, before and after moving it 1 MiB.
* **Members are read from their own base.** A vdev that does not start at
  offset 0 of what was opened — a partition re-created with another start,
  an image cut differently — is now read correctly end to end: the labels
  are re-read relative to the recovered base and every DVA resolves to
  `base + 4 MiB + offset`. A configuration that parses but whose embedded
  checksum does not verify counts as no configuration, which is exactly
  what a member read at the wrong base looks like. `list` and `dump` of a
  member moved 3 MiB give the same datasets and the same image hash as
  before the move, and a whole-object walk through it is identical.
* **`--assume-member PATH[=GUID]` (SPEC F-62, first half).** A member whose
  four labels are gone carries nothing that says which leaf it is, but its
  siblings' configuration does: it names every leaf, and the ones no
  scanned device carries are exactly the slots such a member can fill.
  `list` and `dump` take the assertion — by GUID, or without one when a
  single leaf is missing — and nothing else is taken on trust: on a raidz2
  fixture with two label-less members and a third member left out, the
  correct binding returns the volume bit-exact while a swapped one fails
  every checksum and exits 3 instead of handing back plausible garbage.
* **`--assume-member PATH` works out *which* leaf on its own.** Without a
  GUID the tool tries the member in each vacant leaf and reads the pool
  through it: as many siblings of that top are withheld as the redundancy
  can spare, so the walk leans on the candidate, and a device of zeros is
  then put in its place to tell a slot that merely needs to be occupied
  from one whose contents matter. A leaf is taken when its contents made
  the difference, or when it is the only one that reads at all. Several
  leaves of the same mirror are interchangeable and any is reported;
  several that are not says so and asks for a GUID rather than guessing. A
  device that does not hold this pool's data reads as no leaf and is
  refused.
* **`--hints FILE`: a layout described by hand (SPEC F-65).** When not one
  `vdev_phys` survives on any member, nothing on disk says what the pool
  looked like — but the uberblock rings are still there, and their
  checksums verify against their own offsets. A JSON file gives what a
  `vdev_phys` template would (ashift, the top-level vdevs, their members
  in vdev order, and a base offset per member) and the tool reads through
  it exactly as it would through a label: a raidz2 whose four members have
  had every label configuration zeroed lists its datasets and extracts its
  volume bit-exact. A member with no configuration now also yields a scan
  built from the anchors alone, so the TXG history and root pointers are
  available without any label at all.
* **`--search-order`: the order the checksums accept (SPEC F-66).** What a
  layout leaves open is enumerated rather than guessed. Member order
  cannot be settled by "did it read": a raidz2 with two columns swapped
  still returns the right bytes, reconstructed around the two that no
  longer verify. It is settled by how much had to be repaired — read
  through the right order a healthy pool produces no checksum mismatch at
  all — so every ordering is tried and ranked by mismatches. Ties are
  reported rather than hidden; a vdev too wide to enumerate (more than 7
  members) says so instead of running for hours.

## v0.1.0-alpha.1 — 2026-09-08

First intermediate release: the atomic utility (`scan`, `list`, `dump`)
reads every OpenZFS on-disk feature needed to pull a zvol out of a pool
that no longer imports.

### Reads
* Labels, uberblock rings (any ashift), pool assembly from any subset of
  members, stale labels (txg 0, superseded tops) set aside and reported.
* Every vdev type: stripe, mirror, RAIDZ1/2/3, **dRAID** (permutation
  maps regenerated from OpenZFS's seeds and verified against its
  checksums; distributed spares), nested trees, `spare`/`replacing`.
* Parity reconstruction of missing members and of silently corrupted
  columns (combinatorial, as `vdev_raidz_combrec`), gang blocks,
  embedded block pointers, large dnodes.
* Every checksum: fletcher2/4, sha256, sha512, skein, edonr, blake3
  (salted ones with the pool salt), noparity; correct word order per
  algorithm and the truncated comparison for encrypted datasets.
* Every compression: lz4, zstd (OpenZFS's magicless frames), gzip-1..9,
  lzjb, zle, off, empty.
* MOS, DSL directories/datasets/snapshots/clones, ZAP (micro and fat).

### Encrypted datasets (phase 3, data path)
* `list` shows suite, key format, key location, PBKDF2 parameters, key
  GUID/version and the encryption root without a key.
* `dump --key raw:FILE | hex:HEX | hex:@FILE | passphrase:FILE | prompt`
  derives the wrapping key as libzfs does, unwraps the master key
  (AES-GCM/CCM, key versions 0 and 1), and decrypts data blocks and the
  bonus buffers of dnode blocks. ZIL blocks are not decrypted.

### Commands
* `scan`: per-device label/uberblock report, pool assembly, readability.
* `list -r [--txg N] [--diff N]`: datasets across verified TXGs; finds
  destroyed volumes in older TXGs.
* `dump DATASET … -o OUT.img [--txg N] [--strict] [--resume] [-r]`:
  sparse image, SHA-256 of the output, per-block evidence log, resume,
  bulk extraction with a manifest.
* `--debug` / `--debug-log FILE` tracing of every read decision;
  `-f json` everywhere.

### Guarantees
* Read-only by construction (members opened `O_RDONLY`; output on a
  member is refused). No `unsafe` in the workspace, no C toolchain, no
  system libraries: static binaries for Linux (musl) and FreeBSD.

### Validation
* Unit tests on synthetic fixtures for every layer.
* CI cross-check against OpenZFS 2.2 userland: mirror, raidz2,
  raidz1-of-mirrors, draid1, draid2 pools generated by `ztest`;
  `list`/`scan` diffed against `zdb`; every block of every object read,
  verified and decrypted with ztest's key; each pool walked again with
  `nparity` members left out.
* FreeBSD 14.2 build and tests.

### Known gaps
* No real kernel-imported pool has been tested yet (mfsBSD, FreeBSD
  14/15, Debian, Ubuntu, CachyOS are the planned environments).
* ztest makes no zvols, so end-to-end `dump` of an *encrypted* volume is
  verified on fixtures only.
* Not yet: partial or damaged labels (F-05), GPT/MBR whole-disk images
  (F-06), carving (F-15), the companion tools (`zvoltimeline`,
  `zvolcarve`, `zvolreport`, `zvolfiles`).
