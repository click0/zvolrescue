# Changelog

All notable changes to zvolrescue. Versions: `v0.1.0-alpha.1` first, then
plain minor bumps (`v0.2.0`, `v0.3.0`, …) until 1.0. Every 0.x release is
validated against OpenZFS **userland** pools (`ztest` + `zdb`, no kernel)
in CI; what was tried on real environments is logged in
[docs/REALWORLD-TESTS.md](docs/REALWORLD-TESTS.md).

## v0.2.0 — 2026-09-10

**When the labels are gone.** `v0.1.0-alpha.1` could read any pool whose
labels survived. This release is about the pools where they did not: a
partition re-created somewhere else, a member whose four `vdev_phys`
areas were overwritten, a whole disk imaged rather than a partition, or a
pool with no configuration left anywhere. Nothing new is taken on trust —
every address this release recovers is accepted only after a checksum
verifies at it (SPEC D-5), and the tool still never writes to the
evidence.

### Added
* **Whole-disk images (SPEC F-06, F-60).** A member is usually a
  partition, and an image of the disk it lived on carries the table that
  says where it began. `scan` reports that table — GPT (primary or backup,
  512- or 4096-byte sectors) or MBR, with the ZFS partition types marked —
  and every command looks there first when nothing verifies at offset 0.
  The partition's *length* matters as much as its start: the rear label
  pair is placed against the vdev's own size, so a member read to the end
  of the disk instead of the end of its partition finds only two of its
  four labels.
* **Zero-point recovery from uberblocks (SPEC F-61).** A member whose four
  `vdev_phys` areas have been overwritten no longer scans as a blank disk:
  every uberblock is a self-checksumming block whose verifier is its own
  vdev-relative offset, so one surviving ring slot fixes where the vdev
  starts. `scan` searches by itself when no label configuration is
  readable, and on request with `--zero-point` (`--zero-point-whole`,
  `--psize BYTES` for the rear pair). It reports the base, how many
  checksums confirmed it, which labels they came from, the TXG range and
  the vdev size a rear-label hit implies.
* **Members are read from their own base.** A vdev that does not start at
  offset 0 of what was opened is now read correctly end to end: the labels
  are re-read relative to the recovered base and every DVA resolves to
  `base + 4 MiB + offset`. A configuration that parses but whose embedded
  checksum does not verify counts as no configuration — that is exactly
  what a member read at the wrong base looks like. `list` and `dump` of a
  member moved 3 MiB give the same datasets and the same image hash as
  before the move.
* **`--assume-member PATH[=GUID]` (SPEC F-62).** A member whose labels are
  gone carries nothing that says which leaf it is; its siblings'
  configuration names every leaf, and the ones no scanned device carries
  are the slots it can fill. Without a GUID the tool works out which by
  reading through it: as many siblings of that top are withheld as the
  redundancy can spare, so the walk leans on the candidate, and a device
  of zeros in the same slot separates "this slot has to be occupied" from
  "this member's contents are what read". Leaves of one mirror are
  interchangeable and any is reported; leaves that are not are listed for
  the operator to name. A device that does not hold this pool's data reads
  as no leaf and is refused.
* **`--hints FILE`: a layout described by hand (SPEC F-65).** When not one
  `vdev_phys` survives anywhere, a JSON template gives what a `vdev_phys`
  would (ashift, the top-level vdevs, their members in vdev order, a base
  offset per member) and the tool reads through it exactly as through a
  label. Layouts nest, so a vdev being replaced, one backed by a spare, or
  a mirror of raidz can be described. The uberblocks still come from the
  members: a member with no configuration yields a scan built from the
  anchors alone, which is what makes the template enough on its own.
  `scan -f json` emits each top-level vdev as a `tree` in exactly the
  shape `--hints` takes — the scan of a healthy pool is the template for
  reading a damaged one.
* **`--search-order`: the order the checksums accept (SPEC F-66).** Member
  order cannot be settled by "did it read": a raidz2 with two columns
  swapped still returns the right bytes, reconstructed around the two that
  no longer verify. It is settled by how much had to be repaired — through
  the right order a healthy pool produces no checksum mismatch at all — so
  every ordering is tried and ranked by mismatches. Ties are reported
  rather than hidden; a vdev too wide to enumerate (more than 7 members)
  says so instead of running for hours.
* **`scan --emit-label FILE` hands the result on (SPEC F-67).** The layout
  is written out as the label it describes: the front 128 KiB — blank
  area, boot header and the `vdev_phys` nvlist sealed for the position it
  will occupy — plus the geometry as JSON beside it. It stops short of the
  uberblock ring on purpose, so placing it on a *copy* of the disk leaves
  the uberblocks that are still there intact.
* **One contract for every binary (COMPANIONS §1).** The flags, exit
  codes and JSON envelope this tool established now live in a crate of
  their own, `zvol-common`: the companion tools take the same `--hints`,
  `--search-order` and `--assume-member`, mean the same thing by exit
  code 2, and are pointed at a damaged pool the same way. Nothing about
  `zvolrescue`'s own command line changes.

### Documented
* **The search profile a carver needs (COMPANIONS C-13…C-19).** What
  narrows a raw scan of a disk to blocks that could belong to this pool:
  the ashift and the addresses the geometry allows, the checksum a block
  claims and whether it verifies, the salt for a keyed checksum, the
  compression a block says it used, the TXG range a scan established, and
  what a candidate must show before it is reported rather than guessed at.
  Requirements only — no carver ships in this release.
* [docs/RELEASING.md](docs/RELEASING.md) says how a release is cut, what a
  mistyped tag does, and how to re-cut a release for a tag that is already
  pushed.

### Fixed
* The release job assembles a release as a **draft** and publishes it only
  once it carries every file. A published release is frozen when release
  immutability is on, so attaching the binaries afterwards — what the
  previous job did — could not work at all. A mistyped tag no longer names
  the files after itself, and release notes that would say nothing now
  fail the job instead of being published.
* `ashift` is taken from whichever label still states it when walking the
  uberblock ring of a label whose configuration is gone. It belongs to the
  vdev, not to one copy of its label, and reading a 4 KiB ring as if its
  slots were 1 KiB found the uberblocks but verified none of them.
* `--assume-member` on members that assemble into no pool at all now exits
  2 (unreadable evidence) instead of reporting a usage error.

### Verified
* The `ztest` + `zdb` crosscheck grew four steps, run on five fresh pools
  (mirror, raidz2, raidz1-of-mirrors, draid1, draid2) on every push: the
  base recovered from uberblocks with every `vdev_phys` erased and after a
  1 MiB shift; a whole-object walk through a member moved 1 MiB; the same
  through a member inside a GPT partition of a whole-disk image; and, with
  **every label configuration of every member erased**, the same datasets
  as `zdb` through a layout built mechanically from an earlier scan.
* The damage matrix in
  [zvolrescue-testdata](https://github.com/click0/zvolrescue-testdata)
  runs 38 manifests over three pools; two damage classes now have to be
  answered rather than survived, and both exposed fixes in the tool.

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
