# Changelog

All notable changes to zvolrescue. Versions: `v0.1.0-alpha.1` first, then
plain minor bumps (`v0.2.0`, `v0.3.0`, …) until 1.0. Every 0.x release is
validated against OpenZFS **userland** pools (`ztest` + `zdb`, no kernel)
in CI; what was tried on real environments is logged in
[docs/REALWORLD-TESTS.md](docs/REALWORLD-TESTS.md).

## v0.7.0 — 2026-09-10

**Everything the companion spec asked for.** The last of what
COMPANIONS marks worth having, and the numbers to check it by.

### Added
* **`zvolfiles` reads extended attributes and keeps hard links
  (COMPANIONS Z-04, Z-07, Z-09).** Attributes are read from both places
  they live — packed into the system attributes as an nvlist
  (`xattr=sa`) and in an object's own hidden directory (`xattr=on`) —
  and recorded in `manifest.json` with their values rather than applied,
  because setting one needs the platform's own call and this workspace
  links no system libraries. An object met under a second name is
  written as a hard link to the first rather than copied, so the
  extracted tree keeps the shape it had. A path is matched exactly
  first, and case-folded only where the dataset's `casesensitivity` says
  names are matched that way.

* **`zvoltimeline --pending` (COMPANIONS T-07, SPEC F-15).** How much
  space ZFS has finished with but has not freed, per transaction group:
  the pool's `free_bpobj` and every dataset's deadlist, read from their
  bonus buffers so the answer costs no walk. While a block is still
  accounted for there it has not been reallocated — the difference
  between a destroyed dataset that can still be recovered and one that
  cannot. Cross-checked against `zdb`'s own bpobj accounting on every
  `ztest` pool in CI.

### Fixed
* A dnode with no block pointers but a bonus buffer is recognised as one.
  Requiring at least one block made every DSL dataset and directory
  invisible to a carve — objects that own no data and say everything in
  their bonus — which is exactly the metadata that can name a candidate.

## v0.6.0 — 2026-09-10

**A carve that can name what it found.**

### Added
* **A carved candidate can be named (COMPANIONS C-11).** A dnode found
  by scanning raw space carries no name: names live in the DSL directory
  chain in the MOS, which is what a carve cannot reach. So the scan now
  keeps every dataset dnode it meets, whatever the profile asked for,
  and a candidate is reported with the GUID and creation transaction
  group of the dataset whose objset still points at it — enough to match
  against a `zvoltimeline` line.
* **`zvolcarve scan --sample N` (C-19).** With no idea what to ask for,
  ask the disk: the first N hits are reported as histograms of object
  type, block size, tree depth and birth transaction group, so a profile
  is picked from what is there rather than from memory.
* Releases now carry `zvoltimeline`, `zvolreport`, `zvolcarve` and
  `zvolfiles` for the same three platforms as `zvolrescue`.

## v0.5.0 — 2026-09-10

**Files, not just volumes.** The fourth companion tool, and the phase-4
half of the delivery plan.

### Added
* **`zvolfiles` — files out of filesystem datasets (COMPANIONS §5).**
  The main binary treats a filesystem dataset as an object dump at most;
  this one reads the ZFS POSIX layer. `list` walks the tree with type,
  mode, owner, size, times and symlink targets, at any transaction group
  that still verifies and with `--key` for an encrypted dataset.
  `extract` writes it out, hashing every file into `manifest.json` and
  turning a block that cannot be read into zeros with the count
  recorded, never a silently short file; `--strict` stops at the first
  one. `objects` is the fallback for when the POSIX metadata is too
  damaged to walk: one file per object plus an index — with the root
  directory ZAP zeroed on every member, `list` fails and the file
  contents still come out byte for byte.

  Metadata comes from the system attributes, which is how any pool made
  this decade stores it: a layout number, a packed run of values, and
  two ZAPs in the dataset saying what each value is and how long. A
  legacy `znode_phys_t` bonus is read as one when the magic says so.

## v0.4.0 — 2026-09-10

**What no uberblock points at any more.** The tool the whole
labels-gone chapter was building towards.

### Added
* **`zvolcarve` — volumes that no uberblock points at any more
  (COMPANIONS §3).** Once the ring has rolled past the last transaction
  group that referenced a volume, no walk can reach it and `list` cannot
  see it at any transaction group; its blocks are still on the disk.
  `zvolcarve scan` reads the members through, recognises dnodes by
  structure alone — every field inside the range OpenZFS's `dnode.h`
  allows — walks the trees of what survives, ranks them, and writes a
  workspace `list` and `dump` work from. `dump` extracts through the
  same code and the same checksum verification as `zvolrescue dump`: a
  candidate's score buys it a place in the list and nothing else.

  Metadata is normally compressed, so the scan also tries each
  allocation-aligned offset as the start of an lz4 block. On a `ztest`
  pool that is where 32056 of 33483 dnodes were found; a plaintext-only
  scan would have seen 4% of what is there.

  The search profile (`--volblocksize`, `--levels`, `--txg`, `--size`,
  `--dnode-type`, `--profile`, `--like`) is a filter, never an
  assumption. It is applied at recognition time, so a search for one
  volume does not pay to walk the trees of everything else in the pool,
  and it is decisive in the ranking: a candidate that matched everything
  asked for scores above 0.5 and one that did not scores below it, so a
  hint that was wrong costs ranking rather than the recovery. An empty
  result says which field emptied it — "0 candidates, 15 rejected by
  volblocksize" is a different fact from "there is nothing on this
  disk". `--resume` adds to the index and re-reads the chunk it stopped
  inside; an interrupted scan exits 6.

  Carving works on RAIDZ and dRAID as well as on mirrors: a dnode is 512
  bytes and lies whole inside one allocation sector on one column, so it
  is recognised on a member the same way, and the extraction goes
  through the pool — a raidz2 carve with two of four members left out
  produced the same image, rebuilt from parity. Only the compressed pass
  is mirror-and-single-disk, because a compressed block is split across
  columns and no member holds one contiguously.

## v0.3.0 — 2026-09-10

**One contract, and the first two companions.** The evidence log
becomes the record the spec describes, and two tools start writing it.

### Added
* **`zvoltimeline` — the pool's history from the transaction groups that
  survive (COMPANIONS §2).** Every uberblock that still verifies is the
  pool as it was at that moment; read in order, the transaction groups
  say when a dataset appeared, when it was renamed, and which one still
  had the volume that is gone from the newest. Identity is the `ds_guid`,
  so a rename does not read as a destroy and a create, and a reused name
  with a new GUID reads as both. A transaction group whose MOS can no
  longer be walked is one `unreadable` line, not the end of the run.
  Every `destroyed` line carries the last transaction group that still
  referenced the object and the `zvolrescue dump` command that gets it
  back — with this run's own `--hints`, `--image` and `--assume-member`
  carried over, so it works where the timeline worked. `--from`/`--to`,
  `--dataset` by name or GUID, `-f json`, `--evidence-log`.
* **`zvolreport` — one document a third party can check (COMPANIONS
  §4).** Every tool appends what it did to an evidence log;
  `zvolreport build` consolidates those logs into a report — the case,
  the evidence with its sizes and hashes and which tools read it, the
  tool versions, every command in the order it ran with its exit code,
  the pool and the transaction-group window the scan recorded, what was
  extracted, and every file that was written. It is a function of the
  logs: nothing in it comes from the clock, and two builds of the same
  log are byte-identical. `zvolreport verify` recomputes the SHA-256 of
  everything the report has a hash for and prints a PASS/FAIL table,
  exiting 4 on any file that changed or went missing;
  `--evidence-root`/`--outputs-root` re-base the paths for a machine
  where the disks are mounted somewhere else. `--md` renders the whole
  thing for a ticket or a case file.
* **The evidence log is the record COMPANIONS §1.3 specifies.** It now
  carries the format version, the tool and its version separately, the
  host, the evidence read, the files written and the exit code — not
  just the command line and the result. Every file written carries its
  SHA-256; inputs are hashed only under the new `--hash-inputs`, because
  a shelf of disk images takes hours to read through.

### Fixed
* A dataset is no longer called a clone because its origin is non-zero.
  Every dataset in a modern pool has one — OpenZFS gives the ordinary
  ones the pool's own hidden `$ORIGIN@$ORIGIN` snapshot — so the origin
  is resolved once per walk and compared against it, as
  `dsl_dir_is_clone` does. Checked against `zdb -dddd` on a `ztest` pool,
  where all six datasets carry the `$ORIGIN` snapshot as their origin.

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
