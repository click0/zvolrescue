# Changelog

All notable changes to zvolrescue. Versions: `v0.1.0-alpha.1` first, then
plain minor bumps until 1.0, with a patch where a released minor needs a
fix. Every 0.x release is validated against OpenZFS **userland** pools
(`ztest` + `zdb`, no kernel) in CI; what was tried on real environments
is logged in [docs/REALWORLD-TESTS.md](docs/REALWORLD-TESTS.md).

`v0.2.0` through `v0.7.0` never got releases of their own. A tag here is
made from the GitHub web interface, which can only tag the head of a
branch, so a version overtaken before anyone tagged it stays a
development milestone that names what changed when — the sections below
are their record — and ships inside the next version that does get
tagged. `v0.7.1` is the release that carries those six.

## Unreleased

### Changed
* **A device that refused a read is closed for the rest of the run, in
  the io layer (SPEC N-10).** The medium policy stopped the run at the
  first refusal, and the pool reader refused every later read — but
  only the pool reader. The io layer recorded the incident and went on
  answering reads of the same device, so anything that read a member
  without going through the pool reader (the label reads of a scan,
  the zero-point search, carving) could still reach a disk that had
  just refused, and a unit test pinned that a second read after the
  stop goes through. Now the ledger knows which path the stopping
  incident was on, and every source that is a device answers every
  later read of that path with that incident before touching it —
  memory hits included, so nothing masks a caller still trying. Other
  devices and every image go on being read: the run is over, but the
  report still wants their labels. `--device-may-fail` is unchanged in
  spirit: a skipped refusal closes nothing, the flag exists so that the
  device's other addresses are still read, and the incident that stops
  the run closes it like any stop. Four tests, each failing without
  the gate: the second read after a stop is refused and the device not
  touched; the same path through another handle is closed while
  another device and an image on the same ledger read on; with
  `--device-may-fail` the device stays open until the limit and is
  closed by it; and a real `FileSource` that is a device refuses
  before the read it would otherwise answer.

### Fixed
* **Every run ends the same way, whichever way it failed (SPEC F-33,
  N-10).** The fix below closed the early returns of `dump` and `list`;
  a review of the line found the same door open elsewhere. `zvolfiles
  list`, `objects` and `extract` returned a bare 3 when the MOS or the
  dataset walk failed, with no incident on stderr and no record. And
  when a device refused a *label* read, so that the members never
  opened, every tool printed the incident and exited 7 but wrote no
  evidence record at all. Now the ledger is made once per run, on the
  pool spec, before anything is opened, and one `end_run` closes every
  run — the report of the incidents, the stop as the exit code, the
  record with them — including the runs that failed while opening,
  choosing a pool or a transaction group, or before writing a byte:
  `dump`, `list`, `zvoltimeline`, the three `zvolfiles` commands and
  the four `zvolcarve` commands all go through it. A run that produced
  nothing records that it produced nothing. Checked: in `cargo test`,
  a `dump` of a dataset that does not exist and a `list` at a
  transaction group nobody has both end with their record; in CI on a
  real block device, `zvolfiles list` and `zvoltimeline` on a member
  whose label 0 refuses exit 7 with one incident on stderr and the
  record saying so, and a `scan` of that member still reports the
  other member's labels.
* **A device's refusal on the way to the dataset is exit 7 and an
  incident on record, on a single volume too (SPEC F-33, N-10).** The
  medium policy of v0.9.1 reported a refused read after the run: every
  incident on stderr, the stop as the exit code, both in the evidence
  record. A single-volume `dump` and a `list` never got there when the
  refusal landed on a metadata read — the MOS objset, the dataset tree,
  the volume's dnode: "cannot read the pool" returned early with exit
  3, no `MEDIUM INCIDENT` line, and no evidence record at all, while
  the ledger held the incident and nobody read it. A bulk `-r` run
  reached the report, so the one-volume case was strictly worse. Now
  every early failure ends the way every run ends. Checked in CI on a
  real block device: the eight sectors of the MOS objset mapped to
  device-mapper's error target, `dump` and `list` both exit 7 with the
  incident on stderr and in the record — the block's address taken
  from the reader's own trace, so the test follows the fixture.
* **The dense fixture's indirect pointers count the blocks beneath
  them.** Every pointer the fixture wrote carried `fill = 1`, the
  indirect ones included; ZFS keeps the number of non-hole level-0
  blocks under an indirect pointer there. This tool never reads `fill`,
  so nothing it does changed, but `zdb` reads it and a fixture that
  lies to the cross-check is worse than none. A test builds 2048
  blocks under two levels and checks every pointer at every level.

### Added
* **The direct readers, tested against a closed device.** The io-layer
  gate (above) was shown with `strace` in CI; now a unit test builds a
  member whose first sector refuses, runs the label scan on it as a
  device, and asks what a scan asks next — the partition table, the
  GEOM sector, the anchor search with leave — and finds every one
  refused with the incident and the device read exactly once. And a
  gang header's `asize` is asserted on a mirror and on raidz2, where
  nothing in the read path would notice a wrong one.
* **The four inputs the fuzzer crashed on, committed as seeds.**
  v0.9.0's fuzz commit fixed four panics and kept the crashing inputs
  only under `fuzz/artifacts`, which is ignored; CI had to rediscover
  them inside its thirty seconds. They are under `fuzz/seeds` now,
  named for what they broke — the indirect mapping's address
  arithmetic, a GPT entry's LBA arithmetic twice, a microzap shorter
  than its header — beside the deterministic unit tests that already
  guard each fix.
* **A healthy device asked for its zero point is refused the search,
  with exit 5 — pinned (SPEC N-10).** The labels verify, the pool is
  reported, and `--zero-point` still gets `zero point: not searched`,
  `surface_scan_refused` in the JSON and exit 5: the operator asked
  for a surface search and did not get one, and a script must be told.
  That was the behaviour; the only test covered a device whose labels
  do not verify. Now the CI device job runs it on a real block device
  with verified labels and shows through `strace` that the refusal
  came before any read past the four labels.
* **Smaller guards from the same review.** A read that only partly
  overlaps a remembered window is never served from it, asserted
  rather than assumed; a symlink to a device — `/dev/mapper/NAME`,
  `/dev/disk/by-id/…`, the names an operator types — is refused a
  surface scan like the device itself, by `scan` and by `zvolcarve`;
  and `scan --retries` is refused like `dump --retries`.
* **Gang blocks and remapped blocks on a degraded raidz, tested.** The
  defect v0.9.5 caught before its tag lived on the unverified read
  path — the one a gang header, a block remapped by a vdev removal and
  `read_dva` go through — and it survived every test because the gang
  and removed-vdev fixtures were mirror-only. Now the fixture stripes a
  gang header and a removed vdev's copied blocks onto a raidz layout
  the way ZFS lays them out, and four tests read them back on a 4-wide
  raidz2 with each member missing in turn and with two gone: the gang
  block comes back whole and verified in seven configurations, the
  remapped volume in six, three members gone is a clean error, and a
  silently corrupted column under a gang header is a clean gang error
  while the same damage to a parity column of a healthy row is never
  read — the two halves of the lazy-parity rule, pinned.

## v0.9.5 — 2026-09-20

**The measured release.**
The 512 MiB memory bound and the throughput target had been asserted
and never measured, and zstd was decoded by a pure-Rust crate on the
strength of an assumption. Now every push builds dense 512 MiB volumes,
extracts them and prints the rate and the peak resident set; runs the
reader's own zstd decoder against libzstd on the same blocks; and dumps
one volume twice to check the bytes and the documents come back
identical. The first measurement found its own defect: raidz2 read an
uncompressed volume at a third of the mirror's rate, because every
stripe fetched its parity before anything said it was needed. A healthy
stripe now reads its data columns alone — and a review of the whole
range before the tag caught what that change had broken on the other
read path, a degraded raidz behind a gang or remapped pointer, which is
fixed here and never shipped. Deduplicated volumes are in the
fixtures.

### Changed
* **A healthy raidz stripe is read from its data columns alone.** The
  first measurements (below) showed an uncompressed volume on raidz2
  extracted at a third of the mirror's rate. Two causes, both in the
  striped read: every row fetched its parity columns before anyone
  knew whether they were needed, and the stripe was assembled one byte
  at a time through an iterator. Now the data columns are read first;
  the parity is fetched only for a row that lost a column or, after
  the checksum fails, for the combinatorial reconstruction — as
  OpenZFS reads a healthy stripe, and as a device asks (SPEC N-10):
  half the reads. Both read paths do it — the verified one and the
  unverified one behind `read_dva`, gang headers and remapped blocks —
  and each fetches the parity of a row that lost a column before it
  reconstructs. The assembly copies whole columns. Measured on the same
  volume: about 290 MB/s on raidz2 against about 310 on the mirror,
  from 130; on a quiet machine raidz2 now extracts at the mirror's
  rate, uncompressed, lz4 and gzip alike. Two tests: one counts the
  reads of an extract on a four-wide raidz2 and finds none of the
  parity columns among them; the other reads a pointer through the
  unverified path with each one of the four members missing in turn,
  and checks the reconstructed bytes against the pointer's checksum.

### Added
* **The zstd decoder, measured against libzstd (SPEC §12 Q3, D-8).**
  `tests/zstd-bench.sh` cuts a fixture volume's bytes into 128 KiB
  blocks, compresses them with the `zstd` command, gives each the
  framing OpenZFS gives a zstd block and decodes the lot through the
  reader's own decoder (`zstd-bench`, an example of `zfs-ondisk`),
  every block checked against its original; libzstd's built-in
  benchmark runs on the same bytes. It runs on every push and prints
  one table. Measured: about 400 MB/s for `ruzstd` on one thread
  against about 1 GB/s for libzstd on the fixture text at level 3 —
  more than the media this tool reads deliver, so `ruzstd` stays and
  the question is closed as D-8.
* **A deduplicated volume in the fixtures (SPEC F-28).** `mkfixture …
  dedup` builds the sample pool with `tank/vm/disk0` deduplicated: its
  data pointers carry the dedup bit and sha256 checksums, and
  `dedup=sha256,verify` is set among its properties. There is no
  deduplication table on the pool and none is looked for — a dedup
  pointer is a pointer — so `list --properties` names the property
  and `dump` gives the plain volume's image, byte for byte. Both are
  tests now, in the library and on the command line.
* **Memory and throughput, measured on every push (SPEC N-03, N-08,
  N-05).** Until now the 512 MiB bound and the throughput target were
  asserted and never measured. `mkfixture bench` and `bench-raidz2`
  build a dense volume — every block present under a real indirect
  tree, 128 KiB blocks, of any size, with compression off, lz4 or gzip
  (the fixture gained a compressing `put`) — and print the SHA-256 the
  extracted image must have. `tests/bench.sh` extracts six such volumes
  of 512 MiB and reports, per run, the extraction rate, the rate of a
  plain copy of as many bytes through the same page cache, their ratio,
  and the peak resident set, which `dump` now reports itself
  (`peak_rss_kib`, from `/proc/self/status` on Linux). It fails on a
  wrong hash, on a resident set over 512 MiB, or on a rate under a
  floor; the N-08 ratios are to a disk's read rate and wait for the
  disks of REALWORLD-TESTS E1 and E2, which now say so. Measured here:
  peak resident set about 70 MiB on every volume, and the reader alone
  — output to tmpfs, so the disk is out of it — about 460 MB/s on one
  thread, mirror or single member alike. Reproducibility (N-05) is
  checked the same way: the same volume dumped, scanned and listed
  twice gives identical images and identical documents once `seconds`
  and `peak_rss_kib`, the two fields meant to vary, are set aside.

## v0.9.1 — 2026-09-18

**This tool reads healthy media.**
A data-recovery practitioner read v0.9.0 and saw the danger in it: a
sector a live disk refused was read again in pieces, then by sector,
then again with `--retries`, and a surface scan read a device end to
end. That is what a failing disk survives least. Physical and logical
recovery are separate trades: a disk with defects is imaged first, by a
tool that knows the kind of defect and when to stop, and this tool
works on the image and its map. So now: on a device the first refused
read stops the run with exit 7 and the incident, nothing is read twice
anywhere, surface scans refuse a block device, and `--retries` is gone.
Checked on real block devices in CI — device-mapper's error target on
Linux, `gnop` on FreeBSD — with `strace` proving no address read twice.

### Changed
* **This tool reads healthy media (SPEC N-10, F-33 rewritten).** A
  data-recovery practitioner's reading of v0.9.0: re-reading a sector a
  live disk refused — in pieces, then sector by sector, then again with
  `--retries` — is what a failing disk survives least, and a surface
  scan of one is worse. Physical and logical recovery are separate
  trades: a disk with defects is imaged first, by a tool that knows the
  kind of defect and when to stop, and the metadata is parsed from the
  image. So: on a **device**, the first read it refuses stops the run
  with a new exit code `7`. The incident — device, byte offset and LBA,
  length, `errno`, time, and which volume and block — is on stderr, in
  the JSON (`stopped_by_medium`) and in the evidence record
  (`incidents`), and the message says what to do next: image the disk
  with a map and continue on the image with `--map` and `--resume`.
  Nothing is read twice: no retry, no pieces, no sectors, and not the
  other side of a mirror either — the operator is told first and
  decides. `--retries` is gone. `--device-may-fail` is the one way past
  the first incident: the refused range is skipped once — the mirror
  heals it if it can, else zeros with the incident as the reason — and
  the run stops anyway after eight. On an **image with its map** (F-72)
  nothing changes: the map refuses ranges before they are read, and a
  bad sector still costs only its sector. Checked in CI on a real block
  device: a mirror member on a loop device with eight sectors mapped to
  device-mapper's `error` target stops the run with exit 7 and the LBA;
  with `--device-may-fail` the mirror heals the block and `strace` shows
  no address on the device read twice; on FreeBSD, `gnop -e 5` makes
  the first label read the incident.

* **No address on a device is read twice, anywhere (SPEC N-10).** The
  metadata walk used to come back to the same MOS blocks over and over
  — one block nineteen times in a small dump — and a scan read each
  label twice, then its first and last sectors again for the partition
  table and the GEOM check. The reader now keeps the metadata blocks it
  has read (bounded: small blocks only, dropped whole past 64 MiB), each
  label is read once, and a source answers any read that lies inside a
  recent read from memory. A scan of a device is four reads, one per
  label; a dump of a two-block volume off a mirror member is sixteen,
  none overlapping.

* **Surface scans refuse a block device (SPEC N-10).** The search for
  uberblock anchors when a member's labels are gone (F-61), the root
  search when no uberblock survives (F-64), pointer self-consistency
  (F-63) and carving (`zvolcarve scan`) answer a block device with exit
  `5` and the reason, unless `--surface-scan-on-device` is given. `scan`
  reports it as `zero point: not searched` (JSON `surface_scan_refused`)
  and exits 5 too. Image the disk, and search the image.

## v0.9.0 — 2026-09-18

**Checked, fuzzed, interpreted, signed.**
The audit release, the first of the three tags between v0.8.5 and 1.0.0
(SPEC §10). Nothing the tool reads or writes changes; what changes is
what is known about it on every push. The dependency graph is held to a
licence list and a ban list, and every binary's import table is read
and found to ask for no socket, no exec and no dlopen. Every parser is
fuzzed, and the four panics the fuzzer found on its first run are fixed.
The unit tests of the on-disk parsers run under Miri. And the release
files are signed, keylessly, by the workflow that built them.

### Added
* **What the dependency graph carries, and what the binaries ask their
  platform for, checked on every push (SPEC §8.3 (3), N-07).** The tool
  reads evidence and writes images; it has no business on a network and
  never runs another program. The source said so, and nothing checked
  it. Now `deny.toml` holds the rule for the graph: every licence in the
  tree is a permissive one on the list — the CDDL of the Edon-R port is
  allowed on the `edonr` crate alone, where OpenZFS's files are kept
  apart — no advisory stands against a crate, and the crates that exist
  to open a socket, run a program or load code are named and banned, so
  a dependency that grows one is stopped on the branch it arrives on.
  And every binary the workspace builds — `zvolrescue` and the four
  companions — has a test that reads its ELF symbol tables and fails on
  any of `socket`, `connect`, `execve`, `fork`, `posix_spawn`, `dlopen`
  and their kin, whether imported from the C library on a dynamic build
  or linked in on a static one. The reader is checked against a program
  that does connect and does run a program, so a clean result is known
  to mean something. A source grep for `process::Command` and
  `std::net` runs beside it. Today's binaries import none of it.

* **The parsers are fuzzed on every push (SPEC §9).** Everything in
  `zfs-ondisk` that reads bytes off a disk is now a `cargo fuzz` target
  — a packed nvlist and the label configuration read out of it, a block
  pointer and a gang header, a dnode and an objset header, the three ZAP
  forms, an uberblock slot and a `vdev_phys`, every bonus buffer (space
  map, indirect mapping, DSL directory and dataset, bpobj, deadlist,
  znode, system-attribute header), every decompressor, and a GPT, an
  MBR and a GEOM sector — in both byte orders where the structure has
  one. Each starts from a well-formed seed built with the crate's own
  encoders and read back through the parser before it is committed
  (`fuzz/seeds`, from the example `fuzz-seeds`), and CI runs every
  target for a bounded time under the address sanitizer on a nightly
  toolchain, failing on a panic, an abort or an input that runs past
  the time limit and keeping that input as an artifact. The workspace
  itself stays on stable; the fuzz crate is outside it.

  The first run found four ways to make a parser panic, all on input no
  pool writes and every one of them a crash on a damaged disk: an
  indirect-mapping entry whose destination offset sat at the top of the
  address space overflowed the addition in `remap`, and the sum of
  entry sizes could overflow too; a GPT slot whose LBAs did not fit the
  byte address space overflowed the multiplication, and one spanning
  the whole space overflowed its length by one; and a block whose first
  eight bytes said "microzap" and which ended before its header chunk
  did was sliced past its end. Each now answers as damage — unmapped,
  a skipped slot, a truncated block — with a unit test beside it.

* **Release files are signed (SPEC N-07).** Nobody holds a signing key:
  the release workflow signs `SHA256SUMS` — which covers every binary —
  with a short-lived certificate that Sigstore's Fulcio issues to that
  workflow run against GitHub's OIDC token, and ships the signature,
  the certificate and the transparency-log entry as one bundle beside
  it, `SHA256SUMS.sigstore.json`. The certificate names this
  repository's release workflow and the tag it ran for, and that is
  what `cosign verify-blob` checks; the release notes carry the exact
  line. The workflow verifies its own signature before publishing, so
  a release whose signature does not verify is not published. Each
  binary also gets a GitHub build-provenance attestation — the commit,
  the workflow and the runner that built it — for `gh attestation
  verify`. Nothing changes for `sha256sum -c`.

* **Miri on the on-disk parsers' unit tests, every push (SPEC §9).**
  The workspace forbids unsafe code, so what the interpreter catches is
  in the dependencies the parsers lean on and in the standard library's
  contract as the tests use it: an uninitialised read, an aliasing
  violation, an out-of-bounds access the native build happened to
  survive. The 125 tests of `zfs-ondisk` that run there pass, in five
  and a half minutes on a laptop core. A handful that
  loop over megabytes of pure arithmetic — noise fed to the carver and
  the filesystem signatures, the space-map replay, every RAIDZ loss
  pattern, the dRAID permutation maps, a 1 MiB fletcher — run a tenth of
  their volume there, and the `vdev_phys` round trip, three SHA-256
  passes over 112 KiB that took six minutes interpreted, is skipped
  there; each says so beside its loop, and every one runs in full on
  the native build.

## v0.8.5 — 2026-09-17

**What the disk never gave, and what the disk still says.**
An image's ddrescue map is honoured: sectors the imager could not read
are refused by name, not read as data, and a bad sector on any member
costs its sector rather than its block. A disk's own names — a GPT
label, a `gptid`, a `glabel` — tie a member whose labels are gone to the
leaf its siblings describe, and a member with no anchor at all is found
at the base their `asize` bounds. Three-way mirrors and pools of several
mirrors are fixtures now, and ashift 9 and 13 are cross-checked against
`zdb`.

### Added
* **The imager's map (SPEC F-72), and retries per sector (F-33).** An
  image of a failing disk is made with GNU `ddrescue`, and the mapfile
  beside it is the only record of which bytes the disk actually gave.
  Where it could not read, the image holds zeros that look like data,
  and a block crossing them failed its checksum with nothing to say
  why. `--map MEMBER=MAPFILE` reads the map — its own format, comments
  and status line and hex positions — and every unfinished range is
  refused before it is read, the way a disk refuses a bad sector, so
  the block takes the F-33 path: kept as far as the imager read it,
  zeros for the rest, and the reason names the imager. `scan` reports
  the map per device: bytes never read, by status, and which of the
  four labels the unread ranges touch. The mapfile is hashed into the
  evidence record as an input. And `--retries N` (default 1) reads a
  refused sector that many more times before giving it up, for the
  marginal sector on a live disk that gives on the third try — an
  image file pays nothing for it. Prompted by a Habr write-up of a
  NAND recovery that read every failing page up to 128 times: the
  lesson for a tool that starts from images is that the image's own
  record of what was never read has to be honoured.

* **A member with no anchor at all is found at the base its siblings
  bound (SPEC F-62, the other half).** F-62 could bind a label-less
  member to a leaf by reading through it, but only at a base something
  on the member had confirmed: a surviving uberblock ring, or a
  partition table. Every label gone — rings included — and the member
  somewhere inside a larger image with no table left, and the binding
  tried base 0, read garbage and said nothing reads through it.

  The siblings' labels say how big a leaf of that top is (`asize`, plus
  the labels at both ends), which bounds where its vdev can begin. The
  trial now tries 0 and every 1 MiB multiple that leaves room for such
  a leaf — the first and last 512 of them on a disk large enough to
  have more, since a member is at the front of its disk or its tail is
  at the end — and the base that walks is the one the member is read
  at. Confirmed by the checksums the walk verifies, never assumed, and
  said out loud: `read as leaf … with its vdev at byte N`. The fixture
  can now write a real `asize` for it.

* **Fixtures for a three-way mirror and for a pool of two mirrors.**
  Both shapes were read before — a mirror is any number of sides, and
  a pool is any number of top-level vdevs — but only `ztest` ever
  produced them, by chance: a side attached during its run, a vdev
  added. Now `mkfixture mirror3` builds the widened mirror and
  `mkfixture striped` a pool whose MOS is on `mirror-0` and whose
  volume's data is on `mirror-1`, three leaves wide, so that a read
  has to cross tops to finish. Every push checks: any one side of the
  three-way mirror is a whole copy; the damage-matrix shape (one side's
  labels gone, another absent, the third describing the pool) binds the
  bare side by reading (F-62) and the volume comes out; the two-mirror
  pool reads with one side of each; and with every member of `mirror-1`
  gone the MOS still lists the volume while its blocks are refused by
  the name of the top nothing describes — zeros with the reason, exit 4
  — because a member's label describes only its own top-level vdev,
  which is how ZFS labels work and what makes that top unrecoverable
  without `--hints`.

* **A bad sector costs its sector, not its block (SPEC F-33).** A disk
  with one unreadable sector refuses the whole 8 KiB read that touches
  it, and with no other copy `dump` wrote 8 KiB of zeros — 7.5 KiB of
  which the disk would have given. The real-world matrix had carried
  "read per sector on EIO — to implement" since it was written.

  A read a member refuses is now read again in 4 KiB pieces and, inside
  a piece that still fails, sector by sector; what comes back is kept
  and only the refused sectors are zeros. Each zeroed sector is its own
  range in `bad`, `blocks_salvaged` counts the blocks it happened to,
  and the exit code is 4 as for any image with zeros in it. What was
  kept is unverified — the checksum covers the whole block and part of
  it is gone — and the range's reason says so, because a forensic
  report that called those bytes verified would be lying.

  Only what can be kept in part is: an uncompressed, unencrypted block
  on a disk or mirror. A compressed block cannot be decompressed in
  part, ciphertext cannot be decrypted in part, and under raidz or
  dRAID a partial column is reconstructed rather than kept, so those
  are zeroed whole as before, with the reason naming which. A mirror
  still heals from its other side first, and nothing is salvaged that
  could be read whole; a read that fails once and then gives every
  sector counts only if its checksum then agrees. Tested against a
  source that refuses reads touching given ranges the way a disk with
  bad sectors does; the read error a mirror reports also stopped
  saying "no present member" about a member that is present and
  failing.

* **The names a disk gives itself tie a bare member to its leaf (SPEC
  F-71).** On FreeBSD a member is usually handed to ZFS as
  `/dev/gpt/NAME`, `/dev/gptid/…` or `/dev/label/NAME`, and the pool's
  labels record that string as the member's `path`. `scan` already read
  the GPT partition name and did nothing with it; the partition's own
  GUID and `glabel`'s metadata were not read at all. Now every device
  lists the names its disk carries — GPT name and GUID, and any GEOM
  class in the last sector of the device or of a partition — and where
  a pool has a vacant leaf whose recorded `path` is one of those names,
  the scan says which device that is and spells out the
  `--assume-member` that binds it. The binding is still confirmed by
  reading, exactly as F-62 does: the name says what the disk was
  called, not what is on it. A name that merely contains a pool's name
  (`tank-spare` beside `tank`) is a hint and binds nothing.

  Two more things fall out of reading the GEOM sector. The metadata
  records the size of the provider it sits on, and ZFS was given one
  sector less than that and placed its rear labels against *that* end —
  so a member whose size the sector carries across a 256 KiB boundary
  now shows all four labels instead of three. And a `geli` provider is named as
  encrypted rather than reported as a disk with no ZFS on it.

  Checked on FreeBSD 15 in CI with the real tools: `gpart add -l` and
  `glabel label` on `md` devices, the GUID read back equal to what
  `gpart list` prints, and the volume out of the labelled member equal
  to the volume out of the plain one.

* **The ends of the ashift range, against `zdb`.** The fixtures were
  already built at ashift 9 and 13 as well as 12 (CI step "Every
  ashift"), but the cross-check against OpenZFS userland ran every
  geometry at 12. Two more `ztest` pools — raidz2 at ashift 13 and a
  mirror at 9 — now go through the same thirteen steps as the others,
  so the stride that decides whether a RAIDZ column read lands on the
  right sector is compared against `zdb` at both ends and not only at
  the middle. The real-world matrix rows say 9, 12 and 13 accordingly.

## v0.8.0 — 2026-09-16

**A vdev that is gone, a dataset's own settings, and what a hash is for.**
A pool a top-level vdev was removed from now reads, through the mapping
the removal left in the MOS, and a feature this build cannot account for
stops the read by name instead of letting it guess. `list --properties`
shows what a dataset was written with, user properties included. `dump
--hash md5,sha1` takes the legacy digests in the same pass as SHA-256
and `zvolreport verify` checks every digest a record carries back.
`zvolcarve zeropoint` and `zvolcarve roots` give two more ways into a
pool nothing points into. And an image `dump` had to fill with zeros is
exit 4, not a success.

### Added
* **`dump --hash md5,sha1`: the legacy digests, taken in the same pass
  (SPEC F-53).** An extracted image usually leaves for somewhere else,
  and what is waiting there may be an acquisition log, a
  case-management system or a hashset that only speaks MD5 or SHA-1.
  Taking one afterwards costs another full read of a multi-terabyte
  image, so the moment to take it is while the bytes are going past —
  which is what the requirement said and what half of it had been doing
  for SHA-256 alone.

  Neither is offered as a check on whether the image is *right*. Both
  have practical collision attacks, which matters when someone may have
  chosen the bytes and does not matter for lining an image up against a
  record written before this tool touched it. That is what they are
  for, and the module says so where someone might otherwise reach for
  one as a verifier.

  What was taken goes into the evidence record, into the report, and
  into `zvolreport verify`, which now checks **every** digest a record
  carries rather than only its SHA-256 — one result per digest, with
  the file read once for all of them. A hash that is written down and
  never checked back is decoration.

  `zvolcarve dump` takes the same flag: it writes images too.

  Checked against the tools a forensic toolchain would actually use:
  `sha256sum`, `sha1sum` and `md5sum` agree with all three on a real
  32 MiB sparse image, the published RFC 1321 and FIPS 180 vectors are
  unit tests, and a resumed extraction feeds the prefix into each
  digest so that stopping and continuing comes to what one pass would
  have. One byte changed in a finished image, and all three say so.

* **`list --properties`: what a dataset has set, user properties
  included (SPEC F-14).** The properties ZAP was parsed as far as its
  object number and never read. It holds what an operator holding a
  dead pool most wants next after the dataset list: what `compression`
  and `checksum` this volume was written with, what `recordsize` it
  used, and whatever the shop's own bookkeeping put in a user property.

  **Only what was set here is on disk.** A property nobody set is
  inherited from an ancestor or is the pool's default, and neither is
  written down anywhere — so this reports what the dataset holds and
  says so, rather than computing an effective value out of a table of
  defaults that no disk would confirm. The ancestors are in the same
  listing, which is where an inherited value comes from.

  **A number keeps its number unless the build can show its working.**
  `checksum` and `dedup` carry the same `zio_checksum` enumeration a
  block pointer carries, which this tool already decodes on every block
  it reads and the cross-check compares against `zdb`. `compression`
  carries a `zio_compress` code in its low seven bits with a `zstd`
  level above them — and that split was measured, not remembered:
  across the five pools the cross-check builds and two more with vdevs
  removed, nineteen distinct values appear, and every one either fits
  in seven bits (on, lzjb, zle, lz4) or has exactly `16` — zstd — in
  them with 1..=19 or 100..=120 above. Nothing else produced a high
  part at all. Everything else — `copies`, `recordsize`, every on/off
  flag — prints the number the pool holds, because a name this build
  cannot evidence would be worse than the number.

  Checked against `zdb` on a real `ztest` pool: twenty properties over
  eight datasets, name for name and value for value, with an empty
  `diff`. In CI a fixture volume carries two of ZFS's own properties
  and a user property — which forces a fatzap, since a microzap entry
  is one 64-bit integer and cannot hold a string at all — and the
  listing is compared in both text and JSON. Asking is what separates
  "none set" from "not asked": without the flag no properties are read
  at all, and with it a dataset that set none shows an empty list.

* **A pool a top-level vdev was removed from now reads (SPEC F-69).**
  `zpool remove` does not free what was on a vdev: it copies those
  blocks onto the vdevs that remain and leaves in its place an
  `indirect` vdev holding nothing but a record of where each range of
  its old address space went. The block pointers are never rewritten —
  that would mean walking every pointer in the pool — so they go on
  naming a vdev that no longer exists, and every one of them was
  refused: `DVA names unknown top-level vdev 3`. It came up three times
  in one afternoon on `ztest` images that happened to have had a vdev
  removed during the run, which is what put it at the top of the list.

  That mapping is now read and the addresses translated. A range the
  removal copied in pieces is several entries and is joined back
  together; a piece that landed on a vdev itself removed later is
  followed through that one too, which real pools do — `ztest` produced
  one with three removed vdevs where one maps onto another. Where the
  destination is a mirror, each of its sides is still offered as a
  separate copy, so redundancy survives the translation.

  **The mapping comes from the pool's own account of itself, not from
  the labels.** No label describes a removed vdev: removing it is what
  took its members away. What does describe it is the configuration
  object in the MOS — and reading it there rather than anywhere else is
  also what keeps an older transaction group honest. Asked for a txg
  from before the removal, the configuration of *that* txg has no
  indirect vdev in it, and nothing is translated, because at that point
  nothing had been.

  `scan` asks rather than guesses. A removed vdev is still counted in
  `vdev_children` and still has no member to find, so from the labels
  alone it is a missing vdev — and a first version of this said exactly
  that, calling a pool with every live member present "NOT readable" in
  the summary line and `readable: false` in the JSON a script keys on.
  Now `scan` asks the pool's configuration object which undescribed
  vdevs were removed, only when there is one to ask about and
  `device_removal` is active (a healthy pool never opens its MOS for
  this), and reports them as removed with the pool readable. When the
  MOS cannot be reached it says so and leaves them missing, which they
  may well be. The same answer reaches `--assume-member`, which no
  longer counts a vdev that is gone on purpose against the leaf being
  bound.

  `com.delphix:device_removal` moves to the features this build honours
  and `com.delphix:obsolete_counts` deliberately does not. The counts
  are bookkeeping over the same mapping, and a pointer that still names
  the removed vdev is live whatever they say — but no pool measured
  against this build has had that feature active, and F-70's rule is
  that nothing is honoured here on reasoning alone.

  Checked against `zdb` on two real `ztest` pools with vdevs removed
  mid-run, one with three and one with four: the mapping objects match
  entry for entry and byte for byte, and every object comes out — 343
  of 343 and 279 of 279, with nothing refused. In CI a fixture whose
  volume is addressed entirely on a removed vdev extracts to the same
  sha256 as the same volume on a pool that never had one, and the same
  blocks are refused by name when the mapping is not loaded, so the
  test is of the translation and not of the fixture.

* **A feature this build cannot account for now stops the read (SPEC
  F-70).** The last way left for this tool to be confidently wrong, and
  the only one no checksum catches.

  A label lists under `features_for_read` the read-incompatible features
  that are *active* — the pool itself saying what a reader must
  understand. That list was parsed, printed behind `-v`, and then
  ignored. So a pool using a feature this build has never implemented
  was read as though it were not using it. For most features that is
  merely incomplete. For `raidz_expansion` it is silently wrong: the
  group was widened and its rows reflowed, so the original geometry
  reads *other* blocks, and their checksums agree with themselves.
  Nothing in the tool objected, and nothing could have.

  Every run that reads blocks now checks that list and refuses the pool
  when anything on it is unaccounted for, naming each one and saying
  whether it is known-and-unimplemented — with what goes wrong — or
  simply unknown to this build. `scan` reports the same thing and never
  refuses: surveying a disk is its job, and it says so unprompted rather
  than behind `-v`. `--ignore-unknown-features` reads anyway and states
  what that costs.

  The list of features this build honours is deliberately evidenced
  rather than asserted: each entry is either carried by the pools the
  cross-check compares against `zdb` block for block, or implemented by
  a named module of this workspace. A name misspelled in it costs a
  refusal on a pool that could have been read — recoverable, and the
  operator is told how. A name wrongly added would cost a silent wrong
  answer, which is the thing being fixed.

* **`zvolcarve zeropoint`: where the vdev begins, from the pointers
  alone (SPEC F-63, COMPANIONS C-21).** The last row of the bare-device
  case, and the one the spec had left optional. Every other route to the
  base needs something that survived — a label, a partition table, a
  sibling's configuration, an uberblock, or the operator's own knowledge
  of the layout. This is the case where none of that is left.

  What is still there is that ZFS describes its own blocks. A pointer
  gives a position, a size and a checksum, and the position is relative
  to the vdev's allocatable space — so the pointer is a test of any
  candidate base: assume `B`, read at `B + 4 MiB + offset`, see whether
  the bytes hash to what the pointer said. Candidates step by the
  alignment the pointers themselves imply, since every allocation is a
  multiple of `1 << ashift` and so every offset is too. The salted
  algorithms are left out of the probes on purpose: their salt lives in
  the MOS, which cannot be read until the base is known, so using one
  would be circular.

  **The spec's claim about this was too strong and is corrected with
  it.** It said a wrong base passes no check. A wrong base can pass a
  few: shifting it lines a pointer up with a *different* block of
  identical content, and a sparse member is mostly zeros — the fixture
  used here has 17,379 identical blocks in it. So the answer is reported
  as agreements out of probes read rather than as a yes or a no. On a
  `ztest` pool with all four labels gone and the member 2 MiB into a
  larger image, the true base agreed with 46 of 64 probes and each of
  the five other candidates with exactly 1, which is a distinction an
  operator can act on and a boolean would have thrown away.

* **A file's project id is reported where the dataset keeps one
  (COMPANIONS Z-10).** `ZPL_PROJID` is the last of the feature-flag
  attributes Z-10 named, and the only one still missing. `zvolfiles`
  now carries it into the listing and the manifest. Absent and zero are
  kept apart and always will be: a dataset made before the
  `project_quota` feature has no such attribute at all, while one made
  after it puts every file in project 0 unless told otherwise, so
  printing the first as zero would invent a project nobody set. The
  field is simply not there when there is nothing to say.

  The fixture's attribute numbers, while this was being added, stopped
  claiming to be OpenZFS's. They never were checked against a header,
  and they do not need to be: an attribute's number is whatever that
  dataset's registry ZAP says it is, and this reader resolves every
  attribute through that registry by name, which is how ZFS itself
  works. The comment now says that instead of asserting something
  nobody had verified.

* **`zvolcarve roots`: the MOS when no uberblock survives (SPEC F-64,
  COMPANIONS C-20).** Every other way into a pool starts at an
  uberblock — it carries the root pointer, the root pointer names the
  MOS, and the MOS names everything else. With all four label rings
  gone there is no root pointer anywhere, and until now that was the end
  of the road: `list` exits 3 and says no verified uberblock matches.
  `roots` scans raw space for the MOS's own `objset_phys_t`, in plain
  blocks and inside compressed ones alike.

  Finding a header is cheap; believing one is not. So every header found
  is *used*: the DSL is walked from it, and what ranks a candidate is
  how much of the pool came out, with the birth of its pointers to
  separate the ones that walked equally well. A header that yields
  nothing is still reported, with the reason it gave — "found but
  unreadable" and "not found" are different answers to an operator. The
  ranked list goes to `roots.json` in the workspace.

  The test is specific enough to be cheap: an objset header begins with
  its meta-dnode, so the first 512 bytes must parse as a dnode of type
  `DMU_OT_DNODE` before anything after them is read, and only
  `DMU_OST_META` is collected — a filesystem's or a volume's objset is
  reached *through* the MOS, so one found loose says nothing about where
  the root is. Checked in CI against a fixture whose every uberblock
  ring has been zeroed, with the ordinary path required to fail first so
  the case cannot pass for the wrong reason; and against a real
  `ztest` pool, where it walks out twelve datasets with no uberblock
  involved at any point.

  Reading a block the header points at still needs a layout, because a
  block pointer addresses a DVA and only the layout says where a DVA is.
  Where the labels are gone too, that comes from `--hints` (F-65), which
  `roots` takes like every other command; without it the header is
  reported with its position and birth and the reason it could not be
  followed.

### Fixed
* **`dump` exited 0 on an image it had just filled with zeros.** When a
  block could not be read, the run wrote zeros in its place, printed a
  warning, listed the range and recorded it in the evidence log — and
  then exited `0`. A caller that reads `dump || handle_failure`, which
  is how this tool gets used in a script, was told the volume had been
  recovered.

  `zvolcarve dump` had answered `4` in the same situation all along,
  saying "either way the image is not the whole volume: say so with the
  code, not only in the report". Two tools disagreeing about the same
  fact is one of them being wrong, and the spec was on the wrong side:
  it reserved `4` for `--strict`. Both now exit `4` whenever blocks were
  written as zeros, `--strict` or not, and the spec says so. `--strict`
  is unchanged: it still aborts at the first unreadable block.

  Nothing that could read the volume changes. A mirror that heals from
  its other side, a raidz2 missing two members, a corrupted member
  rebuilt from parity — all still exit `0`, because nothing was zeroed;
  checked on the fixtures CI uses. The damage matrix learned the code
  too, so an incomplete image is named rather than reported as an
  unexplained exit.

* **The real-world test matrix said three implemented things were
  pending (docs/REALWORLD-TESTS).** It is the checklist someone works
  through before trusting this tool on a customer's disks, and it told
  them that whole-disk GPT vdevs *needed* F-06, that `skein` and `edonr`
  were *pending* F-21, and that an encrypted volume was *phase 3* and
  exited 64 without a key. All three landed months ago — the same
  document's own Results table records the runs that proved it, a few
  screens further down — and a tester reading the criteria column would
  have skipped those rows or recorded a false expectation. Nothing
  returns exit 64 any more: the constant survives only so that a future
  unimplemented command can use it.

  The two markers that are still true stay: packaging, and reading per
  sector on EIO, which is genuinely not implemented.

  Four scenarios added for what has landed since the matrix was written:
  a pool a vdev was removed from (F-69, which `ztest` reaches only by
  chance and a real kernel does on demand), `list --properties` against
  `zfs get -s local` (F-14), a pool carrying a feature this build does
  not implement (F-70), and `dump --hash md5,sha1` against `md5sum` and
  `sha1sum` (F-53).

* **The damage matrix called a dataset lost to damage a tool defect.**
  `data-zeros-two-members-same-range` zeros every written byte on two
  leaves of a mirror. On a `ztest` pool that came out three leaves wide,
  enough survived to list thirteen datasets and refuse the blocks naming
  the fourteenth — which is exactly right — and the harness recorded it
  as breakage, because it compared the list against `zdb` on the
  *undamaged* pool and any difference was a defect.

  The oracle knows every dataset the pool had *before* the damage. Damage
  that takes every copy of the blocks naming one takes the dataset with
  them, and the tool not listing it is the same refusal seen one level
  up — the walk says so in the line above. This is the mistake the
  `CLEAN_REASONS` list exists to stop, one level higher, and it is fixed
  the same way: the dataset list is judged after the blocks, and a
  missing dataset is a refusal when the walk refused and a defect when it
  did not. A dataset the tool *invented*, or one whose creation TXG it
  read differently from `zdb`, stays a defect however much else was
  refused: those come from bytes it did read and got wrong.

  Nothing in the tool changed. The same pool and the same damage judge
  the same at the commit before this run's three features as at its head,
  and the verdict turns on how wide `ztest` happened to build the mirror
  — which is what that job's own preamble says it must never enforce.

  The decision is now a table with a doctest beside it, run in CI, since
  the case that matters most needs a mirror wider than two leaves to
  reach and no run can be relied on to produce one.

## v0.7.5 — 2026-09-13

**What it cannot read, it no longer guesses at.** Extended attributes
that lived in a spill block were lost without a word; the second slot of
a large dnode could be read as an object that was never there; the
manifest wrote text and hex into one field and could not say which; and
`--assume-member` reported nothing missing when a whole top-level vdev
was. Every one of those was a plausible answer. Each is now either read
properly or refused by name. FreeBSD 15.x becomes the first-class
target, and the damage matrix runs on every push instead of when someone
remembers it.

### Changed
* **FreeBSD 15.x is the first-class target; 14.x is best-effort; 13.x is
  dropped.** CI's blocking FreeBSD job now builds and tests on the
  newest 15.x, and a second job does the same on 14.x without being
  allowed to hold anything up — `stable/14` is supported upstream until
  November 2028, so a break there should be visible, not fatal. 13.x
  left support in April 2026. Both jobs ask for `15` and `14` rather
  than a point release, so a new one does not need this repository
  edited; a branch the runner does not ship fails the job instead of
  quietly falling back.
* **The published FreeBSD binary is a 15.x binary.** FreeBSD keeps its
  ABI within a major branch and changes it between majors, so one file
  cannot be both. It is built on 15.x and the release notes say so; on
  14.x the build from source is `pkg install rust && cargo build
  --release`, and the suite passes there. CI had been pinned to 14.2,
  which has been out of support for some time.
* **An extended attribute's value in `manifest.json` is now `value` or
  `value_hex`, never one under the other's name (COMPANIONS Z-04).**
  The manifest wrote a value as text when it was text and as hex when
  it was not, in the same field and with nothing to say which — so
  `deadbeef` in the record was a four-byte value and an eight-character
  value at once, and a recovery reading it back could not tell. A value
  that is text is now in `value` and one that is not is in `value_hex`,
  exactly one of the two present. A reader that asks for `value` and
  finds nothing is missing something loudly, which is the outcome to
  prefer over being handed hex it takes for text. `bytes` is unchanged
  and still the length on disk. Names have no such pair: an attribute
  name that is not UTF-8 loses its exact bytes in the nvlist long
  before the manifest, and nothing here can recover them.

### Added
* **`zvolfiles` reads the attributes that did not fit the bonus buffer
  (COMPANIONS Z-10).** A system-attribute layout too large for a dnode's
  bonus is split by OpenZFS: what fits stays there and the rest goes to
  the spill block, under a header and a layout of its own. Until now
  only the bonus half was read, and the half in the spill block was lost
  without a word — an extended attribute of any size is the usual thing
  to go there, so a file with attributes came out looking like a file
  with none. Both halves are now placed and merged. A spill block that
  cannot be read, or that is not a system-attribute buffer, is an error
  naming the object, because the bonus half on its own looks like a
  complete answer and is not one.
* **A dnode that owns more than one slot is walked as one object
  (COMPANIONS Z-10).** `large_dnode` dnodes were already parsed across
  the slots they own; what was missing was a way to enumerate an array
  containing them without reading a bonus buffer as the next object's
  header. `DnodeArray::next_object` steps by what the dnode owns. The
  fixture now carries both cases — a file whose attribute spilled and a
  file two slots wide — and CI asserts both come out of `zvolfiles`
  whole, through the binary and into the manifest.
* **A device is not an image, and the record now says which (SPEC
  F-68).** Every run records, per input, whether it was a regular file
  or a device, and says once when any input is a device — not because
  anything here writes to one, but because the next tool the operator
  reaches for does. `zvolreport` carries it into the report and warns
  there too, so a reader can tell whether a recovery was done against
  copies or against the disks themselves. On FreeBSD a raw disk is a
  character device and counts the same. Checked in CI against a real
  read-only loop device, not only against a fixture.

### Documented
* **SPEC §4.1: what the operator has to do, which the tool cannot do for
  them.** Being read-only by construction is worth little on its own,
  because the next tool reached for — `zpool import -F`, a filesystem
  repair — does write. So the spec now carries the procedure: stop
  writes to the originals first, image them and work from the copies,
  and where there is no room to image, put a write shim underneath.
  FreeBSD 14's `gunion(8)` is written up with the part that bites —
  uncommitted changes are discarded when the union is destroyed, so
  `commit` comes before `destroy` — with the device-mapper `snapshot`
  target named as the Linux equivalent. Uberblocks, the vdev
  configuration and metadata integrity fail independently and are
  checked separately. Experiments belong in a throwaway machine with the
  copies attached, not near the originals. F-68 asks the tool to say
  whether each input is a device or an image, and to record it; it is
  implemented in this same release, above.
* **`ashift` is a test axis, and now a covered one (SPEC §9).** It sets
  the stride of every DVA offset and of the RAIDZ column layout, so an
  error there is the difference between reading the right sector and a
  neighbour's — and every fixture in CI was built at 12. CI now builds
  the mirror and raidz2 fixtures at 9 and 13 as well, requires the label
  to report the `ashift` the pool was made with (an image that came out
  right while the number was read wrong would mean the number is not
  being used), and extracts from a raidz2 at 9 with two of four members
  absent, where the column stride has to be right for parity to
  reconstruct anything. All five produce the image the walked extraction
  pins.

### Fixed
* **The CHANGELOG had two `## Unreleased` sections, and the release
  notes would have carried only the first.** The release workflow takes
  the open section by reading from its heading to the next `## ` — so a
  second heading of the same name does not add to the notes, it cuts
  them short, and four entries under the second one would have gone
  into a release describing changes it does not mention. Merged into
  one. CI now refuses any repeated `## ` heading in either CHANGELOG,
  and checks that the two languages have the same number of sections,
  so one cannot file something the other does not.
* **The damage matrix runs on every push (SPEC §9).** It found two real
  defects in the tool in one afternoon and then only ran when someone
  remembered to run it. A subset now sits in CI: one geometry, ten
  manifests — one per damage class, plus the cases that caught those
  defects — built and judged in about five minutes. The full matrix over
  three geometries stays a manual run.

  It asserts what is true whatever shape the pool came out: that the tool
  never failed in a way the harness cannot account for, and never wrote
  to the evidence it was reading. It does *not* judge the redundancy
  verdicts, because it builds its own pool and a freshly built `ztest`
  pool is a different experiment every time — ztest attaches and detaches
  devices as it runs, so a two-way mirror comes out two, three or four
  leaves wide; it removes vdevs, leaving an `indirect` top whose blocks
  no member describes; and it makes datasets with `checksum=off`. Three
  identical commits got three different answers out of the same manifest
  before this was understood, and all three were the tool behaving
  correctly. Those verdicts belong to the full matrix, which runs against
  the published image whose layout is recorded beside it.
  `tests/golden/build-ztest-image.sh` takes `POOLS` so the build can be
  one geometry instead of three.

  Two things the first version of this job got wrong are fixed with it.
  `run-matrix.py` exits non-zero on a defect, and under `bash -e` that
  killed the step before anything printed *which* case defected or why —
  a check that fails without saying why is the one thing this job exists
  to prevent; its exit is now captured and judged after the report has
  had its say, and the report is uploaded whatever the verdict. And a
  failed decompression is no longer called a tool defect when the block
  had `checksum=off`: that classification rested on "reached only after a
  checksum agreed", which is not true when ZFS was told not to keep one.
  Damage there is undetectable by construction and failing to decompress
  is the only signal there can be.

* **`normalization` is applied when matching a path (COMPANIONS
  Z-09).** A dataset created with `normalization=formD` matches a name
  however it was spelled, so a file stored composed is found by its
  decomposed spelling and the other way round — the case a macOS client
  and a Linux one create between them. It is the *last* thing tried: the
  bytes first, then case folding where `casesensitivity` says so, then
  this, each only when the one before found nothing. That order is the
  point. Folding and normalizing read a name as text and compare it with
  this build's Unicode tables, while ZFS matched with its own, frozen
  long ago; ahead of an exact match that disagreement could pick the
  wrong file, behind one the worst it can do is leave a file unfound,
  which is what happened before.

  The property is a bit set and is read by its bits, with a value whose
  bits name no form treated as no normalization rather than guessed at.
  Nothing here has seen one on a real pool — `ztest` makes no such
  dataset — so the decoding is pinned against the constants in
  `u8_textprep.h` and says so. The fixture for it is a second one,
  because a real dataset cannot be both: `normalization` requires
  `utf8only`, and `utf8only` forbids the `café.txt` the first fixture
  holds as Latin-1.

* **A closed pipe was still a failure where the report is written into
  a sink.** The panic hook added in v0.7.1 covers `println!`, which is
  how four of the five programs write. `zvoltimeline` builds its report
  into an explicit writer, so a closed pipe arrived as an `Err` and came
  out as `zvoltimeline: writing the report: Broken pipe (os error 32)`
  with exit 1 — the same lie in a different shape. It ends quietly with
  0 now, like the others.

  Two things about how this was found are worth keeping. CI's check
  piped into `head -2`, which is a race: when the tool finished writing
  before `head` left, no `EPIPE` happened and the case proved nothing.
  It now also uses a reader that leaves at once, which makes the failure
  certain rather than occasional. And the one earlier red run whose
  cause was never established was this: the check was written so that a
  failure killed the step before it could say what failed, which is
  fixed too.

* **`--assume-member` said nothing was missing when a whole top-level
  vdev was.** A leaf slot exists to be filled because some present
  member's configuration names it; a top-level vdev that nothing present
  describes has no slots at all, so a member cannot be asserted into one
  — its geometry is unknown and there is nothing to check the assertion
  against. Refusing is right; "no scanned pool is missing a member" was
  not, and the labels contradict it, since they carry `vdev_children`.
  The refusal now names the vdev and points at what does help: a member
  of it whose labels survive, or `--hints` (SPEC F-65). It also exits 2
  rather than 1 — the command line was well formed and the operator's
  assertion was sound; what is short is the evidence. `scan` already
  printed the unaccounted vdev on its own line, and still does.

  Found by the damage matrix in
  [zvolrescue-testdata](https://github.com/click0/zvolrescue-testdata),
  which had no other way to say what was wrong with that case.

## v0.7.1 — 2026-09-11

**A closed pipe is not a failure.** One fix, found by running the
binaries a release actually hands out rather than the ones in `target/`.

### Fixed
* A closed pipe stopped being a crash. `zvolcarve list DIR | head -4`
  closes the pipe while the tool is still writing, and Rust turns the
  `EPIPE` into a panic: a backtrace on stderr and exit 101, for an
  operator who did nothing wrong — quitting `less` half way down a
  candidate list did the same. A write that fails for that one reason
  now ends the run with 0 and says nothing, in all five programs. Every
  other panic still reaches stderr with its message; the check that
  tells them apart is on the errno rather than on the words beside it,
  which belong to whatever locale is set. Found by downloading the
  v0.7.0 build and running it, which nothing in CI had done.

## v0.7.0 — 2026-09-11

**Everything the companion spec asked for.** Every requirement
COMPANIONS marks as worth having is implemented, and the numbers to
check them by are in CI. Nothing in the companion tables is left
outstanding but two rows marked *could*.

### Added

* **`zvolcarve` asks the allocator (COMPANIONS C-06).** Every metaslab's
  space map is replayed into a set of ranges, and each block a candidate
  claims is asked about: the space is either still given out or
  released. Neither is a verdict on the data — the checksum is, and
  ranking already reads every block — so it does not move a candidate's
  score. What it adds is the difference between *rewritten* and *freed
  but not yet rewritten*: data that verifies today and may not tomorrow.
  The answer lags, because the pool keeps recent allocations in log
  space maps not yet flushed into the metaslabs, and the report says so.
* **`zvolcarve` reads what a volume holds, and takes its size from it
  (SPEC F-43, COMPANIONS C-12).** A carved dnode says how many blocks an
  object has, which is not how large the volume was made — a volume
  whose tail was never written has fewer. What is inside it usually does
  say: nearly every filesystem writes a superblock near the front
  carrying the size it was made for. ext2/3/4, swap, XFS, btrfs, NTFS
  and FAT32 give a size; UFS2, LUKS, a GPT and a nested ZFS label are
  recognised without one, because a guess with no number is honest and
  an invented number is not. `dump` prefers `--size`, then the size the
  contents state, then what the dnode implies, and says which it used.
* **`zvolfiles` gives a file back the name it had (COMPANIONS Z-09).**
  A dataset with `utf8only=off` may hold a name that is not UTF-8 — on
  Linux a file name is any byte string without `/` or NUL — and decoding
  one into replacement characters silently renames the file, which a
  forensic extraction must not do. The bytes are now carried from the
  directory ZAP through the walk to the output, a path is matched on the
  bytes, and `--path` takes the operating system's own argument rather
  than text. What is printed stays text, with `path_hex` alongside it
  wherever printing lost something. The fixture holds `café.txt` as a
  Latin-1 machine wrote it, and CI checks it comes out under those bytes
  and is not found under the text it prints as.
* **A report can be signed, and checked without this tool (COMPANIONS
  R-07).** `zvolreport build --sign KEY` signs the exact bytes of
  `report.json` with Ed25519 and leaves the raw 64 bytes beside it;
  `zvolreport verify --key KEY.pub` checks them, and `zvolreport keygen`
  writes a pair. The keys are the form OpenSSL writes and reads —
  unencrypted PKCS#8 and SubjectPublicKeyInfo, PEM or bare DER — so a
  third party with no copy of `zvolrescue` can check a report with
  `openssl pkeyutl -verify -pubin -inkey key.pub -rawin -in report.json
  -sigfile report.json.sig`. CI checks both directions against OpenSSL.
  The signature is checked before the document is parsed, because an
  edited report often stops being JSON and "not a report" is a poor way
  to say "this was changed"; a wrong key, an edited value, an appended
  byte and a missing signature each exit 4.
* **`zvolcarve` tries four compressions, not one (COMPANIONS C-10).**
  Metadata is stored compressed, and a pool made before the
  `lz4_compress` feature stores it in lzjb — so a scan that tries lz4
  and nothing else finds no dnodes on such a pool at all, which looks
  exactly like a member that never held any. `scan` now tries lz4, lzjb,
  gzip and zstd by default; `--compressed` takes a subset, or `none` for
  the plaintext pass alone, and refuses an unrecognised name with exit 1
  rather than quietly dropping it. Each codec is asked first whether the
  bytes could be its own, so only lzjb — which has no header — pays a
  full decompression attempt at every offset.
* `zvoltimeline --pending` now also reads what each deadlist's own
  objects come to, and says whether that agrees with the running total
  the deadlist keeps. The pool maintains the two independently, so a
  disagreement is this reader's fault rather than the pool's.
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

* A deadlist's total now follows the block-pointer objects filed under
  its own. `bpo_bytes` covers only the pointers an object holds itself;
  one that has swallowed another — which is how deadlists are merged —
  keeps that other's space in its own header, so stopping at the parent
  undercounts. Caught by the check above on the first `ztest` pool that
  produced the case, and pinned by a fixture that fails without it.
* A deadlist named by more than one dataset is counted once. Nothing in
  CI had produced that case; the check above is what would have caught
  it.
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
