# Real-world test matrix

**Ukrainian version:** [REALWORLD-TESTS.uk.md](REALWORLD-TESTS.uk.md)

What has to be run on real systems before `zvolrescue` is trusted on a
customer's disks. CI covers synthetic fixtures and userland pools from
`ztest`; everything below needs a machine (or VM) with a real kernel ZFS,
real block devices and the distribution's own `zdb`.

Status legend: ☐ not run · ◐ partial · ☑ passed · ✗ failed (link the issue).

## Environments

| Env | Why it matters | ZFS build | Notes |
|---|---|---|---|
| **mfsBSD** (FreeBSD rescue image, RAM-resident) | The realistic rescue medium: no disk to install on, tool must be a static binary copied over the network | FreeBSD base OpenZFS | statically linked `zvolrescue`; `mdconfig` for images; no `ztest` |
| **FreeBSD 14.x** | primary target (SPEC N-06) | base OpenZFS 2.2 | `lang/rust` from ports/pkg; `zdb`, `ztest` in base |
| **FreeBSD 15.x** | next release, newer feature flags | base OpenZFS 2.3+ | expect `raidz_expansion`, `fast_dedup`, `longname` feature flags |
| **Debian stable** | most common Linux host with `zfs-dkms`; the cheapest real kernel: loop devices in a VM | zfs-dkms 2.2 (12 bookworm), 2.3 (13 trixie: `raidz_expansion`) | `apt install zfsutils-linux zfs-dkms`; loop devices; scripted — see [Running on Debian with zfs-dkms and loop devices](#running-on-debian-with-zfs-dkms-and-loop-devices) |
| **Ubuntu LTS** | ships ZFS in-kernel, common on hosts | zfs 2.2/2.3 | the CI cross-check runs here already (userland only) |
| **CachyOS** (Arch-based) | bleeding-edge kernel and OpenZFS git; catches new on-disk features first | OpenZFS latest | `zfs-dkms` or `linux-cachyos-zfs`; `zstd`/`blake3` defaults common |

## Scenarios

Run every scenario on every environment; record `zvolrescue --version`,
`zfs version`, kernel, and attach `--debug-log` for failures.

### A. Read-only guarantees

| # | Scenario | Pass criterion |
|---|---|---|
| A1 | `scan`/`list`/`dump` against a raw block device (`/dev/ada0p3`, `/dev/sdb2`) while the pool is **exported** | Device unchanged (compare `sha256` of the first and last 4 MiB before/after); `zpool import` still works |
| A2 | Output path on the evidence device (`-o /dev/…` or a file on a filesystem living on the input) | exit 5, nothing written |
| A3 | Run as an unprivileged user with read access to the device | works; no privilege needed |

### B. Layouts

| # | Pool | Pass criterion |
|---|---|---|
| B1 | single disk, ashift 9, 12 and 13 | `list -r` == `zdb -d`; `dump` == `sha256` of `/dev/zvol/...` |
| B2 | mirror-2, one member absent | same, from the remaining member |
| B3 | raidz1 (3), raidz2 (4, 6), raidz3 (7) | same with `nparity` members absent |
| B4 | raidz with one member silently corrupted (`dd` over 1 MiB in the middle) | `dump` heals it, reports rebuilt blocks in `--debug` |
| B5 | pool with 2+ top-level vdevs, mixed mirror + raidz | same |
| B6 | pool with a `log` and a `cache` vdev | `scan` lists them; `dump` unaffected |
| B7 | dRAID (`draid2:8d:1s`), also with 1–2 members removed and with a distributed spare active | `list` matches `zpool list -t all`; `dump` hash matches |
| B8 | pool after `zpool attach`/`detach`/`replace` (stale labels on old disks) | `scan` shows the old member with an older txg and does not mix it in |
| B9 | whole-disk vdevs with GPT (Linux `-part1`, FreeBSD `p1`) | `scan` of the whole disk finds the ZFS partition (F-06/F-60; the cross-check covers it on `ztest` members, this covers a real partition table) |
| B10 | FreeBSD members given by name — `gpart -l` labels (`/dev/gpt/NAME`), `gptid`, `glabel` (`/dev/label/NAME`) — one member's labels zeroed | `scan` lists the names off the disk, names the vacant leaf the bare member's name matches and the `--assume-member` for it; the GUID equals `gpart list`'s `rawuuid`; a `glabel`'d member shows all four labels and dumps bit-exact (F-71; CI does this on `md` devices, this covers real disks and a pool the kernel made) |

### C. Data properties

| # | Property | Pass criterion |
|---|---|---|
| C1 | `compression=off,lz4,zstd,zstd-19,gzip-1,gzip-9,lzjb,zle` on the volume | `dump` hash matches for each |
| C2 | `checksum=fletcher2,fletcher4,sha256,sha512,skein,edonr,blake3` | matches for each; all seven verify on `ztest` pools already (see Results), so what this adds is a kernel-written pool |
| C3 | `volblocksize=4K,8K,16K,64K,128K,1M` (needs `large_blocks`) | matches |
| C4 | sparse volume with holes, `zfs create -s -V 100G`, 1 GiB written | image is sparse, `du` small, hash matches |
| C5 | `dedup=on` volume with repeated content | matches |
| C6 | volume with snapshots and a clone; `dump` of `vol@snap` and of the clone | each matches its own hash |
| C7 | encrypted volume (`encryption=aes-256-gcm`) with `--key raw:FILE` | matches with the key; without one every ciphertext block is refused as `encrypted: no key` and nothing is reported as verified |
| C8 | large dnodes (`dnodesize=auto`) on the parent filesystem | `list` unaffected |
| C9 | pool with 100+ datasets, deep nesting, long names (`longname` on FreeBSD 15) | `list -r` complete, matches `zdb -d` |
| C10 | `zpool remove` a top-level vdev, then export (F-69) | `list`/`dump` read the blocks that still name the removed vdev and match `zdb`; `scan` says the vdev is counted but has no member. `ztest` reaches this only by chance — a real kernel does it on demand, which is the point of running it here |
| C11 | `zfs set` several properties, including a user property (`org.example:ticket`), on a volume and on its parent (F-14) | `list --properties` reports exactly what `zfs get -s local` reports for that dataset — no more, since inherited values are not on disk, and no less |
| C12 | a pool whose active `features_for_read` include one this build does not implement (`raidz_expansion` on FreeBSD 15 / OpenZFS 2.3) (F-70) | `list`/`dump` refuse with exit 3 and name the feature; `scan` says so without refusing; `--ignore-unknown-features` reads and states the cost |

### D. Recovery

| # | Scenario | Pass criterion |
|---|---|---|
| D1 | `zfs destroy vol`, export immediately | `list --diff` shows it destroyed; `dump` recovers from the previous txg, hash matches |
| D2 | `zfs destroy vol`, then keep writing 500 MiB elsewhere, export | either recovered from an older txg still in the ring, or a clean "not found at any of N txgs", or — when the MOS of an older txg survived but the volume's blocks were reused — a partial image with every lost block zeroed and counted (exit 4) |
| D3 | `zpool destroy pool` | `scan` shows state DESTROYED; `list`/`dump` still work |
| D4 | pool that does not import (`zpool import` → "I/O error") after zeroing labels L0/L1 on one member | `scan` uses L2/L3; `dump` works |
| D5 | pool whose newest uberblock is damaged (zero the slot) | `list` uses the previous verified txg and says so |
| D6 | interrupt `dump` with SIGINT at ~50 %, then `--resume` | exit 6 with `interrupted_at` in the output and the evidence record, the state file naming that block; after `--resume` the final hash matches and `resumed_from_block` > 0 (F-32; CI does this on a 512 MiB fixture, this does it on a kernel-written pool) |
| D7 | `dump -r pool/vm` with 5 volumes | 5 images + manifest, hashes match |
| D8 | `dump --hash md5,sha1` of a volume (F-53) | the three digests printed equal `sha256sum`, `sha1sum` and `md5sum` of the written image; all three land in the evidence record and `zvolreport verify` checks each |

### E. Scale and packaging

| # | Scenario | Pass criterion |
|---|---|---|
| E1 | 2 TB volume on a 4-disk raidz2 of HDDs | throughput ≥ 40 % of raw read (SPEC N-08); RSS ≤ 512 MiB. *Interim, in CI on every push (`tests/bench.sh`): 512 MiB dense volumes on a raidz2 of files, compression off/lz4/gzip — peak RSS about 70 MiB, rate printed against a plain copy; the ratio to a disk waits for the disk.* |
| E2 | 200 GB volume on NVMe mirror | throughput ≥ 70 % of raw read. *Interim, in CI: the same on a mirror of files; the reader itself runs at several hundred MB/s single-threaded to tmpfs, so the NVMe target will need the worker pool N-08 allows.* |
| E3 | static binary built on Ubuntu runs on mfsBSD (FreeBSD) — *no*, needs a FreeBSD build; verify the FreeBSD static build runs on mfsBSD 14 and 15 | `zvolrescue --version` and a `scan` |
| E4 | `pkg`/ports build on FreeBSD; `.deb` on Debian/Ubuntu; AUR on CachyOS | installs, `man zvolrescue` present (*packaging pending*) |

### F. Hardware

Different controllers and drives change what a "read" means; the tool
must never rely on the device's sector size or on the pool's `ashift`
matching it.

| # | Scenario | Pass criterion |
|---|---|---|
| F1 | 512n, 512e (4 KiB physical / 512 logical) and 4Kn drives, pools with `ashift=9`, `ashift=12` and `ashift=13` on each | `scan` reports the pool's `ashift`, reads use the label geometry only; hashes match on all nine combinations (the cross-check covers 9, 12 and 13 on `ztest` pools against `zdb`; this covers real sector sizes) |
| F2 | Same pool images read through a USB/UAS bridge that translates sectors (4K↔512), and directly | identical output; if the bridge changes the apparent device size, `scan` still finds L2/L3 via the size the OS reports |
| F3 | HBA in JBOD/IT mode (LSI/Broadcom, Adaptec) vs. the same disks on onboard AHCI | identical output |
| F4 | RAID controller exposing a passthrough/"single-disk RAID0" volume with metadata at the disk end | `scan` finds the four labels at the *reported* device size or warns which labels are missing |
| F5 | NVMe (several vendors), SATA SSD, SAS | identical output; throughput per E1/E2 |
| F6 | SMR (shingled) HDD vs. CMR | identical output; long sequential reads do not time out; note throughput |
| F7 | Drive with known bad sectors (or `dm-flakey`/`dm-error` on Linux, `gnop -e 5 -r 10` on FreeBSD injecting EIO) under a mirror | `dump` **stops at the first refused read** with exit 7, naming the member, the byte offset and LBA, the length and the `errno`, and the evidence record carries the incident; no address on that device is read a second time (checked by tracing the reads). With `--device-may-fail` the mirror heals the range from the other member and the run goes on, still without a re-read, and stops by itself after 8 incidents. On a `ddrescue` image of that device with its map, the unreadable *sectors* are zeroed and the rest of each block kept, each as its own `bad` range, `blocks_salvaged` counts them and the exit code is 4 (F-33, F-72, N-10; unit-tested against a source that fails per sector) |
| F8 | Reads on a drive with 4 KiB logical sectors when the pool is `ashift=9` (created on 512e, moved to 4Kn) | reads succeed (buffered I/O); `--debug` shows unaligned offsets handled |
| F9 | Virtual disks: bhyve/QEMU virtio-blk with 512 vs 4096 logical, VMware, Hyper-V; `.img`/`.qcow2`-backed (raw only) | identical output |
| F10 | Disk larger than 2 TiB and 16 TiB (GPT, offsets above 32/64-bit sector limits) | labels found at the correct end offsets |

### G. Golden image and damage matrix (SPEC §9.1)

Built once in a real-kernel VM by a script, then immutable; damage is
applied to temporary copies from manifests. Every run is judged against the
recorded oracle and lands in one of: bit-exact / reconstructed (visible in
the evidence log) / refused cleanly (exit 3) / tool defect.

| ID | Scenario | Expected |
|---|---|---|
| G0 | Interim image without a kernel: `tests/golden/build-ztest-image.sh` (ztest + zdb) — three pools (mirror, raidz2, draid1), real metadata, no zvols; runs judged by walking every object against `zdb -d` | image + oracle in `zvolrescue-testdata`; the matrix runs with no defects |
| G1 | Build the golden image with `tests/golden/build-image.sh` in a real-kernel VM: one pool with mirror + RAIDZ2 + dRAID1 top-level vdevs, zvols of several block sizes, snapshots, clones, renamed/destroyed volume and snapshot, encrypted datasets (raw key, passphrase), every checksum/compression, gang blocks, large dnodes, hundreds of TXGs; record the oracle | image + oracle published in `zvolrescue-testdata` with SHA-256 |
| G2 | Single damage classes (labels, partition, metadata, data, missing member, older-self member) on each geometry | every run in an expected category; no tool defects |
| G3 | Pairs and triples of classes across members and geometries | as G2; the expected category derived from ZFS redundancy for the combination |
| G4 | Held-out combinations run only before a release | as G2 |
| G5 | Read-only invariant on every run | input copies' hashes unchanged |

How to run: build the image once with `tests/golden/build-image.sh OUT` in a real-kernel VM, publish `OUT/release` and `OUT/oracle` in `zvolrescue-testdata`, then `tests/golden/run-matrix.py --image OUT/members --oracle OUT/oracle --manifests <testdata>/manifests --tool ./target/release/zvolrescue` (add `--held-out` before a release). The report lands in `golden-report/report.md`.

## Running on Debian with zfs-dkms and loop devices

The cheapest environment with a real kernel ZFS, and the first one to
run: a Debian VM with `zfs-dkms`, pools the kernel itself makes on loop
devices. A loop device is a block device as far as the tool is concerned
(SPEC N-10: `kind: device` in the record, the first refused read stops
the run, no surface scan without `--surface-scan-on-device`), so
everything the device policy promises is exercised here, on pools whose
every byte OpenZFS wrote. What it cannot give is a disk: E1/E2 (a read
rate relative to a disk), F1–F6 and F8–F10 (sector sizes, controllers,
bridges) stay ☐ until a machine with drives runs them.

`tests/realworld/debian-loop.sh` does the whole run: builds the pools,
takes every oracle from OpenZFS (`sha256sum /dev/zvol/...` before export,
`zdb -d`, `zdb -lu`, `zfs get -s local`), exports them, runs the tool
against the loop devices, and prints the row for the Results table.

Setting up (Debian 12 or 13, `contrib` enabled; a VM with 2 CPUs, 2 GiB
of RAM and 8 GiB of free disk is enough):

```
apt install linux-headers-$(uname -r) zfsutils-linux zfs-dkms dmsetup strace python3 openssl
modprobe zfs
cargo build --release
sudo bash tests/realworld/debian-loop.sh /var/tmp/rw ./target/release/zvolrescue
```

`zfs-dkms` builds the module for the running kernel, so the headers have
to match it (reboot into the kernel the headers are for, first); with
Secure Boot on, the unsigned module will not load. The work directory
must be reachable by the user `nobody` (A3 runs the tool as that user
with read access to the two devices and nothing else), which `/var/tmp`
is and a home directory usually is not. The script refuses to start if a
pool named `zrw*` is imported, creates only such pools, and removes its
loop and device-mapper devices on exit; nothing it does touches another
pool.

What each scenario becomes on loop devices:

| Scenario | How it is built | What is compared |
|---|---|---|
| A1, G5 | the first and last 4 MiB of every loop device hashed before the tool runs and after; every pool imported with `-N` and exported again at the end | hashes equal; every import succeeds |
| A2 | `dump -o /dev/loopN` onto an input | exit 5 |
| A3 | `runuser -u nobody` with `chmod o+r` on the two mirror members | `list -r` succeeds |
| B1 | three single-disk pools at `ashift` 9, 12, 13 | `list -r` = `zdb -d` (names and creation TXGs); image SHA-256 = the kernel's |
| B2 | mirror-2, the tool given one member | same |
| B3 | raidz1 of 3, raidz2 of 4, raidz3 of 7, the tool given `nparity` fewer members | same |
| B4 | 1 MiB of `/dev/urandom` at 8 MiB into one raidz2 member | image matches; the `--debug-log` shows the reconstruction |
| B5 | mirror + raidz1 in one pool, also with one member of each absent | same as B1 |
| B6 | mirror with a `log` and a `cache` device | `scan` of all four exits 0; `dump` from the two data members matches |
| B7 | `draid1:2d:5c:1s`, also with one member absent | same as B1 (skipped if this `zpool` builds no dRAID) |
| B8 | attach a second member, export, copy the original to another loop device, import, `detach` the original | `scan` of the copy and the survivor lists the copy under `stale` and only the survivor under `devices`; `dump` from both matches the pool after the detach. The copy stands in for a disk pulled before the detach: `zpool detach` erases the labels of the device it detaches |
| B9 | a whole loop device (`losetup -P`) given to `zpool create`, which writes the GPT itself | `scan` finds the GPT and the ZFS partition; `dump` from the whole disk and from `-p1` both match |
| C1–C3 | one volume per value: 8 compressions, 7 checksums, 6 block sizes | each image matches the kernel's hash |
| C4 | `zfs create -s -V 1G`, 64 MiB written at 300 MiB | matches; the image is sparse (`du` under 200 MiB) |
| C5 | `dedup=on`, four copies of the same 4 MiB | matches |
| C6 | two snapshots and a clone of one volume | the head, each snapshot and the clone match their own hashes (`snapdev=visible` for the kernel's side) |
| C7 | `encryption=aes-256-gcm`, `keyformat=raw` | matches with `--key raw:FILE`; without one, a non-zero exit and `encrypted block: no key` |
| C8 | `dnodesize=auto` on the parent | matches |
| C9 | 100 datasets, 12 levels deep, one 80-character name | `list -r` = `zdb -d` |
| C10 | two single-disk tops, `zpool remove` the second, then write more | `scan` says `removed_tops: [1]`; `list` and `dump` match |
| C11 | `org.example:ticket` and `compression` on a filesystem and a volume | the set of (dataset, property) from `list --properties` equals `zfs get -s local`; `volblocksize` is left out on the tool's side, since the kernel writes it into the property ZAP at creation but `zfs get` shows its source as `-` |
| C12 | `zpool attach` a fourth member to a raidz1 (OpenZFS 2.3) | `list` exits 3 naming `raidz_expansion`; `scan` exits 0; `--ignore-unknown-features` reads. Skipped on 2.2 |
| D1 | `zfs destroy`, export at once; the TXG before from `zdb -u` | `list --diff` shows it under `destroyed_since`; `dump --txg` matches |
| D2 | `zfs destroy`, then 500 MiB written elsewhere over six TXGs | either the hash matches from an older TXG, or exit 3 with `not found at any of N verified TXG(s)`, or exit 4 with `blocks_zeroed` counted |
| D3 | `zpool destroy` a single-disk pool | `scan` says `state: DESTROYED`; `dump` matches |
| D4 | L0 and L1 zeroed after export | `scan` reports L0/L1 `missing` and L2/L3 `ok`; `dump` matches; whether the kernel still imports it is noted (expected to, since ZFS reads all four labels) |
| D5 | the newest uberblock slot, found with `zdb -lu`, zeroed in all four labels | `list` reports the previous TXG; `dump` matches the last state |
| D6 | SIGINT once the image has passed 128 MiB of 512 | exit 6, `interrupted_at` set, the state file names that block; `--resume` gives `resumed_from_block` > 0 and the kernel's hash |
| D7 | `dump -r` of the eight C1 volumes | eight images named after their datasets plus `manifest.json`; every hash matches |
| D8 | `--hash md5,sha1` | the three digests equal `sha256sum`, `sha1sum`, `md5sum` of the image |
| F7 | `dm-error` over 8 sectors at the first data block of a volume (its DVA from `zdb -dddddd`, plus the 4 MiB of labels) under one mirror member | exit 7 and `MEDIUM INCIDENT … (LBA n, …)`; the evidence record carries the incident with `stopped: true`; `--device-may-fail` heals from the other member, hash matches, one incident not stopped; `strace` shows no address on the device read twice |
| R | `zvolreport build` over every run's evidence, then `verify` | verifies |

The row it prints (`WORKDIR/row.md`) goes into Results below; the
per-scenario lines are in `WORKDIR/results.txt`, the tool's output of
every run in `WORKDIR/out/`, and the evidence log of the whole session in
`WORKDIR/evidence.jsonl`. A failure is a tool defect until shown
otherwise: file it with the `out/*.log` and `out/*.err` of that scenario.

## Results

Append one row per run.

| Date | Env | ZFS | zvolrescue | Scenarios | Result | Notes / log |
|---|---|---|---|---|---|---|
| 2026-09-06 | Ubuntu 24.04 (CI, userland `ztest` only) | 2.2.2 | `429b79e` | B1 B2 B3 B5 (labels, MOS, DSL, RAIDZ reads) | ☑ | `tests/crosscheck-ztest.sh` |
| 2026-09-06 | Ubuntu 24.04 (CI, userland `ztest` only) | 2.2.2 | `b3929a7`+ | C1 (every block of every object walked, `walk-objects`) | ☑ zstd | Real OpenZFS zstd blocks are *magicless* frames with the level in the header's top byte — fixed. Still open: encrypted datasets (checksum truncation for `BP_USES_CRYPT`), `skein`/`edonr`, `noparity`. |
| 2026-09-07 | Ubuntu 24.04 (CI, userland `ztest` only) | 2.2.2 | `8ccf9be`+ | C1 + encrypted datasets (`walk-objects`) | ☑ | Checksums of encrypted-dataset blocks now verify (MAC words ignored, fletcher folded); ciphertext blocks report "encrypted: no key" instead of a false mismatch; `noparity` = `off`. Still open: `skein`/`edonr`. |
| 2026-09-07 | Ubuntu 24.04 (CI, userland `ztest` only) | 2.2.2 | `52991e9`+ | C1 `skein` (`walk-objects`, `mirror` pool) | ☑ | 6 skein blocks and a skein objset verify with the pool salt; the `mirror` walk is now clean apart from ciphertext (no key). Open: `edonr`. |
| 2026-09-07 | Ubuntu 24.04 (CI, userland `ztest` only) | 2.2.2 | `124978c`+ | C1 `sha512` (7 fresh ztest pools, raidz1 of 2 files) | ☑ after fix | `sha512` words are stored in the writer's native order (like blake3/skein), not big-endian like `sha256`; every sha512 block failed before the fix. Fixture-only testing could not catch this. All 8 pools now walk clean. |
| 2026-09-07 | Ubuntu 24.04 (CI, userland `ztest` only) | 2.2.2 | `936d51c`+ | C1 `edonr`; B (leftover attach/replace device in the directory) | ☑ | First edonr block met on the 10th fresh ztest pool: verifies. Pool 7 had a `txg 0` label of a device ztest was attaching: assembler now sets it aside (`scan` shows NOT USED) instead of mis-assembling the pool. |
| 2026-09-07 | Ubuntu 24.04 (CI, userland `ztest` only) | 2.2.2 | `5d06443`+ | C (encrypted datasets: metadata) | ☑ | `list` reads the DSL crypto key ZAP and key properties of every encrypted ztest dataset; suite, key GUID, encryption root, keyformat and version match `zdb -dddd` of the crypto key object (step 4 of the crosscheck script). |
| 2026-09-07 | Ubuntu 24.04 (CI, userland `ztest` only) | 2.2.2 | `7b88116`+ | C (encrypted datasets: key unwrap) | ☑ | ztest's raw wrapping key opens every encryption root of 3 pools (aes-128/192/256, GCM and CCM, key version 1); a key differing in one byte is refused. Step 5 of the crosscheck script. |
| 2026-09-07 | Ubuntu 24.04 (CI, userland `ztest` only) | 2.2.2 | `3a4f756`+ | C (encrypted datasets: decryption) | ☑ | With ztest's key every encrypted block of 3 pools decrypts (aes-128/192/256, GCM and CCM; data, ZAP and dnode blocks; lz4/lzjb/zstd/off under encryption) and every dataset's object count equals its objset fill. Found on the way: `dmu_ot` marks other-ZAP, zvol-prop, znode, master-node and FUID-size objects as authenticated only, not encrypted. `dump --key` wiring checked (no key / wrong key / right key / prompt). |
| 2026-09-07 | Ubuntu 24.04 (CI, userland `ztest` only) | 2.2.2 | `4e89a07`+ | B7 dRAID (draid1 4d:6c:1s, draid2 5d:9c:2s) | ☑ | Datasets match `zdb -d`; every block of every object verifies, with all members and with any 1 (draid1) or 2 (draid2) members left out; a member with 2 MiB of garbage is reconstructed around. Found on the way: dRAID parity runs over the whole group width, so the empty trailing columns of a short row shift the Q/R evaluation. |
| 2026-09-08 | Ubuntu 24.04 (CI, userland `ztest` only) | 2.2.2 | `2ba88b2`+ | C (gang blocks of encrypted datasets) | ☑ after fix | CI's random draid2 pool had a gang block in an encrypted dataset: its header carries the *folded* checksum (`zio_checksum_handle_crypt`), which the reader now expects; ztest `-g 8192` keeps gang blocks in two crosscheck pools. |
| 2026-09-09 | Ubuntu 24.04 (CI container, userland `ztest` only) | 2.2.2 | `26de61d` | G0, G2 (damage matrix on the interim image) | ☑ | First damage-matrix run: 17 applicable cases across mirror, raidz2 and draid1 pools, all passed, no defects, inputs unchanged. 46 cases not applicable because each ztest pool carries one geometry. Two manifest expectations corrected (MOS copy needs parity on raidz; scattered bit flips may hit free space). Report in `zvolrescue-testdata/reports/image-v0-ztest`. |
| 2026-09-10 | Ubuntu 24.04 (CI container, userland `ztest` only) | 2.2.2 | `0996534` | G0, G2, G3 (damage matrix with combinations) | ☑ | Matrix grown to 37 manifests (22 single-class, 15 combinations, 3 held out): 111 runs over the three pools, **99 applicable, all passed, 0 defects**, inputs unchanged (12 n/a: mirror 8, draid1 4). The combinations exposed three wrong assumptions in the harness, not in the tool: (1) the rear label pair sits at `align_down(size, 256K) − 512K`, not at "the last 512 KiB" — on a member of 130 489 457 bytes the naive range started 203 KiB past L2, so that damage class had been quietly missing its target; (2) ztest members are sparse (56 MiB written of 128 MiB), so damage aimed at a nominal offset often landed in a hole — ranges are now resolved over allocated extents (`data:`) or an absolute span anchored to the smallest member (`span:`); (3) dRAID's parity budget is per redundancy group, not per vdev, so a draid1 with 3 groups of 16 children keeps most rows readable after two member losses. Report in `zvolrescue-testdata/reports/image-v0-ztest`. |
| 2026-09-10 | Ubuntu 24.04 (CI container, userland `ztest` only) | 2.2.2 | `ba2d4ad`+ | F-61 (zero point from uberblocks) on 5 fresh ztest pools | ☑ | Step 9 of the crosscheck: with all four `vdev_phys` areas of a member zeroed, the base is still confirmed by 126 uberblock checksums in all five pools, and the same member moved 1 MiB along reports base 1048576 with the vdev's original size from its rear labels. Found on the way: ztest leaves behind devices it was attaching whose labels carry `txg 0` and an uberblock template with **no embedded checksum at all** — nothing to anchor to, and the tool correctly reports no zero point instead of inventing one; the step now picks a member that belongs to the committed pool. |
| 2026-09-10 | Ubuntu 24.04 (CI container, userland `ztest` only) | 2.2.2 | `5b4a366`+ | Moved member read through its recovered base (5 ztest pools + mirror fixture) | ☑ | Step 10 of the crosscheck: a member shifted 1 MiB along, labels intact, walks every block of every object identically to the unshifted pool in all five geometries. On the fixture, `list` and `dump` of a member moved 3 MiB give the same datasets and the same image SHA-256 as before the move. The trigger had to be "no label whose checksum verifies", not "no label that parses": a member moved by a whole number of labels still presents a parsable rear-label nvlist at base 0, sealed with an offset it is no longer at. |
| 2026-09-10 | Ubuntu 24.04 (CI container, userland `ztest` only) | 2.2.2 | `6c7437a` | G0, G2, G3 on a rebuilt interim image, with F-61/F-62 in play | ☑ | 105 runs over three pools: **94 applicable, all passed, 0 defects**, inputs unchanged (11 n/a). Two damage classes now have to be *answered* rather than survived: a member shifted 2048 sectors while another is absent reads bit-exact on a two-way mirror (it used to be a refusal — F-61 puts the shifted member back), and a member whose four `vdev_phys` areas are zeroed while another is absent comes back on raidz2 and draid1 once the manifest asserts it belongs (F-62). Both exposed tool fixes, not manifest fixes: `--assume-member` returned a usage error where the honest answer is unreadable evidence, and it refused where several vacant leaves read equally well, which cost the recovery for nothing. |
| 2026-09-10 | Ubuntu 24.04 (CI container, userland `ztest` only) | 2.2.2 | `c08dc5d`+ | F-65…F-67, F-06/F-60 on 5 fresh ztest pools | ☑ | Crosscheck steps 11 and 12: a member placed inside a GPT partition of a whole-disk image walks every block identically to the bare member in all five geometries (the partition's length matters as much as its start — read to the end of the disk instead, a member finds only two of its four labels); and with **every label configuration of every member erased**, a layout given by hand lists the same datasets as `zdb` in all five, including the nested mirror-of-raidz shapes ztest builds and the dRAID pools. The layouts are built mechanically from `scan -f json`, whose `tree` is now emitted in the shape `--hints` takes. |
