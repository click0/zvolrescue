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
| **mfsBSD** (FreeBSD rescue image, RAM-resident) | The realistic rescue medium: no disk to install on, tool must be a static binary copied over the network | FreeBSD base OpenZFS | statically linked `zvolrescue`; `mdconfig` for images; no `ztest`. **Run**: mfsBSD 14.2 (the newest image published; there is no 15) booted from its ISO under QEMU/KVM, the `mfsbsd` job of `realworld.yml`, `tests/realworld/mfsbsd.sh`; the row is in Results |
| **FreeBSD 14.x** | primary target (SPEC N-06) | base OpenZFS 2.2 | `lang/rust` from ports/pkg; `zdb`, `ztest` in base. **Run**: 14.5-RELEASE as a VM in `realworld.yml` (the `freebsd` job), md devices, on demand; the row is in Results |
| **FreeBSD 15.x** | next release, newer feature flags | base OpenZFS 2.3+ (2.4.2 in 15.1) | expect `raidz_expansion`, `fast_dedup`, `longname` feature flags. **Run**: 15.1-RELEASE as a VM in `realworld.yml`, md devices, on demand — every scenario of the script applies, C12 included; the row is in Results |
| **Debian stable** | most common Linux host with `zfs-dkms`; the cheapest real kernel: loop devices in a VM | zfs-dkms 2.3.9 (13 trixie: `raidz_expansion`), 2.1.11 (12 bookworm) | `apt install zfsutils-linux zfs-dkms`; loop devices; scripted — see [Running on Debian with zfs-dkms and loop devices](#running-on-debian-with-zfs-dkms-and-loop-devices). **Run**: Debian 13 and 12 as QEMU/KVM guests in `.github/workflows/realworld.yml`, on demand; the rows are in Results |
| **Ubuntu LTS** | ships ZFS in-kernel, common on hosts | zfs 2.4.1 (26.04), 2.2.2 with a 2.3 module (24.04) | the CI cross-check runs here already (userland only). **Run**: the same script on the `ubuntu-26.04` and `ubuntu-24.04` runners' own kernels and in-tree modules, the first job of `realworld.yml`; the rows are in Results |
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
| C7 | encrypted volume (`encryption=aes-256-gcm`) with `--key raw:FILE` | matches with the key; without one the run is refused before a block is read (exit 1), naming the suite and the key formats it takes, and nothing is written |
| C8 | large dnodes (`dnodesize=auto`) on the parent filesystem | `list` unaffected |
| C9 | pool with 100+ datasets, deep nesting, long names (`longname` on FreeBSD 15) | `list -r` complete, matches `zdb -d` |
| C10 | `zpool remove` a top-level vdev, then export (F-69) | `list`/`dump` read the blocks that still name the removed vdev and match `zdb`; `scan` says the vdev is counted but has no member. `ztest` reaches this only by chance — a real kernel does it on demand, which is the point of running it here |
| C11 | `zfs set` several properties, including a user property (`org.example:ticket`), on a volume and on its parent (F-14) | `list --properties` reports exactly what `zfs get -s local` reports for that dataset — no more, since inherited values are not on disk, and no less — with two exceptions the kernel keeps outside the property ZAP: `volsize` lives in the volume's own object (`zfs get` calls it local, the ZAP does not have it) and `volblocksize` the other way round (in the ZAP at creation, source `-` to `zfs get`) |
| C12 | a pool whose active `features_for_read` include one this build does not implement (`raidz_expansion` on FreeBSD 15 / OpenZFS 2.3) (F-70) | `list`/`dump` refuse with exit 3 and name the feature; `scan` says so without refusing; `--ignore-unknown-features` reads and states the cost. *Passed on pools three kernels expanded: FreeBSD 15.1 (OpenZFS 2.4.2), Ubuntu 26.04 (2.4.1) and Debian 13 (2.3.9), `kernel-matrix.sh`.* |
| C13 | a pool whose gang headers are the vdev's smallest allocation — `com.klarasystems:dynamic_gang_header`, OpenZFS 2.4, active from the first gang write that needed more than three children; a fragmented pool on 2.4 has it | `scan` names the feature as implemented; `dump` reads both kinds of header the pool holds — the 4 KiB ones written after the feature went active and the 512-byte ones from before — and the image is the kernel's. *Found by the golden image (G1): built with ganging forced on Ubuntu 26.04's OpenZFS 2.4.1, it was refused whole by v0.9.8, which did not know the feature. Passed on Ubuntu 26.04 (2.4.1) and FreeBSD 15.1 (2.4.2), `kernel-matrix.sh`; skipped where the feature does not exist.* |
| C14 | two single-disk tops, a volume written, then `zpool remove` of the second and export, with a TXG from before the removal still in the ring (F-69) | `dump --txg` of that TXG reads every block the removal copied and says the TXG is from before it (`removed_since`); a block rewritten before the removal is zeroed and named as not in the mapping, and reads once the removed disk is named among the members |
| C15 | `zpool checkpoint`, then `zfs destroy` of a volume and enough writes for the ring to go round (F-10, T-01) | `list` names the checkpoint's TXG (`checkpoint_txg`), `list --txg` of it has the volume, `dump` of the volume without `--txg` finds it there and matches the hash taken before the destroy; `zvoltimeline` has a `checkpoint` event and the volume last seen at it; all of it agrees with `zdb -k` |

### D. Recovery

| # | Scenario | Pass criterion |
|---|---|---|
| D1 | `zfs destroy vol`, export immediately | `list --diff` shows it destroyed; `dump` recovers from the previous txg, hash matches — or, when the export's own few txgs already reused a block of the freed volume, a partial image that is the kernel's bytes with exactly the lost blocks zeroed and counted (exit 4) |
| D2 | `zfs destroy vol`, then keep writing 500 MiB elsewhere, export | either recovered from an older txg still in the ring — exit 4 when a newer txg named it and did not read, passed over and said — or a clean "not found at any of N txgs", or — named at a txg whose object set the writes reused and readable at no older one — a clean exit 3 saying so, or — when the MOS of an older txg survived but the volume's blocks were reused — a partial image with every lost block zeroed and counted (exit 4) |
| D3 | `zpool destroy pool` | `scan` shows state DESTROYED; `list`/`dump` still work |
| D4 | pool that does not import (`zpool import` → "I/O error") after zeroing labels L0/L1 on one member | `scan` uses L2/L3; `dump` works |
| D5 | pool whose newest uberblock is damaged (zero the slot) | `list` uses the previous verified txg and says so |
| D6 | interrupt `dump` with SIGINT at ~50 %, then `--resume` | exit 6 with `interrupted_at` in the output and the evidence record, the state file naming that block; after `--resume` the final hash matches and `resumed_from_block` > 0 (F-32; CI does this on a 512 MiB fixture, this does it on a kernel-written pool) |
| D7 | `dump -r pool/vm` with 5 volumes | 5 images + manifest, hashes match |
| D8 | `dump --hash md5,sha1` of a volume (F-53) | the three digests printed equal `sha256sum`, `sha1sum` and `md5sum` of the written image; all three land in the evidence record and `zvolreport verify` checks each |

### E. Scale and packaging

| # | Scenario | Pass criterion |
|---|---|---|
| E1 | 2 TB volume on a 4-disk raidz2 of HDDs | throughput ≥ 40 % of raw read (SPEC N-08); RSS ≤ 512 MiB. *Interim, in CI on every push (`tests/bench.sh`): 512 MiB dense volumes on a raidz2 of files, compression off/lz4/gzip, and on a mirror with blocks of 4 and 8 KiB as well as 128 — peak RSS about 70 MiB, rate printed against a plain copy; the ratio to a disk waits for the disk.* |
| E2 | 200 GB volume on NVMe mirror | throughput ≥ 70 % of raw read. *Interim, in CI: the same on a mirror of files; the reader itself runs at several hundred MB/s single-threaded to tmpfs, so the NVMe target will need the worker pool N-08 allows.* |
| E3 | the FreeBSD static build, built on 15, runs on 15 and on 14 (a Linux build does not: the FreeBSD binary is its own) | `zvolrescue --version`, a `scan`, a `dump` whose hash matches the one taken on 15. *Answered twice. In CI on every push: the job "FreeBSD 15 static binary on FreeBSD 14" takes the binary the FreeBSD 15 job built (`crt-static`; `file`: statically linked, for FreeBSD 15.1) and runs it on FreeBSD 14.5-RELEASE — version, scan and dump pass, the hash matches. And on the rescue image itself, on demand: the `mfsbsd` job of `realworld.yml` boots mfsBSD 14.2 from its ISO under QEMU/KVM, and `tests/realworld/mfsbsd.sh` runs the same binary there against a pool that kernel made on two raw disks — version, scan, list, dump with the kernel's hash; the row is in Results.* |
| E4 | `pkg`/ports build on FreeBSD; `.deb` on Debian/Ubuntu; AUR on CachyOS | installs, `man zvolrescue` present. *Done, and checked in CI on every push: the port (`packaging/freebsd/sysutils/zvolrescue`; crate list from `Cargo.lock`, `distinfo` from `distinfo.sh`) is built from the commit under test with the ports framework, staged, plist-checked, packaged, installed with `pkg` on FreeBSD 15, and the committed `distinfo` is held to the names and the order `make makesum` writes there (`check-distinfo.sh`) — until v0.9.16 it named the GitHub tarball as the framework never looks it up, and nothing compared the two; the `.deb` (`packaging/deb`: the five static binaries and their pages) is built and installed with `dpkg` on the Ubuntu runner, and every release ships one for amd64 and arm64; the AUR PKGBUILD (`packaging/aur`) is built by `makepkg` in an Arch container and installed with `pacman`. Each install runs every program and finds every manual page with `man -w`; the pages (`man/*.1`, mdoc) are kept true to `--help` by `tests/man-check.sh`. Not yet submitted to the ports tree or the AUR: a submission, not a build.* |

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
the evidence log) / refused cleanly (exit 3) / tool defect. Beside the
volumes, a run on the golden image holds every other answer the oracle
has a record for: the files `zvolfiles` extracts against the kernel's
reading of each filesystem, the history `zvoltimeline` gives against
`zpool history -il`, the datasets `list` names against `zdb -t T -d` at
the TXG it listed at (on the control case at every TXG of the ring zdb
recorded), the pool's features it reports against `zpool get` and the
refcounts zdb verified, and what `scan` read of each member's label,
of every slot of its uberblock rings and of the pool's top-level vdevs
against `zdb -l`, `zdb -lu`, `zdb -u` and `zpool status`. The report
`zvolreport` builds of a case's evidence log must say of each volume
what the harness found and verify; where carving is what is left — the
control, a case whose every volume `dump` refused — `zvolcarve` must
find each live volume by its bytes. A wrong answer in any of them makes
the run a defect.

| ID | Scenario | Expected |
|---|---|---|
| G0 | Interim image without a kernel: `tests/golden/build-ztest-image.sh` (ztest + zdb) — three pools (mirror, raidz2, draid1), real metadata, no zvols; runs judged by walking every object against `zdb -d` | image + oracle in `zvolrescue-testdata`; the matrix runs with no defects |
| G1 | Build the golden image with `tests/golden/build-image.sh` on a real kernel: one pool with mirror + RAIDZ2 + dRAID1 top-level vdevs, zvols of several block sizes, snapshots, clones, renamed/destroyed volume and snapshot, encrypted datasets (raw key, passphrase), every checksum/compression, gang blocks, large dnodes, hundreds of TXGs; record the oracle | image + oracle built by the `golden` job of `realworld.yml` on the `ubuntu-26.04` runner's OpenZFS 2.4.1, uploaded as the artifact `golden-image-v1`, published in `zvolrescue-testdata` with SHA-256, the sums pinned in `tests/golden/image-v1.SHA256SUMS`. *Built and published as `image-v1` (Results, 2026-10-10)*; the builder now makes `golden-v2` — besides, a tree of every kind of file, cloned blocks, a promotion, rollbacks, volumes of 128K, `copies=2`, `checksum=off` and `zstd-fast`, compressible content, the hash of a volume just before it is destroyed, the whole oracle from the build |
| G2 | Single damage classes (labels, partition, metadata, data, missing member, older-self member) on each geometry | every run in an expected category; no tool defects |
| G3 | Pairs and triples of classes across members and geometries | as G2; the expected category derived from ZFS redundancy for the combination |
| G4 | Held-out combinations run only before a release (`only: published-held-out`) | as G2 |
| G5 | Read-only invariant on every run | input copies' hashes unchanged |
| G6 | The satellites, built with `tests/golden/build-satellite.sh` on a real kernel: a small pool for each pool-level feature the golden pool does not have — a removed vdev, a checkpoint, a hot spare and an unfinished replacing, an expanded raidz, special and dedup vdevs, ashift 9 and 13, an intent log never applied, `multihost` — each with the golden image's oracle and the manifests that name it | every run in an expected category; the expanded raidz refused, never read as if it were not |

How to run: **Actions → Real-world (kernel ZFS) → Run workflow** with `only: golden` (`golden-held-out` for G4) builds the image on the runner's kernel, reads every volume of it intact to the kernel's hash, runs the whole matrix over it with every expectation enforced — a run outside its expected category fails the job — and uploads `release/` (the members, zstd, with `SHA256SUMS`, and of the `round6-*` copies those the manifests name), `oracle/`, `IMAGE.md` and `report/` as the artifact `golden-golden-v2`, and all but the members, a few MB, as `golden-golden-v2-text`. **Actions → Publish the golden image → Run workflow** with that run's number then publishes it in `zvolrescue-testdata` without anyone downloading it: the members into the release named by `tag`, the oracle into `oracle/<oracle>/` (`golden-v2`; `image-v1`'s is `golden`), `IMAGE.md` and the report into `reports/<tag>/`, after checking the sums and that no run of the matrix fell outside its category; it needs one secret, `TESTDATA_TOKEN`, a fine-grained token for that repository with contents read and write. The `golden-published` job (`only: published`, and every Monday on its own) is the one SPEC §9.1 asks for: for each published image — `image-v1`, `golden-v2` and the satellites `sat-<name>-v1`, a job each — it fetches the release this repository pins in `tests/golden/<tag>.SHA256SUMS`, checks every file against it and the oracle's own record, reads every volume intact, and runs the matrix with the oracle and manifests from `zvolrescue-testdata`'s checkout, the `round6-*` files decompressed beside the members for the `older-self` class; `published-held-out` adds G4. Every run of it on `main`, a pass or not, keeps its report in `zvolrescue-testdata` as the next `reports/<tag>-rN` (laid out there by `tools/add-report.py`, pushed with the same `TESTDATA_TOKEN` when the repository variable `KEEP_REPORTS` is `true`; without either the report stays the run's artifact, and the step says so). By hand: `tests/golden/build-image.sh OUT golden-v2 <testdata>/manifests` as root on a real kernel, then `tests/golden/run-matrix.py --image OUT/members --oracle OUT/oracle --manifests <testdata>/manifests --out REPORT --label golden-v2` (add `--held-out` before a release); the report lands in `REPORT/report-golden-v2.md` and `.json`, and `tools/add-report.py REPORT --tag golden-v2` in a checkout of `zvolrescue-testdata` keeps it there as the next run.

The satellites (G6): `only: satellites` builds all eight in the `satellites` jobs of the same workflow, a job each (`only: sat-spare sat-slog` builds those named), on the `ubuntu-26.04` runner's kernel: `build-satellite.sh /var/tmp/sat <name>` makes the pool `sat-<name>` and its oracle with the code the golden image's builder uses (`tests/golden/lib-build.sh`), the manifests of `zvolrescue-testdata` that name it are run over it — those that name no pool are not run against a satellite — and it is uploaded as `golden-sat-<name>-v1` for `publish-golden.yml`, which publishes it as the release `sat-<name>-v1` with its oracle under `oracle/sat-<name>/` and its `IMAGE.md` beside its report. By hand: `tests/golden/build-satellite.sh OUT <name>` as root on a real kernel, then `run-matrix.py` as for the golden image.

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

`tests/realworld/kernel-matrix.sh` does the whole run: builds the pools,
takes every oracle from OpenZFS (the zvol as the kernel reads it before export,
`zdb -d`, `zdb -lu`, `zfs get -s local`), exports them, runs the tool
against the loop devices, and prints the row for the Results table.

Setting up (Debian 12 or 13, `contrib` enabled; a VM with 2 CPUs, 2 GiB
of RAM and 8 GiB of free disk is enough):

```
apt install linux-headers-$(uname -r) zfsutils-linux zfs-dkms dmsetup strace python3 openssl
modprobe zfs
cargo build --release
sudo bash tests/realworld/kernel-matrix.sh /var/tmp/rw ./target/release/zvolrescue
```

The same script runs on FreeBSD 14 and 15 against the OpenZFS of the
base system, with md devices for loop devices: `gpart` writes B9's GPT
(a `freebsd-zfs` partition), F7's failing range is a `gnop` that refuses
every read between two clean ones, joined back into one device by
`gconcat`, `truss` takes the place of `strace` for the read-once check,
and A3 runs the tool as `nobody` through `chroot -u`:

```
pkg install rust bash python3
cargo build --release
bash tests/realworld/kernel-matrix.sh /var/tmp/rw ./target/release/zvolrescue
```

`.github/workflows/realworld.yml` runs it on demand in every
environment at once, or in those its `only` input names: the
`ubuntu-26.04` and `ubuntu-24.04` runners' own kernels, Debian 13 and 12
VMs with `zfs-dkms`, and FreeBSD 15 and 14 VMs. Its `mfsbsd` job is the
one environment this script does not run in: mfsBSD has no bash or
python, so `tests/realworld/mfsbsd.sh` — `/bin/sh` and the base system —
answers E3 there, with a pool the rescue kernel makes on two raw disks
and the static binary built on FreeBSD 15 copied in over ssh. A
machine of your own — a kernel the runners cannot supply, a box with
disks — runs the same script through `realworld-ssh.yml`, below.

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
| B4 | 1 MiB of `/dev/urandom` over the volume's own blocks on one raidz2 member: the first data block's DVA from `zdb`, spread over the four columns, plus the labels | image matches; the `--debug-log` shows the reconstruction |
| B5 | mirror + raidz1 in one pool, also with one member of each absent | same as B1 |
| B6 | mirror with a `log` and a `cache` device | `scan` of all four exits 0; `dump` from the two data members matches |
| B7 | `draid1:2d:5c:1s`, also with one member absent | same as B1 (skipped if this `zpool` builds no dRAID) |
| B8 | attach a second member, export, copy the original to another loop device, import, `detach` the original | `scan` of the copy and the survivor lists the copy under `stale` and only the survivor under `devices`; `dump` from both matches the pool after the detach. The copy stands in for a disk pulled before the detach: `zpool detach` erases the labels of the device it detaches |
| B9 | a loop device with a GPT written by `sfdisk`, one partition of the type ZFS uses, the pool made on `p1` (`zpool create` on the bare device labels it the same way, but the partition node it then waits for did not appear on either kernel tried) | `scan` of the whole disk finds the GPT and the ZFS partition; `dump` from the whole disk and from `p1` both match |
| C1–C3 | one volume per value: 8 compressions, 7 checksums, 6 block sizes; a value this ZFS does not have (`blake3` needs OpenZFS 2.2) is noted and left out | each image matches the kernel's hash |
| C4 | `zfs create -s -V 1G`, 64 MiB written at 300 MiB | matches; the image is sparse (`du` under 200 MiB) |
| C5 | `dedup=on`, four copies of the same 4 MiB | matches |
| C6 | two snapshots and a clone of one volume | the head, each snapshot and the clone match their own hashes (`snapdev=visible` for the kernel's side) |
| C7 | `encryption=aes-256-gcm`, `keyformat=raw` | matches with `--key raw:FILE`; without one, exit 1 with `is encrypted (aes-256-gcm …); supply --key` and an empty output |
| C8 | `dnodesize=auto` on the parent | matches |
| C9 | 100 datasets, 12 levels deep, one 80-character name | `list -r` = `zdb -d` |
| C10 | two single-disk tops, `zpool remove` the second, then write more | `scan` says `removed_tops: [1]`; `list` and `dump` match |
| C11 | `org.example:ticket` and `compression` on a filesystem and a volume | the set of (dataset, property) from `list --properties` equals `zfs get -s local`; `volblocksize` is left out on the tool's side and `volsize` on the kernel's: the first is in the property ZAP at creation but shown by `zfs get` with source `-`, the second is answered from the volume's own object though `zfs get` calls it local |
| C12 | `zpool attach` a fourth member to a raidz1 (OpenZFS 2.3) | `list` exits 3 naming `raidz_expansion`; `scan` exits 0; `--ignore-unknown-features` reads. Skipped on 2.2 |
| C13 | a mirror filled with ganging forced (`metaslab_force_ganging` 16 KiB, every allocation) on a ZFS that has `dynamic_gang_header`; the feature must come back `active` | `scan` lists the feature under `features_for_read`; the trace shows 4 KiB gang headers read; `dump` matches the kernel. Skipped on 2.3 and older |
| D1 | `zfs destroy`, export at once; the TXG before from `zdb -u` | `list --diff` shows it under `destroyed_since`; `dump --txg` matches, or exits 4 with an image equal to the volume as the kernel read it with exactly the `bad` blocks zeroed (Debian 12's OpenZFS 2.1 reused one block of 768 in the export's own TXGs) |
| D2 | `zfs destroy`, then 500 MiB written elsewhere over six TXGs | either the hash matches from an older TXG — exit 0, or exit 4 with the newer TXG that named it and did not read in `unreadable_at` and no block zeroed — or exit 3 with `not found at any of N verified TXG(s)`, or exit 3 with `is named at txg N but does not read there` and the TXG in `unreadable_at`, or exit 4 with `blocks_zeroed` counted |
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

## Running the matrix on your own machine over ssh

The environments above are the ones GitHub's runners can stand in for.
A kernel ZFS they cannot — a distribution the workflow has no image of,
an OpenZFS built from git (CachyOS in the table), a box with disks for
E1/E2 and F1–F10 — runs the same script on a machine of your own, over
ssh: `.github/workflows/realworld-ssh.yml`. The runner builds the
static binaries for what the machine turns out to be (Linux x86_64 or
aarch64 with musl; FreeBSD amd64, built on FreeBSD 15 as the release
is), copies them and the script over, has the script run there as
root, and brings the record back into the job's summary and an
artifact, exactly as `realworld.yml` does with its own VMs. Nothing
about the machine is in the repository: it is all in one GitHub
Environment (Settings → Environments), named by the workflow's `target`
input, whose secrets are

| Secret | What | |
|---|---|---|
| `SSH_HOST` | the machine: a name or an address | required |
| `SSH_USER` | the user to log in as | required |
| `SSH_PORT` | its sshd port | 22 |
| `SSH_KEY` | an OpenSSH private key for that user (`ssh-keygen -t ed25519 -N '' -f ci`: the secret is `ci`, the machine gets `ci.pub`) | one of |
| `SSH_PASSWORD` | or the user's password: a rescue system booted with a known root password, a throwaway VM | the two |
| `SSH_KNOWN_HOSTS` | the machine's host key as `ssh-keyscan -p PORT HOST` prints it, and the bastion's when there is one; empty, the first key seen is taken and the summary warns | recommended |
| `SSH_CONFIG` | more `ssh_config` for the way in: a `ProxyJump`, the bastion's own `Host` block, `HostKeyAlgorithms` for an old sshd | optional |
| `SSH_JUMP_KEY` | a private key for the bastion when it is not `SSH_KEY`; the config names it `~/.ssh/id_jump` | optional |
| `TS_OAUTH_CLIENT_ID`, `TS_OAUTH_SECRET` | a Tailscale OAuth client with the tag `tag:ci`: the runner joins the tailnet first, and `SSH_HOST` is the machine's name on it | optional |

and whose protection rules (required reviewers) decide who may start a
run against it. Start one from **Actions → Real-world (kernel ZFS) over
ssh → Run workflow** with the environment's name as `target`; `script`
is `matrix` (`kernel-matrix.sh`) or, for a rescue system, `mfsbsd`
(`mfsbsd.sh` on the two raw disks named in `disks`, whose contents it
destroys). One run per environment at a time. The row for the table
below comes back in the summary and, as `row.md`, in the artifact
`realworld-ssh-<target>-<script>`, with the results, the evidence log
and the logs of every scenario beside it.

What the machine needs, besides ssh: for `matrix`, a kernel ZFS with
its userland (`zpool`, `zfs`, `zdb`), `bash`, `python3` and `openssl`
— on Linux also `losetup`, `sfdisk`, `dmsetup` and `strace`
(`util-linux`, `dmsetup`, `strace`), on FreeBSD `pkg install bash
python3`, the rest is in base; for `mfsbsd`, `/bin/sh` and the base
system. The workflow's probe says what is missing before anything is
built.

**The gate.** The key the workflow holds is best installed behind
`tests/realworld/ssh-gate.sh` as a forced command, so that whoever
holds it can ask for what the workflow needs and nothing else — it is
not a shell:

```
install -m 755 tests/realworld/ssh-gate.sh /usr/local/sbin/zvolrescue-gate
echo 'command="/usr/local/sbin/zvolrescue-gate",restrict ssh-ed25519 AAAA… zvolrescue-ci' >> ~ci/.ssh/authorized_keys
echo 'ci ALL=(root) NOPASSWD: /usr/local/sbin/zvolrescue-gate' > /etc/sudoers.d/zvolrescue-gate
```

The gate answers five requests — `probe` (what the machine is), `put`
(one of the four files the workflow ships, into
`/var/tmp/zvolrescue-ci/in`), `run matrix` or `run mfsbsd D0 D1`,
`record` (the run's record without its images) and `clean` — and
refuses everything else. The last three need root, which is what the
sudoers line is for: the gate re-runs itself under `sudo` for them, and
the line allows the gate and nothing else (on FreeBSD, `pkg install
sudo` first; or put the key in root's own `authorized_keys` and leave
the line out). What then runs as root is the repository's own script,
so a run is exactly as trusted as the repository that sent it: lend a
machine you can lose — a VM, a spare box — never one with a pool you
care about. The script refuses to start while a `zrw*` pool is
imported, creates only such pools and tears its devices down on exit;
it writes about 6 GiB under `/var/tmp`. Where there is no gate — a
login with a password, a throwaway VM whose user has `sudo` — the
workflow copies the gate over first and runs it as `~/zvolrescue-gate`,
with the same requests.

**The way in.** Three kinds of access, and what each needs:

* *A key.* `SSH_KEY`, its public half behind the gate as above, and
  `SSH_KNOWN_HOSTS` from `ssh-keyscan`. The machine's sshd needs
  nothing it does not have.
* *A password.* `SSH_PASSWORD` instead of `SSH_KEY`; the runner
  installs `sshpass`, and the gate travels with the run. This is what
  a rescue system offers: mfsBSD answers as `root` with its published
  password, and `script: mfsbsd` with its two disks in `disks` is E3 on
  the real thing. A password reaches the machine itself only; a
  bastion on the way takes a key.
* *A bastion.* The machine is behind a host the Internet can reach — a
  server, or the router itself when it runs OpenWrt — and ssh jumps
  through it. `SSH_CONFIG` holds the jump and the bastion's block,
  `SSH_KNOWN_HOSTS` both host keys, and the bastion gets the public
  half of `SSH_JUMP_KEY` (or of `SSH_KEY`) with no command to run,
  since a jump is a TCP forward, not a login:

  ```
  ProxyJump jump
  Host jump
    HostName router.example.net
    Port 22
    User root
  ```

  On OpenWrt the sshd is dropbear: the key goes into
  `/etc/dropbear/authorized_keys` (System → Administration → SSH-Keys
  in LuCI) as `no-pty,command="/bin/false" ssh-ed25519 …` — no shell,
  while the forward a jump needs stays allowed — and `ssh-keyscan -p 22
  router.example.net` gives its host key. Dropbear has taken `ed25519`
  keys since 2016; for a build that does not, `ssh-keygen -t rsa -b
  4096` and `HostKeyAlgorithms +ssh-rsa` in the config. A machine that
  nothing outside its network can reach has two more ways in: a
  Tailscale tailnet (the `TS_` secrets; the runner joins as `tag:ci`,
  and the tailnet's ACL lets that tag reach the machine's port 22), or
  a self-hosted runner inside the network, named by the `runner` input
  — the runner is then the bastion, and `SSH_HOST` is the machine's
  address on the LAN.

## Format traps found on real pools

The fixture pools are written by the same code that reads them, so they
cannot catch a wrong byte or word order, or a field read from the wrong
place. Each trap below was found only on a real pool (`ztest` or kernel
ZFS), and each cost time. Read this list before changing a parser, the
reader or the checksums; when a real pool shows a new one, add it here
and in [the Ukrainian version](REALWORLD-TESTS.uk.md), next to its row in
Results.

- `sha512` stores the digest words in the writer's native byte order
  (like `blake3`, `skein` and `edonr`); `sha256` stores them big-endian.
- `edonr` has no DEDUP flag, so in an encrypted dataset its words are
  folded with XOR, as fletcher's are; `skein`, `blake3` and `sha*` are not
  folded.
- The gang header of an encrypted block carries the *folded* checksum.
- OpenZFS zstd frames have no magic number; the level is in the top byte
  of the header's second word.
- The `dmu_ot` table: other-ZAP, zvol-prop, znode, master-node and
  FUID-size objects are only authenticated, not encrypted (the
  `ot_encrypt` column).
- `keyformat` and `pbkdf2*` are in the crypto ZAP; `keylocation` is in the
  DSL directory's props.
- The AAD of a dnode block: `dn_used` is at offset 24; the bonus buffer
  starts after *all* `dn_nblkptr` block pointers.
- dRAID parity is computed over the whole group width (empty trailing
  columns shift Q and R); RAIDZ parity covers only the occupied columns.
- A label with `txg 0` (a device being attached or replaced) does not
  describe the topology.

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
| 2026-09-23 | Ubuntu 24.04.5 LTS (GitHub Actions runner, in-tree OpenZFS module, loop devices) | 2.2.2 (kmod 2.3.4) | `0.9.7`+ (`09ba777`) | A1 A2 A3, B1–B9, C1–C11, D1–D8, F7, G5, R | ☑ | `tests/realworld/debian-loop.sh`, first job of `.github/workflows/realworld.yml`; kernel 6.17.0-1022-azure. 34 scenarios on 12 pools the kernel made, every oracle from OpenZFS, the tool reading loop devices as devices: pass. C12 skipped (no `raidz_expansion` in this ZFS). Third run of the script on a real kernel: the first two found one tool defect (B8: a member detached while it was out of the machine listed beside the survivor, not stale) and the script's own mistakes (a dataset comparison that parsed nothing, B4's corruption in free space, C7 and C11 expecting less than the tool does), fixed on the way. F7 stopped at the dm-error hole with exit 7 and healed from the other member with `--device-may-fail`; 1424 reads of the failing device, none overlapping. |
| 2026-09-23 | Debian 12 (bookworm), zfs-dkms against Debian's kernel, loop devices; QEMU/KVM guest on a GitHub Actions runner | 2.1.11 | `0.9.7`+ (`09ba777`) | A1 A2 A3, B1–B9, C1–C11, D1–D8, F7, G5, R | ☑ | `tests/realworld/debian-loop.sh`, second job of `realworld.yml`; kernel 6.1.0-53-cloud-amd64. The environment the script was written for: 34 scenarios pass; C12 skipped, C2 without `checksum=blake3` (not in 2.1). Its earlier run found what Ubuntu's did not: **D2** — `dump` stopped at the oldest TXG that still named the destroyed volume, whose object set block 2.1's allocator had reused, with `every copy failed its checksum` instead of trying older TXGs (fixed: the search goes on to the next older verified TXG, `unreadable_at` in the record); **D1** — the export's own TXGs reused one block of 768 of the volume destroyed just before it, so the honest answer was a partial image (exit 4) with that block zeroed and counted, which the scenario now accepts when the image is the kernel's bytes with exactly the `bad` blocks zeroed. In this run both volumes came back whole. |
| 2026-10-07 | Ubuntu 24.04.5 LTS (GitHub Actions runner, in-tree OpenZFS module, loop devices) | 2.2.2 (kmod 2.3.4) | `0.9.8`+ (`f489e14`) | A1 A2 A3, B1–B9, C1–C11, D1–D8, F7, G5, R | ☑ | `tests/realworld/kernel-matrix.sh` (the script renamed from `debian-loop.sh` once it learned FreeBSD), first job of `realworld.yml`; kernel 6.17.0-1022-azure. 34 pass, C12 skipped. Two of the script's own defects fixed since the 2026-09-23 rows, which those rows did not catch: **A1 and G5 compared nothing** — the loop devices were recorded inside a command substitution, so the list the before/after edge hashes walk was empty and both passed vacuously; the list is a file now, and A1/G5 here compare every device's ends for real. **C4 proved nothing on a ZFS-backed work directory** — `du` counts blocks only once a TXG writes them; C4 now sums the image's data extents with `SEEK_DATA`/`SEEK_HOLE` (67108864 bytes of a 1 GiB image). D2 came back whole from an older TXG. |
| 2026-10-07 | Debian 12 (bookworm), zfs-dkms against Debian's kernel, loop devices; QEMU/KVM guest on a GitHub Actions runner | 2.1.11 | `0.9.8`+ (`f489e14`) | A1 A2 A3, B1–B9, C1–C11, D1–D8, F7, G5, R | ☑ | `kernel-matrix.sh`, second job of `realworld.yml`; kernel 6.1.0-53-cloud-amd64. 34 pass; C12 skipped, C2 without `blake3`. The run before this one (on `3ba764c`) found a second **D2** defect, on this kernel and on FreeBSD 15's: v0.9.8's search passed over a TXG whose object set block did not read, but checked that block alone, and here the block of the volume's *dnodes* had been reused while the object set above it still read — the search stopped there and the run failed opening the volume (exit 3) with an older TXG holding it whole. Fixed in `f489e14` (the search checks the object set, the data object and the size; reproduced with a fixture); in this run D2 came back whole from an older TXG. A1/G5 compare real device edges (see the Ubuntu row). |
| 2026-10-07 | FreeBSD 15.1-RELEASE-p3, base system OpenZFS, md devices; VM (`vmactions/freebsd-vm`) on a GitHub Actions runner | 2.4.2 | `0.9.8`+ (`f489e14`) | A1 A2 A3, B1–B9, C1–C12, D1–D8, F7, G5, R | ☑ | `kernel-matrix.sh`, the `freebsd` job of `realworld.yml`; the first run of the matrix on FreeBSD, and the first environment where all **35** apply. **C12** on a pool the kernel expanded (`zpool attach` to a raidz1): `list` exits 3 naming `raidz_expansion`, `scan` 0, `--ignore-unknown-features` reads. **F7** on FreeBSD's own tools: a `gnop` that refuses every read between two clean ones, joined into one device by `gconcat`, traced with `truss` — stopped with exit 7 at LBA 536968, healed from the other member with `--device-may-fail`, 1424 reads of the failing device, none overlapping. B9's GPT written by `gpart` (`freebsd-zfs`), A3 as `nobody` through `chroot -u`. **D2**: the dnode defect above was found here too; after the fix the newest TXG whose metadata reads had all 768 data blocks reused — a partial image with 768 of 768 blocks zeroed and counted (exit 4), the honest answer. |
| 2026-10-07 | FreeBSD 14.5-RELEASE, base system OpenZFS, md devices; VM on a GitHub Actions runner | 2.2.9 | `0.9.8`+ (`f489e14`) | A1 A2 A3, B1–B9, C1–C11, D1–D8, F7, G5, R | ☑ | `kernel-matrix.sh`, the `freebsd` job of `realworld.yml`; the primary target (SPEC N-06) on a real kernel for the first time. 34 pass, C12 skipped (no `raidz_expansion` in 2.2). F7 through `gnop` + `gconcat` + `truss`: exit 7 at LBA 1732952, 1422 reads, none overlapping. C4: 67141632 bytes of data extents. D2 as on FreeBSD 15: partial image, 768 of 768 blocks zeroed and counted (exit 4). |
| 2026-10-10 | Ubuntu 26.04.1 LTS (GitHub Actions `ubuntu-26.04` runner, in-tree OpenZFS module, loop devices) | 2.4.1 | `0.9.8`+ (`6050981`) | A1 A2 A3, B1–B9, C1–C12, D1–D8, F7, G5, R | ☑ | `kernel-matrix.sh`, the Ubuntu job of `realworld.yml` on its new runner; kernel 7.0.0-1012-azure. The current LTS — the matrix had run only on 24.04 (OpenZFS 2.2.2) until now: all **35** scenarios apply and pass, C12 on a raidz1 this kernel expanded, the first Linux kernel on the matrix with `raidz_expansion`. F7: exit 7 at LBA 4857552, healed with `--device-may-fail`, 1426 reads of the failing device, none overlapping. The 24.04 runner ran beside it and passed again (34, C12 skipped). |
| 2026-10-10 | Debian 13 (trixie), zfs-dkms against Debian's kernel, loop devices; QEMU/KVM guest on a GitHub Actions runner | 2.3.9 | `0.9.8`+ (`6050981`) | A1 A2 A3, B1–B9, C1–C12, D1–D8, F7, G5, R | ☑ | `kernel-matrix.sh`, the Debian job of `realworld.yml`, a matrix of 13 and 12 now; kernel 6.12.111+deb13-cloud-amd64, the cloud image checked against Debian's `SHA512SUMS`. Debian stable — the matrix had run only on 12 (OpenZFS 2.1.11) until now: all 35 pass, C12 included, C2 with `blake3` again. F7: exit 7 at LBA 4849224, 1422 reads, none overlapping. D2 came back whole from an older TXG. The 12 guest ran beside it and passed again (34, C12 skipped, C2 without `blake3`). |
| 2026-10-10 | mfsBSD 14.2-RELEASE (FreeBSD 14.2 booted from its ISO into RAM; QEMU/KVM guest on a GitHub Actions runner, two raw virtio disks) | 2.2.6 | `0.9.8`+ (`57591e4`), the static binary built on FreeBSD 15.1 | E3, A1, G5, R | ☑ | `tests/realworld/mfsbsd.sh`, the `mfsbsd` job of `realworld.yml`: the first run on the rescue medium itself, the first row of the environments table. mfsBSD answered on ssh 25 s after boot; its kernel made a mirror on the two disks and a 128 MiB volume with 96 MiB of data; the 15.1-built static binary (`file`: statically linked, for FreeBSD 15.1) ran `--version`, `scan` (pool EXPORTED, READABLE from both disks), `list -r` (the volume) and `dump`, whose image hashed to the kernel's `eab4d933…cfa08d`, the tool's own `sha256:` line agreeing. Both disks' ends unchanged and the pool importable after the run; `zvolreport` built and verified the case file over the 3 records. The whole job, the FreeBSD 15 build included, takes 3 minutes. |
| 2026-10-10 | Ubuntu 26.04.1 LTS (GitHub Actions `ubuntu-26.04` runner, in-tree OpenZFS module): the golden image built by its kernel, and the damage matrix over it | 2.4.1 | `0.9.8`+ (`beac928`) | G1, G2, G3, G5 | ☑ | The `golden` job of `realworld.yml`: `tests/golden/build-image.sh` and `run-matrix.py`, the first golden image a kernel built (SPEC §9.1) — one pool with mirror-2, raidz2-4 and draid1 top-level vdevs at `ashift` 12, 11 volumes (block sizes, every checksum and compression, a clone, raw-key and passphrase encryption), snapshots, a rename and a destroy, 5015 TXGs, built in 9 minutes; every volume of the intact image read to the kernel's hash first (the encrypted ones with the oracle's keys). Then **41 manifests: 35 pass, 6 n/a, 0 defects**, inputs unchanged — the first matrix where every expectation is enforced. The 6 n/a: five structure-targeted cases (MOS and object-set copies) have a copy on the dRAID top, which the harness does not map through the permutation, and one asks for a third leaf of the two-way mirror. The image's first build was refused whole by v0.9.8: built with ganging forced, the pool had `dynamic_gang_header` active (C13) — 33 of 41 runs "refused" — and, once that was read, 7 more from the 512-byte headers written before the feature went active, read now too. The harness had its own defects, fixed on the way: the job stayed green over those 33 (no `pipefail`; a run outside its category now fails the job), a manifest on a multi-top image was judged by the member it damaged rather than that member's geometry, "refused" was accepted where the honest answer is a partial image (exit 4), and the encrypted volumes' key formats came from a `zfs list` that was not recursive. The artifact `golden-image-v1` — `release/*.zst` with `SHA256SUMS`, `oracle/`, `IMAGE.md`, `report/` — is what `zvolrescue-testdata` publishes as `image-v1`. |
| 2026-10-10 | Ubuntu 24.04 (GitHub Actions runner, no kernel ZFS): the golden image as published, `image-v1` of `zvolrescue-testdata` | 2.4.1 (the image's builder) | `0.9.9`+ (`d94d4f8`) | G2, G3, G4, G5 (the `older-self` class for the first time) | ☑ | The `golden-published` job of `realworld.yml` with `only: published-held-out`: the first matrix against the image as published, the CI job SPEC §9.1 asks for. The 20 release files (2.4 GB) fetched in a minute and checked against `tests/golden/image-v1.SHA256SUMS` and the oracle's own record, decompressed sparse beside each other, the members' sums checked; every volume intact to the kernel's hash with the oracle's keys — the first attempt stopped on `golden/secret-raw/disk`, whose `raw.key` the testdata `.gitignore` had kept out of the publication commit; the key is derived from the builder's seed and was restored byte-identical. Then **49 manifests: 43 pass, 6 n/a, 0 defects**, inputs unchanged, 25 minutes: the 41 of the build-time run with the same verdicts, the **3 held-out** (G4) for the first time — front labels everywhere bit-exact, labels plus two missing members partial, rings on two members bit-exact — and the **5 `older-self`** for the first time, the pattern placed from the release's `round6-*` files: one stale mirror half bit-exact, both halves partial (the mirror's post-round-6 blocks have no current copy anywhere, and none is presented as current), two stale raidz2 columns and one stale dRAID child reconstructed, a stale column beside a missing one reconstructed. The 6 n/a as before: structure-targeted damage is not placed on the dRAID top, and one case asks for a third leaf of the mirror. The release files stay in the Actions cache; the job runs every Monday on its own. |
| 2026-10-10 | Ubuntu 24.04 (GitHub Actions runner, no kernel ZFS): the golden image as published, `image-v1` of `zvolrescue-testdata` | 2.4.1 (the image's builder) | `0.9.9`+ (`1cd1b99`) | G2, G3, G4, G5 (the `metadata` class on the dRAID top for the first time) | ☑ | `golden-published` with `only: published-held-out`, the release files from the Actions cache this time: **49 manifests, 48 pass, 1 n/a, 0 defects**, inputs unchanged, 28 minutes. The five structure-targeted cases that had been n/a on every run — the MOS and object-set copies that live on the dRAID top — apply now: the harness finds such a copy by content (the block's bytes from a copy that arithmetic places, checked against the pointer's fletcher4, searched for on the dRAID's children) and places its data columns, a parity column with them only where it equals a data column (one data sector in the row, the other a zero pad). `metadata-mos-one-copy` bit-exact and `metadata-objset-one-copy` reconstructed from the other copy; `metadata-mos-every-copy` — all three copies of the MOS object set at the newest TXG destroyed — bit-exact from an older uberblock, which is what the manifest asks for; the two combinations with a member missing reconstructed. The one n/a asks for a third leaf of the two-way mirror. Everything else as in the previous row. |
| 2026-10-11 | Ubuntu 24.04 (GitHub Actions runner, no kernel ZFS): the golden image as published, `image-v1` of `zvolrescue-testdata` | 2.4.1 (the image's builder) | `0.9.9`+ (`df1bd53`) | G2, G3, G4, G5 (damage below the object set for the first time) | ☑ | `golden-published` with `only: published-held-out`: **57 manifests, 56 pass, 1 n/a, 0 defects**, inputs unchanged, 26 minutes. Eight new cases aim below the object set, which the oracle's new `zdb -dddddd` capture makes possible (`oracle-capture.yml`: OpenZFS's own zdb, offline, over the released members, on the ubuntu-26.04 runner's 2.4.1 userland; 58 MB, 580 955 lines, in `oracle/golden/`): one piece of a data block of `vm/disk-16k` (a raidz2 data column) reconstructed; every piece of one of its blocks on the mirror — the block's only copy — partial, the block zeroed and counted; the same on the encrypted `secret-raw/disk` partial, nothing decrypted into the image; one copy of a dnode block of `vm/disk-64k` and of the topmost indirect block of `vm/disk-8k` reconstructed from the other copy; every copy of that indirect block partial; every copy of that dnode block reconstructed, which the manifest allows (the block is rewritten only when the dnodes change, so an older TXG holds it intact); a dnode block's copy beside a missing raidz2 member reconstructed. On the way: zdb writes the deep capture's pointers compactly (`vdev:offset:asize`, a `G` on a gang block), the volumes' lower indirect blocks are mostly gang blocks after the forced ganging, so `indirect` means the topmost level, and gang blocks are not aimed at. The one n/a as before. |
| 2026-10-11 | Ubuntu 24.04 (GitHub Actions runner, no kernel ZFS): the golden image as published, `image-v1` of `zvolrescue-testdata` | 2.4.1 (the image's builder) | `0.9.9`+ (`f564019`) | G2, G3, G4, G5 (the crypto key object for the first time) | ☑ | `golden-published` with `only: published-held-out`: **59 manifests, 58 pass, 1 n/a, 0 defects**, inputs unchanged, 37 minutes. Two new cases aim at the DSL crypto key of `secret-raw/disk` — MOS object 323, the ZAP its DSL directory names as `com.datto:crypto_key_obj`, two blocks of three copies each, the dRAID copies placed by content: one copy of every block overwritten, reconstructed from the others; every copy overwritten, that volume refused — unlockable at no TXG even with the right key file — and the eleven others read whole. With it every shape the manifests' format names is placed (a volume's property ZAP on this image is embedded in its dnode's block pointer, so the dnode-block cases are its). The one n/a as before. |
| 2026-10-13 | Ubuntu 24.04 (GitHub Actions runner, no kernel ZFS): the golden image as published, `image-v1` of `zvolrescue-testdata` | 2.4.1 (the image's builder) | `0.9.9`+ (`9b40342`) | G2, G3, G4, G5 (a forged txg and a grown partition for the first time) | ☑ | `golden-published` with `only: published-held-out`: **61 manifests, 61 pass, 0 n/a, 0 defects**, inputs unchanged, 37 minutes. The last two classes of SPEC §9.1's catalogue: `labels-forged-txg` puts a sealed uberblock three TXGs ahead of the pool into every member's rings, pointing at an object set no block matches, and zeroes one member's rear rings besides — the tool passes the forged TXG over for the newest that reads and every volume comes back whole (reconstructed: the raidz2 copy of the forged root is tried through its parity before it is given up); `partition-grown` makes a raidz2 member 48 MiB longer, bit-exact. `combo-across-tops-one-past-budget`, n/a on this image since the first run, now takes two children of the four-child draid1 and lands partial, the lost rows counted and announced. What the forged txg found — `list` stopping at that TXG with exit 3 while `dump` went on without a word — is fixed in the same commit. Every manifest applies. |
| 2026-11-23 | Ubuntu 24.04.5 LTS (container, no kernel ZFS): pools made through OpenZFS's own userland code, `libzpool` driven from a script | 2.2.2 | `0.9.16`+ (`ff87059`) | C14, C15 (for the first time; not on a kernel) | ☑ | By hand, on three pools of file vdevs. **C14**: two tops, an 8 MiB volume half written, `zpool remove` of the second. At a TXG from before the removal, `dump` with the remaining disk alone reads all 512 blocks through the mapping the removal left, where it zeroed 283 as "unknown top-level vdev 1". With 1 MiB of the volume rewritten before the removal, the oldest TXG comes back with 73 blocks zeroed, named as not in the mapping, and with 7 once the removed disk is a member (those 7 fail their checksums: what lay there was written over). **C15**: a volume written, `zpool checkpoint`, the volume destroyed, 45 more syncs, so that no ring holds the checkpoint's TXG 12. `list` names it, `list --txg 12` has the volume as `zdb -k` does, `zvoltimeline` has the volume last seen at it, and `dump` of the volume without `--txg` is byte for byte what `dmu_read` gave before the destroy. Neither scenario is in `kernel-matrix.sh` yet. |
| 2026-11-24 | Ubuntu 24.04.5 LTS (container, no kernel ZFS): pools made through `libzpool` driven from a script, and `ztest` pools | 2.2.2 | `0.9.16`+ (`fa8ec70`) | F-65 and F-67 with no label left (not on a kernel) | ☑ | By hand. Every `vdev_phys` erased on copies of each pool, the layout given in `--hints`. **A vdev's own ashift**: `raidz1` at ashift 9 with `raidz1` at ashift 12 reads whole once each vdev gives its `ashift` — 522 or 754 of 1536 blocks were zeroed under either one value — also with one member of each raidz missing, and `zvolcarve` carves the destroyed volume of such a pool byte for byte. **Emitted labels**: one emitted for every member and position and placed on the copies. On `raidz1`, on `mirror` + `raidz2` + `draid1:2d:1s:4g`, on the mixed-ashift pool, on a pool with a vdev removed and on seven `ztest` pools, `zdb -l` prints for each copy what it prints for the original — but for the `txg` of a vdev whose labels the pool last wrote one group before its configuration — and `zdb -e` opens the copies and lists the same datasets; on the four `libzpool` pools `zdb -bcc` walks every block with no leak. `zpool import` of such copies on a kernel was not tried. The `ztest` part is in step 12 of `crosscheck-ztest.sh` now. |
| 2026-11-24 | Ubuntu 24.04.5 LTS (container, no kernel ZFS): pools made through `libzpool` driven from a script | 2.2.2 | `0.9.16`+ (`2d1050e`) | `zvolcarve` on pools with destroyed volumes, with no label and with no uberblock (COMPANIONS C-01, C-08, C-13…C-21; not on a kernel) | ☑ | By hand, on mirror, two-top and raidz1 pools of file vdevs. **No labels**: the member of an ashift-9 top with its four labels zeroed gives the 3072 candidates and 18 volume dnodes it gives with them (410 and 2 before); six label-less members of `raidz1` at 9 with `raidz1` at 12 give 1762 and 32 (1671 and 18). A mirror member behind 1 MiB + 512 bytes of noise is placed by its block pointers at byte 1049088 — 56 of 64 probes, the 31 that agree a metaslab on being second copies, every one — the scan lists 5383 candidates and 42 volume dnodes (126 and 0), and the destroyed 16 MiB volume dumped with that base in `--hints` is byte for byte what was read out of it before the destroy. **No uberblock**: with every ring zeroed, `roots` lists 28 headers on the mirror (80 rows before) and 18 on `raidz1` (107), and names the root of the pool's last TXG — 45 and 35, as `zdb -u` gives them for the pools before the rings were zeroed — which the default list did not hold. **The profile and the workspace**: `--like` of the surviving neighbour with `--strict-profile` finds the destroyed volume made like it (exit 3 before); a scan resumed in parts writes the index of one pass, field for field; a resume with other compressions, a state that is not the scan's, and a scan over an unfinished workspace are refused; `list` of a scan stopped at 4.4 of 96 MiB says so; a candidate with a block failing on both sides of the mirror is 99%, not 100%. `roots` leads no further yet: nothing takes a root from `roots.json`, so of a pool with no uberblock the datasets are named and a live volume is not extracted by its name. |
| 2026-11-24 | Ubuntu 24.04.5 LTS (container, no kernel ZFS): a pool made through `libzpool` driven from a script | 2.2.2 | `0.9.16`+ (`32c9909`) | F-64 with F-65: no label and no uberblock left, the layout in `--hints` (not on a kernel) | ☑ | By hand, on a mirror of two file vdevs with all four labels of each zeroed whole — configuration and uberblock rings — so that `zvolrescue list --hints` ends "no verified uberblock", exit 3. `zvolcarve roots` and `scan` into one workspace: `roots` names four datasets over 28 headers and lists the two the newest (TXG 45) does not name, `e1/v1` last named at TXG 28 and `e1/v2` at 31; `list` names all 42 volume candidates — 4 of `e1/keep`, 6 of `e1/v1`, 32 of `e1/v2` — each with the size the volume was made. The newest candidate of each, dumped with that size in `--size`, is byte for byte what was read out of the volume while the pool was whole: two destroyed volumes and the live one. What a root does not give yet: `zvolrescue`, `zvolfiles` and `zvoltimeline` take none, so a filesystem, a snapshot or a history of such a pool is not read. |
| 2026-11-25 | Ubuntu 24.04.5 LTS (container, no kernel ZFS): a pool made through `libzpool` driven from a script | 2.2.2 | `0.9.17`+ (`159aea7`) | F-64 with F-65, read by the other programs: no label and no uberblock left, the layout in `--hints`, the headers of `zvolcarve roots` in `--roots` (not on a kernel) | ◐ | By hand, on the pool of the row above: a mirror of two file vdevs with all four labels of each zeroed whole, where `zvolrescue list --hints` ends "no verified uberblock", exit 3. With `--roots` naming the workspace `roots` wrote, 28 headers are 28 transaction groups, TXG 4 to 45. `zvolrescue list` lists the pool at TXG 45, its name and GUID from the MOS when the hints give neither, and at `--txg 28` with the volume destroyed since; `dump` of `e1/keep`, and of the destroyed `e1/v1` and `e1/v2` by their names with no `--txg` — found at TXG 28 and 31 — is byte for byte what was read out of each while the pool was whole, exit 0; `zvoltimeline` tells the three creations and the two destructions, with the `dump` command for each that names `--roots`. Every run says it read from a header and no uberblock, with the member and the offset, and gives no time. On the same pool with its labels left, whose ring has lost TXG 13, `--roots` gives that group back beside the 27 the ring holds, which are read by their uberblocks as before. ◐ because a filesystem's files were read so only on the fixture, in CI: the root dataset of a pool made through `libzpool` holds no file tree, with or without uberblocks. Not tried: raidz, where the header and `--roots` are the same code; `--search-order` by a header, which is not done. |
| 2026-11-25 | Ubuntu 24.04.5 LTS (container, no kernel ZFS): a pool made through `libzpool` driven from a script | 2.2.2 | `0.9.17`+ (`f5c1cc3`) | F-66 from the headers of F-64: a raidz with no label and no uberblock left, its member order not known (not on a kernel) | ☑ | By hand, on a `raidz2` of five 96 MiB file vdevs at ashift 12 with an 8 MiB volume `e1/keep` and a second, `e1/v1`, written, read out and destroyed; on copies, all four labels of each member zeroed whole, and the layout in `--hints` with four of the five members out of place. `zvolrescue list --hints --search-order` ends "no order of 5 members reads this pool at all", exit 3. `zvolcarve roots` with no layout finds 9 headers, TXG 4 to 37, each "no layout", and prints the command that reads the pool at them with `--hints` and `--search-order`. With `--roots` naming its workspace, `--search-order` reads all 120 orders and settles on the order the pool was written in, the only one with no checksum mismatch; `dump` of `e1/keep` (TXG 37) and of the destroyed `e1/v1` by its name (found at TXG 12) through it is byte for byte what `libzpool` read out of each, exit 0. Through the order the hints gave, the pool's metadata still reads, parity covering the columns out of place, and every one of the 1024 blocks of `e1/v1` fails its checksum, exit 4. The originals are unchanged (`sha256sum -c`). |
| 2026-11-26 | Ubuntu 24.04.5 LTS (Claude Code cloud container, no kernel ZFS): the golden image as published, `image-v1` of `zvolrescue-testdata` | 2.4.1 (the image's builder) | `0.9.18`+ (`7f5ef23`) | G2, G3, G5; `zvolfiles` and `zvoltimeline` against the kernel's reading for the first time | ☑ | By hand, `run-matrix.py` over the release files `--print-needs` names: **70 manifests, 70 pass**, inputs unchanged, 41 minutes; volumes 16 bit-exact, 41 reconstructed, 8 partial, 5 refused. For the first time every case also judges `zvolfiles` — every filesystem extracted, every entry held against `oracle/golden/files.json`, what the ubuntu-26.04 runner's kernel read with the pool imported read-only (`oracle-capture.yml`, `what = files-history`) — and `zvoltimeline`, against `zpool history -il` and the recorded GUIDs: files 22 bit-exact, 39 reconstructed, 5 partial (each entry not whole said so by `zvolfiles`), 4 refused; history 68 bit-exact, 2 refused. The control (`control-undamaged`) reads every volume, every file of every filesystem and of its twelve snapshots, and the history, bit-exact; noise past the last metaslab of every member (`range = "slack"`) is bit-exact. Open: after passing a forged TXG over, `zvolfiles` ends 4 where `dump` ends 0. The first full run found the history judge's own fault — a stale member reaches back past a rename, and the volume is rightly named as it was then — not the tool's. Report in `zvolrescue-testdata/reports/image-v1-r3`. |
| 2026-11-26 | Ubuntu 24.04.5 LTS (Claude Code cloud container, no kernel ZFS): the golden image as published, `image-v1` of `zvolrescue-testdata` | 2.4.1 (the image's builder) | `0.9.18`+ (`4a95364`) | G2, G3, G5; the exit status after a TXG passed over | ☑ | By hand, as the run above, after `dump` and `list` were made to end 4 when the newest TXG that names a volume, or the pool or the tree it is under, does not read and an older one is used, as `zvolfiles` did: **70 manifests, 70 pass**, inputs unchanged, 40 minutes; volumes 16 bit-exact, 41 reconstructed, 8 partial, 5 refused; files 22 bit-exact, 40 reconstructed, 4 partial, 4 refused; history 68 bit-exact, 2 refused. Two cases pass a TXG over, now with exit 4 and the bytes judged: `labels-forged-txg` (the forged TXG 5018, for every volume and filesystem — its files `reconstructed` where the run above had them `partial`) and `metadata-dnode-block-every-copy` (`golden/vm/disk-64k`, the newer TXGs whose dnode block lost every copy). Report in `zvolrescue-testdata/reports/image-v1-r4`. |
| 2026-11-26 | Ubuntu 24.04.5 LTS (Claude Code cloud container, no kernel ZFS): the golden image as published, `image-v1` of `zvolrescue-testdata` | 2.4.1 (the image's builder) | `0.9.18`+ | G2, G3, G5; `list` and `scan` against zdb's records for the first time | ☑ | By hand, as the run above, with the matrix judging two answers more in every case: the datasets `list -r` names against `zdb -t T -d` at the TXG it listed at, and what `scan -vv` read of each member's label, of the uberblock and of the top-level vdevs against `zdb -l`, `zdb -u` and `zpool status`. **70 manifests, 70 pass**, inputs unchanged, 40 minutes; volumes, files and history as above; datasets 68 bit-exact, 2 refused (every ring or every label configuration gone, where `list` refuses too); scan 56 bit-exact, 14 refused (a member none of whose labels read, or the uberblock no copy of which is left). On the control `list` read all 13 TXGs of the ring zdb recorded, each as zdb named it, and every TXG at which zdb's listing changes is one it names. The judges were checked against a tampered oracle first — a creation TXG, a dataset made up, a label's `asize`, the uberblock's timestamp, the dRAID's data disks — each a defect. Report in `zvolrescue-testdata/reports/image-v1-r5`. |
| 2026-11-27 | Ubuntu 24.04.5 LTS (Claude Code cloud container, no kernel ZFS): the golden image as published, `image-v1` of `zvolrescue-testdata` | 2.4.1 (the image's builder) | `0.9.18`+ | G2, G3, G5; all five programs judged for the first time | ☑ | By hand, as the run above, with the matrix judging besides: the features `list` names against the refcounts zdb verified and `zpool get all`; every slot of every label's uberblock ring `scan -vv` read, against `zdb -lu` of each member (the oracle's new `labels-uberblocks/`), the uberblock of the export and the pool's version, GUID and ashifts; the report `zvolreport` builds of each case's runs, and verifies; and the volumes `zvolcarve` carves where no ring or no label configuration is left, or the key is wrong or missing, by their bytes. **70 manifests, 70 pass**, inputs unchanged, 44 minutes; volumes, files, history and datasets as above (the features with them); scan 49 bit-exact, 21 refused — the seven more than above are rings: a member put back as an older copy of itself holds other TXGs' slots, which zdb's record says nothing of, and one whose rings were wiped has none of zdb's to verify; report 70 bit-exact; carve bit-exact on the control and both key cases, partial where every ring is gone (the blake3, skein and edonr volumes refused, saying the pool's salt is in the MOS none read), refused where every label configuration is gone. The new judges were checked against a tampered oracle first — a feature's refcount, a ring slot's `guid_sum`, a label's slot and `ashift` — each a defect. Report in `zvolrescue-testdata/reports/image-v1-r6`. |
| 2026-11-27 | Ubuntu 26.04.1 LTS (GitHub Actions `ubuntu-26.04` runner, in-tree OpenZFS module): the second golden image built by its kernel, `golden-v2`, and the damage matrix over it | 2.4.1 | `0.9.18`+ (`7e21a1e`) | G1, G2, G3, G5 | ☑ | The `golden` job of `realworld.yml`, run 45994052548: `build-image.sh` with golden-v2's recipe — image-v1's three top-level vdevs and 1.19 GB allocated (33%), 15 volumes (128K, `copies=2`, `checksum=off`, `zstd-fast` among them, written with content their compression shrinks), `fs-tree` (a fat-ZAP directory, mixed case, formD, hard and long symbolic links, a sparse file of 1100 MiB, 4K records two indirect levels deep, spill blocks, a FIFO and device nodes), cloned blocks (`bclonesaved` 24.7 MB, one clone into another dataset by `copy_file_range`), a promotion, rollbacks, destroys — built in 11 minutes with the whole oracle (zdb offline over the exported members, `zdb -dddddd` one file a dataset, the files and the history through a read-only import); every volume of the intact image read to the kernel's hash first. Then **70 manifests, 70 pass**, inputs unchanged, 63 minutes: volumes 42 reconstructed, 15 bit-exact, 9 partial, 4 refused; the `checksum=off` volume `unverified` in the 19 cases whose damage overwrites data unannounced, bit-exact on the control; files, history, datasets, scan, report and carve as on image-v1; the destroyed `vm/doomed` not among the newest candidates of its block size on the control. The first two builds stopped at the clone into another dataset (FICLONE across filesystems is EXDEV), then at 68 cases the harness misjudged: snapshots a promotion moves, a TXG read in part, `dump`'s own JSON. Published by `publish-golden.yml` as the release `golden-v2` of `zvolrescue-testdata` (16 files, 2.2 GB; of the older copies, the 6 the manifests name), the oracle in `oracle/golden-v2/`, the sums pinned in `tests/golden/golden-v2.SHA256SUMS`; report in `zvolrescue-testdata/reports/golden-v2`. |
| 2026-11-27 | Ubuntu 26.04.1 LTS (GitHub Actions `ubuntu-26.04` runner, in-tree OpenZFS module): the eight satellites of the golden image, built by its kernel, and their manifests | 2.4.1 | `0.9.18`+ (`a848efb`) | G5, G6 | ☑ | The `satellites` jobs of `realworld.yml`, run 46019885463: `build-satellite.sh`, a pool each — removal (three mirrors, the middle one removed), checkpoint (a volume destroyed after it), spare (a hot spare standing in for a stale disk, a replacing left unfinished), expand (raidz1 from three disks to four), special (special and dedup vdevs), ashift (9 beside 13), slog (an intent log never applied, the pool frozen), mmp (`multihost=on`) — each built in 1.5 to 3 minutes with the golden image's oracle, its matrix in under a minute. **26 manifests, 26 pass**, inputs unchanged: volumes 11 bit-exact, 10 reconstructed, 3 partial, 2 refused — the expanded raidz refused by every program (`raidz_expansion` is one this build does not read, SPEC F-70), and the pool whose special vdev is gone with every copy of its metadata. In the first builds the tool read right every case that ran; what failed was the build — members of 128 MiB ran out of space to OpenZFS's slop — and the harness: slots under replacement, vdevs of the special, dedup and log classes and of one device as `zpool status` prints them, an array of one in `zdb -l`, a snapshot `list` said it could not read the kind of, the heartbeat's slot of a multihost ring (`txg % 31`), the checkpoint's uberblock `zdb -u` prints after the pool's, and a frozen pool's blocks of TXGs that never committed. Published by `publish-golden.yml` as the releases `sat-<name>-v1` of `zvolrescue-testdata` (0.59 GB in all, 54 to 97 MB each), the oracles in `oracle/sat-<name>/`, the sums pinned in `tests/golden/sat-<name>-v1.SHA256SUMS`; reports in `zvolrescue-testdata/reports/sat-<name>-v1`. |
| 2026-11-27 | Ubuntu 26.04.1 LTS (GitHub Actions `ubuntu-26.04` runner, in-tree OpenZFS module): pools of the feature sets of older OpenZFS, made by this one | 2.4.1 | `0.9.18`+ (`3fb0750`) | G5, G6 | ☑ | The `satellites` jobs of `realworld.yml`, run 46034346499: `build-satellite.sh` with `compat20` (a raidz1 created with `compatibility=openzfs-2.0-linux`), `nofeatures` (a mirror created with `-d`, version 5000 and every feature disabled) and `v28` (a raidz2 of version 28, before feature flags; the last two compressing with lzjb). **7 manifests, 7 pass** at the first build, inputs unchanged: the version-28 pool read whole by every program — its volumes, files and history, its datasets at every TXG of its rings, its labels and uberblocks, its report and its carve — and through parity with two members gone and with a member's written space zeroed. Published as `sat-compat20-v1`, `sat-nofeatures-v1` and `sat-v28-v1` (0.19 GB), pinned and judged weekly by `golden-published`. |
| 2026-11-27 | FreeBSD 15.1-RELEASE (a `vmactions` VM on a GitHub Actions runner, OpenZFS from base): a satellite made on FreeBSD on GPT partitions, its manifests run on the runner | 2.4.2 | `0.9.18`+ (`81e4711`) | G5, G6 | ☑ | The `satellite-freebsd` job of `realworld.yml`, run 46037623346: `build-satellite.sh freebsd` — three md-backed disks each laid out as the installer lays one out (a GPT, freebsd-boot of 512 KiB, freebsd-zfs aligned to 1 MiB labelled `gpt/fbsdN`), a raidz1 on the labels, the oracle captured on FreeBSD (zdb over `/dev/gpt`, the files through a read-only import, no extended attributes read) — then the matrix on the runner over the whole disks, each vdev 1 MiB in. **4 manifests, 4 pass** at the first build, inputs unchanged: the control bit-exact by every program, a disk absent and part of one zeroed reconstructed, one disk's protective MBR and primary GPT zeroed bit-exact. Published as `sat-freebsd-v1` (45 MB), pinned and judged weekly. |
| 2026-11-27 | Ubuntu 26.04.1 LTS (GitHub Actions `ubuntu-26.04` runner, in-tree OpenZFS module): a satellite at scale, over 2,000 datasets | 2.4.1 | `0.9.18`+ (`73c366e`) | G5, G6 | ☑ | The `satellites` job of `realworld.yml`, run 46043707787: `build-satellite.sh scale` — a mirror of two 512 MiB members, 200 filesystems under `fs`, ten rounds each a recursive snapshot, 2,255 datasets and snapshots in all — built in 2 minutes, its matrix of two manifests in 16½ (every program over every dataset; each of the other satellites' takes under one). **2 manifests, 2 pass**, inputs unchanged, both held out: the control bit-exact by every program, half of one member's written space zeroed reconstructed. At the first build every program read it right and the harness did not: so many records had wrapped the pool's history (a ring of a thousandth of its space, that keeps what the creation logged and the newest of the rest), which had lost the creation of 986 datasets, and the timeline judge took the tool's dates of them for a defect; it now holds them to `zfs get createtxg,origin`. Its oracle keeps of `zdb -dddd` each dataset's line (8.4 MB, not 25). Published as `sat-scale-v1` (90 MB), pinned, and in `golden-published` marked `held`: run by `only: published-held-out` alone. |
