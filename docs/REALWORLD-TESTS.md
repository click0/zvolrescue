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
| **Debian stable** | most common Linux host with `zfs-dkms` | zfs-dkms 2.2 (bookworm) | `apt install zfsutils-linux zfs-dkms`; loop devices |
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
| B1 | single disk, ashift 9 and 12 | `list -r` == `zdb -d`; `dump` == `sha256` of `/dev/zvol/...` |
| B2 | mirror-2, one member absent | same, from the remaining member |
| B3 | raidz1 (3), raidz2 (4, 6), raidz3 (7) | same with `nparity` members absent |
| B4 | raidz with one member silently corrupted (`dd` over 1 MiB in the middle) | `dump` heals it, reports rebuilt blocks in `--debug` |
| B5 | pool with 2+ top-level vdevs, mixed mirror + raidz | same |
| B6 | pool with a `log` and a `cache` vdev | `scan` lists them; `dump` unaffected |
| B7 | dRAID (`draid2:8d:1s`), also with 1–2 members removed and with a distributed spare active | `list` matches `zpool list -t all`; `dump` hash matches |
| B8 | pool after `zpool attach`/`detach`/`replace` (stale labels on old disks) | `scan` shows the old member with an older txg and does not mix it in |
| B9 | whole-disk vdevs with GPT (Linux `-part1`, FreeBSD `p1`) | *needs F-06*: `scan` of the whole disk finds the ZFS partition |

### C. Data properties

| # | Property | Pass criterion |
|---|---|---|
| C1 | `compression=off,lz4,zstd,zstd-19,gzip-1,gzip-9,lzjb,zle` on the volume | `dump` hash matches for each |
| C2 | `checksum=fletcher2,fletcher4,sha256,sha512,skein,edonr,blake3` | matches; `skein`/`edonr` *pending F-21* |
| C3 | `volblocksize=4K,8K,16K,64K,128K,1M` (needs `large_blocks`) | matches |
| C4 | sparse volume with holes, `zfs create -s -V 100G`, 1 GiB written | image is sparse, `du` small, hash matches |
| C5 | `dedup=on` volume with repeated content | matches |
| C6 | volume with snapshots and a clone; `dump` of `vol@snap` and of the clone | each matches its own hash |
| C7 | encrypted volume (`encryption=aes-256-gcm`) with `--key raw:FILE` | *phase 3*; without key: exit 64 today |
| C8 | large dnodes (`dnodesize=auto`) on the parent filesystem | `list` unaffected |
| C9 | pool with 100+ datasets, deep nesting, long names (`longname` on FreeBSD 15) | `list -r` complete, matches `zdb -d` |

### D. Recovery

| # | Scenario | Pass criterion |
|---|---|---|
| D1 | `zfs destroy vol`, export immediately | `list --diff` shows it destroyed; `dump` recovers from the previous txg, hash matches |
| D2 | `zfs destroy vol`, then keep writing 500 MiB elsewhere, export | either recovered from an older txg still in the ring, or a clean "not found at any of N txgs" |
| D3 | `zpool destroy pool` | `scan` shows state DESTROYED; `list`/`dump` still work |
| D4 | pool that does not import (`zpool import` → "I/O error") after zeroing labels L0/L1 on one member | `scan` uses L2/L3; `dump` works |
| D5 | pool whose newest uberblock is damaged (zero the slot) | `list` uses the previous verified txg and says so |
| D6 | interrupt `dump` with SIGINT at ~50 %, then `--resume` | final hash matches, `resumed_from_block` > 0 |
| D7 | `dump -r pool/vm` with 5 volumes | 5 images + manifest, hashes match |

### E. Scale and packaging

| # | Scenario | Pass criterion |
|---|---|---|
| E1 | 2 TB volume on a 4-disk raidz2 of HDDs | throughput ≥ 40 % of raw read (SPEC N-08); RSS ≤ 512 MiB |
| E2 | 200 GB volume on NVMe mirror | throughput ≥ 70 % of raw read |
| E3 | static binary built on Ubuntu runs on mfsBSD (FreeBSD) — *no*, needs a FreeBSD build; verify the FreeBSD static build runs on mfsBSD 14 and 15 | `zvolrescue --version` and a `scan` |
| E4 | `pkg`/ports build on FreeBSD; `.deb` on Debian/Ubuntu; AUR on CachyOS | installs, `man zvolrescue` present (*packaging pending*) |

### F. Hardware

Different controllers and drives change what a "read" means; the tool
must never rely on the device's sector size or on the pool's `ashift`
matching it.

| # | Scenario | Pass criterion |
|---|---|---|
| F1 | 512n, 512e (4 KiB physical / 512 logical) and 4Kn drives, pools with `ashift=9` and `ashift=12` on each | `scan` reports the pool's `ashift`, reads use the label geometry only; hashes match on all six combinations |
| F2 | Same pool images read through a USB/UAS bridge that translates sectors (4K↔512), and directly | identical output; if the bridge changes the apparent device size, `scan` still finds L2/L3 via the size the OS reports |
| F3 | HBA in JBOD/IT mode (LSI/Broadcom, Adaptec) vs. the same disks on onboard AHCI | identical output |
| F4 | RAID controller exposing a passthrough/"single-disk RAID0" volume with metadata at the disk end | `scan` finds the four labels at the *reported* device size or warns which labels are missing |
| F5 | NVMe (several vendors), SATA SSD, SAS | identical output; throughput per E1/E2 |
| F6 | SMR (shingled) HDD vs. CMR | identical output; long sequential reads do not time out; note throughput |
| F7 | Drive with known bad sectors (or `dm-flakey`/`dm-error` on Linux, `gnop -e 5 -r 10` on FreeBSD injecting EIO) under a mirror | `dump` heals from the other member; without redundancy the unreadable *sectors* are zeroed, not the whole block (*read per sector on EIO — to implement*) |
| F8 | Reads on a drive with 4 KiB logical sectors when the pool is `ashift=9` (created on 512e, moved to 4Kn) | reads succeed (buffered I/O); `--debug` shows unaligned offsets handled |
| F9 | Virtual disks: bhyve/QEMU virtio-blk with 512 vs 4096 logical, VMware, Hyper-V; `.img`/`.qcow2`-backed (raw only) | identical output |
| F10 | Disk larger than 2 TiB and 16 TiB (GPT, offsets above 32/64-bit sector limits) | labels found at the correct end offsets |

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
