# Debugging on a test pool

**Ukrainian version:** [DEBUGGING.uk.md](DEBUGGING.uk.md)

`zvolrescue` has been verified on synthetic fixtures. The first real
pool will disagree with it somewhere — an nvlist type it has not seen, a
ZAP leaf layout detail, a feature flag. This page is the loop for
finding out *where*, on a throwaway pool inside a virtual machine.

Everything below is read-only with respect to the pool devices except
the steps that deliberately build or damage the *test* pool.

## 1. Build a test pool

FreeBSD (memory disks):

```sh
truncate -s 256m /tmp/m0.img /tmp/m1.img
mdconfig -a -t vnode -f /tmp/m0.img -u 10
mdconfig -a -t vnode -f /tmp/m1.img -u 11
zpool create -o ashift=12 tpool mirror md10 md11
zfs create tpool/vm
zfs create -V 32m -o volblocksize=8k tpool/vm/disk0
dd if=/dev/random of=/dev/zvol/tpool/vm/disk0 bs=8k count=1024 conv=sync
sha256 /dev/zvol/tpool/vm/disk0            # remember this
zfs snapshot tpool/vm/disk0@before
zpool export tpool
```

Linux (loop devices) is the same with `losetup -f --show /tmp/m0.img`
in place of `mdconfig`, `/dev/loop*` in place of `md*`, and `sha256sum`.

Export the pool before reading it with `zvolrescue`: an imported pool
keeps writing uberblocks, and the labels you look at will move under
you. After export the images `/tmp/m0.img`, `/tmp/m1.img` are the
evidence.

## 2. Compare `scan` with `zdb`

```sh
zvolrescue -vv scan /tmp/m0.img /tmp/m1.img > scan.txt
zdb -l /tmp/m0.img                             # labels + nvlist
zdb -lu /tmp/m0.img                            # + uberblocks
```

What must agree:

| `zvolrescue -vv scan` | `zdb -l` / `-lu` |
|---|---|
| pool name, `pool_guid`, `guid`, `top_guid`, `txg`, `hostname` | the same keys in every label |
| `ashift`, `vdev_tree` children and their `path`/`guid` | `vdev_tree` |
| `features_for_read` | `features_for_read` |
| per-label uberblock `txg`/`timestamp`, best txg | `Uberblock[N]` lines; `zdb -lu` prints them all |
| config checksum `ok` on all four labels | `zdb` prints nothing on success; `failed to unpack label` on failure |

If any nvlist key is missing or garbled in `-vv`, the XDR parser is
wrong for that type: run with `--debug` and look at the `[label]` line —
a parse error prints the first 64 bytes of `vdev_phys`; compare with
`zdb -l` and `hexdump -C -s $((16*1024)) -n 256 /tmp/m0.img`.

## 3. Compare `list` with `zdb -d`

```sh
zvolrescue list -r /tmp/m0.img /tmp/m1.img
zdb -e -p /tmp -d tpool                       # -e/-p: exported pool from images
zdb -e -p /tmp -dddd tpool/vm/disk0           # objects of one dataset
```

`zdb -d` prints every dataset with its object number, type and
`creation_txg`; `list` must show the same names, types, guids and
volsize. If `list` stops early, `--debug` shows the last `[dsl]`
directory it read and the `[dnode]`/`[zap]` lines after it: the object
number there is what to inspect with `zdb -e -p /tmp -dddd tpool <obj>`.

## 4. Compare `dump` with the original

```sh
zvolrescue dump tpool/vm/disk0 /tmp/m0.img /tmp/m1.img -o /tmp/disk0.img --debug-log /tmp/trace.log
sha256 /tmp/disk0.img                          # equals the hash from step 1
```

A mismatch with no unreadable blocks reported means a block was
decoded wrong (compression, byte order, or block tree). Find the first
differing offset with `cmp /tmp/disk0.img /dev/zvol/tpool/vm/disk0`
(re-import the pool for that), divide by `volblocksize` to get the
block id, then in `/tmp/trace.log` look for `locate blkid N` and the
`[zio] read bp` lines that follow: they print the DVA, sizes,
compression and checksum of every block that was read for it.

## 5. Reading a `--debug` trace

Each line is `[module] …`. Modules in reading order:

| Tag | What it reports |
|---|---|
| `cli` | version and argv |
| `label` | per label: config checksum, nvlist result, `ashift` → uberblock slot shift, best label |
| `uberblock` | per slot: txg, timestamp, checksum, root pointer birth |
| `pool` | assembled pools, top-level vdevs, member present/missing |
| `txg` | the verified uberblocks `txg@devN/Lx` chosen from |
| `dsl` | MOS root pointer, object directory, every DSL directory and dataset visited |
| `dnode` | every dnode fetched: object number, type, levels, pointers, block size, bonus |
| `dmu` | block-tree walks: level, index, child pointer or HOLE |
| `zio` | every block read: pointer summary, each DVA/device attempt, checksum result; expected vs computed words and a hex dump on mismatch, hex dump on decompression failure |
| `zap` | block kind, header fields, leaf blocks, entry names |
| `zvol` | extraction geometry and every unreadable block |

The hex dumps use `hexdump -C` layout with the *device* offset (label
offset, or `4 MiB + DVA offset` for data), so the same bytes can be
pulled out with `hexdump -C -s OFFSET -n 64 /tmp/m0.img`.

## 6. Damage experiments

Every fault the tool must survive can be injected into the *images*
(never into a live pool) and then read back:

```sh
# damage one label's nvlist on member 0 — scan must fall back to the other three
dd if=/dev/urandom of=/tmp/m0.img bs=1 count=64 seek=$((16*1024 + 200)) conv=notrunc
# damage a data block on member 0 — dump must heal it from member 1 and say so
dd if=/dev/zero of=/tmp/m0.img bs=1 count=16 seek=$((4*1024*1024 + DVA_OFFSET)) conv=notrunc
```

`DVA_OFFSET` comes from the `[zio] read bp … dvas [vdev 0 off 0x…]`
line of a previous `--debug` run. Compare the `--debug` output before
and after: the `[zio]` line for that block must switch from
`checksum Ok` on device #0 to `Mismatch` followed by `Ok` on device #1.

## 7. What to send in a bug report

`zvolrescue -f json -vv scan …`, `zvolrescue --debug-log trace.log …`
for the failing command, and the matching `zdb -l` / `zdb -e -p … -d`
output. None of these contain volume data; the hex dumps show at most
64 bytes of the block that failed.
