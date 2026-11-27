#!/usr/bin/env python3
"""Run the damage matrix (SPEC §9.1) against a golden image.

    run-matrix.py --image DIR --oracle DIR --manifests DIR [--tool ...] [--walker ...]
                  [--older DIR] [--out DIR] [--only ID ...] [--held-out] [--keep]
    run-matrix.py --print-needs --oracle DIR --manifests DIR [--only ID ...] [--held-out]

For every manifest: copy the members it damages, apply the damage, hash
every input, run the tool, compare what came out with the oracle, classify
the run and re-hash the inputs.

Two judging modes, chosen by the oracle's `layout.json`:

* **dump** (`"volumes": true`) — extract every volume the oracle lists and
  compare the SHA-256 of each image with `volumes.sha256`.
* **walk** (`"volumes": false`, e.g. a ztest-built image, which has no
  zvols) — `list -r` must report exactly the datasets `zdb -d` recorded,
  and the object walker must read and verify every block of every object.

Either way the answer comes from the oracle, never from an earlier run of
the tool. Outcomes: bit-exact / reconstructed / refused / partial /
defect; exit 1 when any run is a defect. A run that ends 4 because the
newest TXG did not read and it read an older one whole (SPEC F-10,
F-20) is judged by its bytes, and the TXGs it passed over are recorded
(`passed_over`); one that passed a TXG over and ended 0 is a defect.

What an operator would tell the tool, a manifest's `[recovery]` says,
and the harness passes on to every run of the case: `assume_members`
(`--assume-member`); `hints = "layout"`, the pool's layout as the
oracle records it, in `--hints` (with `order = "reversed"`, every raidz
and dRAID group's members the other way round); `search_order`
(`--search-order`); `roots`, the object-set headers `zvolcarve roots`
finds on the damaged members (`--roots`); `key = "wrong"` or `"none"`
for the encrypted volumes. The pattern `unreadable` zeroes its range as
an imager leaves what it could not read, and marks it so in a ddrescue
map given with `--map`. The range `slack` is a member's bytes past the
last metaslab of its top-level vdev, from the oracle's `zdb -C`
capture, up to L2. All of these but `assume_members` are the
dump's: a pool with no volumes is walked by a reader that takes none of
them, and such a case is n/a there.

Where the oracle has the kernel's reading of the pool's filesystems
(`files.json`) and its history (`zpool-history-il.txt`), every case also
judges `zvolfiles` — every filesystem extracted, each entry against what
the kernel read — and `zvoltimeline` — every dataset and snapshot at the
TXG, in the manner and with the GUID the pool's record gives, every
rename, promotion and destroy inside the TXGs it read. Whatever the
manifest expects, an entry or an event presented as right that is not
is a defect; `expect.files` and `expect.timeline` say more where the
redundancy does. A case that damages and tells nothing (the control)
judges every snapshot's files too.

Where the oracle has what `zdb -t T -d` named at each of the newest
TXGs (`datasets-by-txg/`), every case also holds `list -r` against it at
the TXG the list was taken at: every dataset with its kind, object
number, creation TXG and referenced size as zdb prints it, and nothing
zdb does not name. A listing zdb contradicts is a defect; one that ends
4 naming the parts of the tree it could not read is partial. The
control lists at every TXG it can read that zdb recorded (`--txg`), and
each TXG at which zdb's listing changes must be one `list` names. The
features it reports are held against `zpool get feature@`
(`zpool-get-all.txt`) and the refcounts zdb verified at the same TXG.

Where the oracle has `zdb -l` of each member (`labels/`), `zdb -u` and
`zpool status`, every case also holds `scan -vv` against them: the
nvlist of the label it read of each member, every key but the state and
the TXG it was written at — an older copy of a member says otherwise of
those — and on the control those too, with all four labels read; every
copy of the uberblocks `zdb -u` printed (`zdb-u.txt`, and of the
exported pool `zdb-u-export.txt`) that verifies, its version, GUID sum,
timestamp, root block's birth and checkpoint TXG; every slot of every
label's ring that verifies against what `zdb -lu` printed of that slot
(`labels-uberblocks/`), unless it holds another TXG — a slot forged, an
older copy of a member — and on the control every slot; each top-level
vdev it assembled, its kind, parity, dRAID geometry, GUID and number of
leaves, the pool's version, GUID and ashifts against `zdb -C`
(`pool-facts.txt`), and on the control their paths. A label or an uberblock that
verifies and says other than zdb read, or a top-level vdev assembled
otherwise, is a defect; a member none of whose labels read, refused.

Every `dump` of a case writes to one evidence log, and `zvolreport`
builds a report of it and verifies it: what the report says of each
volume must be what the harness found, and everything it records must
verify — on the control, and fail where a byte of an output is turned
over. On the control, and on a case whose every volume `dump` refused,
`zvolcarve scan` looks for every volume dnode, and each live volume the
oracle hashes, the encrypted ones aside, must be found by its bytes
among the newest candidates of its block size carved at its size; on
the control one not found is unexpected.

A manifest that names its pool (`image = "<pool>"`, the name the
oracle's `layout.json` gives) runs against that pool alone; one that
names none runs against any. `--print-needs` runs nothing: it prints
the release files the selected manifests need of the oracle's image,
one per line — every member, since no part of a pool reads without the
rest, and the older copy of each member an `older-self` damage names —
for `fetch-image.sh` to fetch those and no others.
"""
import argparse
import collections
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import struct
import sys
import tempfile
import time
import tomllib

UNITS = {"": 1, "K": 1024, "KiB": 1024, "M": 1 << 20, "MiB": 1 << 20, "G": 1 << 30, "GiB": 1 << 30}
LABEL_START = 4 << 20
REDUNDANCY = re.compile(r"reconstruct|no present member|MISSING|combinatorial|NoMember|not present")


class Unresolved(Exception):
    """The manifest addresses something this image does not have."""


def size(s):
    m = re.fullmatch(r"(-?\d+)\s*([KMG]i?B?)?", s.strip())
    if not m:
        raise ValueError(f"bad size {s!r}")
    return int(m.group(1)) * UNITS[m.group(2) or ""]


LABEL_SIZE = 256 << 10          # sizeof(vdev_label_t)
VDEV_PHYS_OFFSET = 16 << 10     # nvlist inside a label
VDEV_PHYS_SIZE = 112 << 10
UBERBLOCK_OFFSET = 128 << 10    # uberblock ring inside a label
UBERBLOCK_SIZE = 128 << 10


def label_offsets(length):
    """Where ZFS puts L0..L3 in a member of `length` bytes: the two front
    labels at the start, the two rear ones measured from the size rounded
    *down* to a whole label, which is not the same as the end of the file."""
    psize = (length // LABEL_SIZE) * LABEL_SIZE
    return [0, LABEL_SIZE, psize - 2 * LABEL_SIZE, psize - LABEL_SIZE]


def label_ranges(spec, length):
    """`label:L0,L1` / `label:all` / `label:all/vdev_phys` / `label:L2/rings`."""
    which, _, part = spec.partition("/")
    names = ["L0", "L1", "L2", "L3"] if which in ("all", "") else which.split(",")
    offsets = label_offsets(length)
    out = []
    for name in names:
        base = offsets[["L0", "L1", "L2", "L3"].index(name.strip())]
        if base < 0 or base >= length:
            continue
        if part in ("", "whole"):
            out.append((base, min(LABEL_SIZE, length - base)))
        elif part == "vdev_phys":
            out.append((base + VDEV_PHYS_OFFSET, VDEV_PHYS_SIZE))
        elif part in ("rings", "uberblocks"):
            out.append((base + UBERBLOCK_OFFSET, UBERBLOCK_SIZE))
        else:
            raise ValueError(f"unknown label part {part!r}")
    if not out:
        raise Unresolved(f"label range {spec!r} falls outside a {length}-byte member")
    return out


UBERBLOCK_MAGIC = 0x00ba_b10c          # "oo-ba-bloc", little-endian on this image
ZEC_MAGIC = 0x0210_da7a_b10c_7a11      # zio_eck_t magic at the end of a sealed slot
ECK_SIZE = 40                          # magic plus four checksum words
BLKPTR_OFFSET = 40                     # ub_rootbp
BLKPTR_BIRTH = BLKPTR_OFFSET + 80      # blk_birth
BLKPTR_CKSUM = BLKPTR_OFFSET + 96      # blk_cksum, four words


def seal_uberblock_slot(slot, vdev_offset):
    """The embedded checksum ZFS writes at the end of an uberblock slot
    (ZIO_CHECKSUM_LABEL): SHA-256 over the slot with the checksum words
    replaced by a verifier — the slot's own byte offset in the vdev — and
    the digest stored as four big-endian words. A slot copied anywhere
    else fails it, which is what makes the offset part of the evidence."""
    buf = bytearray(slot)
    eck = len(buf) - ECK_SIZE
    buf[eck:eck + 8] = ZEC_MAGIC.to_bytes(8, "little")
    buf[eck + 8:eck + ECK_SIZE] = vdev_offset.to_bytes(8, "little") + bytes(24)
    digest = hashlib.sha256(buf).digest()
    for i in range(4):
        word = int.from_bytes(digest[i * 8:i * 8 + 8], "big")
        buf[eck + 8 + i * 8:eck + 16 + i * 8] = word.to_bytes(8, "little")
    return bytes(buf)


def uberblock_slot(slot, vdev_offset):
    """(txg, timestamp) of a slot that carries the magic and verifies at
    `vdev_offset`, else None."""
    if int.from_bytes(slot[0:8], "little") != UBERBLOCK_MAGIC:
        return None
    if seal_uberblock_slot(slot, vdev_offset) != bytes(slot):
        return None
    return int.from_bytes(slot[16:24], "little"), int.from_bytes(slot[32:40], "little")


def forge_uberblock(f, off, length, bump, ashift):
    """`forged-txg:<bump>` on one ring: the ring's newest verified
    uberblock, copied into the slot ZFS would write txg+bump to (txg
    modulo the ring's slot count), with that txg, that birth in its root
    pointer, and the root pointer's checksum words inverted, then sealed
    for its new slot. Every word of the forged slot verifies — the ring
    says a newer state of the pool exists — and the object set behind it
    matches no block, which is what a sync whose uberblocks reached the
    disk and whose MOS did not leaves behind. Returns (txg forged from,
    forged txg, slot index)."""
    slot_size = 1 << min(max(ashift, 10), 13)
    count = length // slot_size
    f.seek(off)
    ring = f.read(length)
    best = None
    for i in range(count):
        s = ring[i * slot_size:(i + 1) * slot_size]
        key = uberblock_slot(s, off + i * slot_size)
        if key and (best is None or key > best[0]):
            best = (key, s)
    if best is None:
        raise Unresolved(f"ring at {off} has no verified uberblock to forge from")
    (txg, ts), s = best
    if bump % count == 0:
        raise ValueError(f"forged-txg:{bump} would land on the slot it is forged from")
    forged = bytearray(s)
    new_txg = txg + bump
    forged[16:24] = new_txg.to_bytes(8, "little")
    forged[32:40] = (ts + bump).to_bytes(8, "little")
    forged[BLKPTR_BIRTH:BLKPTR_BIRTH + 8] = new_txg.to_bytes(8, "little")
    for i in range(4):
        at = BLKPTR_CKSUM + i * 8
        word = int.from_bytes(forged[at:at + 8], "little") ^ 0xffff_ffff_ffff_ffff
        forged[at:at + 8] = word.to_bytes(8, "little")
    index = new_txg % count
    f.seek(off + index * slot_size)
    f.write(seal_uberblock_slot(bytes(forged), off + index * slot_size))
    return txg, new_txg, index


def allocated_extents(path):
    """The written parts of a sparse member, label areas excluded, so that
    `data:` damage lands where ZFS actually put something."""
    length = os.path.getsize(path)
    head = 4 << 20                       # boot block and the front labels
    tail = (length // LABEL_SIZE) * LABEL_SIZE - 2 * LABEL_SIZE
    out, pos = [], head
    fd = os.open(path, os.O_RDONLY)
    try:
        while pos < tail:
            try:
                start = os.lseek(fd, pos, os.SEEK_DATA)
            except OSError:
                break
            if start >= tail:
                break
            try:
                stop = min(os.lseek(fd, start, os.SEEK_HOLE), tail)
            except OSError:
                stop = tail
            if stop > start:
                out.append((start, stop))
            pos = max(stop, start + 1)
    finally:
        os.close(fd)
    return out


def data_ranges(spec, path):
    """`data:20%..40%` — that slice of the member's written space."""
    extents = allocated_extents(path)
    total = sum(b - a for a, b in extents)
    if not total:
        raise Unresolved("member has no written space outside the labels")
    a, _, b = spec.partition("..")
    frm = int(round(float(a.rstrip("%")) / 100 * total))
    to = int(round(float(b.rstrip("%")) / 100 * total)) if b else total
    out, seen = [], 0
    for start, stop in extents:
        n = stop - start
        lo, hi = max(frm - seen, 0), min(to - seen, n)
        if hi > lo:
            out.append((start + lo, hi - lo))
        seen += n
    if not out:
        raise Unresolved(f"data range {spec!r} selected nothing")
    return out


def span_ranges(spec, length):
    """`span:5%..25%` — that slice of the member's data area (everything
    between the boot block and front labels and the rear labels). Unlike
    `data:` this is the same byte range on every member, which is what a
    test of "the same place on two members" needs."""
    head = 4 << 20
    tail = (length // LABEL_SIZE) * LABEL_SIZE - 2 * LABEL_SIZE
    if tail <= head:
        raise Unresolved("member too small to have a data area")
    a, _, b = spec.partition("..")
    total = tail - head
    frm = head + int(round(float(a.rstrip("%")) / 100 * total))
    to = head + int(round(float(b.rstrip("%")) / 100 * total)) if b else tail
    return [(frm, max(to - frm, 0))]


ROWHEIGHT = 16 << 20            # VDEV_DRAID_ROWHEIGHT


def zdb_tops(text):
    """The top-level vdevs of a `zdb -C` capture, in `vdev_tree`'s order:
    each one's `key: value` lines, and `children`, how many it has.

    >>> cap = '''MOS Configuration:
    ...         com.delphix:has_per_vdev_zaps
    ...         vdev_tree:
    ...             type: 'root'
    ...             children[0]:
    ...                 type: 'raidz'
    ...                 nparity: 2
    ...                 com.delphix:vdev_zap_top: 133
    ...                 children[0]:
    ...                     type: 'file'
    ...                     path: '/var/tmp/a:b.img'
    ...                 children[1]:
    ...                     type: 'file'
    ...             children[1]:
    ...                 type: 'mirror'
    ...                 children[0]:
    ...                     type: 'file'
    ...         version: 5000
    ...             children[0]:
    ... '''
    >>> [(t["type"], t.get("nparity"), t["children"]) for t in zdb_tops(cap)]
    [('raidz', '2', 2), ('mirror', None, 1)]
    """
    tops, top, base, level, inner = [], None, None, None, None
    for line in text.splitlines():
        m = re.match(r"(\s*)(\S+):(?:\s+(.*))?$", line)
        if not m:
            continue
        indent, key, value = len(m.group(1)), m.group(2), m.group(3)
        if base is None:
            if key == "vdev_tree" and value is None:
                base = indent
            continue
        if indent <= base:
            break
        if level is None:
            level = indent
        if indent == level:
            top = None
            if key.startswith("children[") and value is None:
                top, inner = {"children": 0}, None
                tops.append(top)
            continue
        if top is None:
            continue
        if inner is None:
            inner = indent
        if indent == inner:
            if key.startswith("children[") and value is None:
                top["children"] += 1
            elif value is not None:
                top[key] = value.strip("'")
    return tops


def metaslab_end(top):
    """How far into each child's data area a top-level vdev's metaslabs
    reach: `asize >> metaslab_shift` whole metaslabs from its start, the
    remainder of `asize` never allocated, mapped onto a child the way
    the vdev maps any offset. A mirror's offset is its children's; a
    raidz's sector `s` is in row `s / children`; a dRAID's group `g` is
    `groupwidth` columns from column `g * groupwidth` of rows of
    `ROWHEIGHT`, wrapping at `ndisks` (`vdev_draid_logical_to_physical`),
    and a group partly in a metaslab counts whole.

    >>> metaslab_end({"type": "mirror", "asize": "532152320", "metaslab_shift": "25", "ashift": "12", "children": 2}) >> 20
    480
    >>> metaslab_end({"type": "raidz", "asize": "2128609280", "metaslab_shift": "27", "ashift": "12", "children": 4}) >> 20
    480
    >>> metaslab_end({"type": "draid", "asize": "1459617792", "metaslab_shift": "27", "ashift": "12", "children": 4,
    ...               "nparity": "1", "draid_ndata": "2", "draid_nspares": "1"}) >> 20
    432
    """
    shift = int(top["metaslab_shift"])
    used = (int(top["asize"]) >> shift) << shift
    if not used:
        return 0
    if top["type"] == "raidz":
        sectors = used >> int(top["ashift"])
        return ((sectors - 1) // top["children"] + 1) << int(top["ashift"])
    if top["type"] == "draid":
        width = int(top["draid_ndata"]) + int(top["nparity"])
        ndisks = top["children"] - int(top["draid_nspares"])
        group = (used - 1) // (width * ROWHEIGHT)
        return (((group + 1) * width - 1) // ndisks + 1) * ROWHEIGHT
    return used


def ranges_for(spec, path, length, reference=None):
    """`reference` is the smallest member of the image: `span:` percentages
    are measured against it so that the same span means the same bytes on
    every member, whatever their individual sizes."""
    if spec.startswith("label:"):
        return label_ranges(spec[len("label:"):], length)
    if spec.startswith("data:"):
        return data_ranges(spec[len("data:"):], path)
    if spec.startswith("span:"):
        out = []
        for off, n in span_ranges(spec[len("span:"):], reference or length):
            n = min(n, max(length - off, 0))
            if n:
                out.append((off, n))
        if not out:
            raise Unresolved(f"span {spec!r} falls outside a {length}-byte member")
        return out
    start, end = parse_range(spec, length)
    return [(start, end - start)]


def parse_range(spec, length):
    a, b = spec.split("..")
    start = size(a) if a else 0
    end = size(b) if b else length
    if start < 0:
        start += length
    if end < 0:
        end += length
    if start >= length:
        raise Unresolved(f"range {spec} starts past the end of a {length}-byte member")
    end = min(end, length)
    if start < 0 or end < start:
        raise ValueError(f"bad range {spec}")
    return start, end


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sparse_copy(src, dst):
    if sys.platform.startswith("linux"):
        subprocess.run(["cp", "--sparse=always", "--reflink=auto", src, dst], check=True)
    else:
        shutil.copyfile(src, dst)


class Oracle:
    def __init__(self, d, image, older=None):
        self.dir, self.image = d, image
        # The same members at an earlier point of the pool's life, for
        # the `older-self` pattern: the builder writes them beside the
        # members as `<image>-round6`, and the release carries them as
        # the `round6-*` files.
        self.older = older or image.rstrip("/") + "-round6"
        self.layout = json.load(open(os.path.join(d, "layout.json")))
        self.pool = self.layout["pool"]
        self.has_volumes = bool(self.layout.get("volumes"))
        self.roles = list(self.layout["members"])
        # What the kernel read out of each filesystem and snapshot
        # (oracle-capture.yml, what = files-history), a listing that is
        # its head's or an earlier one's written once.
        self.files = {}
        fj = os.path.join(d, "files.json")
        if os.path.exists(fj):
            listed = json.load(open(fj))["datasets"]
            for name, v in listed.items():
                while "same_as" in v:
                    v = listed[v["same_as"]]
                if "entries" in v:
                    self.files[name] = v["entries"]
        # The pool's own record of its history, and every dataset's and
        # snapshot's GUID as the builder listed them at the end.
        hist = os.path.join(d, "zpool-history-il.txt")
        self.history = open(hist, errors="replace").read() if os.path.exists(hist) else ""
        self.guids = {}
        listing = os.path.join(d, "zfs-list.txt")
        if os.path.exists(listing):
            for line in open(listing):
                f = line.rstrip("\n").split("\t")
                if len(f) > 2 and f[2].isdigit():
                    self.guids[f[0]] = int(f[2])
        self.inventory = {}
        inv = os.path.join(d, "inventory.txt")
        if os.path.exists(inv):
            for line in open(inv):
                f = line.split()
                if len(f) >= 2:
                    self.inventory[f[0]] = {"creation_txg": int(f[1]), "objects": int(f[2]) if len(f) > 2 and f[2].isdigit() else None}
        self.volumes = {}
        # Every hash of every volume: at the export (the volumes judged),
        # at each snapshot, and — from golden-v2 on — just before it was
        # destroyed (`@destroyed`), with what it was then
        # (`zfs-get-destroyed.txt`).
        self.hashes = {}
        vs = os.path.join(d, "volumes.sha256")
        if os.path.exists(vs):
            for line in open(vs):
                f = line.split()
                if len(f) == 2 and "@" in f[1]:
                    vol, at = f[1].split("@", 1)
                    self.hashes.setdefault(vol, {})[at] = f[0]
                    if at == "export":
                        self.volumes[vol] = f[0]
        # A pool with a checkpoint (sat-checkpoint): its TXG, from the
        # uberblock zdb read the exported pool at, and every volume's
        # hash when it was taken.
        self.at_checkpoint = {vol: at["checkpoint"] for vol, at in self.hashes.items() if "checkpoint" in at}
        self.checkpoint_txg = None
        ue = os.path.join(d, "zdb-u-export.txt")
        if os.path.exists(ue):
            self.checkpoint_txg = zdb_checkpoint(open(ue, errors="replace").read()).get("txg")
        if self.at_checkpoint and not self.checkpoint_txg:
            raise SystemExit(f"{d}: volumes hashed at a checkpoint, and zdb-u-export.txt has no checkpointed uberblock")
        self.destroyed = {}
        gone = os.path.join(d, "zfs-get-destroyed.txt")
        if os.path.exists(gone):
            for line in open(gone, errors="replace"):
                f = line.rstrip("\n").split("\t")
                if len(f) >= 3 and f[1] in ("volsize", "volblocksize") and "destroyed" in self.hashes.get(f[0], {}):
                    self.destroyed.setdefault(f[0], {})[f[1]] = f[2]
        # Keys: the raw key (every ztest dataset; `secret-raw` of the
        # kernel-built image) and, where the image has one, the passphrase
        # of the others. Which one a volume takes comes from the oracle's
        # `zfs list` capture, by its keyformat; `self.key` stays the raw
        # one for the walker.
        self.key = None
        rk = os.path.join(d, "keys", "raw.key")
        if os.path.exists(rk):
            self.key = "raw:" + rk
        self.passphrase = None
        pw = os.path.join(d, "keys", "passphrase.txt")
        if os.path.exists(pw):
            self.passphrase = "passphrase:" + pw
        # `zfs get -r all` names every dataset's keyformat; the `zfs list`
        # capture is the fallback (the first image's was written without
        # `-r` and named the pool alone).
        self.keyformat = {}
        zg = os.path.join(d, "zfs-get-all.txt")
        if os.path.exists(zg):
            for line in open(zg):
                f = line.rstrip("\n").split("\t")
                if len(f) >= 3 and f[1] == "keyformat":
                    self.keyformat[f[0]] = f[2]
        zl = os.path.join(d, "zfs-list.txt")
        if os.path.exists(zl):
            for line in open(zl):
                f = line.rstrip("\n").split("\t")
                if len(f) >= 12:
                    self.keyformat.setdefault(f[0], f[11])
        # What `zdb -t T -d` named at each of the newest TXGs, read at
        # the newest uberblock at or before T.
        self.by_txg, self.refcounts_by_txg = {}, {}
        bt = os.path.join(d, "datasets-by-txg")
        if os.path.isdir(bt):
            for name in os.listdir(bt):
                if name.endswith(".txt") and name[:-4].isdigit():
                    text = open(os.path.join(bt, name), errors="replace").read()
                    self.by_txg[int(name[:-4])] = zdb_datasets(text)
                    self.refcounts_by_txg[int(name[:-4])] = zdb_refcounts(text)
        # At the checkpoint's TXG, the pool as the checkpoint keeps it:
        # `zdb -k -d`, its datasets under the pool's name with a suffix
        # zdb gives them. `zdb -t` of that TXG reads the newest uberblock
        # of the rings at or before it, which is not the checkpoint's.
        ck = os.path.join(d, "datasets-checkpoint.txt")
        if self.checkpoint_txg and os.path.exists(ck):
            text = open(ck, errors="replace").read().replace(self.pool + "_CHECKPOINTED_UNIVERSE", self.pool)
            self.by_txg[self.checkpoint_txg] = zdb_datasets(text)
            self.refcounts_by_txg[self.checkpoint_txg] = zdb_refcounts(text)
        # What `zpool get` said of every feature the pool has enabled,
        # at the end of the build: active or enabled, by short name.
        self.feature_states = {}
        zp = os.path.join(d, "zpool-get-all.txt")
        if os.path.exists(zp):
            for line in open(zp):
                k, _, v = line.rstrip("\n").partition("\t")
                if k.startswith("feature@") and v in ("active", "enabled"):
                    self.feature_states[k[len("feature@"):]] = v
        # What zdb read of each member's labels (`zdb -l`, the first
        # section: all four labels alike on the undamaged image), of the
        # uberblock in use when it was taken (`zdb -u`), and the
        # top-level vdevs `zpool status` named.
        self.labels = {}
        for role in self.roles:
            lp = os.path.join(d, "labels", self.layout["members"][role]["file"][:-4] + ".txt")
            if os.path.exists(lp):
                secs = zdb_labels(open(lp, errors="replace").read())
                if secs:
                    self.labels[role] = secs[0][1]
        # The uberblocks zdb printed: the one in use while the builder
        # still had the pool imported (`zdb-u.txt`), and the one it reads
        # the exported pool at (`zdb-u-export.txt`, oracle-capture.yml).
        self.uberblocks = []
        for name in ("zdb-u.txt", "zdb-u-export.txt"):
            zu = os.path.join(d, name)
            if os.path.exists(zu):
                ub = zdb_uberblock(open(zu, errors="replace").read())
                if ub and all(u["txg"] != ub["txg"] for u in self.uberblocks):
                    self.uberblocks.append(ub)
        # Every uberblock of every label's ring, member by member (`zdb
        # -lu`, oracle-capture.yml what = labels-uberblocks).
        self.rings = {}
        for role in self.roles:
            rp = os.path.join(d, "labels-uberblocks", self.layout["members"][role]["file"][:-4] + ".txt")
            if os.path.exists(rp):
                self.rings[role] = zdb_rings(open(rp, errors="replace").read())
        # `zdb -C` of the imported pool, the lines the builder kept: its
        # version, GUID, and each top-level vdev's ashift in order.
        self.pool_facts = {}
        pf = os.path.join(d, "pool-facts.txt")
        if os.path.exists(pf):
            for line in open(pf):
                k, _, v = line.strip().partition(": ")
                if k in ("version", "pool_guid") and v.isdigit():
                    self.pool_facts[k] = int(v)
                elif k == "ashift" and v.isdigit():
                    self.pool_facts.setdefault("ashift", []).append(int(v))
        # `multihost=on` (sat-mmp): the rings have a heartbeat's slot.
        self.multihost = False
        zp = os.path.join(d, "zpool-get-all.txt")
        if os.path.exists(zp):
            self.multihost = any(line.rstrip("\n") == "multihost\ton" for line in open(zp))
        zs = os.path.join(d, "zpool-status.txt")
        self.status_tops = zpool_status_tops(open(zs, errors="replace").read(), self.layout) if os.path.exists(zs) else {}
        self.zdb = ""
        zd = os.path.join(d, "zdb-dddd.txt")
        if os.path.exists(zd):
            self.zdb = open(zd, errors="replace").read()

    def path(self, role):
        return os.path.join(self.image, self.layout["members"][role]["file"])

    def older_path(self, role, source):
        """The earlier copy of a member that `older-self:<source>` names.

        `source` is `round6`: the copy the builder took of every member
        right after round 6 of the fill, which the image's release
        carries as its `round6-*` files and `fetch-image.sh` puts beside
        its members. Where the oracle has their sums
        (`members-round6.sha256`, from golden-v2 on) the copy is held to
        them, so that a copy from another image's life is never written
        over this one's members by mistake; image-v1's oracle has none,
        and there the release's pinned sums are what binds the copies to
        it. `<tag>-round6`, the form image-v1's manifests were written
        in, names the same copy when the tag is this image's."""
        tag = self.layout.get("image_tag") or ""
        if source not in ("round6", f"{tag}-round6"):
            raise Unresolved(f"older-self source {source!r} is not of this image (round6, or {tag}-round6)")
        name = self.layout["members"][role]["file"]
        p = os.path.join(self.older, name)
        if not os.path.exists(p):
            raise Unresolved(f"this image has no older-self material: {p} not found")
        if os.path.getsize(p) != os.path.getsize(self.path(role)):
            raise Unresolved(f"older-self copy {p} is not the member's size")
        sums = os.path.join(self.dir, "members-round6.sha256")
        if os.path.exists(sums):
            want = dict(reversed(line.split()) for line in open(sums) if len(line.split()) == 2).get(name)
            if want is None:
                raise Unresolved(f"members-round6.sha256 has no sum of {name}")
            if not hasattr(self, "_older_sums"):
                self._older_sums = {}
            if p not in self._older_sums:
                self._older_sums[p] = sha256_file(p)
            if self._older_sums[p] != want:
                raise Unresolved(f"older-self copy {p} is not this image's: its SHA-256 is not the one members-round6.sha256 gives")
        return p

    def slack(self, role, length):
        """`range = "slack"`: the bytes of a member past the end of its
        top-level vdev's last metaslab, as the oracle's `zdb -C` capture
        gives it, up to L2. ZFS allocates nothing outside its metaslabs,
        so nothing of the pool is there to read."""
        zc = os.path.join(self.dir, "zdb-C.txt")
        if not os.path.exists(zc):
            raise Unresolved("the oracle has no zdb -C capture, which is what places a vdev's metaslabs")
        tops = zdb_tops(open(zc).read())
        index = self.layout["members"][role]["top"]
        if index >= len(tops):
            raise Unresolved(f"the zdb -C capture has no top-level vdev {index}")
        top = tops[index]
        lacking = [k for k in ("type", "asize", "metaslab_shift", "ashift") if k not in top]
        if lacking:
            raise Unresolved(f"top-level vdev {index} has no {', '.join(lacking)} in the zdb -C capture")
        if top["type"] not in ("mirror", "raidz", "draid", "file", "disk"):
            raise Unresolved(f"top-level vdev {index} is a {top['type']}, whose offsets this harness does not map")
        start = LABEL_START + metaslab_end(top)
        end = label_offsets(length)[2]
        if start >= end:
            raise Unresolved(f"{role} has no slack: its metaslabs reach L2")
        return [(start, end - start)]

    def key_for(self, dataset):
        """The `--key` spec that unlocks `dataset`, None for a plain one.
        Without a `zfs list` capture every dataset is taken as raw-keyed,
        which is what a ztest image is."""
        default = "none" if self.keyformat else ("raw" if self.key else "none")
        kf = self.keyformat.get(dataset, default)
        if kf == "passphrase":
            return self.passphrase
        if kf in ("raw", "hex"):
            return self.key
        return None

    @property
    def min_length(self):
        if not hasattr(self, "_min_length"):
            self._min_length = min(os.path.getsize(self.path(r)) for r in self.roles)
        return self._min_length

    @property
    def widest_top(self):
        """The top-level vdev with the most members, lowest id first: where
        a manifest's bare `leaf = N` lands. On an image of one top-level
        vdev that is the only choice; on the golden image — a mirror, a
        raidz2 and a dRAID side by side — it keeps "leaves 0 and 1" of a
        manifest two members of one group, as the manifest means them,
        rather than the mirror's two halves and the raidz's third disk.
        `top = N` or `kind = …` in the manifest overrides it."""
        counts = {}
        for info in self.layout["members"].values():
            counts[info["top"]] = counts.get(info["top"], 0) + 1
        return min(counts, key=lambda t: (-counts[t], t))

    def resolve(self, spec):
        """A member reference: a role name, or {kind=…, leaf=N, top=N}."""
        if isinstance(spec, str):
            if spec in self.layout["members"]:
                return spec
            # A bare `<kind>-<i>` from a manifest written for another image.
            m = re.fullmatch(r"([a-z0-9]+)-(\d+)([a-d])?", spec)
            if m:
                leaf = int(m.group(2)) if not m.group(3) else "abcd".index(m.group(3))
                return self.resolve({"kind": m.group(1), "leaf": leaf})
            raise Unresolved(f"no member {spec!r}")
        kind, leaf = spec.get("kind"), spec.get("leaf", 0)
        top = spec.get("top")
        if top is None and not kind:
            top = self.widest_top
        for role, info in self.layout["members"].items():
            if kind and info["group_kind"] != kind:
                continue
            if top is not None and info["top"] != top:
                continue
            if info["index"] == leaf:
                return role
        raise Unresolved(f"no member matching {spec}")

    def damaged_kinds(self, manifest):
        """The group kinds of the members a manifest damages — what its
        expectation is judged by. A target it cannot place, or a manifest
        that names no member, falls back to every kind in the image."""
        kinds = set()
        for d in manifest.get("damage", []):
            try:
                if "member" in d:
                    kinds.add(self.layout["members"][self.resolve(d["member"])]["group_kind"])
                elif "target" in d:
                    for role, _, _ in self.resolve_target(d["target"]):
                        kinds.add(self.layout["members"][role]["group_kind"])
            except Unresolved:
                pass
        return kinds or {m["group_kind"] for m in self.layout["members"].values()}

    def deep(self):
        """The oracle's `zdb -dddddd` capture, read once: one file, or —
        from golden-v2 on, where it is past what a file in git should
        be — the directory split-capture.py cut it into, one file a
        dataset, which in the order of their names are the capture
        again. None without either."""
        if not hasattr(self, "_deep"):
            path = os.path.join(self.dir, "zdb-dddddd.txt")
            parts = os.path.join(self.dir, "zdb-dddddd")
            if os.path.exists(path):
                self._deep = open(path).read()
            elif os.path.isdir(parts):
                self._deep = "".join(open(os.path.join(parts, n)).read()
                                     for n in sorted(os.listdir(parts)) if n.endswith(".txt"))
            else:
                self._deep = None
        return self._deep

    def blocks_of(self, dataset, obj):
        """The block pointers of one object of one dataset from the oracle's
        `zdb -dddddd` capture: {level: [(logical offset, raw pointer text)]}
        in the order zdb printed them. `dataset` is the full name
        (`golden/vm/disk-8k`) or `mos`; `obj` the object number."""
        if self.deep() is None:
            raise Unresolved("the oracle has no zdb -dddddd capture, which is what places a block of an object")
        # A dataset may appear more than once: the pool-wide capture shows
        # an encrypted dataset without its objects, and a capture made
        # with its key, appended, shows them. The first section with
        # objects is the one.
        heads = list(re.finditer(rf"^Dataset {re.escape(dataset)} \[", self._deep, re.M))
        if not heads:
            raise Unresolved(f"dataset {dataset} is not in the zdb -dddddd capture")
        objs, section = None, None
        for head in heads:
            end = re.search(r"^Dataset ", self._deep[head.end():], re.M)
            section = self._deep[head.start():head.end() + (end.start() if end else len(self._deep))]
            objs = list(re.finditer(rf"^\s+{obj}\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.*)$", section, re.M))
            if objs:
                break
        if not objs:
            raise Unresolved(f"object {obj} of {dataset} is not in the zdb -dddddd capture (an encrypted dataset captured without its key?)")
        start = objs[0].end()
        nxt = re.search(r"^\s+Object\s+lvl", section[start:], re.M)
        body = section[start:start + (nxt.start() if nxt else len(section))]
        # zdb -dddddd writes a pointer compactly — `vdev:offset:asize` per
        # copy, a G on a gang block, `<lsize>L/<psize>P`, `cksum=` — where
        # the -dddd root pointers are spelled out. The compact form is
        # rewritten into the spelled-out one here, so that everything
        # downstream reads one shape; the checksum's name, which the
        # compact form drops, comes from the dataset's `checksum` property.
        algo = self.checksum_of(dataset)
        levels = {}
        for m in re.finditer(
                r"^\s*([0-9a-f]+)\s+L(\d)\s+((?:\d+:[0-9a-f]+:[0-9a-f]+G?\s+)+)([0-9a-f]+)L/([0-9a-f]+)P\s+F=\d+\s+B=\d+/\d+\s+cksum=([0-9a-f:]+)",
                body, re.M):
            off, level, dvas, lsize, psize, cksum = m.groups()
            gang = "G" in dvas
            raw = " ".join(f"DVA[{i}]=<{d.rstrip('G')}>" for i, d in enumerate(dvas.split()))
            raw += f" [L{level}] {algo} size={lsize}L/{psize}P cksum={cksum}" + (" gang" if gang else "")
            levels.setdefault(int(level), []).append((int(off, 16), raw))
        if not levels:
            raise Unresolved(f"object {obj} of {dataset} has no block pointers in the capture (a hole, or an embedded block)")
        return levels, objs[0].group(1)

    def checksum_of(self, dataset):
        """The dataset's `checksum` property from `zfs get -r all`, as the
        algorithm's name; `on` is fletcher4. Unknown: an empty string, and
        the pointer's checksum is then not checked."""
        zg = os.path.join(self.dir, "zfs-get-all.txt")
        if dataset == "mos":
            return "fletcher4"
        if os.path.exists(zg):
            for line in open(zg):
                f = line.rstrip("\n").split("\t")
                if len(f) >= 3 and f[0] == dataset and f[1] == "checksum":
                    return "fletcher4" if f[2] in ("on", "fletcher4") else f[2]
        return ""

    def dataset_type(self, name):
        m = re.search(rf"^Dataset {re.escape(name)} \[(\w+)\]", self.zdb, re.M)
        return m.group(1) if m else None

    def a_dataset(self):
        """A dataset of this pool to aim at, chosen from the capture
        rather than named in the manifest.

        `ztest` creates and destroys datasets as it runs, so which names
        survive into a given build is not something a manifest can know;
        naming one makes the case skip on every image where that build
        went differently. Picked for the most block-pointer copies — that
        is what a "one copy destroyed" case needs to mean anything — and
        then by name, so the same image always yields the same choice.
        """
        best = None
        for m in re.finditer(rf"^Dataset ({re.escape(self.pool)}/\S+) .*?rootbp (.*)$", self.zdb, re.M):
            name, raw = m.group(1), m.group(2)
            copies = len(re.findall(r"DVA\[\d\]=<", raw))
            if best is None or (-copies, name) < (-best[1], best[0]):
                best = (name, copies)
        if best is None:
            raise Unresolved("no dataset with a block pointer in this capture")
        return best[0]

    def resolve_target(self, target, notes=None):
        """(role, offset, length) for the chosen DVA copies of a structure,
        located from the oracle's zdb capture.

        A copy on a mirror or raidz top is placed by arithmetic; a copy on
        a dRAID top is found by content — the block's bytes, read from a
        copy that arithmetic places (and checked against the block
        pointer's checksum where that is fletcher4 or sha256), searched
        for on the dRAID's children. What that places is the block's data
        columns; its parity columns hold bytes nothing here can predict,
        and stay. `notes`, when given, is told what was placed how."""
        obj, copy = target["object"], target.get("copy", "all")
        pieces = target.get("pieces", "all")
        raws = None
        if obj == "mos:objset":
            m = re.search(r"^Dataset mos .*?rootbp (.*)$", self.zdb, re.M)
            raws = [m.group(1) if m else ""]
        else:
            ds, what = obj.rsplit(":", 1)
            if ds == "any":
                name = self.a_dataset()
            else:
                name = ds if ds.startswith(self.pool) else f"{self.pool}/{ds}"
            if what == "objset":
                m = re.search(rf"^Dataset {re.escape(name)} .*?rootbp (.*)$", self.zdb, re.M)
                raws = [m.group(1) if m else ""]
            elif what == "crypto-key":
                # The dataset's DSL crypto key: the MOS object its DSL
                # directory names as com.datto:crypto_key_obj, a ZAP whose
                # leaf holds the wrapped keys. Every block of it unless
                # `block` says one.
                key_obj = self.crypto_key_obj(name)
                levels, _ = self.blocks_of("mos", key_obj)
                if 0 not in levels:
                    raise Unresolved(f"target {obj}: crypto key object {key_obj} has no L0 blocks in the capture")
                raws = self.pick_blocks(obj, levels[0], target.get("block", "all"))
            elif what in ("dnode-block", "data", "indirect"):
                # Below the object set, from the -dddddd capture: the
                # dataset's dnode array is object 0 (its L0 blocks are the
                # dnode blocks); a volume's data is object 1, its L0 blocks
                # the data and its L1 blocks the indirect blocks.
                if what == "dnode-block":
                    num, level = 0, 0
                    levels, _ = self.blocks_of(name, num)
                else:
                    if self.dataset_type(name) != "ZVOL":
                        raise Unresolved(f"target {obj}: {name} is not a volume, so `data` names no object of it")
                    num = 1
                    levels, _ = self.blocks_of(name, num)
                    # `indirect` means the topmost level unless `level` says
                    # which: the lower indirect blocks of a volume filled
                    # with ganging forced are mostly gang blocks, which
                    # cannot be aimed at (below).
                    level = 0 if what == "data" else int(target.get("level", max(levels)))
                if level not in levels:
                    raise Unresolved(f"target {obj}: object {num} of {name} has no L{level} blocks")
                raws = self.pick_blocks(obj, levels[level], target.get("block", 0))
            else:
                # `crypto-key` is a documented shape this harness cannot
                # locate yet. Saying so is the point: resolving it to
                # something else would make a manifest claim to damage
                # what it never touched.
                raise Unresolved(f"target {obj}: {what} is not located from this capture (objset, dnode-block, data, indirect, crypto-key are)")
        if pieces not in ("all", "one"):
            raise ValueError(f"target {obj}: pieces is 'all' or 'one', not {pieces!r}")
        out = []
        for raw in raws:
            out.extend(self.place_pointer(obj, raw, copy, pieces, notes))
        return out

    def place_pointer(self, obj, raw, copy, pieces, notes):
        """(role, offset, length) for the chosen copies of one block pointer
        (spelled out as -dddd prints it)."""
        dvas = re.findall(r"DVA\[(\d)\]=<(\d+):([0-9a-f]+):([0-9a-f]+)>", raw)
        if not dvas:
            raise Unresolved(f"target {obj} not found in the zdb capture")
        every = [(int(n), int(v), int(o, 16), int(a, 16)) for n, v, o, a in dvas]
        chosen = [d for d in every if copy == "all" or d[0] == int(copy)]
        if not chosen:
            raise Unresolved(f"target {obj}: no copy {copy}")
        out = []
        for n, vdev, off, asize in chosen:
            if self.top_kind(vdev).startswith("draid"):
                data = self.block_bytes(obj, every, raw)
                placed = self.locate_on_draid(vdev, asize, data)
                out.extend(placed)
                if notes is not None:
                    notes.append(f"{obj} copy {n} on draid: {len(placed)} column(s) found by content on "
                                 + ", ".join(f"{r} @ {o}" for r, o, _ in placed)
                                 + " (parity columns are placed only where they equal a data column)")
            else:
                out.extend(self.dva_to_physical(vdev, off, asize))
        if not out:
            raise Unresolved(f"target {obj}: DVA on a vdev this harness cannot map")
        if pieces == "one":
            # One piece of the first copy: a mirror's half, one raidz data
            # column, one dRAID column — the loss every geometry here
            # survives once. A data column rather than a parity column on
            # raidz, so that the loss is one the reader has to notice.
            n, vdev, off, asize = chosen[0]
            if self.top_kind(vdev).startswith("raidz"):
                m = re.search(r"size=([0-9a-f]+)L/([0-9a-f]+)P", raw)
                psize = int(m.group(2), 16) if m else asize
                data_cols = [(r, o, l) for r, o, l, parity in self.raidz_columns(vdev, off, psize) if not parity and l]
                out = data_cols[:1] or out[:1]
            else:
                out = out[:1]
        return out

    def crypto_key_obj(self, name):
        """The MOS object number of a dataset's DSL crypto key, by way of
        the capture: the dataset's ID is its DSL dataset object, whose
        dir_obj is its DSL directory, whose ZAP names
        com.datto:crypto_key_obj."""
        m = re.search(rf"^Dataset {re.escape(name)} \[\w+\], ID (\d+),", self.zdb, re.M)
        if not m:
            raise Unresolved(f"dataset {name} is not in the zdb capture")
        ds_obj = int(m.group(1))
        mos = self.mos_object(ds_obj)
        d = re.search(r"^\s+dir_obj = (\d+)", mos, re.M)
        if not d:
            raise Unresolved(f"DSL dataset object {ds_obj} of {name} names no dir_obj")
        dir_dump = self.mos_object(int(d.group(1)))
        k = re.search(r"^\s+com\.datto:crypto_key_obj = (\d+)", dir_dump, re.M)
        if not k:
            raise Unresolved(f"{name} is not encrypted: its DSL directory names no crypto_key_obj")
        return int(k.group(1))

    def mos_object(self, num):
        """One object's dump from the MOS section of the -dddddd capture."""
        if self.deep() is None:
            raise Unresolved("the oracle has no zdb -dddddd capture")
        head = re.search(r"^Dataset mos \[", self._deep, re.M)
        end = re.search(r"^Dataset ", self._deep[head.end():], re.M)
        section = self._deep[head.start():head.end() + (end.start() if end else len(self._deep))]
        m = re.search(rf"^\s+{num}\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+.*$", section, re.M)
        if not m:
            raise Unresolved(f"MOS object {num} is not in the zdb -dddddd capture")
        nxt = re.search(r"^\s+Object\s+lvl", section[m.end():], re.M)
        return section[m.start():m.end() + (nxt.start() if nxt else len(section))]

    def pick_blocks(self, obj, blocks, which):
        """`pick_block`, or every block of the level that is not a gang
        block when `which` is "all"."""
        if which == "all":
            out = [raw for _, raw in blocks if not raw.endswith(" gang")]
            if not out:
                raise Unresolved(f"target {obj}: every block of it is a gang block")
            return out
        return [self.pick_block(obj, blocks, which)]

    def pick_block(self, obj, blocks, which):
        """One block pointer of a level: by index, or the first whose first
        copy lies on a top-level vdev of a kind (`on:mirror`, `on:raidz2`,
        `on:draid1`), so that a manifest can ask for a block the harness
        can place — a block with one copy, on a dRAID, has nothing to find
        it by — without naming an index that is this image's alone."""
        # A gang block's pointer names its gang header and an allocated
        # size that is the whole tree's; the header's own size is not in
        # the capture, so damage cannot be aimed at it without taking
        # other blocks with it. Such a pointer is not placed.
        if isinstance(which, int):
            if which >= len(blocks):
                raise Unresolved(f"target {obj}: block {which} asked for, {len(blocks)} in the capture")
            raw = blocks[which][1]
            if raw.endswith(" gang"):
                raise Unresolved(f"target {obj}: block {which} is a gang block, which this harness does not aim at")
            return raw
        if isinstance(which, str) and which.startswith("on:"):
            kind = which[3:]
            for _, raw in blocks:
                m = re.search(r"DVA\[0\]=<(\d+):", raw)
                if m and self.top_kind(int(m.group(1))) == kind and not raw.endswith(" gang"):
                    return raw
            raise Unresolved(f"target {obj}: no block of it that is not a gang block has its first copy on a {kind} top")
        raise ValueError(f"target {obj}: block is an index or on:<kind>, not {which!r}")

    def top(self, vdev):
        tops = [t for t in self.layout["tops"] if t["index"] == vdev]
        if not tops:
            raise Unresolved(f"DVA names top-level vdev {vdev}, which the layout does not have")
        top = tops[0]
        if len(top["groups"]) != 1:
            # `roles` is every member of the top, while the column
            # arithmetic is one group wide. With two groups the two
            # disagree and the answer is quietly wrong — which is worse
            # than no answer, so there is no answer.
            raise Unresolved(
                f"top-level vdev {vdev} has {len(top['groups'])} groups; "
                "this harness maps a DVA only inside a single-group top")
        return top

    def top_kind(self, vdev):
        return self.top(vdev)["groups"][0]["kind"]

    def block_bytes(self, obj, dvas, raw):
        """The logical bytes of a block, read from the intact image at a
        copy that arithmetic places — a mirror's member, or a raidz's data
        columns put back together — and checked against the pointer's
        checksum when it is one this harness can compute."""
        m = re.search(r"size=([0-9a-f]+)L/([0-9a-f]+)P", raw)
        if not m:
            raise Unresolved(f"target {obj}: the block pointer names no size")
        psize = int(m.group(2), 16)
        unit = 1 << self.layout.get("ashift", 12)
        data = None
        for _, vdev, off, asize in dvas:
            kind = self.top_kind(vdev)
            if kind == "mirror":
                role = self.top(vdev)["members"][0]
                with open(self.path(role), "rb") as f:
                    f.seek(LABEL_START + off)
                    data = f.read(psize)
                break
            if kind.startswith("raidz"):
                cols = self.raidz_columns(vdev, off, psize)
                parts = []
                for role, poff, length, parity in cols:
                    if parity or not length:
                        continue
                    with open(self.path(role), "rb") as f:
                        f.seek(poff)
                        parts.append(f.read(length))
                data = b"".join(parts)[:psize]
                break
        if data is None or len(data) != psize:
            raise Unresolved(f"target {obj}: every copy is on a dRAID top, and nothing places one by arithmetic")
        self.check_cksum(obj, data, raw)
        return data

    def check_cksum(self, obj, data, raw):
        """fletcher4 and sha256 are checked against the pointer's `cksum=`;
        the others are left to the uniqueness of the content search."""
        m = re.search(r"cksum=([0-9a-f]+):([0-9a-f]+):([0-9a-f]+):([0-9a-f]+)", raw)
        if not m:
            return
        want = tuple(int(w, 16) for w in m.groups())
        if " fletcher4 " in raw:
            a = b = c = d = 0
            mask = (1 << 64) - 1
            for (w,) in struct.iter_unpack("<I", data):
                a = (a + w) & mask
                b = (b + a) & mask
                c = (c + b) & mask
                d = (d + c) & mask
            got = (a, b, c, d)
        elif " sha256 " in raw:
            got = struct.unpack(">4Q", hashlib.sha256(data).digest())
        else:
            return
        if got != want:
            raise Unresolved(f"target {obj}: the bytes read for it do not match the block pointer's checksum")

    def raidz_columns(self, vdev, offset, psize):
        """The columns of one block on a raidz top, with their exact sizes:
        (role, physical offset, bytes, is_parity), parity first, then the
        data columns in the order the block's bytes fill them — the map
        raidz_map_alloc makes."""
        top = self.top(vdev)
        group = top["groups"][0]
        ashift = self.layout.get("ashift", 12)
        unit = 1 << ashift
        dcols, nparity, roles = group["count"], group["nparity"], top["members"]
        s = -(-psize // unit)
        b = offset >> ashift
        f = b % dcols
        o = (b // dcols) << ashift
        q, r = divmod(s, dcols - nparity)
        bc = nparity + r
        out = []
        for c in range(dcols):
            col = (f + c) % dcols
            coff = o + (unit if f + c >= dcols else 0)
            size = (q + (1 if c < bc else 0)) * unit
            out.append((roles[col], LABEL_START + coff, size, c < nparity))
        return out

    def locate_on_draid(self, vdev, asize, data):
        """Where a block's data columns lie on a dRAID top, found by
        searching its children for the bytes themselves: (role, offset,
        length) per column, each found exactly once at an ashift-aligned
        offset — anything else is no answer."""
        top = self.top(vdev)
        group = top["groups"][0]
        unit = 1 << self.layout.get("ashift", 12)
        width = group["ndata"] + group["nparity"]
        if asize % width or (asize // width) % unit:
            raise Unresolved(f"a dRAID allocation of {asize} bytes is not {width} columns of whole sectors")
        colsize = asize // width
        placed = []
        for i in range(-(-len(data) // colsize)):
            chunk = data[i * colsize:(i + 1) * colsize]
            if not chunk.strip(b"\0"):
                raise Unresolved("a data column of the target is all zeros, which is found everywhere")
            hits = []
            for role in top["members"]:
                hits.extend((role, pos) for pos in self.find_aligned(self.path(role), chunk, unit))
            if not hits:
                raise Unresolved(f"the target's column {i} was not found on the dRAID children")
            # One row of a dRAID group lies at one offset on every child
            # it uses, so the column may be met more than once and still
            # be this block's: a parity column equals a data column when
            # the row's other data columns are padding (one data sector,
            # ndata 2, single parity: P = D xor 0). Several hits at one
            # offset on distinct children are that row, and all of them
            # are the copy; a hit at another offset is some other block
            # with the same bytes, and then there is no answer.
            if len({pos for _, pos in hits}) != 1 or len({r for r, _ in hits}) != len(hits) or len(hits) > width:
                raise Unresolved(f"the target's column {i} was found {len(hits)} times on the dRAID children at "
                                 f"{len({pos for _, pos in hits})} offset(s); one row at one offset is the only answer")
            placed.extend((role, pos, colsize) for role, pos in hits)
        return placed

    @staticmethod
    def find_aligned(path, needle, unit, window=8 << 20):
        """Every offset in the file, a multiple of `unit` from LABEL_START,
        at which `needle` begins."""
        out = []
        n = len(needle)
        with open(path, "rb") as f:
            f.seek(LABEL_START)
            base = LABEL_START
            carry = b""
            while True:
                buf = f.read(window)
                if not buf:
                    break
                hay = carry + buf
                start = base - len(carry)
                i = hay.find(needle)
                while i != -1:
                    pos = start + i
                    if (pos - LABEL_START) % unit == 0:
                        out.append(pos)
                    i = hay.find(needle, i + 1)
                base += len(buf)
                carry = hay[-(n - 1):] if n > 1 else b""
        return out

    def dva_to_physical(self, vdev, offset, asize):
        top = self.top(vdev)
        group = top["groups"][0]
        kind, ashift = group["kind"], self.layout.get("ashift", 12)
        roles = top["members"]
        if kind == "mirror":
            return [(r, LABEL_START + offset, asize) for r in roles]
        if kind.startswith("raidz"):
            unit = 1 << ashift
            dcols = group["count"]
            b = offset >> ashift
            f = b % dcols
            o = (b // dcols) << ashift
            rows = -(-(asize >> ashift) // dcols) + 1
            out = []
            for c in range(dcols):
                col = (f + c) % dcols
                coff = o + (unit if f + c >= dcols else 0)
                out.append((roles[col], LABEL_START + coff, rows * unit))
            return out
        # dRAID places a block's columns through a permutation table
        # derived from the pool, so which child holds which column is not
        # arithmetic the way raidz is. Reimplementing that here, in the
        # thing that is supposed to be the oracle, is how a harness comes
        # to be confidently wrong; a copy on dRAID is found by content
        # instead (`locate_on_draid`), which `resolve_target` does.
        raise Unresolved(
            f"top-level vdev {vdev} is {kind}: a DVA on it is placed by content, not arithmetic")


def apply_damage(oracle, manifest, work, rng):
    """Returns (member paths for the tool, notes). Raises Unresolved when the
    manifest addresses something this image does not have."""
    paths = {r: oracle.path(r) for r in oracle.roles}
    missing, notes, plans = set(), [], {}
    unread = {}   # role -> ranges an imager could not read, for its map
    forged = {}   # (role, from txg, forged txg, slot) -> rings it went into
    for d in manifest.get("damage", []):
        pat = d["pattern"]
        if "target" in d:
            for role, off, length in oracle.resolve_target(d["target"], notes):
                plans.setdefault(role, []).append((off, length, pat))
            continue
        role = oracle.resolve(d["member"])
        if pat == "missing":
            missing.add(role)
            continue
        src = paths[role]
        if pat.startswith("older-self:"):
            # Resolved here, before any member is copied, so that a
            # manifest this image cannot serve is n/a and not half-done.
            oracle.older_path(role, pat.split(":", 1)[1])
        if pat.startswith("forged-txg:"):
            rng_spec = d.get("range", "")
            if not (rng_spec.startswith("label:") and rng_spec.endswith(("/rings", "/uberblocks"))):
                raise ValueError(f"{pat} needs a `label:…/rings` range, not {rng_spec!r}")
        if d.get("range") == "slack":
            rngs = oracle.slack(role, os.path.getsize(src))
        else:
            rngs = ranges_for(d.get("range", "0.."), src, os.path.getsize(src),
                              reference=oracle.min_length)
        for off, length in rngs:
            plans.setdefault(role, []).append((off, length, pat))
    for role, plan in plans.items():
        if role in missing:
            continue
        dst = os.path.join(work, role + ".img")
        sparse_copy(paths[role], dst)
        paths[role] = dst
        for off, length, pat in plan:
            with open(dst, "r+b") as f:
                if pat == "zeros":
                    f.seek(off)
                    f.write(b"\0" * length)
                elif pat == "unreadable":
                    # What an imager leaves where it could not read: zeros
                    # in the image, and the range marked in its map.
                    f.seek(off)
                    f.write(b"\0" * length)
                    unread.setdefault(role, []).append((off, length))
                elif pat == "random":
                    f.seek(off)
                    left = length
                    while left:
                        n = min(left, 1 << 20)
                        f.write(rng.randbytes(n))
                        left -= n
                elif pat.startswith("flip-bits:"):
                    for _ in range(int(pat.split(":")[1])):
                        pos = off + rng.randrange(max(length, 1))
                        f.seek(pos)
                        b = f.read(1) or b"\0"
                        f.seek(pos)
                        f.write(bytes([b[0] ^ (1 << rng.randrange(8))]))
                elif pat.startswith("shift:"):
                    f.seek(0)
                    data = f.read()
                    f.seek(0)
                    f.write(b"\0" * (int(pat.split(":")[1]) * 512) + data)
                elif pat == "truncate":
                    f.truncate(off)
                elif pat.startswith("older-self:"):
                    # The range as it was at that earlier point, written
                    # over the current bytes: every block in it verifies,
                    # and none of it is current.
                    older = oracle.older_path(role, pat.split(":", 1)[1])
                    with open(older, "rb") as o:
                        o.seek(off)
                        f.seek(off)
                        left = length
                        while left:
                            chunk = o.read(min(left, 1 << 20))
                            if not chunk:
                                break
                            f.write(chunk)
                            left -= len(chunk)
                elif pat.startswith("forged-txg:"):
                    # A newer txg than any the pool reached, sealed as
                    # ZFS would have sealed it, pointing at nothing.
                    frm, to, index = forge_uberblock(
                        f, off, length, int(pat.split(":")[1]), oracle.layout.get("ashift", 12))
                    forged[(role, frm, to, index)] = forged.get((role, frm, to, index), 0) + 1
                elif pat.startswith("grow:"):
                    # The partition re-created larger: the same bytes,
                    # then nothing, so the rear labels are no longer
                    # where the size says they should be.
                    f.truncate(os.path.getsize(dst) + size(pat.split(":", 1)[1]))
                else:
                    raise ValueError(f"unknown pattern {pat}")
    for (role, frm, to, index), rings in forged.items():
        notes.append(f"{role}: txg {to} forged from {frm} into slot {index} of {rings} ring(s)")
    ordered = [paths[r] for r in oracle.roles if r not in missing]
    return ordered, notes, paths, unread


# Why a block could not be produced, in the words `ReadError` uses in
# crates/zfs-read/src/zio.rs. Each of these is the tool saying "I cannot
# give you this block, and here is why", which is what damage is supposed
# to produce.
#
# The list used to be four guesses, and every honest reason it had not
# guessed read as a tool defect: a pool that lost a whole top-level vdev
# reported `DVA names unknown top-level vdev 0` for the blocks that lived
# there, which is exactly right, and the matrix called it breakage.
# check-read-errors.py holds this list against the enum, so a new variant
# has to be classified here instead of quietly becoming a defect.
CLEAN_REASONS = (
    "DVA names unknown top-level vdev",   # UnknownVdev: no member for that top
    "no present member holds this copy",  # NoMember
    "not supported yet",                  # Unsupported, ChecksumUnsupported
    "keyed with the pool's salt",         # ChecksumNoSalt: no MOS read, so no salt
    "gang block: header checksum",        # Gang: every copy of the header bad
    "gang block: nesting deeper than",    # Gang: the chain is malformed
    "not recoverable",                    # Unrecoverable
    "I/O error",                          # Io: a short or truncated member
    "every copy failed its checksum",     # AllCopiesBad
    "block pointer is a hole",            # Hole
    "encrypted block: no key",            # Encrypted
)

# Deliberately not clean. Both are reached only after a checksum agreed,
# so the bytes are the bytes ZFS wrote: failing to make sense of them
# afterwards is this reader's fault and not the damage's.
UNCLEAN_VARIANTS = ("Decompress", "Crypt")

# — except when there was no checksum to agree. A dataset with
# `checksum=off` has nothing to verify against, so damaged bytes go
# straight to the decompressor and the failure to decompress them is the
# only signal there can be. `ztest` makes such datasets (a run's own
# histogram counts them under `off: NotChecked`), and calling that a tool
# defect blames the reader for an absence ZFS was told to allow. The
# walker prefixes every outcome with the checksum it used, so the two
# cases are told apart by reading that prefix rather than by guessing.
CHECKSUMLESS = re.compile(r"\boff(?: encrypted)?(?: gang)?: ERROR")


# What the tool says when a member it was told belongs to the pool reads as
# no leaf of it (SPEC F-62). It is an answer, not a breakage: the assertion
# was tried by reading and the evidence did not bear it out, and the tool
# stops there rather than bind on say-so. It exits 1 because the way on is
# an operator's decision (`=GUID`), which is what usage errors are; the
# harness must not read that as the tool failing in a way it cannot
# account for.
UNBOUND = "nothing reads through this member"

# The tool's answer to a volume it cannot unlock: a key that does not
# verify, or none given for a dataset that needs one. Exit 1, because the
# way on is the operator's — the right key — and nothing is written.
KEY_REFUSED = ("MAC does not verify", "is encrypted (")


def write_map(path, length, bad):
    """A ddrescue mapfile of a `length`-byte image: every byte read but
    `bad`, a list of (offset, length), which is marked bad (`-`).

    >>> import io, os, tempfile
    >>> p = os.path.join(tempfile.mkdtemp(), "m.map")
    >>> write_map(p, 0x3000, [(0x1000, 0x200), (0x1100, 0x200)])
    >>> print(open(p).read().split("#      pos        size  status\\n")[1], end="")
    0x00000000  0x00001000  +
    0x00001000  0x00000300  -
    0x00001300  0x00001d00  +
    """
    merged = []
    for off, n in sorted(bad):
        if merged and off <= merged[-1][0] + merged[-1][1]:
            end = max(merged[-1][0] + merged[-1][1], off + n)
            merged[-1] = (merged[-1][0], end - merged[-1][0])
        else:
            merged.append((off, n))
    lines, pos = [], 0
    for off, n in merged:
        if off > pos:
            lines.append((pos, off - pos, "+"))
        lines.append((off, n, "-"))
        pos = off + n
    if pos < length:
        lines.append((pos, length - pos, "+"))
    with open(path, "w") as f:
        f.write("# Mapfile. Written by run-matrix.py for the pattern `unreadable`\n")
        f.write("# current_pos  current_status  current_pass\n")
        f.write(f"0x{length:08x}     +               1\n")
        f.write("#      pos        size  status\n")
        for p, n, st in lines:
            f.write(f"0x{p:08x}  0x{n:08x}  {st}\n")


def layout_hints(oracle, paths, missing, order="as-is"):
    """The pool's layout, as the oracle records it, in the shape
    `--hints` takes: what an operator who knew the pool would write.
    A member not given is `null`. `order = "reversed"` turns every raidz
    and dRAID group the other way round, which `--search-order` is then
    to put right; a mirror has no order to get wrong."""
    ngroups = []
    zc = os.path.join(oracle.dir, "zdb-C.txt")
    if os.path.exists(zc):
        ngroups = [int(m) for m in re.findall(r"draid_ngroups:\s*(\d+)", open(zc).read())]
    tops = []
    for top in sorted(oracle.layout["tops"], key=lambda t: t["index"]):
        group = top["groups"][0]
        kind = top["kind"]
        members = [None if r in missing else paths[r] for r in top["members"]]
        hint = {}
        if kind == "mirror":
            hint["kind"] = "mirror"
        elif kind.startswith("raidz"):
            hint.update(kind="raidz", nparity=group["nparity"])
        elif kind.startswith("draid"):
            if not ngroups:
                raise Unresolved("the oracle has no draid_ngroups for its dRAID (zdb-C.txt)")
            hint.update(kind="draid", nparity=group["nparity"], draid_ndata=group["ndata"],
                        draid_nspares=group["nspares"], draid_ngroups=ngroups.pop(0))
        else:
            hint["kind"] = "disk"
        if order == "reversed" and hint["kind"] in ("raidz", "draid"):
            members = members[::-1]
        hint["members"] = members
        tops.append(hint)
    return {"name": oracle.pool, "ashift": oracle.layout.get("ashift", 12), "tops": tops}


def refusal(returncode, stderr):
    """The refusal a tool exit amounts to, or None when it is not one.

    2 is "not readable as a pool at all", 3 is "the pool is there but
    cannot be recovered at that TXG"; both are refusals. So is 1 when it
    carries the F-62 message: the tool was told a member belongs and
    found by reading that it does not; and 1 when the key does not
    unlock the volume, or none was given for one that needs it.

    >>> refusal(2, "")
    'refused'
    >>> refusal(3, "zvolrescue: no verified uberblock")
    'refused'
    >>> refusal(1, "zvolrescue: --assume-member /x: nothing reads through this member — it is not one of the 2 leaves pool 'p' is missing.")
    'refused (asserted member reads as no leaf)'
    >>> refusal(1, "zvolrescue: golden/secret-raw/disk: MAC does not verify: wrong key or damaged data")
    'refused (the key does not unlock it)'
    >>> refusal(1, "zvolrescue: golden/secret-pw/disk is encrypted (aes-128-ccm, keyformat passphrase); supply --key")
    'refused (the key does not unlock it)'
    >>> refusal(1, "zvolrescue: --before wants Unix seconds") is None
    True
    >>> refusal(0, "") is None
    True
    """
    if returncode in (2, 3):
        return "refused"
    if returncode == 1 and UNBOUND in stderr:
        return "refused (asserted member reads as no leaf)"
    if returncode == 1 and any(k in stderr for k in KEY_REFUSED):
        return "refused (the key does not unlock it)"
    return None


# The tool's answer when some blocks of a volume could not be read from
# any copy: an image with those written as zeros, each one counted and
# listed, exit 4 (SPEC F-33). Neither a clean refusal nor a recovery.
INCOMPLETE = "incomplete (blocks written as zeros)"


def said_passed_over(stdout):
    """The newer TXGs a run's JSON says it passed over because they did
    not read, as `txg N (stage): why`; empty when it names none.

    >>> said_passed_over('{"unreadable_at": [{"txg": 9, "stage": "pool", "error": "MOS: bad"}]}')
    ['txg 9 (pool): MOS: bad']
    >>> said_passed_over('{"unreadable_at": []}'), said_passed_over('not json')
    ([], [])
    """
    try:
        doc = json.loads(stdout)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    return [f"txg {u.get('txg')}" + (f" ({u['stage']})" if u.get("stage") else "")
            + f": {str(u.get('error', ''))[:120]}"
            for u in (doc.get("unreadable_at") or [])]


def passed_over(returncode, stdout):
    """What a `dump` that exited 4 passed over, when that is all it
    exited 4 for; otherwise None.

    `dump` ends 4 when the newest TXG that names the volume, or the pool
    or the tree it is under, did not read and an older one was used: an
    image of an older state than the pool's, the rewind `zpool import -F`
    makes and counts as transactions lost. When every block of it was
    read, the bytes are an answer to judge, not zeros written for blocks.

    >>> rec = {"unreadable_at": [{"txg": 9, "stage": "pool", "error": "MOS"}],
    ...        "volumes": [{"blocks_zeroed": 0, "blocks_salvaged": 0}]}
    >>> passed_over(4, json.dumps(rec))
    'txg 9 (pool): MOS'
    >>> passed_over(0, json.dumps(rec)) is None
    True
    >>> rec["volumes"][0]["blocks_zeroed"] = 1
    >>> passed_over(4, json.dumps(rec)) is None
    True
    >>> passed_over(4, json.dumps({"unreadable_at": [], "volumes": [{}]})) is None
    True
    """
    if returncode != 4:
        return None
    said = said_passed_over(stdout)
    if not said:
        return None
    doc = json.loads(stdout)
    vols = doc.get("volumes") or []
    whole = vols and all(not v.get("blocks_zeroed") and not v.get("blocks_salvaged")
                         and not v.get("aborted") and not v.get("interrupted_at") for v in vols)
    return "; ".join(said) if whole else None


# A volume of `checksum=off` whose bytes came out otherwise than the
# oracle's, where the damage overwrote what such a volume may hold and
# the tool said its blocks were checked by nothing: ZFS itself would have
# handed the same bytes over, so it says nothing of the tool, and is not
# a defect. On the control, where nothing was damaged, the same volume
# has to come out bit-exact like any other.
UNVERIFIED = "unverified (checksum=off, under damage nothing can see)"
# The patterns that put other bytes where the data was, unannounced.
SILENT = ("zeros", "random", "flip-bits:", "older-self:", "shift:")


def silent_damage(oracle, manifest):
    """Whether the damage overwrites, without a word, bytes a volume of
    `checksum=off` may hold, where nothing — not ZFS, not a reader — can
    tell them from its data: a pattern that writes other bytes over a
    range past the front labels and the boot area, other than the rear
    labels and the slack, or over a data block of such a volume. A member
    missing, a range marked unreadable or cut off is known to a reader,
    which reconstructs past it; labels and metadata carry checksums.

    >>> o = type("O", (), {"pool": "p", "checksum_of": lambda self, d: "off" if d == "p/n" else "sha256",
    ...                     "a_dataset": lambda self: "p/c"})()
    >>> [silent_damage(o, {"damage": [d]}) for d in (
    ...     {"member": "x", "pattern": "zeros", "range": "data:10%..20%"},
    ...     {"member": "x", "pattern": "flip-bits:9", "range": "0.."},
    ...     {"member": "x", "pattern": "zeros", "range": "0..1MiB"},
    ...     {"member": "x", "pattern": "random", "range": "512KiB..4MiB"},
    ...     {"member": "x", "pattern": "random", "range": "label:all"},
    ...     {"member": "x", "pattern": "zeros", "range": "slack"},
    ...     {"member": "x", "pattern": "missing"},
    ...     {"member": "x", "pattern": "unreadable", "range": "data:10%..20%"},
    ...     {"member": "x", "pattern": "truncate", "range": "-8MiB.."},
    ...     {"target": {"object": "n:data"}, "pattern": "random"},
    ...     {"target": {"object": "any:data"}, "pattern": "random"},
    ...     {"target": {"object": "n:dnode-block"}, "pattern": "random"})]
    [True, True, False, False, False, False, False, False, False, True, False, False]
    """
    for d in manifest.get("damage", []):
        pat = d.get("pattern", "")
        if not any(pat == p or (p.endswith(":") and pat.startswith(p)) for p in SILENT):
            continue
        if "target" in d:
            ds, _, shape = d["target"].get("object", "").rpartition(":")
            if shape != "data":
                continue
            name = oracle.a_dataset() if ds == "any" else ds if ds.startswith(oracle.pool + "/") else f"{oracle.pool}/{ds}"
            if oracle.checksum_of(name) == "off":
                return True
            continue
        spec = d.get("range", "0..")
        if spec.startswith("label:") or spec == "slack":
            continue
        if not spec.startswith(("data:", "span:")):
            a, _, b = spec.partition("..")
            start, end = size(a) if a else 0, size(b) if b else None
            if start >= 0 and end is not None and end <= LABEL_START:
                continue                      # front labels and the boot area
            if start < 0 and -start <= 2 * LABEL_SIZE:
                continue                      # the rear labels
        return True
    return False


def unverified_blocks(stdout):
    """What a `dump -f json` said it read and nothing verified, over the
    volumes it wrote.

    >>> unverified_blocks('{"volumes": [{"blocks_unverified": 3}, {"blocks_unverified": 0}]}')
    3
    >>> unverified_blocks("not json"), unverified_blocks('{"volumes": []}')
    (0, 0)
    """
    try:
        doc = json.loads(stdout)
    except ValueError:
        return 0
    vols = doc.get("volumes", []) if isinstance(doc, dict) else []
    return sum(int(v.get("blocks_unverified") or 0) for v in vols if isinstance(v, dict))


def judge_dump(args, oracle, manifest, members, work, assume=(), extra=(), key_mode=None, evidence=None):
    want = manifest["expect"].get("volumes", "all")
    volumes = list(oracle.volumes) if want == "all" else list(want)
    outcomes, redundancy = {}, False
    silent = silent_damage(oracle, manifest)

    def bytes_outcome(vol, out, stdout, sha):
        if sha256_file(out) == sha:
            return "ok"
        if silent and oracle.checksum_of(vol) == "off" and unverified_blocks(stdout):
            return UNVERIFIED
        return "hash mismatch"

    def dump(vol, key_name, sha, txg=None, log_evidence=True, counts=True):
        nonlocal redundancy
        out = os.path.join(work, key_name.replace("/", "_") + ".img")
        log = out + ".debug"
        cmd = [args.tool, "-q", "-f", "json", "--debug-log", log,
               *(["--evidence-log", evidence] if evidence and log_evidence else []),
               "dump", vol, *members, "-o", out, *(["--txg", str(txg)] if txg else [])]
        for path in assume:
            cmd += ["--assume-member", path]
        cmd += list(extra)
        key = oracle.key_for(vol)
        if key and key_mode == "wrong":
            key = wrong_key(key, work)
        if key and key_mode != "none":
            cmd += ["--key", key]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        trace = open(log, errors="replace").read() if os.path.exists(log) else ""
        redundancy |= counts and bool(REDUNDANCY.search(trace))
        passed = passed_over(proc.returncode, proc.stdout)
        if passed is not None and os.path.exists(out):
            # Read whole at an older TXG than one that did not read:
            # exit 4 for that alone (SPEC F-10, F-20), and the bytes are
            # judged as an exit 0's are.
            outcomes[key_name] = bytes_outcome(vol, out, proc.stdout, sha)
            outcomes.setdefault("passed_over", {})[key_name] = passed
        elif proc.returncode == 0 and os.path.exists(out):
            outcomes[key_name] = bytes_outcome(vol, out, proc.stdout, sha)
            if said_passed_over(proc.stdout):
                outcomes[key_name] = "exit 0, a newer txg passed over"
        elif refusal(proc.returncode, proc.stderr):
            outcomes[key_name] = "refused"
            # The reason, in the tool's words: a refusal where recovery
            # was expected is only diagnosable from it, and the debug
            # log is gone with the work directory.
            why = proc.stderr.strip().splitlines()
            outcomes.setdefault("refused_detail", {})[key_name] = (
                f"exit {proc.returncode}: " + (why[-1][:200] if why else ""))
        elif proc.returncode == 4:
            # The tool says the image is not the whole volume. That is
            # neither a clean refusal nor an answer, so it is named
            # rather than folded into either.
            outcomes[key_name] = INCOMPLETE
        else:
            outcomes[key_name] = f"exit {proc.returncode}: {proc.stderr.strip()[:160]}"
    for vol in volumes:
        dump(vol, vol, oracle.volumes[vol])
    # The pool checkpoint (`zpool checkpoint`, sat-checkpoint): every
    # volume as it was when the checkpoint was taken (`@checkpoint` in
    # volumes.sha256), read at its TXG; and one destroyed since, which
    # the pool holds until the checkpoint is discarded, read without
    # being told where — the checkpoint is the last place `dump` looks
    # for a dataset (SPEC F-10). Not in the evidence log: the report is
    # judged by the volumes as the pool is now. And not counted as the
    # case's redundancy at work: looking for the destroyed one, `dump`
    # tries the newer TXGs first, whose blocks of it were freed and
    # written over, and their failed reconstructions say nothing of the
    # damage.
    if want == "all":
        for vol, sha in sorted(oracle.at_checkpoint.items()):
            dump(vol, f"{vol}@checkpoint", sha,
                 txg=oracle.checkpoint_txg if vol in oracle.volumes else None, log_evidence=False,
                 counts=False)
    return outcomes, redundancy


# zvolfiles's answer when some of a tree did not read whole: the entries
# it says so of (blocks written as zeros, attributes or directory contents
# unread, an entry that failed), and exit 4.
INCOMPLETE_FILES = "incomplete (entries said not whole)"
KINDS = {"-": "f", "d": "d", "l": "l"}


def iso_ns(stamp):
    """Nanoseconds since the epoch of zvolfiles's `2026-10-10T10:23:13.624952330Z`.

    >>> iso_ns("1970-01-01T00:00:01.5Z")
    1500000000
    >>> iso_ns("2026-10-10T10:23:13.624952330Z")
    1791627793624952330
    """
    import calendar
    whole, _, frac = stamp.rstrip("Z").partition(".")
    secs = calendar.timegm(time.strptime(whole, "%Y-%m-%dT%H:%M:%S"))
    return secs * 10**9 + int((frac + "000000000")[:9])


def compare_files(oracle_entries, manifest, returncode):
    """A filesystem's tree as zvolfiles extracted it (its manifest, its
    exit code) against what the kernel read out of it. The answer is
    `ok` when every entry is there and the same and nothing else is;
    INCOMPLETE_FILES when the run said, with exit 4, that something did
    not read whole and everything it did not say that of is right; `ok`
    too when it ended 4 for a newer TXG passed over alone, that did not
    read (`passed_over`, SPEC F-20), and every entry is right; and
    otherwise what differs — an entry presented as whole that is not,
    one missing that nothing accounts for, one the pool does not hold.

    >>> o = [{"path": ".", "type": "d", "ino": 34},
    ...      {"path": "f", "type": "f", "mode": "644", "uid": 0, "gid": 0, "ino": 2, "size": 3,
    ...       "sha256": "ab", "mtime_ns": 1500000000,
    ...       "xattrs": {"user.x": {"size": 1, "sha256": hashlib.sha256(b"v").hexdigest()}}}]
    >>> got = {"files": [{"path": "f", "type": "-", "mode": "0644", "uid": 0, "gid": 0, "object": 2,
    ...                   "size": 3, "sha256": "ab", "times": {"mtime": "1970-01-01T00:00:01.5Z"},
    ...                   "xattrs": [{"name": "user.x", "value": "v", "bytes": 1}], "errors": 0}]}
    >>> compare_files(o, got, 0)
    ('ok', [])
    >>> got["files"][0]["sha256"] = "cd"
    >>> compare_files(o, got, 0)
    ('mismatch', ['f: sha256 ab != cd'])
    >>> got["files"][0]["errors"] = 2
    >>> compare_files(o, got, 4)
    ('incomplete (entries said not whole)', [])
    >>> compare_files(o, {"files": []}, 0)
    ('mismatch', ['f: missing, and nothing said of it'])
    >>> compare_files(o, {"files": [{"path": "f", "error": "unreadable"}]}, 4)
    ('incomplete (entries said not whole)', [])
    >>> compare_files(o[:1], got, 0)
    ('mismatch', ['f: not in the pool'])
    >>> got["files"][0].update(sha256="ab", errors=0)
    >>> compare_files(o, got, 4)
    ('incomplete (entries said not whole)', [])
    >>> compare_files(o, dict(got, passed_over=[{"txg": 9, "unread": True}]), 4)
    ('ok', [])
    >>> compare_files(o, dict(got, passed_over=[{"txg": 9, "unread": False}]), 4)
    ('incomplete (entries said not whole)', [])
    """
    want = {e["path"]: e for e in oracle_entries if e.get("path") != "."}
    got = {f.get("path"): f for f in manifest.get("files", [])}
    said = lambda f: (f.get("error") or f.get("errors") or f.get("xattr_errors")
                      or f.get("contents_errors") or any(x.get("error") for x in f.get("xattrs", [])))
    owned_up = returncode == 4 and any(said(f) for f in got.values())
    diffs, admitted = [], False
    for path, o in want.items():
        g = got.get(path)
        if g is None:
            if owned_up:
                admitted = True
            else:
                diffs.append(f"{path}: missing, and nothing said of it")
            continue
        if said(g):
            admitted = True
            continue
        checks = [("type", o["type"], KINDS.get(g.get("type"), "o")),
                  ("mode", int(o["mode"], 8), int(g.get("mode", "-1"), 8)),
                  ("uid", o["uid"], g.get("uid")), ("gid", o["gid"], g.get("gid")),
                  ("object", o["ino"], g.get("object"))]
        if "mtime_ns" in o:
            checks.append(("mtime", o["mtime_ns"],
                           iso_ns(g["times"]["mtime"]) if g.get("times") else g.get("mtime")))
        if o["type"] in ("f", "l"):
            checks.append(("size", o["size"], g.get("size")))
        if o["type"] == "f" and not g.get("hardlink_to"):
            checks.append(("sha256", o["sha256"], g.get("sha256")))
        if o["type"] == "l":
            checks.append(("target", o.get("target", o.get("target_hex")), g.get("target", g.get("target_hex"))))
        gx = {x["name"]: x for x in g.get("xattrs", [])}
        checks.append(("xattr names", sorted(o.get("xattrs", {})), sorted(gx)))
        for name, ox in o.get("xattrs", {}).items():
            x = gx.get(name)
            if x is None or x.get("recorded") is not None:
                continue
            raw = x["value"].encode() if "value" in x else bytes.fromhex(x.get("value_hex", ""))
            checks.append((f"xattr {name}", (ox["size"], ox["sha256"]),
                           (x.get("bytes"), hashlib.sha256(raw).hexdigest())))
        diffs += [f"{path}: {what} {a} != {b}" for what, a, b in checks if a != b]
    diffs += [f"{path}: not in the pool" for path in got if path not in want]
    if diffs:
        return "mismatch", diffs
    passed = returncode == 4 and any(p.get("unread") for p in manifest.get("passed_over") or [])
    if admitted or (returncode == 4 and not passed):
        return (INCOMPLETE_FILES, []) if returncode == 4 else ("mismatch", ["exit 0 with entries said not whole"])
    return ("ok", []) if returncode == 0 or passed else ("mismatch", [f"exit {returncode} with every entry whole"])


def judge_files(args, oracle, members, work, assume=(), extra=(), key_mode=None, datasets=()):
    """Every filesystem `datasets` names extracted with zvolfiles and
    held against the kernel's reading of it (`compare_files`)."""
    outcomes, details, redundancy = {}, {}, False
    for name in datasets:
        safe = name.replace("/", "_").replace("@", "_at_")
        out, log = os.path.join(work, "files-" + safe), os.path.join(work, "files-" + safe + ".debug")
        cmd = [args.files_tool, "-q", "-f", "json", "--debug-log", log, "extract", name,
               "--output", out, *members]
        for path in assume:
            cmd += ["--assume-member", path]
        cmd += list(extra)
        key = oracle.key_for(name.split("@")[0])
        if key and key_mode == "wrong":
            key = wrong_key(key, work)
        if key and key_mode != "none":
            cmd += ["--key", key]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        trace = open(log, errors="replace").read() if os.path.exists(log) else ""
        redundancy |= bool(REDUNDANCY.search(trace))
        if refusal(proc.returncode, proc.stderr):
            outcomes[name] = "refused"
        elif proc.returncode in (0, 4):
            try:
                doc = json.loads(proc.stdout)
            except ValueError:
                outcomes[name] = f"exit {proc.returncode}, no manifest on stdout"
                continue
            outcomes[name], diffs = compare_files(oracle.files[name], doc, proc.returncode)
            if diffs:
                details[name] = diffs[:10] + ([f"... {len(diffs) - 10} more"] if len(diffs) > 10 else [])
        else:
            why = proc.stderr.strip().splitlines()
            outcomes[name] = f"exit {proc.returncode}: {why[-1][:160] if why else ''}"
        shutil.rmtree(out, ignore_errors=True)
    return outcomes, details, redundancy


HISTORY_EVENT = re.compile(r"^\S+ \[txg:(\d+)\] (create|snapshot|clone|destroy|rename|promote) (\S+) \((\d+)\)(.*)$")
INCOMPLETE_TIMELINE = "incomplete (history said not whole)"


def history_objects(text):
    """What `zpool history -il` says of every dataset and snapshot, by
    the object id it names: every name it had and from which TXG, the
    TXG it came into being at and how (created, clone, snapshot), and the
    TXG it was destroyed at; with the renames of datasets and the
    promotions, each with its TXG. A snapshot takes its dataset's new
    name with it, and so does a child; a promoted clone takes the
    snapshots of its origin up to the one it was cloned from, which are
    its own from then on (dsl_dataset_promote).

    >>> h = '''History for 'p':
    ... t [txg:10] create p/a (5)   [on h]
    ... t [txg:12] snapshot p/a@s0 (6)   [on h]
    ... t [txg:13] create p/a/b (7)   [on h]
    ... t [txg:20] rename p/a (5) -> p/c [on h]
    ... t [txg:21] clone p/d (8) origin=p/c@s0 (6) [on h]
    ... t [txg:22] create p/gone (9)   [on h]
    ... t [txg:30] destroy p/gone (9) (bptree, mintxg=1) [on h]
    ... '''
    >>> objects, renames, promotions = history_objects(h)
    >>> for o in objects.values(): print(o["names"], o["born"], o["how"], o["destroyed"])
    [(10, 'p/a'), (20, 'p/c')] 10 created None
    [(12, 'p/a@s0'), (20, 'p/c@s0')] 12 snapshot None
    [(13, 'p/a/b'), (20, 'p/c/b')] 13 created None
    [(21, 'p/d')] 21 clone None
    [(22, 'p/gone')] 22 created 30
    >>> renames
    [(20, 'p/a', 'p/c')]
    >>> h = '''History for 'p':
    ... t [txg:10] create p/a (5)   [on h]
    ... t [txg:12] snapshot p/a@s0 (6)   [on h]
    ... t [txg:14] snapshot p/a@s1 (7)   [on h]
    ... t [txg:15] clone p/b (8) origin=p/a@s1 (7) [on h]
    ... t [txg:16] snapshot p/a@s2 (9)   [on h]
    ... t [txg:20] promote p/b (8)   [on h]
    ... '''
    >>> objects, renames, promotions = history_objects(h)
    >>> for o in objects.values(): print(o["names"])
    [(10, 'p/a')]
    [(12, 'p/a@s0'), (20, 'p/b@s0')]
    [(14, 'p/a@s1'), (20, 'p/b@s1')]
    [(15, 'p/b')]
    [(16, 'p/a@s2')]
    >>> promotions
    [(20, 'p/b')]
    """
    objects, renames, promotions = {}, [], []
    how = {"create": "created", "clone": "clone", "snapshot": "snapshot"}
    for line in text.splitlines():
        m = HISTORY_EVENT.match(line)
        if not m:
            continue
        txg, op, name, oid, rest = int(m.group(1)), m.group(2), m.group(3), m.group(4), m.group(5)
        if op in how:
            objects[oid] = {"names": [(txg, name)], "born": txg, "how": how[op], "destroyed": None}
            origin = re.search(r"origin=\S+ \((\d+)\)", rest) if op == "clone" else None
            if origin:
                objects[oid]["origin"] = origin.group(1)
        elif op == "destroy" and oid in objects:
            objects[oid]["destroyed"] = txg
        elif op == "rename":
            new = rest.split("->", 1)[1].split()[0]
            old = objects[oid]["names"][-1][1] if oid in objects else name
            renames.append((txg, old, new))
            for o in objects.values():
                cur = o["names"][-1][1]
                if o["destroyed"] is None and (cur == old or cur.startswith((old + "@", old + "/"))):
                    o["names"].append((txg, new + cur[len(old):]))
        elif op == "promote":
            promotions.append((txg, objects[oid]["names"][-1][1] if oid in objects else name))
            # The origin's snapshots up to the one the clone came of
            # move to the clone, under its name.
            snap = objects.get(objects.get(oid, {}).get("origin"))
            if snap:
                origin_ds, clone = snap["names"][-1][1].split("@")[0], objects[oid]["names"][-1][1]
                for o in objects.values():
                    cur = o["names"][-1][1]
                    if (o["destroyed"] is None and o["how"] == "snapshot" and cur.startswith(origin_ds + "@")
                            and o["born"] <= snap["born"]):
                        o["names"].append((txg, clone + cur[len(origin_ds):]))
    return objects, renames, promotions


def compare_timeline(history_text, guids, pool, doc, returncode):
    """zvoltimeline's history of a pool (its JSON, its exit code) against
    `zpool history -il` and the GUIDs the builder recorded.

    Every dataset and snapshot it says came into being must, under any
    name it had, have come into being at that TXG and in that manner,
    and have the GUID recorded for it; every one the pool holds must be
    there. Every rename, promotion and destroy it reports must be one
    the record has, at the first TXG it read after it; and every one of
    a dataset it read before then must be reported. Only the TXGs it
    read count: one it says did not read shows nothing. The pool's root
    is left out: its dataset comes before the history does.

    >>> h = "History for 'p':\\nt [txg:10] create p/a (5)   [on h]\\nt [txg:40] rename p/a (5) -> p/c [on h]\\n"
    >>> doc = {"txgs": [30, 50], "events": [
    ...     {"event": "created", "object": "p/a", "txg": 10, "guid": "0x10"},
    ...     {"event": "renamed", "object": "p/c", "txg": 50, "details": "was p/a"}]}
    >>> compare_timeline(h, {"p/c": 16}, "p", doc, 0)
    ('ok', [])
    >>> doc["events"][0]["txg"] = 11
    >>> compare_timeline(h, {"p/c": 16}, "p", doc, 0)
    ('mismatch', ['p/a: created at txg 11, the record says 10'])
    >>> doc["events"][0]["txg"] = 10; doc["events"][1]["details"] = "was p/b"
    >>> compare_timeline(h, {"p/c": 16}, "p", doc, 0)
    ('mismatch', ['p/c: renamed at txg 50 from p/b, which the record has no rename for'])
    >>> compare_timeline(h, {"p/c": 16}, "p", {"txgs": [30, 50], "events": []}, 0)
    ('mismatch', ['p/c: not said to have come into being', 'renamed p/a -> p/c at txg 40: not reported'])
    >>> compare_timeline(h, {"p/c": 16}, "p", {"txgs": [30, 50], "events": []}, 4)
    ('incomplete (history said not whole)', [])
    >>> compare_timeline(h, {"p/c": 16}, "p", {"txgs": [45, 50], "events": [
    ...     {"event": "created", "object": "p/c", "txg": 10, "guid": "0x10"}]}, 0)
    ('ok', [])

    A TXG read in part counts for what it reports there:

    >>> doc = {"txgs": [45, 50], "partial_txgs": [45], "events": [
    ...     {"event": "created", "object": "p/a", "txg": 10, "guid": "0x10"},
    ...     {"event": "unreadable", "txg": 45},
    ...     {"event": "renamed", "object": "p/c", "txg": 45, "details": "was p/a"}]}
    >>> compare_timeline(h, {"p/c": 16}, "p", doc, 0)
    ('ok', [])
    """
    objects, renames, promotions = history_objects(history_text)
    unread = {e.get("txg") for e in doc.get("events", []) if e.get("event") == "unreadable"}
    unread |= set(doc.get("unreadable_txgs") or [])
    # A TXG where part of the tree did not read (`partial_txgs`) is read
    # for what did: a change reported there is one the tool saw, at the
    # first TXG it read after it. What it must report is held to the
    # TXGs read whole.
    partial = set(doc.get("partial_txgs") or [])
    read = sorted(t for t in (doc.get("txgs") or []) if t not in unread)
    looked = sorted(t for t in (doc.get("txgs") or []) if t not in unread - partial)
    first_after = lambda h: next((t for t in read if t >= h), None)
    firsts = lambda h: {next((t for t in ts if t >= h), None) for ts in (read, looked)} - {None}
    exists_at = lambda o, t: o["born"] <= t and (o["destroyed"] is None or t < o["destroyed"])
    named = lambda o, name: any(n == name for _, n in o["names"])
    final = lambda o: o["names"][-1][1]
    diffs, seen, reported = [], set(), set()
    for e in doc.get("events", []):
        kind, name, txg = e.get("event"), e.get("object"), e.get("txg")
        if kind in ("created", "clone", "snapshot"):
            if name == pool:
                continue
            had = [(k, o) for k, o in objects.items() if named(o, name)]
            if not had:
                diffs.append(f"{name}: {kind} at txg {txg}, and the record has no such dataset")
                continue
            k, o = next(((k, o) for k, o in had if o["born"] == txg), had[-1])
            seen.add(k)
            if txg != o["born"]:
                diffs.append(f"{name}: {kind} at txg {txg}, the record says {o['born']}")
            if kind != o["how"]:
                diffs.append(f"{name}: {kind}, the record says {o['how']}")
            g = guids.get(final(o)) if o["destroyed"] is None else None
            if g is not None and e.get("guid") and int(e["guid"], 16) != g:
                diffs.append(f"{name}: guid {e['guid']}, the record says {g:#x}")
        elif kind in ("destroyed", "snapshot-destroyed"):
            if not any(o["destroyed"] is not None and txg in firsts(o["destroyed"]) and named(o, name)
                       for o in objects.values()):
                diffs.append(f"{name}: {kind} at txg {txg}, which the record has no destroy for")
            reported.add((kind, name, txg))
        elif kind == "renamed":
            was = re.search(r"was (\S+)", e.get("details", ""))
            was = was.group(1) if was else ""
            # A dataset's rename takes its snapshots and children with it,
            # and each may be reported as renamed in its own right.
            if not any(txg in firsts(h) and name.startswith(new) and name[len(new):][:1] in ("", "@", "/")
                       and was == old + name[len(new):] for h, old, new in renames):
                diffs.append(f"{name}: renamed at txg {txg} from {was}, which the record has no rename for")
            reported.add((kind, name, txg))
        elif kind == "promoted":
            if not any(txg in firsts(h) and n == name for h, n in promotions):
                diffs.append(f"{name}: promoted at txg {txg}, which the record has no promotion for")
            reported.add((kind, name, txg))
    # What it must have said: every dataset and snapshot the pool still
    # holds, and every change to one that a TXG it read before the change
    # held.
    missing = [f"{final(o)}: not said to have come into being"
               for k, o in sorted(objects.items(), key=lambda kv: final(kv[1]))
               if o["destroyed"] is None and k not in seen]
    unreported = []
    for h, old, new in renames:
        at = first_after(h)
        held = any(named(o, old) and exists_at(o, t) for o in objects.values() for t in read if t < h)
        if at is not None and held and not any(("renamed", new, a) in reported for a in firsts(h)):
            unreported.append(f"renamed {old} -> {new} at txg {h}: not reported")
    for o in objects.values():
        h = o["destroyed"]
        if h is None or first_after(h) is None or not any(exists_at(o, t) for t in read if t < h):
            continue
        kind = "snapshot-destroyed" if "@" in final(o) else "destroyed"
        if not any((kind, final(o), a) in reported for a in firsts(h)):
            unreported.append(f"{kind} {final(o)} at txg {h}: not reported")
    for h, name in promotions:
        at = first_after(h)
        if read and read[0] < h and at is not None and not any(("promoted", name, a) in reported for a in firsts(h)):
            unreported.append(f"promoted {name} at txg {h}: not reported")
    if diffs:
        return "mismatch", missing + diffs + unreported
    if missing or unreported:
        return (INCOMPLETE_TIMELINE, []) if returncode == 4 else ("mismatch", missing + unreported)
    return ("ok", []) if returncode == 0 else (INCOMPLETE_TIMELINE, [])


def judge_timeline(args, oracle, members, work, assume=(), extra=()):
    """zvoltimeline over the members, held against the pool's own record
    of its history (`compare_timeline`)."""
    log = os.path.join(work, "timeline.debug")
    cmd = [args.timeline_tool, "-q", "-f", "json", "--debug-log", log, *members]
    for path in assume:
        cmd += ["--assume-member", path]
    cmd += list(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    trace = open(log, errors="replace").read() if os.path.exists(log) else ""
    redundancy = bool(REDUNDANCY.search(trace))
    if refusal(proc.returncode, proc.stderr):
        return "refused", [], redundancy
    if proc.returncode not in (0, 4):
        why = proc.stderr.strip().splitlines()
        return f"exit {proc.returncode}: {why[-1][:160] if why else ''}", [], redundancy
    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        return f"exit {proc.returncode}, no JSON on stdout", [], redundancy
    outcome, diffs = compare_timeline(oracle.history, oracle.guids, oracle.pool, doc, proc.returncode)
    return outcome, diffs[:10] + ([f"... {len(diffs) - 10} more"] if len(diffs) > 10 else []), redundancy


# What `zdb -d` names at a TXG (datasets-by-txg/<txg>.txt, one line a
# dataset): its name, the kind of its object set, its object number, the
# TXG it was created in, what it references as zdb prints a size, and
# how many objects it holds.
ZDB_DATASET = re.compile(r"^Dataset (\S+) \[(\w+)\], ID (\d+), cr_txg (\d+), (\S+), (\d+) objects")
# The kind of object set `zdb` names against the type `list` gives.
ZDB_KIND = {"filesystem": "ZPL", "snapshot(filesystem)": "ZPL",
            "volume": "ZVOL", "snapshot(volume)": "ZVOL"}
INCOMPLETE_LIST = "incomplete (parts of the tree said unread)"


def nicenum(num):
    """A byte count as `zdb` prints it (zfs_nicenum_format, base 1024):
    a whole multiple of its unit as an integer, otherwise with the most
    decimals that fit in five characters.

    >>> [nicenum(n) for n in (0, 512, 1024, 159640, 10370000, 36175872, 1536)]
    ['0', '512', '1K', '156K', '9.89M', '34.5M', '1.50K']
    """
    units = ["", "K", "M", "G", "T", "P", "E"]
    n, index = num, 0
    while n >= 1024 and index < len(units) - 1:
        n //= 1024
        index += 1
    if index == 0 or num % (1024 ** index) == 0:
        return f"{n}{units[index]}"
    for prec in (2, 1, 0):
        text = f"{num / 1024 ** index:.{prec}f}{units[index]}"
        if len(text) <= 5:
            break
    return text


def zdb_datasets(text):
    """Every dataset `zdb -d` names, the MOS aside, by name.

    >>> zdb_datasets("Dataset mos [META], ID 0, cr_txg 4, 10.5M, 791 objects\\n"
    ...              "Dataset p/v [ZVOL], ID 54, cr_txg 9, 156K, 2 objects\\n")
    {'p/v': ('ZVOL', 54, 9, '156K')}
    """
    out = {}
    for line in text.splitlines():
        m = ZDB_DATASET.match(line)
        if m and m.group(1) != "mos":
            out[m.group(1)] = (m.group(2), int(m.group(3)), int(m.group(4)), m.group(5))
    return out


ZDB_REFCOUNT = re.compile(r"^Verified (\S+) feature refcount of (\d+) is correct")


def zdb_refcounts(text):
    """The feature refcounts `zdb -d` verified, by the feature's short name.

    >>> zdb_refcounts("Verified large_blocks feature refcount of 0 is correct\\n"
    ...               "Verified encryption feature refcount of 52 is correct\\n")
    {'large_blocks': 0, 'encryption': 52}
    """
    return {m.group(1): int(m.group(2)) for m in map(ZDB_REFCOUNT.match, text.splitlines()) if m}


def compare_features(states, refcounts, doc, end=True):
    """The features `list` read from the MOS against `zpool get feature@`
    (`states`: the short name of every feature the pool has enabled,
    active or enabled) and the refcounts `zdb -d` verified at the same
    TXG (`refcounts`). A name zdb verified that `zpool get` does not
    know is zdb's own count (`indirect_refcount`), not a feature.

    >>> doc = {"features": [{"guid": "com.delphix:a", "state": "active", "refcount": 2},
    ...                     {"guid": "org.x:b", "state": "enabled", "refcount": 0}]}
    >>> compare_features({"a": "active", "b": "enabled"}, {"a": 2, "b": 0, "c": 0}, doc)
    ('ok', [])
    >>> compare_features({"a": "active", "b": "active"}, {"a": 3}, doc)
    ('mismatch', ['a: refcount 3 != 2', 'b: state active != enabled'])
    >>> compare_features({"a": "active"}, {}, {"features": [], "features_error": "unread"})
    ('refused', [])

    At an older TXG than the end (`end=False`) `zpool get` says nothing
    of a feature's state, and only zdb's count there does:

    >>> compare_features({"a": "active", "b": "active"}, {"a": 2}, doc, end=False)
    ('ok', [])
    """
    if doc.get("features_error"):
        return "refused", []
    got = {f["guid"].split(":", 1)[-1]: f for f in doc.get("features", [])}
    diffs = [f"{n}: enabled, and not listed" for n in sorted(states) if n not in got]
    diffs += [f"{n}: listed, and not enabled" for n in sorted(got) if n not in states]
    for n in sorted(set(states) & set(got)):
        # `zpool get` says what a feature is at the end; at an older TXG
        # (a checkpoint's, taken before the checkpoint's own feature was
        # counted) zdb's count of it there is what says.
        want = states[n] if end else None
        if n in refcounts:
            if refcounts[n] != got[n].get("refcount"):
                diffs.append(f"{n}: refcount {refcounts[n]} != {got[n].get('refcount')}")
            want = "active" if refcounts[n] else "enabled"
        if want is not None and want != got[n].get("state"):
            diffs.append(f"{n}: state {want} != {got[n].get('state')}")
    return ("mismatch", diffs) if diffs else ("ok", [])


def compare_listing(want, doc, returncode):
    """A `list -r` (its JSON, its exit code) against what `zdb -d` named
    at the same TXG. `ok` when every dataset is there with the same
    kind, object number, creation TXG and referenced size, and nothing
    else is; INCOMPLETE_LIST when the run ended 4 naming parts of the
    tree it could not read (`errors`) and every dataset it did list is
    right; otherwise what differs — a dataset listed that zdb does not
    name, one listed differently, one missing that nothing it said
    accounts for.

    >>> want = {"p": ("ZPL", 54, 1, "156K"), "p/v": ("ZVOL", 70, 9, "1K")}
    >>> got = {"datasets": [
    ...     {"name": "p", "type": "filesystem", "object": 54, "creation_txg": 1, "referenced_bytes": 159640},
    ...     {"name": "p/v", "type": "volume", "object": 70, "creation_txg": 9, "referenced_bytes": 1024}]}
    >>> compare_listing(want, got, 0)
    ('ok', [])
    >>> got["datasets"][1]["creation_txg"] = 8
    >>> compare_listing(want, got, 0)
    ('mismatch', ['p/v: creation txg 9 != 8'])
    >>> compare_listing(want, {"datasets": got["datasets"][:1], "errors": ["p/v: unread"]}, 4)
    ('incomplete (parts of the tree said unread)', [])
    >>> compare_listing(want, {"datasets": got["datasets"][:1]}, 0)
    ('mismatch', ['p/v: missing, and nothing said of it'])
    >>> compare_listing({}, {"datasets": got["datasets"][:1]}, 0)
    ('mismatch', ['p: not at that txg'])

    A dataset whose object set did not read is listed with its kind
    `unreadable` (`snapshot(unreadable)`): what the tool says it could not
    tell is not a kind it got wrong, and the listing is not all there is.

    >>> got["datasets"][1].update(type="snapshot(unreadable)", creation_txg=9)
    >>> compare_listing(want, got, 4)
    ('incomplete (parts of the tree said unread)', [])
    """
    got = {d.get("name"): d for d in doc.get("datasets", [])}
    said = returncode == 4 and bool(doc.get("errors"))
    diffs, admitted = [], False
    for name, (kind, obj, created, size) in sorted(want.items()):
        g = got.get(name)
        if g is None:
            if said:
                admitted = True
            else:
                diffs.append(f"{name}: missing, and nothing said of it")
            continue
        unread = g.get("type") in ("unreadable", "snapshot(unreadable)")
        admitted |= unread
        checks = [("kind", kind, kind if unread else ZDB_KIND.get(g.get("type"), g.get("type"))),
                  ("object", obj, g.get("object")),
                  ("creation txg", created, g.get("creation_txg")),
                  ("referenced", size, nicenum(g["referenced_bytes"])
                   if isinstance(g.get("referenced_bytes"), int) else None)]
        diffs += [f"{name}: {what} {a} != {b}" for what, a, b in checks if a != b]
    diffs += [f"{name}: not at that txg" for name in sorted(got) if name not in want]
    if diffs:
        return "mismatch", diffs
    return (INCOMPLETE_LIST, []) if admitted else ("ok", [])


def changes(by_txg):
    """The TXGs at which what `zdb -d` names differs from the TXG before.

    `zdb -t T` reads the pool at the newest uberblock at or before T, so
    a TXG whose listing differs from the one before it is one an
    uberblock was written at.

    >>> changes({4: {"a": 1}, 5: {"a": 1}, 6: {"a": 2}, 7: {"a": 2}})
    [6]
    """
    txgs = sorted(by_txg)
    return [t for prev, t in zip(txgs, txgs[1:]) if by_txg[t] != by_txg[prev] and t == prev + 1]


def judge_list(args, oracle, members, work, assume=(), extra=(), control=False):
    """`list -r` held against `zdb -d` at the TXG it listed at; on the
    control case at every TXG it says it can read that zdb recorded,
    with `--txg`, and its TXGs held against the ones zdb's listing
    changes at. Returns (outcomes, details, judged at)."""
    hints = [a for path in assume for a in ("--assume-member", path)]
    base = [args.tool, "-q", "-f", "json", "list", "-r", *members, *hints, *extra]
    newest = max(oracle.by_txg)
    outcomes, details, at = {}, {}, []

    def one(label, cmd):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if refusal(proc.returncode, proc.stderr):
            outcomes[label] = "refused"
            return None
        if proc.returncode not in (0, 4):
            why = proc.stderr.strip().splitlines()
            outcomes[label] = f"exit {proc.returncode}: {why[-1][:160] if why else ''}"
            return None
        try:
            doc = json.loads(proc.stdout)
        except ValueError:
            outcomes[label] = f"exit {proc.returncode}, no JSON on stdout"
            return None
        passed = said_passed_over(proc.stdout)
        if proc.returncode == 0 and passed:
            outcomes[label] = "exit 0, a newer txg passed over"
            return doc
        if proc.returncode == 4 and not doc.get("errors") and not passed:
            outcomes[label] = "exit 4, and no part of the tree or txg passed over named"
            return doc
        txg = doc.get("txg")
        if not isinstance(txg, int) or txg > newest:
            outcomes[label] = f"listed at txg {txg}, newer than any the pool reached ({newest})"
            return doc
        if txg not in oracle.by_txg:
            # Older than the oracle's listings reach: not judged.
            return doc
        outcomes[label], diffs = compare_listing(oracle.by_txg[txg], doc, proc.returncode)
        at.append(txg)
        if diffs:
            details[label] = diffs[:10] + ([f"... {len(diffs) - 10} more"] if len(diffs) > 10 else [])
        if oracle.feature_states:
            key = f"{label} features"
            outcomes[key], fdiffs = compare_features(oracle.feature_states,
                                                     oracle.refcounts_by_txg.get(txg, {}), doc,
                                                     end=txg == newest)
            if fdiffs:
                details[key] = fdiffs[:10]
        return doc

    doc = one("newest", base)
    if control and doc is not None:
        have = [t for t in doc.get("available_txgs", []) if isinstance(t, int)]
        for t in have:
            if t in oracle.by_txg and t != doc.get("txg"):
                one(f"txg {t}", base + ["--txg", str(t)])
        # The TXGs of the rings: the checkpoint's listing is of another
        # line of the pool's life, and no change of the one they make.
        ring = {t: v for t, v in oracle.by_txg.items() if t != oracle.checkpoint_txg}
        unlisted = [t for t in changes(ring) if t not in have]
        if unlisted:
            outcomes["txgs"] = "mismatch"
            details["txgs"] = [f"zdb's listing changes at txg {t}, which list does not name" for t in unlisted]
    return outcomes, details, sorted(at)


def zdb_labels(text):
    """The labels `zdb -l` printed, as (label numbers, nvlist): an
    integer value as an int, a quoted one as a string, a nested list as
    a dict, `children[i]` as a list, and a bare name (a feature of
    `features_for_read`) as a key set to True — the shape `scan -vv`
    gives a label's nvlist in its JSON.

    >>> zdb_labels('''------------------------------------
    ... LABEL 0
    ... ------------------------------------
    ...     name: 'p'
    ...     txg: 9
    ...     vdev_tree:
    ...         type: 'mirror'
    ...         children[0]:
    ...             guid: 7
    ...         children[1]:
    ...             guid: 8
    ...     features_for_read:
    ...         com.delphix:hole_birth
    ...     labels = 0 1 2 3
    ... ''')
    [([0, 1, 2, 3], {'name': 'p', 'txg': 9, 'vdev_tree': {'type': 'mirror', 'children': [{'guid': 7}, {'guid': 8}]}, 'features_for_read': {'com.delphix:hole_birth': True}})]
    """
    sections = []
    for raw in text.splitlines():
        if raw.strip().startswith("LABEL "):
            sections.append([])
        elif sections and not raw.startswith("---"):
            sections[-1].append(raw)
    out = []
    for lines in sections:
        root, labels = {}, []
        stack = [(-1, root)]
        for raw in lines:
            if not raw.strip():
                continue
            m = re.match(r"^\s*labels = ([\d ]+)\s*$", raw)
            if m:
                labels = [int(x) for x in m.group(1).split()]
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            line = raw.strip()
            while len(stack) > 1 and indent <= stack[-1][0]:
                stack.pop()
            parent = stack[-1][1]
            m = re.match(r"^(\S+?)(\[(\d+)\])?:(?:\s+(.*))?$", line)
            if not m:
                parent[line] = True
                continue
            key, idx, val = m.group(1), m.group(3), m.group(4)
            if val is None:
                child = {}
                if idx is not None:
                    parent.setdefault(key, []).append(child)
                else:
                    parent[key] = child
                stack.append((indent, child))
            elif len(val) > 1 and val[0] == val[-1] == "'":
                parent[key] = val[1:-1]
            else:
                parent[key] = int(val) if re.fullmatch(r"-?\d+", val) else val
        out.append((labels, root))
    return out


def zdb_uberblock(text):
    """The uberblock `zdb -u` printed: its TXG, version, GUID sum,
    timestamp, root block's logical birth and checkpoint TXG.

    >>> zdb_uberblock('''Uberblock:
    ... \\tmagic = 0000000000bab10c
    ... \\tversion = 5000
    ... \\ttxg = 4994
    ... \\tguid_sum = 3365034843304634015
    ... \\ttimestamp = 1791627863 UTC = Sat Oct 10 10:24:23 2026
    ... \\tbp = DVA[0]=<2:2d1ef000:3000> [L0 DMU objset] size=1000L/1000P birth=4994L/4994P fill=793
    ... \\tcheckpoint_txg = 0
    ... ''')
    {'version': 5000, 'txg': 4994, 'guid_sum': 3365034843304634015, 'timestamp': 1791627863, 'rootbp_birth': 4994, 'checkpoint_txg': 0}

    Of a pool with a checkpoint zdb prints, after the pool's own, the
    uberblock the checkpoint keeps (`Checkpointed uberblock found:`):
    that one is zdb_checkpoint's, not this.

    >>> both = "Uberblock:\\n\\ttxg = 288\\n\\tcheckpoint_txg = 0\\n\\nCheckpointed uberblock found:\\n\\ttxg = 167\\n\\tcheckpoint_txg = 167\\n"
    >>> zdb_uberblock(both), zdb_checkpoint(both)["txg"]
    ({'txg': 288, 'checkpoint_txg': 0}, 167)
    """
    text = text.split("Checkpointed uberblock found:", 1)[0]
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\s*(version|txg|guid_sum|timestamp|checkpoint_txg) = (\d+)", line)
        if m:
            out[m.group(1)] = int(m.group(2))
        m = re.search(r"\bbirth=(\d+)L", line)
        if m and line.strip().startswith("bp ="):
            out["rootbp_birth"] = int(m.group(1))
    return out if "txg" in out else {}


def zdb_checkpoint(text):
    """The uberblock a pool checkpoint keeps, as `zdb -u` printed it
    after the pool's own (zdb_uberblock), or {} without a checkpoint."""
    if "Checkpointed uberblock found:" not in text:
        return {}
    return zdb_uberblock(text.split("Checkpointed uberblock found:", 1)[1])


def zdb_rings(text):
    r"""The uberblock rings `zdb -lu` printed of one member: for each
    label number, its slots — slot number to the uberblock in it (as
    zdb_uberblock gives one). Slots alike in several labels are printed
    once with their label numbers; a slot not printed is empty.

    >>> rings = zdb_rings("LABEL 0\n    name: 'p'\n    labels = 0 1 2 3\n"
    ...     "    Uberblock[3]\n\tmagic = 0000000000bab10c\n\tversion = 5000\n\ttxg = 4803\n"
    ...     "\tguid_sum = 9\n\ttimestamp = 1791627862 UTC = Sat Oct 10 10:24:22 2026\n"
    ...     "\tbp = DVA[0]=<2:2c:3000> [L0 DMU objset] size=1000L/1000P birth=4803L/4803P\n"
    ...     "\tcheckpoint_txg = 0\n        labels = 0 2\n")
    >>> sorted(rings), rings[2][3]["txg"], rings[2][3]["rootbp_birth"], 3 in rings.get(1, {})
    ([0, 2], 4803, 4803, False)
    """
    rings, lines, slot = {}, None, None
    for line in text.splitlines():
        m = re.match(r"^\s*Uberblock\[(\d+)\]", line)
        if m:
            lines, slot = [], int(m.group(1))
            continue
        if lines is None:
            continue
        m = re.match(r"^\s*labels = ([\d ]+)\s*$", line)
        if m:
            ub = zdb_uberblock("\n".join(lines))
            for lab in (int(x) for x in m.group(1).split()):
                rings.setdefault(lab, {})[slot] = ub
            lines, slot = None, None
            continue
        lines.append(line)
    return rings


def zpool_status_tops(text, layout=None):
    """The top-level vdevs `zpool status` printed, by id: kind, parity,
    for a dRAID its data disks, children and spares, and the paths of
    its leaves in order — a slot under replacement (`spare-2`,
    `replacing-4`) its devices in its place. Those of the special, dedup
    and log classes too, under their sections. A top-level vdev that is
    one device is printed as its path alone, with no id: with the
    layout, it is the top-level vdev the layout has that device in.

    >>> s = ("config:\\n\\n\\tNAME  STATE\\n\\tp  ONLINE\\n\\t  mirror-0  ONLINE\\n\\t    /a  ONLINE\\n"
    ...      "\\t    /b  ONLINE\\n\\t  draid1:2d:4c:1s-1  ONLINE\\n\\t    /c  ONLINE\\n\\tspares\\n\\t  draid1-1-0  AVAIL\\n")
    >>> zpool_status_tops(s)[0]
    {'kind': 'mirror', 'nparity': None, 'paths': ['/a', '/b']}
    >>> zpool_status_tops(s)[1]
    {'kind': 'draid', 'nparity': 1, 'draid_ndata': 2, 'children': 4, 'draid_nspares': 1, 'paths': ['/c']}
    >>> s = ("config:\\n\\n\\tNAME  STATE\\n\\tp  DEGRADED\\n\\t  raidz2-0  DEGRADED\\n\\t    /a  ONLINE\\n"
    ...      "\\t    spare-1  DEGRADED\\n\\t      /b  OFFLINE\\n\\t      /s  ONLINE\\n\\t    /c  ONLINE\\n"
    ...      "\\tspecial\\n\\t  mirror-2  ONLINE\\n\\t    /d  ONLINE\\n\\t    /e  ONLINE\\n"
    ...      "\\tlogs\\n\\t  /m/log.img  ONLINE\\n\\tspares\\n\\t  /s  INUSE\\n")
    >>> lay = {"tops": [{"index": 3, "kind": "file", "members": ["t3-file-0"]}],
    ...        "members": {"t3-file-0": {"file": "log.img"}}}
    >>> t = zpool_status_tops(s, lay)
    >>> sorted(t), t[0]["paths"], t[2]["kind"], t[3]
    ([0, 2, 3], ['/a', '/b', '/s', '/c'], 'mirror', {'kind': 'file', 'nparity': None, 'paths': ['/m/log.img']})
    """
    single = {}
    for top in (layout or {}).get("tops", []):
        if len(top.get("members", [])) == 1 and not top["kind"].startswith(("mirror", "raidz", "draid")):
            single[layout["members"][top["members"][0]]["file"]] = top
    tops, cur, inside = {}, None, False
    for raw in text.splitlines():
        if raw.startswith("config:"):
            inside = True
            continue
        if not inside or not raw.startswith("\t"):
            if inside and raw.strip() and not raw.startswith("\t"):
                inside = False
            continue
        body = raw[1:]
        depth = (len(body) - len(body.lstrip(" "))) // 2
        name = body.strip().split()[0] if body.strip() else ""
        if depth == 0:
            # The pool's own line, the header, or a section: what is under
            # the pool's line and under the classes' sections is a
            # top-level vdev; a spare or a cache device is not.
            cur = None
            inside = name not in ("spares", "cache")
            continue
        if depth == 1:
            m = re.match(r"^(mirror|raidz(\d)|draid(\d):(\d+)d:(\d+)c:(\d+)s)-(\d+)$", name)
            top = single.get(os.path.basename(name))
            if not m and top is not None:
                tops[top["index"]] = {"kind": top["kind"], "nparity": None, "paths": [name]}
                cur = None
                continue
            if not m:
                cur = None
                continue
            if m.group(1) == "mirror":
                cur = {"kind": "mirror", "nparity": None}
            elif m.group(2):
                cur = {"kind": "raidz", "nparity": int(m.group(2))}
            else:
                cur = {"kind": "draid", "nparity": int(m.group(3)), "draid_ndata": int(m.group(4)),
                       "children": int(m.group(5)), "draid_nspares": int(m.group(6))}
            cur["paths"] = []
            tops[int(m.group(7))] = cur
        elif depth == 2 and cur is not None:
            if re.fullmatch(r"(spare|replacing)-\d+", name):
                continue          # a slot: its devices follow, a level down
            cur["paths"].append(name)
        elif depth == 3 and cur is not None and not re.fullmatch(r"draid\d+-\d+-\d+", name):
            cur["paths"].append(name)
    return tops


def nv_diff(want, got, at=""):
    """Where two nvlists differ, by the path of each value.

    >>> nv_diff({"a": 1, "t": {"c": [{"g": 7}, {"g": 8}]}}, {"a": 1, "t": {"c": [{"g": 7}, {"g": 9}]}, "x": 2})
    ['t.c[1].g: 8 != 9', 'x: null != 2']

    `zdb -l` prints an array of integers as its values on one line, so
    that an array of one is an integer to read and one of several a
    string (`raidz_expand_txgs` of a raidz expanded once, and twice):

    >>> nv_diff({"e": 181, "f": "181 250"}, {"e": [181], "f": [181, 250]}), nv_diff({"e": 182}, {"e": [181]})
    ([], ['e: 182 != [181]'])
    """
    if (isinstance(got, list) and not isinstance(want, (list, dict)) and want is not None
            and all(isinstance(x, int) for x in got) and " ".join(map(str, got)) == str(want)):
        return []
    if isinstance(want, dict) and isinstance(got, dict):
        out = []
        for k in sorted(set(want) | set(got)):
            out += nv_diff(want.get(k), got.get(k), f"{at}.{k}" if at else k)
        return out
    if isinstance(want, list) and isinstance(got, list) and len(want) == len(got):
        return [d for i, (w, g) in enumerate(zip(want, got)) for d in nv_diff(w, g, f"{at}[{i}]")]
    return [] if want == got else [f"{at}: {json.dumps(want)[:120]} != {json.dumps(got)[:120]}"]


# Of a label's nvlist, what an intact label of the same member may say
# otherwise at another point of the pool's life: its state (ACTIVE while
# imported, EXPORTED after) and the TXG its configuration was written at.
LABEL_MAY_DIFFER = {"state", "txg"}


def compare_scan(oracle, doc, roles, control):
    """`scan -vv` (its JSON) against what zdb and zpool printed of the
    pool. Returns (outcomes, details): per member `label` — the nvlist
    of the label it read against `zdb -l`, every key but the state and
    the TXG the same (on the control those too), `refused` where no
    label of it read; `uberblock txg N` — every copy of that uberblock
    that verifies against `zdb -u`; `pool` — the top-level vdevs it
    assembled against `zpool status` and the labels' GUIDs.
    """
    outcomes, details = {}, {}
    # With `multihost=on` the last slot of every ring is the heartbeat's
    # (MMP_BLOCKS_PER_LABEL): a sync puts its uberblock in slot
    # txg % (slots - 1), the heartbeat rewrites the newest one into the
    # last slot of a label at a time with the time of the beat — copies of
    # one TXG that differ in their timestamp alone — and `zdb -lu` does not
    # print that slot (zdb's dump_label_uberblocks, short of -uuuu).
    mmp = 1 if getattr(oracle, "multihost", False) else 0

    def heartbeat(lab, u):
        return mmp and u.get("slot") == (lab.get("slots") or 0) - 1
    for dev in doc.get("devices", []):
        role = roles.get(dev.get("path"))
        want = oracle.labels.get(role)
        if role is None or not want:
            continue
        nv = dev.get("nvlist")
        if not nv:
            outcomes[f"label {role}"] = "mismatch" if control else "refused"
            if control:
                details[f"label {role}"] = ["no label read on an undamaged member"]
            continue
        skip = set() if control else LABEL_MAY_DIFFER
        diffs = nv_diff({k: v for k, v in want.items() if k not in skip},
                        {k: v for k, v in nv.items() if k not in skip})
        if not control and isinstance(nv.get("txg"), int) and nv["txg"] > want.get("txg", 0):
            diffs.append(f"txg {nv['txg']} is newer than the pool reached ({want.get('txg')})")
        if control:
            bad = [l.get("index") for l in dev.get("labels", [])
                   if l.get("config_checksum") != "ok" or l.get("label_txg") != want.get("txg")]
            if bad:
                diffs.append(f"labels {bad} not read as zdb read all four")
        outcomes[f"label {role}"] = "mismatch" if diffs else "ok"
        if diffs:
            details[f"label {role}"] = diffs[:10]
    for ub in oracle.uberblocks:
        key = f"uberblock txg {ub['txg']}"
        copies, diffs = 0, []
        for dev in doc.get("devices", []):
            for lab in dev.get("labels", []):
                for u in lab.get("uberblocks", []):
                    if u.get("checksum") != "ok":
                        continue
                    if (control and not heartbeat(lab, u)
                            and u.get("slot") != u.get("txg", 0) % max((lab.get("slots") or 1) - mmp, 1)):
                        diffs.append(f"{os.path.basename(dev['path'])} L{lab.get('index')}: txg {u.get('txg')} in slot {u.get('slot')}")
                    if u.get("txg") != ub["txg"]:
                        continue
                    copies += 1
                    got = {"version": u.get("version"), "txg": u.get("txg"),
                           "guid_sum": int(u["guid_sum"], 16) if isinstance(u.get("guid_sum"), str) else u.get("guid_sum"),
                           "timestamp": u.get("timestamp"), "rootbp_birth": u.get("rootbp_birth"),
                           "checkpoint_txg": u.get("checkpoint_txg")}
                    diffs += [f"{os.path.basename(dev['path'])} L{lab.get('index')}: {k} {ub[k]} != {got.get(k)}"
                              for k in ub if ub[k] != got.get(k) and not (mmp and k == "timestamp")]
        if diffs:
            outcomes[key], details[key] = "mismatch", sorted(set(diffs))[:10]
        elif copies:
            outcomes[key] = "ok"
        else:
            outcomes[key] = "mismatch" if control else "refused"
            if control:
                details[key] = ["no copy of it on an undamaged pool"]
    # Every slot of every label's ring: a copy that verifies holds what
    # zdb printed of that slot, unless it is another TXG's — a slot the
    # damage forged, or an older copy of the member — which zdb's record
    # says nothing of. On the control every slot zdb printed is there.
    for dev in doc.get("devices", []):
        role = roles.get(dev.get("path"))
        want = oracle.rings.get(role)
        if role is None or not want:
            continue
        key, diffs, seen = f"rings {role}", [], 0
        for lab in dev.get("labels", []):
            idx = lab.get("index")
            wslots = want.get(idx, {})
            got = {u.get("slot"): u for u in lab.get("uberblocks", [])
                   if u.get("checksum") == "ok" and not (heartbeat(lab, u) and u.get("slot") not in wslots)}
            if control and sorted(got) != sorted(wslots):
                diffs.append(f"L{idx}: slots {sorted(set(wslots) ^ set(got))} not as zdb read them")
            for slot, u in got.items():
                w = wslots.get(slot)
                if w is None or w.get("txg") != u.get("txg"):
                    if control:
                        diffs.append(f"L{idx} slot {slot}: txg {u.get('txg')}, zdb read {w and w.get('txg')}")
                    continue
                seen += 1
                g = {"version": u.get("version"), "txg": u.get("txg"),
                     "guid_sum": int(u["guid_sum"], 16) if isinstance(u.get("guid_sum"), str) else u.get("guid_sum"),
                     "timestamp": u.get("timestamp"), "rootbp_birth": u.get("rootbp_birth"),
                     "checkpoint_txg": u.get("checkpoint_txg")}
                diffs += [f"L{idx} slot {slot}: {k} {w[k]} != {g.get(k)}" for k in w if w[k] != g.get(k)]
        outcomes[key] = "mismatch" if diffs else ("ok" if seen else "refused")
        if diffs:
            details[key] = diffs[:10]
    pools = [p for p in doc.get("pools", []) if p.get("name") == oracle.pool]
    if oracle.status_tops and pools:
        p, diffs = pools[0], []
        guid = next(iter(oracle.labels.values())).get("pool_guid") if oracle.labels else None
        facts = oracle.pool_facts
        # A GUID the tool says it does not know is no answer to judge: 0
        # for the pool, and for a vdev one with the marker the layout's
        # synthetic GUIDs carry (0x1117 in the top 16 bits), what a pool
        # read through `--hints` has when no label and no MOS says more.
        said_guid = int(p.get("guid", "0"), 16)
        if not said_guid:
            guid = None
            facts = {k: v for k, v in facts.items() if k != "pool_guid"}
        if facts.get("pool_guid") is not None and said_guid != facts["pool_guid"]:
            diffs.append(f"pool guid {facts['pool_guid']} (zdb -C) != {p.get('guid')}")
        for t in p.get("tops", []):
            i = t.get("id")
            if isinstance(i, int) and i < len(facts.get("ashift", [])) and t.get("ashift") != facts["ashift"][i]:
                diffs.append(f"top {i}: ashift {facts['ashift'][i]} (zdb -C) != {t.get('ashift')}")
        if guid is not None and int(p.get("guid", "0"), 16) != guid:
            diffs.append(f"pool guid {guid} != {p.get('guid')}")
        top_guid = {}
        for nv in oracle.labels.values():
            if "vdev_tree" in nv:
                top_guid[nv["vdev_tree"].get("id")] = nv["vdev_tree"].get("guid")
        for t in p.get("tops", []):
            w = oracle.status_tops.get(t.get("id"))
            if w is None:
                diffs.append(f"top {t.get('id')}: not in the pool")
                continue
            tree = t.get("tree") or {}
            tguid = int(t["guid"], 16) if t.get("guid") else None
            checks = [("kind", w["kind"], t.get("kind")), ("nparity", w["nparity"], t.get("nparity"))]
            if tguid is not None and tguid >> 48 != 0x1117:
                checks.append(("guid", top_guid.get(t.get("id")), tguid))
            if w["kind"] == "draid":
                checks += [("draid_ndata", w["draid_ndata"], tree.get("draid_ndata")),
                           ("draid_nspares", w["draid_nspares"], tree.get("draid_nspares")),
                           ("children", w["children"], len(t.get("members", [])))]
            else:
                checks.append(("children", len(w["paths"]), len(t.get("members", []))))
            if control:
                checks.append(("paths", w["paths"], [m.get("path") for m in t.get("members", [])]))
            diffs += [f"top {t.get('id')}: {k} {a} != {b}" for k, a, b in checks if a != b]
        if control:
            if sorted(t.get("id") for t in p.get("tops", [])) != sorted(oracle.status_tops):
                diffs.append(f"tops {sorted(t.get('id') for t in p.get('tops', []))} != {sorted(oracle.status_tops)}")
            if not p.get("readable"):
                diffs.append("the undamaged pool not readable")
        outcomes["pool"] = "mismatch" if diffs else "ok"
        if diffs:
            details["pool"] = diffs[:10]
    elif oracle.status_tops:
        outcomes["pool"] = "mismatch" if control else "refused"
        details["pool"] = [f"no pool {oracle.pool!r} assembled; pools: "
                           + ", ".join(repr(p.get("name")) for p in doc.get("pools", []))]
    return outcomes, details


def judge_scan(args, oracle, paths, members, work, extra=(), control=False):
    """`scan -vv` of the members, with the layout and maps the case
    gives (`--hints`, `--map`), held against the oracle (compare_scan)."""
    roles = {p: r for r, p in paths.items()}
    cmd = [args.tool, "-q", "-f", "json", "-vv", "scan", *[m for m in members if m], *extra_for_carver(extra)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if refusal(proc.returncode, proc.stderr):
        return {"scan": "refused"}, {}
    if proc.returncode != 0:
        why = proc.stderr.strip().splitlines()
        return {"scan": f"exit {proc.returncode}: {why[-1][:160] if why else ''}"}, {}
    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        return {"scan": "exit 0, no JSON on stdout"}, {}
    return compare_scan(oracle, doc, roles, control)


def compare_report(report, outcomes, files, oracle_volumes):
    """A report `zvolreport build` made of a case's evidence log, against
    what the harness found of each volume: an image read whole and
    right is an extraction with no error and the oracle's SHA-256; one
    the tool said is not the whole volume (exit 4, blocks zeroed) is an
    extraction that says so; one refused is no extraction; and every
    extraction's SHA-256 is that of the file it names. A TXG the dump
    passed over is a warning naming it.

    >>> rep = {"extractions": [{"dataset": "p/a", "sha256": "aa", "errors": 0, "aborted": False, "txg": 9}]}
    >>> compare_report(rep, {"p/a": "ok"}, {"p/a": "aa"}, {"p/a": "aa"})
    ('ok', [])
    >>> compare_report(rep, {"p/a": "ok"}, {"p/a": "aa"}, {"p/a": "bb"})
    ('mismatch', ['p/a: the report has sha256 aa, the oracle bb'])
    >>> compare_report(rep, {"p/a": "refused"}, {}, {"p/a": "aa"})
    ('mismatch', ['p/a: refused, and the report has an extraction of it'])
    >>> compare_report({"extractions": []}, {"p/a": "ok"}, {"p/a": "aa"}, {"p/a": "aa"})
    ('mismatch', ['p/a: read, and not in the report'])
    >>> rep["extractions"][0]["errors"] = 0
    >>> compare_report(rep, {"p/a": INCOMPLETE}, {"p/a": "aa"}, {"p/a": "aa"})
    ('mismatch', ['p/a: blocks written as zeros, and the report says none'])
    >>> compare_report(rep, {"p/a": "ok", "passed_over": {"p/a": "txg 12 (pool): MOS"}}, {"p/a": "aa"}, {"p/a": "aa"})
    ('mismatch', ['p/a: txg 12 passed over, and the report does not say so'])
    >>> rep["warnings"] = ["p/a: txg 12 names it and does not read it (MOS); extracted at the older txg 9"]
    >>> compare_report(rep, {"p/a": "ok", "passed_over": {"p/a": "txg 12 (pool): MOS"}}, {"p/a": "aa"}, {"p/a": "aa"})
    ('ok', [])
    """
    by = {}
    for e in report.get("extractions", []):
        by.setdefault(e.get("dataset"), []).append(e)
    warnings = report.get("warnings") or []
    passed = (outcomes.get("passed_over") or {})
    diffs = []
    for vol, outcome in outcomes.items():
        if vol in ("passed_over", "refused_detail"):
            continue
        got = by.pop(vol, [])
        if outcome == "refused" or outcome.startswith("refused"):
            if any(not e.get("aborted") and not e.get("output_failed") for e in got):
                diffs.append(f"{vol}: refused, and the report has an extraction of it")
            continue
        if not got:
            diffs.append(f"{vol}: read, and not in the report")
            continue
        e = got[-1]
        if e.get("sha256") != files.get(vol):
            diffs.append(f"{vol}: the report has sha256 {e.get('sha256')}, the file {files.get(vol)}")
        if outcome == "ok":
            if e.get("sha256") != oracle_volumes.get(vol) and e.get("sha256") == files.get(vol):
                diffs.append(f"{vol}: the report has sha256 {e.get('sha256')}, the oracle {oracle_volumes.get(vol)}")
            if e.get("errors") or e.get("aborted"):
                diffs.append(f"{vol}: read whole, and the report says {e.get('errors')} error(s)")
        elif outcome == INCOMPLETE and not e.get("errors") and not e.get("aborted"):
            diffs.append(f"{vol}: blocks written as zeros, and the report says none")
        for txg in re.findall(r"txg (\d+)", passed.get(vol, "")):
            if not any(w.startswith(f"{vol}: txg {txg} ") for w in warnings):
                diffs.append(f"{vol}: txg {txg} passed over, and the report does not say so")
    diffs += [f"{vol}: in the report, and no run of this case extracted it" for vol in sorted(by)]
    return ("mismatch", diffs) if diffs else ("ok", [])


def judge_report(args, oracle, outcomes, work, log, tamper=False):
    """`zvolreport build` of the case's evidence log and `verify` of what
    it built, held against what the harness found (compare_report);
    with `tamper`, a byte of one output turned over must make `verify`
    fail that output, and is turned back."""
    report, md = os.path.join(work, "report.json"), os.path.join(work, "report.md")
    if not os.path.exists(log):
        return {"report": "no evidence log written"}, {}
    proc = subprocess.run([args.report_tool, "-q", "-f", "json", "build", log, "-o", report, "--md", md],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        why = proc.stderr.strip().splitlines()
        return {"build": f"exit {proc.returncode}: {why[-1][:160] if why else ''}"}, {}
    rep = json.load(open(report))
    # What was read at the pool checkpoint is not in the log (judge_dump).
    outcomes = {k: v for k, v in outcomes.items() if not k.endswith("@checkpoint")}
    files = {}
    for vol in outcomes:
        out = os.path.join(work, vol.replace("/", "_") + ".img")
        if os.path.exists(out):
            files[vol] = sha256_file(out)
    result, details = {}, {}
    result["report"], diffs = compare_report(rep, outcomes, files, oracle.volumes)
    if diffs:
        details["report"] = diffs[:10]
    proc = subprocess.run([args.report_tool, "-q", "-f", "json", "verify", report],
                          capture_output=True, text=True)
    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        doc = {}
    bad = [c for c in doc.get("checked", []) if c.get("status") not in ("pass", "unhashed")]
    if proc.returncode != 0 or bad:
        result["verify"] = f"exit {proc.returncode}"
        details["verify"] = [f"{c.get('kind')} {os.path.basename(str(c.get('path')))}: {c.get('status')}" for c in bad][:10]
    else:
        result["verify"] = "ok"
    if tamper and files:
        vol = sorted(files)[0]
        out = os.path.join(work, vol.replace("/", "_") + ".img")
        with open(out, "r+b") as f:
            f.seek(0)
            byte = f.read(1)
            f.seek(0)
            f.write(bytes([byte[0] ^ 0xff]))
        proc = subprocess.run([args.report_tool, "-q", "-f", "json", "verify", report],
                              capture_output=True, text=True)
        with open(out, "r+b") as f:
            f.seek(0)
            f.write(byte)
        try:
            doc = json.loads(proc.stdout)
        except ValueError:
            doc = {}
        caught = [c for c in doc.get("checked", []) if c.get("path") == out and c.get("status") == "fail"]
        result["verify tampered"] = "ok" if proc.returncode == 4 and caught else "mismatch"
        if result["verify tampered"] != "ok":
            details["verify tampered"] = [f"{vol}: a byte turned over, verify exit {proc.returncode}, "
                                          f"{'the output failed' if caught else 'the output not failed'}"]
    return result, details


def judge_carve(args, oracle, members, work, extra=(), control=False):
    """`zvolcarve` over the members of a case where carving is what is
    left — the control, and a case whose every volume `dump` refused:
    a scan for every volume dnode, and of each live volume the oracle
    hashes (the encrypted ones aside, whose bytes come out as the
    ciphertext they are), the newest candidates of its block size carved
    at its size until one is the volume as the oracle has it at the
    export. Names are no part of it — a carve finds dnodes, and what
    they were called is in the MOS — so a volume is found by its bytes.
    Returns (outcomes, details): per volume `ok`, or not found — on the
    control `missed`, elsewhere `refused`."""
    props = {}
    for line in open(os.path.join(oracle.dir, "zfs-get-all.txt"), errors="replace"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 3 and f[1] in ("volsize", "volblocksize"):
            props.setdefault(f[0], {})[f[1]] = f[2]
    vols = {}
    for vol, sha in oracle.volumes.items():
        p = props.get(vol, {})
        if oracle.key_for(vol) or "volsize" not in p or "volblocksize" not in p:
            continue
        vols[vol] = (sha, parse_size(p["volsize"]), parse_size(p["volblocksize"]))
    if not vols:
        return {}, {}, {}
    out_dir = os.path.join(work, "carve")
    scan = [args.carver, "-q", "-f", "json", "scan", *members, "--dnode-type", "zvol",
            "--strict-profile", "-o", out_dir, *extra_for_carver(extra)]
    proc = subprocess.run(scan, capture_output=True, text=True)
    index = os.path.join(out_dir, "candidates.json")
    if proc.returncode not in (0, 4) or not os.path.exists(index):
        why = proc.stderr.strip().splitlines()
        verdict = f"scan exit {proc.returncode}: {why[-1][:160] if why else ''}"
        return {vol: verdict if control else "refused" for vol in vols}, {}, {}
    cands = json.load(open(index)).get("candidates", [])
    outcomes, details, carved, reasons = {}, {}, {}, {}
    matched = set()

    def carve(c, size):
        key = (c["id"], size)
        if key not in carved:
            img = os.path.join(out_dir, f"{c['id']}-{size}.img")
            p = subprocess.run([args.carver, "-q", "-f", "json", "dump", out_dir, c["id"], *members,
                                "--size", str(size), "-o", img, *extra_for_carver(extra)],
                               capture_output=True, text=True)
            try:
                rec = json.loads(p.stdout)
            except ValueError:
                rec = {}
            carved[key] = rec.get("sha256")
            why = [b.get("reason") for b in rec.get("bad") or [] if b.get("reason")]
            reasons[key] = ("whole" if rec and not rec.get("blocks_zeroed") else
                            f"blocks zeroed: {why[0] if why else 'no reason given'}" if rec else
                            f"dump exit {p.returncode}")
            if os.path.exists(img):
                os.remove(img)
        return key

    # A candidate born after the newest TXG an uberblock reached is of a
    # TXG that never committed — written to the members, never named by
    # an uberblock: a pool frozen or cut off mid-sync (sat-slog). The
    # oracle says what the pool held at its uberblock, and nothing of
    # those, so they are set aside.
    reached = max((u["txg"] for u in oracle.uberblocks), default=None)
    if reached is not None:
        late = [c for c in cands if (c.get("birth") or 0) > reached]
        cands = [c for c in cands if (c.get("birth") or 0) <= reached]
    else:
        late = []
    for vol, (sha, size, vbs) in sorted(vols.items()):
        group = sorted((c for c in cands if c.get("volblocksize") == vbs),
                       key=lambda c: -(c.get("birth") or 0))
        found, tried = False, []
        # Three of each volume of that block size: every volume's last
        # dnode, and the copies of it a pool keeps, among the newest.
        same = sum(1 for v in vols.values() if v[2] == vbs) + sum(
            1 for v in oracle.volumes if oracle.key_for(v) and parse_size(props.get(v, {}).get("volblocksize", "0")) == vbs)
        for c in group[:3 * max(same, 1)]:
            key = carve(c, size)
            tried.append(key)
            if carved[key] == sha:
                found = True
                matched.add(c["id"])
                outcomes[vol] = "ok"
                details[vol] = [f"{c['id']}, born at txg {c.get('birth')}"]
                break
        if not found:
            outcomes[vol] = "missed" if control else "refused"
            said = collections.Counter(reasons.get(k, "?") for k in tried)
            details[vol] = [f"{len(tried)} candidate(s) of {vbs} bytes carved at the newest births, "
                            "none the volume as the oracle has it at the export"] + \
                [f"{n} {why}" for why, n in said.most_common(4)]
        later = sum(1 for c in late if c.get("volblocksize") == vbs)
        if later:
            details.setdefault(vol, []).append(
                f"{later} candidate(s) of {vbs} bytes born after txg {reached}, the newest an uberblock reached, set aside")
    # A volume destroyed while the pool was built, on the control: what
    # the pool still holds of it. Its blocks were freed and may have been
    # written over since, so nothing is expected; a candidate that carves
    # to what it held just before it was destroyed, or at one of its
    # snapshots, is what the carve got back of it, and is recorded.
    destroyed = {}
    for vol, p in sorted(oracle.destroyed.items()) if control else ():
        if "volsize" not in p or "volblocksize" not in p:
            continue
        size, vbs = parse_size(p["volsize"]), parse_size(p["volblocksize"])
        known = {sha: at for at, sha in oracle.hashes.get(vol, {}).items()}
        group = sorted((c for c in cands if c.get("volblocksize") == vbs and c["id"] not in matched),
                       key=lambda c: -(c.get("birth") or 0))
        destroyed[vol] = "not found among the newest candidates"
        for c in group[:12]:
            at = known.get(carved[carve(c, size)])
            if at:
                destroyed[vol] = (f"as it was just before it was destroyed ({c['id']}, born at txg {c.get('birth')})"
                                  if at == "destroyed" else f"as at {at} ({c['id']}, born at txg {c.get('birth')})")
                if at == "destroyed":
                    break
    return outcomes, details, destroyed


def parse_size(text):
    """`48M`, `16K`, `512` as `zfs get` prints them, in bytes.

    >>> parse_size("48M"), parse_size("16K"), parse_size("512"), parse_size("1G")
    (50331648, 16384, 512, 1073741824)
    """
    units = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}
    text = text.strip()
    if text and text[-1] in units:
        return int(float(text[:-1]) * units[text[-1]])
    return int(text) if text.isdigit() else 0


def accepted_outcomes(expected):
    """The outcomes an expectation admits: `recovered` is either of
    bit-exact and reconstructed, and where a refusal is expected an
    honest partial answer is accepted too.

    >>> accepted_outcomes("recovered")
    ['bit-exact', 'reconstructed']
    >>> accepted_outcomes(["refused", "bit-exact"])
    ['refused', 'bit-exact', 'partial']
    """
    accepted = [expected] if isinstance(expected, str) else list(expected)
    if "recovered" in accepted:
        accepted = [a for a in accepted if a != "recovered"] + ["bit-exact", "reconstructed"]
    if "refused" in accepted:
        accepted = accepted + ["partial"]
    return list(dict.fromkeys(accepted))


def classify(values, redundancy, good=frozenset({"ok"}), incomplete=INCOMPLETE):
    """The category a run's outcomes add up to.

    >>> classify({"ok"}, False), classify({"ok"}, True)
    ('bit-exact', 'reconstructed')
    >>> classify({"ok", "refused"}, False), classify({"refused", INCOMPLETE}, False)
    ('refused', 'partial')
    >>> classify({"ok", "hash mismatch"}, False)
    'defect'
    """
    if values <= good:
        return "reconstructed" if redundancy else "bit-exact"
    if values <= good | {"refused"}:
        return "refused"
    if values <= good | {"refused", incomplete}:
        return "partial"
    return "defect"


def wrong_key(spec, work):
    """A key of the same kind as `spec` that is not the key: the raw
    key with every bit turned over, or a passphrase it is not."""
    kind, _, path = spec.partition(":")
    wrong = os.path.join(work, f"wrong-{kind}")
    if kind == "passphrase":
        with open(wrong, "w") as f:
            f.write("not the passphrase of this dataset\n")
    else:
        with open(path, "rb") as f, open(wrong, "wb") as w:
            w.write(bytes(b ^ 0xff for b in f.read()))
    return f"{kind}:{wrong}"


def judge_datasets(missing, extra, wrong_txg, blocks):
    """How the dataset list compares with the oracle, given what the walk said.

    The oracle is `zdb` on the *undamaged* pool, so every dataset it
    knows is one the pool had before the damage. Damage that takes every
    copy of the blocks naming a dataset takes the dataset with them, and
    the tool not listing it is then the same refusal seen one level up —
    the walk says so in `blocks`. Calling that breakage blames the reader
    for an absence the manifest asked for, which is the mistake
    CLEAN_REASONS exists to stop, one level higher.

    What damage never explains is a dataset the tool *invented*, or one
    whose creation TXG it read differently from zdb: those come from
    bytes it did read and got wrong, so they stay defects however much
    else was refused.

    Returns `(verdict, detail)`; the detail is not judged, only printed.

    >>> judge_datasets([], [], [], "ok")
    ('ok', None)
    >>> judge_datasets(["p/a"], [], [], "refused")[0]
    'refused'
    >>> judge_datasets(["p/a"], [], [], "ok")[0]
    "differ from zdb (missing ['p/a'])"
    >>> judge_datasets([], ["p/ghost"], [], "refused")[0]
    "differ from zdb (extra ['p/ghost'], creation txg differs [])"
    >>> judge_datasets([], [], ["p/a"], "refused")[0]
    "differ from zdb (extra [], creation txg differs ['p/a'])"
    """
    if extra or wrong_txg:
        return (f"differ from zdb (extra {extra[:3]}, "
                f"creation txg differs {wrong_txg[:3]})"), None
    if missing and blocks == "refused":
        return "refused", f"not listed, and blocks were refused: {missing[:3]}"
    if missing:
        return f"differ from zdb (missing {missing[:3]})", None
    return "ok", None


def tree_in_part(returncode, doc):
    """Whether a `list` that exited 4 is one the tool accounts for itself.

    `list` exits 4 when the pool reads and part of its dataset tree does
    not: what it could read is listed, each part that did not is named
    (`errors`), and it says the list is not all there is. That is the
    refusal `judge_datasets` knows from the walk, said by the tool one
    level up. It read as "list exit 4", a failure the harness could not
    account for, on the first pool whose damage took both copies of a
    directory of the tree. An exit 4 that names no part is not that.

    >>> tree_in_part(4, {"datasets": [], "errors": ["p/a: every copy failed its checksum"]})
    True
    >>> tree_in_part(4, {"datasets": [], "errors": []})
    False
    >>> tree_in_part(4, {"datasets": []})
    False
    >>> tree_in_part(0, {"datasets": [], "errors": []})
    False
    """
    return returncode == 4 and bool(doc.get("errors"))


def judge_walk(args, oracle, members, work, assume=()):
    """No zvols: the datasets must match `zdb -d` and every block must read."""
    outcomes = {}
    env = dict(os.environ)
    if oracle.key:
        env["ZR_KEY"] = oracle.key
    hints = [a for path in assume for a in ("--assume-member", path)]
    proc = subprocess.run([args.tool, "-f", "json", "list", "-r", *members, *hints],
                          capture_output=True, text=True)
    if why := refusal(proc.returncode, proc.stderr):
        # 2: the members given are not readable as a pool at all.
        # 3: the pool is there but cannot be recovered at that TXG.
        # 1 with the F-62 message: the member the manifest asserted does
        # not read as any leaf the pool is missing.
        return {"pool": "refused", "refused_detail": why}, False
    if proc.returncode not in (0, 4):
        return {"pool": f"list exit {proc.returncode}: {proc.stderr.strip()[:160]}"}, False
    try:
        doc = json.loads(proc.stdout)
        listed = {d["name"]: d["creation_txg"] for d in doc["datasets"]}
    except Exception as e:  # noqa: BLE001
        return {"pool": f"list output unparsable: {e}"}, False
    # 4: the tree read in part, and the tool named the parts that did
    # not. What it lists is judged as ever; what it does not is its own
    # stated refusal.
    in_part = tree_in_part(proc.returncode, doc)
    # 4 as well when the newest TXG did not read and an older one was
    # listed (SPEC F-10): what it lists is judged as ever.
    passed = said_passed_over(proc.stdout) if proc.returncode == 4 else []
    if proc.returncode == 4 and not in_part and not passed:
        return {"pool": f"list exit 4, and no part of the tree named: {proc.stderr.strip()[:160]}"}, False
    if proc.returncode == 0 and said_passed_over(proc.stdout):
        return {"pool": "list exit 0, a newer txg passed over"}, False
    expected = {n: v["creation_txg"] for n, v in oracle.inventory.items()}
    missing = sorted(set(expected) - set(listed))
    extra = sorted(set(listed) - set(expected))
    wrong_txg = sorted(n for n in set(expected) & set(listed) if expected[n] != listed[n])
    # The debug trace is far too large to keep: stream it and look only for
    # evidence that redundancy was used.
    walk_out = os.path.join(work, "walk.txt")
    redundancy = False
    with open(walk_out, "w") as so:
        wproc = subprocess.Popen([args.walker, *hints, *members], stdout=so,
                                 stderr=subprocess.PIPE, text=True, errors="replace",
                                 env=dict(env, ZR_DEBUG="1"))
        for line in wproc.stderr:
            if not redundancy and REDUNDANCY.search(line):
                redundancy = True
        wproc.wait()
    text = open(walk_out, errors="replace").read()
    # Lines the walker prints for blocks it could not produce. A failure
    # is *clean* when the tool named a reason and offered nothing: that is
    # the correct answer to damage, not a defect. Anything else — a parse
    # error, a decompression failure, a panic — means the tool broke.
    CLEAN = re.compile("|".join(re.escape(r) for r in CLEAN_REASONS))
    failures = [l.strip() for l in text.splitlines()
                if re.search(r"ERROR|Mismatch|dnode:|locate:|objset \S+:", l)]
    unclean = [l for l in failures
               if not CLEAN.search(l) and not CHECKSUMLESS.search(l)]
    if unclean:
        outcomes["blocks"] = "; ".join(unclean[:3])
    elif failures:
        outcomes["blocks"] = "refused"
        outcomes["refused_detail"] = "; ".join(failures[:3])
    elif wproc.returncode not in (0, 1):
        outcomes["blocks"] = f"walker exit {wproc.returncode}"
    else:
        outcomes["blocks"] = "ok"
    # Judged last, because whether a missing dataset is a defect depends
    # on what the walk just said.
    verdict, detail = judge_datasets(missing, extra, wrong_txg,
                                     "refused" if in_part else outcomes["blocks"])
    outcomes["datasets"] = verdict
    if detail:
        outcomes["datasets_detail"] = detail
    if in_part:
        outcomes["tree"] = "refused"
        outcomes["tree_detail"] = "; ".join(str(e)[:160] for e in doc["errors"][:3])
    if passed:
        outcomes["passed_over"] = "; ".join(passed)
    m = re.search(r"^datasets (\d+) objects (\d+) blocks (\d+)", text, re.M)
    if m:
        outcomes["counts"] = f"{m.group(1)} datasets, {m.group(2)} objects, {m.group(3)} blocks"
    return outcomes, redundancy


def extra_for_carver(extra):
    """Of what the dump is told, what `zvolcarve roots` takes too: the
    layout and the maps. `--search-order` is the dump's: roots does not
    read through the layout to find a header, only to walk one."""
    out, it = [], iter(extra)
    for a in it:
        if a in ("--hints", "--map"):
            out += [a, next(it)]
    return out


def for_this_image(oracle, manifest):
    """Whether a manifest is written for the image the oracle describes:
    one naming no pool is written for any but a satellite, one naming a
    pool for every image of it, one naming an image's tag (`golden-v2`)
    for that image alone — a case aimed at something only that image
    holds. A satellite (build-satellite.sh: a small pool of one
    pool-level feature) runs only the manifests that name it: the rest
    are written for pools of several top-level vdevs and every kind of
    dataset, and say nothing of one that has a mirror and two volumes.

    >>> o = type("O", (), {"pool": "golden", "layout": {"image_tag": "golden-v2"}})()
    >>> [for_this_image(o, m) for m in ({}, {"image": "golden"}, {"image": "golden-v2"}, {"image": "image-v1"})]
    [True, True, True, False]
    >>> s = type("O", (), {"pool": "sat-spare", "layout": {"image_tag": "sat-spare-v1", "satellite": True}})()
    >>> [for_this_image(s, m) for m in ({}, {"image": "golden"}, {"image": "sat-spare"}, {"image": "sat-spare-v1"})]
    [False, False, True, True]
    """
    if "image" not in manifest and oracle.layout.get("satellite"):
        return False
    return manifest.get("image", oracle.pool) in (oracle.pool, oracle.layout.get("image_tag"))


def needs(oracle, manifests):
    """The release files the given manifests need of the oracle's image.

    Every member: ZFS spreads every volume over every top-level vdev, so
    no part of a pool reads without the rest. And of the older copies
    only those an `older-self` damage names, which are a few of a large
    set. A reference the oracle cannot resolve needs nothing: the case
    is n/a when it runs, whatever was fetched."""
    files = {oracle.layout["members"][r]["file"] + ".zst" for r in oracle.roles}
    for manifest in manifests:
        for d in manifest.get("damage", []):
            if "member" not in d or not d.get("pattern", "").startswith("older-self:"):
                continue
            try:
                role = oracle.resolve(d["member"])
            except Unresolved:
                continue
            files.add("round6-" + oracle.layout["members"][role]["file"] + ".zst")
    return sorted(files)


def run_case(args, oracle, manifest, rng):
    mid = manifest["id"]
    work = tempfile.mkdtemp(prefix=f"golden-{mid}-", dir=args.tmp)
    # Expectations may differ by geometry: losing one copy of a block is
    # transparent on a mirror and needs parity on a raidz. The geometry is
    # that of the members the manifest damages — on an image with several
    # top-level vdevs, the kinds of the others say nothing about it.
    expect = manifest["expect"]
    kinds = oracle.damaged_kinds(manifest)
    expected = expect["outcome"]
    for kind, alt in expect.get("by_group_kind", {}).items():
        if kind in kinds:
            expected = alt
            break
    # A manifest may name several acceptable outcomes when the damage does
    # not deterministically hit live data (scattered bit flips, say).
    # `recovered` = the data came back, whether or not redundancy had to be
    # engaged visibly. Which of the two happens depends on member order and
    # on where the damage landed, and neither is a property worth pinning.
    # Where the redundancy is gone and a refusal is the honest answer, an
    # image with the lost blocks written as zeros, counted and announced
    # (exit 4) is honest too: it presents nothing as good that is not,
    # and keeps what still reads. Where recovery is expected it stays a
    # failure.
    accepted = accepted_outcomes(expected)
    expected = " | ".join(accepted)
    result = {"id": mid, "description": manifest.get("description", ""),
              "expected": expected, "notes": []}
    try:
        try:
            members, notes, paths, unread = apply_damage(oracle, manifest, work, rng)
        except Unresolved as e:
            # Nothing was copied and nothing was damaged, so the evidence
            # is untouched by construction. Saying so rather than leaving
            # the field absent: a caller reading it as "did this run write
            # to its inputs" would otherwise read an unrun case as a run
            # that did.
            result.update(actual="n/a", verdict="n/a", notes=[str(e)],
                          inputs_unchanged=True)
            return result
        result["notes"] = notes
        if not members:
            # The combination took every member away: there is nothing to
            # read, and refusing is the only correct answer.
            result.update(actual="refused", outcomes={"pool": "refused"},
                          inputs_unchanged=True)
            result["verdict"] = "pass" if "refused" in accepted else "unexpected"
            return result
        # A manifest may name members the tool has to be *told* about: a
        # member whose labels are gone carries nothing that places it, so
        # the operator asserts it belongs and the tool works out which
        # leaf by reading (SPEC F-62).
        assume = []
        for sel in manifest.get("recovery", {}).get("assume_members", []):
            role = oracle.resolve(sel)
            if role in paths and paths[role] in members:
                assume.append(paths[role])
        if assume:
            result["notes"].append("told about " + ", ".join(os.path.basename(a) for a in assume))
        recovery = manifest.get("recovery", {})
        dump_only = sorted(k for k in recovery if k != "assume_members") + (["unreadable"] if unread else [])
        if dump_only and not oracle.has_volumes:
            result.update(actual="n/a", verdict="n/a", inputs_unchanged=True,
                          notes=[f"{', '.join(dump_only)}: a pool with no volumes is walked, and the walker takes none of it"])
            return result
        # What the operator tells the tool besides, as the recovery says.
        extra = []
        for role, bad in unread.items():
            mapfile = os.path.join(work, role + ".map")
            write_map(mapfile, os.path.getsize(paths[role]), bad)
            extra += ["--map", f"{paths[role]}={mapfile}"]
        missing_roles = {r for r in oracle.roles if paths[r] not in members}
        if recovery.get("hints"):
            if recovery["hints"] != "layout":
                raise ValueError(f"hints {recovery['hints']!r}: the harness gives `layout`, the oracle's")
            hints_file = os.path.join(work, "layout.hints")
            with open(hints_file, "w") as f:
                json.dump(layout_hints(oracle, paths, missing_roles, recovery.get("order", "as-is")), f, indent=1)
            extra += ["--hints", hints_file]
            result["notes"].append("hints from the oracle's layout"
                                   + (", every raidz and dRAID group reversed" if recovery.get("order") == "reversed" else ""))
        if recovery.get("search_order"):
            extra.append("--search-order")
        if recovery.get("roots"):
            workspace = os.path.join(work, "roots")
            proc = subprocess.run([args.carver, "-q", "roots", *members, *extra_for_carver(extra),
                                   "-o", workspace], capture_output=True, text=True)
            if proc.returncode == 0:
                extra += ["--roots", workspace]
                result["notes"].append("object-set headers from zvolcarve roots")
            else:
                why = proc.stderr.strip().splitlines()
                result["notes"].append(f"zvolcarve roots exit {proc.returncode}: {why[-1][:160] if why else ''}")
        before = {p: sha256_file(p) for p in members}
        evidence = os.path.join(work, "case.jsonl")
        if oracle.has_volumes:
            outcomes, redundancy = judge_dump(args, oracle, manifest, members, work, assume,
                                              extra, recovery.get("key"), evidence)
            good = {"ok", UNVERIFIED}
        else:
            outcomes, redundancy = judge_walk(args, oracle, members, work, assume)
            good = {"ok"}
        result["outcomes"] = outcomes
        judged = {k: v for k, v in outcomes.items()
                  if k not in ("counts", "refused_detail", "datasets_detail", "tree_detail",
                               "passed_over")}
        actual = classify(set(judged.values()), redundancy, good)
        # The files of the pool's filesystems, where the oracle has the
        # kernel's reading of them: every head, and on a case that damages
        # and tells nothing, every snapshot too. A manifest may say what
        # they must come to (`expect.files`); where it does not, they must
        # still never be presented as whole and be otherwise.
        files_verdict = timeline_verdict = None
        if oracle.files and oracle.has_volumes and os.path.exists(args.files_tool):
            control = not manifest.get("damage") and not recovery
            names = [n for n in oracle.files if control or "@" not in n]
            f_out, f_detail, f_red = judge_files(args, oracle, members, work, assume, extra,
                                                 recovery.get("key"), names)
            f_actual = classify(set(f_out.values()), f_red, incomplete=INCOMPLETE_FILES)
            f_accepted = accepted_outcomes(expect["files"]) if "files" in expect else None
            files_verdict = ("defect" if f_actual == "defect"
                             else "unexpected" if f_accepted and f_actual not in f_accepted else "pass")
            result["files"] = {"expected": " | ".join(f_accepted) if f_accepted else "not defect",
                               "actual": f_actual, "verdict": files_verdict,
                               "outcomes": f_out, **({"detail": f_detail} if f_detail else {})}
        # The datasets `list` names, where the oracle has what `zdb -d`
        # named at each of the newest TXGs: at the TXG it listed at, and
        # on the control case at every one of those it can read. A
        # listing zdb contradicts is a defect; one the tool says is not
        # all there is, `partial`.
        datasets_verdict = None
        if oracle.by_txg and oracle.has_volumes:
            control = not manifest.get("damage") and not recovery
            d_out, d_detail, d_at = judge_list(args, oracle, members, work, assume, extra, control)
            if d_out:
                d_actual = classify(set(d_out.values()), False, incomplete=INCOMPLETE_LIST)
                datasets_verdict = "defect" if d_actual == "defect" else "pass"
                result["datasets"] = {"expected": "not defect", "actual": d_actual,
                                      "verdict": datasets_verdict, "outcomes": d_out, "txgs": d_at,
                                      **({"detail": d_detail} if d_detail else {})}
            else:
                result["datasets"] = {"expected": "not defect", "actual": "n/a", "verdict": "pass",
                                      "outcomes": {}, "txgs": []}
        # The report `zvolreport` builds of the case's evidence log: what
        # it says of each volume must be what the harness found, and what
        # it records must verify — on the control, and fail where a byte
        # of an output is turned over.
        report_verdict = None
        if oracle.has_volumes and os.path.exists(args.report_tool):
            control = not manifest.get("damage") and not recovery
            r_out, r_detail = judge_report(args, oracle, outcomes, work, evidence, tamper=control)
            r_actual = classify(set(r_out.values()), False)
            report_verdict = "defect" if r_actual == "defect" else "pass"
            result["report"] = {"expected": "not defect", "actual": r_actual, "verdict": report_verdict,
                                "outcomes": r_out, **({"detail": r_detail} if r_detail else {})}
        # What `zvolcarve` finds where carving is what is left: on the
        # control, and on a case whose every volume `dump` refused, each
        # live volume found by its bytes among the newest candidates.
        carve_verdict = None
        refused_all = oracle.has_volumes and all(
            v == "refused" for k, v in outcomes.items() if k not in ("refused_detail", "passed_over"))
        if oracle.has_volumes and os.path.exists(args.carver) and (
                (not manifest.get("damage") and not recovery) or refused_all):
            control = not manifest.get("damage") and not recovery
            c_out, c_detail, c_destroyed = judge_carve(args, oracle, members, work, extra, control)
            if c_out:
                c_actual = ("bit-exact" if set(c_out.values()) == {"ok"}
                            else "partial" if "ok" in c_out.values() else "refused")
                carve_verdict = "unexpected" if "missed" in c_out.values() else "pass"
                result["carve"] = {"expected": "every volume" if control else "not defect",
                                   "actual": c_actual, "verdict": carve_verdict,
                                   "outcomes": c_out, **({"detail": c_detail} if c_detail else {}),
                                   **({"destroyed": c_destroyed} if c_destroyed else {})}
        # What `scan` read of the labels, the uberblock and the pool's
        # shape, where the oracle has `zdb -l`, `zdb -u` and `zpool
        # status`: a label or an uberblock that verifies and says other
        # than zdb read, or a top-level vdev assembled otherwise, is a
        # defect; one it could not read, refused.
        scan_verdict = None
        if oracle.labels and oracle.has_volumes:
            control = not manifest.get("damage") and not recovery
            s_out, s_detail = judge_scan(args, oracle, paths, members, work, extra, control)
            s_actual = classify(set(s_out.values()), False)
            scan_verdict = "defect" if s_actual == "defect" else "pass"
            result["scan"] = {"expected": "not defect", "actual": s_actual, "verdict": scan_verdict,
                              "outcomes": s_out, **({"detail": s_detail} if s_detail else {})}
        # The pool's history, where the oracle has its record: the same
        # rule, and `expect.timeline` where the manifest says more.
        if oracle.history and oracle.guids and os.path.exists(args.timeline_tool):
            t_out, t_detail, _ = judge_timeline(args, oracle, members, work, assume, extra)
            # Reading the older TXGs meets blocks freed and written over
            # since as a matter of course, and its log is full of failed
            # reconstructions that say nothing of the damage: a history
            # that holds is bit-exact.
            t_actual = classify({t_out}, False, incomplete=INCOMPLETE_TIMELINE)
            t_accepted = accepted_outcomes(expect["timeline"]) if "timeline" in expect else None
            timeline_verdict = ("defect" if t_actual == "defect"
                                else "unexpected" if t_accepted and t_actual not in t_accepted else "pass")
            result["timeline"] = {"expected": " | ".join(t_accepted) if t_accepted else "not defect",
                                  "actual": t_actual, "verdict": timeline_verdict, "outcome": t_out,
                                  **({"detail": t_detail} if t_detail else {})}
        after = {p: sha256_file(p) for p in members}
        changed = [os.path.basename(p) for p in members if before[p] != after[p]]
        result["inputs_unchanged"] = not changed
        if changed:
            actual = "defect"
            result["notes"].append(f"INPUT MODIFIED: {changed}")
        result["actual"] = actual
        result["verdict"] = ("pass" if actual in accepted
                             else "defect" if actual == "defect" else "unexpected")
        # The case is as good as the worst of what was judged in it.
        rank = {"pass": 0, "unexpected": 1, "defect": 2}
        result["verdict"] = max([result["verdict"], files_verdict or "pass", timeline_verdict or "pass",
                                 datasets_verdict or "pass", scan_verdict or "pass",
                                 report_verdict or "pass", carve_verdict or "pass"], key=rank.__getitem__)
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", help="directory holding the member files")
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--manifests", required=True)
    ap.add_argument("--tool", default="./target/release/zvolrescue")
    ap.add_argument("--walker", default="./target/release/examples/walk-objects")
    ap.add_argument("--carver", default="./target/release/zvolcarve",
                    help="zvolcarve, for a manifest whose recovery reads the object-set headers it finds")
    ap.add_argument("--files-tool", default="./target/release/zvolfiles",
                    help="zvolfiles, judged against the oracle's files.json where it has one")
    ap.add_argument("--timeline-tool", default="./target/release/zvoltimeline",
                    help="zvoltimeline, judged against the oracle's zpool-history-il.txt where it has one")
    ap.add_argument("--report-tool", default="./target/release/zvolreport",
                    help="zvolreport, which builds and verifies a report of each case's evidence log")
    ap.add_argument("--out", default="golden-report")
    ap.add_argument("--label", default="", help="name of this image in the report")
    ap.add_argument("--tmp", default=None)
    ap.add_argument("--only", nargs="*", default=[])
    ap.add_argument("--held-out", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--older", default=None,
                    help="the members at an earlier point of the pool's life, for older-self (default: <image>-round6)")
    ap.add_argument("--print-needs", action="store_true",
                    help="print the release files the selected manifests need, and run nothing")
    args = ap.parse_args()
    if not args.print_needs and not args.image:
        ap.error("--image is required unless --print-needs is given")
    oracle = Oracle(args.oracle, args.image or "", args.older)
    selected, elsewhere = [], []
    for name in sorted(os.listdir(args.manifests)):
        if not name.endswith(".toml"):
            continue
        manifest = tomllib.load(open(os.path.join(args.manifests, name), "rb"))
        if args.only and manifest["id"] not in args.only:
            continue
        if manifest.get("held_out") and not args.held_out:
            continue
        if not for_this_image(oracle, manifest):
            elsewhere.append(manifest)
            continue
        selected.append(manifest)
    if args.print_needs:
        print("\n".join(needs(oracle, selected)))
        return
    os.makedirs(args.out, exist_ok=True)
    label = args.label or os.path.basename(args.oracle.rstrip("/"))
    results = []
    for manifest in selected:
        r = run_case(args, oracle, manifest, random.Random(manifest["id"]))
        r["image"] = label
        results.append(r)
        files = (f"  files {r['files']['actual']}" if "files" in r else "") + \
            (f"  timeline {r['timeline']['actual']}" if "timeline" in r else "") + \
            (f"  datasets {r['datasets']['actual']}" if "datasets" in r else "") + \
            (f"  scan {r['scan']['actual']}" if "scan" in r else "") + \
            (f"  report {r['report']['actual']}" if "report" in r else "") + \
            (f"  carve {r['carve']['actual']}" if "carve" in r else "")
        print(f"{label:<8} {r['verdict']:<10} {r['id']:<32} expected {r['expected']:<14} actual {r['actual']}{files}")
    # One asked for by name and written for another pool is n/a here, and
    # shown; the rest of another pool's manifests are not this run's.
    for manifest in elsewhere:
        if not args.only:
            continue
        r = {"id": manifest["id"], "description": manifest.get("description", ""),
             "expected": "—", "actual": "n/a", "verdict": "n/a", "inputs_unchanged": True,
             "notes": [f"written for the pool {manifest['image']!r}, and this is {oracle.pool!r}" if "image" in manifest
                       else f"written for no pool in particular, and {oracle.pool!r} is a satellite"],
             "image": label}
        results.append(r)
        print(f"{label:<8} {r['verdict']:<10} {r['id']:<32} {r['notes'][0]}")
    if elsewhere and not args.only:
        print(f"{label}: {len(elsewhere)} manifest(s) written for another pool, not run here")
    with open(os.path.join(args.out, f"report-{label}.json"), "w") as f:
        json.dump(results, f, indent=1)
    with open(os.path.join(args.out, f"report-{label}.md"), "w") as f:
        f.write(f"# Damage matrix: {label}\n\n")
        f.write("| Manifest | Expected | Actual | Files | Timeline | Datasets | Scan | Report | Carve | Verdict | Inputs unchanged | Detail |\n|---|---|---|---|---|---|---|---|---|---|---|---|\n")
        for r in results:
            detail = "; ".join(list(r.get("notes", [])) + [f"{k}: {v}" for k, v in r.get("outcomes", {}).items() if v != "ok"]
                               + [f"files {k}: {v}" for k, v in r.get("files", {}).get("outcomes", {}).items() if v != "ok"])
            files = r["files"]["actual"] if "files" in r else "—"
            timeline = r["timeline"]["actual"] if "timeline" in r else "—"
            datasets = r["datasets"]["actual"] if "datasets" in r else "—"
            scan = r["scan"]["actual"] if "scan" in r else "—"
            report = r["report"]["actual"] if "report" in r else "—"
            carve = r["carve"]["actual"] if "carve" in r else "—"
            if r.get("timeline", {}).get("outcome", "ok") != "ok":
                detail += f"; timeline: {r['timeline']['outcome']}"
            for side in ("datasets", "scan", "report", "carve"):
                detail += "".join(f"; {side} {k}: {v}" for k, v in r.get(side, {}).get("outcomes", {}).items()
                                  if v != "ok")
            f.write(f"| `{r['id']}` | {r['expected'].replace('|', chr(92) + '|')} | {r['actual']} | {files} | {timeline} | {datasets} | {scan} | {report} | {carve} | {r['verdict']} | "
                    f"{'yes' if r.get('inputs_unchanged') else ('—' if r['verdict'] == 'n/a' else 'NO')} | {detail} |\n")
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(f"{label}: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    sys.exit(1 if counts.get("defect") else 0)


if __name__ == "__main__":
    main()
