#!/usr/bin/env python3
"""Cross-check zvolfiles against ZPL datasets the kernel's OpenZFS wrote.

Every fixture in this repository was written by this repository, and
for a year two decoding mistakes (the SA registry's attribute number,
the legacy znode's offsets) sat in the reader and in the fixture alike,
so that every test agreed with every other and no real filesystem read.
This writes the files with the code that defines the format — a pool on
two image files, through the kernel module — records what the kernel
says is there, exports the pool, and holds `zvolfiles extract` to it:
every path, its type, mode, owner, size, times, bytes, link target,
device number and extended attributes, in a dataset of each kind the
reader decodes differently:

  sa       system attributes, xattr=sa (a symlink's label after its target)
  dir      system attributes, xattr=dir (an attribute directory)
  legacy   ZPL version 4: znode_phys_t in the bonus, no system attributes
  fold     casesensitivity=insensitive
  kc, kd   normalization=formKC and formKD

Usage (as root, with the zfs module loadable):
  crosscheck-zpl.py ZVOLFILES WORKDIR
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import unicodedata

POOL = "xck"
SIZE = 512 * 1024 * 1024
DATASETS = {
    "sa": ["-o", "xattr=sa"],
    "dir": ["-o", "xattr=dir"],
    "legacy": ["-o", "version=4", "-o", "xattr=dir"],
    "fold": ["-o", "casesensitivity=insensitive", "-o", "xattr=sa"],
    "kc": ["-o", "normalization=formKC", "-o", "utf8only=on", "-o", "xattr=sa"],
    "kd": ["-o", "normalization=formKD", "-o", "utf8only=on", "-o", "xattr=sa"],
}
# A name with a composed letter, and the same name decomposed.
RESUME_NFC = unicodedata.normalize("NFC", "résumé.txt")
RESUME_NFD = unicodedata.normalize("NFD", RESUME_NFC)
FAILURES = []


def run(*args, check=True):
    print("+", " ".join(args), flush=True)
    return subprocess.run(args, check=check)


def fail(msg):
    FAILURES.append(msg)
    print("FAIL:", msg, flush=True)


def populate(root, name):
    """Every kind of entry the reader decodes differently."""

    def write(rel, data, mode=None):
        p = os.path.join(root, rel)
        with open(p, "wb") as f:
            f.write(data)
        if mode is not None:
            os.chmod(p, mode)
        return p

    rnd = lambda n: os.urandom(n)
    write("empty", b"")
    one = write("one", b"x")
    write("page", rnd(4096))
    write("block-plus-one", rnd(128 * 1024 + 1))
    write("big", rnd(3 * 1024 * 1024))
    sparse = write("sparse", b"head")
    with open(sparse, "r+b") as f:
        f.seek(10 * 1024 * 1024 - 4)
        f.write(b"tail")
    os.makedirs(os.path.join(root, "sub", "deeper"))
    write("sub/deeper/file", b"deep\n")
    os.chmod(os.path.join(root, "sub"), 0o750)
    os.symlink("sub/deeper/file", os.path.join(root, "short-link"))
    os.symlink("t" * 300, os.path.join(root, "long-link"))
    os.link(one, os.path.join(root, "one-again"))
    os.mkfifo(os.path.join(root, "fifo"))
    os.mknod(os.path.join(root, "null"), 0o666 | stat.S_IFCHR, os.makedev(1, 3))
    os.mknod(os.path.join(root, "sda1"), 0o660 | stat.S_IFBLK, os.makedev(8, 1))
    private = write("private", b"secret\n", 0o600)
    os.chown(private, 1001, 1002)
    write("suid", b"#!/bin/sh\n", 0o4755)
    write(RESUME_NFC, b"cv\n")
    write("MixedCase.TXT", b"case\n")
    # Extended attributes: small, binary, and one too large for the
    # bonus buffer, which goes to the spill block or the directory.
    os.setxattr(one, "user.small", b"hello")
    os.setxattr(one, "user.binary", bytes(range(256)))
    os.setxattr(os.path.join(root, "page"), "user.large", b"L" * 20000)
    # A label on a symlink, as SELinux gives every one: under xattr=sa
    # it lies after the link's target in the system attributes.
    os.setxattr(os.path.join(root, "short-link"), "trusted.label",
                b"system_u:object_r:user_home_t:s0\0", follow_symlinks=False)
    # Times the extraction is held to, before 1970 among them.
    os.utime(one, ns=(981173106_789000000, 981173106_123456789))
    os.utime(os.path.join(root, "page"), ns=(0, -86400_000000000))
    os.utime(os.path.join(root, "short-link"), ns=(1, 1_000000000), follow_symlinks=False)


def snapshot_tree(root):
    """What the kernel says is in the dataset, keyed by relative path."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not (dirpath == root and d == ".zfs")]
        for n in dirnames + filenames:
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, root)
            st = os.lstat(p)
            e = {
                "type": stat.filemode(st.st_mode)[0],
                "mode": "%04o" % stat.S_IMODE(st.st_mode),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "mtime": st.st_mtime_ns // 1_000_000_000,
                "ino": st.st_ino,
            }
            if stat.S_ISREG(st.st_mode):
                e["size"] = st.st_size
                with open(p, "rb") as f:
                    e["sha256"] = hashlib.sha256(f.read()).hexdigest()
            elif stat.S_ISLNK(st.st_mode):
                e["target"] = os.readlink(p)
            elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
                e["rdev"] = [os.major(st.st_rdev), os.minor(st.st_rdev)]
            try:
                names = os.listxattr(p, follow_symlinks=False)
            except OSError:
                names = []
            e["xattrs"] = {
                x: os.getxattr(p, x, follow_symlinks=False).hex()
                for x in names
                if not x.startswith("system.")
            }
            out[rel] = e
    return out


def manifest_xattrs(rec):
    got = {}
    for x in rec.get("xattrs", []):
        if "value" in x:
            got[x["name"]] = x["value"].encode().hex()
        elif "value_hex" in x:
            got[x["name"]] = x["value_hex"]
        else:
            got[x["name"]] = None
    return got


def check_dataset(zf, members, ds, want, work):
    out = os.path.join(work, "out-" + ds)
    shutil.rmtree(out, ignore_errors=True)
    r = subprocess.run(
        [zf, "-q", "extract", f"{POOL}/{ds}", *members, "-o", out],
        capture_output=True, text=True)
    print(r.stdout + r.stderr, flush=True)
    if r.returncode != 0:
        fail(f"{ds}: extract exited {r.returncode}")
    with open(os.path.join(out, "manifest.json")) as f:
        manifest = json.load(f)
    got = {rec["path"]: rec for rec in manifest["files"]}
    if set(got) != set(want):
        fail(f"{ds}: paths differ: only in the pool {sorted(set(want) - set(got))}, "
             f"only in the manifest {sorted(set(got) - set(want))}")
    first_name = {}
    for path, w in sorted(want.items()):
        rec = got.get(path)
        if rec is None:
            continue
        where = f"{ds}/{path}"
        for key in ("type", "mode", "uid", "gid", "mtime"):
            if str(rec.get(key)) != str(w[key]):
                fail(f"{where}: {key} {rec.get(key)!r}, the kernel says {w[key]!r}")
        if rec.get("error"):
            fail(f"{where}: {rec['error']}")
        if rec.get("errors") or rec.get("xattr_errors") or rec.get("contents_errors"):
            fail(f"{where}: not read whole: {rec}")
        if "sha256" in w:
            if rec.get("size") != w["size"]:
                fail(f"{where}: size {rec.get('size')}, the kernel says {w['size']}")
            if rec.get("sha256") != w["sha256"]:
                fail(f"{where}: sha256 {rec.get('sha256')}, the kernel's {w['sha256']}")
            if w["ino"] in first_name:
                if rec.get("hardlink_to") != first_name[w["ino"]]:
                    fail(f"{where}: not recorded as a link to {first_name[w['ino']]}")
            else:
                first_name[w["ino"]] = path
                with open(os.path.join(out, path), "rb") as f:
                    if hashlib.sha256(f.read()).hexdigest() != w["sha256"]:
                        fail(f"{where}: the file written is not the file's bytes")
        if "target" in w and rec.get("target") != w["target"]:
            fail(f"{where}: target {rec.get('target')!r}, the kernel says {w['target']!r}")
        if "rdev" in w:
            rd = rec.get("rdev") or {}
            if [rd.get("major"), rd.get("minor")] != w["rdev"]:
                fail(f"{where}: device {rd}, the kernel says {w['rdev']}")
        if manifest_xattrs(rec) != w["xattrs"]:
            fail(f"{where}: extended attributes {manifest_xattrs(rec)}, "
                 f"the kernel says {w['xattrs']}")
    r = subprocess.run([zf, "-q", "list", "-R", f"{POOL}/{ds}", *members],
                       capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"{ds}: list exited {r.returncode}: {r.stderr}")
    print(f"{ds}: {len(want)} entries compared", flush=True)


def check_lookup(zf, members, ds, asked, on_disk, work):
    """A spelling the dataset matches, found and written as on disk."""
    out = os.path.join(work, "look-" + ds)
    shutil.rmtree(out, ignore_errors=True)
    r = subprocess.run([zf, "-q", "extract", f"{POOL}/{ds}", *members, "-o", out,
                        "--path", asked], capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(os.path.join(out, on_disk)):
        fail(f"{ds}: --path {asked!r} did not find {on_disk!r} "
             f"(exit {r.returncode}): {r.stderr}")


def main():
    zf, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    members = [os.path.join(work, f"m{i}.img") for i in (0, 1)]
    for m in members:
        with open(m, "wb") as f:
            f.truncate(SIZE)
    altroot = os.path.join(work, "root")
    run("zpool", "create", "-f", "-o", "ashift=12", "-O", "mountpoint=none",
        "-O", "acltype=off", "-R", altroot, POOL, "mirror", *members)
    want = {}
    try:
        for ds, opts in DATASETS.items():
            run("zfs", "create", *opts, "-o", f"mountpoint=/{ds}", f"{POOL}/{ds}")
            populate(os.path.join(altroot, ds), ds)
        run("sync")
        for ds in DATASETS:
            want[ds] = snapshot_tree(os.path.join(altroot, ds))
    finally:
        run("zpool", "export", POOL)
    for ds in DATASETS:
        check_dataset(zf, members, ds, want[ds], work)
    check_lookup(zf, members, "fold", "mixedcase.txt", "MixedCase.TXT", work)
    check_lookup(zf, members, "kc", RESUME_NFD, RESUME_NFC, work)
    check_lookup(zf, members, "kd", RESUME_NFD, RESUME_NFC, work)
    if FAILURES:
        print(f"\n{len(FAILURES)} disagreement(s) with the kernel's OpenZFS")
        sys.exit(1)
    print("\nzvolfiles agrees with the kernel's OpenZFS on every entry")


if __name__ == "__main__":
    main()
