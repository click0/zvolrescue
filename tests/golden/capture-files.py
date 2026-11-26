#!/usr/bin/env python3
"""What the kernel reads out of a pool's filesystems, for the oracle.

    capture-files.py [--add] OUT.json POOL NAME=PATH [NAME=PATH ...]

Each NAME=PATH is a dataset or a snapshot (`pool/fs`, `pool/fs@snap`)
and the directory the kernel has it mounted at — a filesystem of a pool
imported read-only, a snapshot under its `.zfs/snapshot/`. Every entry
under it is recorded, the root included, in byte order of its path:
its type, mode, owner, size, link count, inode (the object number on
ZFS), modification time, the SHA-256 of a regular file's content, a
symbolic link's target, and every extended attribute's name with the
size and SHA-256 of its value. A listing equal to one already recorded
is written as `{"same_as": NAME}`. Nothing is followed across a mount
point or through a link, and a filesystem's `.zfs` is left out. With
`--add` the datasets go into OUT.json beside those already there, so
that each filesystem can be mounted alone — a child mounted inside its
parent hides the directory the parent itself holds there.

This is the oracle side of the files a pool holds: `zvolfiles` is
judged against it, and it is made by OpenZFS — the kernel, through the
VFS — never by the tool under test (oracle-capture.yml in zvolrescue,
what = files-history).
"""
import hashlib
import json
import os
import stat
import sys


def record(top, rel, dev):
    """One entry: `rel` is its path under `top`, in bytes."""
    full = os.path.join(top, rel) if rel else top
    st = os.lstat(full)
    kind = ("f" if stat.S_ISREG(st.st_mode) else "d" if stat.S_ISDIR(st.st_mode)
            else "l" if stat.S_ISLNK(st.st_mode) else "o")
    out = {}
    name = rel or b"."
    try:
        out["path"] = name.decode("utf-8")
    except UnicodeDecodeError:
        out["path_hex"] = name.hex()
    out.update(type=kind, mode=f"{stat.S_IMODE(st.st_mode):o}", uid=st.st_uid,
               gid=st.st_gid, size=st.st_size, nlink=st.st_nlink, ino=st.st_ino,
               mtime_ns=st.st_mtime_ns)
    if kind == "f":
        h = hashlib.sha256()
        with open(full, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        out["sha256"] = h.hexdigest()
    elif kind == "l":
        target = os.readlink(full)
        try:
            out["target"] = target.decode("utf-8")
        except UnicodeDecodeError:
            out["target_hex"] = target.hex()
    elif kind == "o":
        out["rdev"] = st.st_rdev
    xattrs = {}
    try:
        names = os.listxattr(full, follow_symlinks=False)
    except OSError as e:
        out["xattr_error"] = e.strerror
        names = []
    for n in sorted(names):
        try:
            v = os.getxattr(full, n, follow_symlinks=False)
        except OSError as e:
            xattrs[n] = {"error": e.strerror}
            continue
        xattrs[n] = {"size": len(v), "sha256": hashlib.sha256(v).hexdigest()}
    if xattrs:
        out["xattrs"] = xattrs
    return out, kind == "d" and st.st_dev == dev


def listing(top):
    """Every entry under `top`, the root first, in byte order of path.

    `top` is walked as `top/.`: a snapshot's `.zfs/snapshot/<name>` is
    mounted by the kernel only when a path goes through it, and an
    lstat of the name alone answers for the control directory's node
    rather than for the snapshot's own root."""
    top = os.path.join(os.fsencode(top), b".")
    dev = os.lstat(top).st_dev
    entries, stack = [], [b""]
    while stack:
        rel = stack.pop()
        entry, descend = record(top, rel, dev)
        entries.append(entry)
        if descend:
            names = sorted(os.listdir(os.path.join(top, rel) if rel else top), reverse=True)
            if not rel:
                # ZFS's own control directory, listed when snapdir=visible:
                # the snapshots are recorded under their own names.
                names = [n for n in names if n != b".zfs"]
            stack += [os.path.join(rel, n) if rel else n for n in names]
    return entries


def main(argv):
    add = argv[:1] == ["--add"]
    argv = argv[1:] if add else argv
    if len(argv) < 3 or any("=" not in a for a in argv[2:]):
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 1
    out, pool = argv[0], argv[1]
    result = {"pool": pool, "datasets": {}}
    if add and os.path.exists(out):
        result = json.load(open(out))
        if result.get("pool") != pool:
            print(f"capture-files: {out} is of pool {result.get('pool')!r}, not {pool!r}", file=sys.stderr)
            return 1
    seen = {v["digest"]: k for k, v in result["datasets"].items() if "digest" in v}
    for spec in argv[2:]:
        name, path = spec.split("=", 1)
        try:
            entries = listing(path)
        except OSError as e:
            where = os.fsdecode(e.filename) if e.filename is not None else path
            result["datasets"][name] = {"path": path, "error": f"{e.strerror}: {where}"}
            continue
        canon = json.dumps(entries, sort_keys=True).encode()
        digest = hashlib.sha256(canon).hexdigest()
        if digest in seen:
            result["datasets"][name] = {"same_as": seen[digest]}
        else:
            seen[digest] = name
            result["datasets"][name] = {"path": path, "entries": entries, "digest": digest}
        print(f"{name}: {len(entries)} entries"
              + (f", the same as {seen[digest]}" if seen[digest] != name else ""))
    with open(out, "w") as f:
        json.dump(result, f, indent=1, sort_keys=True)
        f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
