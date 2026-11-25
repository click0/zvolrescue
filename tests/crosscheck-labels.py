#!/usr/bin/env python3
"""The labels `scan --emit-label` writes, imported by the kernel.

A pool whose label configurations are all gone is read through a layout
given by hand (SPEC F-65), and `scan --emit-label` hands that layout on:
it writes, for each member and each of the four places a label goes,
the label the pool's own configuration in its MOS gives that member
(F-67). That was checked against `zdb -e`, which reads the copies with
OpenZFS's own code in userland. What a person does with such copies is
`zpool import`, through the kernel, and that is what this does:

  1. a pool of a mirror and a raidz1 on five image files, made by the
     kernel, with a filesystem of files whose hashes are recorded, then
     exported;
  2. copies of the members with the configuration of all four labels of
     each erased — `zpool import` finds no pool in them;
  3. the layout of the pool as `scan` tells it, pointed at the copies,
     and a label emitted for every member and position and placed;
  4. `zpool import` of the copies, read-only: every vdev online, and
     every file the bytes it was written with.

The originals are never imported again; the copies are read-only.

Usage (as root, with the zfs module loaded):
  crosscheck-labels.py ZVOLRESCUE WORKDIR
"""

import hashlib
import json
import os
import random
import shutil
import subprocess
import sys

POOL = "xlab"
SIZE = 256 * 1024 * 1024
LABEL, PHYS_OFF, PHYS = 256 * 1024, 16 * 1024, 112 * 1024
FAILURES = []


def run(*args, check=True, capture=False):
    print("+", " ".join(args), flush=True)
    return subprocess.run(args, check=check, text=True, capture_output=capture)


def fail(msg):
    FAILURES.append(msg)
    print("FAIL:", msg, flush=True)


def tree_of(root):
    """Every regular file under `root`, by path, with its hash."""
    out = {}
    for dirpath, _, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root)] = hashlib.sha256(fh.read()).hexdigest()
    return out


def erase_configurations(path):
    """The configuration nvlist of every label, zeroed: the uberblock
    rings are left as they are."""
    aligned = os.path.getsize(path) & ~(LABEL - 1)
    with open(path, "r+b") as f:
        for off in (0, LABEL, aligned - 2 * LABEL, aligned - LABEL):
            f.seek(off + PHYS_OFF)
            f.write(b"\0" * PHYS)


def main():
    zr, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    members_dir = os.path.join(work, "members")
    copies_dir = os.path.join(work, "copies")
    os.makedirs(members_dir)
    os.makedirs(copies_dir)
    members = [os.path.join(members_dir, f"m{i}.img") for i in range(5)]
    for m in members:
        with open(m, "wb") as f:
            f.truncate(SIZE)

    # 1. The pool, by the kernel.
    alt1 = os.path.join(work, "alt1")
    run("zpool", "create", "-f", "-o", "ashift=12", "-R", alt1,
        "-O", "mountpoint=/" + POOL, "-O", "compression=lz4", POOL,
        "mirror", members[0], members[1], "raidz1", *members[2:])
    imported = True
    try:
        run("zfs", "create", f"{POOL}/fs")
        fs = os.path.join(alt1, POOL, "fs")
        rng = random.Random(4816229)
        os.makedirs(os.path.join(fs, "sub"))
        for i, size in enumerate([1, 4096, 131072, 3 * 1024 * 1024 + 17, 9000000]):
            where = fs if i % 2 == 0 else os.path.join(fs, "sub")
            with open(os.path.join(where, f"f{i}.bin"), "wb") as f:
                f.write(rng.randbytes(size))
        with open(os.path.join(fs, "zeros.bin"), "wb") as f:
            f.write(b"\0" * (2 * 1024 * 1024))
        written = tree_of(fs)
        run("zpool", "export", POOL)
        imported = False
        print(f"written: {len(written)} file(s)")

        # 3, before 2: the layout as `scan` tells it from the members.
        scan = json.loads(run(zr, "-q", "-f", "json", "scan", *members, capture=True).stdout)
        pool = scan["pools"][0]
        tops = sorted(pool["tops"], key=lambda t: t["id"])

        def to_copies(node):
            n = dict(node)
            if n.get("members") is not None:
                n["members"] = [os.path.join(copies_dir, os.path.basename(m))
                                for m in n["members"]]
            if n.get("children") is not None:
                n["children"] = [to_copies(c) for c in n["children"]]
            return n

        ashift = next(d["config"]["ashift"] for d in scan["devices"]
                      if d.get("config") and d["config"].get("ashift"))
        hints = {"name": pool["name"], "ashift": ashift,
                 "tops": [to_copies(t["tree"]) for t in tops]}
        hints_file = os.path.join(work, "hints.json")
        with open(hints_file, "w") as f:
            json.dump(hints, f, indent=1)

        # 2. The copies, with no configuration left.
        copies = []
        for m in members:
            c = os.path.join(copies_dir, os.path.basename(m))
            run("cp", "--sparse=always", m, c)
            erase_configurations(c)
            copies.append(c)
        found = run("zpool", "import", "-d", copies_dir, check=False, capture=True)
        if POOL in found.stdout:
            fail(f"zpool import finds the pool in the copies before any label is placed:\n{found.stdout}")
        else:
            print("with every configuration erased, zpool import finds no pool in the copies")

        # 3. A label for every member and position, placed.
        def leaves(n):
            if n.get("children") is not None:
                return [m for c in n["children"] for m in leaves(c)]
            return n["members"]

        label = os.path.join(work, "label.bin")
        for ti, top in enumerate(hints["tops"]):
            for li, member in enumerate(leaves(top)):
                aligned = os.path.getsize(member) & ~(LABEL - 1)
                for index, at in enumerate((0, LABEL, aligned - 2 * LABEL, aligned - LABEL)):
                    # What scan prints of the members, forty times over,
                    # is not what this is about: the label file is.
                    run(zr, "-q", "scan", *copies, "--hints", hints_file,
                        "--emit-label", label, "--emit-for", f"{ti}:{li}",
                        "--emit-label-index", str(index), capture=True)
                    with open(label + ".json") as f:
                        geometry = json.load(f)
                    if geometry["config"] != "pool":
                        fail(f"{ti}:{li} L{index}: the label is a template: {geometry.get('note')}")
                    with open(label, "rb") as src, open(member, "r+b") as dst:
                        dst.seek(at)
                        dst.write(src.read())
        print("a label emitted for every member and position, and placed")

        # 4. The kernel's import of the copies, read-only.
        alt2 = os.path.join(work, "alt2")
        listed = run("zpool", "import", "-d", copies_dir, check=False, capture=True)
        print(listed.stdout, listed.stderr)
        got = run("zpool", "import", "-d", copies_dir, "-o", "readonly=on",
                  "-R", alt2, POOL, check=False, capture=True)
        forced = False
        if got.returncode != 0:
            print(got.stdout, got.stderr)
            # A label carries the state the configuration in the MOS was
            # written in, and that is not "exported".
            got = run("zpool", "import", "-f", "-d", copies_dir, "-o", "readonly=on",
                      "-R", alt2, POOL, check=False, capture=True)
            forced = got.returncode == 0
        if got.returncode != 0:
            fail(f"zpool import of the relabelled copies: {got.stdout}{got.stderr}")
            return
        imported = True
        status = run("zpool", "status", "-P", POOL, capture=True).stdout
        print(status)
        for c in copies:
            line = next((l for l in status.splitlines() if c in l), "")
            if "ONLINE" not in line:
                fail(f"{c} is not online in the imported pool: {line.strip()!r}")
        if "No known data errors" not in status:
            fail("zpool status reports data errors")
        read = tree_of(os.path.join(alt2, POOL, "fs"))
        if read != written:
            missing = sorted(set(written) - set(read))
            wrong = sorted(p for p in written if p in read and read[p] != written[p])
            fail(f"the files read back differ: missing {missing}, other bytes {wrong}")
        else:
            print(f"imported{' (with -f)' if forced else ''}: every vdev online, "
                  f"and all {len(read)} file(s) are the bytes they were written with")
    finally:
        if imported:
            run("zpool", "export", POOL, check=False)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main()
    if FAILURES:
        sys.exit(f"{len(FAILURES)} failure(s)")
    print("crosscheck-labels: the kernel imports the pool from the labels scan --emit-label wrote")
