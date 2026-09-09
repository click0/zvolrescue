#!/usr/bin/env python3
"""Run the damage matrix (SPEC 9.1) against the golden image.

    run-matrix.py --image DIR --oracle DIR --manifests DIR --tool zvolrescue [--out DIR]
                  [--only ID ...] [--held-out] [--keep]

For every manifest: copy the members it damages (the rest are used in
place), apply the damage, hash every input, run `zvolrescue dump` for
every volume the oracle lists at export, compare the SHA-256 of each
output with the oracle, classify the run (bit-exact / reconstructed /
refused / defect), and re-hash the inputs. Writes report.json and
report.md to --out. Exit status 1 when any run is a defect.

The oracle is never produced by the tool: volume hashes come from
oracle/volumes.sha256, structure positions for `target` damage from the
oracle's zdb captures. Only Python's standard library is used (tomllib
needs Python 3.11).
"""
import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

UNITS = {"": 1, "KiB": 1024, "MiB": 1 << 20, "GiB": 1 << 30, "K": 1024, "M": 1 << 20, "G": 1 << 30}
LABEL_START = 4 << 20


def size(s):
    m = re.fullmatch(r"(-?\d+)\s*([KMG]i?B?)?", s.strip())
    if not m:
        raise ValueError(f"bad size {s!r}")
    return int(m.group(1)) * UNITS[m.group(2) or ""]


def parse_range(spec, length):
    """'a..b' with optional negative (from end) and open ends -> (start, end)."""
    a, b = spec.split("..")
    start = size(a) if a else 0
    end = size(b) if b else length
    if start < 0:
        start += length
    if end < 0:
        end += length
    if not 0 <= start <= end <= length:
        raise ValueError(f"range {spec} outside member of {length} bytes")
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
    def __init__(self, d):
        self.dir = d
        self.layout = json.load(open(os.path.join(d, "layout.json")))
        self.pool = self.layout["pool"]
        self.volumes = {}  # name@tag -> sha256
        for line in open(os.path.join(d, "volumes.sha256")):
            parts = line.split()
            if len(parts) == 2:
                self.volumes[parts[1]] = parts[0]
        self.export = {k[: -len("@export")]: v for k, v in self.volumes.items() if k.endswith("@export")}
        self.keys = {}
        kd = os.path.join(d, "keys")
        if os.path.exists(os.path.join(kd, "raw.key")):
            self.keys["raw"] = "raw:" + os.path.join(kd, "raw.key")
        if os.path.exists(os.path.join(kd, "passphrase.txt")):
            self.keys["passphrase"] = "passphrase:" + os.path.join(kd, "passphrase.txt")
        # dataset -> keyformat from zfs list (name type guid creation used refer volsize volblocksize checksum compression encryption keyformat)
        self.keyformat = {}
        zl = os.path.join(d, "zfs-list.txt")
        if os.path.exists(zl):
            for line in open(zl):
                f = line.rstrip("\n").split("\t")
                if len(f) >= 12 and f[11] not in ("none", "-"):
                    self.keyformat[f[0]] = f[11]
        self.zdb = ""
        zd = os.path.join(d, "zdb-dddd.txt")
        if os.path.exists(zd):
            self.zdb = open(zd, errors="replace").read()

    def key_spec(self, dataset):
        for name, fmt in self.keyformat.items():
            if dataset == name or dataset.startswith(name + "/"):
                return self.keys.get(fmt)
        return None

    def members(self):
        out = []
        for top in self.layout["tops"]:
            out.extend(top["members"])
        return out

    def resolve_target(self, target):
        """Return [(member, offset, length)] for every chosen DVA copy of a structure, from the zdb capture."""
        obj, copy = target["object"], target.get("copy", "all")
        dvas = []
        if obj == "mos:objset":
            m = re.search(r"^Dataset mos .*?rootbp (.*?)\[", self.zdb, re.M)
            if m:
                dvas = re.findall(r"DVA\[(\d)\]=<(\d+):([0-9a-f]+):([0-9a-f]+)>", m.group(1))
        else:
            ds, what = obj.rsplit(":", 1)
            name = f"{self.pool}/{ds}"
            sect = re.search(rf"^Dataset {re.escape(name)} .*?rootbp (.*?)\[.*?(?=^Dataset |\Z)", self.zdb, re.M | re.S)
            if sect:
                if what == "objset":
                    dvas = re.findall(r"DVA\[(\d)\]=<(\d+):([0-9a-f]+):([0-9a-f]+)>", sect.group(1))
                elif what == "dnode-block":
                    # Object 0 (the dnode array) of that dataset: its first L0 block.
                    m = re.search(r"^\s+Object\s+lvl.*?\n\s+0\s+.*?Indirect blocks:\n(.*?)(?=^\s+Object\s|\Z)", sect.group(0), re.M | re.S)
                    if m:
                        l0 = re.search(r"L0 ((?:\d+:[0-9a-f]+:[0-9a-f]+ ?)+)", m.group(1))
                        if l0:
                            dvas = [(str(i), *d.split(":")) for i, d in enumerate(l0.group(1).split())]
        if copy != "all":
            dvas = [d for d in dvas if int(d[0]) == int(copy)]
        return [self.dva_to_physical(int(v), int(off, 16), int(sz, 16)) for _, v, off, sz in dvas]

    def dva_to_physical(self, vdev, offset, asize):
        """Map a DVA to (member, byte offset, length) ranges. Mirror: every member;
        raidz: the data/parity columns from the raidz layout; draid: not resolved."""
        top = self.layout["tops"][vdev]
        kind = top["kind"]
        ashift = self.layout.get("ashift", 12)
        if kind == "mirror":
            return [(m, LABEL_START + offset, asize) for m in top["members"]]
        if kind.startswith("raidz"):
            # vdev_raidz_map_alloc, columns in stripe order; the 1 MiB parity
            # swap of raidz1 is irrelevant for overwriting every column.
            unit = 1 << ashift
            dcols = len(top["members"])
            nparity = top["nparity"]
            b = offset >> ashift
            s = asize >> ashift  # asize already includes parity: use whole stripe span
            f = b % dcols
            o = (b // dcols) << ashift
            out = []
            rows = -(-s // dcols) + 1
            for c in range(dcols):
                col = (f + c) % dcols
                coff = o + (unit if f + c >= dcols else 0)
                out.append((top["members"][col], LABEL_START + coff, rows * unit))
            return out
        return []  # draid: left to a later version of this harness


def apply_damage(oracle, manifest, image_dir, work, rng):
    """Copy damaged members into work, apply the damage, return (member paths for the tool, notes)."""
    paths = {m: os.path.join(image_dir, m + ".img") for m in oracle.members()}
    missing = set()
    notes = []
    plans = {}  # member -> list of (offset, length, pattern)
    for d in manifest.get("damage", []):
        pat = d["pattern"]
        if "target" in d:
            for member, off, length in oracle.resolve_target(d["target"]):
                plans.setdefault(member, []).append((off, length, pat))
            if not oracle.resolve_target(d["target"]):
                notes.append(f"target {d['target']} unresolvable from the oracle (draid or missing capture)")
            continue
        member = d["member"]
        if pat == "missing":
            missing.add(member)
            continue
        length = os.path.getsize(paths[member])
        start, end = parse_range(d.get("range", "0.."), length)
        plans.setdefault(member, []).append((start, end - start, pat))
    for member, plan in plans.items():
        if member in missing:
            continue
        dst = os.path.join(work, member + ".img")
        sparse_copy(paths[member], dst)
        paths[member] = dst
        for off, length, pat in plan:
            with open(dst, "r+b") as f:
                if pat == "zeros":
                    f.seek(off)
                    f.write(b"\0" * length)
                elif pat == "random":
                    f.seek(off)
                    remaining = length
                    while remaining:
                        n = min(remaining, 1 << 20)
                        f.write(rng.randbytes(n))
                        remaining -= n
                elif pat.startswith("flip-bits:"):
                    n = int(pat.split(":")[1])
                    for _ in range(n):
                        pos = off + rng.randrange(length)
                        f.seek(pos)
                        b = f.read(1)
                        f.seek(pos)
                        f.write(bytes([b[0] ^ (1 << rng.randrange(8))]))
                elif pat.startswith("shift:"):
                    sectors = int(pat.split(":")[1])
                    f.seek(0)
                    data = f.read()
                    f.seek(0)
                    f.write(b"\0" * (sectors * 512) + data)
                elif pat == "truncate":
                    f.truncate(off)
                elif pat.startswith("older-self:"):
                    src_tag = pat.split(":", 1)[1]
                    older = os.path.join(image_dir, src_tag.replace("image-v1-", "") + "-" + member + ".img")
                    if not os.path.exists(older):
                        notes.append(f"older copy {older} not found")
                        continue
                    with open(older, "rb") as o:
                        o.seek(off)
                        chunk = o.read(length)
                    f.seek(off)
                    f.write(chunk)
                else:
                    raise ValueError(f"unknown pattern {pat}")
    ordered = [paths[m] for m in oracle.members() if m not in missing]
    return ordered, notes


def run_case(args, oracle, manifest, rng):
    mid = manifest["id"]
    work = tempfile.mkdtemp(prefix=f"golden-{mid}-", dir=args.tmp)
    result = {"id": mid, "description": manifest.get("description", ""), "expected": manifest["expect"]["outcome"]}
    try:
        members, notes = apply_damage(oracle, manifest, args.image, work, rng)
        result["notes"] = notes
        before = {p: sha256_file(p) for p in members}
        want = manifest["expect"].get("volumes", "all")
        volumes = list(oracle.export) if want == "all" else list(want)
        outcomes = {}
        reconstructed = False
        evidence_all = ""
        for vol in volumes:
            out = os.path.join(work, vol.replace("/", "_") + ".img")
            log = out + ".debug"
            cmd = [args.tool, "-q", "-f", "json", "--debug-log", log, "dump", vol, *members, "-o", out]
            key = oracle.key_spec(vol)
            if key:
                cmd += ["--key", key]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            evidence = open(log, errors="replace").read() if os.path.exists(log) else ""
            evidence_all += evidence + proc.stderr
            if proc.returncode == 0 and os.path.exists(out):
                got = sha256_file(out)
                ok = got == oracle.export[vol]
                recon = bool(re.search(r"reconstruct|MISSING|combinatorial|no present member", evidence))
                reconstructed |= recon
                outcomes[vol] = "bit-exact" if ok and not recon else ("reconstructed" if ok else f"hash mismatch (exit 0)")
            elif proc.returncode in (3, 4):
                partial = os.path.exists(out) and proc.returncode == 4
                outcomes[vol] = "refused" if not partial else "partial output (exit 4)"
            else:
                outcomes[vol] = f"exit {proc.returncode}: {proc.stderr.strip()[:200]}"
        result["volumes"] = outcomes
        cats = set(outcomes.values())
        if cats <= {"bit-exact", "reconstructed"}:
            actual = "reconstructed" if "reconstructed" in cats else "bit-exact"
        elif cats == {"refused"}:
            actual = "refused"
        else:
            actual = "defect"
        # evidence substrings the manifest asks for
        wanted = manifest["expect"].get("evidence", [])
        missing_ev = [e for e in wanted if e not in evidence_all]
        after = {p: sha256_file(p) for p in members}
        changed = [p for p in members if before[p] != after[p]]
        result["inputs_unchanged"] = not changed
        if changed:
            actual = "defect"
            result["notes"].append(f"INPUT MODIFIED: {changed}")
        result["actual"] = actual
        result["evidence_missing"] = missing_ev
        result["verdict"] = "pass" if actual == result["expected"] and not missing_ev else ("defect" if actual == "defect" else "unexpected")
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", required=True, help="directory with <member>.img (and round6-<member>.img)")
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--manifests", required=True)
    ap.add_argument("--tool", default="./target/release/zvolrescue")
    ap.add_argument("--out", default="golden-report")
    ap.add_argument("--tmp", default=None, help="scratch directory for damaged copies")
    ap.add_argument("--only", nargs="*", default=[])
    ap.add_argument("--held-out", action="store_true", help="include manifests marked held_out")
    ap.add_argument("--keep", action="store_true", help="keep damaged copies and outputs")
    args = ap.parse_args()
    oracle = Oracle(args.oracle)
    os.makedirs(args.out, exist_ok=True)
    results = []
    for name in sorted(os.listdir(args.manifests)):
        if not name.endswith(".toml"):
            continue
        manifest = tomllib.load(open(os.path.join(args.manifests, name), "rb"))
        if args.only and manifest["id"] not in args.only:
            continue
        if manifest.get("held_out") and not args.held_out:
            continue
        rng = random.Random(manifest["id"])  # reproducible garbage per manifest
        r = run_case(args, oracle, manifest, rng)
        results.append(r)
        print(f"{r['verdict']:<10} {r['id']:<32} expected {r['expected']:<14} actual {r['actual']}")
    json.dump(results, open(os.path.join(args.out, "report.json"), "w"), indent=1)
    with open(os.path.join(args.out, "report.md"), "w") as f:
        f.write("| Manifest | Expected | Actual | Verdict | Inputs unchanged | Notes |\n|---|---|---|---|---|---|\n")
        for r in results:
            f.write(f"| `{r['id']}` | {r['expected']} | {r['actual']} | {r['verdict']} | {'yes' if r.get('inputs_unchanged') else 'NO'} | {'; '.join(r.get('notes', []) + r.get('evidence_missing', []))} |\n")
    bad = [r for r in results if r["verdict"] != "pass"]
    print(f"{len(results) - len(bad)}/{len(results)} passed")
    sys.exit(1 if any(r["verdict"] == "defect" for r in results) else 0)


if __name__ == "__main__":
    main()
