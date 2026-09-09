#!/usr/bin/env python3
"""Run the damage matrix (SPEC §9.1) against a golden image.

    run-matrix.py --image DIR --oracle DIR --manifests DIR [--tool ...] [--walker ...]
                  [--out DIR] [--only ID ...] [--held-out] [--keep]

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
the tool. Outcomes: bit-exact / reconstructed / refused / defect; exit 1
when any run is a defect.
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
    def __init__(self, d, image):
        self.dir, self.image = d, image
        self.layout = json.load(open(os.path.join(d, "layout.json")))
        self.pool = self.layout["pool"]
        self.has_volumes = bool(self.layout.get("volumes"))
        self.roles = list(self.layout["members"])
        self.inventory = {}
        inv = os.path.join(d, "inventory.txt")
        if os.path.exists(inv):
            for line in open(inv):
                f = line.split()
                if len(f) >= 2:
                    self.inventory[f[0]] = {"creation_txg": int(f[1]), "objects": int(f[2]) if len(f) > 2 and f[2].isdigit() else None}
        self.volumes = {}
        vs = os.path.join(d, "volumes.sha256")
        if os.path.exists(vs):
            for line in open(vs):
                f = line.split()
                if len(f) == 2 and f[1].endswith("@export"):
                    self.volumes[f[1][: -len("@export")]] = f[0]
        self.key = None
        rk = os.path.join(d, "keys", "raw.key")
        if os.path.exists(rk):
            self.key = "raw:" + rk
        self.zdb = ""
        zd = os.path.join(d, "zdb-dddd.txt")
        if os.path.exists(zd):
            self.zdb = open(zd, errors="replace").read()

    def path(self, role):
        return os.path.join(self.image, self.layout["members"][role]["file"])

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
        for role, info in self.layout["members"].items():
            if kind and info["group_kind"] != kind:
                continue
            if top is not None and info["top"] != top:
                continue
            if info["index"] == leaf:
                return role
        raise Unresolved(f"no member matching {spec}")

    def resolve_target(self, target):
        """(role, offset, length) for the chosen DVA copies of a structure,
        located from the oracle's zdb capture."""
        obj, copy = target["object"], target.get("copy", "all")
        if obj == "mos:objset":
            m = re.search(r"^Dataset mos .*?rootbp (.*)$", self.zdb, re.M)
            raw = m.group(1) if m else ""
        else:
            ds, what = obj.rsplit(":", 1)
            name = ds if ds.startswith(self.pool) else f"{self.pool}/{ds}"
            m = re.search(rf"^Dataset {re.escape(name)} .*?rootbp (.*)$", self.zdb, re.M)
            raw = m.group(1) if m else ""
            if what not in ("objset", "dnode-block"):
                raise Unresolved(f"target {obj}: only objset/dnode-block are located from zdb")
        dvas = re.findall(r"DVA\[(\d)\]=<(\d+):([0-9a-f]+):([0-9a-f]+)>", raw)
        if not dvas:
            raise Unresolved(f"target {obj} not found in the zdb capture")
        if copy != "all":
            dvas = [d for d in dvas if int(d[0]) == int(copy)]
        out = []
        for _, vdev, off, sz in dvas:
            out.extend(self.dva_to_physical(int(vdev), int(off, 16), int(sz, 16)))
        if not out:
            raise Unresolved(f"target {obj}: DVA on a vdev this harness cannot map")
        return out

    def dva_to_physical(self, vdev, offset, asize):
        tops = [t for t in self.layout["tops"] if t["index"] == vdev]
        if not tops:
            return []
        top = tops[0]
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
        return []  # draid: a later version of this harness


def apply_damage(oracle, manifest, work, rng):
    """Returns (member paths for the tool, notes). Raises Unresolved when the
    manifest addresses something this image does not have."""
    paths = {r: oracle.path(r) for r in oracle.roles}
    missing, notes, plans = set(), [], {}
    for d in manifest.get("damage", []):
        pat = d["pattern"]
        if "target" in d:
            for role, off, length in oracle.resolve_target(d["target"]):
                plans.setdefault(role, []).append((off, length, pat))
            continue
        role = oracle.resolve(d["member"])
        if pat == "missing":
            missing.add(role)
            continue
        length = os.path.getsize(paths[role])
        start, end = parse_range(d.get("range", "0.."), length)
        plans.setdefault(role, []).append((start, end - start, pat))
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
                    raise Unresolved("this image has no older-self material")
                else:
                    raise ValueError(f"unknown pattern {pat}")
    ordered = [paths[r] for r in oracle.roles if r not in missing]
    return ordered, notes


def judge_dump(args, oracle, manifest, members, work):
    want = manifest["expect"].get("volumes", "all")
    volumes = list(oracle.volumes) if want == "all" else list(want)
    outcomes, redundancy = {}, False
    for vol in volumes:
        out = os.path.join(work, vol.replace("/", "_") + ".img")
        log = out + ".debug"
        cmd = [args.tool, "-q", "-f", "json", "--debug-log", log, "dump", vol, *members, "-o", out]
        if oracle.key:
            cmd += ["--key", oracle.key]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        trace = open(log, errors="replace").read() if os.path.exists(log) else ""
        redundancy |= bool(REDUNDANCY.search(trace))
        if proc.returncode == 0 and os.path.exists(out):
            outcomes[vol] = "ok" if sha256_file(out) == oracle.volumes[vol] else "hash mismatch"
        elif proc.returncode == 3:
            outcomes[vol] = "refused"
        else:
            outcomes[vol] = f"exit {proc.returncode}: {proc.stderr.strip()[:160]}"
    return outcomes, redundancy


def judge_walk(args, oracle, members, work):
    """No zvols: the datasets must match `zdb -d` and every block must read."""
    outcomes = {}
    env = dict(os.environ)
    if oracle.key:
        env["ZR_KEY"] = oracle.key
    proc = subprocess.run([args.tool, "-f", "json", "list", "-r", *members],
                          capture_output=True, text=True)
    if proc.returncode == 3:
        return {"pool": "refused"}, False
    if proc.returncode != 0:
        return {"pool": f"list exit {proc.returncode}: {proc.stderr.strip()[:160]}"}, False
    try:
        listed = {d["name"]: d["creation_txg"] for d in json.loads(proc.stdout)["datasets"]}
    except Exception as e:  # noqa: BLE001
        return {"pool": f"list output unparsable: {e}"}, False
    expected = {n: v["creation_txg"] for n, v in oracle.inventory.items()}
    if listed != expected:
        only_oracle = sorted(set(expected) - set(listed))
        only_tool = sorted(set(listed) - set(expected))
        outcomes["datasets"] = f"differ from zdb (missing {only_oracle[:3]}, extra {only_tool[:3]})"
    else:
        outcomes["datasets"] = "ok"
    # The debug trace is far too large to keep: stream it and look only for
    # evidence that redundancy was used.
    walk_out = os.path.join(work, "walk.txt")
    redundancy = False
    with open(walk_out, "w") as so:
        wproc = subprocess.Popen([args.walker, *members], stdout=so,
                                 stderr=subprocess.PIPE, text=True, errors="replace",
                                 env=dict(env, ZR_DEBUG="1"))
        for line in wproc.stderr:
            if not redundancy and REDUNDANCY.search(line):
                redundancy = True
        wproc.wait()
    text = open(walk_out, errors="replace").read()
    # Lines the walker prints for blocks it could not produce. A failure is
    # *clean* when the tool said why and offered nothing: redundancy
    # exhausted, every copy bad, no key. Anything else (a parse error, a
    # decompression failure, a panic) means the tool broke.
    CLEAN = re.compile(r"not recoverable|every copy failed|no present member|"
                       r"no key|not supported yet|block pointer is a hole")
    failures = [l.strip() for l in text.splitlines()
                if re.search(r"ERROR|Mismatch|dnode:|locate:|objset \S+:", l)]
    unclean = [l for l in failures if not CLEAN.search(l)]
    if unclean:
        outcomes["blocks"] = "; ".join(unclean[:3])
    elif failures:
        outcomes["blocks"] = "refused"
        outcomes["refused_detail"] = "; ".join(failures[:3])
    elif wproc.returncode not in (0, 1):
        outcomes["blocks"] = f"walker exit {wproc.returncode}"
    else:
        outcomes["blocks"] = "ok"
    m = re.search(r"^datasets (\d+) objects (\d+) blocks (\d+)", text, re.M)
    if m:
        outcomes["counts"] = f"{m.group(1)} datasets, {m.group(2)} objects, {m.group(3)} blocks"
    return outcomes, redundancy


def run_case(args, oracle, manifest, rng):
    mid = manifest["id"]
    work = tempfile.mkdtemp(prefix=f"golden-{mid}-", dir=args.tmp)
    # Expectations may differ by geometry: losing one copy of a block is
    # transparent on a mirror and needs parity on a raidz.
    expect = manifest["expect"]
    kinds = {m["group_kind"] for m in oracle.layout["members"].values()}
    expected = expect["outcome"]
    for kind, alt in expect.get("by_group_kind", {}).items():
        if kind in kinds:
            expected = alt
            break
    # A manifest may name several acceptable outcomes when the damage does
    # not deterministically hit live data (scattered bit flips, say).
    accepted = [expected] if isinstance(expected, str) else list(expected)
    expected = " | ".join(accepted)
    result = {"id": mid, "description": manifest.get("description", ""),
              "expected": expected, "notes": []}
    try:
        try:
            members, notes = apply_damage(oracle, manifest, work, rng)
        except Unresolved as e:
            result.update(actual="n/a", verdict="n/a", notes=[str(e)])
            return result
        result["notes"] = notes
        before = {p: sha256_file(p) for p in members}
        if oracle.has_volumes:
            outcomes, redundancy = judge_dump(args, oracle, manifest, members, work)
            good = {"ok"}
        else:
            outcomes, redundancy = judge_walk(args, oracle, members, work)
            good = {"ok"}
        result["outcomes"] = outcomes
        judged = {k: v for k, v in outcomes.items() if k not in ("counts", "refused_detail")}
        values = set(judged.values())
        if values <= good:
            actual = "reconstructed" if redundancy else "bit-exact"
        elif values <= good | {"refused"}:
            actual = "refused"
        else:
            actual = "defect"
        after = {p: sha256_file(p) for p in members}
        changed = [os.path.basename(p) for p in members if before[p] != after[p]]
        result["inputs_unchanged"] = not changed
        if changed:
            actual = "defect"
            result["notes"].append(f"INPUT MODIFIED: {changed}")
        result["actual"] = actual
        result["verdict"] = ("pass" if actual in accepted
                             else "defect" if actual == "defect" else "unexpected")
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", required=True, help="directory holding the member files")
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--manifests", required=True)
    ap.add_argument("--tool", default="./target/release/zvolrescue")
    ap.add_argument("--walker", default="./target/release/examples/walk-objects")
    ap.add_argument("--out", default="golden-report")
    ap.add_argument("--label", default="", help="name of this image in the report")
    ap.add_argument("--tmp", default=None)
    ap.add_argument("--only", nargs="*", default=[])
    ap.add_argument("--held-out", action="store_true")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    oracle = Oracle(args.oracle, args.image)
    os.makedirs(args.out, exist_ok=True)
    label = args.label or os.path.basename(args.oracle.rstrip("/"))
    results = []
    for name in sorted(os.listdir(args.manifests)):
        if not name.endswith(".toml"):
            continue
        manifest = tomllib.load(open(os.path.join(args.manifests, name), "rb"))
        if args.only and manifest["id"] not in args.only:
            continue
        if manifest.get("held_out") and not args.held_out:
            continue
        r = run_case(args, oracle, manifest, random.Random(manifest["id"]))
        r["image"] = label
        results.append(r)
        print(f"{label:<8} {r['verdict']:<10} {r['id']:<32} expected {r['expected']:<14} actual {r['actual']}")
    with open(os.path.join(args.out, f"report-{label}.json"), "w") as f:
        json.dump(results, f, indent=1)
    with open(os.path.join(args.out, f"report-{label}.md"), "w") as f:
        f.write(f"# Damage matrix: {label}\n\n")
        f.write("| Manifest | Expected | Actual | Verdict | Inputs unchanged | Detail |\n|---|---|---|---|---|---|\n")
        for r in results:
            detail = "; ".join(list(r.get("notes", [])) + [f"{k}: {v}" for k, v in r.get("outcomes", {}).items() if v != "ok"])
            f.write(f"| `{r['id']}` | {r['expected']} | {r['actual']} | {r['verdict']} | "
                    f"{'yes' if r.get('inputs_unchanged') else ('—' if r['verdict'] == 'n/a' else 'NO')} | {detail} |\n")
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(f"{label}: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    sys.exit(1 if counts.get("defect") else 0)


if __name__ == "__main__":
    main()
