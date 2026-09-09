#!/usr/bin/env python3
"""Turn `zdb -C <pool>` output into layout.json for the damage matrix.

    zdb -e -p DIR -C ztest | zdb-layout.py --pool ztest --tag image-v0-ztest > layout.json

Reads the pool configuration as OpenZFS prints it and names every leaf of
every top-level vdev `<kind>-<index>` (mirror-0a/0b for two-way mirrors,
`raidz2-0`, `draid1-0`, …). Log, cache and spare devices are skipped: the
damage matrix addresses pool members only. Nothing here consults
zvolrescue — the layout is the oracle's own answer.
"""
import argparse
import json
import re
import sys

def parse(text):
    """Indentation-driven walk of the `vdev_tree:` block."""
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip() == "vdev_tree:"), None)
    if start is None:
        raise SystemExit("zdb-layout: no vdev_tree in the input")
    base = len(lines[start]) - len(lines[start].lstrip())
    stack = [{"depth": base, "node": {"children": []}}]
    for line in lines[start + 1:]:
        if not line.strip():
            continue
        depth = len(line) - len(line.lstrip())
        if depth <= base:
            break
        m = re.match(r"\s*children\[(\d+)\]:", line)
        if m:
            while len(stack) > 1 and stack[-1]["depth"] >= depth:
                stack.pop()
            node = {"children": []}
            stack[-1]["node"]["children"].append(node)
            stack.append({"depth": depth, "node": node})
            continue
        m = re.match(r"\s*([a-z_0-9]+):\s*(.*)", line)
        if m:
            while len(stack) > 1 and stack[-1]["depth"] > depth:
                stack.pop()
            key, value = m.group(1), m.group(2).strip().strip("'")
            stack[-1]["node"][key] = value
    # The wrapper collects the root vdev's own keys; its children are the
    # top-level vdevs.
    return stack[0]["node"]


def kind_of(node):
    k = node.get("type", "?")
    if k == "raidz":
        return "raidz%s" % node.get("nparity", "1")
    if k == "draid":
        return "draid%s" % node.get("nparity", "1")
    return k


def groups(node):
    """[(group node, [leaf, ...])] — every innermost group of a top-level
    vdev with the leaves directly under it. `mirror(raidz2(f,f,f,f))` has one
    group, the raidz2; `mirror(f,f)` has one group, the mirror itself."""
    children = node.get("children", [])
    if not children:
        return []
    if all(not c.get("children") for c in children):
        return [(node, children)]
    out = []
    for c in children:
        out.extend(groups(c))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--source", default="ztest")
    ap.add_argument("--volumes", action="store_true", help="the image has zvols (kernel-built)")
    args = ap.parse_args()
    root = parse(sys.stdin.read())
    ashift = None
    tops, members = [], {}
    for top_index, top in enumerate(root.get("children", [])):
        if top.get("is_log") == "1":
            continue
        ashift = ashift or top.get("ashift")
        gs = groups(top)
        names = []
        for g_index, (group, leaf_nodes) in enumerate(gs):
            gk = kind_of(group)
            for i, leaf in enumerate(leaf_nodes):
                role = f"t{top_index}-{gk}-{i}" if len(gs) == 1 else f"t{top_index}g{g_index}-{gk}-{i}"
                names.append(role)
                members[role] = {
                    "file": leaf.get("path", "").rsplit("/", 1)[-1],
                    "guid": leaf.get("guid", "0"),
                    "top": top_index,
                    "group": g_index,
                    "group_kind": gk,
                    "index": i,
                }
        top_entry = {
            "index": top_index,
            "kind": kind_of(top),
            "members": names,
            "groups": [
                {
                    "kind": kind_of(g),
                    **({"nparity": int(g["nparity"])} if "nparity" in g else {}),
                    **({"ndata": int(g["draid_ndata"])} if "draid_ndata" in g else {}),
                    **({"nspares": int(g["draid_nspares"])} if "draid_nspares" in g else {}),
                    "count": len(lv),
                }
                for g, lv in gs
            ],
        }
        tops.append(top_entry)
    json.dump({
        "pool": args.pool,
        "image_tag": args.tag,
        "source": args.source,
        "kernel": args.source != "ztest",
        "volumes": bool(args.volumes),
        "ashift": int(ashift) if ashift else 12,
        "tops": tops,
        "members": members,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
