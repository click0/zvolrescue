#!/usr/bin/env python3
"""The verdicts of a damage-matrix report (run-matrix.py's JSON) as a
Markdown table with the counts, the reason of every n/a, the detail of
every run that landed outside its expected category — and an exit
status: 1 when such a run exists or a run changed its inputs, the two
things a matrix over an image of known layout must never let through.

    summarize-report.py REPORT.json ["Title"]
"""
import collections
import json
import sys

path = sys.argv[1]
title = sys.argv[2] if len(sys.argv) > 2 else "The damage matrix"
rs = json.load(open(path))

print(f"## {title}")
print()
print("| Manifest | Expected | Actual | Verdict |")
print("|---|---|---|---|")
for r in rs:
    print(f"| `{r['id']}` | {r['expected']} | {r['actual']} | {r['verdict']} |")
c = collections.Counter(r["verdict"] for r in rs)
print()
print(f"{len(rs)} manifests: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))

for r in rs:
    if r["verdict"] == "n/a":
        print(f"- `{r['id']}` n/a: {'; '.join(r.get('notes') or [])}")
bad = [r for r in rs if r["verdict"] not in ("pass", "n/a")]
for r in bad:
    print(f"- **{r['id']}**: expected {r['expected']}, got {r['actual']}")
    for n in r.get("notes") or []:
        print(f"  - {n}")
    for k, v in (r.get("outcomes") or {}).items():
        if k == "refused_detail":
            for vol, why in v.items():
                print(f"  - {vol}: {why}")
        elif v != "ok":
            print(f"  - {k}: {v}")
wrote = [r["id"] for r in rs if r.get("inputs_unchanged") is False]
if wrote:
    print(f"- **a run modified its own evidence**: {wrote}")
sys.exit(1 if bad or wrote else 0)
