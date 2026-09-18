#!/bin/sh
# Memory and throughput on dense volumes (SPEC N-03, N-08).
#
#   tests/bench.sh [ZVOLRESCUE] [MKFIXTURE] [WORKDIR] [MIB]
#
# Builds a dense volume — every block present under a real indirect
# tree, 128 KiB blocks — on a mirror and on a raidz2, with compression
# off, lz4 and gzip, and extracts each with `dump`. For every run it
# reports the extraction rate, the rate of a plain copy of the same
# number of bytes out of a member (read warm from the page cache, as
# the extraction reads, and written next to it, as the extraction
# writes), the ratio, and the peak resident set the run reports.
#
# What is enforced: the extracted image has the SHA-256 the generator
# computed (a wrong tree is not a benchmark), the peak resident set is
# under N-03's 512 MiB, and the extraction rate is above BENCH_FLOOR
# MB/s (default 50) — a floor against a pathological regression, not
# the N-08 target. N-08's 70 % / 40 % are ratios to a *disk's* read
# rate, where the disk is the bottleneck; here the members are warm in
# the page cache, so the copy is bounded by the write side alone and
# the ratio says how much the reader's own work — checksums, parity,
# decompression, two sides of a mirror — costs on top of it. That is
# worth knowing and is printed. A real disk is REALWORLD-TESTS E1/E2.
#
# Needs: the release binary, the mkfixture example built in release,
# python3.
set -eu
ZR=${1:-./target/release/zvolrescue}
MK=${2:-./target/release/examples/mkfixture}
WORK=${3:-/tmp/zvolrescue-bench}
MIB=${4:-256}
FLOOR=${BENCH_FLOOR:-50}
LIMIT_KIB=$((512 * 1024))

rm -rf "$WORK"; mkdir -p "$WORK"
fail=0
echo "| pool | compression | volume | dump MB/s | copy MB/s | ratio | peak RSS |"
echo "|---|---|---|---|---|---|---|"
for kind in bench bench-raidz2; do
    for comp in off lz4 gzip; do
        dir="$WORK/$kind-$comp"
        rm -rf "$dir"
        want=$("$MK" "$dir" "$kind" 12 "$MIB" "$comp" | sed -n 's/^sha256 //p')
        members=$(ls "$dir"/member*.img)
        # Raw, once per pool kind, from the uncompressed member (a
        # compressed one is shorter than the volume): the volume's worth
        # of bytes read warm from the page cache, as the extraction reads
        # them, and written next to it through the same page cache the
        # extraction writes through — the floor no reader can beat on
        # this host, a copy. Best of three, since writeback jitters.
        if [ "$comp" = off ]; then
            raw=$(python3 - "$dir" "$MIB" $members <<'PY'
import os, subprocess, sys, time
d, mib, first = sys.argv[1], int(sys.argv[2]), sys.argv[3]
total = mib << 20
best = 0.0
for _ in range(3):
    t = time.perf_counter()
    with open(f"{d}/raw.img", "wb") as out:
        subprocess.run(["head", "-c", str(total), first], stdout=out, check=True)
    best = max(best, total / (time.perf_counter() - t) / 1e6)
    os.remove(f"{d}/raw.img")
print(best)
PY
)
        fi
        "$ZR" -q -f json dump tank/vm/disk0 $members -o "$dir/out.img" > "$dir/dump.json" 2> "$dir/dump.err" || {
            echo "dump failed for $kind/$comp:"; cat "$dir/dump.err"; fail=1; continue; }
        python3 - "$kind" "$comp" "$want" "$raw" "$dir/dump.json" "$MIB" "$FLOOR" "$LIMIT_KIB" <<'PY' || fail=1
import json, sys
kind, comp, want, raw, path, mib, floor, limit = sys.argv[1:]
raw, floor, limit = float(raw), float(floor), int(limit)
d = json.load(open(path)); v = d["volumes"][0]
mbs = v["bytes_written"] / v["seconds"] / 1e6
rss = d.get("peak_rss_kib")
rss_s = f"{rss / 1024:.0f} MiB" if rss else "n/a"
label = {"bench": "mirror", "bench-raidz2": "raidz2"}[kind]
print(f"| {label} | {comp} | {mib} MiB | {mbs:.0f} | {raw:.0f} | {mbs / raw * 100:.0f} % | {rss_s} |")
bad = []
if v["sha256"] != want:
    bad.append(f"sha256 {v['sha256']} != {want}")
if v.get("bad"):
    bad.append(f"{len(v['bad'])} unreadable range(s)")
if rss is not None and rss > limit:
    bad.append(f"peak RSS {rss} KiB over {limit} KiB (N-03)")
if mbs < floor:
    bad.append(f"{mbs:.1f} MB/s under the {floor} MB/s floor")
if bad:
    print(f"FAIL {kind}/{comp}: " + "; ".join(bad), file=sys.stderr)
    sys.exit(1)
PY
        rm -f "$dir/out.img" "$dir"/member*.img
    done
done
exit $fail
