#!/bin/sh
# The zstd decoder, pure Rust against libzstd (SPEC §12 Q3, D-8).
#
#   tests/zstd-bench.sh [ZVOLRESCUE] [MKFIXTURE] [ZSTD_BENCH] [WORKDIR] [MIB] [LEVEL]
#
# Takes a dense fixture volume's bytes (the lz4 bench volume's text,
# extracted with `dump`, so the data is the fixtures' own), cuts them
# into 128 KiB blocks — the volume's block size, and the largest block
# zstd meets on a default pool — compresses each with the `zstd`
# command at LEVEL (default 3, OpenZFS's `zstd` default), and decodes
# the lot through the reader's own decoder (`zstd-bench`, checked
# against the originals). libzstd's rate on the same bytes comes from
# `zstd -b`, its built-in benchmark, on the same block size.
#
# Nothing is enforced but correctness: the numbers are the answer to
# the open question, printed as one markdown table. Needs: the release
# binaries, the two examples built in release, the zstd command.
set -eu
ZR=${1:-./target/release/zvolrescue}
MK=${2:-./target/release/examples/mkfixture}
ZB=${3:-./target/release/examples/zstd-bench}
WORK=${4:-/tmp/zvolrescue-zstd}
MIB=${5:-64}
LEVEL=${6:-3}

rm -rf "$WORK"; mkdir -p "$WORK/blocks"
"$MK" "$WORK/fx" bench 12 "$MIB" lz4 > /dev/null
"$ZR" -q dump tank/vm/disk0 "$WORK"/fx/member*.img -o "$WORK/vol.img" > /dev/null
( cd "$WORK/blocks" && split -b 131072 -a 4 -d "$WORK/vol.img" b && for f in b*; do mv "$f" "$f.raw"; done )
for f in "$WORK"/blocks/*.raw; do zstd -q "-$LEVEL" "$f" -o "${f%.raw}.zst"; done
ours=$(ZSTD_LEVEL="$LEVEL" "$ZB" "$WORK/blocks" 5 | sed -n 's/^mbs //p')
# `zstd -b` reports the compression rate and then the decompression
# rate, each as "N MB/s"; the last one is the decode.
theirs=$(zstd -q "-b$LEVEL" -B131072 -i3 "$WORK/vol.img" 2>&1 | tr '\r' '\n' | grep -o '[0-9.]* MB/s' | tail -1 | cut -d' ' -f1)
echo "| data | block | level | ruzstd MB/s | libzstd MB/s | ratio |"
echo "|---|---|---|---|---|---|"
python3 - "$MIB" "$LEVEL" "$ours" "$theirs" <<'PY'
import sys
mib, level, ours, theirs = sys.argv[1:]
o, t = float(ours), float(theirs)
print(f"| fixture text, {mib} MiB | 128 KiB | {level} | {o:.0f} | {t:.0f} | {o / t * 100:.0f} % |")
PY
rm -rf "$WORK"
