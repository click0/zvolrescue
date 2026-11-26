#!/bin/sh
# fetch-image.sh TAG PIN DEST [MEMBERS_SHA256]
#
# The golden image as published: the release TAG of zvolrescue-testdata,
# every file named in PIN (this repository's copy of the release's
# SHA256SUMS, tests/golden/<tag>.SHA256SUMS) fetched into DEST/dl unless
# already there, checked against PIN, and decompressed sparse into
# DEST/members (the members) and DEST/members-round6 (the `round6-*`
# copies, for the older-self pattern). With MEMBERS_SHA256 (the oracle's
# members.sha256), the decompressed members are checked too.
#
# With NEEDS=FILE in the environment — one release file a line, as
# `run-matrix.py --print-needs` prints what the manifests it would run
# need — only those are fetched, checked and decompressed, and each of
# them has to be in PIN. A run of manifests that names no older copy
# then fetches none, and one that names a few fetches those few.
set -eu
TAG=$1; PIN=$2; DEST=$3; SUMS=${4:-}
REPO=${TESTDATA_REPO:-click0/zvolrescue-testdata}
command -v zstd >/dev/null || { echo "fetch-image: zstd not found" >&2; exit 1; }
# Both files by absolute path, before the cd below moves away from them.
PIN=$(cd "$(dirname "$PIN")" && pwd)/$(basename "$PIN")
[ -z "$SUMS" ] || SUMS=$(cd "$(dirname "$SUMS")" && pwd)/$(basename "$SUMS")
mkdir -p "$DEST/dl" "$DEST/members" "$DEST/members-round6"
# The lines of PIN this run fetches: all of them, or those NEEDS names.
LIST=$(cd "$DEST" && pwd)/fetch.pin
if [ -n "${NEEDS:-}" ]; then
    awk 'NR == FNR { if ($1 != "") want[$1] = 1; next }
         ($2 in want) { print; got[$2] = 1 }
         END { for (n in want) if (!(n in got)) { print "fetch-image: " n " is not in the pin" > "/dev/stderr"; bad = 1 }
               exit bad }' "$NEEDS" "$PIN" > "$LIST"
    echo "fetch-image: $(wc -l < "$LIST") of the $(wc -l < "$PIN") files of $TAG, as NEEDS lists them"
else
    cp "$PIN" "$LIST"
fi
cd "$DEST/dl"
while read -r sum name; do
    [ -s "$name" ] || curl -sSL --retry 3 -o "$name" "https://github.com/$REPO/releases/download/$TAG/$name"
done < "$LIST"
sha256sum -c "$LIST"
while read -r sum f; do
    name=${f%.zst}
    case $f in
        round6-*) zstd -d -q -f --sparse "$f" -o "../members-round6/${name#round6-}" ;;
        *)        zstd -d -q -f --sparse "$f" -o "../members/$name" ;;
    esac
done < "$LIST"
if [ -n "$SUMS" ]; then
    (cd ../members && sha256sum -c "$SUMS")
fi
du -sh ../members ../members-round6
