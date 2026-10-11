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
set -eu
TAG=$1; PIN=$2; DEST=$3; SUMS=${4:-}
REPO=${TESTDATA_REPO:-click0/zvolrescue-testdata}
command -v zstd >/dev/null || { echo "fetch-image: zstd not found" >&2; exit 1; }
PIN=$(cd "$(dirname "$PIN")" && pwd)/$(basename "$PIN")
mkdir -p "$DEST/dl" "$DEST/members" "$DEST/members-round6"
cd "$DEST/dl"
while read -r sum name; do
    [ -s "$name" ] || curl -sSL --retry 3 -o "$name" "https://github.com/$REPO/releases/download/$TAG/$name"
done < "$PIN"
sha256sum -c "$PIN"
for f in *.img.zst; do
    name=${f%.zst}
    case $f in
        round6-*) zstd -d -q -f --sparse "$f" -o "../members-round6/${name#round6-}" ;;
        *)        zstd -d -q -f --sparse "$f" -o "../members/$name" ;;
    esac
done
if [ -n "$SUMS" ]; then
    SUMS=$(cd "$(dirname "$SUMS")" && pwd)/$(basename "$SUMS")
    (cd ../members && sha256sum -c "$SUMS")
fi
du -sh ../members ../members-round6
