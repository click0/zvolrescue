#!/bin/sh
# Build the INTERIM golden image with OpenZFS userland only (SPEC §9.1).
#
#   sh tests/golden/build-ztest-image.sh OUT [TAG]
#
# `ztest` creates and exercises real pools without a kernel module, so this
# runs anywhere OpenZFS userland is installed — no VM, no root, no disks.
# It is a stopgap for the real golden image (tests/golden/build-image.sh),
# with two limitations that the damage matrix must respect:
#
#   * ztest makes no zvols, so runs are judged by walking every object of
#     every dataset against the oracle instead of by volume hashes;
#   * ztest cannot mix top-level vdev kinds in one pool, so the interim
#     image is three pools (mirror, raidz2, draid1) rather than one.
#
# Everything else is genuine: real MOS, DSL, dnodes, ZAPs, every checksum
# and compression, encrypted datasets, gang blocks, hundreds of TXGs. The
# oracle comes from `zdb` only — never from zvolrescue.
#
# One further limitation: there is no `older-self` material here. ztest can
# only continue on an existing pool through a cachefile it does not leave
# behind, so a member cannot be captured at two points of the same pool's
# life. Manifests using that pattern are skipped on this image.
set -eu

OUT=${1:?output directory}
TAG=${2:-image-v0-ztest}
KEY_MATERIAL=abcdefghijklmnopqrstuvwxyz012345   # ztest_wkeydata, fixed in ztest.c
RUN_TIME=${RUN_TIME:-45}

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
say() { printf '== %s\n' "$*"; }
die() { printf 'build-ztest-image: %s\n' "$*" >&2; exit 1; }
command -v ztest >/dev/null || die "ztest not found (Debian/Ubuntu: zfs-test)"
command -v zdb   >/dev/null || die "zdb not found (zfsutils-linux)"
command -v zstd  >/dev/null || die "zstd not found"
if command -v sha256sum >/dev/null; then sha() { sha256sum "$1" | awk '{print $1}'; }
else sha() { sha256 -q "$1"; }; fi

# build_pool TOPOLOGY ztest-args...
# One ztest run per pool: it creates the pool, exercises it for RUN_TIME
# seconds (hundreds of TXGs) and leaves the members on disk. `-g` lowers the
# gang threshold so gang blocks are always present, `-k 0` lets the run end
# cleanly instead of in a simulated crash.
build_pool() {
    topo=$1; shift
    dir="$OUT/pools/$topo"
    rm -rf "$dir"; mkdir -p "$dir"
    say "$topo: ztest (${RUN_TIME}s)"
    ( cd "$dir" && ztest -f "$dir" -v 1 "$@" -g 8192 -s 128m -a 12 -d 4 -t 4 -k 0 \
        -T "$RUN_TIME" -P 8 > "$dir/ztest.log" 2>&1 ) || {
        grep -v "^\(loading\|verifying\)" "$dir/ztest.log" | tail -5; die "$topo: ztest failed"; }
}

capture_oracle() {
    topo=$1
    dir="$OUT/pools/$topo"
    od="$OUT/oracle/$topo"
    mkdir -p "$od/labels" "$od/keys"
    say "$topo: oracle"
    printf '%s' "$KEY_MATERIAL" > "$od/keys/raw.key"
    zdb -e -p "$dir" -d    ztest > "$od/datasets.txt"  2>/dev/null || true
    zdb -e -p "$dir" -dddd ztest > "$od/zdb-dddd.txt"  2>&1 || true
    zdb -e -p "$dir" -C    ztest > "$od/zdb-C.txt"     2>&1 || true
    zdb -e -p "$dir" -u    ztest > "$od/zdb-u.txt"     2>&1 || true
    # Dataset inventory (name, creation TXG, object count) straight from
    # `zdb -d`: the independent answer every damaged run is compared against.
    awk '/^Dataset /{
             name=$2; txg=""; objs="";
             for (i=1;i<=NF;i++) { if ($i=="cr_txg") { txg=$(i+1); gsub(/,/,"",txg) }
                                   if ($i=="objects" || $i=="objects,") objs=$(i-1) }
             if (name != "mos") printf "%s %s %s\n", name, txg, objs }' \
        "$od/datasets.txt" | sort > "$od/inventory.txt"
    # Roles, files and GUIDs from the pool configuration itself.
    python3 "$(dirname "$0")/zdb-layout.py" --pool ztest --tag "$TAG" \
        < "$od/zdb-C.txt" > "$od/layout.json"
    python3 - "$od/layout.json" > "$od/members.txt" <<'PYEOF'
import json, sys
layout = json.load(open(sys.argv[1]))
for top in layout["tops"]:
    for role in top["members"]:
        print(role, layout["members"][role]["file"])
PYEOF
    while read -r role file; do
        zdb -l "$dir/$file" > "$od/labels/$role.txt" 2>&1 || true
    done < "$od/members.txt"
}

package() {
    topo=$1
    dir="$OUT/pools/$topo"
    od="$OUT/oracle/$topo"
    rel="$OUT/release"; mkdir -p "$rel"
    say "$topo: packaging"
    while read -r role file; do
        zstd -T0 -12 -q -f "$dir/$file" -o "$rel/$topo-$role.img.zst"
    done < "$od/members.txt"
}

say "interim golden image $TAG"
for spec in "mirror -K raidz -m 2 -r 1 -R 0" \
            "raidz2 -K raidz -m 1 -r 4 -R 2" \
            "draid1 -K draid -m 1 -r 4 -R 1 -D 2 -S 1"; do
    # shellcheck disable=SC2086
    set -- $spec
    topo=$1; shift
    build_pool "$topo" "$@"
    capture_oracle "$topo"
    package "$topo"
done

( cd "$OUT/release" && for f in *.zst; do printf '%s  %s\n' "$(sha "$f")" "$f"; done > SHA256SUMS )

{
    echo "# The interim golden image ($TAG)"
    echo
    echo "Built $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(uname -srm) with OpenZFS userland"
    echo "(\`$(zdb -V 2>/dev/null || echo 'zdb, version unknown')\`), **no kernel module**:"
    echo "\`ztest\` created and exercised the pools in userland."
    echo
    echo "## What this is and is not"
    echo
    echo "This is a stopgap until the real golden image can be built on a host with"
    echo "a ZFS kernel module (\`tests/golden/build-image.sh\`). It carries real"
    echo "OpenZFS metadata — MOS, DSL, dnodes, ZAPs, every checksum and compression,"
    echo "encrypted datasets, gang blocks, hundreds of TXGs — but:"
    echo
    echo "* **no zvols**: ztest creates filesystem-like datasets only, so damage runs"
    echo "  are judged by walking every object of every dataset against the oracle,"
    echo "  not by comparing volume hashes;"
    echo "* **three pools, not one**: ztest cannot mix top-level vdev kinds, so the"
    echo "  mirror, raidz2 and draid1 geometries live in separate pools. Damage"
    echo "  manifests that span geometries do not apply here."
    echo
    echo "## Pools"
    echo
    echo "| Pool | Topology | Members (role → file) |"
    echo "|---|---|---|"
    for topo in mirror raidz2 draid1; do
        m=$(awk '{printf "%s → %s, ", $1, $2}' "$OUT/oracle/$topo/members.txt" | sed 's/, $//')
        k=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tops"][0]["kind"])' "$OUT/oracle/$topo/layout.json")
        echo "| $topo | $k | $m |"
    done
    echo
    echo "## Datasets"
    echo
    for topo in mirror raidz2 draid1; do
        echo "### $topo"
        echo
        echo '```'
        cat "$OUT/oracle/$topo/inventory.txt"
        echo '```'
        echo
    done
    echo "## Oracle"
    echo
    echo "\`oracle/<pool>/\`: \`inventory.txt\` (dataset, creation TXG, object count — from"
    echo "\`zdb -d\`), \`datasets.txt\`, \`zdb-dddd.txt\` (every object with its block"
    echo "pointers and the checksums ZFS recorded), \`zdb-C.txt\`, \`zdb-u.txt\`,"
    echo "\`labels/<role>.txt\` (\`zdb -l\`), \`members.txt\`, \`layout.json\`, \`keys/raw.key\`"
    echo "(ztest's fixed wrapping key). Nothing here was produced by zvolrescue."
    echo
    echo "## Release files"
    echo
    echo "\`<pool>-<role>.img.zst\` are the published members, one file per role."
    echo "There is no \`older-self\` material in this image: ztest cannot be resumed"
    echo "on an existing pool without a cachefile it does not leave behind, so a"
    echo "member cannot be captured at two points of the same pool\'s life. Manifests"
    echo "using that pattern are skipped until the kernel-built image exists."
    echo
    echo '```'
    cat "$OUT/release/SHA256SUMS"
    echo '```'
} > "$OUT/IMAGE.md"

say "done: $OUT/release, $OUT/oracle, $OUT/IMAGE.md"
