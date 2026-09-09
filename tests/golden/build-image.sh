#!/bin/sh
# Build the golden pool image (SPEC §9.1, REALWORLD-TESTS scenario G1).
#
# Runs on a host with a real OpenZFS kernel module (FreeBSD 14/15 or Linux),
# as root, in a scratch directory. It creates one pool on file-backed
# members with three top-level vdevs (mirror, raidz2, draid1), fills it
# with every kind of metadata zvolrescue must read, drives hundreds of
# TXGs, records the oracle, exports the pool and packages the members for
# a release of zvolrescue-testdata.
#
#   sh tests/golden/build-image.sh /var/tmp/golden [image-tag]
#
# Output: OUT/release/ (zstd-compressed members + SHA256SUMS) and
# OUT/oracle/ (hashes, zdb captures, keys, layout.json) and OUT/IMAGE.md.
# Nothing here is ever produced by zvolrescue itself: the oracle comes from
# OpenZFS only.
#
# Deterministic content: every write is a keystream from a fixed seed, so a
# rebuild in the same environment yields the same volume hashes (block
# placement and TXG numbers may differ, and that is fine: the oracle is
# captured from whatever this run produced).
set -eu

OUT=${1:?output directory}
TAG=${2:-image-v1}
POOL=golden
MEMBER_SIZE=512M
SEED=zvolrescue-golden-2026
PASSPHRASE="golden passphrase for tests"
mkdir -p "$OUT/members" "$OUT/release" "$OUT/oracle" "$OUT/oracle/labels" "$OUT/oracle/datasets-by-txg" "$OUT/oracle/keys"
OUT=$(cd "$OUT" && pwd)

os=$(uname -s)
say() { printf '== %s\n' "$*"; }
die() { printf 'build-image: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root (zpool/zfs need it)"
command -v zpool >/dev/null || die "zpool not found"
command -v zdb >/dev/null || die "zdb not found"
command -v zstd >/dev/null || die "zstd not found"
if command -v sha256sum >/dev/null; then SHA="sha256sum"; else SHA="sha256 -r"; fi
sha() { $SHA "$1" | awk '{print $1}'; }

# Deterministic pseudo-random bytes: AES-CTR keystream of zeros, keyed by
# SEED and a per-stream label. Same input, same bytes, on any host.
stream() { # stream LABEL BYTES > data
    key=$(printf '%s:%s' "$SEED" "$1" | openssl dgst -sha256 | awk '{print $NF}')
    head -c "$2" /dev/zero | openssl enc -aes-256-ctr -K "$key" -iv 00000000000000000000000000000000 2>/dev/null
}

zvol_dev() { echo "/dev/zvol/$1"; }
wait_dev() { # zvol devices appear asynchronously
    i=0; while [ ! -e "$1" ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done
    [ -e "$1" ] || die "device $1 did not appear"
}
tunable() { # tunable NAME VALUE (Linux module parameter or FreeBSD sysctl)
    case $os in
        Linux) [ -w "/sys/module/zfs/parameters/$1" ] && echo "$2" > "/sys/module/zfs/parameters/$1" || true ;;
        FreeBSD) sysctl "vfs.zfs.$3=$2" >/dev/null 2>&1 || true ;;
    esac
}
txg_sync() { zpool sync "$POOL"; }

# ---------------------------------------------------------------- members
say "members"
M_MIRROR="mirror-0a mirror-0b"
M_RAIDZ="raidz2-0 raidz2-1 raidz2-2 raidz2-3"
M_DRAID="draid1-0 draid1-1 draid1-2 draid1-3"
ALL="$M_MIRROR $M_RAIDZ $M_DRAID"
for m in $ALL; do truncate -s "$MEMBER_SIZE" "$OUT/members/$m.img"; done
paths() { for m in "$@"; do printf '%s ' "$OUT/members/$m.img"; done; }

# Gang blocks: force them for allocations above a small size while the
# pool is being filled (Linux metaslab_force_ganging, FreeBSD
# vfs.zfs.metaslab.force_ganging).
tunable metaslab_force_ganging 16384 metaslab.force_ganging

# ---------------------------------------------------------------- pool
say "pool"
zpool create -f -o ashift=12 -o autotrim=off -O compression=lz4 -O snapdev=visible -O dnodesize=auto \
    "$POOL" \
    mirror $(paths $M_MIRROR) \
    raidz2 $(paths $M_RAIDZ) \
    draid1:2d:4c:1s $(paths $M_DRAID)

# Keys of the encrypted datasets (they protect nothing).
stream rawkey 32 > "$OUT/oracle/keys/raw.key"
printf '%s\n' "$PASSPHRASE" > "$OUT/oracle/keys/passphrase.txt"

# ---------------------------------------------------------------- datasets
say "datasets"
zfs create "$POOL/vm"
zfs create -o dnodesize=auto "$POOL/fs-largednode"
# zvols: one per checksum/compression pair worth having, several block sizes
zfs create -V 48M -b 8K   -o checksum=fletcher4 -o compression=lz4  "$POOL/vm/disk-8k"
zfs create -V 48M -b 16K  -o checksum=sha256    -o compression=zstd "$POOL/vm/disk-16k"
zfs create -V 48M -b 64K  -o checksum=sha512    -o compression=gzip-6 "$POOL/vm/disk-64k"
zfs create -V 48M -b 16K  -o checksum=skein     -o compression=lzjb "$POOL/vm/disk-skein"
zfs create -V 48M -b 16K  -o checksum=edonr     -o compression=zle  "$POOL/vm/disk-edonr"
zfs create -V 48M -b 16K  -o checksum=blake3    -o compression=off  "$POOL/vm/disk-blake3"
zfs create -s -V 256M -b 16K -o checksum=fletcher4 -o compression=lz4 "$POOL/vm/disk-sparse"
# encrypted: raw key and passphrase
zfs create -o encryption=aes-256-gcm -o keyformat=raw -o keylocation="file://$OUT/oracle/keys/raw.key" "$POOL/secret-raw"
zfs create -V 48M -b 16K -o checksum=sha256 -o compression=lz4 "$POOL/secret-raw/disk"
zfs create -o encryption=aes-128-ccm -o keyformat=passphrase -o keylocation="file://$OUT/oracle/keys/passphrase.txt" "$POOL/secret-pw"
zfs create -V 48M -b 8K -o checksum=skein -o compression=zstd "$POOL/secret-pw/disk"
# a volume that will be destroyed, and one that will be renamed
zfs create -V 32M -b 16K -o checksum=sha256 "$POOL/vm/doomed"
zfs create -V 32M -b 16K -o checksum=fletcher4 "$POOL/vm/oldname"
txg_sync

VOLS="vm/disk-8k vm/disk-16k vm/disk-64k vm/disk-skein vm/disk-edonr vm/disk-blake3 vm/disk-sparse secret-raw/disk secret-pw/disk vm/doomed vm/oldname"
for v in $VOLS; do wait_dev "$(zvol_dev "$POOL/$v")"; done

# Fill each volume with a distinct deterministic stream (sparse one only
# partially), then the large-dnode filesystem with xattr-heavy files.
fill() { # fill VOL BYTES OFFSET_MIB  (dd seek= counts bs-sized blocks on GNU and BSD alike)
    stream "$1@$3" "$2" | dd of="$(zvol_dev "$POOL/$1")" bs=1M seek="$3" conv=notrunc status=none
}
say "initial fill"
for v in $VOLS; do
    case $v in
        vm/disk-sparse) fill "$v" 8388608 0; fill "$v" 8388608 128 ;;
        *) fill "$v" 33554432 0 ;;
    esac
done
i=0; while [ $i -lt 400 ]; do
    stream "file$i" $((1024 + i * 37)) > "/$POOL/fs-largednode/f$i"
    xv=$(stream "xattr$i" 300 | od -An -tx1 | tr -d ' \n')
    case $os in
        Linux) setfattr -n user.golden -v "$xv" "/$POOL/fs-largednode/f$i" 2>/dev/null || true ;;
        FreeBSD) setextattr user golden "$xv" "/$POOL/fs-largednode/f$i" 2>/dev/null || true ;;
    esac
    i=$((i+1))
done
txg_sync

# ---------------------------------------------------------------- history
# Hundreds of TXGs: small writes to every volume between snapshots, so
# older TXGs point at data since overwritten and the uberblock rings fill.
say "history (this takes a while)"
record_volume_hashes() { # record TAG
    for v in $VOLS; do
        dev=$(zvol_dev "$POOL/$v")
        [ -e "$dev" ] || continue
        printf '%s  %s@%s\n' "$(sha "$dev")" "$POOL/$v" "$1" >> "$OUT/oracle/volumes.sha256"
    done
}
round=0
while [ $round -lt 12 ]; do
    step=0
    while [ $step -lt 8 ]; do
        for v in $VOLS; do
            off=$(( (round * 8 + step) * 3 % 32 ))   # MiB, spread over the first 32 MiB
            fill "$v" 262144 "$off"
        done
        txg_sync
        step=$((step+1))
    done
    snap="s$round"
    zfs snapshot -r "$POOL@$snap"
    txg_sync
    for v in $VOLS; do wait_dev "$(zvol_dev "$POOL/$v@$snap")" 2>/dev/null || true; done
    for v in $VOLS; do
        dev=$(zvol_dev "$POOL/$v@$snap")
        [ -e "$dev" ] && printf '%s  %s@%s\n' "$(sha "$dev")" "$POOL/$v" "$snap" >> "$OUT/oracle/volumes.sha256"
    done
    case $round in
        6) # a consistent copy of every member right after this round's sync:
           # the "older copy of itself" material for the damage manifests
           mkdir -p "$OUT/members-round6"
           for m in $ALL; do cp "$OUT/members/$m.img" "$OUT/members-round6/$m.img"; done ;;
    esac
    case $round in
        3) zfs clone "$POOL/vm/disk-16k@s3" "$POOL/vm/clone-of-16k"; VOLS="$VOLS vm/clone-of-16k"; wait_dev "$(zvol_dev "$POOL/vm/clone-of-16k")" ;;
        6) zfs rename "$POOL/vm/oldname" "$POOL/vm/newname"; VOLS=$(echo "$VOLS" | sed 's#vm/oldname#vm/newname#') ;;
        9) zfs destroy "$POOL/vm/doomed@s2"; zfs destroy -r "$POOL/vm/doomed"; VOLS=$(echo "$VOLS" | sed 's#vm/doomed##') ;;
    esac
    txg_sync
    round=$((round+1))
done
tunable metaslab_force_ganging 16777216 metaslab.force_ganging

# ---------------------------------------------------------------- oracle
say "oracle"
record_volume_hashes export
zpool status -v "$POOL" > "$OUT/oracle/zpool-status.txt"
zfs list -t all -o name,type,guid,creation,used,refer,volsize,volblocksize,checksum,compression,encryption,keyformat -H "$POOL" > "$OUT/oracle/zfs-list.txt"
zfs get -r -H -o name,property,value all "$POOL" > "$OUT/oracle/zfs-get-all.txt"
zdb -d "$POOL" > "$OUT/oracle/datasets.txt"
zdb -dddd "$POOL" > "$OUT/oracle/zdb-dddd.txt" 2>&1 || true
zdb -C "$POOL" > "$OUT/oracle/zdb-C.txt"
zdb -u "$POOL" > "$OUT/oracle/zdb-u.txt" 2>&1 || true
zpool get -H -o property,value all "$POOL" > "$OUT/oracle/zpool-get-all.txt"
zdb -C "$POOL" | grep -E "^\s*(txg|version|pool_guid|ashift):" | head -20 > "$OUT/oracle/pool-facts.txt" || true

say "export"
zfs unmount -a 2>/dev/null || true
zpool export "$POOL"

# Per-member labels and per-TXG dataset lists come from the exported files.
for m in $ALL; do zdb -l "$OUT/members/$m.img" > "$OUT/oracle/labels/$m.txt" 2>&1 || true; done
zdb -e -p "$OUT/members" -d "$POOL" > "$OUT/oracle/datasets-exported.txt" 2>&1 || true
# every uberblock TXG still readable: try the newest 128 (the ring depth)
newest=$(zdb -e -p "$OUT/members" -u "$POOL" 2>/dev/null | awk '/txg = /{print $3}' | sort -n | tail -1)
if [ -n "$newest" ]; then
    t=$newest; n=0
    while [ $n -lt 128 ] && [ "$t" -gt 0 ]; do
        if zdb -e -p "$OUT/members" -t "$t" -d "$POOL" > "$OUT/oracle/datasets-by-txg/$t.txt" 2>/dev/null; then :; else rm -f "$OUT/oracle/datasets-by-txg/$t.txt"; fi
        t=$((t-1)); n=$((n+1))
    done
fi

# layout.json: the machine-readable form of the topology
{
    echo "{"
    echo "  \"pool\": \"$POOL\", \"ashift\": 12, \"member_size\": \"$MEMBER_SIZE\", \"image_tag\": \"$TAG\","
    echo "  \"tops\": ["
    echo "    {\"kind\": \"mirror\", \"members\": [\"mirror-0a\", \"mirror-0b\"]},"
    echo "    {\"kind\": \"raidz2\", \"nparity\": 2, \"members\": [\"raidz2-0\", \"raidz2-1\", \"raidz2-2\", \"raidz2-3\"]},"
    echo "    {\"kind\": \"draid1\", \"nparity\": 1, \"ndata\": 2, \"nspares\": 1, \"members\": [\"draid1-0\", \"draid1-1\", \"draid1-2\", \"draid1-3\"]}"
    echo "  ],"
    echo "  \"member_guids\": {"
    first=1
    for m in $ALL; do
        g=$(awk '/^\s*guid:/{print $2; exit}' "$OUT/oracle/labels/$m.txt")
        [ $first = 1 ] || echo ","
        first=0
        printf '    "%s": "%s"' "$m" "$g"
    done
    echo
    echo "  }"
    echo "}"
} > "$OUT/oracle/layout.json"

# ---------------------------------------------------------------- release
say "release files"
for m in $ALL; do zstd -T0 -19 -q -f "$OUT/members/$m.img" -o "$OUT/release/$m.img.zst"; done
for m in $ALL; do zstd -T0 -19 -q -f "$OUT/members-round6/$m.img" -o "$OUT/release/round6-$m.img.zst"; done
( cd "$OUT/release" && for f in *.zst; do printf '%s  %s\n' "$(sha "$f")" "$f"; done > SHA256SUMS )
( cd "$OUT/members" && for f in *.img; do printf '%s  %s\n' "$(sha "$f")" "$f"; done > "$OUT/oracle/members.sha256" )

# ---------------------------------------------------------------- IMAGE.md
{
    echo "# The golden image ($TAG)"
    echo
    echo "Built $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(uname -srm) with $(zpool version 2>/dev/null | head -1)."
    echo
    echo "## Layout"
    echo
    echo "One pool \`$POOL\`, ashift 12, three top-level vdevs on $MEMBER_SIZE file members:"
    echo
    echo "| Top-level vdev | Members |"; echo "|---|---|"
    echo "| mirror-0 | $M_MIRROR |"; echo "| raidz2-1 | $M_RAIDZ |"; echo "| draid1:2d:4c:1s-2 | $M_DRAID |"
    echo
    echo "## Datasets"
    echo; echo '```'; cat "$OUT/oracle/zfs-list.txt"; echo '```'
    echo
    echo "## History"
    echo
    echo "12 rounds of 8 TXGs with 256 KiB writes to every volume, a recursive snapshot \`s<round>\` after each round; clone of \`vm/disk-16k@s3\` at round 3; \`vm/oldname\` renamed to \`vm/newname\` at round 6; \`vm/doomed@s2\` then \`vm/doomed\` destroyed at round 9. Gang blocks forced (threshold 16 KiB) during the fill. Deterministic content from seed \`$SEED\`. The \`round6-*\` release files are a consistent copy of every member taken right after round 6 (the \`older-self:image-v1-round6\` pattern of the damage manifests)."
    echo
    echo "## Oracle"
    echo
    echo "See \`oracle/\`: \`volumes.sha256\` (every volume at every snapshot and at export), \`datasets*.txt\`, \`datasets-by-txg/\`, \`labels/\`, \`zdb-*.txt\`, \`zpool-status.txt\`, \`keys/\`, \`layout.json\`, \`members.sha256\` (uncompressed members)."
    echo
    echo "## Release files"
    echo; echo '```'; cat "$OUT/release/SHA256SUMS"; echo '```'
} > "$OUT/IMAGE.md"

say "done: $OUT/release, $OUT/oracle, $OUT/IMAGE.md"
