#!/bin/sh
# Build the golden pool image (SPEC §9.1, REALWORLD-TESTS scenario G1).
#
# Runs on a host with a real OpenZFS kernel module, as root, in a scratch
# directory: Linux for the whole of it; FreeBSD 14/15 builds the pool and
# the zdb captures, and leaves out what this script does through Linux
# alone (device nodes, the kernel's reading of the files). It creates one
# pool on file-backed members with three top-level vdevs (mirror, raidz2,
# draid1), fills it with every kind of metadata zvolrescue must read,
# drives hundreds of TXGs, records the oracle, exports the pool and
# packages the members for a release of zvolrescue-testdata.
#
#   sh tests/golden/build-image.sh OUT [TAG [MANIFESTS]]
#
# TAG is the image's tag (default golden-v2). With MANIFESTS, a directory
# of damage manifests, only the older copies (`round6-*`) those manifests
# name are packaged — `run-matrix.py --print-needs` says which — so that
# the release carries no copy that no case reads.
#
# Output: OUT/release/ (zstd-compressed members + SHA256SUMS), OUT/oracle/
# (hashes, zdb captures, labels and their uberblock rings, the kernel's
# reading of every file, the pool's history, keys, layout.json) and
# OUT/IMAGE.md. Nothing here is ever produced by zvolrescue itself: the
# oracle comes from OpenZFS only — zdb, the kernel through the VFS, and
# sha256 of what the kernel's zvols give.
#
# The recipe is golden-v2's: image-v1's (this file's history up to
# 5954015 has it) with, besides, a filesystem holding a tree of every kind
# of entry, a filesystem destroyed, a clone promoted, rollbacks, a
# snapshot destroyed, volumes of volblocksize 128K, of copies=2, of
# checksum=off and of zstd-fast, cloned blocks, the volumes' content
# compressible where their compression is on, the hash of a volume taken
# just before it is destroyed, and the whole oracle captured here rather
# than by oracle-capture.yml afterwards.
#
# Deterministic content: every write is a keystream from a fixed seed, so a
# rebuild in the same environment yields the same volume hashes (block
# placement and TXG numbers may differ, and that is fine: the oracle is
# captured from whatever this run produced).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?output directory}
TAG=${2:-golden-v2}
MANIFESTS=${3:-}
[ -z "$MANIFESTS" ] || MANIFESTS=$(cd "$MANIFESTS" && pwd)
POOL=golden
MEMBER_SIZE=512M
SEED=zvolrescue-golden-2026
PASSPHRASE="golden passphrase for tests"
# shellcheck source=tests/golden/lib-build.sh
. "$HERE/lib-build.sh"

# ---------------------------------------------------------------- members
say "members"
M_MIRROR="mirror-0a mirror-0b"
M_RAIDZ="raidz2-0 raidz2-1 raidz2-2 raidz2-3"
M_DRAID="draid1-0 draid1-1 draid1-2 draid1-3"
ALL="$M_MIRROR $M_RAIDZ $M_DRAID"
for m in $ALL; do truncate -s "$MEMBER_SIZE" "$OUT/members/$m.img"; done

# Cloned blocks (`cp --reflink`, FICLONE): off by default in some
# releases, and refused while the source has dirty data unless told to
# wait for it.
tunable zfs_bclone_enabled 1 bclone_enabled
tunable zfs_bclone_wait_dirty 1 bclone_wait_dirty

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
# golden-v2: the largest volblocksize a volume takes by default, two
# copies of every block, no checksum at all, and zstd's fast levels
zfs create -V 48M -b 128K -o checksum=sha256    -o compression=lz4  "$POOL/vm/disk-128k"
zfs create -V 48M -b 16K  -o checksum=fletcher4 -o compression=lz4 -o copies=2 "$POOL/vm/disk-copies2"
zfs create -V 48M -b 16K  -o checksum=off       -o compression=off  "$POOL/vm/disk-nocsum"
zfs create -V 48M -b 16K  -o checksum=sha256    -o compression=zstd-fast "$POOL/vm/disk-zstdfast"
# encrypted: raw key and passphrase
zfs create -o encryption=aes-256-gcm -o keyformat=raw -o keylocation="file://$OUT/oracle/keys/raw.key" "$POOL/secret-raw"
zfs create -V 48M -b 16K -o checksum=sha256 -o compression=lz4 "$POOL/secret-raw/disk"
zfs create -o encryption=aes-128-ccm -o keyformat=passphrase -o keylocation="file://$OUT/oracle/keys/passphrase.txt" "$POOL/secret-pw"
zfs create -V 48M -b 8K -o checksum=skein -o compression=zstd "$POOL/secret-pw/disk"
# a volume that will be destroyed, and one that will be renamed
zfs create -V 32M -b 16K -o checksum=sha256 "$POOL/vm/doomed"
zfs create -V 32M -b 16K -o checksum=fletcher4 "$POOL/vm/oldname"
# golden-v2: a filesystem of every kind of entry, with names that only
# compare equal under its normalization; legacy dnodes and attributes in
# the system-attribute area, so that a few attributes spill out of the
# dnode into a block of their own. A filesystem whose clone is promoted
# over it, and one that is destroyed.
zfs create -o casesensitivity=mixed -o normalization=formD -o xattr=sa -o dnodesize=legacy "$POOL/fs-tree"
zfs create "$POOL/fs-base"
zfs create "$POOL/fs-doomed"
txg_sync

VOLS="vm/disk-8k vm/disk-16k vm/disk-64k vm/disk-skein vm/disk-edonr vm/disk-blake3 vm/disk-sparse vm/disk-128k vm/disk-copies2 vm/disk-nocsum vm/disk-zstdfast secret-raw/disk secret-pw/disk vm/doomed vm/oldname"
for v in $VOLS; do wait_dev "$(zvol_dev "$POOL/$v")"; done

# What each volume is written with: compressible where its compression
# is on (and on the clone, as on its origin), the stream where it is off
# and where image-v1's recipe had it.
kind_of() {
    case $1 in
        vm/disk-8k|vm/disk-16k|vm/disk-64k|vm/disk-skein|vm/disk-zstdfast|vm/clone-of-16k|secret-raw/disk|secret-pw/disk) echo text ;;
        vm/disk-edonr) echo holey ;;
        *) echo stream ;;
    esac
}
# fill VOL BYTES OFFSET_MIB  (dd seek= counts bs-sized blocks on GNU and BSD alike)
fill() {
    "$(kind_of "$1")" "$1@$3" "$2" | dd of="$(zvol_dev "$POOL/$1")" bs=1M seek="$3" conv=notrunc status=none
}

# ---------------------------------------------------------------- the tree
# Written before gang blocks are forced: a gang block is not cloned.
say "the tree"
T=/$POOL/fs-tree
mkdir -p "$T/deep" "$T/docs" "$T/links" "$T/sparse" "$T/empty" "$T/special" "$T/attrs" "$T/names" "$T/wide" "$T/big"
# Nine levels of directories, a few files at each.
d=$T/deep
for level in a b c d e f g h i; do
    d=$d/$level; mkdir -p "$d"
    i=0; while [ $i -lt 5 ]; do stream "tree:$level:$i" $((60 + i * 997)) > "$d/f$i"; i=$((i+1)); done
done
# Text of every size from a few bytes to several records.
i=0; while [ $i -lt 40 ]; do text "doc$i" $((i * i * 211 + 17)) > "$T/docs/doc$i.txt"; i=$((i+1)); done
# A directory whose names are longer than a micro-ZAP holds: a fat ZAP
# with leaves of its own.
i=0; while [ $i -lt 300 ]; do
    n=$(printf 'entry-%04d-%s' $i "$(printf 'wide%s' $i | openssl dgst -sha256 | awk '{print substr($NF, 1, 48)}')")
    stream "wide$i" $((i % 7 * 50)) > "$T/wide/$n"
    i=$((i+1))
done
# Names: three that differ in case alone (a mixed-sensitivity filesystem
# keeps them apart), one written composed and then decomposed (the same
# name under formD: the second write lands in the first file), Cyrillic,
# and one of the longest a name can be.
printf 'lower\n' > "$T/names/readme"
printf 'title\n' > "$T/names/Readme"
printf 'upper\n' > "$T/names/README"
printf 'composed\n' > "$T/names/$(printf 'caf\303\251')"
printf 'decomposed\n' >> "$T/names/$(printf 'cafe\314\201')"
printf 'cyrillic\n' > "$T/names/$(printf '\320\277\321\200\320\270\320\262\321\226\321\202')"
printf 'long\n' > "$T/names/$(head -c 255 /dev/zero | tr '\0' n)"
# Hard links within a directory and across directories, symbolic links
# short, long (a target past what the dnode holds), to a directory and to
# nothing.
ln "$T/docs/doc1.txt" "$T/links/hard-1"
ln "$T/docs/doc1.txt" "$T/deep/a/hard-2"
ln "$T/docs/doc2.txt" "$T/links/hard-3"
ln -s ../docs/doc1.txt "$T/links/short"
ln -s "$(head -c 1000 /dev/zero | tr '\0' x | fold -w 100 | paste -sd/ -)" "$T/links/long"
ln -s ../deep "$T/links/to-dir"
ln -s nowhere "$T/links/dangling"
# Sparse: data at the start, at 300 MiB and at 1000 MiB of an 1100 MiB
# file, so that whole indirect blocks are holes; and one that is nothing
# but a hole.
stream sparse-a 131072 | dd of="$T/sparse/huge" bs=128K seek=0 conv=notrunc status=none
stream sparse-b 131072 | dd of="$T/sparse/huge" bs=128K seek=2400 conv=notrunc status=none
stream sparse-c 131072 | dd of="$T/sparse/huge" bs=128K seek=8000 conv=notrunc status=none
truncate -s 1100M "$T/sparse/huge"
truncate -s 64M "$T/sparse/all-hole"
# 4 KiB records, 1536 of them: two level-1 blocks under a level-2 block.
zfs set recordsize=4K "$POOL/fs-tree"
stream records4k 6291456 > "$T/big/records-4k"
zfs set recordsize=128K "$POOL/fs-tree"
stream blob 8388608 > "$T/big/blob"
# Attributes: of a few hundred bytes to a few KiB, more than a legacy
# dnode's bonus holds, so they spill into a block of their own; one past
# what the attribute area takes, which goes to a directory of attributes;
# one on a directory.
i=0; while [ $i -lt 12 ]; do
    f=$T/attrs/a$i
    stream "attr-file$i" 300 > "$f"
    stream "attr$i" $((200 + i * 300)) | xattr_set "$f" big
    stream "attr-small$i" 64 | xattr_set "$f" small
    i=$((i+1))
done
stream attr-huge 40000 | xattr_set "$T/attrs/a0" huge
stream attr-dir 100 | xattr_set "$T/attrs" on-a-directory
# Owners, modes and times out of the ordinary; an empty file, an empty
# directory, a FIFO and two device nodes.
chown 1000:1000 "$T/docs/doc3.txt"
chown 65534:65534 "$T/deep/a/f0"
chmod 0600 "$T/docs/doc4.txt"
chmod 4755 "$T/docs/doc5.txt"
chmod 1777 "$T/empty"
touch -t 199912312359.59 "$T/docs/doc6.txt"
touch -h -t 200102030405.06 "$T/links/short"
: > "$T/docs/empty.txt"
mkfifo "$T/special/fifo"
case $os in
    Linux) mknod "$T/special/null" c 1 3; mknod "$T/special/loop0" b 7 0 ;;
esac
# The filesystem whose clone is promoted, and the one destroyed.
i=0; while [ $i -lt 30 ]; do stream "base$i" $((1000 + i * 4099)) > "/$POOL/fs-base/b$i"; i=$((i+1)); done
i=0; while [ $i -lt 20 ]; do text "doomed-file$i" $((500 + i * 3001)) > "/$POOL/fs-doomed/d$i"; i=$((i+1)); done
# Cloned blocks: within a dataset, and across two.
txg_sync
clone_file "$T/big/blob" "$T/big/blob.clone"
clone_file "$T/big/records-4k" "$T/big/records-4k.clone"
clone_across "$T/big/blob" "/$POOL/fs-base/blob.clone"
txg_sync
[ "$(zpool get -H -o value feature@block_cloning "$POOL")" = active ] || die "feature@block_cloning is not active after cloning"

# Gang blocks: force them for allocations above a small size while the
# pool is being filled (Linux metaslab_force_ganging, FreeBSD
# vfs.zfs.metaslab.force_ganging).
tunable metaslab_force_ganging 16384 metaslab.force_ganging

# Fill each volume with a distinct deterministic stream (sparse one only
# partially), then the large-dnode filesystem with xattr-heavy files.
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
    record_snapshot_hashes "$snap"
    case $round in
        6) # a consistent copy of every member right after this round's sync:
           # the "older copy of itself" material for the damage manifests
           mkdir -p "$OUT/members-round6"
           for m in $ALL; do cp "$OUT/members/$m.img" "$OUT/members-round6/$m.img"; done ;;
    esac
    case $round in
        1) # a clone of a filesystem, written to, promoted at round 4
           zfs clone "$POOL/fs-base@s1" "$POOL/fs-promoted"
           i=0; while [ $i -lt 10 ]; do stream "promoted$i" $((2000 + i * 5003)) > "/$POOL/fs-promoted/p$i"; i=$((i+1)); done
           text base-after-clone 7000 > "/$POOL/fs-base/b0" ;;
        2) # the tree: a file grown, one added
           text doc7-append 5000 >> "$T/docs/doc7.txt"
           text new-in-2 3000 > "$T/docs/new-in-2.txt" ;;
        3) zfs clone "$POOL/vm/disk-16k@s3" "$POOL/vm/clone-of-16k"; VOLS="$VOLS vm/clone-of-16k"; wait_dev "$(zvol_dev "$POOL/vm/clone-of-16k")" ;;
        4) zfs promote "$POOL/fs-promoted" ;;
        5) # the tree: a directory removed with its files, a hard link undone
           rm -r "$T/deep/a/b/c/d/e/f/g/h/i"
           rm "$T/links/hard-3" ;;
        6) zfs rename "$POOL/vm/oldname" "$POOL/vm/newname"; VOLS=$(echo "$VOLS" | sed 's#vm/oldname#vm/newname#') ;;
        7) # a snapshot destroyed from the middle of a volume's chain
           zfs destroy "$POOL/vm/disk-64k@s5" ;;
        8) # rollbacks: what was written after s8 is thrown away again
           fill vm/disk-8k 1048576 40
           text rolled-back 20000 > "$T/rolled-back.txt"
           txg_sync
           retry zfs rollback "$POOL/vm/disk-8k@s8"
           retry zfs rollback "$POOL/fs-tree@s8"
           wait_dev "$(zvol_dev "$POOL/vm/disk-8k")" ;;
        9) before_destroy vm/doomed
           zfs destroy "$POOL/vm/doomed@s2"; zfs destroy -r "$POOL/vm/doomed"; VOLS=$(echo "$VOLS" | sed 's#vm/doomed##') ;;
        10) # the tree: part of a 4K-record file rewritten (its clone keeps
            # the old blocks), a file moved; a filesystem destroyed
            stream records4k-r10 65536 | dd of="$T/big/records-4k" bs=4K seek=700 conv=notrunc status=none
            mv "$T/docs/doc8.txt" "$T/deep/a/doc8-moved.txt"
            before_destroy fs-doomed
            zfs destroy -r "$POOL/fs-doomed" ;;
    esac
    txg_sync
    round=$((round+1))
done
tunable metaslab_force_ganging 16777217 metaslab.force_ganging

# ---------------------------------------------------------------- oracle
say "oracle"
record_volume_hashes export
oracle_imported
oracle_exported

# layout.json: the topology as zdb reports it, in the shape the damage
# matrix reads (zdb-layout.py, shared with the ztest image): every member
# a role `t<top>-<kind>-<i>`, every top-level vdev with its groups, and
# `volumes` set, so runs against this image are judged by volume hashes.
python3 "$HERE/zdb-layout.py" --pool "$POOL" --tag "$TAG" --source kernel --volumes \
    < "$OUT/oracle/zdb-C.txt" > "$OUT/oracle/layout.json"

# ---------------------------------------------------------------- release
say "release files"
# The older copies the manifests name, or all of them without manifests.
if [ -n "$MANIFESTS" ]; then
    python3 "$HERE/run-matrix.py" --print-needs --held-out --oracle "$OUT/oracle" --manifests "$MANIFESTS" > "$OUT/needs.txt"
fi
keep_round6() { # keep_round6 MEMBER
    [ -z "$MANIFESTS" ] || grep -qx "round6-$1.img.zst" "$OUT/needs.txt"
}
release_members
for m in $ALL; do
    if keep_round6 "$m"; then zstd -T0 -19 -q -f "$OUT/members-round6/$m.img" -o "$OUT/release/round6-$m.img.zst"; fi
done
release_sums
round6=$(cd "$OUT/release" && ls round6-*.zst 2>/dev/null | sed 's/^round6-//; s/\.img\.zst$//' | tr '\n' ' ' | sed 's/ $//')

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
    echo "## What is in it"
    echo
    echo "* Volumes over every checksum and compression, of volblocksize 8K to 128K, one sparse, one of \`copies=2\`, one of \`checksum=off\`, two encrypted (a raw key and a passphrase). Where a volume's compression is on, it is written with content that compression shrinks — the hex dump of a keystream, every line twice; for \`zle\`, the keystream with every other 2 KiB zeroed — and with the keystream itself where it is off."
    echo "* \`fs-largednode\`: 400 files with an extended attribute each, large dnodes."
    echo "* \`fs-tree\`, \`casesensitivity=mixed\`, \`normalization=formD\`, \`xattr=sa\`, legacy dnodes: nine levels of directories, a fat-ZAP directory of 300 long names, names differing in case alone, a name written composed and decomposed (one file under formD), a Cyrillic name, a name of 255 bytes, hard links in one directory and across two, symbolic links short, of 1009 bytes, to a directory and to nothing, a sparse file of 1100 MiB with three records of data, a file that is all hole, a file of 1536 records of 4 KiB (two level-1 blocks under a level-2 block), attributes that spill out of the dnode, one in a directory of attributes, one on a directory, unusual owners and modes, a FIFO and two device nodes; and cloned blocks (\`cp --reflink\`), within the dataset and into \`fs-base\`."
    echo "* \`fs-base\` and \`fs-promoted\`: a clone of \`fs-base@s1\`, written to, promoted at round 4."
    echo
    echo "## History"
    echo
    echo "12 rounds of 8 TXGs with 256 KiB writes to every volume, a recursive snapshot \`s<round>\` after each round. After round 1, \`fs-base@s1\` cloned to \`fs-promoted\`; 2, a file of the tree grown and one added; 3, \`vm/disk-16k@s3\` cloned to \`vm/clone-of-16k\`; 4, \`fs-promoted\` promoted; 5, a directory of the tree removed with its files and a hard link undone; 6, \`vm/oldname\` renamed to \`vm/newname\`; 7, \`vm/disk-64k@s5\` destroyed; 8, \`vm/disk-8k\` and \`fs-tree\` written to and rolled back to \`s8\`; 9, \`vm/doomed@s2\` then \`vm/doomed\` destroyed, its bytes hashed just before (\`vm/doomed@destroyed\` in \`volumes.sha256\`); 10, 64 KiB of the 4K-record file rewritten, a file of the tree moved, \`fs-doomed\` destroyed. Gang blocks forced (threshold 16 KiB) from the volumes' first fill to the end of the history; the tree was written before. Deterministic content from seed \`$SEED\`. The \`round6-*\` release files are a consistent copy of members taken right after round 6 (the \`older-self:round6\` pattern of the damage manifests): ${round6:-none}."
    echo
    echo "## Oracle"
    echo
    echo "See \`oracle/\`: \`volumes.sha256\` (every volume at every snapshot, at export, and just before it was destroyed), \`zfs-get-destroyed.txt\` (the properties of what was destroyed, just before), \`datasets*.txt\`, \`datasets-by-txg/\`, \`labels/\`, \`labels-uberblocks/\`, \`zdb-u-export.txt\`, \`zdb-*.txt\` and \`zdb-dddddd/\` (offline, over the exported members; the last one file a dataset), \`files.json\`, \`zpool-history-il.txt\` and \`files-capture.txt\` (the kernel, read-only), \`zpool-status.txt\`, \`keys/\`, \`layout.json\`, \`members.sha256\` and \`members-round6.sha256\` (uncompressed)."
    echo
    echo "## Release files"
    echo; echo '```'; cat "$OUT/release/SHA256SUMS"; echo '```'
} > "$OUT/IMAGE.md"

say "done: $OUT/release, $OUT/oracle, $OUT/IMAGE.md"
