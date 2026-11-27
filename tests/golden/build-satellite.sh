#!/bin/sh
# Build a satellite of the golden image (zvolrescue-testdata ROADMAP,
# stage 2): a small pool on file-backed members made for one pool-level
# feature that the golden pool does not have, with the same oracle the
# golden image's builder records — every capture from OpenZFS, nothing
# from zvolrescue.
#
#   sh tests/golden/build-satellite.sh OUT NAME [TAG]
#
# NAME is one of the recipes below; the pool is `sat-NAME`, the tag
# `sat-NAME-v1` unless TAG says otherwise. Runs where build-image.sh
# runs (Linux with the OpenZFS kernel module, as root). Output as
# build-image.sh's: OUT/release/ (zstd-compressed members + SHA256SUMS),
# OUT/oracle/ and OUT/IMAGE.md; no older copies — no manifest of a
# satellite uses one.
#
#   removal     three mirrors, the middle one removed: the indirect vdev
#   checkpoint  a pool checkpoint, a volume destroyed after it
#   spare       raidz2 with a hot spare at work and a replacing that did not finish
#   expand      raidz1 expanded from three disks to four
#   special     special and dedup vdevs
#   ashift      raidz1 at ashift 9 beside raidz1 at ashift 13
#   slog        a separate intent log, with records the pool never applied
#   mmp         multihost=on: the uberblocks of its heartbeat
#   compat20    the feature set of OpenZFS 2.0 (compatibility=openzfs-2.0-linux)
#   nofeatures  a pool of version 5000 with every feature disabled (-d)
#   v28         a pool of version 28, before feature flags
#   freebsd     made on FreeBSD with its base OpenZFS, on GPT partitions
#               as its installer lays them out (run on FreeBSD)
#   scale       a pool of thousands of datasets, held out of regular runs
#   large       a volume of 10 GiB of content ZFS compresses, held out
#
# Every satellite holds the same few datasets — a volume of 8K blocks
# with content lz4 shrinks, one of 16K blocks of the keystream, a
# filesystem of small files — written over four rounds of TXGs with a
# recursive snapshot after each, and the recipe's feature put in between.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?output directory}
NAME=${2:?satellite name}
TAG=${3:-sat-$NAME-v1}
POOL=sat-$NAME
SEED=zvolrescue-$POOL-2026
ASHIFT=12
CREATE_OPTS=""
# lz4 is a feature (org.illumos:lz4_compress): a pool without features
# compresses with lzjb.
COMPRESSION=lz4
HISTORY_NOTE=""
# shellcheck source=tests/golden/lib-build.sh
. "$HERE/lib-build.sh"

# Members of 256 MiB and sparse volumes: OpenZFS holds back up to 128 MiB
# of a pool's space (its slop), which of a mirror of 128 MiB is half, and
# a volume that is not sparse reserves the whole of its size besides.
make_members() { # make_members SIZE NAME...
    size=$1; shift
    for m in "$@"; do truncate -s "$size" "$OUT/members/$m.img"; done
}
create() { # create VDEV-SPEC...: the pool, every satellite alike
    # shellcheck disable=SC2086
    zpool create -f -o ashift=$ASHIFT -o autotrim=off $CREATE_OPTS -O compression=$COMPRESSION -O snapdev=visible \
        "$POOL" "$@"
}

common_datasets() {
    zfs create "$POOL/vm"
    zfs create -s -V 24M -b 8K  -o checksum=fletcher4 -o compression=$COMPRESSION "$POOL/vm/disk-8k"
    zfs create -s -V 24M -b 16K -o checksum=sha256    -o compression=off "$POOL/vm/disk-16k"
    zfs create "$POOL/fs"
    VOLS="vm/disk-8k vm/disk-16k"
}
wait_vols() { for v in $VOLS; do wait_dev "$(zvol_dev "$POOL/$v")"; done; }

kind_of() {
    case $1 in
        vm/disk-8k|vm/disk-small|vm/disk-sync) echo text ;;
        *) echo stream ;;
    esac
}
# fill VOL BYTES OFFSET_MIB: a dedup volume is written the same bytes at
# every offset, so that its blocks are the same blocks.
fill() {
    case $1 in
        vm/disk-dedup) stream dedup "$2" ;;
        *) "$(kind_of "$1")" "$1@$3" "$2" ;;
    esac | dd of="$(zvol_dev "$POOL/$1")" bs=1M seek="$3" conv=notrunc status=none
}
initial_fill() {
    say "initial fill"
    wait_vols
    for v in $VOLS; do fill "$v" 16777216 0; done
    mkdir -p "/$POOL/fs/dir/sub"
    i=0; while [ $i -lt 20 ]; do
        text "file$i" $((100 + i * i * 401)) > "/$POOL/fs/f$i.txt"
        stream "bin$i" $((512 + i * 2048)) > "/$POOL/fs/dir/b$i"
        i=$((i+1))
    done
    ln -s ../f1.txt "/$POOL/fs/dir/sub/link"
    ln "/$POOL/fs/f2.txt" "/$POOL/fs/dir/hard"
    txg_sync
}
at_round() { :; }    # a recipe's feature, after round N's snapshot
# rounds FROM TO: 4 TXGs of 256 KiB writes to every volume and a file
# each, then a recursive snapshot `s<round>` and its volumes' hashes.
rounds() {
    r=$1
    while [ "$r" -le "$2" ]; do
        step=0
        while [ $step -lt 4 ]; do
            for v in $VOLS; do fill "$v" 262144 $(( (r * 4 + step) * 3 % 16 )); done
            text "round$r-$step" $((3000 + step * 1500)) > "/$POOL/fs/r$r-$step.txt"
            txg_sync
            step=$((step+1))
        done
        zfs snapshot -r "$POOL@s$r"
        txg_sync
        record_snapshot_hashes "s$r"
        at_round "$r"
        txg_sync
        r=$((r+1))
    done
}
feature_active() { # feature_active NAME: or the build is not the satellite it says
    [ "$(zpool get -H -o value "feature@$1" "$POOL")" = active ] || die "feature@$1 is not active"
}

# ---------------------------------------------------------------- recipes
recipe_removal() {
    DESCRIPTION="Three two-way mirrors, the middle one removed after round 1: what it held copied onto the other two and found through the mapping the removal leaves (\`com.delphix:device_removal\`, the indirect vdev \`indirect-1\`), the snapshots of rounds 0 and 1 read through it. The removed disks are no members of the pool any more, and not in the release."
    ALL="mirror-0a mirror-0b mirror-1a mirror-1b mirror-2a mirror-2b"
    make_members 256M $ALL
    create mirror $(paths mirror-0a mirror-0b) mirror $(paths mirror-1a mirror-1b) mirror $(paths mirror-2a mirror-2b)
    common_datasets; initial_fill
    at_round() {
        [ "$1" = 1 ] || return 0
        say "mirror-1 removed"
        zpool remove "$POOL" mirror-1
        zpool wait -t remove "$POOL"
        zpool status "$POOL" | grep -q 'mirror-1' && die "mirror-1 is still in the pool"
        feature_active device_removal
        rm -f "$OUT/members/mirror-1a.img" "$OUT/members/mirror-1b.img"
        ALL="mirror-0a mirror-0b mirror-2a mirror-2b"
    }
    HISTORY_NOTE="After round 1, \`mirror-1\` removed (\`zpool remove\`, waited for)."
    rounds 0 3
}

recipe_checkpoint() {
    DESCRIPTION="One raidz1, checkpointed after round 1 (\`zpool checkpoint\`) and exported with the checkpoint in place: the volume \`vm/precious\` destroyed right after it, and rounds 2 and 3 written over the others. What the pool held at the checkpoint is every volume's \`@checkpoint\` hash in \`volumes.sha256\`, \`vm/precious\`'s among them; its TXG is \`checkpoint_txg\` in \`zdb-u-export.txt\`."
    ALL="raidz1-0 raidz1-1 raidz1-2"
    make_members 256M $ALL
    create raidz1 $(paths $ALL)
    common_datasets
    zfs create -s -V 16M -b 16K -o checksum=sha256 -o compression=lz4 "$POOL/vm/precious"
    VOLS="$VOLS vm/precious"
    initial_fill
    at_round() {
        [ "$1" = 1 ] || return 0
        say "checkpoint"
        record_volume_hashes checkpoint
        zpool checkpoint "$POOL"
        before_destroy vm/precious
        zfs destroy -r "$POOL/vm/precious"
        VOLS="vm/disk-8k vm/disk-16k"
        rm "/$POOL/fs/f3.txt" "/$POOL/fs/dir/b4"
        feature_active zpool_checkpoint
    }
    after_export() {
        zdbe -k -d "$POOL" > "$OUT/oracle/datasets-checkpoint.txt" 2>&1 || true
    }
    HISTORY_NOTE="After round 1, every volume hashed (\`@checkpoint\`), the pool checkpointed, \`vm/precious\` hashed again (\`@destroyed\`) and destroyed with its snapshots, two files of \`fs\` removed. \`datasets-checkpoint.txt\` is \`zdb -e -k -d\`, the datasets of the checkpointed state."
    rounds 0 3
}

recipe_spare() {
    DESCRIPTION="One raidz2 of five disks with a hot spare: the third disk taken offline after round 0, written past for a round, and replaced by the spare after round 1 (\`spare-2\`, the spare resilvered whole, the disk left offline and stale); after round 2 the fifth disk replaced by a new one with the resilver held still (\`zfs_scan_suspend_progress\`), so that the pool is exported with \`replacing-4\` unfinished — the new disk holding only what was written after. Every device of both slots is a member (\`t0-raidz2-2.1\`, \`t0-raidz2-4.1\`)."
    ALL="raidz2-0 raidz2-1 raidz2-2 raidz2-3 raidz2-4 spare-0 new-0"
    make_members 256M $ALL
    create raidz2 $(paths raidz2-0 raidz2-1 raidz2-2 raidz2-3 raidz2-4) spare $(paths spare-0)
    common_datasets; initial_fill
    at_round() {
        case $1 in
            0) zpool offline "$POOL" "$OUT/members/raidz2-2.img" ;;
            1) zpool replace "$POOL" "$OUT/members/raidz2-2.img" "$OUT/members/spare-0.img"
               zpool wait -t resilver "$POOL" ;;
            2) tunable zfs_scan_suspend_progress 1 scan_suspend_progress
               zpool replace "$POOL" "$OUT/members/raidz2-4.img" "$OUT/members/new-0.img" ;;
        esac
    }
    HISTORY_NOTE="After round 0, \`raidz2-2\` taken offline; after round 1, replaced by \`spare-0\` and the resilver waited for; after round 2, \`raidz2-4\` replaced by \`new-0\` with the scan suspended."
    rounds 0 3
    zpool status "$POOL" | grep -q 'spare-2' || die "no spare-2 in the pool"
    zpool status "$POOL" | grep -q 'replacing-4' || die "no replacing-4 in the pool: the resilver finished"
}

recipe_expand() {
    DESCRIPTION="One raidz1 of three disks expanded to four after round 1 (\`zpool attach\`, \`org.openzfs:raidz_expansion\`), the reflow waited for: the blocks born before it keep three disks' worth of columns laid over four, those after are four wide. zvolrescue does not read such a raidz and says so (SPEC F-70): the satellite is the case that holds it to that, and the pool a reader of it would be built against."
    ALL="raidz1-0 raidz1-1 raidz1-2 raidz1-3"
    make_members 256M $ALL
    create raidz1 $(paths raidz1-0 raidz1-1 raidz1-2)
    common_datasets; initial_fill
    at_round() {
        [ "$1" = 1 ] || return 0
        say "raidz1-0 expanded"
        zpool attach "$POOL" raidz1-0 "$OUT/members/raidz1-3.img"
        zpool wait -t raidz_expand "$POOL"
        feature_active raidz_expansion
    }
    HISTORY_NOTE="After round 1, \`raidz1-3\` attached to \`raidz1-0\` and the expansion waited for."
    rounds 0 3
}

recipe_special() {
    ALL="raidz1-0 raidz1-1 raidz1-2 special-0a special-0b dedup-0a dedup-0b"
    make_members 256M raidz1-0 raidz1-1 raidz1-2
    make_members 128M special-0a special-0b dedup-0a dedup-0b
    create raidz1 $(paths raidz1-0 raidz1-1 raidz1-2) special mirror $(paths special-0a special-0b) \
        dedup mirror $(paths dedup-0a dedup-0b)
    common_datasets
    zfs set special_small_blocks=16K "$POOL/fs"
    # A volume's blocks follow special_small_blocks where this OpenZFS
    # lets a volume have it.
    if zfs create -s -V 16M -b 8K -o checksum=sha256 -o compression=lz4 -o special_small_blocks=8K "$POOL/vm/disk-small"; then
        small="\`vm/disk-small\`, all of whose 8K blocks go there too"
    else
        zfs create -s -V 16M -b 8K -o checksum=sha256 -o compression=lz4 "$POOL/vm/disk-small"
        small="\`vm/disk-small\`, of 8K blocks, which stay on the raidz: a volume takes no \`special_small_blocks\` on this OpenZFS"
    fi
    DESCRIPTION="One raidz1 with a special mirror and a dedup mirror beside it (\`org.zfsonlinux:allocation_classes\`): the metadata on the special vdev, and \`fs\`'s blocks up to 16K (\`special_small_blocks\`); $small; \`vm/disk-dedup\`, written the same 256 KiB at every offset with \`dedup=on\`, its table on the dedup vdev."
    zfs create -s -V 24M -b 16K -o checksum=sha256 -o compression=off -o dedup=on "$POOL/vm/disk-dedup"
    VOLS="$VOLS vm/disk-small vm/disk-dedup"
    initial_fill
    feature_active allocation_classes
    rounds 0 3
}

recipe_ashift() {
    DESCRIPTION="Two raidz1 of three disks side by side, the first at ashift 9 and the second at 13 — the two sector sizes the golden image does not have, and two of them in one pool, where every top-level vdev has its own."
    ALL="raidz1a9-0 raidz1a9-1 raidz1a9-2 raidz1a13-0 raidz1a13-1 raidz1a13-2"
    make_members 192M $ALL
    ASHIFT=9
    create raidz1 $(paths raidz1a9-0 raidz1a9-1 raidz1a9-2)
    zpool add -f -o ashift=13 "$POOL" raidz1 $(paths raidz1a13-0 raidz1a13-1 raidz1a13-2)
    zdb -C "$POOL" | grep -E '^\s*ashift:' | tr -d ' ' | tr '\n' ' ' | grep -q 'ashift:9 ashift:13' ||
        die "the two raidz1 are not at ashift 9 and 13: $(zdb -C "$POOL" | grep -E '^\s*ashift:' | tr '\n' ' ')"
    common_datasets; initial_fill
    rounds 0 3
}

recipe_slog() {
    DESCRIPTION="A mirror with a separate intent log (\`log-0\`): after round 2 the pool frozen (\`zpool freeze\`, what the OpenZFS test suite does to the same end) and written to synchronously — 4 MiB of \`vm/disk-sync\` and files of \`fs\`, both \`sync=always\` — so that those writes are in the intent log alone, and exported so. What the members hold is the pool at the freeze: the volumes' \`@export\` hashes are taken right before it, and the oracle's readings of the exported pool are of it. \`vm/disk-sync@replayed\` is the same volume after an import that replays the log, on a copy of the members: what a reader that applies the log would give."
    ALL="mirror-0a mirror-0b log-0"
    make_members 256M mirror-0a mirror-0b
    make_members 128M log-0
    create mirror $(paths mirror-0a mirror-0b) log $(paths log-0)
    common_datasets
    zfs create -s -V 24M -b 8K -o checksum=fletcher4 -o compression=lz4 -o sync=always "$POOL/vm/disk-sync"
    zfs set sync=always "$POOL/fs"
    VOLS="$VOLS vm/disk-sync"
    initial_fill
    rounds 0 2
    say "frozen, and written to"
    record_volume_hashes export
    EXPORT_HASHED=1
    zpool freeze "$POOL"
    text after-freeze 4194304 | dd of="$(zvol_dev "$POOL/vm/disk-sync")" bs=64K seek=64 conv=notrunc,fsync status=none
    i=0; while [ $i -lt 5 ]; do text "after-freeze$i" 5000 > "/$POOL/fs/after-freeze-$i.txt"; i=$((i+1)); done
    sync
    HISTORY_NOTE="After round 2, the volumes hashed (\`@export\`), the pool frozen, 4 MiB of \`vm/disk-sync\` from offset 4 MiB and five files of \`fs\` written with every write synchronous."
}
slog_replayed() {
    say "the intent log replayed, on a copy of the members"
    mkdir -p "$OUT/replay"
    for m in $ALL; do cp "$OUT/members/$m.img" "$OUT/replay/$m.img"; done
    zpool import -d "$OUT/replay" -o cachefile=none -N "$POOL"
    wait_dev "$(zvol_dev "$POOL/vm/disk-sync")"
    printf '%s  %s@replayed\n' "$(sha "$(zvol_dev "$POOL/vm/disk-sync")")" "$POOL/vm/disk-sync" >> "$OUT/oracle/volumes.sha256"
    zpool export "$POOL"
    for m in $ALL; do rm -f "$OUT/replay/$m.img"; done
    rmdir "$OUT/replay"
    grep -q "$(grep "$POOL/vm/disk-sync@export" "$OUT/oracle/volumes.sha256" | cut -c1-64)  $POOL/vm/disk-sync@replayed" "$OUT/oracle/volumes.sha256" &&
        die "the replayed volume is the frozen one: the intent log held nothing"
    return 0
}

recipe_mmp() {
    DESCRIPTION="One mirror with \`multihost=on\`: between the rounds the pool left imported for seconds at a time, so that the heartbeat of multi-modifier protection writes its uberblocks — the TXG of the last sync, a newer timestamp, the MMP fields — into the rings."
    ALL="mirror-0a mirror-0b"
    make_members 256M $ALL
    [ -s /etc/hostid ] || zgenhostid
    CREATE_OPTS="-o multihost=on"
    create mirror $(paths $ALL)
    common_datasets; initial_fill
    at_round() { sleep 5; }
    HISTORY_NOTE="Five seconds of heartbeat after every round, and as many before the export."
    rounds 0 3
    sleep 5
}

# The feature sets of older pools, made by this OpenZFS (stage 3): what a
# pool created by an older one, or made to be imported by one, carries.
recipe_compat20() {
    DESCRIPTION="One raidz1 of three disks created with \`compatibility=openzfs-2.0-linux\`: the features OpenZFS 2.0 on Linux knows and no later one — no block cloning, no RAIDZ expansion, no \`zilsaxattr\`, \`head_errlog\` or \`vdev_zaps_v2\` — as a pool made to be imported by 2.0, or made by it, has."
    ALL="raidz1-0 raidz1-1 raidz1-2"
    make_members 256M $ALL
    CREATE_OPTS="-o compatibility=openzfs-2.0-linux"
    create raidz1 $(paths $ALL)
    [ "$(zpool get -H -o value feature@block_cloning "$POOL")" = disabled ] || die "block_cloning is not disabled"
    common_datasets; initial_fill
    rounds 0 3
}
recipe_nofeatures() {
    DESCRIPTION="One mirror created with \`zpool create -d\`: pool version 5000 with every feature disabled — no hole birth, no embedded data, no lz4 (its volume compressed with lzjb), no large dnodes, no spacemap histogram — what a pool upgraded from a legacy version and never given a feature looks like."
    ALL="mirror-0a mirror-0b"
    make_members 256M $ALL
    CREATE_OPTS="-d"
    COMPRESSION=lzjb
    create mirror $(paths $ALL)
    zpool get -H -o property,value all "$POOL" | awk -F'\t' '$1 ~ /^feature@/ && $2 != "disabled" { bad = 1 } END { exit bad }' ||
        die "a feature is enabled"
    common_datasets; initial_fill
    rounds 0 3
}
recipe_v28() {
    DESCRIPTION="One raidz2 of four disks created with \`-o version=28\`: the last pool version before feature flags, with the ZPL of version 5 — its labels say version 28 and list no features, its MOS has no feature objects, and its volume is compressed with lzjb."
    ALL="raidz2-0 raidz2-1 raidz2-2 raidz2-3"
    make_members 256M $ALL
    CREATE_OPTS="-o version=28"
    COMPRESSION=lzjb
    create raidz2 $(paths $ALL)
    [ "$(zpool get -H -o value version "$POOL")" = 28 ] || die "the pool is not of version 28"
    common_datasets; initial_fill
    rounds 0 3
}

# Made on another system (stage 3): FreeBSD, its base OpenZFS, its disks
# laid out as its installer lays them out.
recipe_freebsd() {
    [ "$os" = FreeBSD ] || die "the freebsd satellite is made on FreeBSD (md devices, gpart, its base OpenZFS)"
    DESCRIPTION="One raidz1 of three disks made on FreeBSD $(freebsd-version) with the OpenZFS of its base system ($(zfs version 2>/dev/null | head -1)), each disk laid out as FreeBSD's installer lays one out — a GPT with a freebsd-boot partition of 512 KiB and a freebsd-zfs one aligned to 1 MiB, labelled \`gpt/<disk>\` — and the pool made on the labels. The members are the whole disks, partition table and all, and \`layout.json\` gives each the offset of its vdev."
    ALL="fbsd0 fbsd1 fbsd2"
    make_members 320M $ALL
    : > "$OUT/members.map"
    : > "$OUT/mds.txt"
    for m in $ALL; do
        md=$(mdconfig -a -t vnode -f "$OUT/members/$m.img")
        echo "$m $md" >> "$OUT/mds.txt"
        gpart create -s gpt "$md" >/dev/null
        gpart add -t freebsd-boot -s 512k "$md" >/dev/null
        gpart add -a 1m -t freebsd-zfs -l "$m" "$md" >/dev/null
        start=$(gpart show "$md" | awk '$4 == "freebsd-zfs" { print $1 }')
        sector=$(diskinfo "$md" | awk '{ print $2 }')
        echo "$m $m.img $((start * sector))" >> "$OUT/members.map"
    done
    cat "$OUT/members.map"
    SEARCH=/dev/gpt
    member_dev() { echo "/dev/gpt/$1"; }
    MAP=$OUT/members.map
    create raidz1 gpt/fbsd0 gpt/fbsd1 gpt/fbsd2
    common_datasets; initial_fill
    rounds 0 3
}
# At scale (stage 3): thousands of datasets, for what reading them takes.
recipe_scale() {
    DESCRIPTION="A pool at scale: one mirror with 200 filesystems under \`fs\`, every one of them snapshotted with the rest at each of ten rounds — over 2,000 datasets, 200 filesystems written to a few at a time between the snapshots — for what listing, reading and dating thousands of datasets takes. So many records fill the pool's history, a ring of a thousandth of its space, and it wraps: \`zpool history\` keeps what the creation logged and, of the rest, the newest alone, and the oldest datasets' coming into being is \`zfs get createtxg\`'s to say. Its manifests are held out of the regular runs, and its oracle has no \`zdb -dddddd\` (a file a dataset would be thousands), of \`zdb -dddd\` each dataset's own line alone, and the datasets of the newest 16 TXGs alone."
    ALL="mirror-0a mirror-0b"
    make_members 512M $ALL
    create mirror $(paths $ALL)
    common_datasets
    i=0; while [ $i -lt 200 ]; do zfs create "$POOL/fs/c$(printf %03d $i)"; i=$((i+1)); done
    initial_fill
    at_round() {
        # a file in twenty of the children, a different twenty each round
        j=0; while [ $j -lt 20 ]; do
            c=$(printf %03d $(( ($1 * 20 + j) % 200 )))
            text "scale$1-$j" $((500 + j * 97)) > "/$POOL/fs/c$c/r$1.txt"
            j=$((j+1))
        done
    }
    HISTORY_NOTE="200 filesystems created under \`fs\` before the fill; after every round, a file written to twenty of them."
    DEEP=0
    BY_TXG=16
    rounds 0 9
    [ "$(zfs list -H -t all -r -o name "$POOL" | wc -l)" -ge 2000 ] || die "fewer than 2,000 datasets"
}

# A database's preallocated pages, 8 KiB each as a volume of 8K blocks
# holds them: a header and a trailer as InnoDB writes them (a checksum,
# the page's number and its neighbours', an LSN) with nothing between,
# which every codec shrinks to tens of bytes and ZFS keeps in the block
# pointer itself (embedded_data); every 64th a page of rows, text from
# POOL_FILE.
pages() { # pages LABEL BYTES POOL_FILE > data
    python3 -c '
import struct, sys, zlib
label, n, pool = sys.argv[1], int(sys.argv[2]), open(sys.argv[3], "rb").read()
P, out, batch = 8192, sys.stdout.buffer, []
empty = bytes(P - 46)
for i in range(n // P):
    crc = zlib.crc32(f"{label}:{i}".encode())
    lsn = 1000000 + i * 512
    rows = i % 64 == 63
    head = struct.pack(">IIIIQHQI", crc, i, max(i - 1, 0), i + 1, lsn, 0x45BF if rows else 0, lsn, 7)
    if rows:
        at = (i * 7 * P) % (len(pool) - P)
        body = pool[at:at + P - 46]
    else:
        body = empty
    batch.append(head + body + struct.pack(">II", crc, lsn & 0xFFFFFFFF))
    if len(batch) == 256:
        out.write(b"".join(batch)); batch = []
out.write(b"".join(batch))' "$1" "$2" "$3"
}
# Whether FILE holds something past its first 4 GiB, its rear labels
# aside: a block whose offset in its member is no 32-bit number.
past_4gib() { # past_4gib FILE
    python3 -c '
import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
end, pos = os.fstat(fd).st_size - (512 << 10), 4 << 30
while pos < end:
    try:
        pos = os.lseek(fd, pos, os.SEEK_DATA)
    except OSError:
        break
    if pos >= end:
        break
    chunk = os.pread(fd, min(1 << 20, end - pos), pos)
    if chunk.strip(b"\0"):
        sys.exit(0)
    pos += len(chunk)
sys.exit(1)' "$1"
}
recipe_large() {
    DESCRIPTION="A large volume of content ZFS compresses: \`vm/big\`, 10 GiB of 8K blocks with zstd — the disk of a database's machine, 256 MiB of its system (text), 128 MiB of media (the keystream) and the rest the database's preallocated pages, each a header and a trailer with nothing between, which ZFS keeps in the block pointer itself (\`embedded_data\`), every 64th a page of rows; then three runs of 4 MiB written over it, one across the volume's 4 GiB. Over 1.3 million blocks under four levels of indirect blocks (8K blocks: a level-2 block spans 8 GiB), offsets past 4 GiB in the volume and in its members, on a mirror of two 12 GiB members of which the pool fills a twentieth. Its manifests are held out of the regular runs, and its oracle has no \`zdb -dddddd\` (a line a block would be over a million) and of \`zdb -dddd\` each dataset's own line alone."
    ALL="mirror-0a mirror-0b"
    make_members 12G $ALL
    create mirror $(paths $ALL)
    common_datasets
    initial_fill
    DEEP=0
    rounds 0 1
    say "vm/big"
    zfs create -s -V 10G -b 8K -o compression=zstd "$POOL/vm/big"
    dev=$(zvol_dev "$POOL/vm/big"); wait_dev "$dev"
    text big-system 268435456 | dd of="$dev" bs=1M conv=notrunc status=none
    txg_sync
    stream big-media 134217728 | dd of="$dev" bs=1M seek=256 conv=notrunc status=none
    txg_sync
    text big-rows 33554432 > "$OUT/rows.txt"
    pages big-pages $(( (10240 - 384) * 1048576 )) "$OUT/rows.txt" | dd of="$dev" bs=1M seek=384 conv=notrunc status=none
    rm -f "$OUT/rows.txt"
    txg_sync
    for at in 4094 6144 10236; do
        stream "big-late@$at" 4194304 | dd of="$dev" bs=1M seek=$at conv=notrunc status=none
        txg_sync
    done
    VOLS="$VOLS vm/big"
    feature_active zstd_compress
    feature_active embedded_data
    [ "$(zfs get -Hp -o value logicalused "$POOL/vm/big")" -gt $((9 << 30)) ] || die "vm/big holds less than 9 GiB"
    for m in $ALL; do past_4gib "$OUT/members/$m.img" || die "$m: nothing written past its first 4 GiB"; done
    HISTORY_NOTE="After the rounds, \`vm/big\` created and written whole, then three runs of 4 MiB of the keystream over it at 4094 MiB, 6 GiB and its last 4 MiB, a TXG each; it has no snapshot."
}

freebsd_detach() {
    while read -r m md; do mdconfig -d -u "$md"; done < "$OUT/mds.txt"
}

# ---------------------------------------------------------------- build
case $NAME in
    removal|checkpoint|spare|expand|special|ashift|slog|mmp|compat20|nofeatures|v28|freebsd|scale|large) ;;
    *) die "no satellite $NAME (removal checkpoint spare expand special ashift slog mmp compat20 nofeatures v28 freebsd scale large)" ;;
esac
MAP=""
say "$POOL ($TAG)"
EXPORT_HASHED=""
"recipe_$NAME"

say "oracle"
[ -n "$EXPORT_HASHED" ] || record_volume_hashes export
oracle_imported
oracle_exported
[ "$NAME" != slog ] || slog_replayed
[ "$NAME" != spare ] || tunable zfs_scan_suspend_progress 0 scan_suspend_progress
[ "$NAME" != freebsd ] || freebsd_detach

python3 "$HERE/zdb-layout.py" --pool "$POOL" --tag "$TAG" --source kernel --volumes --satellite \
    ${MAP:+--map "$MAP"} < "$OUT/oracle/zdb-C.txt" > "$OUT/oracle/layout.json"

say "release files"
release_members
release_sums

{
    echo "# Satellite \`$POOL\` ($TAG)"
    echo
    echo "Built $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(uname -srm) with $(zpool version 2>/dev/null | head -1)."
    echo
    echo "$DESCRIPTION"
    echo
    echo "## Layout"
    echo
    echo "Ashift $(grep -E '^\s*ashift:' "$OUT/oracle/pool-facts.txt" | awk '{print $2}' | tr '\n' ' ' | sed 's/ $//; s/ /, /g'), as \`zpool status\` printed it at the end:"
    echo
    echo '```'; sed -n '/^config:/,/^errors:/p' "$OUT/oracle/zpool-status.txt" | sed '/^errors:/d'; echo '```'
    echo
    echo "## Datasets"
    echo; echo '```'; cat "$OUT/oracle/zfs-list.txt"; echo '```'
    echo
    echo "## History"
    echo
    echo "\`vm/disk-8k\` (8K blocks, $COMPRESSION, written with content it shrinks) and \`vm/disk-16k\` (16K blocks, sha256, the keystream), 16 MiB of each, and \`fs\`, twenty text files, twenty of the keystream in a directory, a symbolic and a hard link. Then rounds of four TXGs with 256 KiB written to every volume and a file to \`fs\` in each, a recursive snapshot \`s<round>\` after each round. ${HISTORY_NOTE} Deterministic content from seed \`$SEED\`."
    echo
    echo "## Oracle"
    echo
    echo "As the golden image's, without older copies: \`volumes.sha256\`, \`zfs-get-destroyed.txt\` where something was destroyed, \`datasets*.txt\`, \`datasets-by-txg/\`, \`labels/\`, \`labels-uberblocks/\`, \`zdb-u-export.txt\`, \`zdb-*.txt\` and \`zdb-dddddd/\`, \`files.json\`, \`zpool-history-il.txt\`, \`files-capture.txt\`, \`zpool-status.txt\`, \`layout.json\` (\`satellite\`: the manifests that name no pool are not run against it), \`members.sha256\`."
    echo
    echo "## Release files"
    echo; echo '```'; cat "$OUT/release/SHA256SUMS"; echo '```'
} > "$OUT/IMAGE.md"

say "done: $OUT/release, $OUT/oracle, $OUT/IMAGE.md"
