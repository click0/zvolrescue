# What the image builders share (build-image.sh, build-satellite.sh):
# sourced, not run. The builder sets, before sourcing it:
#
#   HERE  the directory of the builders     OUT   the output directory
#   POOL  the pool's name                   SEED  the seed of every keystream
#
# and, before calling what follows, ALL (the members, file names without
# `.img`, under OUT/members) and VOLS (the volumes, without the pool's
# name). Everything here comes from OpenZFS alone — zpool, zfs, zdb, the
# kernel through the VFS, and sha256 of what the kernel's zvols give —
# never from zvolrescue.

BUILDER=${0##*/}
mkdir -p "$OUT/members" "$OUT/release" "$OUT/oracle" "$OUT/oracle/labels" "$OUT/oracle/labels-uberblocks" \
    "$OUT/oracle/datasets-by-txg" "$OUT/oracle/keys"
OUT=$(cd "$OUT" && pwd)

os=$(uname -s)
say() { printf '== %s\n' "$*"; }
die() { printf '%s: %s\n' "${BUILDER%.sh}" "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root (zpool/zfs need it)"
command -v zpool >/dev/null || die "zpool not found"
command -v zdb >/dev/null || die "zdb not found"
command -v zstd >/dev/null || die "zstd not found"
command -v python3 >/dev/null || die "python3 not found (zdb-layout.py writes the layout)"
if command -v sha256sum >/dev/null; then SHA="sha256sum"; else SHA="sha256 -r"; fi
sha() { $SHA "$1" | awk '{print $1}'; }
sums() { # sums DIR > list: `<sha256>  <name>` of every member image in DIR
    ( cd "$1" && for f in *.img; do printf '%s  %s\n' "$(sha "$f")" "$f"; done )
}

# Deterministic pseudo-random bytes: AES-CTR keystream of zeros, keyed by
# SEED and a per-stream label. Same input, same bytes, on any host.
stream() { # stream LABEL BYTES > data
    key=$(printf '%s:%s' "$SEED" "$1" | openssl dgst -sha256 | awk '{print $NF}')
    head -c "$2" /dev/zero | openssl enc -aes-256-ctr -K "$key" -iv 00000000000000000000000000000000 2>/dev/null
}
# Content a codec has something to do with. The stream itself shrinks by
# nothing, and ZFS keeps a block uncompressed unless it saves an eighth:
# image-v1's volumes were filled with it, so every one of them was stored
# uncompressed whatever its `compression` said. `text` is the hex dump of
# a stream with every line written twice — literals, short matches and a
# long one each line, about a quarter of its size under zstd — and
# `holey` the stream with every other 2 KiB zeroed, which is the one
# thing `zle` compresses.
text() { # text LABEL BYTES > data
    stream "$1" $(( $2 / 6 + 64 )) | od -An -v -tx1 | awk '{ print; print }' | head -c "$2"
}
holey() { # holey LABEL BYTES > data
    stream "$1" $(( $2 / 2 + 2048 )) | python3 -c '
import sys
r, o, n = sys.stdin.buffer.read(), sys.stdout.buffer, int(sys.argv[1])
o.write(b"".join(r[i:i + 2048] + bytes(2048) for i in range(0, len(r), 2048))[:n])' "$2"
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
# A zvol is opened by udev for a moment after it is written to, and a
# rollback of it is refused while it is open: a few tries.
retry() { # retry CMD...
    n=0
    until "$@"; do
        n=$((n + 1)); [ $n -lt 10 ] || die "$* kept failing"
        command -v udevadm >/dev/null && udevadm settle || true
        sleep 1
    done
}
xattr_set() { # xattr_set FILE NAME < value: the user namespace's NAME
    case $os in
        Linux) python3 -c 'import os, sys; os.setxattr(sys.argv[1], "user." + sys.argv[2], sys.stdin.buffer.read())' "$1" "$2" ;;
        FreeBSD) setextattr -i user "$2" "$1" ;;
    esac
}
clone_file() { # clone_file SRC DST: the same blocks, cloned
    case $os in
        Linux) cp --reflink=always "$1" "$2" ;;
        *) cp "$1" "$2" ;;   # copy_file_range(2), which clones where it can
    esac || die "cloning $1 to $2 failed"
}
# Into another dataset: the VFS refuses FICLONE across two filesystems
# (EXDEV), and copy_file_range(2) is the way, which ZFS answers with
# cloned blocks where it can and with a copy where it cannot. What the
# pool says it saved tells which it was.
clone_across() { # clone_across SRC DST
    txg_sync
    before=$(zpool get -Hp -o value bclonesaved "$POOL")
    python3 -c '
import os, sys
with open(sys.argv[1], "rb") as s, open(sys.argv[2], "wb") as d:
    n, off = os.fstat(s.fileno()).st_size, 0
    while off < n:
        k = os.copy_file_range(s.fileno(), d.fileno(), n - off, off, off)
        if k == 0:
            break
        off += k' "$1" "$2" || die "copy_file_range $1 to $2 failed"
    txg_sync
    after=$(zpool get -Hp -o value bclonesaved "$POOL")
    [ $((after - before)) -ge $(( $(wc -c < "$1") / 2 )) ] ||
        die "copy_file_range $1 to $2 copied rather than cloned (bclonesaved $before -> $after)"
}

paths() { for m in "$@"; do printf '%s ' "$OUT/members/$m.img"; done; }

record_volume_hashes() { # record TAG: every volume of VOLS as its device reads now
    for v in $VOLS; do
        dev=$(zvol_dev "$POOL/$v")
        [ -e "$dev" ] || continue
        printf '%s  %s@%s\n' "$(sha "$dev")" "$POOL/$v" "$1" >> "$OUT/oracle/volumes.sha256"
    done
}
record_snapshot_hashes() { # record_snapshot_hashes SNAP: every volume of VOLS at @SNAP
    for v in $VOLS; do wait_dev "$(zvol_dev "$POOL/$v@$1")" 2>/dev/null || true; done
    for v in $VOLS; do
        dev=$(zvol_dev "$POOL/$v@$1")
        [ -e "$dev" ] && printf '%s  %s@%s\n' "$(sha "$dev")" "$POOL/$v" "$1" >> "$OUT/oracle/volumes.sha256"
    done
}
# What a dataset was, just before it is destroyed: its properties, and a
# volume's bytes, which nothing in the pool records once it is gone.
before_destroy() { # before_destroy DATASET
    zfs get -H -o name,property,value all "$POOL/$1" >> "$OUT/oracle/zfs-get-destroyed.txt"
    if [ "$(zfs get -H -o value type "$POOL/$1")" = volume ]; then
        printf '%s  %s@destroyed\n' "$(sha "$(zvol_dev "$POOL/$1")")" "$POOL/$1" >> "$OUT/oracle/volumes.sha256"
    fi
}

# ---------------------------------------------------------------- oracle
# The pool as it is while imported: what `zpool` and `zfs` say of it, and
# zdb of the imported pool. The volumes' hashes at the export are the
# builder's to record first (`record_volume_hashes export`): what the
# devices read is not always what is on the members.
oracle_imported() {
    zpool status -v "$POOL" > "$OUT/oracle/zpool-status.txt"
    zfs list -r -t all -o name,type,guid,creation,used,refer,volsize,volblocksize,checksum,compression,encryption,keyformat -H "$POOL" > "$OUT/oracle/zfs-list.txt"
    zfs get -r -H -o name,property,value all "$POOL" > "$OUT/oracle/zfs-get-all.txt"
    zdb -d "$POOL" > "$OUT/oracle/datasets.txt"
    zdb -C "$POOL" > "$OUT/oracle/zdb-C.txt"
    zdb -u "$POOL" > "$OUT/oracle/zdb-u.txt" 2>&1 || true
    zpool get -H -o property,value all "$POOL" > "$OUT/oracle/zpool-get-all.txt"
    zdb -C "$POOL" | grep -E "^\s*(txg|version|pool_guid|ashift):" | head -20 > "$OUT/oracle/pool-facts.txt" || true
}

# Where zdb and an import find the members, and the device of a member:
# its file, unless a builder's pool is made on something in it (the
# FreeBSD satellite: a partition of each, under /dev/gpt).
SEARCH=${SEARCH:-$OUT/members}
member_dev() { echo "$OUT/members/$1.img"; }
zdbe() { zdb -e -p "$SEARCH" "$@"; }

# The pool exported, and everything read of the exported members: their
# sums before anything reads them, zdb offline over them, the kernel's
# reading of every file with the pool imported read-only, and the sums
# again. A builder may define `after_export`, called once zdb is done and
# before the read-only import, for captures of its own.
oracle_exported() {
    say "export"
    zfs unmount -a 2>/dev/null || true
    zpool export "$POOL"
    # The members as the release will hold them, before anything reads them:
    # every capture below is checked to have left them so.
    sums "$OUT/members" > "$OUT/oracle/members.sha256"
    [ ! -d "$OUT/members-round6" ] || sums "$OUT/members-round6" > "$OUT/oracle/members-round6.sha256"

    # zdb offline, over the exported members: what the release holds.
    # Every member's labels (`-l`), and with every uberblock of their rings
    # (`-lu`); the uberblock zdb reads the exported pool at.
    for m in $ALL; do
        zdb -l "$(member_dev "$m")" > "$OUT/oracle/labels/$m.txt" 2>&1 || true
        zdb -lu "$(member_dev "$m")" > "$OUT/oracle/labels-uberblocks/$m.txt" 2>&1 || die "zdb -lu $m"
    done
    zdbe -u "$POOL" > "$OUT/oracle/zdb-u-export.txt" 2>&1 || die "zdb -e -u"
    zdbe -d "$POOL" > "$OUT/oracle/datasets-exported.txt" 2>&1 || true
    # Every object of every dataset (`-dddd`), and with its block pointers
    # level by level (`-dddddd`): what lets a manifest aim at a dnode block,
    # an indirect block or one data block of a named object. The second is
    # far past what one file in git should be, so it is kept a dataset a file
    # (split-capture.py; the harness reads the directory as the one capture).
    zdbe -dddd "$POOL" > "$OUT/oracle/zdb-dddd.txt" 2>&1 || true
    test -s "$OUT/oracle/zdb-dddd.txt" || die "zdb -e -dddd wrote nothing"
    # A builder of a pool of thousands of datasets, whose manifests aim at
    # no block, leaves it out (DEEP=0): a file a dataset is thousands.
    if [ "${DEEP:-1}" != 0 ]; then
        zdbe -dddddd "$POOL" > "$OUT/zdb-dddddd.txt" 2> "$OUT/zdb-dddddd.err" || die "zdb -e -dddddd: $(tail -n 3 "$OUT/zdb-dddddd.err")"
        python3 "$HERE/split-capture.py" "$OUT/zdb-dddddd.txt" "$OUT/oracle/zdb-dddddd"
        rm -f "$OUT/zdb-dddddd.txt"
    fi
    # every uberblock TXG still readable: try the newest 128 (the ring
    # depth), or as many as the builder says (BY_TXG: of thousands of
    # datasets, each listing is large)
    newest=$(zdbe -u "$POOL" 2>/dev/null | awk '/txg = /{print $3}' | sort -n | tail -1)
    if [ -n "$newest" ]; then
        t=$newest; n=0
        while [ $n -lt "${BY_TXG:-128}" ] && [ "$t" -gt 0 ]; do
            if zdbe -t "$t" -d "$POOL" > "$OUT/oracle/datasets-by-txg/$t.txt" 2>/dev/null; then :; else rm -f "$OUT/oracle/datasets-by-txg/$t.txt"; fi
            t=$((t-1)); n=$((n+1))
        done
    fi
    if command -v after_export >/dev/null 2>&1; then after_export; fi

    # The kernel's reading of every file: the pool imported read-only, every
    # filesystem mounted alone on a directory of its own (a child mounted
    # inside its parent would hide what the parent holds there), each of its
    # snapshots under its .zfs/snapshot; and the pool's own history. What
    # zvolfiles and zvoltimeline are judged against.
    if [ "$os" = Linux ] || [ "$os" = FreeBSD ]; then
        say "files and history, the pool imported read-only"
        ALT=$OUT/altroot; MNT=$OUT/mnt
        forced=""
        zpool import -d "$SEARCH" -o readonly=on -o cachefile=none -R "$ALT" -N "$POOL" ||
            { forced=" -f"; zpool import -f -d "$SEARCH" -o readonly=on -o cachefile=none -R "$ALT" -N "$POOL"; }
        zfs list -H -t filesystem,volume -r -o name,encryptionroot,keyformat "$POOL" |
            awk -F'\t' '$1 == $2 && $3 != "none" { print $1, $3 }' > "$OUT/roots.txt"
        while read -r root format; do
            case $format in raw) file=raw.key ;; passphrase) file=passphrase.txt ;; *) file=$format.key ;; esac
            zfs load-key -L "file://$OUT/oracle/keys/$file" "$root"
        done < "$OUT/roots.txt"
        zfs list -H -t filesystem -r -o name "$POOL" > "$OUT/filesystems.txt"
        n=0
        while read -r name; do
            n=$((n + 1)); dir=$MNT/$n
            mkdir -p "$dir"
            case $os in
                Linux) mount -t zfs -o ro,zfsutil "$name" "$dir" ;;
                *) mount -t zfs -o ro "$name" "$dir" ;;
            esac || die "$name did not mount"
            set -- "$name=$dir"
            for snap in $(zfs list -H -o name -t snapshot -d 1 "$name"); do
                set -- "$@" "$snap=$dir/.zfs/snapshot/${snap#*@}"
            done
            python3 -I "$HERE/capture-files.py" --add "$OUT/oracle/files.json" "$POOL" "$@"
            case $os in
                Linux) umount -R "$dir" ;;
                # its snapshots' mounts under .zfs first, newest mount first
                *) mount -p | awk -v d="$dir" '$2 == d || index($2, d "/") == 1 { print $2 }' | sort -r |
                       while read -r mp; do umount -f "$mp"; done ;;
            esac
        done < "$OUT/filesystems.txt"
        python3 - "$OUT/oracle/files.json" "${BUILDER%.sh}" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))["datasets"]
bad = {k: v["error"] for k, v in d.items() if "error" in v}
if bad:
    sys.exit(f"{sys.argv[2]}: not read: {bad}")
files = sum(1 for v in d.values() for e in v.get("entries", []) if e["type"] == "f")
print(f"{len(d)} filesystems and snapshots, {files} files")
EOF
        zpool history -il "$POOL" > "$OUT/oracle/zpool-history-il.txt"
        {
            echo "# How files.json and zpool-history-il.txt were captured"
            echo
            echo "builder: tests/golden/$BUILDER of zvolrescue (tests/golden/capture-files.py), right after the export"
            echo "host:    $(uname -srm)"
            echo "openzfs: $(zfs version 2>/dev/null | tr '\n' ' ')"
            echo "import:  zpool import -d ${SEARCH#$OUT/} -o readonly=on -o cachefile=none -R ALTROOT -N$forced $POOL"
            echo "keys:    zfs load-key -L file://oracle/keys/... for each encryption root"
            echo "mounts:  each filesystem alone, mount -t zfs -o ro$([ "$os" = Linux ] && echo ,zfsutil), its snapshots under .zfs/snapshot"
            [ "$os" = Linux ] || echo "xattrs:  not read (no listxattr here)"
            echo
            zpool status -v "$POOL"
            echo
            zfs list -t all -r -o name,mounted,mountpoint,used,referenced "$POOL"
        } > "$OUT/oracle/files-capture.txt"
        zpool export "$POOL"
    fi
    # Nothing read above wrote: the members are the bytes the release holds.
    sums "$OUT/members" > "$OUT/after.sha256"
    cmp "$OUT/oracle/members.sha256" "$OUT/after.sha256" || die "a member changed after the export"
    [ ! -f "$OUT/oracle/files-capture.txt" ] ||
        echo "members: unchanged after the export (their sums against members.sha256)" >> "$OUT/oracle/files-capture.txt"
}

# The members compressed for the release, and the sums of what it holds.
release_members() {
    for m in $ALL; do zstd -T0 -19 -q -f "$OUT/members/$m.img" -o "$OUT/release/$m.img.zst"; done
}
release_sums() {
    ( cd "$OUT/release" && for f in *.zst; do printf '%s  %s\n' "$(sha "$f")" "$f"; done > SHA256SUMS )
}
