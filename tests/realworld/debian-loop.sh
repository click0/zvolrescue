#!/bin/bash
# The real-world matrix on Debian with zfs-dkms and loop devices
# (docs/REALWORLD-TESTS.md, "Running on Debian with zfs-dkms and loop
# devices").
#
# The cheapest environment with a real kernel ZFS: pools the kernel
# itself made, on loop devices, which are block devices as far as the
# tool is concerned (SPEC N-10: a device, not an image). Every oracle
# comes from OpenZFS — `sha256sum /dev/zvol/...` before export, `zdb -d`,
# `zdb -lu` and `zfs get` — never from zvolrescue.
#
#   apt install zfsutils-linux zfs-dkms dmsetup strace python3
#   modprobe zfs
#   sudo bash tests/realworld/debian-loop.sh /var/tmp/rw [./target/release/zvolrescue]
#
# Runs as root in a scratch directory (sparse member files and the
# images the tool writes: about 6 GiB of disk), creates only pools whose names begin with `zrw`, refuses to
# start if any such pool exists, and tears down its own loop and
# device-mapper devices on exit. Nothing it does touches another pool.
#
# Output: WORKDIR/results.txt (one line per scenario), WORKDIR/env.txt,
# WORKDIR/evidence.jsonl (every run of the tool), WORKDIR/row.md (the
# Results row for the matrix), WORKDIR/out/*.log for failures. Exit 0
# when every attempted scenario passed, 1 otherwise.
#
# What it covers: A1 A2 A3 B1 B2 B3 B4 B5 B6 B7 B8 B9 C1 C2 C3 C4 C5 C6
# C7 C8 C9 C10 C11 C12 D1 D2 D3 D4 D5 D6 D7 D8 F7 G5. C12 needs OpenZFS
# 2.3 (`raidz_expansion`) and is skipped on 2.2 with a note; B7 is
# skipped when this zpool does not build dRAID. What a loop device
# cannot give — E1, E2 (a disk's read rate), F1–F6 and F8–F10 (sector
# sizes, controllers, bridges) — is not attempted and stays ☐.
set -u

WORK=${1:?work directory}
ZR=${2:-./target/release/zvolrescue}
ZR=$(readlink -f "$ZR")
REPORT=$(dirname "$ZR")/zvolreport
SEED=zvolrescue-realworld-2026
P=zrw   # pool name prefix
mkdir -p "$WORK/img" "$WORK/out"
WORK=$(cd "$WORK" && pwd)
EV=$WORK/evidence.jsonl
: > "$WORK/results.txt"
: > "$EV"

say() { printf '\n== %s\n' "$*"; }
die() { printf 'debian-loop: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- checks
[ "$(id -u)" = 0 ] || die "run as root (zpool, losetup and dmsetup need it)"
[ -x "$ZR" ] || die "$ZR is not executable (build with cargo build --release)"
for c in zpool zfs zdb losetup sfdisk dmsetup sha256sum sha1sum md5sum python3 openssl blockdev; do
    command -v "$c" >/dev/null || die "$c not found"
done
[ -e /dev/zfs ] || modprobe zfs 2>/dev/null || die "the zfs kernel module is not loaded (apt install zfs-dkms; modprobe zfs)"
[ -e /dev/zfs ] || die "/dev/zfs missing after modprobe"
if zpool list -H -o name 2>/dev/null | grep -q "^$P"; then
    die "a pool named $P* is already imported; this script only ever creates and destroys those, so export or destroy it first"
fi
HAVE_STRACE=1; command -v strace >/dev/null || HAVE_STRACE=0

{
    echo "date: $(date -u +%Y-%m-%d)"
    echo "os: $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "kernel: $(uname -r)"
    echo "zfs: $(zfs version 2>/dev/null | tr '\n' ' ')"
    echo "tool: $("$ZR" --version)"
    echo "strace: $HAVE_STRACE"
} | tee "$WORK/env.txt"
ZFS_VER=$(zfs version 2>/dev/null | sed -n 's/^zfs-\([0-9][0-9.]*\).*/\1/p' | head -1)
# The module's version where it differs from userland's (Ubuntu ships a
# newer in-tree module than its tools), and where the module came from.
KMOD_VER=$(zfs version 2>/dev/null | sed -n 's/^zfs-kmod-\([0-9][0-9.]*\).*/\1/p' | head -1)
[ -z "$KMOD_VER" ] || [ "$KMOD_VER" = "$ZFS_VER" ] || ZFS_VER="$ZFS_VER (kmod $KMOD_VER)"
MODULE_FROM="in-tree module"; dkms status 2>/dev/null | grep -q '^zfs' && MODULE_FROM="zfs-dkms"
TOOL_VER=$("$ZR" --version | awk '{print $2}')

# ---------------------------------------------------------------- teardown
LOOPS=""
POOLS=""
cleanup() {
    set +e
    for p in $POOLS; do
        zpool list -H -o name "$p" >/dev/null 2>&1 && zpool export "$p" >/dev/null 2>&1
    done
    dmsetup info zr-bad >/dev/null 2>&1 && dmsetup remove zr-bad
    for l in $LOOPS; do losetup -d "$l" 2>/dev/null; done
}
trap cleanup EXIT

# ---------------------------------------------------------------- helpers
# Loop device over a sparse file. Prints the device.
mkloop() { # mkloop NAME SIZE [losetup options]
    truncate -s "$2" "$WORK/img/$1.img"
    dev=$(losetup --find --show "${@:3}" "$WORK/img/$1.img") || die "losetup failed for $1"
    LOOPS="$LOOPS $dev"
    echo "$dev"
}
# Deterministic bytes: AES-CTR keystream keyed by SEED and a label.
stream() { # stream LABEL BYTES
    key=$(printf '%s:%s' "$SEED" "$1" | openssl dgst -sha256 | awk '{print $NF}')
    head -c "$2" /dev/zero | openssl enc -aes-256-ctr -K "$key" -iv 00000000000000000000000000000000 2>/dev/null
}
zdev() { echo "/dev/zvol/$1"; }
wait_dev() {
    i=0; while [ ! -e "$1" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
    [ -e "$1" ] || die "device $1 did not appear"
}
wait_dev_soft() { # the same, as a verdict rather than an exit
    i=0; while [ ! -e "$1" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
    [ -e "$1" ]
}
# A property value this ZFS does not have (blake3 needs OpenZFS 2.2)
# skips its volume with a note instead of ending the run.
NOT_HERE_C1=""; NOT_HERE_C2=""; NOT_HERE_C3=""
fill() { # fill POOL/VOL BYTES [SEEK_MIB]  — deterministic content
    wait_dev "$(zdev "$1")"
    stream "$1@${3:-0}" "$2" | dd of="$(zdev "$1")" bs=1M seek="${3:-0}" conv=notrunc,fsync status=none
}
oracle() { # oracle POOL/VOL → sha256 of the whole volume as the kernel reads it
    wait_dev "$(zdev "$1")"
    sha256sum "$(zdev "$1")" | awk '{print $1}'
}
declare -A DEVS   # pool → its devices, for the import check at the end
newpool() { # newpool NAME "DEVICES" [-o|-O prop=value]... VDEV-SPEC... — records it for teardown
    name=$1; POOLS="$POOLS $name"; DEVS[$name]=$2; shift 2
    opts=()
    while [ $# -gt 0 ]; do case $1 in -o|-O) opts+=("$1" "$2"); shift 2 ;; *) break ;; esac; done
    zpool create -f "${opts[@]}" "$name" "$@" || die "zpool create $name failed"
}
import_args() { for d in ${DEVS[$1]}; do printf -- '-d %s ' "$d"; done; }
export_pool() { zpool sync "$1"; zpool export "$1" || die "zpool export $1 failed"; sync; }
run() { # run LOG ARGS... — the tool with the evidence log; exit code in $code
    log=$WORK/out/$1.log; shift
    "$ZR" --evidence-log "$EV" "$@" >"$log" 2>"$log.err"; code=$?
}
sha_of() { sha256sum "$1" | awk '{print $1}'; }
jsonq() { python3 -c "import json,sys; d=json.load(sys.stdin); $1"; }

PASSED=""; FAILED=""; SKIPPED=""
result() { # result ID PASS|FAIL|SKIP note
    printf '%s %s %s\n' "$1" "$2" "$3" | tee -a "$WORK/results.txt"
    case $2 in
        PASS) PASSED="$PASSED $1" ;;
        FAIL) FAILED="$FAILED $1" ;;
        SKIP) SKIPPED="$SKIPPED $1" ;;
    esac
}
# dump_matches ID POOL/VOL EXPECTED_SHA DEVS... [-- more options]: the
# image's hash equals the kernel's, from the devices given (members may
# be left out).
dump_matches() {
    id=$1; vol=$2; want=$3; shift 3
    out=$WORK/out/$id.img; rm -f "$out"
    run "$id-dump" -f json dump "$vol" "$@" -o "$out"
    got=$(jsonq 'print(d["volumes"][0]["sha256"])' < "$WORK/out/$id-dump.log" 2>/dev/null)
    file=$(sha_of "$out" 2>/dev/null)
    if [ "$code" = 0 ] && [ "$got" = "$want" ] && [ "$file" = "$want" ]; then
        return 0
    fi
    echo "   $id: dump exit $code, reported $got, file $file, kernel $want" >&2
    return 1
}
# partial_matches IMG REF LOG: an exit-4 image tells the truth about what
# it lost — it is REF (the volume as the kernel read it) with exactly the
# blocks LOG lists under "bad" zeroed, and its hash is the one reported.
partial_matches() {
    python3 - "$1" "$2" "$3" <<'PY'
import hashlib, json, sys
img, ref, log = sys.argv[1:]
v = json.load(open(log))["volumes"][0]
data = bytearray(open(ref, "rb").read())
for b in v["bad"]:
    data[b["offset"]:b["offset"] + b["len"]] = bytes(b["len"])
want = hashlib.sha256(data).hexdigest()
got = hashlib.sha256(open(img, "rb").read()).hexdigest()
if got == want == v["sha256"]:
    print("%d of %d blocks lost" % (v["blocks_zeroed"], v["blocks_total"]))
    sys.exit(0)
print("image %s, reference with the bad blocks zeroed %s, reported %s" % (got, want, v["sha256"]), file=sys.stderr)
sys.exit(1)
PY
}
# datasets_match ID POOL DEVS...: `list -r` names and creation TXGs equal
# `zdb -e -d` over the backing files (a loop device and its file are the
# same bytes; zdb reads the files, the tool reads the devices).
datasets_match() {
    id=$1; pool=$2; shift 2
    zdb -e -p "$WORK/img" -d "$pool" 2>/dev/null | python3 -c '
import re,sys
for l in sys.stdin:
    m = re.match(r"Dataset (\S+) \[(\w+)\], ID \d+, cr_txg (\d+)", l)
    if m and m.group(1) != "mos":
        print(m.group(1), m.group(3))' | sort > "$WORK/out/$id-zdb.txt"
    run "$id-list" -f json list -r "$@"
    jsonq 'print("\n".join(x["name"] + " " + str(x["creation_txg"]) for x in d["datasets"]))' < "$WORK/out/$id-list.log" 2>/dev/null | sort > "$WORK/out/$id-zr.txt"
    if [ "$code" = 0 ] && [ -s "$WORK/out/$id-zdb.txt" ] && diff -u "$WORK/out/$id-zdb.txt" "$WORK/out/$id-zr.txt" > "$WORK/out/$id-diff.txt"; then
        return 0
    fi
    echo "   $id: list exit $code; see $WORK/out/$id-diff.txt" >&2
    return 1
}
# Hash of the first and last 4 MiB of a device (A1, G5).
edges() { { dd if="$1" bs=1M count=4 status=none; dd if="$1" bs=1M skip=$(( $(blockdev --getsize64 "$1") / 1048576 - 4 )) status=none; } | sha256sum | awk '{print $1}'; }

# ================================================================ pools
# Every pool is built, filled, its oracles taken, and exported before the
# tool sees it. Member paths are the loop devices.
declare -A SHA

# ---- B1: single disk at three ashifts
say "pools: single disk, ashift 9 / 12 / 13 (B1)"
for a in 9 12 13; do
    d=$(mkloop "single$a" 512M)
    newpool "${P}s$a" "$d" -o ashift=$a "$d"
    zfs create -V 32M -b 16K "${P}s$a/vol"
    fill "${P}s$a/vol" 24M
    SHA[s$a]=$(oracle "${P}s$a/vol")
    export_pool "${P}s$a"
    eval "S$a=$d"
done

# ---- the mirror: most of C and D live here
say "pool: mirror-2 (B2, C, D)"
M0=$(mkloop mirror0 3G); M1=$(mkloop mirror1 3G)
newpool "${P}m" "$M0 $M1" -o ashift=12 -O compression=off -O snapdev=visible -O mountpoint=none mirror "$M0" "$M1"
zfs create "${P}m/vm"
# C1 compression, under vm (D7 dumps them all)
C1_KEYS=""
for c in off lz4 zstd zstd-19 gzip-1 gzip-9 lzjb zle; do
    if zfs create -V 16M -b 16K -o compression=$c "${P}m/vm/c-$c" 2>"$WORK/out/c1-create-$c.err"; then
        C1_KEYS="$C1_KEYS $c"
        wait_dev "$(zdev "${P}m/vm/c-$c")"
        # compressible and incompressible halves
        { stream "c-$c" 6M; head -c 6M /dev/zero; stream "c-$c-2" 4M; } | dd of="$(zdev "${P}m/vm/c-$c")" bs=1M conv=notrunc,fsync status=none
    else NOT_HERE_C1="${NOT_HERE_C1:-} compression=$c"; fi
done
# C2 checksums
C2_KEYS=""
for k in fletcher2 fletcher4 sha256 sha512 skein edonr blake3; do
    if zfs create -V 16M -b 16K -o checksum=$k "${P}m/k-$k" 2>"$WORK/out/c2-create-$k.err"; then
        C2_KEYS="$C2_KEYS $k"; fill "${P}m/k-$k" 12M
    else NOT_HERE_C2="${NOT_HERE_C2:-} checksum=$k"; fi
done
# C3 volblocksize
C3_KEYS=""
for b in 4K 8K 16K 64K 128K 1M; do
    if zfs create -V 32M -b $b "${P}m/b-$b" 2>"$WORK/out/c3-create-$b.err"; then
        C3_KEYS="$C3_KEYS $b"; fill "${P}m/b-$b" 24M
    else NOT_HERE_C3="${NOT_HERE_C3:-} volblocksize=$b"; fi
done
# C4 sparse, C5 dedup, C6 snapshots and a clone, C8 large dnodes, C11 properties
zfs create -s -V 1G -b 16K "${P}m/sparse"; fill "${P}m/sparse" 64M 300
zfs create -V 32M -b 16K -o dedup=on "${P}m/dedup"
wait_dev "$(zdev "${P}m/dedup")"
{ for i in 1 2 3 4; do stream dedup 4M; done; } | dd of="$(zdev "${P}m/dedup")" bs=1M conv=notrunc,fsync status=none
zfs create -V 32M -b 16K "${P}m/snapped"; fill "${P}m/snapped" 16M
zpool sync "${P}m"; zfs snapshot "${P}m/snapped@one"
fill "${P}m/snapped" 8M 8
zpool sync "${P}m"; zfs snapshot "${P}m/snapped@two"
zfs clone "${P}m/snapped@one" "${P}m/cloned"; fill "${P}m/cloned" 4M 20
zfs create -o dnodesize=auto "${P}m/bigdnode"
zfs create -V 16M -b 16K "${P}m/bigdnode/vol"; fill "${P}m/bigdnode/vol" 8M
zfs set org.example:ticket=RW-1 compression=lz4 "${P}m/bigdnode"
zfs set org.example:ticket=RW-2 "${P}m/bigdnode/vol"
# C7 encrypted, raw key
head -c 32 /dev/urandom > "$WORK/raw.key"
zfs create -o encryption=aes-256-gcm -o keyformat=raw -o keylocation="file://$WORK/raw.key" "${P}m/secret"
zfs create -V 16M -b 16K "${P}m/secret/vol"; fill "${P}m/secret/vol" 12M
# C9 many datasets, deep nesting, a long name
zfs create "${P}m/many"
for i in $(seq 1 100); do zfs create "${P}m/many/d$i"; done
deep=${P}m/many
for i in $(seq 1 12); do deep=$deep/lvl$i; zfs create "$deep"; done
zfs create "${P}m/many/$(printf 'a-name-of-eighty-characters-%050d' 0)"
# D6 a dense volume big enough to interrupt; F7 a volume to put a hole under
zfs create -V 512M -b 16K "${P}m/big"; fill "${P}m/big" 512M
zfs create -V 16M -b 16K "${P}m/f7"; fill "${P}m/f7" 16M
# D1, D2: volumes that will be destroyed
zfs create -V 16M -b 16K "${P}m/doomed1"; fill "${P}m/doomed1" 12M
# D1 compares block by block when a block was reused: the bytes as the
# kernel read them, not only their hash.
dd if="$(zdev "${P}m/doomed1")" of="$WORK/doomed1.raw" bs=1M status=none
zfs create -V 16M -b 16K "${P}m/doomed2"; fill "${P}m/doomed2" 12M
zpool sync "${P}m"
for v in $(zfs list -H -o name -t volume -r "${P}m"); do SHA[$v]=$(oracle "$v"); done
SHA["${P}m/snapped@one"]=$(oracle "${P}m/snapped@one")
SHA["${P}m/snapped@two"]=$(oracle "${P}m/snapped@two")
# volsize is answered from the zvol's own object, not the property ZAP,
# though `zfs get` calls it local; volblocksize the other way round.
zfs get -H -s local -o name,property,value all "${P}m/bigdnode" "${P}m/bigdnode/vol" | awk -F'\t' '$2 != "volsize"' | sort > "$WORK/out/c11-zfs.txt"
zfs list -H -o name -r "${P}m" | wc -l > "$WORK/out/c9-count.txt"
# The TXG before the destroys, from the kernel's own uberblock.
TXG_BEFORE=$(zdb -u "${P}m" 2>/dev/null | sed -n 's/^[[:space:]]*txg = //p' | head -1)
[ -n "$TXG_BEFORE" ] || die "zdb -u ${P}m gave no txg"
zfs destroy "${P}m/doomed1"
export_pool "${P}m"
# D1 is checked now, before D2 writes 500 MiB into the same pool: the
# blocks of the MOS at TXG_BEFORE are free after the destroy and may be
# reused by those writes, which is D2's point and would rob D1 of its
# older TXG for no reason the scenario names.
say "D1: destroyed and exported at once"
# D1: destroyed and exported at once. The export still writes a few
# TXGs of its own, and a block the destroy freed may be reused by them
# — Debian 12's OpenZFS 2.1 did that to one block of 768 — so a partial
# image passes too, if it is the kernel's bytes with exactly the lost
# blocks zeroed and counted (exit 4).
run d1-diff -f json list -r --diff "$TXG_BEFORE" "$M0" "$M1"
if [ "$code" = 0 ] && jsonq 'names=[x["name"] for x in d["diff"]["destroyed_since"]]; assert "'"${P}m/doomed1"'" in names, names' < "$WORK/out/d1-diff.log" 2>"$WORK/out/d1-assert.err"; then
    if dump_matches d1 "${P}m/doomed1" "${SHA[${P}m/doomed1]}" "$M0" "$M1" --txg "$TXG_BEFORE"; then
        result D1 PASS "--diff $TXG_BEFORE shows it destroyed; dump --txg $TXG_BEFORE matches"
    elif [ "$code" = 4 ] && lost=$(partial_matches "$WORK/out/d1.img" "$WORK/doomed1.raw" "$WORK/out/d1-dump.log" 2>"$WORK/out/d1-partial.err"); then
        result D1 PASS "--diff $TXG_BEFORE shows it destroyed; dump --txg $TXG_BEFORE is partial: $lost to the export's own TXGs, zeroed and counted, the rest the kernel's bytes (exit 4)"
    else result D1 FAIL "dump exit $code; $(tail -1 "$WORK/out/d1-partial.err" 2>/dev/null)"; fi
else result D1 FAIL "list exit $code; $(tail -1 "$WORK/out/d1-assert.err" 2>/dev/null)"; fi

# D2: destroy, then keep writing elsewhere before exporting
# shellcheck disable=SC2046
zpool import $(import_args "${P}m") "${P}m" || die "re-import of ${P}m failed"
zfs destroy "${P}m/doomed2"
zfs create -V 600M -b 16K "${P}m/filler"; fill "${P}m/filler" 500M
zpool sync "${P}m"
for i in 1 2 3 4 5; do fill "${P}m/filler" 1M $((i * 40)); zpool sync "${P}m"; done
export_pool "${P}m"

# ---- B3: raidz1 (3), raidz2 (4), raidz3 (7); B4 corrupts a raidz2 member
say "pools: raidz1 3, raidz2 4, raidz3 7 (B3, B4)"
RZ1=""; for i in 0 1 2; do RZ1="$RZ1 $(mkloop rz1-$i 512M)"; done
RZ2=""; for i in 0 1 2 3; do RZ2="$RZ2 $(mkloop rz2-$i 512M)"; done
RZ3=""; for i in 0 1 2 3 4 5 6; do RZ3="$RZ3 $(mkloop rz3-$i 512M)"; done
# shellcheck disable=SC2086
newpool "${P}z1" "$RZ1" -o ashift=12 raidz1 $RZ1
# shellcheck disable=SC2086
newpool "${P}z2" "$RZ2" -o ashift=12 raidz2 $RZ2
# shellcheck disable=SC2086
newpool "${P}z3" "$RZ3" -o ashift=12 raidz3 $RZ3
for z in z1 z2 z3; do
    zfs create -V 64M -b 16K -o compression=lz4 "${P}$z/vol"; fill "${P}$z/vol" 48M
    SHA[$z]=$(oracle "${P}$z/vol")
    export_pool "${P}$z"
done

# ---- B5: mirror + raidz1 in one pool; B6: log and cache
say "pools: mixed tops (B5), log and cache (B6)"
X0=$(mkloop mixed0 512M); X1=$(mkloop mixed1 512M); X2=$(mkloop mixed2 512M); X3=$(mkloop mixed3 512M); X4=$(mkloop mixed4 512M)
newpool "${P}x" "$X0 $X1 $X2 $X3 $X4" -o ashift=12 mirror "$X0" "$X1" raidz1 "$X2" "$X3" "$X4"
zfs create -V 96M -b 16K "${P}x/vol"; fill "${P}x/vol" 90M
SHA[x]=$(oracle "${P}x/vol"); export_pool "${P}x"
L0=$(mkloop log0 512M); L1=$(mkloop log1 512M); LL=$(mkloop logdev 256M); LC=$(mkloop cachedev 256M)
newpool "${P}l" "$L0 $L1 $LL $LC" -o ashift=12 mirror "$L0" "$L1" log "$LL" cache "$LC"
zfs create -V 32M -b 16K -o sync=always "${P}l/vol"; fill "${P}l/vol" 24M
SHA[l]=$(oracle "${P}l/vol"); export_pool "${P}l"

# ---- B7: dRAID, when this ZFS builds one
say "pool: draid (B7)"
DR=""; for i in 0 1 2 3 4; do DR="$DR $(mkloop draid-$i 512M)"; done
# shellcheck disable=SC2086
if zpool create -f -o ashift=12 "${P}d" draid1:2d:5c:1s $DR 2>"$WORK/out/b7-create.err"; then
    HAVE_DRAID=1; POOLS="$POOLS ${P}d"; DEVS[${P}d]=$DR
    zfs create -V 64M -b 16K "${P}d/vol"; fill "${P}d/vol" 48M
    SHA[d]=$(oracle "${P}d/vol"); export_pool "${P}d"
else
    HAVE_DRAID=0
fi

# ---- B8: attach a mirror, keep a copy of the original, detach it. The
# copy carries the labels the original had as a mirror member: an older
# txg for the same top-level vdev, which `zpool detach` erases from the
# real device (vdev_label_init VDEV_LABEL_REMOVE) but not from a disk
# that was pulled before the detach.
say "pool: attach, copy, detach (B8)"
A0=$(mkloop attach0 512M); A1=$(mkloop attach1 512M)
newpool "${P}a" "$A0 $A1" -o ashift=12 "$A0"
zfs create -V 32M -b 16K "${P}a/vol"; fill "${P}a/vol" 16M
zpool attach "${P}a" "$A0" "$A1"
zpool wait -t resilver "${P}a"
export_pool "${P}a"
AOLD=$(mkloop attach-old 512M)
dd if="$A0" of="$AOLD" bs=1M conv=fsync status=none
# shellcheck disable=SC2046
zpool import $(import_args "${P}a") "${P}a" || die "re-import of ${P}a failed"
zpool detach "${P}a" "$A0"
DEVS[${P}a]=$A1
fill "${P}a/vol" 8M 16
SHA[a]=$(oracle "${P}a/vol"); export_pool "${P}a"

# ---- B9: a whole disk with a GPT, the pool in its ZFS partition. The
# GPT is written by sfdisk with the partition type ZFS itself uses —
# `zpool create` on the bare loop device labels it the same way, but
# the partition node it then expects did not appear on either kernel
# tried, and a scenario's setup must not end the run.
say "pool: whole-disk vdev with a GPT (B9)"
W=$(mkloop whole 512M -P)
echo 'type=6A898CC3-1DD2-11B2-99A6-080020736631' | sfdisk --quiet --label gpt "$W" >/dev/null
partprobe "$W" 2>/dev/null || partx -a "$W" 2>/dev/null || true
HAVE_B9=0
if wait_dev_soft "${W}p1"; then
    HAVE_B9=1
    newpool "${P}w" "${W}p1" -o ashift=12 "${W}p1"
    zfs create -V 32M -b 16K "${P}w/vol"; fill "${P}w/vol" 24M
    SHA[w]=$(oracle "${P}w/vol"); export_pool "${P}w"
fi

# ---- C10: a top-level vdev removed
say "pool: top-level vdev removed (C10)"
R0=$(mkloop remove0 512M); R1=$(mkloop remove1 512M)
newpool "${P}r" "$R0 $R1" -o ashift=12 "$R0" "$R1"
zfs create -V 96M -b 16K "${P}r/vol"; fill "${P}r/vol" 90M
zpool remove "${P}r" "$R1"
zpool wait -t remove "${P}r"
fill "${P}r/vol" 4M 90
SHA[r]=$(oracle "${P}r/vol"); export_pool "${P}r"

# ---- C12: raidz expansion (OpenZFS 2.3)
say "pool: raidz expansion (C12)"
E0=$(mkloop expand0 512M); E1=$(mkloop expand1 512M); E2=$(mkloop expand2 512M); E3=$(mkloop expand3 512M)
newpool "${P}e" "$E0 $E1 $E2" -o ashift=12 raidz1 "$E0" "$E1" "$E2"
zfs create -V 32M -b 16K "${P}e/vol"; fill "${P}e/vol" 24M
if [ "$(zpool get -H -o value feature@raidz_expansion "${P}e" 2>/dev/null)" = enabled ] \
    && zpool attach "${P}e" raidz1-0 "$E3" 2>"$WORK/out/c12-attach.err"; then
    zpool wait -t raidz_expand "${P}e"
    DEVS[${P}e]="$E0 $E1 $E2 $E3"
    fill "${P}e/vol" 4M 24
    HAVE_EXPAND=1
else
    HAVE_EXPAND=0
fi
SHA[e]=$(oracle "${P}e/vol"); export_pool "${P}e"

# ---- D3: a destroyed pool; D4, D5: labels and uberblocks damaged after export
say "pools: destroyed (D3), labels zeroed (D4), newest uberblock zeroed (D5)"
D3=$(mkloop destroyed 512M)
newpool "${P}k" "$D3" -o ashift=12 "$D3"
zfs create -V 32M -b 16K "${P}k/vol"; fill "${P}k/vol" 24M
SHA[k]=$(oracle "${P}k/vol"); zpool sync "${P}k"; zpool destroy "${P}k"; sync
D4=$(mkloop labels 512M)
newpool "${P}4" "$D4" -o ashift=12 "$D4"
zfs create -V 32M -b 16K "${P}4/vol"; fill "${P}4/vol" 24M
SHA[4]=$(oracle "${P}4/vol"); export_pool "${P}4"
dd if=/dev/zero of="$D4" bs=256K count=2 conv=notrunc,fsync status=none   # L0 and L1
D5=$(mkloop uber 512M)
newpool "${P}5" "$D5" -o ashift=12 "$D5"
zfs create -V 32M -b 16K "${P}5/vol"; fill "${P}5/vol" 24M
for i in 1 2 3; do fill "${P}5/vol" 1M $((24 + i)); zpool sync "${P}5"; done
SHA[5]=$(oracle "${P}5/vol"); export_pool "${P}5"
# The newest slot, from zdb; slots are 4 KiB at ashift 12, the ring is at
# 128 KiB into each of the four labels.
D5_SLOT=$(zdb -lu "$D5" 2>/dev/null | python3 -c '
import re,sys
best=(-1,None); slot=None
for l in sys.stdin:
    m = re.match(r"\s*Uberblock\[(\d+)\]", l)
    if m: slot=int(m.group(1)); continue
    m = re.match(r"\s*txg = (\d+)", l)
    if m and slot is not None and int(m.group(1)) > best[0]: best=(int(m.group(1)), slot)
print(best[1] if best[1] is not None else "")')
D5_TXG=$(zdb -lu "$D5" 2>/dev/null | sed -n 's/^[[:space:]]*txg = //p' | sort -n | tail -1)
D5_SIZE=$(blockdev --getsize64 "$D5")
if [ -n "$D5_SLOT" ]; then
    for base in 0 262144 $(( (D5_SIZE / 262144) * 262144 - 524288 )) $(( (D5_SIZE / 262144) * 262144 - 262144 )); do
        dd if=/dev/zero of="$D5" bs=4096 count=1 seek=$(( (base + 131072) / 4096 + D5_SLOT )) conv=notrunc,fsync status=none
    done
fi
sync

# Every device the tool will read: hashes of both ends, before (A1, G5).
ALL_DEVS=$LOOPS
declare -A EDGE
for d in $ALL_DEVS; do EDGE[$d]=$(edges "$d"); done

# ================================================================ scenarios
say "scenarios"

# A2: output on an input device
run a2 dump "${P}m/vm/c-off" "$M0" "$M1" -o "$M0"
if [ "$code" = 5 ]; then result A2 PASS "exit 5"; else result A2 FAIL "exit $code, wanted 5"; fi

# B1
b1fail=""
for a in 9 12 13; do
    eval "d=\$S$a"
    datasets_match "b1-$a" "${P}s$a" "$d" && dump_matches "b1-$a" "${P}s$a/vol" "${SHA[s$a]}" "$d" || b1fail="$b1fail $a"
done
if [ -z "$b1fail" ]; then result B1 PASS "ashift 9, 12, 13 match zdb and the kernel's hash"; else result B1 FAIL "ashift$b1fail; see out/b1-*"; fi

# B2: mirror, one member absent
if datasets_match b2 "${P}m" "$M1" && dump_matches b2 "${P}m/vm/c-lz4" "${SHA[${P}m/vm/c-lz4]}" "$M1"; then result B2 PASS "from $M1 alone"; else result B2 FAIL "see out/b2-*"; fi

# B3: raidz with nparity members absent
b3fail=""
for z in z1:1 z2:2 z3:3; do
    n=${z#*:}; z=${z%:*}
    eval "devs=\$RZ${z#z}"
    # shellcheck disable=SC2086
    keep=$(echo $devs | tr ' ' '\n' | head -n -"$n" | tr '\n' ' ')
    # shellcheck disable=SC2086
    datasets_match "b3-$z" "${P}$z" $keep && dump_matches "b3-$z" "${P}$z/vol" "${SHA[$z]}" $keep || b3fail="$b3fail $z"
done
if [ -z "$b3fail" ]; then result B3 PASS "raidz1/2/3 with nparity members absent"; else result B3 FAIL "$b3fail"; fi

# B4: a raidz2 member silently corrupted over 1 MiB of the volume's own
# blocks: the first L0 block's DVA from zdb, spread over the four columns
# (a member holds a quarter of the vdev's address space, after the 4 MiB
# of labels), and 1 MiB from there on member 0.
# shellcheck disable=SC2086
set -- $RZ2
b4_dva=$(zdb -e -p "$WORK/img" -dddddd "${P}z2/vol" 1 2>/dev/null | python3 -c '
import re,sys
for l in sys.stdin:
    m = re.search(r"\bL0 (\d+):([0-9a-f]+):([0-9a-f]+)\b", l)
    if m and m.group(1) == "0":
        print(int(m.group(2), 16)); break')
b4_at=$(( ${b4_dva:-33554432} / 4 + 4194304 ))
dd if=/dev/urandom of="$1" bs=1M count=1 seek=$(( b4_at / 1048576 )) conv=notrunc,fsync status=none
EDGE[$1]=$(edges "$1")
rm -f "$WORK/out/b4.img"
"$ZR" --evidence-log "$EV" -f json dump "${P}z2/vol" "$@" -o "$WORK/out/b4.img" --debug-log "$WORK/out/b4-debug.log" > "$WORK/out/b4-dump.log" 2>"$WORK/out/b4-dump.err"; code=$?
got=$(jsonq 'print(d["volumes"][0]["sha256"])' < "$WORK/out/b4-dump.log" 2>/dev/null)
rebuilt=$(grep -c "rebuilt\|reconstruct" "$WORK/out/b4-debug.log" 2>/dev/null)
if [ "$code" = 0 ] && [ "$got" = "${SHA[z2]}" ] && [ "${rebuilt:-0}" -gt 0 ]; then
    result B4 PASS "healed; $rebuilt reconstruction notes in the trace"
else
    result B4 FAIL "exit $code, hash $got, wanted ${SHA[z2]}; $rebuilt reconstruction notes in the trace"
fi

# B5, B6
if datasets_match b5 "${P}x" "$X0" "$X1" "$X2" "$X3" "$X4" && dump_matches b5 "${P}x/vol" "${SHA[x]}" "$X0" "$X1" "$X2" "$X3" "$X4" \
    && dump_matches b5-degraded "${P}x/vol" "${SHA[x]}" "$X1" "$X2" "$X3"; then result B5 PASS "mirror + raidz1, also with one member of each absent"; else result B5 FAIL "see out/b5-*"; fi
run b6-scan -f json scan "$L0" "$L1" "$LL" "$LC"
if [ "$code" = 0 ] && dump_matches b6 "${P}l/vol" "${SHA[l]}" "$L0" "$L1"; then result B6 PASS "scan of log and cache exit 0; dump without them matches"; else result B6 FAIL "scan exit $code; see out/b6-*"; fi

# B7
if [ "$HAVE_DRAID" = 1 ]; then
    # shellcheck disable=SC2086
    set -- $DR
    if datasets_match b7 "${P}d" "$@" && dump_matches b7 "${P}d/vol" "${SHA[d]}" "$@" && dump_matches b7-degraded "${P}d/vol" "${SHA[d]}" "$2" "$3" "$4" "$5"; then
        result B7 PASS "draid1:2d:5c:1s, also with one member absent"
    else result B7 FAIL "see out/b7-*"; fi
else result B7 SKIP "this zpool does not create draid ($(head -c 120 "$WORK/out/b7-create.err" | tr '\n' ' '))"; fi

# B8: the copy of the detached original is set aside, not mixed in
run b8-scan -f json scan "$AOLD" "$A1"
if [ "$code" = 0 ] && jsonq '
p=d["pools"][0]; assert p["stale"] and p["stale"][0]["device"]=="'"$AOLD"'", p["stale"]
assert [m["present"] for t in p["tops"] for m in t["members"]] == ["'"$A1"'"], p["tops"]' < "$WORK/out/b8-scan.log" 2>"$WORK/out/b8-assert.err" \
    && dump_matches b8 "${P}a/vol" "${SHA[a]}" "$AOLD" "$A1"; then
    result B8 PASS "the older copy is stale; dump from both matches the pool after the detach"
else result B8 FAIL "scan exit $code; $(tail -1 "$WORK/out/b8-assert.err" 2>/dev/null)"; fi

# B9: the whole disk, and its partition
run b9-scan -f json scan "$W"
if [ "$HAVE_B9" = 0 ]; then result B9 FAIL "the partition node ${W}p1 never appeared after sfdisk wrote the GPT"
elif [ "$code" = 0 ] && jsonq '
x=d["devices"][0]; t=x["partitions"]; assert t["scheme"]=="gpt", t
assert any(p["zfs"] for p in t["partitions"]), t; assert x["vdev_base"]>0, x' < "$WORK/out/b9-scan.log" 2>"$WORK/out/b9-assert.err" \
    && dump_matches b9 "${P}w/vol" "${SHA[w]}" "$W" && dump_matches b9-part "${P}w/vol" "${SHA[w]}" "${W}p1"; then
    result B9 PASS "GPT found on the whole disk; dump from the disk and from p1 match"
else result B9 FAIL "scan exit $code; $(tail -1 "$WORK/out/b9-assert.err" 2>/dev/null)"; fi

# C1, C2, C3: one dump per property value
# What this ZFS does not have is said, not counted either way.
here() { [ -z "$1" ] || printf '; not in this ZFS:%s' "$1"; }
cfail=""
for c in $C1_KEYS; do dump_matches "c1-$c" "${P}m/vm/c-$c" "${SHA[${P}m/vm/c-$c]}" "$M0" "$M1" || cfail="$cfail $c"; done
if [ -z "$cfail" ]; then result C1 PASS "$(echo $C1_KEYS | wc -w) compressions$(here "$NOT_HERE_C1")"; else result C1 FAIL "$cfail"; fi
cfail=""
for k in $C2_KEYS; do dump_matches "c2-$k" "${P}m/k-$k" "${SHA[${P}m/k-$k]}" "$M0" "$M1" || cfail="$cfail $k"; done
if [ -z "$cfail" ]; then result C2 PASS "$(echo $C2_KEYS | wc -w) checksums$(here "$NOT_HERE_C2")"; else result C2 FAIL "$cfail"; fi
cfail=""
for b in $C3_KEYS; do dump_matches "c3-$b" "${P}m/b-$b" "${SHA[${P}m/b-$b]}" "$M0" "$M1" || cfail="$cfail $b"; done
if [ -z "$cfail" ]; then result C3 PASS "$(echo $C3_KEYS | wc -w) block sizes$(here "$NOT_HERE_C3")"; else result C3 FAIL "$cfail"; fi

# C4: sparse image
if dump_matches c4 "${P}m/sparse" "${SHA[${P}m/sparse]}" "$M0" "$M1"; then
    used=$(du -B1 "$WORK/out/c4.img" | awk '{print $1}')
    if [ "$used" -lt $((200 * 1048576)) ]; then result C4 PASS "1 GiB image uses $used bytes on disk"; else result C4 FAIL "image not sparse: $used bytes"; fi
else result C4 FAIL "see out/c4-*"; fi

# C5, C6, C7, C8
if dump_matches c5 "${P}m/dedup" "${SHA[${P}m/dedup]}" "$M0" "$M1"; then result C5 PASS "dedup=on"; else result C5 FAIL "see out/c5-*"; fi
if dump_matches c6-one "${P}m/snapped@one" "${SHA[${P}m/snapped@one]}" "$M0" "$M1" && dump_matches c6-two "${P}m/snapped@two" "${SHA[${P}m/snapped@two]}" "$M0" "$M1" \
    && dump_matches c6-head "${P}m/snapped" "${SHA[${P}m/snapped]}" "$M0" "$M1" && dump_matches c6-clone "${P}m/cloned" "${SHA[${P}m/cloned]}" "$M0" "$M1"; then
    result C6 PASS "two snapshots, the head and a clone each match"
else result C6 FAIL "see out/c6-*"; fi
rm -f "$WORK/out/c7.img"
run c7-dump -f json dump "${P}m/secret/vol" "$M0" "$M1" -o "$WORK/out/c7.img" --key "raw:$WORK/raw.key"
got=$(jsonq 'print(d["volumes"][0]["sha256"])' < "$WORK/out/c7-dump.log" 2>/dev/null)
run c7-nokey -f json dump "${P}m/secret/vol" "$M0" "$M1" -o "$WORK/out/c7-nokey.img"; nokey=$code
if [ "$got" = "${SHA[${P}m/secret/vol]}" ] && [ "$nokey" = 1 ] && grep -q "is encrypted (aes-256-gcm" "$WORK/out/c7-nokey.log.err" && grep -q "supply --key" "$WORK/out/c7-nokey.log.err" && [ ! -s "$WORK/out/c7-nokey.img" ]; then
    result C7 PASS "aes-256-gcm with the raw key; without one a refusal naming the suite (exit 1), nothing written"
else result C7 FAIL "with key: $got (wanted ${SHA[${P}m/secret/vol]}); without: exit $nokey"; fi
if dump_matches c8 "${P}m/bigdnode/vol" "${SHA[${P}m/bigdnode/vol]}" "$M0" "$M1"; then result C8 PASS "dnodesize=auto parent"; else result C8 FAIL "see out/c8-*"; fi

# C9: every dataset, and at least the count the kernel gave
if datasets_match c9 "${P}m" "$M0" "$M1" && [ "$(wc -l < "$WORK/out/c9-zr.txt")" -ge "$(cat "$WORK/out/c9-count.txt")" ]; then
    result C9 PASS "$(wc -l < "$WORK/out/c9-zr.txt") datasets match zdb -d"
else result C9 FAIL "see out/c9-*"; fi

# C10: the removed vdev
run c10-scan -f json scan "$R0" "$R1"
if [ "$code" = 0 ] && jsonq 'p=d["pools"][0]; assert p["readable"] and p["removed_tops"]==[1] and p["missing_tops"]==[], p' < "$WORK/out/c10-scan.log" 2>"$WORK/out/c10-assert.err" \
    && dump_matches c10 "${P}r/vol" "${SHA[r]}" "$R0" "$R1" && datasets_match c10 "${P}r" "$R0" "$R1"; then
    result C10 PASS "vdev 1 removed, blocks read through the mapping"
else result C10 FAIL "scan exit $code; $(tail -1 "$WORK/out/c10-assert.err" 2>/dev/null)"; fi

# C11: exactly the local properties. `volblocksize` is in the volume's
# property ZAP (set once at creation) but `zfs get` shows its source as
# `-`, not `local`, so it is left out of the comparison on the tool's side.
run c11 -f json list -r --properties "$M0" "$M1"
jsonq '
for x in d["datasets"]:
    if x["name"] in ("'"${P}m/bigdnode"'", "'"${P}m/bigdnode/vol"'"):
        for p in x.get("properties") or []:
            if p["name"] != "volblocksize": print(x["name"], p["name"], p["value"])' < "$WORK/out/c11.log" 2>/dev/null | sort > "$WORK/out/c11-zr.txt"
if [ "$code" = 0 ] && diff <(awk '{print $1, $2}' "$WORK/out/c11-zfs.txt") <(awk '{print $1, $2}' "$WORK/out/c11-zr.txt") > "$WORK/out/c11-diff.txt" \
    && grep -q "org.example:ticket RW-2" "$WORK/out/c11-zr.txt"; then
    result C11 PASS "$(wc -l < "$WORK/out/c11-zr.txt") local properties, the same set as zfs get -s local"
else result C11 FAIL "see out/c11-diff.txt"; fi

# C12: the expanded raidz is refused by name
if [ "$HAVE_EXPAND" = 1 ]; then
    run c12-list list -r "$E0" "$E1" "$E2" "$E3"; l=$code
    run c12-scan scan "$E0" "$E1" "$E2" "$E3"; s=$code
    run c12-ignore -f json list -r --ignore-unknown-features "$E0" "$E1" "$E2" "$E3"; g=$code
    if [ "$l" = 3 ] && grep -q "raidz_expansion" "$WORK/out/c12-list.log.err" && [ "$s" = 0 ] && grep -q "raidz_expansion" "$WORK/out/c12-scan.log" && [ "$g" = 0 ]; then
        result C12 PASS "list exit 3 naming raidz_expansion; scan exit 0; --ignore-unknown-features reads"
    else result C12 FAIL "list $l, scan $s, ignore $g"; fi
else result C12 SKIP "raidz_expansion not available in this ZFS (needs OpenZFS 2.3)"; fi

# D2: destroyed, then 500 MiB written elsewhere over several TXGs. Four
# honest answers: whole from an older TXG; named at no TXG left in the
# ring; named at one whose object set the writes reused, readable at
# none (exit 3 either way); or an older MOS intact but data blocks
# reused, zeroed and counted (exit 4).
rm -f "$WORK/out/d2.img"
run d2 -f json dump "${P}m/doomed2" "$M0" "$M1" -o "$WORK/out/d2.img"
got=$(jsonq 'print(d["volumes"][0]["sha256"])' < "$WORK/out/d2.log" 2>/dev/null)
zeroed=$(jsonq 'v=d["volumes"][0]; print(v["blocks_zeroed"], "of", v["blocks_total"])' < "$WORK/out/d2.log" 2>/dev/null)
unreadable=$(jsonq 'print(" ".join(str(u["txg"]) for u in d.get("unreadable_at", [])))' < "$WORK/out/d2.log" 2>/dev/null)
if [ "$code" = 0 ] && [ "$got" = "${SHA[${P}m/doomed2]}" ]; then result D2 PASS "recovered whole from an older TXG"
elif [ "$code" = 3 ] && grep -q "not found at any of" "$WORK/out/d2.log.err"; then result D2 PASS "a clean 'not found at any of N verified TXGs' (exit 3)"
elif [ "$code" = 3 ] && [ -n "$unreadable" ] && grep -q "object set does not read there" "$WORK/out/d2.log.err"; then result D2 PASS "named at txg $unreadable, object set reused by the later writes, readable at no older TXG: a clean exit 3 naming it"
elif [ "$code" = 4 ] && [ -n "$zeroed" ]; then result D2 PASS "the MOS of an older TXG survived but the data was reused: partial image, $zeroed blocks zeroed and counted (exit 4)"
else result D2 FAIL "exit $code, hash $got"; fi

# D3: destroyed pool
run d3-scan -f json scan "$D3"
if [ "$code" = 0 ] && jsonq 'assert d["devices"][0]["config"]["state"]=="DESTROYED", d["devices"][0]["config"]' < "$WORK/out/d3-scan.log" 2>"$WORK/out/d3-assert.err" \
    && dump_matches d3 "${P}k/vol" "${SHA[k]}" "$D3"; then result D3 PASS "state DESTROYED; dump matches"
else result D3 FAIL "scan exit $code; $(tail -1 "$WORK/out/d3-assert.err" 2>/dev/null)"; fi

# D4: L0 and L1 zeroed (whether the kernel still imports it is checked
# after A1, since an import writes)
run d4-scan -f json scan "$D4"
if [ "$code" = 0 ] && jsonq 'ls=d["devices"][0]["labels"]; ok=[l["config_checksum"]=="ok" for l in ls]; assert ok[:2]==[False,False] and ok[2:]==[True,True], ls' < "$WORK/out/d4-scan.log" 2>"$WORK/out/d4-assert.err" \
    && dump_matches d4 "${P}4/vol" "${SHA[4]}" "$D4"; then d4=PASS
else d4=FAIL; fi

# D5: the newest uberblock slot zeroed in all four labels
if [ -n "$D5_SLOT" ]; then
    run d5 -f json list -r "$D5"
    used=$(jsonq 'print(d["txg"])' < "$WORK/out/d5.log" 2>/dev/null)
    if [ "$code" = 0 ] && [ -n "$used" ] && [ "$used" -lt "$D5_TXG" ] && dump_matches d5 "${P}5/vol" "${SHA[5]}" "$D5"; then
        result D5 PASS "txg $used used instead of the zeroed $D5_TXG (slot $D5_SLOT); dump matches the last state"
    else result D5 FAIL "list exit $code, txg ${used:-?}, newest was $D5_TXG"; fi
else result D5 FAIL "could not find the newest uberblock slot with zdb -lu"; fi

# D6: SIGINT part-way, then --resume. The signal ends the run at the
# next block with its state written (F-32, exit 6). Job control is
# turned on for the launch so the background job does not inherit
# SIGINT ignored, as a non-interactive shell's background jobs do.
rm -f "$WORK/out/d6.img" "$WORK/out/d6.img.resume.json"
set -m
"$ZR" --evidence-log "$EV" -f json dump "${P}m/big" "$M0" "$M1" -o "$WORK/out/d6.img" > "$WORK/out/d6-first.log" 2>"$WORK/out/d6-first.err" &
pid=$!
set +m
for _ in $(seq 1 6000); do
    sz=$(stat -c %s "$WORK/out/d6.img" 2>/dev/null || echo 0)
    [ "$sz" -ge $((128 * 1048576)) ] && break
    kill -0 $pid 2>/dev/null || break
    sleep 0.005
done
if kill -0 $pid 2>/dev/null; then
    kill -INT $pid; wait $pid; first=$?
    at=$(jsonq 'print(d["volumes"][0]["interrupted_at"])' < "$WORK/out/d6-first.log" 2>/dev/null)
    state=$(python3 -c 'import json; print(json.load(open("'"$WORK/out/d6.img.resume.json"'"))["blocks_done"])' 2>/dev/null)
    run d6 -f json dump "${P}m/big" "$M0" "$M1" -o "$WORK/out/d6.img" --resume
    from=$(jsonq 'print(d["volumes"][0]["resumed_from_block"])' < "$WORK/out/d6.log" 2>/dev/null)
    got=$(jsonq 'print(d["volumes"][0]["sha256"])' < "$WORK/out/d6.log" 2>/dev/null)
    if [ "$first" = 6 ] && [ -n "$at" ] && [ "$state" = "$at" ] && [ "$code" = 0 ] && [ "${from:-0}" = "$at" ] && [ "$got" = "${SHA[${P}m/big]}" ] && [ "$(sha_of "$WORK/out/d6.img")" = "${SHA[${P}m/big]}" ]; then
        result D6 PASS "SIGINT after $((sz / 1048576)) MiB: exit 6, interrupted at block $at, state file agrees, resumed there, hash matches"
    else result D6 FAIL "first exit $first, interrupted_at ${at:-?}, state ${state:-?}, resume exit $code from ${from:-?}, hash $got"; fi
else
    wait $pid; first=$?
    result D6 FAIL "the 512 MiB dump finished (exit $first) before 128 MiB were seen on disk; nothing was interrupted"
fi

# D7: recursive dump of vm/ (images are named after the dataset, / as _)
rm -rf "$WORK/out/d7"
run d7 -f json dump -r "${P}m/vm" "$M0" "$M1" -o "$WORK/out/d7"
d7fail=""
for c in $C1_KEYS; do
    f=$WORK/out/d7/${P}m_vm_c-$c.img
    [ -f "$f" ] && [ "$(sha_of "$f")" = "${SHA[${P}m/vm/c-$c]}" ] || d7fail="$d7fail $c"
done
if [ "$code" = 0 ] && [ -f "$WORK/out/d7/manifest.json" ] && [ -z "$d7fail" ]; then result D7 PASS "$(echo $C1_KEYS | wc -w) images + manifest, every hash matches"
else result D7 FAIL "exit $code; mismatched:$d7fail"; fi

# D8: md5 and sha1 alongside
rm -f "$WORK/out/d8.img"
run d8 -f json dump "${P}m/k-sha256" "$M0" "$M1" -o "$WORK/out/d8.img" --hash md5,sha1
if [ "$code" = 0 ] && jsonq '
v=d["volumes"][0]; import subprocess
def h(t): return subprocess.run([t, "'"$WORK/out/d8.img"'"], capture_output=True, text=True).stdout.split()[0]
assert v["sha256"]==h("sha256sum") and v["sha1"]==h("sha1sum") and v["md5"]==h("md5sum"), v' < "$WORK/out/d8.log" 2>"$WORK/out/d8-assert.err"; then
    result D8 PASS "sha256, sha1 and md5 equal the coreutils digests"
else result D8 FAIL "exit $code; $(tail -1 "$WORK/out/d8-assert.err" 2>/dev/null)"; fi

# F7: dm-error under one member of the mirror, over the first data block
# of f7 (its DVA from zdb; a mirror child's byte offset is the DVA offset
# plus the 4 MiB the labels take).
say "F7: dm-error under $M0"
f7_dva=$(zdb -e -p "$WORK/img" -dddddd "${P}m/f7" 1 2>/dev/null | python3 -c '
import re,sys
for l in sys.stdin:
    m = re.search(r"\bL0 (\d+):([0-9a-f]+):([0-9a-f]+)\b", l)
    if m and m.group(1) == "0":
        print(int(m.group(2), 16)); break')
if [ -n "$f7_dva" ]; then
    bad=$(( (f7_dva + 4194304) / 512 ))
    size=$(blockdev --getsz "$M0")
    printf '0 %s linear %s 0\n%s 8 error\n%s %s linear %s %s\n' "$bad" "$M0" "$bad" "$((bad+8))" "$((size-bad-8))" "$M0" "$((bad+8))" | dmsetup create zr-bad
    dev=/dev/mapper/zr-bad; real=$(readlink -f "$dev")
    run f7-stop dump "${P}m/f7" "$dev" "$M1" -o "$WORK/out/f7-stop.img"; stop=$code
    if [ "$HAVE_STRACE" = 1 ]; then
        strace -f -y -e trace=pread64 -o "$WORK/out/f7-trace.txt" "$ZR" --evidence-log "$EV" -f json dump "${P}m/f7" "$dev" "$M1" -o "$WORK/out/f7-heal.img" --device-may-fail > "$WORK/out/f7-heal.log" 2>"$WORK/out/f7-heal.err"; heal=$?
    else
        run f7-heal -f json dump "${P}m/f7" "$dev" "$M1" -o "$WORK/out/f7-heal.img" --device-may-fail; heal=$code
    fi
    dmsetup remove zr-bad
    f7ok=1
    { [ "$stop" = 7 ] && grep -q "MEDIUM INCIDENT: $dev refused .* (LBA $bad, " "$WORK/out/f7-stop.log.err"; } || f7ok=0
    { [ "$heal" = 0 ] && [ "$(sha_of "$WORK/out/f7-heal.img")" = "${SHA[${P}m/f7]}" ]; } || f7ok=0
    REAL="$real" DEV="$dev" EV="$EV" TRACE="$WORK/out/f7-trace.txt" BAD="$bad" HAVE_STRACE="$HAVE_STRACE" python3 - > "$WORK/out/f7-check.txt" 2>&1 <<'EOF' || f7ok=0
import json, os, re
recs = [json.loads(l) for l in open(os.environ["EV"]) if l.strip()]
stop, heal = recs[-2], recs[-1]
si, hi = stop.get("incidents", []), heal.get("incidents", [])
assert stop["status"] == 7 and len(si) == 1 and si[0]["stopped"], (stop["status"], si)
assert si[0]["lba"] == int(os.environ["BAD"]), si[0]
assert heal["status"] == 0 and len(hi) == 1 and not hi[0]["stopped"], (heal["status"], hi)
if os.environ["HAVE_STRACE"] == "1":
    pat = re.compile(r'pread64\(\d+<(?:' + re.escape(os.environ["DEV"]) + '|' + re.escape(os.environ["REAL"]) + r')>, .*, (\d+), (\d+)\) = ')
    reads = sorted((int(m.group(2)), int(m.group(1))) for m in map(pat.search, open(os.environ["TRACE"])) if m)
    assert reads, "no read of the device seen in the trace"
    twice = [(a, b) for a, b in zip(reads, reads[1:]) if b[0] < a[0] + a[1]]
    assert not twice, f"an address on the device was read twice: {twice}"
    print(f"{len(reads)} reads of the device, none overlapping")
print("ok")
EOF
    if [ "$f7ok" = 1 ]; then result F7 PASS "stop exit 7 at LBA $bad; --device-may-fail heals from $M1; $(grep -v '^ok$' "$WORK/out/f7-check.txt" | tail -1)"
    else result F7 FAIL "stop exit $stop, heal exit $heal; $(tail -1 "$WORK/out/f7-check.txt")"; fi
else result F7 FAIL "could not find the volume's first L0 block with zdb"; fi

# A3: an unprivileged user with read access to the devices (a copy of the
# binary it can reach, no evidence log it could not write)
if ! id nobody >/dev/null 2>&1; then result A3 SKIP "no user nobody"
else
    cp "$ZR" "$WORK/zvolrescue-for-nobody"; chmod 755 "$WORK/zvolrescue-for-nobody"; chmod o+rx "$WORK"
    if ! runuser -u nobody -- test -x "$WORK/zvolrescue-for-nobody"; then
        result A3 SKIP "$WORK is not reachable by nobody (a parent directory is not world-traversable); use a directory under /var/tmp"
    else
        chmod o+r "$M0" "$M1"
        if (cd / && runuser -u nobody -- "$WORK/zvolrescue-for-nobody" -q -f json list -r "$M0" "$M1") > "$WORK/out/a3.log" 2>"$WORK/out/a3.err"; then
            result A3 PASS "list as nobody, with read access to the two devices and nothing else"
        else result A3 FAIL "exit $?: $(tail -1 "$WORK/out/a3.err")"; fi
        chmod o-r "$M0" "$M1"
    fi
fi

# A1, G5: nothing on any device changed; then the kernel still imports
# every pool (an import writes, so it comes after the comparison).
changed=""
for d in $ALL_DEVS; do [ "$(edges "$d")" = "${EDGE[$d]}" ] || changed="$changed $d"; done
imports=""
for p in $POOLS; do
    case $p in "${P}k"|"${P}4"|"${P}5") continue ;; esac
    # shellcheck disable=SC2046
    if zpool import $(import_args "$p") -N "$p" >/dev/null 2>"$WORK/out/import-$p.err"; then zpool export "$p" 2>/dev/null || { sleep 2; zpool export "$p"; }; else imports="$imports $p"; fi
done
if [ -z "$changed" ] && [ -z "$imports" ]; then result A1 PASS "every device's ends unchanged; every pool still imports"
else result A1 FAIL "changed:$changed; do not import:$imports"; fi
if [ -z "$changed" ]; then result G5 PASS "inputs unchanged"; else result G5 FAIL "changed:$changed"; fi
if zpool import -d "$D4" -N "${P}4" >/dev/null 2>&1; then zpool export "${P}4"; d4import="zpool import still works (L2/L3)"; else d4import="zpool import fails"; fi
if [ "$d4" = PASS ]; then result D4 PASS "L2/L3 used; dump matches; $d4import"
else result D4 FAIL "scan or dump; $(tail -1 "$WORK/out/d4-assert.err" 2>/dev/null); $d4import"; fi

# The case file, checked back (D8's second half; COMPANIONS R-01…R-07)
if [ -x "$REPORT" ]; then
    if "$REPORT" build "$EV" -o "$WORK/report.md" >/dev/null 2>"$WORK/out/report.err" && "$REPORT" verify "$WORK/report.md" >"$WORK/out/verify.txt" 2>&1; then
        result R PASS "zvolreport build + verify over $(wc -l < "$EV") records"
    else result R FAIL "$(tail -1 "$WORK/out/verify.txt" "$WORK/out/report.err" 2>/dev/null | tail -1)"; fi
fi

# ================================================================ the row
say "summary"
os=$(. /etc/os-release && echo "$PRETTY_NAME")
mark="☑"; [ -z "$FAILED" ] || mark="✗"
note="tests/realworld/debian-loop.sh, kernel $(uname -r)"
[ -z "$FAILED" ] || note="$note; failed:$FAILED"
[ -z "$SKIPPED" ] || note="$note; skipped:$SKIPPED"
# shellcheck disable=SC2086
printf '| %s | %s (%s, loop devices) | %s | `%s` | %s | %s | %s |\n' "$(date -u +%Y-%m-%d)" "$os" "$MODULE_FROM" "$ZFS_VER" "$TOOL_VER" "$(echo $PASSED)" "$mark" "$note" | tee "$WORK/row.md"
echo "passed:$PASSED"
echo "failed:$FAILED"
echo "skipped:$SKIPPED"
[ -z "$FAILED" ]
