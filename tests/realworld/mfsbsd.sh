#!/bin/sh
# E3 on the rescue medium itself (docs/REALWORLD-TESTS.md): mfsBSD, a
# FreeBSD that lives in RAM, two raw disks its own kernel made a pool
# on, and the static binary built on FreeBSD 15 copied in — the way the
# tool reaches a machine with no system left to install anything on.
#
#   sh tests/realworld/mfsbsd.sh WORKDIR ZVOLRESCUE DISK0 DISK1
#
# Runs as root on mfsBSD (or any FreeBSD with a kernel ZFS) with /bin/sh
# and the base system alone: no bash, python or packages, which the
# rescue image does not have. WORKDIR is created on a tmpfs when it does
# not exist yet — mfsBSD's root is a memory disk with little room, and a
# rescue system has no disk of its own to write to. DISK0 and DISK1 are
# overwritten: a mirror pool is made on them, a volume filled, the pool
# exported, and the tool reads them as the devices they are. Nothing
# else on the machine is touched; the pool's name begins with zrw, like
# the matrix's pools, and the script refuses to start if one does.
#
# Output as kernel-matrix.sh gives it: WORKDIR/results.txt (one line per
# check), env.txt, evidence.jsonl, row.md (the Results row), out/*.log.
# Exit 0 when every check passed.
#
# What it covers: E3 (the binary built on 15 runs here: version, scan,
# list, and a dump whose hash is the kernel's), A1 and G5 (the disks
# unchanged to the byte at both ends, the pool importable afterwards)
# and R (zvolreport over the run's evidence, when it is beside the
# binary).
set -u

WORK=${1:?work directory}
ZR=${2:?path to zvolrescue}
D0=${3:?first disk}
D1=${4:?second disk}
P=zrw   # pool name prefix, shared with kernel-matrix.sh
POOL=${P}e
VOL=$POOL/vol
VOLSIZE=128M
FILL=96   # MiB of data written at the volume's start; the rest stays a hole

say() { printf '\n== %s\n' "$*"; }
die() { printf 'mfsbsd: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
[ "$(uname -s)" = FreeBSD ] || die "this is for FreeBSD (mfsBSD); the matrix is kernel-matrix.sh"
for c in zpool zfs sha256 diskinfo openssl; do command -v "$c" >/dev/null || die "$c not found"; done
for d in "$D0" "$D1"; do [ -c "$d" ] || die "$d is not a character device"; done
[ "$D0" != "$D1" ] || die "the two disks are the same device"
if zpool list -H -o name 2>/dev/null | grep -q "^$P"; then
    die "a pool named $P* is already imported; this script only ever creates and destroys those, so export or destroy it first"
fi

# A rescue system's root is a memory disk with little free room; the
# image and the logs go to a tmpfs of their own unless a directory is
# already there to take them.
if [ ! -d "$WORK" ]; then
    mkdir -p "$WORK"
    mount -t tmpfs tmpfs "$WORK" || die "cannot mount a tmpfs at $WORK"
fi
WORK=$(cd "$WORK" && pwd)
mkdir -p "$WORK/out"
EV=$WORK/evidence.jsonl
: > "$WORK/results.txt"
: > "$EV"
ZR=$(cd "$(dirname "$ZR")" && pwd)/$(basename "$ZR")
REPORT=$(dirname "$ZR")/zvolreport
chmod +x "$ZR" 2>/dev/null
[ -x "$ZR" ] || die "$ZR is not executable"

# ---------------------------------------------------------------- environment
# mfsBSD is FreeBSD booted from a memory disk: its root is /dev/ufs/mfsroot
# (or an md), and the loader carries its mfsbsd.* variables.
ROOTFS=$(df / | awk 'NR == 2 { print $1 }')
if kenv -q mfsbsd.autodhcp >/dev/null 2>&1 || [ "$(hostname)" = mfsbsd ]; then FLAVOR=mfsBSD; else FLAVOR=FreeBSD; fi
REL=$(freebsd-version -k 2>/dev/null || uname -r)
FILE_SAYS=$(file -b "$ZR" 2>/dev/null || echo "file not available")
{
    echo "date: $(date -u +%Y-%m-%d)"
    echo "os: $FLAVOR $REL ($(uname -sr), root on $ROOTFS)"
    echo "kernel: $(uname -r)"
    echo "zfs: $(zfs version 2>/dev/null | tr '\n' ' ')"
    echo "tool: $("$ZR" --version)"
    echo "binary: $FILE_SAYS"
    echo "disks: $D0 $(diskinfo "$D0" | awk '{print $3}') bytes, $D1 $(diskinfo "$D1" | awk '{print $3}') bytes"
} | tee "$WORK/env.txt"
ZFS_VER=$(zfs version 2>/dev/null | sed -n 's/^zfs-\([0-9][0-9.]*\).*/\1/p' | head -n 1)
TOOL_VER=$("$ZR" --version | awk '{print $2}')
# The branch the binary was built for, as its ELF header says it.
BUILT_FOR=$(echo "$FILE_SAYS" | sed -n 's/.*for \(FreeBSD [0-9][0-9.]*\).*/\1/p')

# ---------------------------------------------------------------- helpers
PASSED=""; FAILED=""
result() { # result ID PASS|FAIL note
    printf '%s %s %s\n' "$1" "$2" "$3" | tee -a "$WORK/results.txt"
    case $2 in
        PASS) PASSED="$PASSED $1" ;;
        FAIL) FAILED="$FAILED $1" ;;
    esac
}
run() { # run LOG ARGS... — the tool with the evidence log; exit code in $code
    log=$WORK/out/$1.log; shift
    "$ZR" --evidence-log "$EV" "$@" >"$log" 2>"$log.err"; code=$?
}
# Hash of the first and last 4 MiB of a disk (A1, G5).
edges() { { dd if="$1" bs=1M count=4 status=none; dd if="$1" bs=1M skip=$(( $(diskinfo "$1" | awk '{print $3}') / 1048576 - 4 )) status=none; } | sha256 -q; }
cleanup() {
    set +e
    zpool list -H -o name "$POOL" >/dev/null 2>&1 && zpool destroy "$POOL"
}
trap cleanup EXIT

# ---------------------------------------------------------------- the pool
say "pool: $POOL, a mirror of $D0 and $D1, made by this kernel"
zpool create -f -o ashift=12 -O compression=off "$POOL" mirror "$D0" "$D1" || die "zpool create failed"
zfs create -V "$VOLSIZE" -o volblocksize=16k "$VOL" || die "zfs create -V failed"
dev=/dev/zvol/$VOL
i=0; while [ ! -e "$dev" ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done
[ -e "$dev" ] || die "$dev did not appear"
# Deterministic bytes (an AES-CTR keystream), incompressible either way;
# the volume's tail stays a hole.
key=$(printf 'zvolrescue-mfsbsd-2026' | openssl dgst -sha256 | awk '{print $NF}')
head -c $(( FILL * 1048576 )) /dev/zero | openssl enc -aes-256-ctr -K "$key" -iv 00000000000000000000000000000000 2>/dev/null | dd of="$dev" bs=1M status=none || die "writing the volume failed"
zpool sync "$POOL"
# The oracle: the volume as the kernel reads it back, holes as zeros.
KERNEL_SHA=$(dd if="$dev" bs=1M status=none | sha256 -q)
echo "kernel's hash of $VOL: $KERNEL_SHA"
zpool export "$POOL" || die "zpool export failed"
sync

# Both ends of both disks, before the tool reads them (A1, G5).
E0=$(edges "$D0"); E1=$(edges "$D1")

# ---------------------------------------------------------------- E3
say "E3: the binary built on ${BUILT_FOR:-FreeBSD 15} on this $FLAVOR"
e3=PASS; why=""
case $FILE_SAYS in
    *"statically linked"*|*"static-pie linked"*) ;;
    "file not available") why="$why; file(1) is not here to confirm the binary is static" ;;
    *) e3=FAIL; why="$why; not static: $FILE_SAYS" ;;
esac
run version --version
[ "$code" = 0 ] && grep -q '^zvolrescue [0-9]' "$WORK/out/version.log" || { e3=FAIL; why="$why; --version exit $code"; }
run scan scan "$D0" "$D1"
if [ "$code" != 0 ] || ! grep -q "^pool \"$POOL\" guid 0x[0-9a-f]*: state EXPORTED.*READABLE from scanned members" "$WORK/out/scan.log" \
    || ! grep -q "present: $D0\$" "$WORK/out/scan.log" || ! grep -q "present: $D1\$" "$WORK/out/scan.log"; then
    e3=FAIL; why="$why; scan exit $code: $(grep '^pool ' "$WORK/out/scan.log" | head -n 1)$(head -n 1 "$WORK/out/scan.err")"
fi
run list list -r "$D0" "$D1"
if [ "$code" != 0 ] || ! grep -q "^$VOL  *volume " "$WORK/out/list.log"; then
    e3=FAIL; why="$why; list exit $code: $(head -n 1 "$WORK/out/list.err")"
fi
run dump dump "$VOL" "$D0" "$D1" -o "$WORK/vol.img"
if [ "$code" = 0 ] && [ -f "$WORK/vol.img" ]; then
    got=$(sha256 -q "$WORK/vol.img")
    said=$(sed -n 's/^  sha256: \([0-9a-f]*\)$/\1/p' "$WORK/out/dump.log")
    if [ "$got" != "$KERNEL_SHA" ]; then e3=FAIL; why="$why; dump's image hashes $got, the kernel's volume $KERNEL_SHA"
    elif [ "$said" != "$got" ]; then e3=FAIL; why="$why; dump said sha256 $said, the image hashes $got"
    fi
else e3=FAIL; why="$why; dump exit $code: $(tail -n 1 "$WORK/out/dump.err")"; fi
if [ "$e3" = PASS ]; then
    result E3 PASS "the binary built on ${BUILT_FOR:-FreeBSD 15} runs on $FLAVOR $REL: version, scan (pool EXPORTED, READABLE from both disks), list (the volume), dump of $VOLSIZE with the kernel's hash${why}"
else result E3 FAIL "${why#; }"; fi

# ---------------------------------------------------------------- A1, G5
say "A1, G5: the disks after the run"
changed=""
[ "$(edges "$D0")" = "$E0" ] || changed="$changed $D0"
[ "$(edges "$D1")" = "$E1" ] || changed="$changed $D1"
if zpool import -N "$POOL" >/dev/null 2>"$WORK/out/import.err"; then imports=yes; zpool export "$POOL"; else imports=no; fi
if [ -z "$changed" ] && [ "$imports" = yes ]; then result A1 PASS "both disks' ends unchanged; the pool still imports"
else result A1 FAIL "changed:$changed; imports: $imports $(head -n 1 "$WORK/out/import.err" 2>/dev/null)"; fi
if [ -z "$changed" ]; then result G5 PASS "inputs unchanged"; else result G5 FAIL "changed:$changed"; fi

# ---------------------------------------------------------------- R
if [ -x "$REPORT" ]; then
    if "$REPORT" build "$EV" -o "$WORK/report.md" >/dev/null 2>"$WORK/out/report.err" && "$REPORT" verify "$WORK/report.md" >"$WORK/out/verify.txt" 2>&1; then
        result R PASS "zvolreport build + verify over $(wc -l < "$EV" | tr -d ' ') records"
    else result R FAIL "$(tail -n 1 "$WORK/out/verify.txt" "$WORK/out/report.err" 2>/dev/null | tail -n 1)"; fi
fi

# The pool is this script's to remove: import it back and destroy it, so
# the disks do not carry a zrw pool after the run.
zpool import -N "$POOL" >/dev/null 2>&1 && zpool destroy "$POOL"

# ================================================================ the row
say "summary"
mark="☑"; [ -z "$FAILED" ] || mark="✗"
note="tests/realworld/mfsbsd.sh; the static binary built on ${BUILT_FOR:-FreeBSD 15}, root on $ROOTFS"
[ -z "$FAILED" ] || note="$note; failed:$FAILED"
# shellcheck disable=SC2086
printf '| %s | %s %s (FreeBSD in RAM, raw disks) | %s | `%s` | %s | %s | %s |\n' "$(date -u +%Y-%m-%d)" "$FLAVOR" "$REL" "$ZFS_VER" "$TOOL_VER" "$(echo $PASSED)" "$mark" "$note" | tee "$WORK/row.md"
echo "passed:$PASSED"
echo "failed:$FAILED"
[ -z "$FAILED" ]
