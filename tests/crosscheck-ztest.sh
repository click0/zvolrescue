#!/bin/sh
# Cross-check zvolrescue against OpenZFS userland: create a pool with
# ztest (no kernel module needed), then compare `zvolrescue list -r` with
# `zdb -d`, and `zvolrescue -vv scan` with `zdb -l`.
#
#   tests/crosscheck-ztest.sh [ZVOLRESCUE] [WORKDIR] [WALK-OBJECTS]
#
# Third, every block of every object of every dataset is read with the
# walk-objects example (cargo build --release -p zfs-read --examples):
# checksums of all algorithms, decompression, embedded/gang pointers, and
# the per-dataset object count against the objset pointer's fill.
#
# Needs: ztest and zdb (Debian/Ubuntu: zfsutils-linux zfs-test), python3.
# -K raidz pins the vdev class: ztest otherwise picks raidz or draid at
# random, and draid is not readable yet.
# Exit status is non-zero when any comparison differs.
set -eu
ZR=${1:-./target/release/zvolrescue}
WORK=${2:-/tmp/zvolrescue-crosscheck}
WALK=${3:-./target/release/examples/walk-objects}
rm -rf "$WORK"; mkdir -p "$WORK"
fail=0

run_pool() {
    name=$1; shift
    dir="$WORK/$name"; mkdir -p "$dir"
    echo "== $name: ztest $*"
    ( cd "$dir" && ztest -f "$dir" -v 1 -K raidz "$@" -s 96m -a 12 -d 3 -t 2 -k 0 -T 15 -P 8 > "$dir/ztest.log" 2>&1 ) || { echo "ztest failed:"; tail -5 "$dir/ztest.log"; fail=1; return; }
    members=$(ls "$dir"/ztest.*a)

    # 1. datasets: name + creation txg, from zdb and from zvolrescue.
    zdb -e -p "$dir" -d ztest 2>/dev/null | python3 -c '
import re,sys
for l in sys.stdin:
    m = re.match(r"Dataset (\S+) \[(\w+)\], ID \d+, cr_txg (\d+)", l)
    if m and m.group(1) != "mos":
        print(m.group(1), m.group(3))' | sort > "$dir/zdb.txt"
    $ZR -f json list -r $members | python3 -c '
import json,sys
d = json.load(sys.stdin)
for x in d["datasets"]:
    print(x["name"], x["creation_txg"])' | sort > "$dir/zr.txt"
    if diff -u "$dir/zdb.txt" "$dir/zr.txt"; then
        echo "   datasets: $(wc -l < "$dir/zr.txt") match zdb"
    else
        echo "   datasets: MISMATCH"; fail=1
    fi

    # 2. label facts of the first member.
    first=$(echo "$members" | head -1)
    zdb -l "$first" 2>/dev/null | python3 -c '
import re,sys
want = {}
for l in sys.stdin:
    m = re.match(r"\s+(name|pool_guid|txg|top_guid|guid|hostname|vdev_children): (.+)", l)
    if m and m.group(1) not in want:
        want[m.group(1)] = m.group(2).strip("\x27")
for k in sorted(want): print(k, want[k])' > "$dir/zdb-label.txt"
    $ZR -f json scan "$first" | python3 -c '
import json,sys
c = json.load(sys.stdin)["devices"][0]["config"]
out = {"name": c["name"], "pool_guid": str(int(c["pool_guid"],16)), "txg": str(c["txg"]), "top_guid": str(int(c["top_guid"],16)), "guid": str(int(c["vdev_guid"],16)), "hostname": c["hostname"], "vdev_children": str(c["vdev_children"])}
for k in sorted(out): print(k, out[k])' > "$dir/zr-label.txt"
    if diff -u "$dir/zdb-label.txt" "$dir/zr-label.txt"; then
        echo "   label: matches zdb -l"
    else
        echo "   label: MISMATCH"; fail=1
    fi

    # 3. every block of every object, all member files including any
    #    leftover of an attach/replace and the spares.
    if [ -x "$WALK" ]; then
        if "$WALK" "$dir"/ztest.* > "$dir/walk.txt" 2> "$dir/walk.err"; then
            echo "   walk: $(head -1 "$dir/walk.txt"), no checksum or decode error"
        else
            echo "   walk: FAILED"; cat "$dir/walk.txt"; tail -20 "$dir/walk.err"; fail=1
        fi
    else
        echo "   walk: skipped ($WALK not built)"
    fi

    # 4. encryption metadata of every encrypted dataset against zdb's dump
    #    of the DSL crypto key object (suite, key guid, root dir, keyformat,
    #    version).
    $ZR -f json list -r $members | python3 -c '
import json,sys
d = json.load(sys.stdin)
seen = set()
for x in d["datasets"]:
    e = x.get("encryption")
    if e and e["crypto_key_object"] not in seen:
        seen.add(e["crypto_key_object"])
        fmt = {"raw": 1, "hex": 2, "passphrase": 3}[e["keyformat"]]
        print(e["crypto_key_object"], e["suite"], int(e["key_guid"], 16), e["encryption_root_dir_object"], fmt, e["key_version"])' > "$dir/zr-crypto.txt"
    : > "$dir/zdb-crypto.txt"
    while read -r obj suite guid root fmt ver; do
        zdb -e -p "$dir" -dddd ztest "$obj" 2>/dev/null | python3 -c '
import re,sys
obj = sys.argv[1]
names = {3:"aes-128-ccm",4:"aes-192-ccm",5:"aes-256-ccm",6:"aes-128-gcm",7:"aes-192-gcm",8:"aes-256-gcm"}
v = {}
for l in sys.stdin:
    # zdb prints the GUID as a signed 64-bit number.
    m = re.match(r"\s+(DSL_CRYPTO_SUITE|DSL_CRYPTO_GUID|DSL_CRYPTO_ROOT_DDOBJ|keyformat|DSL_CRYPTO_VERSION) = (-?\d+)", l)
    if m: v[m.group(1)] = int(m.group(2)) & 0xffffffffffffffff
print(obj, names.get(v.get("DSL_CRYPTO_SUITE"), "?"), v.get("DSL_CRYPTO_GUID"), v.get("DSL_CRYPTO_ROOT_DDOBJ"), v.get("keyformat"), v.get("DSL_CRYPTO_VERSION", 0))' "$obj" >> "$dir/zdb-crypto.txt"
    done < "$dir/zr-crypto.txt"
    if diff -u "$dir/zdb-crypto.txt" "$dir/zr-crypto.txt"; then
        echo "   encryption: $(wc -l < "$dir/zr-crypto.txt") crypto key object(s) match zdb"
    else
        echo "   encryption: MISMATCH"; fail=1
    fi
}

run_pool mirror -m 2 -r 1 -R 0
run_pool raidz2 -m 1 -r 4 -R 2
run_pool raidz1-of-mirrors -m 2 -r 3 -R 1

exit $fail
