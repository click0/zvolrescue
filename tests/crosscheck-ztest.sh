#!/bin/sh
# Cross-check zvolrescue against OpenZFS userland: create a pool with
# ztest (no kernel module needed), then compare `zvolrescue list -r` with
# `zdb -d`, and `zvolrescue -vv scan` with `zdb -l`.
#
#   tests/crosscheck-ztest.sh [ZVOLRESCUE] [WORKDIR] [WALK-OBJECTS] [UNWRAP-KEY]
#
# Pools: mirror, raidz2, raidz1-of-mirrors, draid1 (4d:6c:1s), draid2
# (5d:9c:2s). Steps 4-8 need the walk-objects and unwrap-key examples.
#
# Third, every block of every object of every dataset is read with the
# walk-objects example (cargo build --release -p zfs-read --examples):
# checksums of all algorithms, decompression, embedded/gang pointers, and
# the per-dataset object count against the objset pointer's fill.
#
# Needs: ztest and zdb (Debian/Ubuntu: zfsutils-linux zfs-test), python3.
# -K pins the vdev class (ztest otherwise picks raidz or draid at random).
# Exit status is non-zero when any comparison differs.
set -eu
ZR=${1:-./target/release/zvolrescue}
WORK=${2:-/tmp/zvolrescue-crosscheck}
WALK=${3:-./target/release/examples/walk-objects}
UNWRAP=${4:-$(dirname "$WALK")/unwrap-key}
rm -rf "$WORK"; mkdir -p "$WORK"
fail=0

# wipe_copy SRC OUT PAD: copy SRC to OUT after PAD bytes of filler, with
# every vdev_phys area of the copy erased — a member whose four label
# configurations are gone, optionally moved along.
wipe_copy() {
    python3 - "$1" "$2" "$3" <<'EOF'
import os, shutil, sys
LABEL, PHYS_OFF, PHYS = 256*1024, 16*1024, 112*1024
src, out, pad = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(src, "rb") as f, open(out, "wb") as g:
    if pad:
        g.write(b"\x5a" * pad)
    shutil.copyfileobj(f, g)
aligned = os.path.getsize(src) & ~(LABEL - 1)
with open(out, "r+b") as f:
    for off in (0, LABEL, aligned - 2*LABEL, aligned - LABEL):
        f.seek(pad + off + PHYS_OFF); f.write(b"\0" * PHYS)
EOF
}

# run_pool NAME REDUNDANCY ZTEST-ARGS...: REDUNDANCY is how many members
# the walk in step 8 leaves out (parity level, or 1 for a mirror).
run_pool() {
    name=$1; redundancy=$2; shift 2
    dir="$WORK/$name"; mkdir -p "$dir"
    echo "== $name: ztest $*"
    ( cd "$dir" && ztest -f "$dir" -v 1 "$@" -s 96m -a 12 -d 3 -t 2 -k 0 -T 15 -P 8 > "$dir/ztest.log" 2>&1 ) || { echo "ztest failed:"; tail -5 "$dir/ztest.log"; fail=1; return; }
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
    $ZR -f json list -r $members > "$dir/list.json"
    python3 -c '
import json,sys
d = json.load(open(sys.argv[1]))
seen = set()
for x in d["datasets"]:
    e = x.get("encryption")
    if e and e["crypto_key_object"] not in seen:
        seen.add(e["crypto_key_object"])
        fmt = {"raw": 1, "hex": 2, "passphrase": 3}[e["keyformat"]]
        print(e["crypto_key_object"], e["suite"], int(e["key_guid"], 16), e["encryption_root_dir_object"], fmt, e["key_version"])' "$dir/list.json" > "$dir/zr-crypto.txt"
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

    # 5. unwrap the master keys with ztest's fixed raw wrapping key
    #    (ztest_wkeydata); a wrong key must be refused.
    if [ -x "$UNWRAP" ] && [ -s "$dir/zr-crypto.txt" ]; then
        printf 'abcdefghijklmnopqrstuvwxyz012345' > "$dir/ztest.key"
        printf 'abcdefghijklmnopqrstuvwxyz012346' > "$dir/wrong.key"
        if "$UNWRAP" "raw:$dir/ztest.key" "$dir"/ztest.* > "$dir/unwrap.txt" 2>/dev/null; then
            echo "   unwrap: $(wc -l < "$dir/unwrap.txt") encryption root(s) opened with ztest's key"
        else
            echo "   unwrap: FAILED"; cat "$dir/unwrap.txt"; fail=1
        fi
        if "$UNWRAP" "raw:$dir/wrong.key" "$dir"/ztest.* > "$dir/unwrap-wrong.txt" 2>/dev/null; then
            echo "   unwrap: a WRONG key was accepted"; cat "$dir/unwrap-wrong.txt"; fail=1
        else
            echo "   unwrap: wrong key refused"
        fi

        # 6. every block of the encrypted datasets decrypted and verified:
        #    the walk with the key must be clean and every dataset's object
        #    count must equal its objset fill (no dnode block skipped).
        if [ -x "$WALK" ]; then
            if ZR_KEY="raw:$dir/ztest.key" "$WALK" "$dir"/ztest.* > "$dir/walk-key.txt" 2> "$dir/walk-key.err" \
                && ! grep -q "no key\|decrypt" "$dir/walk-key.txt" \
                && [ "$(grep -c 'object count == objset fill' "$dir/walk-key.txt")" = 1 ]; then
                enc=$(grep -c "encrypted: Ok" "$dir/walk-key.txt")
                echo "   walk with key: $(head -1 "$dir/walk-key.txt"), all encrypted blocks decrypted ($enc outcome lines), every object counted"
            else
                echo "   walk with key: FAILED"; cat "$dir/walk-key.txt"; tail -20 "$dir/walk-key.err"; fail=1
            fi
        fi

        # 7. dump --key wiring on an encrypted dataset (ztest makes no
        #    volumes, so the right key must get as far as "not a volume").
        encds=$(python3 -c '
import json,sys
d = json.load(open(sys.argv[1]))
print(next(x["name"] for x in d["datasets"] if x.get("encryption") and not x["name"].count("@")))' "$dir/list.json" 2>/dev/null || true)
        if [ -n "$encds" ]; then
            if $ZR -q dump "$encds" $members -o "$dir/enc.img" --key "raw:$dir/ztest.key" 2> "$dir/dump-key.err"; rc=$?; [ $rc = 3 ] && grep -q "not a volume" "$dir/dump-key.err"; then
                echo "   dump --key: $encds unlocked with the right key (then refused as not a volume)"
            else
                echo "   dump --key: unexpected result (exit $rc)"; cat "$dir/dump-key.err"; fail=1
            fi
            if $ZR -q dump "$encds" $members -o "$dir/enc.img" --key "raw:$dir/wrong.key" 2> "$dir/dump-wrong.err"; rc=$?; [ $rc = 1 ] && grep -q "MAC does not verify" "$dir/dump-wrong.err"; then
                echo "   dump --key: wrong key refused (exit 1)"
            else
                echo "   dump --key: wrong key NOT refused properly (exit $rc)"; cat "$dir/dump-wrong.err"; fail=1
            fi
            if $ZR -q dump "$encds" $members -o "$dir/enc.img" 2> "$dir/dump-nokey.err"; rc=$?; [ $rc = 1 ] && grep -q "supply --key" "$dir/dump-nokey.err"; then
                echo "   dump: without a key it says which key is needed (exit 1)"
            else
                echo "   dump: no-key message wrong (exit $rc)"; cat "$dir/dump-nokey.err"; fail=1
            fi
        fi
    fi

    # 8. redundancy: the walk (with the key, when the pool has one) must
    #    stay clean with the first REDUNDANCY member files left out —
    #    parity reconstruction on raidz/draid, the surviving side of a
    #    mirror. ztest does not always create an encrypted dataset, so a
    #    pool may have no key file and no keyed walk to compare against.
    if [ -x "$WALK" ] && [ "$redundancy" -gt 0 ]; then
        left="$(ls "$dir"/ztest.*a | tail -n +$((redundancy + 1))) $(ls "$dir"/ztest.*b 2>/dev/null || true)"
        omitted=$(ls "$dir"/ztest.*a | head -n "$redundancy" | xargs -n1 basename | tr '\n' ' ')
        if [ -f "$dir/ztest.key" ]; then
            key="raw:$dir/ztest.key"; reference="$dir/walk-key.txt"
        else
            key=""; reference="$dir/walk.txt"
        fi
        if ZR_KEY="$key" "$WALK" $left > "$dir/walk-missing.txt" 2> "$dir/walk-missing.err" \
            && ! grep -q "ERROR\|dnode:\|no key\|decrypt" "$dir/walk-missing.txt" \
            && [ "$(head -1 "$dir/walk-missing.txt")" = "$(head -1 "$reference")" ]; then
            echo "   redundancy: without $omitted the walk is identical ($(head -1 "$dir/walk-missing.txt"))"
        else
            echo "   redundancy: FAILED without $omitted"; head -12 "$dir/walk-missing.txt"; tail -5 "$dir/walk-missing.err"; fail=1
        fi
    fi

    # 9. zero point: with every vdev_phys erased, the base must still be
    #    recovered from an uberblock checksum, and it must survive the
    #    member being moved (a rewritten partition table). One temporary
    #    copy at a time: these are whole members.
    # Pick a member that is really part of the committed pool: ztest
    # leaves behind devices it was attaching, whose labels carry txg 0 and
    # an uberblock template with no embedded checksum at all — nothing for
    # an anchor to verify, and the tool must not invent one.
    anchored=$(for m in $members; do
        if [ "$($ZR -f json scan "$m" | python3 -c 'import json,sys; print(json.load(sys.stdin)["devices"][0]["newest_txg"])')" != "None" ]; then
            echo "$m"; break
        fi
    done)
    [ -n "$anchored" ] || anchored=$(echo "$members" | head -1)
    # The rear labels sit at align_down(size, 256 KiB), so that is the
    # size an anchor there implies.
    want_size=$(( $(stat -c %s "$anchored") / 262144 * 262144 ))
    zero_point() {  # zero_point FILE -> "base anchors psize"
        $ZR -f json scan "$1" | python3 -c '
import json,sys
z = (json.load(sys.stdin)["devices"][0].get("zero_point") or [{}])[0]
print(z.get("base"), z.get("anchors"), z.get("psize"))'
    }
    wipe_copy "$anchored" "$dir/tmp.img" 0
    plain=$(zero_point "$dir/tmp.img"); rm -f "$dir/tmp.img"
    wipe_copy "$anchored" "$dir/tmp.img" 1048576
    shifted=$(zero_point "$dir/tmp.img"); rm -f "$dir/tmp.img"
    if [ "$(echo "$plain" | awk '{print $1}')" = "0" ] \
        && [ "$(echo "$shifted" | awk '{print $1}')" = "1048576" ] \
        && [ "$(echo "$shifted" | awk '{print $3}')" = "$want_size" ]; then
        echo "   zero point: base recovered from uberblocks without any vdev_phys ($(echo "$plain" | awk '{print $2}') anchors), and after a 1 MiB shift"
    else
        echo "   zero point: FAILED"; echo "plain: $plain"; echo "shifted: $shifted"; fail=1
    fi

    # 10. a member whose labels are intact but which starts 1 MiB in (a
    #     partition re-created with another start): every block of every
    #     object must still read, through the recovered base.
    if [ -x "$WALK" ] && [ -s "$dir/walk.txt" ]; then
        : "${key:=}"; : "${reference:=$dir/walk.txt}"
        { head -c 1048576 /dev/zero | tr '\0' 'Z'; cat "$anchored"; } > "$dir/moved-intact.img"
        others="$(echo "$members" | grep -v "^$anchored$" | tr '\n' ' ') $(ls "$dir"/ztest.*b 2>/dev/null | tr '\n' ' ')"
        if ZR_KEY="$key" "$WALK" "$dir/moved-intact.img" $others > "$dir/walk-moved.txt" 2> "$dir/walk-moved.err" \
            && ! grep -q "ERROR\|dnode:\|no key\|decrypt" "$dir/walk-moved.txt" \
            && [ "$(head -1 "$dir/walk-moved.txt")" = "$(head -1 "$reference")" ]; then
            echo "   moved member: the walk through a member shifted by 1 MiB is identical ($(head -1 "$dir/walk-moved.txt"))"
        else
            echo "   moved member: FAILED"; head -12 "$dir/walk-moved.txt"; tail -5 "$dir/walk-moved.err"; fail=1
        fi
        rm -f "$dir/moved-intact.img"
    fi

}

run_pool mirror 1 -K raidz -m 2 -r 1 -R 0
run_pool raidz2 2 -K raidz -m 1 -r 4 -R 2
# -g lowers the gang-block threshold so gang blocks (also of encrypted
# datasets) are always present on these two.
run_pool raidz1-of-mirrors 1 -K raidz -m 2 -r 3 -R 1 -g 8192
run_pool draid1 1 -K draid -m 1 -r 6 -R 1 -D 4 -S 1
run_pool draid2 2 -K draid -m 1 -r 9 -R 2 -D 5 -S 2 -g 8192

exit $fail
