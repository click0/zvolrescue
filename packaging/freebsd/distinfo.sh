#!/bin/sh
# packaging/freebsd/distinfo.sh VERSION — the port's distinfo for tag
# vVERSION, without a FreeBSD box: the GitHub tarball the ports
# framework fetches (codeload, named the way USE_GITHUB names it) and
# every crate of Makefile.crates, hashed and sized in the order and the
# form `make makesum` writes them. Run after the tag exists; the
# result is committed as sysutils/zvolrescue/distinfo.
#
# A download that fails stops the script, and a crate is held to the
# checksum Cargo.lock records for it: what was written down for
# wasi-0.11.1+wasi-snapshot-preview1 was the hash and the 364 bytes of
# a 404 page, a different one at every release.
set -eu
v=$1
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
port=$here/sysutils/zvolrescue
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
line() { # line DISTNAME FILE
    printf 'SHA256 (%s) = %s\n' "$1" "$(sha256sum "$2" | cut -d' ' -f1)"
    printf 'SIZE (%s) = %s\n' "$1" "$(stat -c %s "$2")"
}
locked() { # locked NAME VERSION — the checksum Cargo.lock has for it
    awk -v n="$1" -v v="$2" '
        /^\[\[package\]\]/ { name=""; version="" }
        /^name = / { name=$3; gsub(/"/, "", name) }
        /^version = / { version=$3; gsub(/"/, "", version) }
        /^checksum = / && name == n && version == v { c=$3; gsub(/"/, "", c); print c; exit }
    ' "$root/Cargo.lock"
}
{
    printf 'TIMESTAMP = %s\n' "$(date +%s)"
    curl -fsSL -o "$tmp/gh" "https://codeload.github.com/click0/zvolrescue/tar.gz/v$v"
    line "rust/click0-zvolrescue-v${v}_GH0.tar.gz" "$tmp/gh"
    for c in $(sed -n 's/^\t\t\([^ ]*\).*/\1/p' "$port/Makefile.crates"); do
        # The name ends where the version begins, at the first -N.N.N:
        # a name has no dot in it, and a version may have hyphens of
        # its own, so the last hyphen is not the place.
        name=$(printf '%s\n' "$c" | sed 's/-[0-9][0-9]*\.[0-9][0-9]*\.[0-9].*$//')
        ver=${c#"$name"-}
        file=$name-$(printf '%s\n' "$ver" | sed 's/+/%2B/g').crate
        curl -fsSL -o "$tmp/crate" "https://static.crates.io/crates/$name/$file"
        want=$(locked "$name" "$ver")
        got=$(sha256sum "$tmp/crate" | cut -d' ' -f1)
        if [ "$got" != "$want" ]; then
            echo "$c: what was fetched hashes to $got, Cargo.lock has ${want:-no checksum for it}" >&2
            exit 1
        fi
        line "rust/crates/$c.crate" "$tmp/crate"
    done
} > "$tmp/distinfo"
# Whole or not at all: a run that stopped half way leaves the file as
# it was.
cp "$tmp/distinfo" "$port/distinfo"
echo "$port/distinfo: $(grep -c '^SHA256' "$port/distinfo") files"
