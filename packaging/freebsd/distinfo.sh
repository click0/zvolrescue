#!/bin/sh
# packaging/freebsd/distinfo.sh VERSION — the port's distinfo for tag
# vVERSION, without a FreeBSD box: the GitHub tarball the ports
# framework fetches (codeload, named the way USE_GITHUB names it) and
# every crate of Makefile.crates, hashed and sized in the order and the
# form `make makesum` writes them. Run after the tag exists; the
# result is committed as sysutils/zvolrescue/distinfo.
set -eu
v=$1
here=$(cd "$(dirname "$0")" && pwd)
port=$here/sysutils/zvolrescue
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
line() { # line DISTNAME FILE
    printf 'SHA256 (%s) = %s\n' "$1" "$(sha256sum "$2" | cut -d' ' -f1)"
    printf 'SIZE (%s) = %s\n' "$1" "$(stat -c %s "$2")"
}
{
    printf 'TIMESTAMP = %s\n' "$(date +%s)"
    curl -sSL -o "$tmp/gh" "https://codeload.github.com/click0/zvolrescue/tar.gz/v$v"
    line "rust/click0-zvolrescue-v${v}_GH0.tar.gz" "$tmp/gh"
    for c in $(sed -n 's/^\t\t\([^ ]*\).*/\1/p' "$port/Makefile.crates"); do
        name=${c%-*}; ver=${c##*-}
        curl -sSL -o "$tmp/crate" "https://static.crates.io/crates/$name/$name-$ver.crate"
        line "rust/crates/$c.crate" "$tmp/crate"
    done
} > "$port/distinfo"
echo "$port/distinfo: $(grep -c '^SHA256' "$port/distinfo") files"
