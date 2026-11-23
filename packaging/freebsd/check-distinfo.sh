#!/bin/sh
# packaging/freebsd/check-distinfo.sh COMMITTED WRITTEN — the committed
# distinfo names its files as `make makesum` does, and in its order.
#
# WRITTEN is a distinfo makesum wrote for the same port: in CI, the one
# the FreeBSD job writes for the commit under test. The two are of
# different tarballs — a tag's, a commit's — and may differ by a crate
# the lock file took or dropped since the tag, so neither hashes nor
# the whole list are compared. What is compared is what the ports
# framework goes by: it looks a checksum up by the file's name, to the
# letter (Mk/Scripts/functions.sh, distinfo_data), so the names both
# files have must be spelled alike and come in one order, and the
# tarball must be among them. The committed file had the tarball as
# `rust/click0-…`, first: no checksum was found for it, and nothing
# compared the file with what makesum writes.
set -eu
committed=$1
written=$2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# The files named, in order; the tarball without its version, which is
# a tag in one and a commit in the other.
names() { # names ALGORITHM FILE
    sed -En "s/^$1 \\((.*)\\) = .*/\\1/p" "$2" |
        sed -E 's/^(click0-zvolrescue-)v.*(_GH0\.tar\.gz)$/\1\2/'
}
fail() {
    echo "$committed: $1" >&2
    exit 1
}
names SHA256 "$committed" > "$tmp/committed"
names SIZE "$committed" > "$tmp/sizes"
names SHA256 "$written" > "$tmp/written"
[ -s "$tmp/committed" ] || fail "no SHA256 line"
[ -s "$tmp/written" ] || { echo "$written: no SHA256 line" >&2; exit 1; }
cmp -s "$tmp/committed" "$tmp/sizes" ||
    fail "its SIZE lines are not of the files its SHA256 lines are, in their order"
grep -qx 'click0-zvolrescue-_GH0\.tar\.gz' "$tmp/written" ||
    { echo "$written: the GitHub tarball is not in it under the name expected" >&2; exit 1; }
grep -qx 'click0-zvolrescue-_GH0\.tar\.gz' "$tmp/committed" ||
    fail "no line names the GitHub tarball as the ports framework looks it up: $(grep -n 'GH0' "$committed" | head -1)"
# What each has of the other's, in its own order.
grep -Fxf "$tmp/written" "$tmp/committed" > "$tmp/c" || true
grep -Fxf "$tmp/committed" "$tmp/written" > "$tmp/w" || true
if ! cmp -s "$tmp/c" "$tmp/w"; then
    diff "$tmp/c" "$tmp/w" | head -20 >&2 || true
    fail "its files are not in the order make makesum writes them (above: committed < and makesum >)"
fi
echo "$committed: $(wc -l < "$tmp/c" | tr -d ' ') files named and ordered as make makesum has them"
