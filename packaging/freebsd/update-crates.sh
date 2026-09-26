#!/bin/sh
# packaging/freebsd/update-crates.sh — Makefile.crates of the port from
# Cargo.lock: every crate the lock file takes from crates.io, as
# `make cargo-crates` in the ports tree would list them, so the port
# fetches exactly what the tree builds with. CI regenerates it and
# refuses a Cargo.lock the committed file no longer matches.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
out=$root/packaging/freebsd/sysutils/zvolrescue/Makefile.crates
{
    echo "CARGO_CRATES=\t\\"
    awk '
        /^\[\[package\]\]/ { name=""; version=""; source="" }
        /^name = / { name=$3; gsub(/"/, "", name) }
        /^version = / { version=$3; gsub(/"/, "", version) }
        /^source = "registry\+https:\/\/github.com\/rust-lang\/crates.io-index"/ { print name "-" version }
    ' "$root/Cargo.lock" | sort -u | sed 's/^/\t\t/; s/$/ \\/' | sed '$ s/ \\$//'
} > "$out"
echo "$out: $(grep -c '^		' "$out") crates"
