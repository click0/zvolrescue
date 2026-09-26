#!/bin/sh
# tests/man-check.sh BINDIR MANDIR — the manual pages tell the truth
# about the programs: every subcommand and every long option that
# `--help` prints is named in the program's page, the version the page
# carries is the workspace's, and each page parses clean under mandoc
# (when mandoc is installed; without it that part is skipped and said).
# A page written by hand drifts from a CLI that grows unless something
# reads both; CI runs this on every push.
set -eu
bindir=$1
mandir=$2
fail=0
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$(dirname "$0")/../Cargo.toml" | head -1)
for prog in zvolrescue zvoltimeline zvolreport zvolcarve zvolfiles; do
    page=$mandir/$prog.1
    if [ ! -f "$page" ]; then echo "$prog: no $page"; fail=1; continue; fi
    grep -q "^\.Dt $(echo "$prog" | tr a-z A-Z) 1$" "$page" || { echo "$prog: .Dt is not '$(echo "$prog" | tr a-z A-Z) 1'"; fail=1; }
    grep -qF -- "$version" "$page" || { echo "$prog: version $version is not in $page"; fail=1; }
    subs=$("$bindir/$prog" --help | awk '/^Commands:/{f=1;next} /^$/{f=0} f{print $1}' | grep -v '^help$' || true)
    for cmd in $subs; do
        grep -qE "(^|[[:space:]])Cm $cmd([[:space:]]|$)" "$page" || { echo "$prog: subcommand $cmd is not in $page"; fail=1; }
    done
    for cmd in "" $subs; do
        # shellcheck disable=SC2086
        for opt in $("$bindir/$prog" $cmd --help | grep -oE -- '^ +(-[a-zA-Z], )?--[a-z][a-z0-9-]*' | grep -oE -- '--[a-z][a-z0-9-]*' | sort -u); do
            case $opt in --help|--version) continue ;; esac
            grep -qF -- "Fl -${opt#--}" "$page" || { echo "$prog${cmd:+ $cmd}: $opt is not in $page"; fail=1; }
        done
    done
    if command -v mandoc >/dev/null; then
        if ! out=$(mandoc -T lint -W warning "$page" 2>&1); then
            echo "$page: mandoc:"; echo "$out"; fail=1
        fi
    fi
done
command -v mandoc >/dev/null || echo "man-check: mandoc not installed; pages checked for content only"
[ "$fail" = 0 ] && echo "man-check: every page names every subcommand and option of its program"
exit "$fail"
