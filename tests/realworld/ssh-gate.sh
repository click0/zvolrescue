#!/bin/sh
# zvolrescue-gate: the one command a CI ssh key may run on a machine
# that lends its kernel ZFS to the real-world matrix
# (docs/REALWORLD-TESTS.md, "Running the matrix on your own machine
# over ssh"; the workflow is .github/workflows/realworld-ssh.yml).
#
# Installed as the forced command of the key the workflow holds —
#
#   command="/usr/local/sbin/zvolrescue-gate",restrict ssh-ed25519 AAAA... zvolrescue-ci
#
# — so that whatever the workflow, or anyone else holding that key,
# asks for arrives here in SSH_ORIGINAL_COMMAND and is one of the verbs
# below or is refused. Nothing here is a shell.
#
#   probe              what this machine is: OS, machine, kernel, ZFS,
#                      whether the gate can become root, bash, python3
#   put NAME           stdin into WORK/in/NAME; NAME is one of the four
#                      files the workflow ships, nothing else
#   run matrix         tests/realworld/kernel-matrix.sh as root, with
#                      WORK/rw as its directory
#   run mfsbsd D0 D1   tests/realworld/mfsbsd.sh as root, on the two raw
#                      disks D0 and D1 — whose contents it destroys
#   record             the run's record (not its images) as a tar.gz
#                      on stdout
#   clean              remove WORK/rw and WORK/in
#
# `run`, `record` and `clean` need root: the matrix makes pools, loop or
# md devices and a device-mapper target. Either install the gate for
# root's own authorized_keys, or for an unprivileged user with this one
# sudoers line and nothing else —
#
#   ci ALL=(root) NOPASSWD: /usr/local/sbin/zvolrescue-gate
#
# — and the gate re-runs itself under sudo for those three verbs only.
# What then runs as root is the repository's own script, so a run is
# exactly as trusted as the repository that sent it: lend a machine you
# can lose (a VM, a spare box), never one with a pool you care about.
# The script refuses to start while a pool named zrw* is imported,
# creates only such pools, and tears its devices down on exit; it
# writes about 6 GiB under WORK.
#
# Without a forced command — a throwaway VM, a rescue system booted
# with a known root password — the workflow copies this file over first
# and runs it as `~/zvolrescue-gate VERB ...`: the same verbs, from the
# arguments. POSIX sh, so that it runs on mfsBSD too.
set -u

# Where the shipped files and the run live. Edit here; the environment
# does not survive sudo.
WORK=/var/tmp/zvolrescue-ci

case $0 in
/*) SELF=$0 ;;
*) SELF=$(pwd)/$0 ;;
esac

if [ $# -eq 0 ]; then
    # Under a forced command the request is the command the client
    # asked for, word-split: the verbs take no argument with a space in it.
    # shellcheck disable=SC2086
    set -- ${SSH_ORIGINAL_COMMAND:-}
fi
verb=${1:-}
[ $# -gt 0 ] && shift

refuse() { printf 'zvolrescue-gate: refused: %s\n' "$*" >&2; exit 2; }

case $verb in
run|record|clean)
    if [ "$(id -u)" != 0 ]; then
        exec sudo -n "$SELF" "$verb" "$@"
    fi
    ;;
esac

case $verb in
probe)
    printf 'zvolrescue-gate 1\n'
    printf 'os %s\narch %s\nkernel %s\nhost %s\n' "$(uname -s)" "$(uname -m)" "$(uname -r)" "$(hostname)"
    zfs=$(zfs version 2>/dev/null | head -n 1)
    printf 'zfs %s\n' "${zfs:-none}"
    if [ "$(id -u)" = 0 ]; then printf 'root yes\n'
    elif sudo -n -l "$SELF" >/dev/null 2>&1; then printf 'root sudo\n'
    else printf 'root no\n'; fi
    for t in bash python3 openssl; do
        if command -v "$t" >/dev/null 2>&1; then printf '%s yes\n' "$t"; else printf '%s no\n' "$t"; fi
    done
    printf 'work %s\n' "$WORK"
    ;;
put)
    name=${1:-}
    case $name in
    zvolrescue|zvolreport|kernel-matrix.sh|mfsbsd.sh) ;;
    *) refuse "put ${name:-?}: not a file the workflow ships" ;;
    esac
    mkdir -p "$WORK/in" && chmod 755 "$WORK" "$WORK/in" || exit 1
    cat > "$WORK/in/$name" || exit 1
    case $name in zvolrescue|zvolreport) chmod 755 "$WORK/in/$name" ;; esac
    printf 'put %s: %s bytes\n' "$name" "$(wc -c < "$WORK/in/$name" | tr -d ' ')"
    ;;
run)
    what=${1:-}
    [ $# -gt 0 ] && shift
    [ -x "$WORK/in/zvolrescue" ] || refuse "run: put zvolrescue first"
    rm -rf "$WORK/rw" && mkdir -p "$WORK/rw" && chmod 755 "$WORK/rw" || exit 1
    case $what in
    matrix)
        [ -f "$WORK/in/kernel-matrix.sh" ] || refuse "run matrix: put kernel-matrix.sh first"
        command -v bash >/dev/null 2>&1 || refuse "run matrix: this machine has no bash (a rescue system? run mfsbsd is the one for it)"
        exec bash "$WORK/in/kernel-matrix.sh" "$WORK/rw" "$WORK/in/zvolrescue"
        ;;
    mfsbsd)
        [ -f "$WORK/in/mfsbsd.sh" ] || refuse "run mfsbsd: put mfsbsd.sh first"
        d0=${1:-}; d1=${2:-}
        for d in "$d0" "$d1"; do
            case $d in /dev/*) ;; *) refuse "run mfsbsd: two raw disks under /dev, e.g. /dev/vtbd0 /dev/vtbd1 (their contents are destroyed)" ;; esac
            case $d in *[!A-Za-z0-9/._-]*) refuse "run mfsbsd: $d is not a device name" ;; esac
            [ -c "$d" ] || [ -b "$d" ] || refuse "run mfsbsd: $d is not a device"
        done
        exec sh "$WORK/in/mfsbsd.sh" "$WORK/rw" "$WORK/in/zvolrescue" "$d0" "$d1"
        ;;
    *) refuse "run ${what:-?}: matrix or mfsbsd" ;;
    esac
    ;;
record)
    cd "$WORK/rw" 2>/dev/null || refuse "record: nothing has run"
    # The record without the images: the row, the results, the evidence
    # log, the report, and the logs of the scenarios.
    files=$(ls env.txt results.txt row.md evidence.jsonl report.md 2>/dev/null
            [ -d out ] && find out -maxdepth 1 -type f \( -name '*.log' -o -name '*.err' -o -name '*.txt' -o -name '*.json' -o -name '*.md' \))
    [ -n "$files" ] || refuse "record: the run left nothing"
    # shellcheck disable=SC2086
    tar czf - $files
    ;;
clean)
    rm -rf "$WORK/rw" "$WORK/in"
    printf 'clean: %s/rw and %s/in removed\n' "$WORK" "$WORK"
    ;;
"")
    refuse "no request (this key runs zvolrescue-gate, not a shell)"
    ;;
*)
    refuse "$verb: not a verb of zvolrescue-gate (probe, put, run, record, clean)"
    ;;
esac
