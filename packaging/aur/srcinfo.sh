#!/bin/bash
# packaging/aur/srcinfo.sh — .SRCINFO from the PKGBUILD beside it,
# in the shape `makepkg --printsrcinfo` gives, for a machine that has
# no makepkg: bash reads the PKGBUILD itself, arrays included.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$here/PKGBUILD"
printf 'pkgbase = %s\n' "$pkgname"
printf '\tpkgdesc = %s\n' "$pkgdesc"
printf '\tpkgver = %s\n' "$pkgver"
printf '\tpkgrel = %s\n' "$pkgrel"
printf '\turl = %s\n' "$url"
for a in "${arch[@]}"; do printf '\tarch = %s\n' "$a"; done
for l in "${license[@]}"; do printf '\tlicense = %s\n' "$l"; done
for d in "${makedepends[@]}"; do printf '\tmakedepends = %s\n' "$d"; done
for d in "${depends[@]}"; do printf '\tdepends = %s\n' "$d"; done
for s in "${source[@]}"; do printf '\tsource = %s\n' "$s"; done
for s in "${sha256sums[@]}"; do printf '\tsha256sums = %s\n' "$s"; done
printf '\npkgname = %s\n' "$pkgname"
