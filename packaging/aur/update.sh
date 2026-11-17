#!/bin/sh
# packaging/aur/update.sh VERSION — point the PKGBUILD at tag vVERSION:
# pkgver, pkgrel back to 1, the sha256 of GitHub's tarball of that tag
# (fetched here, so this runs after the tag exists), and .SRCINFO
# regenerated in the shape `makepkg --printsrcinfo` gives. Then the
# two files are what the AUR repository takes.
set -eu
v=$1
here=$(cd "$(dirname "$0")" && pwd)
# Fetched to a file, and a fetch that fails stops here: piped into
# sha256sum, a tag that is not there gave the hash of the 404 page.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL -o "$tmp" "https://github.com/click0/zvolrescue/archive/refs/tags/v$v.tar.gz"
sum=$(sha256sum "$tmp" | cut -d' ' -f1)
sed -i -e "s/^pkgver=.*/pkgver=$v/" -e "s/^pkgrel=.*/pkgrel=1/" -e "s/^sha256sums=.*/sha256sums=('$sum')/" "$here/PKGBUILD"
"$here/srcinfo.sh" > "$here/.SRCINFO"
cat "$here/.SRCINFO"
