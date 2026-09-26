#!/bin/sh
# packaging/aur/update.sh VERSION — point the PKGBUILD at tag vVERSION:
# pkgver, pkgrel back to 1, the sha256 of GitHub's tarball of that tag
# (fetched here, so this runs after the tag exists), and .SRCINFO
# regenerated in the shape `makepkg --printsrcinfo` gives. Then the
# two files are what the AUR repository takes.
set -eu
v=$1
here=$(cd "$(dirname "$0")" && pwd)
sum=$(curl -sSL "https://github.com/click0/zvolrescue/archive/refs/tags/v$v.tar.gz" | sha256sum | cut -d' ' -f1)
sed -i -e "s/^pkgver=.*/pkgver=$v/" -e "s/^pkgrel=.*/pkgrel=1/" -e "s/^sha256sums=.*/sha256sums=('$sum')/" "$here/PKGBUILD"
"$here/srcinfo.sh" > "$here/.SRCINFO"
cat "$here/.SRCINFO"
