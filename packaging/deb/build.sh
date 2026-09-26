#!/bin/sh
# packaging/deb/build.sh VERSION ARCH BINDIR MANDIR OUTDIR
#
# A .deb of the five programs and their manual pages, made with
# dpkg-deb alone: the binaries are the release's static musl builds and
# depend on nothing, so there is no build to describe to a Debian build
# chain, only files to place. ARCH is Debian's name for the machine
# (amd64, arm64). VERSION is the workspace version, with `+git<commit>`
# appended for a build of an untagged commit. The result is
# OUTDIR/zvolrescue_VERSION_ARCH.deb.
set -eu
v=$1; arch=$2; bindir=$3; mandir=$4; out=$5
here=$(cd "$(dirname "$0")" && pwd)
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
chmod 755 "$root"
mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/man/man1" "$root/usr/share/doc/zvolrescue"
for b in zvolrescue zvoltimeline zvolreport zvolcarve zvolfiles; do
    install -m 755 "$bindir/$b" "$root/usr/bin/$b"
    gzip -9n < "$mandir/$b.1" > "$root/usr/share/man/man1/$b.1.gz"
done
install -m 644 "$here/copyright" "$root/usr/share/doc/zvolrescue/copyright"
size=$(du -sk "$root/usr" | cut -f1)
sed -e "s/@VERSION@/$v/" -e "s/@ARCH@/$arch/" -e "s/@SIZE@/$size/" "$here/control.in" > "$root/DEBIAN/control"
mkdir -p "$out"
dpkg-deb --root-owner-group --build "$root" "$out/zvolrescue_${v}_${arch}.deb"
