#!/bin/sh
# Builds a pacman package from the current source tree. Needs cargo and makepkg.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

tar czf "$stage/cryptosec-$version.tar.gz" \
    --exclude=./target --exclude=./.git --exclude='./*.deb' \
    --transform "s,^\.,cryptosec-$version," .

cat > "$stage/PKGBUILD" <<PKGBUILD
# Maintainer: Leon Pelzmann <brunonick1801@gmail.com>
pkgname=cryptosec
pkgver=$version
pkgrel=1
pkgdesc='File and directory encryption for the command line'
arch=('x86_64' 'aarch64')
url='https://github.com/poezi123/CryptoSec'
license=('MIT')
depends=('gcc-libs')
makedepends=('cargo')
options=('!debug')
source=("cryptosec-\$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
  cd "\$srcdir/cryptosec-\$pkgver"
  export RUSTUP_TOOLCHAIN=stable
  export CARGO_TARGET_DIR=target
  cargo build --release --locked
}

check() {
  cd "\$srcdir/cryptosec-\$pkgver"
  export RUSTUP_TOOLCHAIN=stable
  cargo test --release --locked
}

package() {
  cd "\$srcdir/cryptosec-\$pkgver"
  install -Dm755 target/release/cryptosec "\$pkgdir/usr/bin/cryptosec"
  install -Dm644 docs/cryptosec.1 "\$pkgdir/usr/share/man/man1/cryptosec.1"
  install -Dm644 packaging/desktop/cryptosec.desktop "\$pkgdir/usr/share/applications/cryptosec.desktop"
  install -Dm644 packaging/desktop/cryptosec.xml "\$pkgdir/usr/share/mime/packages/cryptosec.xml"
  install -Dm644 README.md "\$pkgdir/usr/share/doc/cryptosec/README.md"
  install -Dm644 LICENSE "\$pkgdir/usr/share/licenses/cryptosec/LICENSE"
}
PKGBUILD

cd "$stage"
makepkg -f "$@" >&2
pkg=$(ls -1 "cryptosec-$version"-*.pkg.tar.* | head -1)
mv "$pkg" "$root/$pkg"
echo "$root/$pkg"
