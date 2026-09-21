#!/bin/sh
# Builds a .deb from the current source tree. Needs cargo and dpkg-deb.
# Run it on the system the package is meant for: the binary links against the
# glibc of the machine it was built on.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
arch=$(dpkg --print-architecture)
stage=$(mktemp -d)
chmod 755 "$stage"
trap 'rm -rf "$stage"' EXIT

echo "building cryptosec $version for $arch"
make build

make install DESTDIR="$stage" PREFIX=/usr
install -d "$stage/DEBIAN"
mv "$stage/usr/share/doc/cryptosec/LICENSE" "$stage/usr/share/doc/cryptosec/copyright"

size=$(du -ks "$stage/usr" | cut -f1)
cat > "$stage/DEBIAN/control" <<CONTROL
Package: cryptosec
Version: $version
Section: utils
Priority: optional
Architecture: $arch
Depends: libc6
Recommends: shared-mime-info, desktop-file-utils
Installed-Size: $size
Maintainer: Leon Pelzmann <brunonick1801@gmail.com>
Homepage: https://github.com/poezi123/CryptoSec
Description: File and directory encryption for the command line
 cryptosec packs a file or a whole directory into a single encrypted
 container. AES-256-GCM and ChaCha20-Poly1305 are available with a
 password, RSA-4096, X25519 and ML-KEM-768 with a key pair.
 .
 Containers start with a readable banner, so opening one in an editor
 says what it is instead of showing binary noise.
CONTROL

cat > "$stage/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    if command -v update-mime-database >/dev/null 2>&1; then
        update-mime-database /usr/share/mime >/dev/null 2>&1 || true
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
    fi
fi
POSTINST

cat > "$stage/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ]; then
    if command -v update-mime-database >/dev/null 2>&1; then
        update-mime-database /usr/share/mime >/dev/null 2>&1 || true
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
    fi
fi
POSTRM

chmod 755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/postrm"
gzip -9n "$stage/usr/share/man/man1/cryptosec.1"

out="cryptosec_${version}_${arch}.deb"
dpkg-deb --build --root-owner-group "$stage" "$out" >/dev/null
echo "$root/$out"
