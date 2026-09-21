#!/bin/sh
# Builds and installs cryptosec. Uses the native package manager on Arch and
# Debian based systems so the result can be removed again in the usual way.
set -eu

root=$(cd "$(dirname "$0")" && pwd)
cd "$root"

say()  { printf '%s\n' "$*"; }
die()  { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
    SUDO=
else
    command -v sudo >/dev/null 2>&1 || die "sudo is required (or run this as root)"
    SUDO=sudo
fi

uninstall=0
case "${1:-}" in
    --uninstall|-u) uninstall=1 ;;
    --help|-h)
        say "usage: ./install.sh [--uninstall]"
        exit 0 ;;
    "") ;;
    *) die "unknown option $1" ;;
esac

if   command -v pacman  >/dev/null 2>&1; then family=arch
elif command -v apt-get >/dev/null 2>&1; then family=debian
else family=other
fi

if [ "$uninstall" -eq 1 ]; then
    case "$family" in
        arch)   $SUDO pacman -Rns cryptosec ;;
        debian) $SUDO apt-get remove -y cryptosec ;;
        other)  $SUDO make uninstall PREFIX="${PREFIX:-/usr/local}" ;;
    esac
    say "cryptosec removed. Your key store in ~/.config/cryptosec was kept."
    exit 0
fi

command -v cargo >/dev/null 2>&1 || {
    case "$family" in
        arch)   die "cargo is missing: sudo pacman -S rust" ;;
        debian) die "cargo is missing: sudo apt install cargo" ;;
        other)  die "cargo is missing, install Rust from https://rustup.rs" ;;
    esac
}

case "$family" in
    arch)
        [ "$(id -u)" -ne 0 ] || die "on Arch, run this as a normal user (makepkg refuses root)"
        command -v makepkg >/dev/null 2>&1 || die "makepkg is missing: sudo pacman -S base-devel"
        say "==> building a pacman package"
        pkg=$(packaging/build-arch.sh --nocheck)
        say "==> installing $pkg"
        $SUDO pacman -U --noconfirm "$pkg"
        ;;
    debian)
        command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb is missing: sudo apt install dpkg-dev"
        say "==> building a .deb"
        deb=$(packaging/build-deb.sh)
        say "==> installing $deb"
        $SUDO dpkg -i "$deb" || $SUDO apt-get -f install -y
        ;;
    other)
        say "==> no pacman or apt found, installing to ${PREFIX:-/usr/local} directly"
        make build
        $SUDO make install PREFIX="${PREFIX:-/usr/local}"
        $SUDO make update-caches PREFIX="${PREFIX:-/usr/local}" || true
        ;;
esac

say ""
say "cryptosec $(cryptosec --version 2>/dev/null | awk '{print $2}') is installed."
say "Try:  cryptosec -e some-file.txt"
say "Docs: man cryptosec"
