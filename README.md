# CryptoSec

A small command line tool that encrypts a file or a whole directory into a
single container, and decrypts it again. Written in Rust, Linux only.

```
$ cryptosec -e notes.txt
? Encryption scheme ›
❯ AES-256-GCM           password protected
  ChaCha20-Poly1305     password protected
  RSA-4096              key pair
  ECC / X25519          key pair
  ML-KEM-768            key pair, post-quantum
```

Opening the result in an editor does not show binary noise:

```
$ cat notes.txt.csec
Encrypted by CryptoSec
Decrypt with: cryptosec -d <this file>
Get it at: https://github.com/poezi123/CryptoSec
...
```

## Install

```
git clone https://github.com/poezi123/CryptoSec.git
cd CryptoSec
./install.sh
```

The installer builds a native package and hands it to the package manager:
`makepkg` plus `pacman -U` on Arch, `dpkg-deb` plus `dpkg -i` on Debian and
Ubuntu. Anywhere else it falls back to `make install` into `/usr/local`.
Removing it again works the usual way, or with `./install.sh --uninstall`.

Needs `cargo` (`pacman -S rust`, `apt install cargo`) and, on Arch,
`base-devel`.

## Usage

```
cryptosec -e PATH            encrypt a file or directory
cryptosec -d PATH            decrypt a container
cryptosec -k -e PATH         encrypt but keep the original alongside
cryptosec --info PATH        show what a container holds
cryptosec keygen NAME -t ecc create a key pair
cryptosec keys               list the key store
```

A directory is packed into a tar archive first, so permissions, symlinks and
empty directories survive. The container is always written next to the input
as `NAME.csec`; `-o` puts it somewhere else.

Encrypting replaces the input and decrypting replaces the container, so a
plaintext copy never stays behind next to its encrypted version.

Nothing is deleted on trust. After writing a container, cryptosec reads it
back through the normal decryption path and holds it against the original:
byte for byte for a file, and entry by entry for a directory, including file
contents, symlink targets and the number of entries. Only if all of that
matches does the source go away. If the check finds anything at all, the
container is discarded and the source stays.

`-k` keeps the input in place. `--no-verify` skips the check, and then keeps
the input as well, because nothing was proven. `--shred` overwrites the source
with random bytes before removing it.

Non-interactive use:

```
cryptosec --algo aes --password-stdin -e backup.tar < pw.txt
cryptosec --algo ecc --key work -e report.pdf
```

## Schemes

| Menu entry | Payload | Key handling |
| --- | --- | --- |
| AES-256-GCM | AES-256-GCM | Argon2id over your password |
| ChaCha20-Poly1305 | ChaCha20-Poly1305 | Argon2id over your password |
| RSA-4096 | AES-256-GCM | data key wrapped with RSA-OAEP (SHA-256) |
| ECC / X25519 | AES-256-GCM | ephemeral X25519, HKDF-SHA256, AES-GCM key wrap |
| ML-KEM-768 | AES-256-GCM | ML-KEM encapsulation, HKDF-SHA256, AES-GCM key wrap |

RSA and elliptic curves cannot encrypt bulk data directly, so the three key
pair schemes all work the same way: a random 256 bit data key encrypts the
payload, and only that key is wrapped for the recipient. This is the same
hybrid construction that PGP, age and TLS use.

Key pairs live in `~/.config/cryptosec/keys` (`NAME.pub`, `NAME.key`, mode
0600). Private keys are protected with a passphrase unless you pass
`--no-passphrase`. Encrypting only needs the public key; when decrypting, the
matching private key is looked up by the fingerprint stored in the container.

## Container layout

```
Encrypted by CryptoSec      readable banner, also used as the MIME magic
Decrypt with / Get it at    two fixed lines, identical in every container
CSEC\x01 | u32 | JSON       magic, length, header (salt, wrapped key, nonce)
chunk 0 .. chunk n          1 MiB each, AES-GCM or ChaCha20-Poly1305
```

The readable part is deliberately the same in every container. It says what
the file is and where to get the tool, and nothing about this particular
file.

Each chunk gets its own nonce built from a random per-file prefix, a counter
and a last-chunk flag, and is authenticated against a hash of the header.
Removing chunks from the end, swapping two chunks, appending data or editing
the header all fail to authenticate. The original file name sits in the first
record of the encrypted stream, not in the readable part.

## What it does not hide

The payload size, the scheme in use and, for key pair containers, the
recipient fingerprint. If that matters, pad the input or encrypt inside an
archive of a fixed size. No creation time is stored.

The header also holds the salt, the nonces and the wrapped data key in the
clear, and that is how it has to be. A salt is not a secret: its job is to
stop precomputed tables and to keep two containers with the same password
from being attacked together. Every design that stretches a password stores
it in the open, from LUKS to age to `/etc/shadow`. The same goes for the
scheme name. Anything cryptosec can read without a key, an attacker can read
too, so nothing there is treated as secret. What protects the payload is the
password and Argon2id, or the private key.

Removing the source unlinks it, which leaves the old blocks on the disk until
they are reused. `--shred` overwrites the contents once first, but on SSDs and
on copy-on-write filesystems such as Btrfs or ZFS older copies can still
survive. Treat it as a convenience, not a guarantee.

Losing a private key or forgetting a password means the data is gone. There is
no recovery path, and adding one would defeat the purpose.

## Desktop integration

The packages register `application/x-cryptosec` for `*.csec` and a desktop
entry that runs `cryptosec open` in a terminal. Opening a container from a
file manager shows what it is and offers to decrypt it.

## Building

```
make build     # cargo build --release --locked
make test      # round trips, tampering, truncation, key modes, replace rules
make install   # honours PREFIX and DESTDIR
```

The RSA test is marked `#[ignore]` because generating a 4096 bit key in an
unoptimised build is slow; run it with `cargo test --release -- --ignored`.

## License

MIT, see [LICENSE](LICENSE).
