//! Radix-Cascade: Radix-AEAD inside ChaCha20-Poly1305 inside AES-256-GCM,
//! each layer with its own key derived from one master key, plus a key
//! commitment in front.
//!
//! Radix sits innermost: it only ever decrypts data that already passed both
//! standard tags. While either standard layer holds, the cascade is as strong
//! as that layer, and the commitment binds every ciphertext to exactly one
//! master key, which neither AES-GCM nor ChaCha20-Poly1305 does on its own.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::aead;

pub const NONCE: usize = 12;
/// Length of the key commitment in front of the ciphertext.
pub const COMMIT: usize = 32;
/// Commitment plus one tag per layer.
pub const OVERHEAD: usize = COMMIT + aead::TAG + 16 + 16;
/// AES-GCM allows 2^36 - 32 bytes per nonce, and its input is the message
/// plus the two inner tags.
pub const MAX_MESSAGE: u64 = (1 << 36) - 32 - aead::TAG as u64 - 16;

const SALT: &[u8] = b"radix/cascade/v1";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Wrong key, wrong nonce, wrong associated data or modified data.
    Auth,
    TooLong,
}

/// The three layer keys and the commitment, derived once from a master key.
pub struct Cascade {
    radix: [u8; 32],
    chacha: ChaCha20Poly1305,
    aes: Aes256Gcm,
    commit: [u8; 32],
}

impl Drop for Cascade {
    fn drop(&mut self) {
        self.radix.zeroize();
        self.commit.zeroize();
    }
}

/// Radix takes a 16 byte nonce; the 12 byte cascade nonce gets a fixed tail.
/// The map is injective, so unique nonces stay unique.
fn radix_nonce(nonce: &[u8; NONCE]) -> [u8; aead::NONCE] {
    let mut n = [0u8; aead::NONCE];
    n[..NONCE].copy_from_slice(nonce);
    n[NONCE..].copy_from_slice(b"csc1");
    n
}

impl Cascade {
    /// HKDF-SHA256 with a distinct label per output. Under the PRF assumption
    /// for HMAC-SHA256 the outputs are independent, so the public commitment
    /// says nothing about the layer keys.
    pub fn new(master: &[u8; 32]) -> Self {
        let h = Hkdf::<Sha256>::new(Some(SALT), master);
        let mut radix = [0u8; 32];
        let mut chacha = [0u8; 32];
        let mut aes = [0u8; 32];
        let mut commit = [0u8; 32];
        h.expand(b"layer 1: radix-aead", &mut radix).unwrap();
        h.expand(b"layer 2: chacha20-poly1305", &mut chacha)
            .unwrap();
        h.expand(b"layer 3: aes-256-gcm", &mut aes).unwrap();
        h.expand(b"key commitment", &mut commit).unwrap();
        let c = Cascade {
            radix,
            chacha: ChaCha20Poly1305::new((&chacha).into()),
            aes: Aes256Gcm::new((&aes).into()),
            commit,
        };
        chacha.zeroize();
        aes.zeroize();
        c
    }

    /// Returns commitment || AES-GCM(ChaCha20-Poly1305(Radix-AEAD(msg))).
    pub fn seal(&self, nonce: &[u8; NONCE], ad: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        if msg.len() as u64 > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let mut inner = aead::encrypt(&self.radix, &radix_nonce(nonce), ad, msg);
        let middle = self.chacha.encrypt(
            nonce.into(),
            Payload {
                msg: &inner,
                aad: ad,
            },
        );
        inner.zeroize();
        let mut middle = middle.map_err(|_| Error::TooLong)?;
        let outer = self.aes.encrypt(
            nonce.into(),
            Payload {
                msg: &middle,
                aad: ad,
            },
        );
        middle.zeroize();
        let outer = outer.map_err(|_| Error::TooLong)?;
        let mut out = Vec::with_capacity(COMMIT + outer.len());
        out.extend_from_slice(&self.commit);
        out.extend_from_slice(&outer);
        Ok(out)
    }

    /// Checks the commitment, then peels the layers from the outside in.
    pub fn open(&self, nonce: &[u8; NONCE], ad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
        if sealed.len() < OVERHEAD {
            return Err(Error::Auth);
        }
        let (commit, outer) = sealed.split_at(COMMIT);
        if !bool::from(commit.ct_eq(&self.commit)) {
            return Err(Error::Auth);
        }
        let mut middle = self
            .aes
            .decrypt(
                nonce.into(),
                Payload {
                    msg: outer,
                    aad: ad,
                },
            )
            .map_err(|_| Error::Auth)?;
        let inner = self.chacha.decrypt(
            nonce.into(),
            Payload {
                msg: &middle,
                aad: ad,
            },
        );
        middle.zeroize();
        let mut inner = inner.map_err(|_| Error::Auth)?;
        let plain = aead::decrypt(&self.radix, &radix_nonce(nonce), ad, &inner);
        inner.zeroize();
        plain.map_err(|_| Error::Auth)
    }
}

pub fn seal(
    master: &[u8; 32],
    nonce: &[u8; NONCE],
    ad: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, Error> {
    Cascade::new(master).seal(nonce, ad, msg)
}

pub fn open(
    master: &[u8; 32],
    nonce: &[u8; NONCE],
    ad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, Error> {
    Cascade::new(master).open(nonce, ad, sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The final 84 bytes of the worked example in the Radix description.
    #[test]
    fn known_answer() {
        let master: [u8; 32] =
            unhex("a547e729f35ce60fdaa650f1bff6e6117ddaa7e55f48cc72d0e7adc390ef3050")
                .try_into()
                .unwrap();
        let sealed = seal(&master, b"Nonce-Bsp-01", b"", b"Text").unwrap();
        assert_eq!(
            sealed,
            unhex(
                "a31d2c385d1d74b5f91e5770a6370e91266ee15431b2307504a10fb45c28ed1c\
                 20ccf23cf625b05a8b09ec7be8b3136f7c7aaff7f06bbe9ede829bcc363d640a\
                 f725f6d8d3bb6387d6b789fa81370f6b3884e6b8"
            )
        );
        assert_eq!(
            open(&master, b"Nonce-Bsp-01", b"", &sealed).unwrap(),
            b"Text"
        );
    }

    #[test]
    fn every_bit_flip_and_cut_is_rejected() {
        let master = [0x42u8; 32];
        let n = *b"cascade-0001";
        let sealed = seal(&master, &n, b"hdr", b"tamper me").unwrap();
        assert_eq!(sealed.len(), 9 + OVERHEAD);
        for i in 0..sealed.len() * 8 {
            let mut bad = sealed.clone();
            bad[i / 8] ^= 1 << (i % 8);
            assert_eq!(open(&master, &n, b"hdr", &bad), Err(Error::Auth), "bit {i}");
        }
        for cut in 0..sealed.len() {
            assert!(
                open(&master, &n, b"hdr", &sealed[..cut]).is_err(),
                "cut {cut}"
            );
        }
        assert!(open(&master, &n, b"HDR", &sealed).is_err());
        let mut other = master;
        other[0] ^= 1;
        assert!(open(&other, &n, b"hdr", &sealed).is_err());
    }

    #[test]
    fn commitment_binds_the_master_key() {
        let n = *b"cascade-0002";
        let a = seal(&[1u8; 32], &n, b"", b"same").unwrap();
        let b = seal(&[2u8; 32], &n, b"", b"same").unwrap();
        assert_ne!(a[..COMMIT], b[..COMMIT]);
        let mut mixed = a.clone();
        mixed[..COMMIT].copy_from_slice(&b[..COMMIT]);
        assert!(open(&[1u8; 32], &n, b"", &mixed).is_err());
        assert!(open(&[2u8; 32], &n, b"", &mixed).is_err());
    }
}
