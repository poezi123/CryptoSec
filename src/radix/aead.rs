//! Radix-AEAD: authenticated encryption in a keyed duplex over Radix-P.
//!
//! Rate 256 bit (words 0..8), capacity 256 bit (words 8..16), 256 bit key,
//! 128 bit nonce, 128 bit tag, following the monkey-duplex layout of Ascon.
//! The key enters the capacity once more after initialisation and before the
//! tag, so a recovered state reveals neither the key nor a way to forge tags.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::permutation::{permute, State, ROUNDS};

pub const KEY: usize = 32;
pub const NONCE: usize = 16;
pub const TAG: usize = 16;
pub const RATE: usize = 32;

/// "RadixARX" in ASCII, then the parameters, so a different variant can never
/// share an initial state with this one.
const IV: [u32; 4] = [
    u32::from_le_bytes(*b"Radi"),
    u32::from_le_bytes(*b"xARX"),
    (1 << 24) | ((ROUNDS as u32) << 16) | ((RATE as u32) << 8) | (TAG as u32),
    0,
];

#[derive(Debug, PartialEq, Eq)]
pub struct AuthError;

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authentication failed")
    }
}

impl std::error::Error for AuthError {}

fn words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut out = [0u32; N];
    for (w, chunk) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        *w = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

/// Reads byte `i` of the state, little endian inside each word.
#[inline(always)]
fn get(s: &State, i: usize) -> u8 {
    (s[i / 4] >> (8 * (i % 4))) as u8
}

#[inline(always)]
fn xor(s: &mut State, i: usize, b: u8) {
    s[i / 4] ^= (b as u32) << (8 * (i % 4));
}

#[inline(always)]
fn set(s: &mut State, i: usize, b: u8) {
    let shift = 8 * (i % 4);
    s[i / 4] = (s[i / 4] & !(0xff << shift)) | ((b as u32) << shift);
}

struct Duplex {
    s: State,
    k: [u32; 8],
}

impl Drop for Duplex {
    fn drop(&mut self) {
        self.s.zeroize();
        self.k.zeroize();
    }
}

impl Duplex {
    fn new(key: &[u8; KEY], nonce: &[u8; NONCE]) -> Self {
        let k: [u32; 8] = words(key);
        let n: [u32; 4] = words(nonce);
        let mut s = [0u32; 16];
        s[..8].copy_from_slice(&k);
        s[8..12].copy_from_slice(&n);
        s[12..].copy_from_slice(&IV);
        permute(&mut s);
        let mut d = Duplex { s, k };
        d.key_into_capacity();
        d
    }

    fn key_into_capacity(&mut self) {
        for i in 0..8 {
            self.s[8 + i] ^= self.k[i];
        }
    }

    /// 10* padding, so every message, the empty one included, ends in a
    /// partial block and lengths 31 and 32 cannot collide.
    fn absorb_ad(&mut self, ad: &[u8]) {
        if !ad.is_empty() {
            let mut blocks = ad.chunks_exact(RATE);
            for block in &mut blocks {
                for (w, b) in self.s[..8].iter_mut().zip(block.chunks_exact(4)) {
                    *w ^= u32::from_le_bytes(b.try_into().unwrap());
                }
                permute(&mut self.s);
            }
            let rest = blocks.remainder();
            for (i, &b) in rest.iter().enumerate() {
                xor(&mut self.s, i, b);
            }
            xor(&mut self.s, rest.len(), 0x01);
            permute(&mut self.s);
        }
        // Domain separation between associated data and message, always set.
        self.s[15] ^= 0x8000_0000;
    }

    fn encrypt(&mut self, msg: &[u8], out: &mut Vec<u8>) {
        let mut blocks = msg.chunks_exact(RATE);
        for block in &mut blocks {
            for (w, m) in self.s[..8].iter_mut().zip(block.chunks_exact(4)) {
                *w ^= u32::from_le_bytes(m.try_into().unwrap());
                out.extend_from_slice(&w.to_le_bytes());
            }
            permute(&mut self.s);
        }
        let rest = blocks.remainder();
        for (i, &b) in rest.iter().enumerate() {
            xor(&mut self.s, i, b);
            out.push(get(&self.s, i));
        }
        xor(&mut self.s, rest.len(), 0x01);
    }

    fn decrypt(&mut self, ct: &[u8], out: &mut Vec<u8>) {
        let mut blocks = ct.chunks_exact(RATE);
        for block in &mut blocks {
            for (w, c) in self.s[..8].iter_mut().zip(block.chunks_exact(4)) {
                let c = u32::from_le_bytes(c.try_into().unwrap());
                out.extend_from_slice(&(*w ^ c).to_le_bytes());
                *w = c;
            }
            permute(&mut self.s);
        }
        let rest = blocks.remainder();
        for (i, &c) in rest.iter().enumerate() {
            out.push(get(&self.s, i) ^ c);
            set(&mut self.s, i, c);
        }
        xor(&mut self.s, rest.len(), 0x01);
    }

    fn tag(&mut self) -> [u8; TAG] {
        self.key_into_capacity();
        permute(&mut self.s);
        let mut t = [0u8; TAG];
        for i in 0..4 {
            let w = self.s[12 + i] ^ self.k[4 + i];
            t[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
        t
    }
}

/// Returns ciphertext || tag.
pub fn encrypt(key: &[u8; KEY], nonce: &[u8; NONCE], ad: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut d = Duplex::new(key, nonce);
    d.absorb_ad(ad);
    let mut out = Vec::with_capacity(msg.len() + TAG);
    d.encrypt(msg, &mut out);
    out.extend_from_slice(&d.tag());
    out
}

/// Plaintext is only returned after the tag matched; on failure the buffer
/// is wiped first.
pub fn decrypt(
    key: &[u8; KEY],
    nonce: &[u8; NONCE],
    ad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, AuthError> {
    if sealed.len() < TAG {
        return Err(AuthError);
    }
    let (ct, tag) = sealed.split_at(sealed.len() - TAG);
    let mut d = Duplex::new(key, nonce);
    d.absorb_ad(ad);
    let mut out = Vec::with_capacity(ct.len());
    d.decrypt(ct, &mut out);
    let expected = d.tag();
    if bool::from(expected.as_slice().ct_eq(tag)) {
        Ok(out)
    } else {
        out.zeroize();
        Err(AuthError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; KEY] = *b"0123456789abcdef0123456789abcdef";
    const N: [u8; NONCE] = *b"nonce-0000000001";

    #[test]
    fn known_answer() {
        let ct = encrypt(&K, &N, b"CryptoSec", b"Hallo Radix");
        let hex: String = ct.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "f9502b368b14487ba89257a12c93c1b44a856b7c8e447c90b42406"
        );
    }

    #[test]
    fn round_trip_across_block_boundaries() {
        for len in [0usize, 1, 31, 32, 33, 63, 64, 65, 1000] {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            for ad in [&b""[..], b"x", &[7u8; 32], &[9u8; 33]] {
                let ct = encrypt(&K, &N, ad, &msg);
                assert_eq!(ct.len(), len + TAG);
                assert_eq!(decrypt(&K, &N, ad, &ct).unwrap(), msg);
            }
        }
    }

    #[test]
    fn every_bit_flip_and_cut_is_rejected() {
        let ct = encrypt(&K, &N, b"ad", b"forty bytes of message for the check!!");
        for i in 0..ct.len() * 8 {
            let mut bad = ct.clone();
            bad[i / 8] ^= 1 << (i % 8);
            assert!(decrypt(&K, &N, b"ad", &bad).is_err(), "bit {i}");
        }
        for cut in 0..ct.len() {
            assert!(decrypt(&K, &N, b"ad", &ct[..cut]).is_err(), "cut {cut}");
        }
        assert!(decrypt(&K, &N, b"aD", &ct).is_err());
    }
}
