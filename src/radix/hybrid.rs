//! Radix-Hybrid: X25519 and ML-KEM-768 combined into one KEM.
//!
//! The shared secret is HKDF over both component secrets plus the full
//! transcript (both ciphertexts and both public keys). It stays secret as long
//! as at least one of the two components is secure.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublic, SharedSecret, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

type MlEk = <MlKem768 as KemCore>::EncapsulationKey;
type MlDk = <MlKem768 as KemCore>::DecapsulationKey;

pub const SALT: &[u8] = b"radix/hybrid/v1";
pub const ML_CT: usize = 1088;
pub const ML_EK: usize = 1184;
pub const ML_DK: usize = 2400;
/// Encoded t-hat: 3 polynomials of 256 coefficients, 12 bit each.
pub const ML_T: usize = 1152;
const Q: u16 = 3329;

/// The 32 byte shared secret; wiped when dropped.
pub type SharedKey = Zeroizing<[u8; 32]>;

pub struct SecretKey {
    x: StaticSecret,
    m: MlDk,
    public: PublicKey,
}

#[derive(Clone)]
pub struct PublicKey {
    pub x: XPublic,
    pub m: MlEk,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridCiphertext {
    /// Ephemeral X25519 public key.
    pub eph: [u8; 32],
    /// ML-KEM-768 ciphertext.
    pub kem: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KemError {
    /// The X25519 result was all zero, which happens for low order points.
    NonContributory,
    Malformed,
    Encapsulation,
    /// A stored key failed the FIPS 203 input checks.
    InvalidKey,
}

/// FIPS 203, 7.2 "modulus check": every 12 bit coefficient of t-hat must be
/// below q, i.e. ByteEncode12(ByteDecode12(t)) == t.
pub fn check_encapsulation_key(ek: &[u8]) -> Result<(), KemError> {
    if ek.len() != ML_EK {
        return Err(KemError::InvalidKey);
    }
    for c in ek[..ML_T].chunks_exact(3) {
        let a = u16::from(c[0]) | (u16::from(c[1] & 0x0f) << 8);
        let b = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
        if a >= Q || b >= Q {
            return Err(KemError::InvalidKey);
        }
    }
    Ok(())
}

/// FIPS 203, 7.3 "hash check": dk = dk_PKE || ek || H(ek) || z, and the stored
/// H(ek) must match the embedded ek. The embedded ek gets the modulus check too.
pub fn check_decapsulation_key(dk: &[u8]) -> Result<(), KemError> {
    if dk.len() != ML_DK {
        return Err(KemError::InvalidKey);
    }
    let ek = &dk[ML_T..ML_T + ML_EK];
    let h = &dk[ML_T + ML_EK..ML_T + ML_EK + 32];
    check_encapsulation_key(ek)?;
    let actual = Sha3_256::digest(ek);
    if bool::from(actual.as_slice().ct_eq(h)) {
        Ok(())
    } else {
        Err(KemError::InvalidKey)
    }
}

impl SecretKey {
    pub fn generate() -> Self {
        let x = StaticSecret::random_from_rng(OsRng);
        let (m, ek) = MlKem768::generate(&mut OsRng);
        Self::from_parts(x, m, ek)
    }

    fn from_parts(x: StaticSecret, m: MlDk, ek: MlEk) -> Self {
        let public = PublicKey {
            x: XPublic::from(&x),
            m: ek,
        };
        SecretKey { x, m, public }
    }

    /// X25519 secret (32 byte) || ML-KEM decapsulation key (2400 byte).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(32 + ML_DK));
        out.extend_from_slice(self.x.as_bytes());
        out.extend_from_slice(self.m.as_bytes().as_slice());
        out
    }

    /// Parses `to_bytes` output and runs the FIPS 203 decapsulation key check.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, KemError> {
        if raw.len() != 32 + ML_DK {
            return Err(KemError::InvalidKey);
        }
        check_decapsulation_key(&raw[32..])?;
        let mut x = [0u8; 32];
        x.copy_from_slice(&raw[..32]);
        let x_secret = StaticSecret::from(x);
        x.zeroize();
        let enc = raw[32..].try_into().map_err(|_| KemError::InvalidKey)?;
        let m = MlDk::from_bytes(enc);
        let ek = m.encapsulation_key().clone();
        Ok(Self::from_parts(x_secret, m, ek))
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

impl PublicKey {
    /// X25519 public key (32 byte) || ML-KEM encapsulation key (1184 byte).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.x.as_bytes().to_vec();
        out.extend_from_slice(self.m.as_bytes().as_slice());
        out
    }

    /// Parses `to_bytes` output and runs the FIPS 203 modulus check.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, KemError> {
        if raw.len() != 32 + ML_EK {
            return Err(KemError::InvalidKey);
        }
        check_encapsulation_key(&raw[32..])?;
        let x: [u8; 32] = raw[..32].try_into().map_err(|_| KemError::InvalidKey)?;
        let enc = raw[32..].try_into().map_err(|_| KemError::InvalidKey)?;
        Ok(PublicKey {
            x: XPublic::from(x),
            m: MlEk::from_bytes(enc),
        })
    }
}

/// shared = HKDF-SHA256(salt = label, ikm = ss_mlkem || ss_x25519,
///                      info = ct_mlkem || eph || pk_x25519 || pk_mlkem)
pub fn combine(ss_m: &[u8], ss_x: &[u8], ct: &HybridCiphertext, pk: &PublicKey) -> SharedKey {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ss_m);
    ikm.extend_from_slice(ss_x);
    let h = Hkdf::<Sha256>::new(Some(SALT), &ikm);

    let mut info = Vec::with_capacity(ML_CT + 32 + 32 + ML_EK);
    info.extend_from_slice(&ct.kem);
    info.extend_from_slice(&ct.eph);
    info.extend_from_slice(pk.x.as_bytes());
    info.extend_from_slice(pk.m.as_bytes().as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    h.expand(&info, out.as_mut()).unwrap();
    out
}

/// Shared tail of both encapsulation paths.
fn finish(
    pk: &PublicKey,
    eph_pub: XPublic,
    ss_x: SharedSecret,
    kem_ct: Ciphertext<MlKem768>,
    mut ss_m: ml_kem::SharedKey<MlKem768>,
) -> Result<(HybridCiphertext, SharedKey), KemError> {
    if !ss_x.was_contributory() {
        ss_m.as_mut_slice().zeroize();
        return Err(KemError::NonContributory);
    }
    let ct = HybridCiphertext {
        eph: *eph_pub.as_bytes(),
        kem: kem_ct.to_vec(),
    };
    let shared = combine(ss_m.as_slice(), ss_x.as_bytes(), &ct, pk);
    ss_m.as_mut_slice().zeroize();
    Ok((ct, shared))
}

/// Fresh randomness from the operating system for both components. The
/// ephemeral X25519 secret is an `EphemeralSecret`, so it can be used exactly
/// once and is wiped right after the Diffie-Hellman step.
pub fn encapsulate(pk: &PublicKey) -> Result<(HybridCiphertext, SharedKey), KemError> {
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = XPublic::from(&eph);
    let ss_x = eph.diffie_hellman(&pk.x);
    let (kem_ct, ss_m) =
        pk.m.encapsulate(&mut OsRng)
            .map_err(|_| KemError::Encapsulation)?;
    finish(pk, eph_pub, ss_x, kem_ct, ss_m)
}

pub fn decapsulate(sk: &SecretKey, ct: &HybridCiphertext) -> Result<SharedKey, KemError> {
    let ss_x = sk.x.diffie_hellman(&XPublic::from(ct.eph));
    if !ss_x.was_contributory() {
        return Err(KemError::NonContributory);
    }
    let kem_ct: &Ciphertext<MlKem768> = ct
        .kem
        .as_slice()
        .try_into()
        .map_err(|_| KemError::Malformed)?;
    // ML-KEM uses implicit rejection: a manipulated ciphertext does not fail
    // here but yields an unrelated secret, so the later AEAD check fails.
    let mut ss_m = sk.m.decapsulate(kem_ct).map_err(|_| KemError::Malformed)?;
    let shared = combine(ss_m.as_slice(), ss_x.as_bytes(), ct, &sk.public);
    ss_m.as_mut_slice().zeroize();
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_agree_and_strangers_do_not() {
        let alice = SecretKey::generate();
        let bob = SecretKey::generate();
        let (ct, ss) = encapsulate(alice.public()).unwrap();
        assert_eq!(ct.kem.len(), ML_CT);
        assert_eq!(decapsulate(&alice, &ct).unwrap(), ss);
        assert_ne!(decapsulate(&bob, &ct).unwrap(), ss);
        let mut bad = ct.clone();
        bad.kem[100] ^= 1;
        assert_ne!(decapsulate(&alice, &bad).unwrap(), ss);
    }

    #[test]
    fn low_order_points_are_rejected() {
        let sk = SecretKey::generate();
        let (mut ct, _) = encapsulate(sk.public()).unwrap();
        for u in [0u8, 1] {
            ct.eph = [0u8; 32];
            ct.eph[0] = u;
            assert_eq!(decapsulate(&sk, &ct), Err(KemError::NonContributory));
        }
    }

    #[test]
    fn keys_round_trip_through_bytes() {
        let sk = SecretKey::generate();
        let sk2 = SecretKey::from_bytes(&sk.to_bytes()).unwrap();
        let pk2 = PublicKey::from_bytes(&sk.public().to_bytes()).unwrap();
        let (ct, ss) = encapsulate(&pk2).unwrap();
        assert_eq!(decapsulate(&sk2, &ct).unwrap(), ss);
    }

    #[test]
    fn fips_203_checks_refuse_bad_keys() {
        let sk = SecretKey::generate();
        let mut pk = sk.public().to_bytes();
        // First coefficient of t-hat set to exactly q.
        pk[32] = (Q & 0xff) as u8;
        pk[33] = (pk[33] & 0xf0) | (Q >> 8) as u8;
        assert_eq!(PublicKey::from_bytes(&pk).err(), Some(KemError::InvalidKey));
        pk[32] = ((Q - 1) & 0xff) as u8;
        assert!(PublicKey::from_bytes(&pk).is_ok());

        let raw = sk.to_bytes();
        for pos in [32 + ML_T + 10, 32 + ML_T + ML_EK] {
            let mut bad = raw.to_vec();
            bad[pos] ^= 1;
            assert!(SecretKey::from_bytes(&bad).is_err(), "byte {pos}");
        }
        assert!(SecretKey::from_bytes(&raw[1..]).is_err());
    }
}
