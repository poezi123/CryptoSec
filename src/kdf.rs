use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

/// Argon2id cost. 64 MiB / 3 passes sits well above the OWASP minimum and
/// still finishes in well under a second on a normal desktop.
pub const M_COST: u32 = 65536;
pub const T_COST: u32 = 3;
pub const P_COST: u32 = 4;

const WRAP_AAD: &[u8] = b"cryptosec/keywrap/v1";

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

pub fn argon2id(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32]> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow!("invalid Argon2 parameters: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    a2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

pub fn hkdf(ikm: &[u8], info: &[u8], extra: &[&[u8]]) -> [u8; 32] {
    let h = Hkdf::<Sha256>::new(None, ikm);
    let mut full = info.to_vec();
    for part in extra {
        full.extend_from_slice(part);
    }
    let mut out = [0u8; 32];
    h.expand(&full, &mut out)
        .expect("32 bytes is a valid length");
    out
}

pub fn wrap_with_kek(kek: &[u8; 32], dek: &[u8; 32]) -> Result<([u8; 12], Vec<u8>)> {
    let nonce = random_bytes::<12>();
    let cipher = Aes256Gcm::new(kek.into());
    let ct = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: dek,
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| anyhow!("wrapping the data key failed"))?;
    Ok((nonce, ct))
}

pub fn unwrap_with_kek(kek: &[u8; 32], nonce: Option<&[u8]>, wrapped: &[u8]) -> Result<[u8; 32]> {
    let nonce = nonce.ok_or_else(|| anyhow!("header is missing the wrap nonce"))?;
    let nonce: [u8; 12] = nonce.try_into().context("damaged wrap nonce")?;
    let cipher = Aes256Gcm::new(kek.into());
    let mut plain = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: wrapped,
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| anyhow!("wrong password or key - the data key did not unwrap"))?;
    let out: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("unexpected data key length"))?;
    plain.zeroize();
    Ok(out)
}

/// Passphrase protection for private key files, same building blocks as the
/// password mode of the container itself.
#[derive(Serialize, Deserialize)]
pub struct SealedSecret {
    pub kdf: String,
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub nonce: String,
    pub data: String,
}

pub fn seal_secret(passphrase: &str, secret: &[u8]) -> Result<SealedSecret> {
    let salt = random_bytes::<16>();
    let mut kek = argon2id(passphrase, &salt, M_COST, T_COST, P_COST)?;
    let nonce = random_bytes::<12>();
    let cipher = Aes256Gcm::new(&kek.into());
    let data = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: secret,
                aad: b"cryptosec/privatekey/v1",
            },
        )
        .map_err(|_| anyhow!("protecting the private key failed"))?;
    kek.zeroize();
    Ok(SealedSecret {
        kdf: "argon2id".into(),
        salt: B64.encode(salt),
        m_cost: M_COST,
        t_cost: T_COST,
        p_cost: P_COST,
        nonce: B64.encode(nonce),
        data: B64.encode(data),
    })
}

pub fn open_secret(passphrase: &str, sealed: &SealedSecret) -> Result<Vec<u8>> {
    let salt = B64.decode(&sealed.salt).context("damaged key file")?;
    let nonce = B64.decode(&sealed.nonce).context("damaged key file")?;
    let data = B64.decode(&sealed.data).context("damaged key file")?;
    let nonce: [u8; 12] = nonce.as_slice().try_into().context("damaged key file")?;
    let mut kek = argon2id(
        passphrase,
        &salt,
        sealed.m_cost,
        sealed.t_cost,
        sealed.p_cost,
    )?;
    let cipher = Aes256Gcm::new(&kek.into());
    let out = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: data.as_slice(),
                aad: b"cryptosec/privatekey/v1",
            },
        )
        .map_err(|_| anyhow!("wrong passphrase for this private key"));
    kek.zeroize();
    out
}
