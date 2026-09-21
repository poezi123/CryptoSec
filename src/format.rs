use std::io::{Read, Write};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Marker that separates the readable preamble from the binary container.
pub const MAGIC: &[u8] = b"CSEC\x01";
/// First line of every container. Also used as the shared-mime-info magic.
pub const BANNER: &str = "Encrypted by CryptoSec";
pub const EXTENSION: &str = "csec";
pub const CHUNK: usize = 1024 * 1024;
pub const TAG: usize = 16;
/// Upper bound for the preamble scan, so a random file is rejected quickly.
const PREAMBLE_LIMIT: usize = 8 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Meta {
    pub version: u32,
    pub cipher: Cipher,
    pub recipient: Recipient,
    pub nonce_prefix: String,
    pub chunk_size: u32,
    pub created: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

impl Cipher {
    pub fn label(&self) -> &'static str {
        match self {
            Cipher::Aes256Gcm => "AES-256-GCM",
            Cipher::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }
}

/// How the data key is wrapped. Everything here is public by design.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "mode")]
pub enum Recipient {
    #[serde(rename = "password")]
    Password {
        kdf: String,
        salt: String,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        wrap_nonce: String,
        wrapped: String,
    },
    #[serde(rename = "rsa-4096")]
    Rsa {
        fingerprint: String,
        wrapped: String,
    },
    #[serde(rename = "x25519")]
    X25519 {
        fingerprint: String,
        ephemeral: String,
        wrap_nonce: String,
        wrapped: String,
    },
    #[serde(rename = "ml-kem-768")]
    MlKem {
        fingerprint: String,
        kem_ct: String,
        wrap_nonce: String,
        wrapped: String,
    },
}

impl Recipient {
    pub fn label(&self) -> String {
        match self {
            Recipient::Password { kdf, .. } => format!("password ({kdf})"),
            Recipient::Rsa { fingerprint, .. } => format!("RSA-4096 key {fingerprint}"),
            Recipient::X25519 { fingerprint, .. } => format!("X25519 key {fingerprint}"),
            Recipient::MlKem { fingerprint, .. } => format!("ML-KEM-768 key {fingerprint}"),
        }
    }

    pub fn fingerprint(&self) -> Option<&str> {
        match self {
            Recipient::Password { .. } => None,
            Recipient::Rsa { fingerprint, .. }
            | Recipient::X25519 { fingerprint, .. }
            | Recipient::MlKem { fingerprint, .. } => Some(fingerprint),
        }
    }
}

/// Written as the first record of the encrypted stream, so the original name
/// never shows up in clear text.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub name: String,
    pub kind: Kind,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Directory,
}

impl Kind {
    pub fn label(&self) -> &'static str {
        match self {
            Kind::File => "single file",
            Kind::Directory => "directory (tar archive)",
        }
    }
}

pub fn preamble(meta: &Meta, container_name: &str) -> String {
    format!(
        "{BANNER}\n\
         ==============================================================\n\
         \x20 Cipher    : {}\n\
         \x20 Key mode  : {}\n\
         \x20 Created   : {}\n\
         \x20 Decrypt   : cryptosec -d {}\n\
         ==============================================================\n\
         The payload below is encrypted. Without the matching password\n\
         or private key it cannot be recovered - not by this tool and\n\
         not by anyone else.\n\n",
        meta.cipher.label(),
        meta.recipient.label(),
        meta.created,
        container_name,
    )
}

pub fn write_header<W: Write>(out: &mut W, meta: &Meta, container_name: &str) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(meta)?;
    out.write_all(preamble(meta, container_name).as_bytes())?;
    out.write_all(MAGIC)?;
    out.write_all(&(json.len() as u32).to_le_bytes())?;
    out.write_all(&json)?;
    Ok(json)
}

/// Reads preamble plus metadata and leaves the reader at the first chunk.
pub fn read_header<R: Read>(input: &mut R) -> Result<(Meta, Vec<u8>)> {
    let mut scan: Vec<u8> = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if input.read(&mut byte)? == 0 {
            bail!("not a CryptoSec container (no header found)");
        }
        scan.push(byte[0]);
        if scan.ends_with(MAGIC) {
            break;
        }
        if scan.len() > PREAMBLE_LIMIT {
            bail!("not a CryptoSec container (no header found)");
        }
    }

    let mut len = [0u8; 4];
    input.read_exact(&mut len).context("truncated header")?;
    let len = u32::from_le_bytes(len) as usize;
    if len == 0 || len > PREAMBLE_LIMIT {
        bail!("corrupt header (metadata length {len})");
    }
    let mut json = vec![0u8; len];
    input.read_exact(&mut json).context("truncated header")?;
    let meta: Meta = serde_json::from_slice(&json).context("corrupt header")?;
    if meta.version != 1 {
        bail!(
            "container version {} is not supported by this build",
            meta.version
        );
    }
    if meta.chunk_size as usize != CHUNK {
        bail!("unsupported chunk size {}", meta.chunk_size);
    }
    Ok((meta, json))
}

/// Associated data for every chunk, binding the payload to its header.
pub fn aad(meta_json: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"cryptosec/v1");
    h.update(meta_json);
    h.finalize().into()
}

pub fn looks_encrypted(path: &std::path::Path) -> bool {
    if let Ok(mut f) = std::fs::File::open(path) {
        let mut head = [0u8; 32];
        if let Ok(n) = f.read(&mut head) {
            return head[..n].starts_with(BANNER.as_bytes());
        }
    }
    false
}
