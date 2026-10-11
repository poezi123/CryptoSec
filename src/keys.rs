use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroize;

use crate::kdf;
use crate::radix::{cascade, hybrid};

type MlEk = <MlKem768 as KemCore>::EncapsulationKey;
type MlDk = <MlKem768 as KemCore>::DecapsulationKey;

/// FIPS 203, 7.2: every coefficient of t-hat must be below q = 3329. The
/// ml-kem crate does not check this itself.
fn check_ml_kem_public(ek: &[u8]) -> Result<()> {
    hybrid::check_encapsulation_key(ek).map_err(|_| anyhow!("invalid ML-KEM public key"))
}

/// FIPS 203, 7.3: the H(ek) stored in dk must match the embedded ek.
fn check_ml_kem_private(dk: &[u8]) -> Result<()> {
    hybrid::check_decapsulation_key(dk).map_err(|_| anyhow!("damaged ML-KEM private key"))
}

/// Associated data for the data key wrapped under Radix-Cascade.
const RADIX_WRAP_AD: &[u8] = b"cryptosec/radix/keywrap/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgo {
    Rsa4096,
    X25519,
    MlKem768,
    /// X25519 + ML-KEM-768 hybrid, the key pair of the Radix scheme.
    Radix,
}

impl KeyAlgo {
    pub fn tag(&self) -> &'static str {
        match self {
            KeyAlgo::Rsa4096 => "rsa-4096",
            KeyAlgo::X25519 => "x25519",
            KeyAlgo::MlKem768 => "ml-kem-768",
            KeyAlgo::Radix => "radix-hybrid",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            KeyAlgo::Rsa4096 => "RSA-4096",
            KeyAlgo::X25519 => "X25519 (ECC)",
            KeyAlgo::MlKem768 => "ML-KEM-768",
            KeyAlgo::Radix => "Radix (concept)",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "rsa-4096" | "rsa" => Ok(KeyAlgo::Rsa4096),
            "x25519" | "ecc" => Ok(KeyAlgo::X25519),
            "ml-kem-768" | "mlkem" | "ml-kem" => Ok(KeyAlgo::MlKem768),
            "radix-hybrid" | "radix" => Ok(KeyAlgo::Radix),
            other => bail!("unknown key type '{other}'"),
        }
    }
}

pub enum PublicKey {
    Rsa(Box<RsaPublicKey>),
    X25519(XPublic),
    MlKem(Box<MlEk>),
    Radix(Box<hybrid::PublicKey>),
}

pub enum PrivateKey {
    Rsa(Box<RsaPrivateKey>),
    X25519(StaticSecret),
    MlKem(Box<MlDk>),
    Radix(Box<hybrid::SecretKey>),
}

impl PublicKey {
    pub fn algo(&self) -> KeyAlgo {
        match self {
            PublicKey::Rsa(_) => KeyAlgo::Rsa4096,
            PublicKey::X25519(_) => KeyAlgo::X25519,
            PublicKey::MlKem(_) => KeyAlgo::MlKem768,
            PublicKey::Radix(_) => KeyAlgo::Radix,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(match self {
            PublicKey::Rsa(k) => k.to_public_key_der()?.as_bytes().to_vec(),
            PublicKey::X25519(k) => k.as_bytes().to_vec(),
            PublicKey::MlKem(k) => k.as_bytes().to_vec(),
            PublicKey::Radix(k) => k.to_bytes(),
        })
    }

    pub fn from_bytes(algo: KeyAlgo, raw: &[u8]) -> Result<Self> {
        Ok(match algo {
            KeyAlgo::Rsa4096 => PublicKey::Rsa(Box::new(
                RsaPublicKey::from_public_key_der(raw).context("damaged RSA public key")?,
            )),
            KeyAlgo::X25519 => {
                let arr: [u8; 32] = raw.try_into().context("damaged X25519 public key")?;
                PublicKey::X25519(XPublic::from(arr))
            }
            KeyAlgo::MlKem768 => {
                check_ml_kem_public(raw)?;
                let enc = raw
                    .try_into()
                    .map_err(|_| anyhow!("damaged ML-KEM public key"))?;
                PublicKey::MlKem(Box::new(MlEk::from_bytes(enc)))
            }
            KeyAlgo::Radix => PublicKey::Radix(Box::new(
                hybrid::PublicKey::from_bytes(raw)
                    .map_err(|_| anyhow!("invalid Radix public key"))?,
            )),
        })
    }

    pub fn fingerprint(&self) -> Result<String> {
        Ok(fingerprint(self.algo(), &self.to_bytes()?))
    }
}

impl PrivateKey {
    pub fn algo(&self) -> KeyAlgo {
        match self {
            PrivateKey::Rsa(_) => KeyAlgo::Rsa4096,
            PrivateKey::X25519(_) => KeyAlgo::X25519,
            PrivateKey::MlKem(_) => KeyAlgo::MlKem768,
            PrivateKey::Radix(_) => KeyAlgo::Radix,
        }
    }

    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Rsa(k) => PublicKey::Rsa(Box::new(k.to_public_key())),
            PrivateKey::X25519(k) => PublicKey::X25519(XPublic::from(k)),
            PrivateKey::MlKem(k) => PublicKey::MlKem(Box::new(k.encapsulation_key().clone())),
            PrivateKey::Radix(k) => PublicKey::Radix(Box::new(k.public().clone())),
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(match self {
            PrivateKey::Rsa(k) => k.to_pkcs8_der()?.as_bytes().to_vec(),
            PrivateKey::X25519(k) => k.to_bytes().to_vec(),
            PrivateKey::MlKem(k) => k.as_bytes().to_vec(),
            PrivateKey::Radix(k) => k.to_bytes().to_vec(),
        })
    }

    fn from_bytes(algo: KeyAlgo, raw: &[u8]) -> Result<Self> {
        Ok(match algo {
            KeyAlgo::Rsa4096 => PrivateKey::Rsa(Box::new(
                RsaPrivateKey::from_pkcs8_der(raw).context("damaged RSA private key")?,
            )),
            KeyAlgo::X25519 => {
                let arr: [u8; 32] = raw.try_into().context("damaged X25519 private key")?;
                PrivateKey::X25519(StaticSecret::from(arr))
            }
            KeyAlgo::MlKem768 => {
                check_ml_kem_private(raw)?;
                let enc = raw
                    .try_into()
                    .map_err(|_| anyhow!("damaged ML-KEM private key"))?;
                PrivateKey::MlKem(Box::new(MlDk::from_bytes(enc)))
            }
            KeyAlgo::Radix => PrivateKey::Radix(Box::new(
                hybrid::SecretKey::from_bytes(raw)
                    .map_err(|_| anyhow!("damaged Radix private key"))?,
            )),
        })
    }
}

pub fn fingerprint(algo: KeyAlgo, pub_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(algo.tag().as_bytes());
    h.update(b"\0");
    h.update(pub_bytes);
    let d = h.finalize();
    d[..8].iter().map(|b| format!("{b:02x}")).collect()
}

pub fn generate(algo: KeyAlgo) -> Result<PrivateKey> {
    let mut rng = rand::thread_rng();
    Ok(match algo {
        KeyAlgo::Rsa4096 => PrivateKey::Rsa(Box::new(RsaPrivateKey::new(&mut rng, 4096)?)),
        KeyAlgo::X25519 => PrivateKey::X25519(StaticSecret::random_from_rng(&mut rng)),
        KeyAlgo::MlKem768 => {
            let (dk, _) = MlKem768::generate(&mut rng);
            PrivateKey::MlKem(Box::new(dk))
        }
        KeyAlgo::Radix => PrivateKey::Radix(Box::new(hybrid::SecretKey::generate())),
    })
}

/// Wraps a 32 byte data key for the recipient. Returns the parts the header
/// needs: an optional KEM ciphertext plus the wrapped key itself.
pub fn wrap(pk: &PublicKey, dek: &[u8; 32]) -> Result<Wrapped> {
    let mut rng = rand::thread_rng();
    match pk {
        PublicKey::Rsa(k) => {
            let ct = k.encrypt(&mut rng, Oaep::new::<Sha256>(), dek)?;
            Ok(Wrapped {
                kem: None,
                nonce: None,
                wrapped: ct,
            })
        }
        PublicKey::X25519(k) => {
            let eph = StaticSecret::random_from_rng(&mut rng);
            let eph_pub = XPublic::from(&eph);
            let shared = eph.diffie_hellman(k);
            let kek = kdf::hkdf(
                shared.as_bytes(),
                b"cryptosec/x25519/v1",
                &[eph_pub.as_bytes().as_slice(), k.as_bytes().as_slice()],
            );
            let (nonce, wrapped) = kdf::wrap_with_kek(&kek, dek)?;
            Ok(Wrapped {
                kem: Some(eph_pub.as_bytes().to_vec()),
                nonce: Some(nonce),
                wrapped,
            })
        }
        PublicKey::MlKem(k) => {
            let (ct, shared) = k
                .encapsulate(&mut rng)
                .map_err(|_| anyhow!("ML-KEM encapsulation failed"))?;
            let ct = ct.to_vec();
            let kek = kdf::hkdf(shared.as_slice(), b"cryptosec/ml-kem-768/v1", &[&ct]);
            let (nonce, wrapped) = kdf::wrap_with_kek(&kek, dek)?;
            Ok(Wrapped {
                kem: Some(ct),
                nonce: Some(nonce),
                wrapped,
            })
        }
        PublicKey::Radix(k) => {
            // The hybrid secret is the master key of a Radix-Cascade that
            // wraps the data key, so the key wrap is a cascade as well.
            let (ct, master) =
                hybrid::encapsulate(k).map_err(|_| anyhow!("Radix encapsulation failed"))?;
            let nonce = kdf::random_bytes::<12>();
            let wrapped = cascade::seal(&master, &nonce, RADIX_WRAP_AD, dek)
                .map_err(|_| anyhow!("wrapping the data key failed"))?;
            let mut kem = ct.eph.to_vec();
            kem.extend_from_slice(&ct.kem);
            Ok(Wrapped {
                kem: Some(kem),
                nonce: Some(nonce),
                wrapped,
            })
        }
    }
}

pub struct Wrapped {
    pub kem: Option<Vec<u8>>,
    pub nonce: Option<[u8; 12]>,
    pub wrapped: Vec<u8>,
}

pub fn unwrap(
    sk: &PrivateKey,
    kem: Option<&[u8]>,
    nonce: Option<&[u8]>,
    wrapped: &[u8],
) -> Result<[u8; 32]> {
    match sk {
        PrivateKey::Rsa(k) => {
            let mut plain = k
                .decrypt(Oaep::new::<Sha256>(), wrapped)
                .map_err(|_| anyhow!("this private key does not fit the container"))?;
            let out: [u8; 32] = plain
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("unexpected data key length"))?;
            plain.zeroize();
            Ok(out)
        }
        PrivateKey::X25519(k) => {
            let kem = kem.ok_or_else(|| anyhow!("header is missing the ephemeral key"))?;
            let arr: [u8; 32] = kem.try_into().context("damaged ephemeral key")?;
            let eph_pub = XPublic::from(arr);
            let shared = k.diffie_hellman(&eph_pub);
            let own_pub = XPublic::from(k);
            let kek = kdf::hkdf(
                shared.as_bytes(),
                b"cryptosec/x25519/v1",
                &[eph_pub.as_bytes().as_slice(), own_pub.as_bytes().as_slice()],
            );
            kdf::unwrap_with_kek(&kek, nonce, wrapped)
        }
        PrivateKey::MlKem(k) => {
            let kem = kem.ok_or_else(|| anyhow!("header is missing the KEM ciphertext"))?;
            let ct = kem
                .try_into()
                .map_err(|_| anyhow!("damaged ML-KEM ciphertext"))?;
            let shared = k
                .decapsulate(ct)
                .map_err(|_| anyhow!("ML-KEM decapsulation failed"))?;
            let kek = kdf::hkdf(shared.as_slice(), b"cryptosec/ml-kem-768/v1", &[kem]);
            kdf::unwrap_with_kek(&kek, nonce, wrapped)
        }
        PrivateKey::Radix(k) => {
            let kem = kem.ok_or_else(|| anyhow!("header is missing the KEM ciphertext"))?;
            if kem.len() != 32 + hybrid::ML_CT {
                bail!("damaged Radix key exchange data");
            }
            let ct = hybrid::HybridCiphertext {
                eph: kem[..32].try_into().unwrap(),
                kem: kem[32..].to_vec(),
            };
            let nonce = nonce.ok_or_else(|| anyhow!("header is missing the wrap nonce"))?;
            let nonce: [u8; 12] = nonce.try_into().context("damaged wrap nonce")?;
            let master = hybrid::decapsulate(k, &ct)
                .map_err(|_| anyhow!("this private key does not fit the container"))?;
            let mut plain = cascade::open(&master, &nonce, RADIX_WRAP_AD, wrapped)
                .map_err(|_| anyhow!("wrong key - the data key did not unwrap"))?;
            let out: [u8; 32] = plain
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("unexpected data key length"))?;
            plain.zeroize();
            Ok(out)
        }
    }
}

// ---------------------------------------------------------------- key store

pub fn store_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("CRYPTOSEC_HOME") {
        Some(p) => PathBuf::from(p),
        None => match std::env::var_os("XDG_CONFIG_HOME") {
            Some(p) => PathBuf::from(p).join("cryptosec"),
            None => {
                let home = std::env::var_os("HOME")
                    .ok_or_else(|| anyhow!("HOME is not set, cannot locate the key store"))?;
                PathBuf::from(home).join(".config").join("cryptosec")
            }
        },
    };
    let dir = base.join("keys");
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).ok();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).ok();
    Ok(dir)
}

pub struct KeyEntry {
    pub name: String,
    pub algo: KeyAlgo,
    pub fingerprint: String,
    pub protected: bool,
    pub has_private: bool,
}

pub fn list() -> Result<Vec<KeyEntry>> {
    let dir = store_dir()?;
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pub") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let armor = Armor::parse(&fs::read_to_string(&path)?)?;
        let secret = dir.join(format!("{name}.key"));
        let protected = match fs::read_to_string(&secret) {
            Ok(text) => Armor::parse(&text)?.field("protection") != Some("none"),
            Err(_) => false,
        };
        out.push(KeyEntry {
            algo: KeyAlgo::parse(armor.field("algorithm").unwrap_or_default())?,
            fingerprint: armor.field("fingerprint").unwrap_or_default().to_string(),
            protected,
            has_private: secret.exists(),
            name,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

pub fn save(name: &str, sk: &PrivateKey, passphrase: Option<&str>) -> Result<(PathBuf, PathBuf)> {
    let dir = store_dir()?;
    let pk = sk.public();
    let algo = sk.algo();
    let fp = pk.fingerprint()?;
    let pub_path = dir.join(format!("{name}.pub"));
    let key_path = dir.join(format!("{name}.key"));
    if pub_path.exists() || key_path.exists() {
        bail!("a key named '{name}' already exists in {}", dir.display());
    }

    let mut pub_armor = Armor::new("PUBLIC", &pk.to_bytes()?);
    pub_armor.set("name", name);
    pub_armor.set("algorithm", algo.tag());
    pub_armor.set("fingerprint", &fp);
    fs::write(&pub_path, pub_armor.render())?;
    fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o644))?;

    let mut raw = sk.to_bytes()?;
    let (body, protection) = match passphrase {
        Some(pass) => {
            let sealed = kdf::seal_secret(pass, &raw)?;
            (serde_json::to_vec(&sealed)?, "argon2id")
        }
        None => (raw.clone(), "none"),
    };
    raw.zeroize();

    let mut key_armor = Armor::new("PRIVATE", &body);
    key_armor.set("name", name);
    key_armor.set("algorithm", algo.tag());
    key_armor.set("fingerprint", &fp);
    key_armor.set("protection", protection);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_path)?;
    f.write_all(key_armor.render().as_bytes())?;
    f.sync_all()?;
    Ok((pub_path, key_path))
}

pub fn load_public(name_or_path: &str) -> Result<(String, PublicKey)> {
    let path = resolve(name_or_path, "pub")?;
    let armor = Armor::parse(&fs::read_to_string(&path)?)?;
    let algo = KeyAlgo::parse(armor.field("algorithm").unwrap_or_default())?;
    let pk = PublicKey::from_bytes(algo, &armor.body)?;
    let name = armor.field("name").unwrap_or(name_or_path).to_string();
    Ok((name, pk))
}

/// Loads a private key, asking for its passphrase only when the file is protected.
pub fn load_private<F>(name_or_path: &str, ask: F) -> Result<PrivateKey>
where
    F: Fn(&str) -> Result<String>,
{
    let path = resolve(name_or_path, "key")?;
    let armor = Armor::parse(&fs::read_to_string(&path)?)?;
    let algo = KeyAlgo::parse(armor.field("algorithm").unwrap_or_default())?;
    let name = armor.field("name").unwrap_or(name_or_path).to_string();
    let mut raw = if armor.field("protection") == Some("none") {
        armor.body.clone()
    } else {
        let sealed: kdf::SealedSecret =
            serde_json::from_slice(&armor.body).context("damaged private key file")?;
        let mut pass = ask(&name)?;
        let out = kdf::open_secret(&pass, &sealed);
        pass.zeroize();
        out?
    };
    let sk = PrivateKey::from_bytes(algo, &raw);
    raw.zeroize();
    sk
}

/// Picks the stored key that matches a container's fingerprint.
pub fn find_by_fingerprint(fp: &str) -> Result<Option<KeyEntry>> {
    Ok(list()?
        .into_iter()
        .find(|k| k.fingerprint == fp && k.has_private))
}

fn resolve(name_or_path: &str, ext: &str) -> Result<PathBuf> {
    let direct = Path::new(name_or_path);
    if direct.is_file() {
        return Ok(direct.to_path_buf());
    }
    let candidate = store_dir()?.join(format!("{name_or_path}.{ext}"));
    if candidate.is_file() {
        return Ok(candidate);
    }
    bail!(
        "no key '{name_or_path}' found (looked in {})",
        store_dir()?.display()
    )
}

// ------------------------------------------------------------------- armor

pub struct Armor {
    kind: String,
    headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Armor {
    fn new(kind: &str, body: &[u8]) -> Self {
        Armor {
            kind: kind.to_string(),
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    fn set(&mut self, k: &str, v: &str) {
        self.headers.push((k.to_string(), v.to_string()));
    }

    pub fn field(&self, k: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }

    fn render(&self) -> String {
        let mut s = format!("-----BEGIN CRYPTOSEC {} KEY-----\n", self.kind);
        for (k, v) in &self.headers {
            s.push_str(&format!("{k}: {v}\n"));
        }
        s.push('\n');
        let b64 = B64.encode(&self.body);
        for line in b64.as_bytes().chunks(64) {
            s.push_str(std::str::from_utf8(line).unwrap());
            s.push('\n');
        }
        s.push_str(&format!("-----END CRYPTOSEC {} KEY-----\n", self.kind));
        s
    }

    fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        let begin = lines
            .next()
            .ok_or_else(|| anyhow!("empty key file"))?
            .trim();
        if !begin.starts_with("-----BEGIN CRYPTOSEC ") {
            bail!("not a CryptoSec key file");
        }
        let kind = begin
            .trim_start_matches("-----BEGIN CRYPTOSEC ")
            .trim_end_matches(" KEY-----")
            .to_string();
        let mut headers = Vec::new();
        let mut b64 = String::new();
        let mut in_body = false;
        for line in lines {
            let line = line.trim();
            if line.starts_with("-----END") {
                break;
            }
            if !in_body {
                if line.is_empty() {
                    in_body = true;
                    continue;
                }
                if let Some((k, v)) = line.split_once(':') {
                    headers.push((k.trim().to_string(), v.trim().to_string()));
                    continue;
                }
                in_body = true;
            }
            b64.push_str(line);
        }
        let body = B64.decode(b64.as_bytes()).context("damaged key file")?;
        Ok(Armor {
            kind,
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ml_kem_pair() -> (Vec<u8>, Vec<u8>) {
        let sk = generate(KeyAlgo::MlKem768).unwrap();
        (sk.to_bytes().unwrap(), sk.public().to_bytes().unwrap())
    }

    #[test]
    fn ml_kem_keys_round_trip() {
        let (dk, ek) = ml_kem_pair();
        let sk = PrivateKey::from_bytes(KeyAlgo::MlKem768, &dk).unwrap();
        let pk = PublicKey::from_bytes(KeyAlgo::MlKem768, &ek).unwrap();
        let dek = [7u8; 32];
        let w = wrap(&pk, &dek).unwrap();
        let back = unwrap(
            &sk,
            w.kem.as_deref(),
            w.nonce.as_ref().map(|n| &n[..]),
            &w.wrapped,
        )
        .unwrap();
        assert_eq!(back, dek);
    }

    #[test]
    fn ml_kem_public_key_out_of_range_is_refused() {
        let (_, mut ek) = ml_kem_pair();
        // First coefficient = 4095, above q.
        ek[0] = 0xff;
        ek[1] |= 0x0f;
        assert!(PublicKey::from_bytes(KeyAlgo::MlKem768, &ek).is_err());
    }

    #[test]
    fn ml_kem_private_key_with_wrong_hash_is_refused() {
        let (dk, _) = ml_kem_pair();
        for pos in [hybrid::ML_T + hybrid::ML_EK, hybrid::ML_T + 10] {
            let mut bad = dk.clone();
            bad[pos] ^= 1;
            assert!(
                PrivateKey::from_bytes(KeyAlgo::MlKem768, &bad).is_err(),
                "byte {pos}"
            );
        }
    }
}
