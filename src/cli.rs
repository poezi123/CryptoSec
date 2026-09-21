use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use crate::format::Cipher;
use crate::keys::KeyAlgo;

const EXAMPLES: &str = "\
Examples:
  cryptosec -e notes.txt              encrypt a file, pick the scheme interactively
  cryptosec -e ~/documents            pack a directory into one encrypted container
  cryptosec -d notes.txt.csec         decrypt again
  cryptosec -k -e notes.txt           encrypt but keep the original alongside
  cryptosec --algo ecc --key work -e report.pdf
  cryptosec keygen work -t ecc        create a key pair named 'work'
  cryptosec keys                      list the key pairs in the key store
";

#[derive(Parser, Debug)]
#[command(
    name = "cryptosec",
    version,
    about = "Encrypt and decrypt files or directories from the terminal",
    after_help = EXAMPLES
)]
pub struct Cli {
    /// Encrypt a file or directory
    #[arg(short = 'e', long = "encrypt", value_name = "PATH", group = "action")]
    pub encrypt: Option<PathBuf>,

    /// Decrypt a .csec container
    #[arg(short = 'd', long = "decrypt", value_name = "PATH", group = "action")]
    pub decrypt: Option<PathBuf>,

    /// Show what a container holds without decrypting it
    #[arg(long = "info", value_name = "PATH", group = "action")]
    pub info: Option<PathBuf>,

    /// Write the result here instead of next to the input
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Scheme to use: aes, chacha, rsa, ecc, mlkem
    #[arg(long, value_name = "SCHEME")]
    pub algo: Option<String>,

    /// Key pair to encrypt for, or decrypt with
    #[arg(long, value_name = "NAME")]
    pub key: Option<String>,

    /// Read the password from stdin instead of prompting
    #[arg(long)]
    pub password_stdin: bool,

    /// Overwrite an existing output path
    #[arg(short = 'f', long)]
    pub force: bool,

    /// Skip the read-back check after encrypting
    #[arg(long)]
    pub no_verify: bool,

    /// Leave the input in place instead of replacing it
    #[arg(short = 'k', long)]
    pub keep: bool,

    /// Overwrite the source with random bytes before removing it
    #[arg(long)]
    pub shred: bool,

    /// Only print errors
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new key pair in the key store
    Keygen {
        /// Name of the key pair, asked for when left out
        name: Option<String>,
        /// rsa, ecc or mlkem
        #[arg(short = 't', long = "type", value_name = "TYPE")]
        key_type: Option<String>,
        /// Store the private key without passphrase protection
        #[arg(long)]
        no_passphrase: bool,
    },
    /// List the key pairs in the key store
    Keys,
    /// Show a container and offer to decrypt it (used by the desktop handler)
    Open { path: PathBuf },
}

/// A scheme is either a password protected cipher or a key pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Password(Cipher),
    KeyPair(KeyAlgo),
}

impl Scheme {
    pub const MENU: [Scheme; 5] = [
        Scheme::Password(Cipher::Aes256Gcm),
        Scheme::Password(Cipher::ChaCha20Poly1305),
        Scheme::KeyPair(KeyAlgo::Rsa4096),
        Scheme::KeyPair(KeyAlgo::X25519),
        Scheme::KeyPair(KeyAlgo::MlKem768),
    ];

    pub fn menu_entry(&self) -> String {
        match self {
            Scheme::Password(Cipher::Aes256Gcm) => {
                "AES-256-GCM           password protected".into()
            }
            Scheme::Password(Cipher::ChaCha20Poly1305) => {
                "ChaCha20-Poly1305     password protected".into()
            }
            Scheme::KeyPair(KeyAlgo::Rsa4096) => "RSA-4096              key pair".into(),
            Scheme::KeyPair(KeyAlgo::X25519) => "ECC / X25519          key pair".into(),
            Scheme::KeyPair(KeyAlgo::MlKem768) => {
                "ML-KEM-768            key pair, post-quantum".into()
            }
        }
    }

    pub fn cipher(&self) -> Cipher {
        match self {
            Scheme::Password(c) => *c,
            // Key pairs only wrap the data key; the payload always uses AES-GCM.
            Scheme::KeyPair(_) => Cipher::Aes256Gcm,
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "aes" | "aes256" | "aes-256-gcm" => Scheme::Password(Cipher::Aes256Gcm),
            "chacha" | "chacha20" | "chacha20-poly1305" => {
                Scheme::Password(Cipher::ChaCha20Poly1305)
            }
            "rsa" | "rsa-4096" => Scheme::KeyPair(KeyAlgo::Rsa4096),
            "ecc" | "x25519" => Scheme::KeyPair(KeyAlgo::X25519),
            "mlkem" | "ml-kem" | "ml-kem-768" | "kyber" => Scheme::KeyPair(KeyAlgo::MlKem768),
            other => bail!("unknown scheme '{other}' (use aes, chacha, rsa, ecc or mlkem)"),
        })
    }
}
