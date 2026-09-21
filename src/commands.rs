use std::io::Read;
use std::path::Path;

use anyhow::{bail, Result};

use crate::keys::{self, KeyAlgo};
use crate::ops::{self, Options};
use crate::ui;

pub fn keygen(
    name: Option<String>,
    algo: KeyAlgo,
    no_passphrase: bool,
    quiet: bool,
) -> Result<String> {
    let name = match name {
        Some(n) => n,
        None => ui::ask_name("Key name", "default")?,
    };
    if name.is_empty() || name.contains('/') || name.starts_with('.') {
        bail!("'{name}' is not a usable key name");
    }

    let passphrase = if no_passphrase {
        None
    } else if ui::interactive() {
        Some(ui::read_password(
            &format!("Passphrase for key '{name}'"),
            true,
            false,
        )?)
    } else {
        bail!("no terminal available - use --no-passphrase for unattended key generation");
    };

    if !quiet && algo == KeyAlgo::Rsa4096 {
        eprintln!("generating an RSA-4096 key pair, this takes a moment...");
    }
    let sk = keys::generate(algo)?;
    let (pub_path, key_path) = keys::save(&name, &sk, passphrase.as_deref())?;

    if !quiet {
        println!("created {} key pair '{}'", algo.label(), name);
        println!("  public  {}", pub_path.display());
        println!("  private {}", key_path.display());
        if passphrase.is_none() {
            println!("  the private key is stored unprotected, keep the file safe");
        }
        println!("\nAnyone with the public key can encrypt for you.");
        println!("Back up the private key - without it the data is gone.");
    }
    Ok(name)
}

pub fn list_keys() -> Result<()> {
    let entries = keys::list()?;
    if entries.is_empty() {
        println!("no key pairs yet - create one with: cryptosec keygen");
        return Ok(());
    }
    println!(
        "{:<16} {:<16} {:<18} PRIVATE KEY",
        "NAME", "TYPE", "FINGERPRINT"
    );
    for k in entries {
        let state = match (k.has_private, k.protected) {
            (false, _) => "missing",
            (true, true) => "passphrase",
            (true, false) => "unprotected",
        };
        println!(
            "{:<16} {:<16} {:<18} {}",
            k.name,
            k.algo.label(),
            k.fingerprint,
            state
        );
    }
    Ok(())
}

/// Entry point for the desktop file handler: show what the container is and
/// offer to unpack it, then keep the terminal window open.
pub fn open(path: &Path) -> Result<()> {
    ops::info(path)?;
    if ui::interactive() {
        println!();
        if ui::confirm("Decrypt this container now?", true)? {
            let opts = Options {
                output: None,
                scheme: None,
                key: None,
                password_stdin: false,
                force: false,
                verify: false,
                shred: false,
                quiet: false,
            };
            if let Err(e) = ops::decrypt(path, &opts) {
                eprintln!("cryptosec: {e:#}");
            }
        }
        println!("\nPress Enter to close.");
        let _ = std::io::stdin().read(&mut [0u8; 1]);
    }
    Ok(())
}
