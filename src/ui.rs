use std::io::{BufRead, IsTerminal};

use anyhow::{bail, Result};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Select};

use crate::cli::Scheme;
use crate::keys::KeyEntry;

pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

pub fn choose_scheme() -> Result<Scheme> {
    if !interactive() {
        bail!("no terminal available - pass --algo to choose a scheme");
    }
    let items: Vec<String> = Scheme::MENU.iter().map(|s| s.menu_entry()).collect();
    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Encryption scheme")
        .items(&items)
        .default(0)
        .interact()?;
    Ok(Scheme::MENU[idx])
}

pub enum KeyChoice {
    Existing(String),
    Generate,
}

pub fn choose_key(entries: &[KeyEntry]) -> Result<KeyChoice> {
    if !interactive() {
        bail!("no terminal available - pass --key to choose a key pair");
    }
    let mut items: Vec<String> = entries
        .iter()
        .map(|k| format!("{:<16} {:<14} {}", k.name, k.algo.label(), k.fingerprint))
        .collect();
    items.push("generate a new key pair".to_string());
    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Key pair")
        .items(&items)
        .default(0)
        .interact()?;
    if idx == entries.len() {
        Ok(KeyChoice::Generate)
    } else {
        Ok(KeyChoice::Existing(entries[idx].name.clone()))
    }
}

pub fn ask_name(prompt: &str, default: &str) -> Result<String> {
    if !interactive() {
        return Ok(default.to_string());
    }
    let name: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(default.to_string())
        .interact_text()?;
    Ok(name)
}

pub fn confirm(prompt: &str, default: bool) -> Result<bool> {
    if !interactive() {
        return Ok(default);
    }
    Ok(Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(default)
        .interact()?)
}

/// Reads a password. `confirm_twice` is used when the password protects
/// something new, so a typo cannot lock the data away.
pub fn read_password(prompt: &str, confirm_twice: bool, from_stdin: bool) -> Result<String> {
    if from_stdin {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let pass = line.trim_end_matches(['\n', '\r']).to_string();
        if pass.is_empty() {
            bail!("empty password on stdin");
        }
        return Ok(pass);
    }
    if !interactive() {
        bail!("no terminal available - use --password-stdin");
    }
    loop {
        let first = rpassword::prompt_password(format!("{prompt}: "))?;
        if first.is_empty() {
            eprintln!("  password must not be empty");
            continue;
        }
        if !confirm_twice {
            return Ok(first);
        }
        let again = rpassword::prompt_password("Repeat password: ")?;
        if first == again {
            if first.len() < 12 {
                eprintln!("  note: short passwords are the weakest part of any container");
            }
            return Ok(first);
        }
        eprintln!("  the two entries differ, try again");
    }
}

pub fn passphrase_for_key(name: &str) -> Result<String> {
    read_password(&format!("Passphrase for key '{name}'"), false, false)
}
