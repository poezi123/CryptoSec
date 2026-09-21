mod cli;
mod commands;
mod format;
mod kdf;
mod keys;
mod ops;
mod stream;
mod ui;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command, Scheme};
use keys::KeyAlgo;
use ops::Options;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cryptosec: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    if let Some(cmd) = &cli.command {
        if cli.encrypt.is_some() || cli.decrypt.is_some() || cli.info.is_some() {
            anyhow::bail!("-e, -d and --info cannot be combined with a subcommand");
        }
        return match cmd {
            Command::Keygen {
                name,
                key_type,
                no_passphrase,
            } => {
                let algo = match key_type {
                    Some(t) => KeyAlgo::parse(t)?,
                    None => ask_key_type()?,
                };
                commands::keygen(name.clone(), algo, *no_passphrase, cli.quiet).map(|_| ())
            }
            Command::Keys => commands::list_keys(),
            Command::Open { path } => commands::open(path),
        };
    }

    if let Some(path) = &cli.info {
        return ops::info(path);
    }

    let scheme = match &cli.algo {
        Some(a) => Some(Scheme::parse(a)?),
        None => None,
    };
    let opts = Options {
        output: cli.output.clone(),
        scheme,
        key: cli.key.clone(),
        password_stdin: cli.password_stdin,
        force: cli.force,
        verify: !cli.no_verify,
        keep: cli.keep,
        shred: cli.shred,
        quiet: cli.quiet,
    };

    if let Some(path) = &cli.encrypt {
        return ops::encrypt(path, &opts);
    }
    if let Some(path) = &cli.decrypt {
        return ops::decrypt(path, &opts);
    }

    use clap::CommandFactory;
    Cli::command().print_help()?;
    println!();
    Ok(())
}

fn ask_key_type() -> Result<KeyAlgo> {
    let scheme = ui::choose_scheme()?;
    match scheme {
        Scheme::KeyPair(a) => Ok(a),
        Scheme::Password(_) => {
            anyhow::bail!("that scheme uses a password, not a key pair")
        }
    }
}
