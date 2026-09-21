use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use zeroize::Zeroize;

use crate::cli::Scheme;
use crate::format::{self, Kind, Manifest, Meta, Recipient, EXTENSION};
use crate::kdf;
use crate::keys::{self, KeyAlgo};
use crate::stream::{DecReader, EncWriter, Sealer};
use crate::ui;

pub struct Options {
    pub output: Option<PathBuf>,
    pub scheme: Option<Scheme>,
    pub key: Option<String>,
    pub password_stdin: bool,
    pub force: bool,
    pub verify: bool,
    pub keep: bool,
    pub shred: bool,
    pub quiet: bool,
}

/// Removes a half written file unless it was handed over on success.
struct Scratch {
    path: PathBuf,
    dir: bool,
    armed: bool,
}

impl Scratch {
    fn file(path: PathBuf) -> Self {
        Scratch {
            path,
            dir: false,
            armed: true,
        }
    }

    fn dir(path: PathBuf) -> Self {
        Scratch {
            path,
            dir: true,
            armed: true,
        }
    }

    fn keep(mut self) -> PathBuf {
        self.armed = false;
        self.path.clone()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if self.armed {
            let _ = if self.dir {
                fs::remove_dir_all(&self.path)
            } else {
                fs::remove_file(&self.path)
            };
        }
    }
}

fn scratch_path(target: &Path, suffix: &str) -> PathBuf {
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("cryptosec");
    let mut tag = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut tag);
    let tag: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    target.with_file_name(format!(".{name}.{tag}.{suffix}"))
}

/// Keeps terminal output in the same shape the user typed the path in.
fn sibling_of(input: &Path, name: &str, fallback: &Path) -> PathBuf {
    if input.file_name().is_some() {
        input.with_file_name(name)
    } else {
        fallback.to_path_buf()
    }
}

fn ensure_free(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!("{} already exists (use -f to overwrite)", path.display());
    }
    Ok(())
}

// ------------------------------------------------------------------ encrypt

pub fn encrypt(input: &Path, opts: &Options) -> Result<()> {
    if opts.shred && opts.keep {
        bail!("--shred and --keep contradict each other");
    }
    if opts.shred && !opts.verify {
        bail!("--shred needs the read-back check, drop --no-verify");
    }

    let src = input
        .canonicalize()
        .with_context(|| format!("cannot open {}", input.display()))?;
    let name = src
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("unusable path {}", src.display()))?
        .to_string();
    let kind = if src.is_dir() {
        Kind::Directory
    } else {
        Kind::File
    };

    if kind == Kind::File
        && format::looks_encrypted(&src)
        && !ui::confirm(
            "This file is already a CryptoSec container. Encrypt it again?",
            false,
        )?
    {
        bail!("nothing to do");
    }

    let container = format!("{name}.{EXTENSION}");
    let out = match &opts.output {
        Some(p) => p.clone(),
        None => src.with_file_name(&container),
    };
    let out_display = match &opts.output {
        Some(p) => p.clone(),
        None => sibling_of(input, &container, &out),
    };
    ensure_free(&out, opts.force)?;

    let scheme = match opts.scheme {
        Some(s) => s,
        None => ui::choose_scheme()?,
    };

    let mut dek = kdf::random_bytes::<32>();
    let mut password: Option<String> = None;
    let recipient = match scheme {
        Scheme::Password(_) => {
            let pass = ui::read_password("Password", true, opts.password_stdin)?;
            let salt = kdf::random_bytes::<16>();
            let mut kek = kdf::argon2id(&pass, &salt, kdf::M_COST, kdf::T_COST, kdf::P_COST)?;
            let (nonce, wrapped) = kdf::wrap_with_kek(&kek, &dek)?;
            kek.zeroize();
            password = Some(pass);
            Recipient::Password {
                kdf: "argon2id".into(),
                salt: B64.encode(salt),
                m_cost: kdf::M_COST,
                t_cost: kdf::T_COST,
                p_cost: kdf::P_COST,
                wrap_nonce: B64.encode(nonce),
                wrapped: B64.encode(wrapped),
            }
        }
        Scheme::KeyPair(algo) => {
            let (_, pk) = pick_public_key(algo, opts)?;
            let fp = pk.fingerprint()?;
            let w = keys::wrap(&pk, &dek)?;
            match algo {
                KeyAlgo::Rsa4096 => Recipient::Rsa {
                    fingerprint: fp,
                    wrapped: B64.encode(w.wrapped),
                },
                KeyAlgo::X25519 => Recipient::X25519 {
                    fingerprint: fp,
                    ephemeral: B64.encode(w.kem.unwrap_or_default()),
                    wrap_nonce: B64.encode(w.nonce.unwrap_or_default()),
                    wrapped: B64.encode(w.wrapped),
                },
                KeyAlgo::MlKem768 => Recipient::MlKem {
                    fingerprint: fp,
                    kem_ct: B64.encode(w.kem.unwrap_or_default()),
                    wrap_nonce: B64.encode(w.nonce.unwrap_or_default()),
                    wrapped: B64.encode(w.wrapped),
                },
            }
        }
    };

    let prefix = kdf::random_bytes::<7>();
    let meta = Meta {
        version: 1,
        cipher: scheme.cipher(),
        recipient,
        nonce_prefix: B64.encode(prefix),
        chunk_size: format::CHUNK as u32,
    };

    let scratch = Scratch::file(scratch_path(&out, "part"));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&scratch.path)
        .with_context(|| format!("cannot write next to {}", out.display()))?;
    let mut writer = BufWriter::new(file);
    let meta_json = format::write_header(&mut writer, &meta)?;
    let sealer = Sealer::new(meta.cipher, &dek, prefix, format::aad(&meta_json));
    let mut enc = EncWriter::new(writer, sealer);

    let manifest = Manifest {
        name: name.clone(),
        kind,
    };
    let mj = serde_json::to_vec(&manifest)?;
    enc.write_all(&(mj.len() as u32).to_le_bytes())?;
    enc.write_all(&mj)?;

    match kind {
        Kind::File => {
            let mut f = BufReader::new(File::open(&src)?);
            io::copy(&mut f, &mut enc).context("reading the source file")?;
        }
        Kind::Directory => {
            let mut builder = tar::Builder::new(&mut enc);
            builder.follow_symlinks(false);
            builder
                .append_dir_all(&name, &src)
                .with_context(|| format!("packing {}", src.display()))?;
            builder.finish()?;
            drop(builder);
        }
    }

    let writer = enc.finish()?;
    let file = writer.into_inner().map_err(|e| anyhow!("{e}"))?;
    file.sync_all()?;
    drop(file);

    let tmp = scratch.keep();
    fs::rename(&tmp, &out).with_context(|| format!("cannot move result to {}", out.display()))?;

    if opts.verify {
        verify(&out, &dek, password.as_deref(), &src, kind, &name)
            .context("read-back check failed, the source was left untouched")?;
    }
    dek.zeroize();
    if let Some(mut p) = password {
        p.zeroize();
    }

    if !opts.quiet {
        println!("{} -> {}", input.display(), out_display.display());
        println!("  cipher   {}", meta.cipher.label());
        println!("  key mode {}", meta.recipient.label());
        println!("  contents {}", kind.label());
        if opts.verify {
            println!("  verified decrypts back to the original");
        }
    }

    // The source only goes away once the container has been read back and
    // compared against it.
    let note = if opts.keep {
        "source kept (-k)"
    } else if !opts.verify {
        "source kept: nothing was verified (--no-verify)"
    } else {
        sync_parent(&out)?;
        if opts.shred {
            shred(&src, kind)?;
            "source overwritten and removed"
        } else {
            remove(&src, kind)?;
            "source removed"
        }
    };
    if !opts.quiet {
        println!("  {note}");
    }
    Ok(())
}

fn pick_public_key(algo: KeyAlgo, opts: &Options) -> Result<(String, keys::PublicKey)> {
    if let Some(name) = &opts.key {
        let (name, pk) = keys::load_public(name)?;
        if pk.algo() != algo {
            bail!(
                "key '{name}' is a {} key, but {} was requested",
                pk.algo().label(),
                algo.label()
            );
        }
        return Ok((name, pk));
    }
    let matching: Vec<keys::KeyEntry> = keys::list()?
        .into_iter()
        .filter(|k| k.algo == algo)
        .collect();
    if matching.is_empty() {
        if !ui::confirm(
            &format!("No {} key pair yet. Create one now?", algo.label()),
            true,
        )? {
            bail!("no key pair available");
        }
        let name = ui::ask_name("Key name", "default")?;
        let name = crate::commands::keygen(Some(name), algo, false, opts.quiet)?;
        let (name, pk) = keys::load_public(&name)?;
        return Ok((name, pk));
    }
    match ui::choose_key(&matching)? {
        ui::KeyChoice::Existing(name) => {
            let (name, pk) = keys::load_public(&name)?;
            Ok((name, pk))
        }
        ui::KeyChoice::Generate => {
            let name = ui::ask_name("Key name", "default")?;
            let name = crate::commands::keygen(Some(name), algo, false, opts.quiet)?;
            let (name, pk) = keys::load_public(&name)?;
            Ok((name, pk))
        }
    }
}

/// Reads the finished container back. For password containers the key is
/// re-derived from the stored salt, so a broken password path shows up here
/// and not weeks later.
fn verify(
    out: &Path,
    dek: &[u8; 32],
    password: Option<&str>,
    src: &Path,
    kind: Kind,
    name: &str,
) -> Result<()> {
    let mut file = BufReader::new(File::open(out)?);
    let (stored, meta_json) = format::read_header(&mut file)?;
    let mut check = *dek;
    if let (Recipient::Password { .. }, Some(pass)) = (&stored.recipient, password) {
        check = unwrap_password(&stored.recipient, pass)?;
        if check != *dek {
            bail!("the re-derived data key does not match");
        }
    }
    let prefix = decode_prefix(&stored)?;
    let sealer = Sealer::new(stored.cipher, &check, prefix, format::aad(&meta_json));
    let mut dec = DecReader::new(file, sealer);
    let manifest = read_manifest(&mut dec)?;
    if manifest.name != name || manifest.kind != kind {
        bail!("the container describes different contents than were written");
    }
    check.zeroize();
    match kind {
        Kind::File => {
            compare(&mut dec, &mut BufReader::new(File::open(src)?))?;
            io::copy(&mut dec, &mut io::sink())?;
        }
        Kind::Directory => verify_directory(&mut dec, src, name)?,
    }
    Ok(())
}

/// Walks the archive that was just written and holds every entry against the
/// directory on disk. Nothing is deleted on the strength of a weaker check.
fn verify_directory<R: Read>(dec: &mut R, src: &Path, root: &str) -> Result<()> {
    let mut seen = 0usize;
    let mut archive = tar::Archive::new(dec);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let mut parts = path.components();
        let first = parts
            .next()
            .ok_or_else(|| anyhow!("the archive holds an entry without a path"))?;
        if first.as_os_str() != root {
            bail!(
                "the archive holds an entry outside {root}: {}",
                path.display()
            );
        }
        let rest = parts.as_path();
        let target = if rest.as_os_str().is_empty() {
            src.to_path_buf()
        } else {
            src.join(rest)
        };
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            if !target.is_dir() {
                bail!("{} is in the archive but not on disk", path.display());
            }
        } else if entry_type.is_symlink() {
            let stored = entry
                .link_name()?
                .ok_or_else(|| anyhow!("{} has no link target", path.display()))?
                .into_owned();
            if fs::read_link(&target)? != stored {
                bail!("the symlink {} points somewhere else now", path.display());
            }
            seen += 1;
        } else {
            let mut disk = BufReader::new(File::open(&target).with_context(|| {
                format!("{} is in the archive but not on disk", path.display())
            })?);
            compare(&mut entry, &mut disk)
                .with_context(|| format!("{} differs from the archive", path.display()))?;
            seen += 1;
        }
    }
    let dec = archive.into_inner();
    io::copy(dec, &mut io::sink())?;

    let on_disk = count_entries(src)?;
    if seen != on_disk {
        bail!("the archive holds {seen} entries, the directory {on_disk}");
    }
    Ok(())
}

/// Everything that is not a directory, so symlinks count as themselves.
fn count_entries(root: &Path) -> Result<usize> {
    let mut count = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if fs::symlink_metadata(&path)?.is_dir() {
                stack.push(path);
            } else {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn remove(path: &Path, kind: Kind) -> Result<()> {
    match kind {
        Kind::File => fs::remove_file(path)?,
        Kind::Directory => fs::remove_dir_all(path)?,
    }
    Ok(())
}

/// Makes a rename durable before the only other copy of the data is deleted.
fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn compare<A: Read, B: Read>(a: &mut A, b: &mut B) -> Result<()> {
    let mut ba = vec![0u8; 64 * 1024];
    let mut bb = vec![0u8; 64 * 1024];
    loop {
        let na = fill(a, &mut ba)?;
        let nb = fill(b, &mut bb)?;
        if na != nb || ba[..na] != bb[..nb] {
            bail!("the decrypted data differs from the source");
        }
        if na == 0 {
            return Ok(());
        }
    }
}

fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

// ------------------------------------------------------------------ decrypt

pub fn decrypt(input: &Path, opts: &Options) -> Result<()> {
    let src = input
        .canonicalize()
        .with_context(|| format!("cannot open {}", input.display()))?;
    let mut file = BufReader::new(File::open(&src)?);
    let (meta, meta_json) = format::read_header(&mut file)
        .with_context(|| format!("{} is not a CryptoSec container", src.display()))?;

    if !opts.quiet {
        println!("{}", format::BANNER);
        println!("  cipher   {}", meta.cipher.label());
        println!("  key mode {}", meta.recipient.label());
    }

    let mut dek = obtain_dek(&meta, opts)?;
    let prefix = decode_prefix(&meta)?;
    let sealer = Sealer::new(meta.cipher, &dek, prefix, format::aad(&meta_json));
    dek.zeroize();
    let mut dec = DecReader::new(file, sealer);
    let manifest = read_manifest(&mut dec)?;

    let safe_name = Path::new(&manifest.name)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty() && *n != "." && *n != "..")
        .ok_or_else(|| anyhow!("the container carries an unusable name"))?
        .to_string();

    let out = match &opts.output {
        Some(p) => p.clone(),
        None => src.with_file_name(&safe_name),
    };
    let out_display = match &opts.output {
        Some(p) => p.clone(),
        None => sibling_of(input, &safe_name, &out),
    };
    ensure_free(&out, opts.force)?;

    match manifest.kind {
        Kind::File => {
            let scratch = Scratch::file(scratch_path(&out, "part"));
            let mut w = BufWriter::new(
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&scratch.path)?,
            );
            io::copy(&mut dec, &mut w)?;
            let f = w.into_inner().map_err(|e| anyhow!("{e}"))?;
            f.sync_all()?;
            drop(f);
            let tmp = scratch.keep();
            if opts.force && out.exists() {
                fs::remove_file(&out)?;
            }
            fs::rename(&tmp, &out)?;
        }
        Kind::Directory => {
            let scratch = Scratch::dir(scratch_path(&out, "tmp"));
            fs::create_dir(&scratch.path)?;
            let mut archive = tar::Archive::new(&mut dec);
            archive.set_preserve_permissions(true);
            archive.set_overwrite(true);
            archive
                .unpack(&scratch.path)
                .context("unpacking the archive")?;
            // Anything the reader did not consume would mean a short archive.
            io::copy(&mut dec, &mut io::sink())?;
            let unpacked = scratch.path.join(&safe_name);
            let staged = if unpacked.exists() {
                unpacked
            } else {
                scratch.path.clone()
            };
            if opts.force && out.exists() {
                fs::remove_dir_all(&out)?;
            }
            fs::rename(&staged, &out).context("moving the unpacked directory into place")?;
            let tmp = scratch.keep();
            let _ = fs::remove_dir_all(&tmp);
        }
    }

    // Every chunk was authenticated on the way out, so the container has done
    // its job and is replaced by what it held.
    let note = if opts.keep {
        "container kept (-k)"
    } else {
        sync_parent(&out)?;
        fs::remove_file(&src).with_context(|| format!("cannot remove {}", src.display()))?;
        "container removed"
    };

    if !opts.quiet {
        println!("  restored {}", out_display.display());
        println!("  {note}");
    }
    Ok(())
}

fn obtain_dek(meta: &Meta, opts: &Options) -> Result<[u8; 32]> {
    match &meta.recipient {
        Recipient::Password { .. } => {
            let mut pass = ui::read_password("Password", false, opts.password_stdin)?;
            let dek = unwrap_password(&meta.recipient, &pass);
            pass.zeroize();
            dek
        }
        other => {
            let fp = other.fingerprint().unwrap_or_default();
            let name = match &opts.key {
                Some(n) => n.clone(),
                None => match keys::find_by_fingerprint(fp)? {
                    Some(entry) => entry.name,
                    None => bail!(
                        "no private key {fp} in the key store - pass --key with the file path"
                    ),
                },
            };
            let sk = keys::load_private(&name, ui::passphrase_for_key)?;
            if sk.public().fingerprint()? != fp {
                bail!("key '{name}' does not match this container ({fp})");
            }
            let (kem, nonce, wrapped) = match other {
                Recipient::Rsa { wrapped, .. } => (None, None, B64.decode(wrapped)?),
                Recipient::X25519 {
                    ephemeral,
                    wrap_nonce,
                    wrapped,
                    ..
                } => (
                    Some(B64.decode(ephemeral)?),
                    Some(B64.decode(wrap_nonce)?),
                    B64.decode(wrapped)?,
                ),
                Recipient::MlKem {
                    kem_ct,
                    wrap_nonce,
                    wrapped,
                    ..
                } => (
                    Some(B64.decode(kem_ct)?),
                    Some(B64.decode(wrap_nonce)?),
                    B64.decode(wrapped)?,
                ),
                Recipient::Password { .. } => unreachable!(),
            };
            keys::unwrap(&sk, kem.as_deref(), nonce.as_deref(), &wrapped)
        }
    }
}

fn unwrap_password(recipient: &Recipient, password: &str) -> Result<[u8; 32]> {
    let Recipient::Password {
        salt,
        m_cost,
        t_cost,
        p_cost,
        wrap_nonce,
        wrapped,
        kdf: name,
    } = recipient
    else {
        bail!("this container is not password protected");
    };
    if name != "argon2id" {
        bail!("unsupported key derivation '{name}'");
    }
    let salt = B64.decode(salt).context("damaged header")?;
    let nonce = B64.decode(wrap_nonce).context("damaged header")?;
    let wrapped = B64.decode(wrapped).context("damaged header")?;
    let mut kek = kdf::argon2id(password, &salt, *m_cost, *t_cost, *p_cost)?;
    let dek = kdf::unwrap_with_kek(&kek, Some(&nonce), &wrapped);
    kek.zeroize();
    dek
}

fn decode_prefix(meta: &Meta) -> Result<[u8; 7]> {
    let raw = B64.decode(&meta.nonce_prefix).context("damaged header")?;
    raw.as_slice()
        .try_into()
        .map_err(|_| anyhow!("damaged header (nonce prefix)"))
}

fn read_manifest<R: Read>(dec: &mut R) -> Result<Manifest> {
    let mut len = [0u8; 4];
    dec.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len == 0 || len > 64 * 1024 {
        bail!("damaged container (manifest length {len})");
    }
    let mut buf = vec![0u8; len];
    dec.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).context("damaged container manifest")
}

// --------------------------------------------------------------------- misc

pub fn info(path: &Path) -> Result<()> {
    let mut file = BufReader::new(File::open(path)?);
    let (meta, _) = format::read_header(&mut file)
        .with_context(|| format!("{} is not a CryptoSec container", path.display()))?;
    println!("{}", format::BANNER);
    println!("  file     {}", path.display());
    println!("  cipher   {}", meta.cipher.label());
    println!("  key mode {}", meta.recipient.label());
    if let Some(fp) = meta.recipient.fingerprint() {
        match keys::find_by_fingerprint(fp)? {
            Some(k) => println!("  key      '{}' is in your key store", k.name),
            None => println!("  key      {fp} is not in your key store"),
        }
    }
    println!("\nDecrypt with: cryptosec -d {}", path.display());
    Ok(())
}

fn shred(path: &Path, kind: Kind) -> Result<()> {
    match kind {
        Kind::File => shred_file(path),
        Kind::Directory => {
            for entry in walkdir_files(path)? {
                shred_file(&entry)?;
            }
            fs::remove_dir_all(path)?;
            Ok(())
        }
    }
}

fn walkdir_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                out.push(path);
            }
        }
    }
    Ok(out)
}

/// Best effort only: on SSDs and copy-on-write filesystems the old blocks may
/// survive. The README says so too.
fn shred_file(path: &Path) -> Result<()> {
    let len = fs::metadata(path)?.len();
    let mut f = fs::OpenOptions::new().write(true).open(path)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut written = 0u64;
    while written < len {
        rand::thread_rng().fill_bytes(&mut buf);
        let n = std::cmp::min(buf.len() as u64, len - written) as usize;
        f.write_all(&buf[..n])?;
        written += n as u64;
    }
    f.sync_all()?;
    drop(f);
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    fn scratch_dir() -> PathBuf {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("cryptosec-ops-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("tree/sub")).unwrap();
        fs::write(dir.join("tree/a.txt"), "aaa").unwrap();
        fs::write(dir.join("tree/sub/b.bin"), vec![7u8; 4096]).unwrap();
        std::os::unix::fs::symlink("a.txt", dir.join("tree/link")).unwrap();
        dir
    }

    fn tar_of(dir: &Path) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        b.follow_symlinks(false);
        b.append_dir_all("tree", dir.join("tree")).unwrap();
        b.finish().unwrap();
        b.into_inner().unwrap()
    }

    #[test]
    fn accepts_a_tree_that_still_matches() {
        let dir = scratch_dir();
        let archive = tar_of(&dir);
        verify_directory(&mut Cursor::new(archive), &dir.join("tree"), "tree").unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_changed_file_contents() {
        let dir = scratch_dir();
        let archive = tar_of(&dir);
        fs::write(dir.join("tree/a.txt"), "bbb").unwrap();
        let err = verify_directory(&mut Cursor::new(archive), &dir.join("tree"), "tree")
            .unwrap_err()
            .to_string();
        assert!(err.contains("a.txt"), "{err}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_a_file_the_archive_never_saw() {
        let dir = scratch_dir();
        let archive = tar_of(&dir);
        fs::write(dir.join("tree/sub/late.txt"), "added after packing").unwrap();
        let err = verify_directory(&mut Cursor::new(archive), &dir.join("tree"), "tree")
            .unwrap_err()
            .to_string();
        assert!(err.contains("entries"), "{err}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_a_retargeted_symlink() {
        let dir = scratch_dir();
        let archive = tar_of(&dir);
        fs::remove_file(dir.join("tree/link")).unwrap();
        std::os::unix::fs::symlink("sub/b.bin", dir.join("tree/link")).unwrap();
        let err = verify_directory(&mut Cursor::new(archive), &dir.join("tree"), "tree")
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_a_file_that_disappeared() {
        let dir = scratch_dir();
        let archive = tar_of(&dir);
        fs::remove_file(dir.join("tree/sub/b.bin")).unwrap();
        let err = verify_directory(&mut Cursor::new(archive), &dir.join("tree"), "tree")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not on disk"), "{err}");
        fs::remove_dir_all(&dir).unwrap();
    }
}
