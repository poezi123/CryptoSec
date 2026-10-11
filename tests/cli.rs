use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("cryptosec-test-{}-{tag}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("cfg")).unwrap();
        fs::create_dir_all(root.join("work")).unwrap();
        Sandbox { root }
    }

    fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_cryptosec"));
        c.env("CRYPTOSEC_HOME", self.root.join("cfg"))
            .current_dir(self.work())
            .args(args);
        c
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> (bool, String) {
        let mut child = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(text) = stdin {
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        let mut text = String::from_utf8_lossy(&out.stdout).to_string();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (out.status.success(), text)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const PASS: &str = "correct horse battery staple\n";

fn write_bytes(path: &Path, len: usize) {
    let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
    fs::write(path, data).unwrap();
}

#[test]
fn password_roundtrip_across_chunk_boundaries() {
    let sb = Sandbox::new("chunks");
    // 1 MiB is the chunk size, so the boundary cases matter most.
    for len in [0usize, 1, 1024, 1048575, 1048576, 1048577, 2097152] {
        let src = sb.work().join(format!("d{len}.bin"));
        write_bytes(&src, len);
        let original = fs::read(&src).unwrap();
        let name = format!("d{len}.bin");
        let container = format!("d{len}.bin.csec");

        let (ok, log) = sb.run(
            &["-q", "--algo", "aes", "--password-stdin", "-e", &name],
            Some(PASS),
        );
        assert!(ok, "encrypt {len} failed: {log}");
        assert!(!src.exists(), "the source survived encryption at {len}");

        let (ok, log) = sb.run(&["-q", "--password-stdin", "-d", &container], Some(PASS));
        assert!(ok, "decrypt {len} failed: {log}");
        assert_eq!(
            fs::read(&src).unwrap(),
            original,
            "payload differs at {len}"
        );
    }
}

#[test]
fn container_starts_with_the_readable_banner() {
    let sb = Sandbox::new("banner");
    fs::write(sb.work().join("a.txt"), "secret").unwrap();
    let (ok, _) = sb.run(
        &["-q", "--algo", "aes", "--password-stdin", "-e", "a.txt"],
        Some(PASS),
    );
    assert!(ok);
    let raw = fs::read(sb.work().join("a.txt.csec")).unwrap();
    assert!(raw.starts_with(b"Encrypted by CryptoSec"));
    assert!(!raw.windows(6).any(|w| w == b"secret"));

    // Everything before the binary header is the readable part. It carries the
    // banner, how to decrypt and where the tool comes from, and nothing else:
    // no timestamp, no scheme, nothing that describes this particular file.
    let magic = raw
        .windows(5)
        .position(|w| w == b"CSEC\x01")
        .expect("header magic");
    let preamble = String::from_utf8(raw[..magic].to_vec()).unwrap();
    assert_eq!(
        preamble,
        "Encrypted by CryptoSec\n\
         Decrypt with: cryptosec -d <this file>\n\
         Get it at: https://github.com/poezi123/CryptoSec\n\n"
    );
}

/// Containers written by 0.1.0 carry a "created" field that no longer exists.
/// They must keep opening, or an upgrade would lock people out of their data.
#[test]
fn containers_from_the_previous_release_still_open() {
    let sb = Sandbox::new("legacy");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-0.1.0.csec");
    let container = sb.work().join("legacy.txt.csec");
    fs::copy(&fixture, &container).unwrap();

    let (ok, log) = sb.run(
        &["-q", "--password-stdin", "-d", "legacy.txt.csec"],
        Some(PASS),
    );
    assert!(ok, "{log}");
    assert_eq!(
        fs::read_to_string(sb.work().join("legacy.txt")).unwrap(),
        "legacy round trip\n"
    );
}

#[test]
fn directory_roundtrip_keeps_the_tree() {
    let sb = Sandbox::new("dir");
    let dir = sb.work().join("tree");
    fs::create_dir_all(dir.join("sub/deep")).unwrap();
    fs::create_dir(dir.join("empty")).unwrap();
    fs::write(dir.join("one.txt"), "one").unwrap();
    fs::write(dir.join("sub/two.txt"), "two").unwrap();
    write_bytes(&dir.join("sub/deep/three.bin"), 300_000);
    std::os::unix::fs::symlink("one.txt", dir.join("link.txt")).unwrap();
    std::os::unix::fs::symlink("nowhere", dir.join("dangling")).unwrap();

    let (ok, log) = sb.run(
        &["-q", "--algo", "chacha", "--password-stdin", "-e", "tree"],
        Some(PASS),
    );
    assert!(ok, "{log}");
    assert!(!dir.exists(), "the source tree survived encryption");

    let (ok, log) = sb.run(&["-q", "--password-stdin", "-d", "tree.csec"], Some(PASS));
    assert!(ok, "{log}");
    assert_eq!(fs::read_to_string(dir.join("one.txt")).unwrap(), "one");
    assert_eq!(fs::read_to_string(dir.join("sub/two.txt")).unwrap(), "two");
    assert_eq!(
        fs::metadata(dir.join("sub/deep/three.bin")).unwrap().len(),
        300_000
    );
    assert!(dir.join("empty").is_dir());
    assert_eq!(
        fs::read_link(dir.join("link.txt")).unwrap(),
        Path::new("one.txt")
    );
    assert_eq!(
        fs::read_link(dir.join("dangling")).unwrap(),
        Path::new("nowhere")
    );
}

#[test]
fn wrong_password_is_rejected() {
    let sb = Sandbox::new("wrongpw");
    fs::write(sb.work().join("a.txt"), "secret").unwrap();
    sb.run(
        &["-q", "--algo", "aes", "--password-stdin", "-e", "a.txt"],
        Some(PASS),
    );
    let (ok, log) = sb.run(
        &["-q", "--password-stdin", "-d", "a.txt.csec"],
        Some("not the password\n"),
    );
    assert!(!ok);
    assert!(log.contains("wrong password"), "{log}");
    assert!(!sb.work().join("a.txt").exists());
    assert!(
        sb.work().join("a.txt.csec").exists(),
        "a failed decrypt must not remove the container"
    );
}

#[test]
fn a_single_flipped_byte_is_detected() {
    let sb = Sandbox::new("tamper");
    write_bytes(&sb.work().join("a.bin"), 5000);
    sb.run(
        &["-q", "--algo", "aes", "--password-stdin", "-e", "a.bin"],
        Some(PASS),
    );
    let container = sb.work().join("a.bin.csec");
    let mut raw = fs::read(&container).unwrap();
    let last = raw.len() - 20;
    raw[last] ^= 0x01;
    fs::write(&container, raw).unwrap();

    let (ok, log) = sb.run(
        &[
            "-q",
            "--password-stdin",
            "-d",
            "a.bin.csec",
            "-o",
            "out.bin",
        ],
        Some(PASS),
    );
    assert!(!ok);
    assert!(log.contains("authentication failed"), "{log}");
    assert!(
        !sb.work().join("out.bin").exists(),
        "partial output left behind"
    );
}

#[test]
fn truncation_is_detected() {
    let sb = Sandbox::new("truncate");
    write_bytes(&sb.work().join("a.bin"), 3_000_000);
    sb.run(
        &["-q", "--algo", "aes", "--password-stdin", "-e", "a.bin"],
        Some(PASS),
    );
    let container = sb.work().join("a.bin.csec");
    let raw = fs::read(&container).unwrap();
    // Drop the final chunk completely: the stream still parses, but the
    // last-chunk marker is gone.
    fs::write(&container, &raw[..raw.len() - (16 + 100)]).unwrap();
    let (ok, log) = sb.run(
        &[
            "-q",
            "--password-stdin",
            "-d",
            "a.bin.csec",
            "-o",
            "out.bin",
        ],
        Some(PASS),
    );
    assert!(!ok, "truncated container was accepted");
    assert!(!log.is_empty());
}

#[test]
fn keypair_roundtrip_ecc_and_mlkem() {
    let sb = Sandbox::new("keypair");
    for (name, algo) in [("alice", "ecc"), ("bob", "mlkem")] {
        let (ok, log) = sb.run(&["-q", "keygen", name, "-t", algo, "--no-passphrase"], None);
        assert!(ok, "keygen {algo}: {log}");
    }
    write_bytes(&sb.work().join("a.bin"), 200_000);
    let original = fs::read(sb.work().join("a.bin")).unwrap();

    for (name, algo) in [("alice", "ecc"), ("bob", "mlkem")] {
        let out = format!("{name}.csec");
        let (ok, log) = sb.run(
            &[
                "-q", "-k", "--algo", algo, "--key", name, "-e", "a.bin", "-o", &out,
            ],
            None,
        );
        assert!(ok, "encrypt {algo}: {log}");
        let back = format!("back-{name}.bin");
        // No --key: the private key is located through the fingerprint.
        let (ok, log) = sb.run(&["-q", "-d", &out, "-o", &back], None);
        assert!(ok, "decrypt {algo}: {log}");
        assert_eq!(fs::read(sb.work().join(&back)).unwrap(), original);
    }
}

#[test]
fn a_foreign_key_cannot_open_the_container() {
    let sb = Sandbox::new("foreign");
    sb.run(
        &["-q", "keygen", "alice", "-t", "ecc", "--no-passphrase"],
        None,
    );
    sb.run(
        &["-q", "keygen", "mallory", "-t", "ecc", "--no-passphrase"],
        None,
    );
    fs::write(sb.work().join("a.txt"), "secret").unwrap();
    let (ok, _) = sb.run(
        &["-q", "-k", "--algo", "ecc", "--key", "alice", "-e", "a.txt"],
        None,
    );
    assert!(ok);
    let (ok, log) = sb.run(
        &["-q", "-d", "a.txt.csec", "--key", "mallory", "-o", "x.txt"],
        None,
    );
    assert!(!ok);
    assert!(log.contains("does not match"), "{log}");
}

#[test]
fn existing_output_is_not_overwritten_by_accident() {
    let sb = Sandbox::new("overwrite");
    fs::write(sb.work().join("a.txt"), "new").unwrap();
    fs::write(sb.work().join("a.txt.csec"), "important").unwrap();
    let (ok, log) = sb.run(
        &["-q", "--algo", "aes", "--password-stdin", "-e", "a.txt"],
        Some(PASS),
    );
    assert!(!ok);
    assert!(log.contains("already exists"), "{log}");
    assert_eq!(
        fs::read_to_string(sb.work().join("a.txt.csec")).unwrap(),
        "important"
    );
}

#[test]
fn plain_files_are_not_mistaken_for_containers() {
    let sb = Sandbox::new("plain");
    fs::write(sb.work().join("a.txt"), "just text\n").unwrap();
    let (ok, log) = sb.run(&["-q", "--password-stdin", "-d", "a.txt"], Some(PASS));
    assert!(!ok);
    assert!(log.contains("not a CryptoSec container"), "{log}");
}

#[test]
#[ignore = "RSA-4096 key generation is too slow for an unoptimised test build"]
fn keypair_roundtrip_rsa() {
    let sb = Sandbox::new("rsa");
    let (ok, log) = sb.run(
        &["-q", "keygen", "carol", "-t", "rsa", "--no-passphrase"],
        None,
    );
    assert!(ok, "{log}");
    write_bytes(&sb.work().join("a.bin"), 100_000);
    let original = fs::read(sb.work().join("a.bin")).unwrap();
    let (ok, log) = sb.run(
        &["-q", "-k", "--algo", "rsa", "--key", "carol", "-e", "a.bin"],
        None,
    );
    assert!(ok, "{log}");
    let (ok, log) = sb.run(&["-q", "-d", "a.bin.csec", "-o", "back.bin"], None);
    assert!(ok, "{log}");
    assert_eq!(fs::read(sb.work().join("back.bin")).unwrap(), original);
}

#[test]
fn encrypting_replaces_the_source_and_decrypting_replaces_the_container() {
    let sb = Sandbox::new("replace");
    let plain = sb.work().join("a.txt");
    let container = sb.work().join("a.txt.csec");
    fs::write(&plain, "round trip").unwrap();

    let (ok, log) = sb.run(
        &["-q", "--algo", "aes", "--password-stdin", "-e", "a.txt"],
        Some(PASS),
    );
    assert!(ok, "{log}");
    assert!(!plain.exists(), "plaintext left behind");
    assert!(container.exists());

    let (ok, log) = sb.run(&["-q", "--password-stdin", "-d", "a.txt.csec"], Some(PASS));
    assert!(ok, "{log}");
    assert_eq!(fs::read_to_string(&plain).unwrap(), "round trip");
    assert!(!container.exists(), "container left behind");
}

#[test]
fn keep_leaves_the_input_in_place() {
    let sb = Sandbox::new("keep");
    fs::write(sb.work().join("a.txt"), "hello").unwrap();
    let (ok, log) = sb.run(
        &[
            "-q",
            "-k",
            "--algo",
            "aes",
            "--password-stdin",
            "-e",
            "a.txt",
        ],
        Some(PASS),
    );
    assert!(ok, "{log}");
    assert_eq!(
        fs::read_to_string(sb.work().join("a.txt")).unwrap(),
        "hello"
    );

    let (ok, log) = sb.run(
        &["-q", "-k", "-f", "--password-stdin", "-d", "a.txt.csec"],
        Some(PASS),
    );
    assert!(ok, "{log}");
    assert!(sb.work().join("a.txt.csec").exists());
}

#[test]
fn skipping_the_check_keeps_the_source() {
    let sb = Sandbox::new("noverify");
    fs::write(sb.work().join("a.txt"), "hello").unwrap();
    let (ok, log) = sb.run(
        &[
            "--no-verify",
            "--algo",
            "aes",
            "--password-stdin",
            "-e",
            "a.txt",
        ],
        Some(PASS),
    );
    assert!(ok, "{log}");
    assert!(
        sb.work().join("a.txt").exists(),
        "nothing was verified, so the source must stay"
    );
    assert!(log.contains("nothing was verified"), "{log}");
}

#[test]
fn shred_and_keep_are_rejected_together() {
    let sb = Sandbox::new("conflict");
    fs::write(sb.work().join("a.txt"), "hello").unwrap();
    let (ok, log) = sb.run(
        &[
            "-q",
            "-k",
            "--shred",
            "--algo",
            "aes",
            "--password-stdin",
            "-e",
            "a.txt",
        ],
        Some(PASS),
    );
    assert!(!ok);
    assert!(log.contains("contradict"), "{log}");
    assert!(sb.work().join("a.txt").exists());
}

#[test]
fn shred_removes_the_source_after_the_check() {
    let sb = Sandbox::new("shred");
    write_bytes(&sb.work().join("a.bin"), 50_000);
    let (ok, log) = sb.run(
        &[
            "-q",
            "--shred",
            "--algo",
            "aes",
            "--password-stdin",
            "-e",
            "a.bin",
        ],
        Some(PASS),
    );
    assert!(ok, "{log}");
    assert!(!sb.work().join("a.bin").exists());

    let (ok, log) = sb.run(&["-q", "--password-stdin", "-d", "a.bin.csec"], Some(PASS));
    assert!(ok, "{log}");
    assert_eq!(fs::metadata(sb.work().join("a.bin")).unwrap().len(), 50_000);
}

// ------------------------------------------------------------ Radix (concept)

fn radix_sandbox(tag: &str) -> Sandbox {
    let sb = Sandbox::new(tag);
    let (ok, log) = sb.run(
        &["-q", "keygen", "rx", "-t", "radix", "--no-passphrase"],
        None,
    );
    assert!(ok, "keygen radix: {log}");
    sb
}

#[test]
fn radix_roundtrip_across_chunk_boundaries() {
    let sb = radix_sandbox("radix-chunks");
    for len in [0usize, 1, 1048575, 1048576, 1048577, 2_500_000] {
        let name = format!("r{len}.bin");
        write_bytes(&sb.work().join(&name), len);
        let original = fs::read(sb.work().join(&name)).unwrap();
        let (ok, log) = sb.run(&["-q", "--algo", "radix", "--key", "rx", "-e", &name], None);
        assert!(ok, "encrypt {len}: {log}");
        assert!(!sb.work().join(&name).exists());
        // No --key: the private key is found through the fingerprint.
        let (ok, log) = sb.run(&["-q", "-d", &format!("{name}.csec")], None);
        assert!(ok, "decrypt {len}: {log}");
        assert_eq!(
            fs::read(sb.work().join(&name)).unwrap(),
            original,
            "len {len}"
        );
    }
}

#[test]
fn radix_containers_are_version_2_and_say_so() {
    let sb = radix_sandbox("radix-info");
    fs::write(sb.work().join("a.txt"), "secret").unwrap();
    let (ok, log) = sb.run(
        &["-k", "--algo", "radix", "--key", "rx", "-e", "a.txt"],
        None,
    );
    assert!(ok, "{log}");
    assert!(log.contains("Radix-Cascade (concept)"), "{log}");
    let raw = fs::read(sb.work().join("a.txt.csec")).unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("\"version\":2"), "header is not version 2");
    assert!(text.contains("\"cipher\":\"radix-cascade\""));
    assert!(text.contains("\"mode\":\"radix-hybrid\""));
    assert!(!text.contains("secret"));
    let (ok, log) = sb.run(&["--info", "a.txt.csec"], None);
    assert!(ok, "{log}");
    assert!(log.contains("Radix hybrid key"), "{log}");
    assert!(log.contains("'rx' is in your key store"), "{log}");
}

#[test]
fn radix_directory_roundtrip() {
    let sb = radix_sandbox("radix-dir");
    let dir = sb.work().join("tree");
    fs::create_dir_all(dir.join("sub")).unwrap();
    fs::write(dir.join("one.txt"), "one").unwrap();
    write_bytes(&dir.join("sub/big.bin"), 1_500_000);
    let (ok, log) = sb.run(
        &["-q", "--algo", "radix", "--key", "rx", "-e", "tree"],
        None,
    );
    assert!(ok, "{log}");
    assert!(!dir.exists());
    let (ok, log) = sb.run(&["-q", "-d", "tree.csec"], None);
    assert!(ok, "{log}");
    assert_eq!(fs::read_to_string(dir.join("one.txt")).unwrap(), "one");
    assert_eq!(
        fs::metadata(dir.join("sub/big.bin")).unwrap().len(),
        1_500_000
    );
}

#[test]
fn radix_detects_a_flipped_byte_anywhere_in_the_payload() {
    let sb = radix_sandbox("radix-tamper");
    write_bytes(&sb.work().join("a.bin"), 1_100_000);
    let (ok, log) = sb.run(
        &["-q", "-k", "--algo", "radix", "--key", "rx", "-e", "a.bin"],
        None,
    );
    assert!(ok, "{log}");
    let container = sb.work().join("a.bin.csec");
    let clean = fs::read(&container).unwrap();
    // Commitment of the first chunk, inside the first chunk, and the very end.
    let magic = clean.windows(5).position(|w| w == b"CSEC\x01").unwrap();
    let len = u32::from_le_bytes(clean[magic + 5..magic + 9].try_into().unwrap()) as usize;
    let payload = magic + 9 + len;
    for pos in [payload, payload + 5000, clean.len() - 1] {
        let mut raw = clean.clone();
        raw[pos] ^= 0x01;
        fs::write(&container, &raw).unwrap();
        let (ok, log) = sb.run(&["-q", "-d", "a.bin.csec", "-o", "out.bin"], None);
        assert!(!ok, "flip at {pos} was accepted");
        assert!(log.contains("authentication failed"), "{log}");
        assert!(
            !sb.work().join("out.bin").exists(),
            "partial output at {pos}"
        );
    }
}

#[test]
fn radix_detects_truncation() {
    let sb = radix_sandbox("radix-truncate");
    write_bytes(&sb.work().join("a.bin"), 2_200_000);
    let (ok, log) = sb.run(
        &["-q", "--algo", "radix", "--key", "rx", "-e", "a.bin"],
        None,
    );
    assert!(ok, "{log}");
    let container = sb.work().join("a.bin.csec");
    let raw = fs::read(&container).unwrap();
    // Cut away almost all of the last chunk (it also holds the manifest
    // bytes, so a few remain): the end marker can no longer authenticate.
    let cut = 2_200_000 - 2 * 1_048_576 + 80;
    fs::write(&container, &raw[..raw.len() - cut]).unwrap();
    let (ok, _) = sb.run(&["-q", "-d", "a.bin.csec", "-o", "out.bin"], None);
    assert!(!ok, "truncated Radix container was accepted");
    assert!(!sb.work().join("out.bin").exists());
}

#[test]
fn radix_foreign_key_cannot_open_the_container() {
    let sb = radix_sandbox("radix-foreign");
    sb.run(
        &["-q", "keygen", "mallory", "-t", "radix", "--no-passphrase"],
        None,
    );
    fs::write(sb.work().join("a.txt"), "secret").unwrap();
    let (ok, _) = sb.run(
        &["-q", "-k", "--algo", "radix", "--key", "rx", "-e", "a.txt"],
        None,
    );
    assert!(ok);
    let (ok, log) = sb.run(
        &["-q", "-d", "a.txt.csec", "--key", "mallory", "-o", "x.txt"],
        None,
    );
    assert!(!ok);
    assert!(log.contains("does not match"), "{log}");
}

#[test]
fn radix_refuses_a_damaged_public_key() {
    let sb = radix_sandbox("radix-badkey");
    let pub_path = sb.root.join("cfg/keys/rx.pub");
    let text = fs::read_to_string(&pub_path).unwrap_or_else(|_| {
        panic!("public key not at {}", pub_path.display());
    });
    // Replace the key body with base64 of a key whose first ML-KEM
    // coefficient is out of range (all bits set).
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut in_body = false;
    let mut replaced = false;
    for l in &lines {
        if !in_body && l.is_empty() {
            in_body = true;
            out.push(l.to_string());
            continue;
        }
        if in_body && !replaced && !l.starts_with("-----") {
            // Base64 "////" decodes to 0xff 0xff 0xff: x25519 bytes first, so
            // patch further in, where the ML-KEM key starts (byte 32).
            let mut chars: Vec<char> = l.chars().collect();
            for c in chars.iter_mut().skip(44).take(4) {
                *c = '/';
            }
            out.push(chars.into_iter().collect());
            replaced = true;
            continue;
        }
        out.push(l.to_string());
    }
    fs::write(&pub_path, out.join("\n") + "\n").unwrap();
    fs::write(sb.work().join("a.txt"), "secret").unwrap();
    let (ok, log) = sb.run(
        &["-q", "--algo", "radix", "--key", "rx", "-e", "a.txt"],
        None,
    );
    assert!(!ok, "damaged public key was accepted: {log}");
    assert!(log.contains("invalid Radix public key"), "{log}");
    assert!(sb.work().join("a.txt").exists());
}
