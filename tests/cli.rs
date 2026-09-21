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
        fs::remove_file(&src).unwrap();

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
}

#[test]
fn directory_roundtrip_keeps_the_tree() {
    let sb = Sandbox::new("dir");
    let dir = sb.work().join("tree");
    fs::create_dir_all(dir.join("sub/deep")).unwrap();
    fs::write(dir.join("one.txt"), "one").unwrap();
    fs::write(dir.join("sub/two.txt"), "two").unwrap();
    write_bytes(&dir.join("sub/deep/three.bin"), 300_000);

    let (ok, log) = sb.run(
        &["-q", "--algo", "chacha", "--password-stdin", "-e", "tree"],
        Some(PASS),
    );
    assert!(ok, "{log}");
    fs::remove_dir_all(&dir).unwrap();

    let (ok, log) = sb.run(&["-q", "--password-stdin", "-d", "tree.csec"], Some(PASS));
    assert!(ok, "{log}");
    assert_eq!(fs::read_to_string(dir.join("one.txt")).unwrap(), "one");
    assert_eq!(fs::read_to_string(dir.join("sub/two.txt")).unwrap(), "two");
    assert_eq!(
        fs::metadata(dir.join("sub/deep/three.bin")).unwrap().len(),
        300_000
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
    fs::remove_file(sb.work().join("a.txt")).unwrap();
    let (ok, log) = sb.run(
        &["-q", "--password-stdin", "-d", "a.txt.csec"],
        Some("not the password\n"),
    );
    assert!(!ok);
    assert!(log.contains("wrong password"), "{log}");
    assert!(!sb.work().join("a.txt").exists());
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
                "-q", "--algo", algo, "--key", name, "-e", "a.bin", "-o", &out,
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
        &["-q", "--algo", "ecc", "--key", "alice", "-e", "a.txt"],
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
        &["-q", "--algo", "rsa", "--key", "carol", "-e", "a.bin"],
        None,
    );
    assert!(ok, "{log}");
    let (ok, log) = sb.run(&["-q", "-d", "a.bin.csec", "-o", "back.bin"], None);
    assert!(ok, "{log}");
    assert_eq!(fs::read(sb.work().join("back.bin")).unwrap(), original);
}
