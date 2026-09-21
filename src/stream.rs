use std::io::{self, Read, Write};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;

use crate::format::{Cipher, CHUNK, TAG};

/// STREAM-style chunking: every chunk gets its own nonce, the final chunk is
/// flagged, so truncating the file is detected instead of silently accepted.
pub struct Sealer {
    aead: Aeads,
    prefix: [u8; 7],
    aad: [u8; 32],
    counter: u32,
}

enum Aeads {
    Aes(Box<Aes256Gcm>),
    Cha(Box<ChaCha20Poly1305>),
}

impl Sealer {
    pub fn new(cipher: Cipher, key: &[u8; 32], prefix: [u8; 7], aad: [u8; 32]) -> Self {
        let aead = match cipher {
            Cipher::Aes256Gcm => Aeads::Aes(Box::new(Aes256Gcm::new(key.into()))),
            Cipher::ChaCha20Poly1305 => Aeads::Cha(Box::new(ChaCha20Poly1305::new(key.into()))),
        };
        Sealer {
            aead,
            prefix,
            aad,
            counter: 0,
        }
    }

    fn nonce(&self, last: bool) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..7].copy_from_slice(&self.prefix);
        n[7..11].copy_from_slice(&self.counter.to_be_bytes());
        n[11] = u8::from(last);
        n
    }

    fn seal(&mut self, plain: &[u8], last: bool) -> io::Result<Vec<u8>> {
        let nonce = self.nonce(last);
        let payload = Payload {
            msg: plain,
            aad: &self.aad,
        };
        let out = match &self.aead {
            Aeads::Aes(c) => c.encrypt((&nonce).into(), payload),
            Aeads::Cha(c) => c.encrypt((&nonce).into(), payload),
        };
        self.counter = self.counter.wrapping_add(1);
        out.map_err(|_| io::Error::other("encryption failed"))
    }

    fn open(&mut self, ct: &[u8], last: bool) -> io::Result<Vec<u8>> {
        let nonce = self.nonce(last);
        let payload = Payload {
            msg: ct,
            aad: &self.aad,
        };
        let out = match &self.aead {
            Aeads::Aes(c) => c.decrypt((&nonce).into(), payload),
            Aeads::Cha(c) => c.decrypt((&nonce).into(), payload),
        };
        self.counter = self.counter.wrapping_add(1);
        out.map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "authentication failed - wrong key or damaged file",
            )
        })
    }
}

pub struct EncWriter<W: Write> {
    inner: W,
    sealer: Sealer,
    buf: Vec<u8>,
    done: bool,
}

impl<W: Write> EncWriter<W> {
    pub fn new(inner: W, sealer: Sealer) -> Self {
        EncWriter {
            inner,
            sealer,
            buf: Vec::with_capacity(CHUNK),
            done: false,
        }
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.flush_full()?;
        let tail = std::mem::take(&mut self.buf);
        let ct = self.sealer.seal(&tail, true)?;
        self.inner.write_all(&ct)?;
        self.inner.flush()?;
        self.done = true;
        Ok(self.inner)
    }

    fn flush_full(&mut self) -> io::Result<()> {
        while self.buf.len() >= CHUNK {
            let rest = self.buf.split_off(CHUNK);
            let chunk = std::mem::replace(&mut self.buf, rest);
            let ct = self.sealer.seal(&chunk, false)?;
            self.inner.write_all(&ct)?;
        }
        Ok(())
    }
}

impl<W: Write> Write for EncWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        self.flush_full()?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct DecReader<R: Read> {
    inner: R,
    sealer: Sealer,
    plain: Vec<u8>,
    pos: usize,
    done: bool,
}

impl<R: Read> DecReader<R> {
    pub fn new(inner: R, sealer: Sealer) -> Self {
        DecReader {
            inner,
            sealer,
            plain: Vec::new(),
            pos: 0,
            done: false,
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        let mut ct = vec![0u8; CHUNK + TAG];
        let n = read_upto(&mut self.inner, &mut ct)?;
        if n == 0 && !self.done {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file ends early - the container is truncated",
            ));
        }
        let last = n < CHUNK + TAG;
        self.plain = self.sealer.open(&ct[..n], last)?;
        self.pos = 0;
        if last {
            self.done = true;
            let mut extra = [0u8; 1];
            if self.inner.read(&mut extra)? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "trailing data after the final chunk",
                ));
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for DecReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pos == self.plain.len() {
            if self.done {
                return Ok(0);
            }
            self.fill()?;
        }
        let n = std::cmp::min(out.len(), self.plain.len() - self.pos);
        out[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// `Read::read` may return short reads; a chunk boundary must not depend on that.
fn read_upto<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}
