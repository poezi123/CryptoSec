//! Radix (concept): a hybrid post-quantum key exchange and a triple AEAD
//! cascade around an experimental ARX permutation.
//!
//! Radix-P and Radix-AEAD are a new, not externally reviewed design and are
//! only used as the innermost layer of Radix-Cascade, whose security rests on
//! AES-256-GCM and ChaCha20-Poly1305. Radix-Hybrid combines X25519 with
//! ML-KEM-768 and stays secure while either of the two holds.

pub mod aead;
pub mod cascade;
pub mod hybrid;
pub mod permutation;
