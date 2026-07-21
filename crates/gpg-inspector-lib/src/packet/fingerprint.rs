//! Key fingerprint and key ID derivation.
//!
//! Computing a fingerprint requires hashing the public key material
//! (RFC 4880 §12.2, RFC 9580 §5.5.4). This is the library's single
//! deliberate exception to its "no cryptographic operations" design
//! philosophy: hashing for key *identity* only, never decryption,
//! signature verification, or key generation.
//!
//! V3 (MD5) fingerprints are intentionally not computed: v3 keys are
//! obsolete and MD5 is broken.

use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Computes a V4 key fingerprint: SHA-1 over `0x99 || len(2) || body`,
/// where `body` is the public key packet body (version octet through
/// key material).
pub fn v4_fingerprint(key_body: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update((key_body.len() as u16).to_be_bytes());
    hasher.update(key_body);
    hasher.finalize().into()
}

/// Computes a V6 key fingerprint (RFC 9580): SHA-256 over
/// `0x9B || len(4) || body`.
pub fn v6_fingerprint(key_body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x9B]);
    hasher.update((key_body.len() as u32).to_be_bytes());
    hasher.update(key_body);
    hasher.finalize().into()
}

/// Derives the 8-byte key ID from a fingerprint: the low-order (last)
/// 8 bytes for V4, the high-order (first) 8 bytes for V6.
pub fn key_id(version: u8, fingerprint: &[u8]) -> String {
    let bytes = match version {
        6 => &fingerprint[..8],
        _ => &fingerprint[fingerprint.len() - 8..],
    };
    to_hex(bytes)
}

/// Formats bytes as an uppercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}
