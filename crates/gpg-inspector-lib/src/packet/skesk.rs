//! Symmetric-Key Encrypted Session Key packet parsing (tag 3).
//!
//! SKESK packets hold a session key encrypted with a symmetric key derived
//! from a passphrase. This allows a message to be decrypted with a passphrase
//! instead of (or in addition to) a public key.
//!
//! RFC 4880 Section 5.3, RFC 9580 Section 5.3

use crate::error::Result;
use crate::lookup::{
    lookup_aead_algorithm, lookup_hash_algorithm, lookup_s2k_type, lookup_symmetric_algorithm,
};
use crate::stream::ByteStream;

use super::Field;

/// S2K (String-to-Key) specifier for passphrase-based key derivation.
#[derive(Debug, Clone)]
pub struct S2kSpecifier {
    /// S2K type (0=Simple, 1=Salted, 3=Iterated, 4=Argon2).
    pub s2k_type: u8,
    /// Hash algorithm (for types 0, 1, 3).
    pub hash_algorithm: Option<u8>,
    /// 8-byte salt (for types 1, 3).
    pub salt: Option<Vec<u8>>,
    /// Iteration count byte (for type 3).
    pub count: Option<u8>,
    /// Argon2 parameters (for type 4).
    pub argon2_params: Option<Argon2Params>,
}

/// Argon2 parameters for S2K type 4.
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// 16-byte salt.
    pub salt: Vec<u8>,
    /// Parallelism parameter (t).
    pub parallelism: u8,
    /// Memory parameter (m), encoded as power of 2.
    pub memory: u8,
    /// Iterations parameter (p).
    pub iterations: u8,
}

/// Parsed Symmetric-Key Encrypted Session Key packet.
#[derive(Debug, Clone)]
pub struct SkeskPacket {
    /// Packet version (4, 5, or 6).
    pub version: u8,
    /// Symmetric cipher algorithm.
    pub cipher_algorithm: u8,
    /// AEAD algorithm (v5/v6 only).
    pub aead_algorithm: Option<u8>,
    /// S2K specifier.
    pub s2k: S2kSpecifier,
    /// IV (v5/v6 AEAD only).
    pub iv: Option<Vec<u8>>,
    /// Encrypted session key (may be absent if S2K produces the session key directly).
    pub encrypted_session_key: Option<Vec<u8>>,
    /// Authentication tag (v5/v6 AEAD only).
    pub auth_tag: Option<Vec<u8>>,
}

/// Parses a Symmetric-Key Encrypted Session Key packet body.
pub fn parse_skesk(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<SkeskPacket> {
    let version_start = body_offset + stream.pos();
    let version = stream.octet()?;
    fields.push(Field::field(
        "Version",
        version.to_string(),
        (version_start, version_start + 1),
    ));

    match version {
        4 => parse_skesk_v4(stream, fields, body_offset, version),
        5 | 6 => parse_skesk_v6(stream, fields, body_offset, version),
        _ => parse_skesk_v4(stream, fields, body_offset, version), // Best effort
    }
}

fn parse_skesk_v4(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
    version: u8,
) -> Result<SkeskPacket> {
    let cipher_start = body_offset + stream.pos();
    let cipher_algorithm = stream.octet()?;
    let cipher_lookup = lookup_symmetric_algorithm(cipher_algorithm);
    fields.push(Field::field(
        "Cipher Algorithm",
        cipher_lookup.display(),
        (cipher_start, cipher_start + 1),
    ));

    let s2k = parse_s2k_specifier(stream, fields, body_offset)?;

    // Remaining bytes are the encrypted session key (optional)
    let remaining = stream.remaining();
    let encrypted_session_key = if remaining > 0 {
        let esk_start = body_offset + stream.pos();
        let esk = stream.rest();
        let esk_end = body_offset + stream.pos();
        fields.push(Field::field(
            "Encrypted Session Key",
            format!("{} bytes", esk.len()),
            (esk_start, esk_end),
        ));
        Some(esk)
    } else {
        fields.push(Field::field(
            "Session Key",
            "Derived directly from S2K",
            (body_offset + stream.pos(), body_offset + stream.pos()),
        ));
        None
    };

    Ok(SkeskPacket {
        version,
        cipher_algorithm,
        aead_algorithm: None,
        s2k,
        iv: None,
        encrypted_session_key,
        auth_tag: None,
    })
}

fn parse_skesk_v6(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
    version: u8,
) -> Result<SkeskPacket> {
    // v6: count (1) + cipher (1) + aead (1) + s2k_len (1) + s2k + iv + encrypted_key + tag

    let count_start = body_offset + stream.pos();
    let count = stream.octet()?;
    fields.push(Field::field(
        "S2K + Cipher Info Length",
        count.to_string(),
        (count_start, count_start + 1),
    ));

    let cipher_start = body_offset + stream.pos();
    let cipher_algorithm = stream.octet()?;
    let cipher_lookup = lookup_symmetric_algorithm(cipher_algorithm);
    fields.push(Field::field(
        "Cipher Algorithm",
        cipher_lookup.display(),
        (cipher_start, cipher_start + 1),
    ));

    let aead_start = body_offset + stream.pos();
    let aead_algorithm = stream.octet()?;
    let aead_lookup = lookup_aead_algorithm(aead_algorithm);
    fields.push(Field::field(
        "AEAD Algorithm",
        aead_lookup.display(),
        (aead_start, aead_start + 1),
    ));

    let s2k_len_start = body_offset + stream.pos();
    let s2k_len = stream.octet()? as usize;
    fields.push(Field::field(
        "S2K Length",
        s2k_len.to_string(),
        (s2k_len_start, s2k_len_start + 1),
    ));

    let s2k = parse_s2k_specifier(stream, fields, body_offset)?;

    // IV length depends on AEAD mode
    let iv_len = match aead_algorithm {
        1 => 16, // EAX
        2 => 15, // OCB
        3 => 12, // GCM
        _ => 16, // Default
    };
    let iv_start = body_offset + stream.pos();
    let iv = stream.bytes(iv_len)?;
    fields.push(Field::field(
        "IV/Nonce",
        format!("{} bytes", iv.len()),
        (iv_start, iv_start + iv_len),
    ));

    // Auth tag is 16 bytes at the end, rest is encrypted session key
    let remaining = stream.remaining();
    let tag_len = 16;
    let esk_len = remaining.saturating_sub(tag_len);

    let encrypted_session_key = if esk_len > 0 {
        let esk_start = body_offset + stream.pos();
        let esk = stream.bytes(esk_len)?;
        fields.push(Field::field(
            "Encrypted Session Key",
            format!("{} bytes", esk.len()),
            (esk_start, esk_start + esk_len),
        ));
        Some(esk)
    } else {
        None
    };

    let auth_tag = if stream.remaining() >= tag_len {
        let tag_start = body_offset + stream.pos();
        let tag = stream.bytes(tag_len)?;
        fields.push(Field::field(
            "Authentication Tag",
            format!("{} bytes", tag.len()),
            (tag_start, tag_start + tag_len),
        ));
        Some(tag)
    } else {
        None
    };

    Ok(SkeskPacket {
        version,
        cipher_algorithm,
        aead_algorithm: Some(aead_algorithm),
        s2k,
        iv: Some(iv),
        encrypted_session_key,
        auth_tag,
    })
}

/// Parses an S2K specifier.
fn parse_s2k_specifier(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<S2kSpecifier> {
    let type_start = body_offset + stream.pos();
    let s2k_type = stream.octet()?;
    fields.push(Field::field(
        "S2K Type",
        lookup_s2k_type(s2k_type),
        (type_start, type_start + 1),
    ));

    match s2k_type {
        0 => {
            // Simple S2K: just hash algorithm
            let hash_start = body_offset + stream.pos();
            let hash_algorithm = stream.octet()?;
            let hash_lookup = lookup_hash_algorithm(hash_algorithm);
            fields.push(Field::field(
                "S2K Hash",
                hash_lookup.display(),
                (hash_start, hash_start + 1),
            ));

            Ok(S2kSpecifier {
                s2k_type,
                hash_algorithm: Some(hash_algorithm),
                salt: None,
                count: None,
                argon2_params: None,
            })
        }
        1 => {
            // Salted S2K: hash algorithm + 8-byte salt
            let hash_start = body_offset + stream.pos();
            let hash_algorithm = stream.octet()?;
            let hash_lookup = lookup_hash_algorithm(hash_algorithm);
            fields.push(Field::field(
                "S2K Hash",
                hash_lookup.display(),
                (hash_start, hash_start + 1),
            ));

            let salt_start = body_offset + stream.pos();
            let salt = stream.bytes(8)?;
            let salt_hex: String = salt.iter().map(|b| format!("{:02X}", b)).collect();
            fields.push(Field::field(
                "S2K Salt",
                salt_hex,
                (salt_start, salt_start + 8),
            ));

            Ok(S2kSpecifier {
                s2k_type,
                hash_algorithm: Some(hash_algorithm),
                salt: Some(salt),
                count: None,
                argon2_params: None,
            })
        }
        3 => {
            // Iterated and Salted S2K: hash + salt + count
            let hash_start = body_offset + stream.pos();
            let hash_algorithm = stream.octet()?;
            let hash_lookup = lookup_hash_algorithm(hash_algorithm);
            fields.push(Field::field(
                "S2K Hash",
                hash_lookup.display(),
                (hash_start, hash_start + 1),
            ));

            let salt_start = body_offset + stream.pos();
            let salt = stream.bytes(8)?;
            let salt_hex: String = salt.iter().map(|b| format!("{:02X}", b)).collect();
            fields.push(Field::field(
                "S2K Salt",
                salt_hex,
                (salt_start, salt_start + 8),
            ));

            let count_start = body_offset + stream.pos();
            let count = stream.octet()?;
            // Decode iteration count: (16 + (c & 15)) << ((c >> 4) + 6)
            let iterations = (16u32 + (count as u32 & 15)) << ((count >> 4) + 6);
            fields.push(Field::field(
                "S2K Iterations",
                format!("{} (encoded: {})", iterations, count),
                (count_start, count_start + 1),
            ));

            Ok(S2kSpecifier {
                s2k_type,
                hash_algorithm: Some(hash_algorithm),
                salt: Some(salt),
                count: Some(count),
                argon2_params: None,
            })
        }
        4 => {
            // Argon2 S2K: 16-byte salt + t + m + p
            let salt_start = body_offset + stream.pos();
            let salt = stream.bytes(16)?;
            let salt_hex: String = salt.iter().map(|b| format!("{:02X}", b)).collect();
            fields.push(Field::field(
                "Argon2 Salt",
                salt_hex,
                (salt_start, salt_start + 16),
            ));

            let t_start = body_offset + stream.pos();
            let parallelism = stream.octet()?;
            fields.push(Field::field(
                "Argon2 Parallelism (t)",
                parallelism.to_string(),
                (t_start, t_start + 1),
            ));

            let m_start = body_offset + stream.pos();
            let memory = stream.octet()?;
            let memory_kb = 1u64 << memory;
            fields.push(Field::field(
                "Argon2 Memory (m)",
                format!("{} KiB (2^{})", memory_kb, memory),
                (m_start, m_start + 1),
            ));

            let p_start = body_offset + stream.pos();
            let iterations = stream.octet()?;
            fields.push(Field::field(
                "Argon2 Iterations (p)",
                iterations.to_string(),
                (p_start, p_start + 1),
            ));

            Ok(S2kSpecifier {
                s2k_type,
                hash_algorithm: None,
                salt: None,
                count: None,
                argon2_params: Some(Argon2Params {
                    salt,
                    parallelism,
                    memory,
                    iterations,
                }),
            })
        }
        _ => {
            // Unknown S2K type, just return minimal info
            Ok(S2kSpecifier {
                s2k_type,
                hash_algorithm: None,
                salt: None,
                count: None,
                argon2_params: None,
            })
        }
    }
}
