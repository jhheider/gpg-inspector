//! One-Pass Signature packet parsing (tag 4).
//!
//! One-Pass Signature packets precede the signed data and contain enough
//! information to allow the receiver to begin calculating hashes needed
//! to verify the signature. This allows the actual Signature packet to
//! be placed at the end of the message.
//!
//! RFC 4880 Section 5.4

use crate::error::Result;
use crate::lookup::{lookup_hash_algorithm, lookup_public_key_algorithm, lookup_signature_type};
use crate::stream::ByteStream;

use super::Field;

/// Parsed One-Pass Signature packet.
#[derive(Debug, Clone)]
pub struct OnePassSignaturePacket {
    /// Packet version (3 or 6).
    pub version: u8,
    /// Signature type (binary, text, certification, etc.).
    pub signature_type: u8,
    /// Hash algorithm used.
    pub hash_algorithm: u8,
    /// Public-key algorithm used.
    pub public_key_algorithm: u8,
    /// Key ID of the signing key (v3) or salt (v6).
    pub key_id: Vec<u8>,
    /// Nested flag: 0 = another One-Pass Signature follows.
    pub nested: u8,
    /// Fingerprint (v6 only).
    pub fingerprint: Option<Vec<u8>>,
}

/// Parses a One-Pass Signature packet body.
pub fn parse_one_pass_signature(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<OnePassSignaturePacket> {
    let version_start = body_offset + stream.pos();
    let version = stream.octet()?;
    fields.push(Field::field(
        "Version",
        version.to_string(),
        (version_start, version_start + 1),
    ));

    if version == 6 {
        parse_v6_one_pass_signature(stream, fields, body_offset, version)
    } else {
        parse_v3_one_pass_signature(stream, fields, body_offset, version)
    }
}

fn parse_v3_one_pass_signature(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
    version: u8,
) -> Result<OnePassSignaturePacket> {
    let sig_type_start = body_offset + stream.pos();
    let signature_type = stream.octet()?;
    let sig_type_lookup = lookup_signature_type(signature_type);
    fields.push(Field::field(
        "Signature Type",
        sig_type_lookup.display(),
        (sig_type_start, sig_type_start + 1),
    ));

    let hash_start = body_offset + stream.pos();
    let hash_algorithm = stream.octet()?;
    let hash_lookup = lookup_hash_algorithm(hash_algorithm);
    fields.push(Field::field(
        "Hash Algorithm",
        hash_lookup.display(),
        (hash_start, hash_start + 1),
    ));

    let pk_start = body_offset + stream.pos();
    let public_key_algorithm = stream.octet()?;
    let pk_lookup = lookup_public_key_algorithm(public_key_algorithm);
    fields.push(Field::field(
        "Public-Key Algorithm",
        pk_lookup.display(),
        (pk_start, pk_start + 1),
    ));

    let key_id_start = body_offset + stream.pos();
    let key_id = stream.bytes(8)?;
    let key_id_hex: String = key_id.iter().map(|b| format!("{:02X}", b)).collect();
    fields.push(Field::field(
        "Issuer Key ID",
        key_id_hex,
        (key_id_start, key_id_start + 8),
    ));

    let nested_start = body_offset + stream.pos();
    let nested = stream.octet()?;
    let nested_desc = if nested == 0 {
        "0 (more signatures follow)"
    } else {
        "1 (last signature)"
    };
    fields.push(Field::field(
        "Nested",
        nested_desc,
        (nested_start, nested_start + 1),
    ));

    Ok(OnePassSignaturePacket {
        version,
        signature_type,
        hash_algorithm,
        public_key_algorithm,
        key_id,
        nested,
        fingerprint: None,
    })
}

fn parse_v6_one_pass_signature(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
    version: u8,
) -> Result<OnePassSignaturePacket> {
    let sig_type_start = body_offset + stream.pos();
    let signature_type = stream.octet()?;
    let sig_type_lookup = lookup_signature_type(signature_type);
    fields.push(Field::field(
        "Signature Type",
        sig_type_lookup.display(),
        (sig_type_start, sig_type_start + 1),
    ));

    let hash_start = body_offset + stream.pos();
    let hash_algorithm = stream.octet()?;
    let hash_lookup = lookup_hash_algorithm(hash_algorithm);
    fields.push(Field::field(
        "Hash Algorithm",
        hash_lookup.display(),
        (hash_start, hash_start + 1),
    ));

    let pk_start = body_offset + stream.pos();
    let public_key_algorithm = stream.octet()?;
    let pk_lookup = lookup_public_key_algorithm(public_key_algorithm);
    fields.push(Field::field(
        "Public-Key Algorithm",
        pk_lookup.display(),
        (pk_start, pk_start + 1),
    ));

    // v6: salt length (1 octet) + salt
    let salt_len_start = body_offset + stream.pos();
    let salt_len = stream.octet()? as usize;
    fields.push(Field::field(
        "Salt Length",
        salt_len.to_string(),
        (salt_len_start, salt_len_start + 1),
    ));

    let salt_start = body_offset + stream.pos();
    let salt = stream.bytes(salt_len)?;
    let salt_hex: String = salt.iter().map(|b| format!("{:02X}", b)).collect();
    fields.push(Field::field(
        "Salt",
        salt_hex,
        (salt_start, salt_start + salt_len),
    ));

    // v6: fingerprint (32 bytes)
    let fp_start = body_offset + stream.pos();
    let fingerprint = stream.bytes(32)?;
    let fp_hex: String = fingerprint.iter().map(|b| format!("{:02X}", b)).collect();
    fields.push(Field::field(
        "Issuer Fingerprint",
        fp_hex,
        (fp_start, fp_start + 32),
    ));

    let nested_start = body_offset + stream.pos();
    let nested = stream.octet()?;
    let nested_desc = if nested == 0 {
        "0 (more signatures follow)"
    } else {
        "1 (last signature)"
    };
    fields.push(Field::field(
        "Nested",
        nested_desc,
        (nested_start, nested_start + 1),
    ));

    Ok(OnePassSignaturePacket {
        version,
        signature_type,
        hash_algorithm,
        public_key_algorithm,
        key_id: salt,
        nested,
        fingerprint: Some(fingerprint),
    })
}
