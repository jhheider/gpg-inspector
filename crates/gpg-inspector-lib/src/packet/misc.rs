//! Miscellaneous simple packet parsing.
//!
//! This module handles several simple packet types that have straightforward
//! structures:
//! - Marker packet (tag 10) - obsolete, contains "PGP" magic
//! - Symmetrically Encrypted Data (tag 9) - legacy encrypted data
//! - AEAD Encrypted Data (tag 20) - RFC 9580 AEAD encryption
//! - Padding packet (tag 21) - RFC 9580 padding

use crate::error::Result;
use crate::lookup::{lookup_aead_algorithm, lookup_symmetric_algorithm};
use crate::stream::ByteStream;

use super::Field;

// =============================================================================
// Marker Packet (tag 10)
// =============================================================================

/// Parsed Marker packet.
///
/// The Marker packet is obsolete and contains only the three bytes "PGP".
/// It was used to indicate newer message formats to older PGP versions.
#[derive(Debug, Clone)]
pub struct MarkerPacket {
    /// Whether the packet contains valid "PGP" magic bytes.
    pub valid: bool,
}

/// Parses a Marker packet body.
///
/// RFC 4880 Section 5.8: Must contain exactly 0x50, 0x47, 0x50 ("PGP").
pub fn parse_marker(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<MarkerPacket> {
    let marker_start = body_offset + stream.pos();
    let data = stream.rest();

    let valid = data == [0x50, 0x47, 0x50]; // "PGP"
    let status = if valid {
        "PGP (valid)"
    } else if data.len() == 3 {
        "Invalid marker"
    } else {
        "Invalid length"
    };

    fields.push(Field::field(
        "Marker",
        status,
        (marker_start, marker_start + data.len()),
    ));

    Ok(MarkerPacket { valid })
}

// =============================================================================
// Symmetrically Encrypted Data Packet (tag 9)
// =============================================================================

/// Parsed Symmetrically Encrypted Data packet.
///
/// This is the legacy encryption format without integrity protection.
/// The encrypted data is in OpenPGP CFB mode.
#[derive(Debug, Clone)]
pub struct SymmetricallyEncryptedDataPacket {
    /// The encrypted data (includes random prefix and encrypted content).
    pub encrypted_data: Vec<u8>,
}

/// Parses a Symmetrically Encrypted Data packet body.
///
/// RFC 4880 Section 5.7: Contains raw CFB-encrypted data.
pub fn parse_symmetrically_encrypted_data(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<SymmetricallyEncryptedDataPacket> {
    let data_start = body_offset + stream.pos();
    let encrypted_data = stream.rest();
    let data_end = body_offset + stream.pos();

    fields.push(Field::field(
        "Encrypted Data",
        format!("{} bytes (legacy CFB, no MDC)", encrypted_data.len()),
        (data_start, data_end),
    ));

    Ok(SymmetricallyEncryptedDataPacket { encrypted_data })
}

// =============================================================================
// AEAD Encrypted Data Packet (tag 20)
// =============================================================================

/// Parsed AEAD Encrypted Data packet.
///
/// RFC 9580: Authenticated encryption with associated data.
#[derive(Debug, Clone)]
pub struct AeadEncryptedDataPacket {
    /// Packet version (1).
    pub version: u8,
    /// Symmetric cipher algorithm.
    pub cipher_algorithm: u8,
    /// AEAD mode (EAX, OCB, GCM).
    pub aead_algorithm: u8,
    /// Chunk size (power of 2, encoded).
    pub chunk_size: u8,
    /// Initialization vector / starting nonce.
    pub iv: Vec<u8>,
    /// Encrypted data with authentication tags.
    pub encrypted_data: Vec<u8>,
}

/// Parses an AEAD Encrypted Data packet body.
pub fn parse_aead_encrypted_data(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<AeadEncryptedDataPacket> {
    let version_start = body_offset + stream.pos();
    let version = stream.octet()?;
    fields.push(Field::field(
        "Version",
        version.to_string(),
        (version_start, version_start + 1),
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

    let chunk_start = body_offset + stream.pos();
    let chunk_size = stream.octet()?;
    let chunk_bytes = 1u64 << (chunk_size + 6);
    fields.push(Field::field(
        "Chunk Size",
        format!("{} bytes (2^{})", chunk_bytes, chunk_size + 6),
        (chunk_start, chunk_start + 1),
    ));

    // IV length depends on AEAD mode
    let iv_len = match aead_algorithm {
        1 => 16, // EAX
        2 => 15, // OCB
        3 => 12, // GCM
        _ => 16, // Default
    };

    let iv_start = body_offset + stream.pos();
    let iv = stream.bytes(iv_len)?;
    let iv_hex: String = iv.iter().map(|b| format!("{:02X}", b)).collect();
    fields.push(Field::field(
        "IV/Nonce",
        iv_hex,
        (iv_start, iv_start + iv_len),
    ));

    let data_start = body_offset + stream.pos();
    let encrypted_data = stream.rest();
    let data_end = body_offset + stream.pos();

    if !encrypted_data.is_empty() {
        fields.push(Field::field(
            "Encrypted Data",
            format!("{} bytes (with auth tags)", encrypted_data.len()),
            (data_start, data_end),
        ));
    }

    Ok(AeadEncryptedDataPacket {
        version,
        cipher_algorithm,
        aead_algorithm,
        chunk_size,
        iv,
        encrypted_data,
    })
}

// =============================================================================
// Padding Packet (tag 21)
// =============================================================================

/// Parsed Padding packet.
///
/// RFC 9580: Contains random padding bytes to obscure message size.
#[derive(Debug, Clone)]
pub struct PaddingPacket {
    /// The padding bytes (should be random).
    pub padding: Vec<u8>,
}

/// Parses a Padding packet body.
pub fn parse_padding(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<PaddingPacket> {
    let padding_start = body_offset + stream.pos();
    let padding = stream.rest();
    let padding_end = body_offset + stream.pos();

    fields.push(Field::field(
        "Padding",
        format!("{} bytes", padding.len()),
        (padding_start, padding_end),
    ));

    Ok(PaddingPacket { padding })
}
