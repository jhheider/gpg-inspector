//! Symmetrically Encrypted Integrity Protected Data packet parsing.
//!
//! This module parses SEIPD packets (tag 18), which contain encrypted
//! message data with integrity protection. Version 1 uses MDC (Modification
//! Detection Code), while version 2 uses AEAD encryption.

use crate::error::Result;
use crate::lookup::{lookup_aead_algorithm, lookup_symmetric_algorithm};
use crate::packet::Field;
use crate::stream::ByteStream;

/// A parsed SEIPD (Symmetrically Encrypted Integrity Protected Data) packet.
///
/// Contains encrypted data and, for version 2, AEAD parameters.
#[derive(Debug, Clone)]
pub struct SeipdPacket {
    /// Packet version (1 = MDC, 2 = AEAD).
    pub version: u8,
    /// Symmetric cipher algorithm (version 2 only).
    pub cipher_algo: Option<u8>,
    /// AEAD algorithm (version 2 only).
    pub aead_algo: Option<u8>,
    /// Chunk size exponent (version 2 only).
    pub chunk_size: Option<u8>,
    /// 32-byte salt (version 2 only, RFC 9580).
    pub salt: Option<Vec<u8>>,
    /// The encrypted data.
    pub encrypted_data: Vec<u8>,
}

/// Parses a SEIPD packet body.
pub fn parse_seipd(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<SeipdPacket> {
    let version_start = offset + stream.pos();
    let version = stream.octet()?;
    let version_end = offset + stream.pos();
    fields.push(Field::field(
        "Version",
        version.to_string(),
        (version_start, version_end),
    ));

    let (cipher_algo, aead_algo, chunk_size, salt) = if version == 2 {
        let cipher_start = offset + stream.pos();
        let cipher = stream.octet()?;
        let cipher_end = offset + stream.pos();
        let cipher_info = lookup_symmetric_algorithm(cipher);
        fields.push(Field::field(
            "Cipher",
            cipher_info.display(),
            (cipher_start, cipher_end),
        ));

        let aead_start = offset + stream.pos();
        let aead = stream.octet()?;
        let aead_end = offset + stream.pos();
        let aead_info = lookup_aead_algorithm(aead);
        fields.push(Field::field(
            "AEAD",
            aead_info.display(),
            (aead_start, aead_end),
        ));

        let chunk_start = offset + stream.pos();
        let chunk = stream.octet()?;
        let chunk_end = offset + stream.pos();
        let chunk_bytes = 1usize << (chunk + 6);
        fields.push(Field::field(
            "Chunk Size",
            format!("{} bytes", chunk_bytes),
            (chunk_start, chunk_end),
        ));

        // V2: 32-byte salt (RFC 9580)
        let salt_start = offset + stream.pos();
        let salt_bytes = stream.bytes(32)?;
        let salt_end = offset + stream.pos();
        fields.push(Field::field("Salt", "32 bytes", (salt_start, salt_end)));

        (Some(cipher), Some(aead), Some(chunk), Some(salt_bytes))
    } else {
        (None, None, None, None)
    };

    let data_start = offset + stream.pos();
    let encrypted_data = stream.rest();
    let data_end = offset + stream.pos();
    fields.push(Field::field(
        "Encrypted Data",
        format!("{} bytes", encrypted_data.len()),
        (data_start, data_end),
    ));

    Ok(SeipdPacket {
        version,
        cipher_algo,
        aead_algo,
        chunk_size,
        salt,
        encrypted_data,
    })
}
