//! Symmetrically Encrypted Integrity Protected Data packet parsing.
//!
//! This module parses SEIPD packets (tag 18), which contain encrypted
//! message data with integrity protection. Version 1 uses MDC (Modification
//! Detection Code), while version 2 uses AEAD encryption.

use crate::color::ColorTracker;
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
    /// The encrypted data.
    pub encrypted_data: Vec<u8>,
}

/// Parses a SEIPD packet body.
pub fn parse_seipd(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<SeipdPacket> {
    let version_start = offset + stream.pos();
    let version = stream.octet()?;
    let version_end = offset + stream.pos();
    let color = colors.set_field(version_start, version_end);
    fields.push(Field::field(
        "Version",
        version.to_string(),
        (version_start, version_end),
        color,
    ));

    let (cipher_algo, aead_algo, chunk_size) = if version == 2 {
        let cipher_start = offset + stream.pos();
        let cipher = stream.octet()?;
        let cipher_end = offset + stream.pos();
        let color = colors.set_field(cipher_start, cipher_end);
        let cipher_info = lookup_symmetric_algorithm(cipher);
        fields.push(Field::field(
            "Cipher",
            cipher_info.display(),
            (cipher_start, cipher_end),
            color,
        ));

        let aead_start = offset + stream.pos();
        let aead = stream.octet()?;
        let aead_end = offset + stream.pos();
        let color = colors.set_field(aead_start, aead_end);
        let aead_info = lookup_aead_algorithm(aead);
        fields.push(Field::field(
            "AEAD",
            aead_info.display(),
            (aead_start, aead_end),
            color,
        ));

        let chunk_start = offset + stream.pos();
        let chunk = stream.octet()?;
        let chunk_end = offset + stream.pos();
        let color = colors.set_field(chunk_start, chunk_end);
        let chunk_bytes = 1usize << (chunk + 6);
        fields.push(Field::field(
            "Chunk Size",
            format!("{} bytes", chunk_bytes),
            (chunk_start, chunk_end),
            color,
        ));

        (Some(cipher), Some(aead), Some(chunk))
    } else {
        (None, None, None)
    };

    let data_start = offset + stream.pos();
    let encrypted_data = stream.rest();
    let data_end = offset + stream.pos();
    let color = colors.set_field(data_start, data_end);
    fields.push(Field::field(
        "Encrypted Data",
        format!("{} bytes", encrypted_data.len()),
        (data_start, data_end),
        color,
    ));

    Ok(SeipdPacket {
        version,
        cipher_algo,
        aead_algo,
        chunk_size,
        encrypted_data,
    })
}
