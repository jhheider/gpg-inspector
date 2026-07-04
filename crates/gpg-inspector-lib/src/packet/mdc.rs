//! Modification Detection Code packet parsing (tag 19).
//!
//! MDC packets contain a 20-byte SHA-1 hash of the plaintext data,
//! used to detect message modification. An MDC packet must always
//! be the last packet in a Symmetrically Encrypted Integrity Protected
//! Data packet's plaintext.
//!
//! RFC 4880 Section 5.14

use crate::error::Result;
use crate::stream::ByteStream;

use super::Field;

/// Parsed Modification Detection Code packet.
#[derive(Debug, Clone)]
pub struct MdcPacket {
    /// The 20-byte SHA-1 hash.
    pub hash: [u8; 20],
}

/// Parses a Modification Detection Code packet body.
///
/// The packet must be exactly 20 bytes (SHA-1 hash output).
pub fn parse_mdc(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<MdcPacket> {
    let hash_start = body_offset + stream.pos();
    let hash_bytes = stream.bytes(20)?;

    let mut hash = [0u8; 20];
    hash.copy_from_slice(&hash_bytes);

    let hash_hex: String = hash.iter().map(|b| format!("{:02X}", b)).collect();
    fields.push(Field::field(
        "SHA-1 Hash",
        hash_hex,
        (hash_start, hash_start + 20),
    ));

    Ok(MdcPacket { hash })
}
