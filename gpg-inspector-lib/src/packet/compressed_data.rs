//! Compressed Data packet parsing (tag 8).
//!
//! Compressed Data packets contain compressed data that, when decompressed,
//! yields other OpenPGP packets (typically Literal Data or Signature packets).
//!
//! RFC 4880 Section 5.6

use crate::error::Result;
use crate::lookup::lookup_compression_algorithm;
use crate::stream::ByteStream;

use super::Field;

/// Parsed Compressed Data packet.
#[derive(Debug, Clone)]
pub struct CompressedDataPacket {
    /// Compression algorithm used.
    pub algorithm: u8,
    /// Compressed data (not decompressed).
    pub compressed_data: Vec<u8>,
}

/// Parses a Compressed Data packet body.
pub fn parse_compressed_data(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<CompressedDataPacket> {
    let algo_start = body_offset + stream.pos();
    let algorithm = stream.octet()?;
    let algo_lookup = lookup_compression_algorithm(algorithm);
    fields.push(Field::field(
        "Algorithm",
        algo_lookup.display(),
        (algo_start, algo_start + 1),
    ));

    let data_start = body_offset + stream.pos();
    let compressed_data = stream.rest();
    let data_end = body_offset + stream.pos();

    if !compressed_data.is_empty() {
        fields.push(Field::field(
            "Compressed Data",
            format!("{} bytes", compressed_data.len()),
            (data_start, data_end),
        ));
    }

    Ok(CompressedDataPacket {
        algorithm,
        compressed_data,
    })
}
