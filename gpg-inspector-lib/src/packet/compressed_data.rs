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

/// Maximum decompressed size in bytes (decompression-bomb guard).
#[cfg(feature = "decompress")]
pub const MAX_DECOMPRESSED: u64 = 64 * 1024 * 1024;

/// Decompresses a Compressed Data packet payload.
///
/// Supports the RFC 4880 algorithms: 0 (uncompressed passthrough),
/// 1 (ZIP / raw DEFLATE), 2 (ZLIB), and 3 (BZip2). Output is capped at
/// [`MAX_DECOMPRESSED`] bytes to guard against decompression bombs.
///
/// Returns a human-readable error message on failure so callers can
/// surface it as a field without aborting the parse.
#[cfg(feature = "decompress")]
pub fn decompress(algorithm: u8, data: &[u8]) -> std::result::Result<Vec<u8>, String> {
    use std::io::Read;

    let mut out = Vec::new();
    let limit = MAX_DECOMPRESSED + 1;
    let read_result = match algorithm {
        0 => {
            out.extend_from_slice(data);
            Ok(data.len())
        }
        1 => flate2::read::DeflateDecoder::new(data)
            .take(limit)
            .read_to_end(&mut out),
        2 => flate2::read::ZlibDecoder::new(data)
            .take(limit)
            .read_to_end(&mut out),
        3 => bzip2::read::BzDecoder::new(data)
            .take(limit)
            .read_to_end(&mut out),
        n => return Err(format!("unsupported compression algorithm {}", n)),
    };

    match read_result {
        Ok(_) if out.len() as u64 > MAX_DECOMPRESSED => Err(format!(
            "decompressed data exceeds {} MiB cap; not expanded",
            MAX_DECOMPRESSED / (1024 * 1024)
        )),
        Ok(_) => Ok(out),
        Err(e) => Err(format!("decompression failed: {}", e)),
    }
}
