//! ASCII armor encoding and decoding for PGP data.
//!
//! This module handles the ASCII-armored format used for PGP data,
//! which wraps binary data in Base64 encoding with headers, footers,
//! and a CRC24 checksum.
//!
//! # Format
//!
//! Armored data looks like:
//! ```text
//! -----BEGIN PGP PUBLIC KEY BLOCK-----
//!
//! mDMEZ... (Base64 data)
//! =XXXX (CRC24 checksum)
//! -----END PGP PUBLIC KEY BLOCK-----
//! ```
//!
//! The armor type (e.g., "PGP PUBLIC KEY BLOCK") identifies the content type.

use std::sync::Arc;

use crate::error::{Error, Result};

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_decode_char(c: u8) -> Option<u8> {
    BASE64_CHARS.iter().position(|&x| x == c).map(|p| p as u8)
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let input: Vec<u8> = input
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace())
        .collect();

    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;

    for &byte in &input {
        if byte == b'=' {
            break;
        }
        let value = base64_decode_char(byte)
            .ok_or_else(|| Error::Base64Error(format!("Invalid character: {}", byte as char)))?;

        buffer = (buffer << 6) | (value as u32);
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

fn crc24(data: &[u8]) -> u32 {
    const CRC24_INIT: u32 = 0xB704CE;
    const CRC24_POLY: u32 = 0x1864CFB;

    let mut crc = CRC24_INIT;
    for &byte in data {
        crc ^= (byte as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= CRC24_POLY;
            }
        }
    }
    crc & 0xFFFFFF
}

/// The result of decoding ASCII-armored PGP data.
///
/// Contains the decoded binary data and the armor type identifier.
pub struct ArmorResult {
    /// The decoded binary PGP packet data.
    pub bytes: Arc<[u8]>,
    /// The armor type (e.g., "PGP PUBLIC KEY BLOCK", "PGP MESSAGE").
    pub armor_type: Arc<str>,
}

/// Decodes ASCII-armored PGP data into binary.
///
/// This function parses the armor format, extracts the Base64-encoded body,
/// decodes it, and validates the CRC24 checksum if present.
///
/// # Arguments
///
/// * `input` - ASCII-armored PGP data
///
/// # Errors
///
/// Returns `Error::InvalidArmor` if:
/// - Missing `-----BEGIN ... -----` header
/// - Missing `-----END ... -----` footer
/// - Empty body
///
/// Returns `Error::Base64Error` if the Base64 data contains invalid characters.
///
/// Returns `Error::ChecksumMismatch` if the CRC24 checksum doesn't match.
///
/// # Example
///
/// ```ignore
/// use gpg_inspector_lib::armor::decode_armor;
///
/// let armored = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----
///
/// mDMEZ...
/// =XXXX
/// -----END PGP PUBLIC KEY BLOCK-----"#;
///
/// let result = decode_armor(armored)?;
/// println!("Type: {}", result.armor_type);
/// println!("Size: {} bytes", result.bytes.len());
/// ```
pub fn decode_armor(input: &str) -> Result<ArmorResult> {
    let lines: Vec<&str> = input.lines().collect();
    let (bytes, armor_type, _next) = decode_block(&lines, 0)?;

    Ok(ArmorResult {
        bytes: bytes.into(),
        armor_type: armor_type.into(),
    })
}

/// Decodes the first armor block found at or after line index `from`.
///
/// Returns the decoded bytes, the armor type, and the line index just
/// past the block's END footer.
fn decode_block(lines: &[&str], from: usize) -> Result<(Vec<u8>, String, usize)> {
    let header_idx = lines[from..]
        .iter()
        .position(|line| line.starts_with("-----BEGIN ") && line.ends_with("-----"))
        .map(|p| p + from)
        .ok_or_else(|| Error::InvalidArmor("Missing BEGIN header".into()))?;

    let header_line = lines[header_idx];
    let armor_type = header_line
        .strip_prefix("-----BEGIN ")
        .and_then(|s| s.strip_suffix("-----"))
        .ok_or_else(|| Error::InvalidArmor("Invalid BEGIN header format".into()))?
        .to_string();

    let end_marker = format!("-----END {}-----", armor_type);
    let footer_idx = lines[header_idx..]
        .iter()
        .position(|line| *line == end_marker)
        .map(|p| p + header_idx)
        .ok_or_else(|| Error::InvalidArmor("Missing END header".into()))?;

    let mut body_start = header_idx + 1;
    while body_start < footer_idx {
        let line = lines[body_start];
        if line.is_empty() || line.contains(':') {
            body_start += 1;
        } else {
            break;
        }
    }

    let body_lines: Vec<&str> = lines[body_start..footer_idx]
        .iter()
        .copied()
        .filter(|line| !line.is_empty())
        .collect();

    if body_lines.is_empty() {
        return Err(Error::InvalidArmor("Empty body".into()));
    }

    let checksum_line = body_lines
        .last()
        .filter(|line| line.starts_with('='))
        .copied();

    let data_lines = if checksum_line.is_some() {
        &body_lines[..body_lines.len() - 1]
    } else {
        &body_lines[..]
    };

    let base64_data: String = data_lines.join("");
    let bytes = base64_decode(&base64_data)?;

    if let Some(checksum_str) = checksum_line {
        let checksum_b64 = &checksum_str[1..];
        let checksum_bytes = base64_decode(checksum_b64)?;
        if checksum_bytes.len() >= 3 {
            let expected = ((checksum_bytes[0] as u32) << 16)
                | ((checksum_bytes[1] as u32) << 8)
                | (checksum_bytes[2] as u32);
            let actual = crc24(&bytes);
            if expected != actual {
                return Err(Error::ChecksumMismatch { expected, actual });
            }
        }
    }

    Ok((bytes, armor_type, footer_idx + 1))
}

/// One decoded armor block within a [`MultiArmorResult`].
pub struct ArmorBlock {
    /// The armor type (e.g., "PGP PUBLIC KEY BLOCK", "PGP SIGNATURE").
    pub armor_type: Arc<str>,
    /// Byte range of this block's decoded data within
    /// [`MultiArmorResult::bytes`].
    pub range: (usize, usize),
}

/// The result of decoding input that may contain several armor blocks
/// and/or a cleartext signed message.
pub struct MultiArmorResult {
    /// All blocks' decoded binary data, concatenated in input order, so
    /// that packet byte spans share a single address space.
    pub bytes: Arc<[u8]>,
    /// The decoded blocks, in input order, with their byte ranges.
    pub blocks: Vec<ArmorBlock>,
    /// The dash-unescaped cleartext, if the input contained a
    /// `-----BEGIN PGP SIGNED MESSAGE-----` section.
    pub cleartext: Option<Arc<str>>,
}

const CLEARTEXT_HEADER: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const SIGNATURE_HEADER: &str = "-----BEGIN PGP SIGNATURE-----";

/// Decodes ASCII-armored PGP data that may contain multiple armor blocks.
///
/// A strict superset of [`decode_armor`]: every `-----BEGIN ... -----`
/// block in the input is decoded and the binary data concatenated (with
/// per-block ranges in [`MultiArmorResult::blocks`]). Cleartext signed
/// messages (`-----BEGIN PGP SIGNED MESSAGE-----`) are also handled: the
/// dash-escaped cleartext is captured and the trailing signature block is
/// decoded normally.
///
/// # Errors
///
/// Returns `Error::InvalidArmor` if no armor block is found, a block is
/// malformed, or a cleartext section has no trailing signature block.
/// Base64 and CRC24 checksum errors propagate per block.
pub fn decode_armor_multi(input: &str) -> Result<MultiArmorResult> {
    let lines: Vec<&str> = input.lines().collect();

    let mut bytes: Vec<u8> = Vec::new();
    let mut blocks: Vec<ArmorBlock> = Vec::new();
    let mut cleartext: Option<Arc<str>> = None;
    let mut idx = 0;

    while let Some(begin_rel) = lines[idx..]
        .iter()
        .position(|line| line.starts_with("-----BEGIN ") && line.ends_with("-----"))
    {
        let begin_idx = idx + begin_rel;

        if lines[begin_idx] == CLEARTEXT_HEADER {
            let (text, sig_idx) = read_cleartext(&lines, begin_idx + 1)?;
            if cleartext.is_none() {
                cleartext = Some(text.into());
            }
            // Continue at the signature header; it decodes as a normal block
            idx = sig_idx;
            continue;
        }

        let (block_bytes, armor_type, next) = decode_block(&lines, begin_idx)?;
        let start = bytes.len();
        bytes.extend_from_slice(&block_bytes);
        blocks.push(ArmorBlock {
            armor_type: armor_type.into(),
            range: (start, bytes.len()),
        });
        idx = next;
    }

    if blocks.is_empty() {
        return Err(Error::InvalidArmor("Missing BEGIN header".into()));
    }

    Ok(MultiArmorResult {
        bytes: bytes.into(),
        blocks,
        cleartext,
    })
}

/// Reads a cleartext signed message body starting just after its BEGIN
/// line. Skips `Hash:` armor headers, collects dash-unescaped text until
/// the signature block, and returns the text plus the line index of the
/// `-----BEGIN PGP SIGNATURE-----` header.
fn read_cleartext(lines: &[&str], mut idx: usize) -> Result<(String, usize)> {
    // Armor headers (e.g. "Hash: SHA256") end at the first empty line
    while idx < lines.len() && !lines[idx].is_empty() {
        idx += 1;
    }
    if idx < lines.len() {
        idx += 1; // skip the blank separator line
    }

    let mut text_lines: Vec<&str> = Vec::new();
    while idx < lines.len() {
        let line = lines[idx];
        if line == SIGNATURE_HEADER {
            return Ok((text_lines.join("\n"), idx));
        }
        text_lines.push(line.strip_prefix("- ").unwrap_or(line));
        idx += 1;
    }

    Err(Error::InvalidArmor(
        "Cleartext signed message missing signature block".into(),
    ))
}

/// Returns `true` if `bytes` looks like raw (unarmored) binary PGP data.
///
/// Every OpenPGP packet stream begins with a tag octet whose high bit is
/// set (RFC 4880 §4.2), while ASCII-armored input always begins with
/// printable ASCII, so testing the first byte's high bit is a reliable
/// discriminator.
pub fn looks_binary(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|&b| b & 0x80 != 0)
}
