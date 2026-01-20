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

pub struct ArmorResult {
    pub bytes: Arc<[u8]>,
    pub armor_type: Arc<str>,
}

pub fn decode_armor(input: &str) -> Result<ArmorResult> {
    let lines: Vec<&str> = input.lines().collect();

    let header_idx = lines
        .iter()
        .position(|line| line.starts_with("-----BEGIN ") && line.ends_with("-----"))
        .ok_or_else(|| Error::InvalidArmor("Missing BEGIN header".into()))?;

    let header_line = lines[header_idx];
    let armor_type = header_line
        .strip_prefix("-----BEGIN ")
        .and_then(|s| s.strip_suffix("-----"))
        .ok_or_else(|| Error::InvalidArmor("Invalid BEGIN header format".into()))?
        .to_string();

    let end_marker = format!("-----END {}-----", armor_type);
    let footer_idx = lines
        .iter()
        .position(|line| *line == end_marker)
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
            let expected =
                ((checksum_bytes[0] as u32) << 16)
                    | ((checksum_bytes[1] as u32) << 8)
                    | (checksum_bytes[2] as u32);
            let actual = crc24(&bytes);
            if expected != actual {
                return Err(Error::ChecksumMismatch { expected, actual });
            }
        }
    }

    Ok(ArmorResult {
        bytes: bytes.into(),
        armor_type: armor_type.into(),
    })
}
