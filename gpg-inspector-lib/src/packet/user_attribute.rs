//! User Attribute packet parsing (tag 17).
//!
//! User Attribute packets can store additional data about a key holder,
//! most commonly an image (photo ID). The packet contains one or more
//! subpackets, each with its own type and data.
//!
//! RFC 4880 Section 5.12

use crate::error::Result;
use crate::stream::ByteStream;

use super::Field;

/// Image encoding format in a User Attribute image subpacket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// JPEG image (format 1).
    Jpeg,
    /// Private/experimental format (100-110).
    Private(u8),
    /// Unknown format.
    Unknown(u8),
}

impl ImageFormat {
    fn from_u8(b: u8) -> Self {
        match b {
            1 => ImageFormat::Jpeg,
            100..=110 => ImageFormat::Private(b),
            _ => ImageFormat::Unknown(b),
        }
    }

    fn description(&self) -> String {
        match self {
            ImageFormat::Jpeg => "1 (JPEG)".to_string(),
            ImageFormat::Private(n) => format!("{} (Private/Experimental)", n),
            ImageFormat::Unknown(n) => format!("{} (Unknown)", n),
        }
    }
}

/// A subpacket within a User Attribute packet.
#[derive(Debug, Clone)]
pub enum UserAttributeSubpacket {
    /// Image subpacket (type 1).
    Image {
        /// Header version (typically 1).
        header_version: u8,
        /// Image encoding format.
        format: ImageFormat,
        /// Raw image data.
        image_data: Vec<u8>,
    },
    /// Unknown subpacket type.
    Unknown {
        /// Subpacket type ID.
        subpacket_type: u8,
        /// Raw subpacket data.
        data: Vec<u8>,
    },
}

/// Parsed User Attribute packet.
#[derive(Debug, Clone)]
pub struct UserAttributePacket {
    /// List of attribute subpackets.
    pub subpackets: Vec<UserAttributeSubpacket>,
}

/// Parses a User Attribute packet body.
pub fn parse_user_attribute(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<UserAttributePacket> {
    let mut subpackets = Vec::new();

    while !stream.is_empty() {
        let subpacket_start = body_offset + stream.pos();
        let (subpacket_len, _len_size) = parse_subpacket_length(stream)?;

        if subpacket_len == 0 {
            continue;
        }

        let _type_pos = body_offset + stream.pos();
        let subpacket_type = stream.octet()?;
        let data_len = subpacket_len - 1; // Subtract type byte

        let subpacket = match subpacket_type {
            1 => parse_image_subpacket(stream, fields, body_offset, data_len)?,
            100..=110 => {
                let data_start = body_offset + stream.pos();
                let data = stream.bytes(data_len)?;
                fields.push(Field::field(
                    "Private Subpacket",
                    format!("Type {}, {} bytes", subpacket_type, data.len()),
                    (subpacket_start, data_start + data_len),
                ));
                UserAttributeSubpacket::Unknown {
                    subpacket_type,
                    data,
                }
            }
            _ => {
                let data_start = body_offset + stream.pos();
                let data = stream.bytes(data_len)?;
                fields.push(Field::field(
                    "Unknown Subpacket",
                    format!("Type {}, {} bytes", subpacket_type, data.len()),
                    (subpacket_start, data_start + data_len),
                ));
                UserAttributeSubpacket::Unknown {
                    subpacket_type,
                    data,
                }
            }
        };

        subpackets.push(subpacket);
    }

    Ok(UserAttributePacket { subpackets })
}

/// Parses an image subpacket (type 1).
fn parse_image_subpacket(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
    data_len: usize,
) -> Result<UserAttributeSubpacket> {
    let header_start = body_offset + stream.pos();

    // Image header: 2 bytes (little-endian length), 1 byte version, 1 byte format
    // For v1 headers, total header length is 16 bytes (including the length field)
    let header_len_lo = stream.octet()? as u16;
    let header_len_hi = stream.octet()? as u16;
    let header_len = header_len_lo | (header_len_hi << 8);

    let header_version = stream.octet()?;

    fields.push(Field::field(
        "Image Subpacket",
        format!("Header v{}, {} bytes total", header_version, header_len),
        (header_start, header_start + 3),
    ));

    if header_version == 1 {
        let format_pos = body_offset + stream.pos();
        let format_byte = stream.octet()?;
        let format = ImageFormat::from_u8(format_byte);
        fields.push(Field::subfield(
            "Image Format",
            format.description(),
            (format_pos, format_pos + 1),
        ));

        // Skip remaining header bytes (12 reserved bytes for v1)
        let remaining_header = header_len as usize - 4; // Already read 4 bytes
        if remaining_header > 0 && stream.remaining() >= remaining_header {
            stream.skip(remaining_header)?;
        }

        // Rest is image data
        let image_start = body_offset + stream.pos();
        let image_bytes_available = data_len.saturating_sub(header_len as usize);
        let image_data = if image_bytes_available > 0 && stream.remaining() >= image_bytes_available
        {
            stream.bytes(image_bytes_available)?
        } else {
            stream.rest()
        };

        // Try to detect image type from magic bytes
        let detected_type = detect_image_type(&image_data);
        let image_desc = if let Some(detected) = detected_type {
            format!("{} bytes ({})", image_data.len(), detected)
        } else {
            format!("{} bytes", image_data.len())
        };

        fields.push(Field::subfield(
            "Image Data",
            image_desc,
            (image_start, image_start + image_data.len()),
        ));

        Ok(UserAttributeSubpacket::Image {
            header_version,
            format,
            image_data,
        })
    } else {
        // Unknown header version, store as raw data
        let data_start = body_offset + stream.pos();
        let remaining = data_len.saturating_sub(3); // Already read 3 bytes
        let data = if remaining > 0 {
            stream.bytes(remaining)?
        } else {
            Vec::new()
        };

        fields.push(Field::subfield(
            "Image Data",
            format!("{} bytes (unknown header v{})", data.len(), header_version),
            (data_start, data_start + data.len()),
        ));

        Ok(UserAttributeSubpacket::Image {
            header_version,
            format: ImageFormat::Unknown(0),
            image_data: data,
        })
    }
}

/// Parses a subpacket length (same format as signature subpackets).
fn parse_subpacket_length(stream: &mut ByteStream) -> Result<(usize, usize)> {
    let first = stream.octet()? as usize;
    if first < 192 {
        Ok((first, 1))
    } else if first < 255 {
        let second = stream.octet()? as usize;
        Ok((((first - 192) << 8) + second + 192, 2))
    } else {
        let len = stream.uint32()? as usize;
        Ok((len, 5))
    }
}

/// Attempts to detect image type from magic bytes.
fn detect_image_type(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }

    // JPEG: FF D8 FF
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("JPEG detected");
    }

    // PNG: 89 50 4E 47
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        return Some("PNG detected");
    }

    // GIF: 47 49 46 38
    if data.starts_with(&[0x47, 0x49, 0x46, 0x38]) {
        return Some("GIF detected");
    }

    // BMP: 42 4D
    if data.starts_with(&[0x42, 0x4D]) {
        return Some("BMP detected");
    }

    None
}
