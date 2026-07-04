//! Literal Data packet parsing (tag 11).
//!
//! Literal Data packets contain the actual message content that is not
//! to be further interpreted. This includes the data format, optional
//! filename, modification date, and the literal data itself.
//!
//! RFC 4880 Section 5.9

use chrono::{DateTime, TimeZone, Utc};

use crate::error::Result;
use crate::stream::ByteStream;

use super::Field;

/// Data format indicator for Literal Data packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFormat {
    /// Binary data ('b', 0x62).
    Binary,
    /// Text data ('t', 0x74) - may need line ending conversion.
    Text,
    /// UTF-8 text ('u', 0x75) - text known to be UTF-8.
    Utf8,
    /// MIME format ('m', 0x6D) - RFC 9580.
    Mime,
    /// Local mode ('l', 0x6C) - deprecated.
    Local,
    /// Unknown format.
    Unknown(u8),
}

impl DataFormat {
    fn from_u8(b: u8) -> Self {
        match b {
            0x62 => DataFormat::Binary,
            0x74 => DataFormat::Text,
            0x75 => DataFormat::Utf8,
            0x6D => DataFormat::Mime,
            0x6C => DataFormat::Local,
            _ => DataFormat::Unknown(b),
        }
    }

    fn description(&self) -> String {
        match self {
            DataFormat::Binary => "b (Binary)".to_string(),
            DataFormat::Text => "t (Text)".to_string(),
            DataFormat::Utf8 => "u (UTF-8 text)".to_string(),
            DataFormat::Mime => "m (MIME)".to_string(),
            DataFormat::Local => "l (Local - deprecated)".to_string(),
            DataFormat::Unknown(b) => format!("{:#04x} (Unknown)", b),
        }
    }
}

/// Parsed Literal Data packet.
#[derive(Debug, Clone)]
pub struct LiteralDataPacket {
    /// Data format indicator.
    pub format: DataFormat,
    /// Filename (may be empty).
    pub filename: String,
    /// Modification date (Unix timestamp, 0 = unspecified).
    pub date: u32,
    /// The literal data content.
    pub data: Vec<u8>,
}

/// Parses a Literal Data packet body.
pub fn parse_literal_data(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<LiteralDataPacket> {
    let format_start = body_offset + stream.pos();
    let format_byte = stream.octet()?;
    let format = DataFormat::from_u8(format_byte);
    fields.push(Field::field(
        "Format",
        format.description(),
        (format_start, format_start + 1),
    ));

    let filename_len_start = body_offset + stream.pos();
    let filename_len = stream.octet()? as usize;
    fields.push(Field::field(
        "Filename Length",
        filename_len.to_string(),
        (filename_len_start, filename_len_start + 1),
    ));

    let filename = if filename_len > 0 {
        let filename_start = body_offset + stream.pos();
        let filename_bytes = stream.bytes(filename_len)?;
        let filename_str = String::from_utf8_lossy(&filename_bytes).to_string();

        // Check for special "_CONSOLE" name
        let display_name = if filename_str == "_CONSOLE" {
            format!("{} (for your eyes only)", filename_str)
        } else {
            filename_str.clone()
        };

        fields.push(Field::field(
            "Filename",
            display_name,
            (filename_start, filename_start + filename_len),
        ));
        filename_str
    } else {
        String::new()
    };

    let date_start = body_offset + stream.pos();
    let date = stream.uint32()?;
    let date_display = if date == 0 {
        "0 (unspecified)".to_string()
    } else {
        let datetime: DateTime<Utc> = Utc.timestamp_opt(date as i64, 0).unwrap();
        datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    };
    fields.push(Field::field(
        "Date",
        date_display,
        (date_start, date_start + 4),
    ));

    let data_start = body_offset + stream.pos();
    let data = stream.rest();
    let data_end = body_offset + stream.pos();

    if !data.is_empty() {
        // Show a preview for text formats, byte count for binary
        let data_desc = match format {
            DataFormat::Text | DataFormat::Utf8 => {
                let preview = String::from_utf8_lossy(&data);
                if preview.len() > 64 {
                    format!(
                        "{} bytes: \"{}...\"",
                        data.len(),
                        &preview[..60].replace('\n', "\\n")
                    )
                } else {
                    format!("{} bytes: \"{}\"", data.len(), preview.replace('\n', "\\n"))
                }
            }
            _ => format!("{} bytes", data.len()),
        };

        fields.push(Field::field("Data", data_desc, (data_start, data_end)));
    }

    Ok(LiteralDataPacket {
        format,
        filename,
        date,
        data,
    })
}
