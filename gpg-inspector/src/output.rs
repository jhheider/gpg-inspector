use crate::ui::colors::{ColorTracker, PALETTE_RGB};
use gpg_inspector_lib::Packet;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

fn rgb_color(r: u8, g: u8, b: u8) -> String {
    format!("\x1b[38;2;{};{};{}m", r, g, b)
}

fn palette_color(index: u8) -> String {
    let (r, g, b) = PALETTE_RGB[index as usize % PALETTE_RGB.len()];
    rgb_color(r, g, b)
}

pub fn output_txt(packets: &[Packet], bytes: &[u8], use_color: bool) -> String {
    let mut output = String::new();
    let color_tracker = ColorTracker::compute_from_packets(packets, bytes.len());

    // Track field colors for display
    let mut field_color_index: u8 = 0;

    for packet in packets {
        if use_color {
            output.push_str(&format!(
                "{}=== {} Packet [0x{:04X}-0x{:04X}] ==={}\n",
                BOLD, packet.tag, packet.start, packet.end, RESET
            ));
        } else {
            output.push_str(&format!(
                "=== {} Packet [0x{:04X}-0x{:04X}] ===\n",
                packet.tag, packet.start, packet.end
            ));
        }

        // Skip the first field (packet header) as it's represented in the header line
        for field in packet.fields.iter().skip(1) {
            let indent = "  ".repeat(field.indent as usize);

            // Get color for this field (only non-header fields get colors)
            let field_color = if field.indent > 0 {
                let c = field_color_index;
                field_color_index = (field_color_index + 1) % 12;
                Some(c)
            } else {
                None
            };

            if use_color {
                let color = field_color.map(palette_color).unwrap_or_default();
                output.push_str(&format!(
                    "{}{}{}: {}{} {}[0x{:04X}-0x{:04X}]{}\n",
                    indent,
                    color,
                    field.name,
                    field.value,
                    RESET,
                    DIM,
                    field.span.0,
                    field.span.1,
                    RESET
                ));
            } else {
                output.push_str(&format!(
                    "{}{}: {} [0x{:04X}-0x{:04X}]\n",
                    indent, field.name, field.value, field.span.0, field.span.1
                ));
            }
        }

        output.push('\n');
    }

    if use_color {
        output.push_str(&format!("{}--- Hex Dump ---{}\n", BOLD, RESET));
    } else {
        output.push_str("--- Hex Dump ---\n");
    }
    output.push_str(&format_hex_dump(&color_tracker, bytes, use_color));

    output
}

fn format_hex_dump(color_tracker: &ColorTracker, bytes: &[u8], use_color: bool) -> String {
    let mut output = String::new();

    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = i * 16;

        // Address
        if use_color {
            output.push_str(&format!("{}{:08x}{} ", DIM, offset, RESET));
        } else {
            output.push_str(&format!("{:08x}  ", offset));
        }

        // Hex bytes (two groups of 8)
        let mut last_color: Option<u8> = None;
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                output.push(' ');
            }

            if use_color {
                let color = color_tracker.get_color(offset + j);
                if color != last_color {
                    if last_color.is_some() {
                        output.push_str(RESET);
                    }
                    if let Some(c) = color {
                        output.push_str(&palette_color(c));
                    }
                    last_color = color;
                }
            }

            output.push_str(&format!("{:02x} ", byte));
        }

        if use_color && last_color.is_some() {
            output.push_str(RESET);
        }

        // Padding for incomplete lines
        if chunk.len() < 16 {
            let missing = 16 - chunk.len();
            for j in 0..missing {
                if chunk.len() + j == 8 {
                    output.push(' ');
                }
                output.push_str("   ");
            }
        }

        // ASCII representation
        if use_color {
            output.push_str(&format!(" {}|", DIM));
        } else {
            output.push_str(" |");
        }

        last_color = None;
        for (j, byte) in chunk.iter().enumerate() {
            if use_color {
                let color = color_tracker.get_color(offset + j);
                if color != last_color {
                    if last_color.is_some() {
                        output.push_str(RESET);
                        output.push_str(DIM);
                    }
                    if let Some(c) = color {
                        output.push_str(RESET);
                        output.push_str(&palette_color(c));
                    }
                    last_color = color;
                }
            }

            let c = if *byte >= 0x20 && *byte < 0x7F {
                *byte as char
            } else {
                '.'
            };
            output.push(c);
        }

        if use_color {
            output.push_str(RESET);
            output.push_str(&format!("{}|{}\n", DIM, RESET));
        } else {
            output.push_str("|\n");
        }
    }

    output
}

#[cfg(feature = "serde")]
pub fn output_json(packets: &[Packet], bytes: &[u8]) -> String {
    use serde::Serialize;

    #[derive(Serialize)]
    struct JsonOutput {
        packets: Vec<JsonPacket>,
        bytes: String,
    }

    #[derive(Serialize)]
    struct JsonPacket {
        tag: String,
        range: JsonRange,
        fields: Vec<JsonField>,
    }

    #[derive(Serialize)]
    struct JsonRange {
        start: usize,
        end: usize,
    }

    #[derive(Serialize)]
    struct JsonField {
        name: String,
        value: String,
        indent: u8,
        range: JsonRange,
    }

    let json_packets: Vec<JsonPacket> = packets
        .iter()
        .map(|p| JsonPacket {
            tag: format!("{}", p.tag),
            range: JsonRange {
                start: p.start,
                end: p.end,
            },
            fields: p
                .fields
                .iter()
                .skip(1) // Skip packet header field
                .map(|f| JsonField {
                    name: f.name.to_string(),
                    value: f.value.to_string(),
                    indent: f.indent,
                    range: JsonRange {
                        start: f.span.0,
                        end: f.span.1,
                    },
                })
                .collect(),
        })
        .collect();

    let output = JsonOutput {
        packets: json_packets,
        bytes: hex::encode(bytes),
    };

    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpg_inspector_lib::Field;
    use gpg_inspector_lib::packet::PacketBody;
    use gpg_inspector_lib::packet::tags::PacketTag;

    fn make_test_packet() -> Packet {
        Packet {
            start: 0,
            end: 10,
            tag: PacketTag::UserId,
            body: PacketBody::Unknown(vec![]),
            fields: vec![
                Field::packet("Packet: User ID", "8 bytes", (0, 2)),
                Field::field("User ID", "test", (2, 6)),
                Field::subfield("Domain", "example.com", (6, 10)),
            ],
        }
    }

    #[test]
    fn test_rgb_color() {
        let result = rgb_color(255, 128, 0);
        assert_eq!(result, "\x1b[38;2;255;128;0m");
    }

    #[test]
    fn test_palette_color() {
        // First color in palette is coral red (0xFF, 0x6B, 0x6B)
        let result = palette_color(0);
        assert_eq!(result, "\x1b[38;2;255;107;107m");

        // Test wrapping (palette has 12 colors)
        let result_wrapped = palette_color(12);
        assert_eq!(result_wrapped, palette_color(0));
    }

    #[test]
    fn test_color_tracker_from_packets() {
        let packet = make_test_packet();
        let packets = vec![packet];
        let tracker = ColorTracker::compute_from_packets(&packets, 10);

        // Byte 0-1 are header (no color)
        assert_eq!(tracker.get_color(0), None);
        assert_eq!(tracker.get_color(1), None);

        // Bytes 2-5 are field with color 0
        assert_eq!(tracker.get_color(2), Some(0));
        assert_eq!(tracker.get_color(5), Some(0));

        // Bytes 6-9 are subfield with color 1
        assert_eq!(tracker.get_color(6), Some(1));
        assert_eq!(tracker.get_color(9), Some(1));
    }

    #[test]
    fn test_get_byte_color_outside_range() {
        let packet = make_test_packet();
        let packets = vec![packet];
        let tracker = ColorTracker::compute_from_packets(&packets, 10);

        // Byte outside tracked range
        assert_eq!(tracker.get_color(100), None);
    }

    #[test]
    fn test_output_txt_no_color() {
        let packet = make_test_packet();
        let bytes = vec![0xc6, 0x08, 0x74, 0x65, 0x73, 0x74, 0x40, 0x65, 0x78, 0x2e];

        let result = output_txt(&[packet], &bytes, false);

        // Check packet header
        assert!(result.contains("=== User ID Packet [0x0000-0x000A] ==="));

        // Check fields (with indentation)
        assert!(result.contains("  User ID: test [0x0002-0x0006]"));
        assert!(result.contains("    Domain: example.com [0x0006-0x000A]"));

        // Check hex dump header
        assert!(result.contains("--- Hex Dump ---"));

        // Verify no ANSI codes
        assert!(!result.contains("\x1b["));
    }

    #[test]
    fn test_output_txt_with_color() {
        let packet = make_test_packet();
        let bytes = vec![0xc6, 0x08, 0x74, 0x65, 0x73, 0x74, 0x40, 0x65, 0x78, 0x2e];

        let result = output_txt(&[packet], &bytes, true);

        // Check for ANSI codes
        assert!(result.contains(BOLD));
        assert!(result.contains(RESET));
        assert!(result.contains(DIM));

        // Check packet header has bold
        assert!(result.contains(&format!("{}=== User ID Packet", BOLD)));

        // Check field has color
        assert!(result.contains("\x1b[38;2;")); // RGB color code
    }

    #[test]
    fn test_output_txt_empty_packets() {
        let result = output_txt(&[], &[], false);
        assert!(result.contains("--- Hex Dump ---"));
    }

    #[test]
    fn test_hex_dump_full_line() {
        let bytes: Vec<u8> = (0..16).collect();
        let tracker = ColorTracker::new(16);
        let result = format_hex_dump(&tracker, &bytes, false);

        assert!(result.contains("00000000"));
        assert!(result.contains("00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f"));
        assert!(result.contains("|................|"));
    }

    #[test]
    fn test_hex_dump_partial_line() {
        let bytes: Vec<u8> = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
        let tracker = ColorTracker::new(5);
        let result = format_hex_dump(&tracker, &bytes, false);

        assert!(result.contains("00000000"));
        assert!(result.contains("48 65 6c 6c 6f"));
        assert!(result.contains("|Hello|"));
    }

    #[test]
    fn test_hex_dump_multiple_lines() {
        let bytes: Vec<u8> = (0..32).collect();
        let tracker = ColorTracker::new(32);
        let result = format_hex_dump(&tracker, &bytes, false);

        assert!(result.contains("00000000"));
        assert!(result.contains("00000010"));
    }

    #[test]
    fn test_hex_dump_non_printable() {
        let bytes: Vec<u8> = vec![0x00, 0x1F, 0x7F, 0xFF];
        let tracker = ColorTracker::new(4);
        let result = format_hex_dump(&tracker, &bytes, false);

        // Non-printable characters should be replaced with '.'
        assert!(result.contains("|....|"));
    }

    #[test]
    fn test_hex_dump_with_color() {
        let packet = make_test_packet();
        let bytes = vec![0xc6, 0x08, 0x74, 0x65, 0x73, 0x74, 0x40, 0x65, 0x78, 0x2e];
        let tracker = ColorTracker::compute_from_packets(&[packet], bytes.len());

        let result = format_hex_dump(&tracker, &bytes, true);

        // Check for ANSI codes
        assert!(result.contains(DIM)); // Address is dim
        assert!(result.contains(RESET)); // Reset codes present
        assert!(result.contains("\x1b[38;2;")); // Color codes for bytes
    }

    #[test]
    fn test_hex_dump_color_transitions() {
        // Create a packet where colors change mid-line
        let packet = Packet {
            start: 0,
            end: 16,
            tag: PacketTag::LiteralData,
            body: PacketBody::Unknown(vec![]),
            fields: vec![
                Field::packet("Packet", "16 bytes", (0, 2)),
                Field::field("Field1", "data", (0, 4)),
                Field::field("Field2", "data", (4, 8)),
                Field::field("Field3", "data", (8, 12)),
                Field::field("Field4", "data", (12, 16)),
            ],
        };

        let bytes: Vec<u8> = (0..16).collect();
        let tracker = ColorTracker::compute_from_packets(&[packet], bytes.len());
        let result = format_hex_dump(&tracker, &bytes, true);

        // Should have multiple color codes (one for each field transition)
        let color_count = result.matches("\x1b[38;2;").count();
        assert!(
            color_count >= 4,
            "Expected at least 4 color codes, got {}",
            color_count
        );
    }

    #[test]
    fn test_output_txt_field_without_color() {
        // Test packet header field (indent == 0)
        let packet = Packet {
            start: 0,
            end: 5,
            tag: PacketTag::UserId,
            body: PacketBody::Unknown(vec![]),
            fields: vec![
                Field::packet("Packet: User ID", "3 bytes", (0, 2)),
                Field::field("Note", "test", (2, 5)),
            ],
        };

        let bytes = vec![0xc6, 0x03, 0x61, 0x62, 0x63];
        let result = output_txt(&[packet], &bytes, true);

        // Field should still be in output
        assert!(result.contains("Note: test"));
    }

    #[test]
    fn test_output_txt_non_first_field_with_indent_zero() {
        // Test a field after the packet header that has indent 0 (unusual but tests the branch)
        let packet = Packet {
            start: 0,
            end: 10,
            tag: PacketTag::UserId,
            body: PacketBody::Unknown(vec![]),
            fields: vec![
                Field::packet("Packet: User ID", "8 bytes", (0, 2)),
                Field::new("Section", "data", 0, (2, 6)), // indent 0 non-header field
                Field::field("Value", "test", (6, 10)),
            ],
        };

        let bytes = vec![0xc6, 0x08, 0x74, 0x65, 0x73, 0x74, 0x40, 0x65, 0x78, 0x2e];
        let result = output_txt(&[packet], &bytes, true);

        // Both fields should be in output
        assert!(result.contains("Section: data"));
        assert!(result.contains("Value: test"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_output_json_structure() {
        let packet = Packet {
            start: 0,
            end: 10,
            tag: PacketTag::UserId,
            body: PacketBody::Unknown(vec![]),
            fields: vec![
                Field::packet("Packet: User ID", "5 bytes", (0, 2)),
                Field::field("User ID", "test@example.com", (2, 10)),
            ],
        };

        let bytes = vec![0xc6, 0x05, 0x74, 0x65, 0x73, 0x74, 0x40, 0x65, 0x78, 0x2e];
        let json = output_json(&[packet], &bytes);

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("packets").is_some());
        assert!(parsed.get("bytes").is_some());

        let packets = parsed.get("packets").unwrap().as_array().unwrap();
        assert_eq!(packets.len(), 1);

        let first_packet = &packets[0];
        assert_eq!(
            first_packet.get("tag").unwrap().as_str().unwrap(),
            "User ID"
        );
    }
}
