//! Packet format tests - old/new format headers and length encoding

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

// ============================================================================
// Old Format Packet Tests
// ============================================================================

fn build_old_format_packet(tag: u8, len_type: u8, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    // Old format: 0x80 | (tag << 2) | len_type
    packet.push(0x80 | (tag << 2) | len_type);

    match len_type {
        0 => packet.push(data.len() as u8),
        1 => packet.extend_from_slice(&(data.len() as u16).to_be_bytes()),
        2 => packet.extend_from_slice(&(data.len() as u32).to_be_bytes()),
        3 => {} // Indeterminate length
        _ => panic!("Invalid len_type"),
    }

    packet.extend_from_slice(data);
    packet
}

#[test]
fn test_old_format_one_byte_length() {
    let data = b"Test User ID";
    let packet = build_old_format_packet(13, 0, data); // Tag 13 = User ID, len_type 0

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    assert_eq!(result.unwrap()[0].tag, PacketTag::UserId);
}

#[test]
fn test_old_format_two_byte_length() {
    let data = b"Test User ID";
    let packet = build_old_format_packet(13, 1, data); // len_type 1 = 2-byte length

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_old_format_four_byte_length() {
    let data = b"Test User ID";
    let packet = build_old_format_packet(13, 2, data); // len_type 2 = 4-byte length

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_old_format_indeterminate_length() {
    let data = b"Test User ID";
    let packet = build_old_format_packet(13, 3, data); // len_type 3 = indeterminate

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

// ============================================================================
// New Format Length Tests
// ============================================================================

#[test]
fn test_new_format_two_byte_length() {
    // Length 192-8383 uses two bytes
    let mut packet = Vec::new();
    packet.push(0xC0 | 13); // User ID
    // Two-byte length for 200 bytes: (200 - 192) = 8, first byte = 192 + (8 >> 8) = 192, second = 8
    // Actually: len = ((first - 192) << 8) + second + 192
    // For 200: 200 = ((192 - 192) << 8) + 8 + 192 = 8 + 192 = 200
    packet.push(192);
    packet.push(8);
    packet.extend(vec![b'A'; 200]);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_new_format_five_byte_length() {
    // Length >= some threshold uses 0xFF + 4-byte length
    let mut packet = Vec::new();
    packet.push(0xC0 | 13); // User ID
    packet.push(0xFF);
    packet.extend_from_slice(&100u32.to_be_bytes());
    packet.extend(vec![b'B'; 100]);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_new_format_partial_length() {
    // Partial body length: first byte 224-254 means 2^(first & 0x1F) bytes
    let mut packet = Vec::new();
    packet.push(0xC0 | 13); // User ID
    packet.push(224); // 2^(224 & 0x1F) = 2^0 = 1 byte
    packet.push(b'X');

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

// ============================================================================
// Unknown Packet Type Tests
// ============================================================================

#[test]
fn test_unknown_packet_type() {
    let mut packet = Vec::new();
    packet.push(0xC0 | 15); // Tag 15 is not defined (between 14 and 17)
    packet.push(5);
    packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    assert_eq!(result.unwrap()[0].tag, PacketTag::Unknown(15));
}

#[test]
fn test_reserved_packet_type() {
    let mut packet = Vec::new();
    packet.push(0xC0 | 0); // Tag 0 = Reserved
    packet.push(3);
    packet.extend_from_slice(&[0x01, 0x02, 0x03]);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    assert_eq!(result.unwrap()[0].tag, PacketTag::Reserved);
}

// ============================================================================
// Error Cases
// ============================================================================

#[test]
fn test_invalid_packet_header() {
    // First byte must have bit 7 set
    let packet = vec![0x00, 0x01, 0x02];

    let result = parse_bytes(packet);
    assert!(result.is_err());
}

#[test]
fn test_empty_input() {
    let result = parse_bytes(Vec::new());
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}
