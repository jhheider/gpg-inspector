//! Modification Detection Code packet tests - Tag 19

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

fn build_mdc_packet(hash: &[u8; 20]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xD3); // New format, tag 19
    packet.push(20); // Always 20 bytes

    packet.extend_from_slice(hash);

    packet
}

#[test]
fn test_mdc_packet() {
    let hash: [u8; 20] = [
        0x2F, 0xD4, 0xE1, 0xC6, 0x7A, 0x2D, 0x28, 0xFC, 0xED, 0x84, 0x9E, 0xE1, 0xBB, 0x76, 0xE7,
        0x39, 0x1B, 0x93, 0xEB, 0x12,
    ];
    let packet = build_mdc_packet(&hash);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::ModificationDetectionCode);
}

#[test]
fn test_mdc_hash_displayed() {
    let hash: [u8; 20] = [
        0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18,
        0x90, 0xAF, 0xD8, 0x07, 0x09,
    ];
    let packet = build_mdc_packet(&hash);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let hash_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "SHA-1 Hash");
    assert!(hash_field.is_some());

    // Verify hash is displayed in hex
    let hash_value = &hash_field.unwrap().value;
    assert!(hash_value.contains("DA39A3EE"));
}

#[test]
fn test_mdc_zero_hash() {
    let hash: [u8; 20] = [0u8; 20];
    let packet = build_mdc_packet(&hash);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::ModificationDetectionCode);
}

#[test]
fn test_mdc_all_ff_hash() {
    let hash: [u8; 20] = [0xFF; 20];
    let packet = build_mdc_packet(&hash);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let hash_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "SHA-1 Hash");
    assert!(hash_field.is_some());
    assert!(hash_field.unwrap().value.contains("FFFFFFFF"));
}
