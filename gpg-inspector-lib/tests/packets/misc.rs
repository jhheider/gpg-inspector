//! Miscellaneous packet tests - Marker (10), SED (9), AEAD (20), Padding (21)

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

// =============================================================================
// Marker Packet (tag 10)
// =============================================================================

fn build_marker_packet(data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 10); // Tag 10 = Marker
    packet.push(data.len() as u8);
    packet.extend_from_slice(data);
    packet
}

#[test]
fn test_marker_valid() {
    let packet = build_marker_packet(b"PGP");

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::Marker);

    let marker_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Marker");
    assert!(marker_field.is_some());
    assert!(marker_field.unwrap().value.contains("valid"));
}

#[test]
fn test_marker_invalid_content() {
    let packet = build_marker_packet(b"XXX");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let marker_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Marker");
    assert!(marker_field.is_some());
    assert!(marker_field.unwrap().value.contains("Invalid"));
}

#[test]
fn test_marker_wrong_length() {
    let packet = build_marker_packet(b"PG");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let marker_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Marker");
    assert!(marker_field.is_some());
    assert!(marker_field.unwrap().value.contains("Invalid"));
}

// =============================================================================
// Symmetrically Encrypted Data Packet (tag 9)
// =============================================================================

fn build_sed_packet(encrypted_data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 9); // Tag 9 = Symmetrically Encrypted Data
    packet.push(encrypted_data.len() as u8);
    packet.extend_from_slice(encrypted_data);
    packet
}

#[test]
fn test_sed_basic() {
    let packet = build_sed_packet(&[0xAB, 0xCD, 0xEF, 0x12, 0x34]);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::SymmetricallyEncryptedData);
}

#[test]
fn test_sed_encrypted_data_field() {
    let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let packet = build_sed_packet(&data);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Encrypted Data");
    assert!(data_field.is_some());
    assert!(data_field.unwrap().value.contains("8 bytes"));
    assert!(data_field.unwrap().value.contains("legacy"));
}

#[test]
fn test_sed_empty() {
    let packet = build_sed_packet(&[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::SymmetricallyEncryptedData);
}

// =============================================================================
// AEAD Encrypted Data Packet (tag 20)
// =============================================================================

fn build_aead_packet(cipher: u8, aead: u8, chunk_size: u8, iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 20); // Tag 20 = AEAD Encrypted Data

    let body_len = 1 + 1 + 1 + 1 + iv.len() + data.len();
    packet.push(body_len as u8);

    packet.push(1); // Version 1
    packet.push(cipher);
    packet.push(aead);
    packet.push(chunk_size);
    packet.extend_from_slice(iv);
    packet.extend_from_slice(data);

    packet
}

#[test]
fn test_aead_eax() {
    let iv = [0u8; 16]; // EAX uses 16-byte IV
    let packet = build_aead_packet(9, 1, 10, &iv, &[0xAB, 0xCD]);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::AeadEncryptedData);

    let aead_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "AEAD Algorithm");
    assert!(aead_field.is_some());
    assert!(aead_field.unwrap().value.contains("EAX"));
}

#[test]
fn test_aead_ocb() {
    let iv = [0u8; 15]; // OCB uses 15-byte IV
    let packet = build_aead_packet(9, 2, 10, &iv, &[0xAB, 0xCD]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let aead_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "AEAD Algorithm");
    assert!(aead_field.is_some());
    assert!(aead_field.unwrap().value.contains("OCB"));
}

#[test]
fn test_aead_gcm() {
    let iv = [0u8; 12]; // GCM uses 12-byte IV
    let packet = build_aead_packet(9, 3, 10, &iv, &[0xAB, 0xCD]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let aead_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "AEAD Algorithm");
    assert!(aead_field.is_some());
    assert!(aead_field.unwrap().value.contains("GCM"));
}

#[test]
fn test_aead_cipher_algorithm() {
    let iv = [0u8; 16];
    let packet = build_aead_packet(9, 1, 10, &iv, &[0xAB, 0xCD]); // AES-256

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let cipher_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Cipher Algorithm");
    assert!(cipher_field.is_some());
    assert!(cipher_field.unwrap().value.contains("AES-256"));
}

#[test]
fn test_aead_chunk_size() {
    let iv = [0u8; 16];
    let packet = build_aead_packet(9, 1, 10, &iv, &[]); // chunk = 2^16 = 65536

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let chunk_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Chunk Size");
    assert!(chunk_field.is_some());
    assert!(chunk_field.unwrap().value.contains("65536"));
}

// =============================================================================
// Padding Packet (tag 21)
// =============================================================================

fn build_padding_packet(padding: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 21); // Tag 21 = Padding
    packet.push(padding.len() as u8);
    packet.extend_from_slice(padding);
    packet
}

#[test]
fn test_padding_basic() {
    let packet = build_padding_packet(&[0x00; 16]);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::Padding);
}

#[test]
fn test_padding_size_displayed() {
    let packet = build_padding_packet(&[0x00; 32]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let padding_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Padding");
    assert!(padding_field.is_some());
    assert!(padding_field.unwrap().value.contains("32 bytes"));
}

#[test]
fn test_padding_empty() {
    let packet = build_padding_packet(&[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::Padding);
}

#[test]
fn test_padding_random_content() {
    let packet = build_padding_packet(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let padding_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Padding");
    assert!(padding_field.is_some());
    assert!(padding_field.unwrap().value.contains("6 bytes"));
}

// =============================================================================
// AEAD Unknown Algorithm Tests
// =============================================================================

#[test]
fn test_aead_unknown_algorithm() {
    // Unknown AEAD algorithm (99) should default to 16-byte IV
    let iv = [0u8; 16];
    let packet = build_aead_packet(9, 99, 10, &iv, &[0xAB, 0xCD]); // Unknown AEAD algo

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::AeadEncryptedData);

    let aead_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "AEAD Algorithm");
    assert!(aead_field.is_some());
    // Should show unknown algorithm with ID
    assert!(aead_field.unwrap().value.contains("99"));
}

#[test]
fn test_aead_with_encrypted_data() {
    let iv = [0u8; 16];
    let encrypted_data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let packet = build_aead_packet(9, 1, 10, &iv, &encrypted_data);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Encrypted Data");
    assert!(data_field.is_some());
    assert!(data_field.unwrap().value.contains("8 bytes"));
    assert!(data_field.unwrap().value.contains("auth tags"));
}

#[test]
fn test_aead_empty_data() {
    let iv = [0u8; 16];
    let packet = build_aead_packet(9, 1, 10, &iv, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    // Empty data should not create an Encrypted Data field
    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Encrypted Data");
    assert!(data_field.is_none());
}

#[test]
fn test_aead_version_field() {
    let iv = [0u8; 16];
    let packet = build_aead_packet(9, 1, 10, &iv, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let version_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Version");
    assert!(version_field.is_some());
    assert!(version_field.unwrap().value.contains('1'));
}

#[test]
fn test_aead_iv_displayed() {
    let iv = [
        0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
        0x55,
    ];
    let packet = build_aead_packet(9, 1, 10, &iv, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let iv_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "IV/Nonce");
    assert!(iv_field.is_some());
    assert!(iv_field.unwrap().value.contains("ABCDEF"));
}
