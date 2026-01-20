//! Packet-level tests with raw byte data
//!
//! Tests for packet parsing using constructed byte sequences.

use gpg_inspector_lib::{parse_bytes, ColorTracker, Field};
use gpg_inspector_lib::packet::tags::PacketTag;

// ============================================================================
// PacketTag Tests
// ============================================================================

#[test]
fn test_packet_tag_from_u8_all_known() {
    assert_eq!(PacketTag::from_u8(0), PacketTag::Reserved);
    assert_eq!(PacketTag::from_u8(1), PacketTag::PublicKeyEncryptedSessionKey);
    assert_eq!(PacketTag::from_u8(2), PacketTag::Signature);
    assert_eq!(PacketTag::from_u8(3), PacketTag::SymmetricKeyEncryptedSessionKey);
    assert_eq!(PacketTag::from_u8(4), PacketTag::OnePassSignature);
    assert_eq!(PacketTag::from_u8(5), PacketTag::SecretKey);
    assert_eq!(PacketTag::from_u8(6), PacketTag::PublicKey);
    assert_eq!(PacketTag::from_u8(7), PacketTag::SecretSubkey);
    assert_eq!(PacketTag::from_u8(8), PacketTag::CompressedData);
    assert_eq!(PacketTag::from_u8(9), PacketTag::SymmetricallyEncryptedData);
    assert_eq!(PacketTag::from_u8(10), PacketTag::Marker);
    assert_eq!(PacketTag::from_u8(11), PacketTag::LiteralData);
    assert_eq!(PacketTag::from_u8(12), PacketTag::Trust);
    assert_eq!(PacketTag::from_u8(13), PacketTag::UserId);
    assert_eq!(PacketTag::from_u8(14), PacketTag::PublicSubkey);
    assert_eq!(PacketTag::from_u8(17), PacketTag::UserAttribute);
    assert_eq!(PacketTag::from_u8(18), PacketTag::SymmetricallyEncryptedIntegrityProtectedData);
    assert_eq!(PacketTag::from_u8(19), PacketTag::ModificationDetectionCode);
    assert_eq!(PacketTag::from_u8(20), PacketTag::AeadEncryptedData);
    assert_eq!(PacketTag::from_u8(21), PacketTag::Padding);
    assert_eq!(PacketTag::from_u8(99), PacketTag::Unknown(99));
}

#[test]
fn test_packet_tag_to_u8_all_known() {
    assert_eq!(PacketTag::Reserved.to_u8(), 0);
    assert_eq!(PacketTag::PublicKeyEncryptedSessionKey.to_u8(), 1);
    assert_eq!(PacketTag::Signature.to_u8(), 2);
    assert_eq!(PacketTag::SymmetricKeyEncryptedSessionKey.to_u8(), 3);
    assert_eq!(PacketTag::OnePassSignature.to_u8(), 4);
    assert_eq!(PacketTag::SecretKey.to_u8(), 5);
    assert_eq!(PacketTag::PublicKey.to_u8(), 6);
    assert_eq!(PacketTag::SecretSubkey.to_u8(), 7);
    assert_eq!(PacketTag::CompressedData.to_u8(), 8);
    assert_eq!(PacketTag::SymmetricallyEncryptedData.to_u8(), 9);
    assert_eq!(PacketTag::Marker.to_u8(), 10);
    assert_eq!(PacketTag::LiteralData.to_u8(), 11);
    assert_eq!(PacketTag::Trust.to_u8(), 12);
    assert_eq!(PacketTag::UserId.to_u8(), 13);
    assert_eq!(PacketTag::PublicSubkey.to_u8(), 14);
    assert_eq!(PacketTag::UserAttribute.to_u8(), 17);
    assert_eq!(PacketTag::SymmetricallyEncryptedIntegrityProtectedData.to_u8(), 18);
    assert_eq!(PacketTag::ModificationDetectionCode.to_u8(), 19);
    assert_eq!(PacketTag::AeadEncryptedData.to_u8(), 20);
    assert_eq!(PacketTag::Padding.to_u8(), 21);
    assert_eq!(PacketTag::Unknown(99).to_u8(), 99);
}

#[test]
fn test_packet_tag_display_all() {
    assert_eq!(format!("{}", PacketTag::Reserved), "Reserved");
    assert_eq!(format!("{}", PacketTag::PublicKeyEncryptedSessionKey), "Public-Key Encrypted Session Key");
    assert_eq!(format!("{}", PacketTag::Signature), "Signature");
    assert_eq!(format!("{}", PacketTag::SymmetricKeyEncryptedSessionKey), "Symmetric-Key Encrypted Session Key");
    assert_eq!(format!("{}", PacketTag::OnePassSignature), "One-Pass Signature");
    assert_eq!(format!("{}", PacketTag::SecretKey), "Secret Key");
    assert_eq!(format!("{}", PacketTag::PublicKey), "Public Key");
    assert_eq!(format!("{}", PacketTag::SecretSubkey), "Secret Subkey");
    assert_eq!(format!("{}", PacketTag::CompressedData), "Compressed Data");
    assert_eq!(format!("{}", PacketTag::SymmetricallyEncryptedData), "Symmetrically Encrypted Data");
    assert_eq!(format!("{}", PacketTag::Marker), "Marker");
    assert_eq!(format!("{}", PacketTag::LiteralData), "Literal Data");
    assert_eq!(format!("{}", PacketTag::Trust), "Trust");
    assert_eq!(format!("{}", PacketTag::UserId), "User ID");
    assert_eq!(format!("{}", PacketTag::PublicSubkey), "Public Subkey");
    assert_eq!(format!("{}", PacketTag::UserAttribute), "User Attribute");
    assert_eq!(format!("{}", PacketTag::SymmetricallyEncryptedIntegrityProtectedData), "Symmetrically Encrypted Integrity Protected Data");
    assert_eq!(format!("{}", PacketTag::ModificationDetectionCode), "Modification Detection Code");
    assert_eq!(format!("{}", PacketTag::AeadEncryptedData), "AEAD Encrypted Data");
    assert_eq!(format!("{}", PacketTag::Padding), "Padding");
    assert_eq!(format!("{}", PacketTag::Unknown(99)), "Unknown (99)");
}

// ============================================================================
// PKESK Packet Tests (Tag 1)
// ============================================================================

/// Build a PKESK packet with new format header
fn build_pkesk_packet(algorithm: u8, key_material: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    // New format header: 0xC0 | tag
    packet.push(0xC0 | 1); // Tag 1 = PKESK

    // Body: version (1) + key_id (8) + algorithm (1) + key_material
    let body_len = 1 + 8 + 1 + key_material.len();
    packet.push(body_len as u8); // Length (< 192)

    packet.push(3); // Version 3
    packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // Key ID
    packet.push(algorithm);
    packet.extend_from_slice(key_material);

    packet
}

#[test]
fn test_pkesk_rsa_algorithm() {
    // RSA (algo 1): MPI for encrypted session key
    // MPI: 2-byte bit count + data. 16 bits = 2 bytes of data
    let key_material = vec![0x00, 0x10, 0xAB, 0xCD]; // 16-bit MPI
    let packet = build_pkesk_packet(1, &key_material);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].tag, PacketTag::PublicKeyEncryptedSessionKey);
}

#[test]
fn test_pkesk_elgamal_algorithm() {
    // Elgamal (algo 16): Two MPIs
    let key_material = vec![
        0x00, 0x08, 0xAB, // 8-bit MPI 1
        0x00, 0x08, 0xCD, // 8-bit MPI 2
    ];
    let packet = build_pkesk_packet(16, &key_material);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_pkesk_ecdh_algorithm() {
    // ECDH (algo 18): MPI + wrapped key
    let key_material = vec![
        0x00, 0x08, 0xAB, // 8-bit MPI (ephemeral)
        0x01, 0x02, 0x03, // wrapped session key
    ];
    let packet = build_pkesk_packet(18, &key_material);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_pkesk_x25519_algorithm() {
    // X25519 (algo 25): 32-byte ephemeral + wrapped key
    let mut key_material = vec![0u8; 32]; // 32-byte ephemeral key
    key_material.extend_from_slice(&[0x01, 0x02, 0x03]); // wrapped key
    let packet = build_pkesk_packet(25, &key_material);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_pkesk_unknown_algorithm() {
    // Unknown algorithm: just raw bytes
    let key_material = vec![0x01, 0x02, 0x03, 0x04];
    let packet = build_pkesk_packet(99, &key_material);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

// ============================================================================
// SEIPD Packet Tests (Tag 18)
// ============================================================================

fn build_seipd_v1_packet(encrypted_data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 18); // Tag 18 = SEIPD

    let body_len = 1 + encrypted_data.len(); // version + data
    packet.push(body_len as u8);

    packet.push(1); // Version 1
    packet.extend_from_slice(encrypted_data);

    packet
}

fn build_seipd_v2_packet(cipher: u8, aead: u8, chunk_size: u8, encrypted_data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 18); // Tag 18 = SEIPD

    let body_len = 4 + encrypted_data.len(); // version + cipher + aead + chunk + data
    packet.push(body_len as u8);

    packet.push(2); // Version 2
    packet.push(cipher);
    packet.push(aead);
    packet.push(chunk_size);
    packet.extend_from_slice(encrypted_data);

    packet
}

#[test]
fn test_seipd_v1() {
    let packet = build_seipd_v1_packet(&[0xAB, 0xCD, 0xEF]);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::SymmetricallyEncryptedIntegrityProtectedData);
}

#[test]
fn test_seipd_v2_aes256_gcm() {
    let packet = build_seipd_v2_packet(9, 3, 10, &[0xAB, 0xCD, 0xEF]); // AES-256, GCM, chunk=2^16

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

// ============================================================================
// Secret Key Packet Tests (Tag 5)
// ============================================================================

fn build_secret_key_packet(s2k_usage: u8, extra_data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 5); // Tag 5 = Secret Key

    // Minimal v4 public key portion + s2k + extra
    let mut body = Vec::new();
    body.push(4); // Version 4
    body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Creation time
    body.push(1); // RSA algorithm
    // Minimal RSA public key: n and e as small MPIs
    body.extend_from_slice(&[0x00, 0x08, 0x03]); // n: 8-bit MPI
    body.extend_from_slice(&[0x00, 0x08, 0x03]); // e: 8-bit MPI
    body.push(s2k_usage);
    body.extend_from_slice(extra_data);

    // Length
    if body.len() < 192 {
        packet.push(body.len() as u8);
    } else {
        packet.push(0xFF);
        packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    }
    packet.extend(body);

    packet
}

#[test]
fn test_secret_key_unencrypted() {
    // S2K usage 0 = unencrypted
    let packet = build_secret_key_packet(0, &[0x01, 0x02]); // Some secret key data

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::SecretKey);
}

#[test]
fn test_secret_key_encrypted_s2k_254() {
    // S2K usage 254 = SHA-1 checksum, encrypted with S2K specifier
    // cipher (1) + s2k_type (1) + s2k_hash (1) + [salt (8) if type 1/3] + [count (1) if type 3] + IV + encrypted data
    let mut extra = Vec::new();
    extra.push(9); // AES-256
    extra.push(3); // Iterated and salted S2K
    extra.push(8); // SHA-256
    extra.extend_from_slice(&[0x01; 8]); // Salt
    extra.push(96); // Count byte
    extra.extend_from_slice(&[0x00; 16]); // IV (16 bytes for AES)
    extra.extend_from_slice(&[0xAB, 0xCD]); // Encrypted data

    let packet = build_secret_key_packet(254, &extra);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_secret_key_encrypted_s2k_255() {
    // S2K usage 255 = checksum (not SHA-1), encrypted
    let mut extra = Vec::new();
    extra.push(7); // AES-128
    extra.push(1); // Salted S2K (no count)
    extra.push(2); // SHA-1
    extra.extend_from_slice(&[0x02; 8]); // Salt
    extra.extend_from_slice(&[0x00; 16]); // IV
    extra.extend_from_slice(&[0xEF]); // Encrypted data

    let packet = build_secret_key_packet(255, &extra);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_secret_key_encrypted_s2k_254_non_aes() {
    // S2K usage 254 with non-AES cipher (uses 8-byte IV instead of 16)
    let mut extra = Vec::new();
    extra.push(3); // CAST5 (not AES, so 8-byte IV)
    extra.push(0); // Simple S2K
    extra.push(2); // SHA-1
    extra.extend_from_slice(&[0x00; 8]); // IV (8 bytes for non-AES)
    extra.extend_from_slice(&[0xDD]); // Encrypted data

    let packet = build_secret_key_packet(254, &extra);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_secret_key_encrypted_simple_s2k() {
    // Simple S2K (type 0) - no salt or count
    let mut extra = Vec::new();
    extra.push(7); // AES-128
    extra.push(0); // Simple S2K
    extra.push(2); // SHA-1
    extra.extend_from_slice(&[0x00; 16]); // IV
    extra.extend_from_slice(&[0xAA]); // Encrypted data

    let packet = build_secret_key_packet(254, &extra);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_secret_key_legacy_encryption() {
    // S2K usage != 0/254/255 means legacy encryption (s2k_usage is the cipher algo)
    // Just IV + encrypted data, IV size depends on algorithm
    let mut extra = Vec::new();
    extra.extend_from_slice(&[0x00; 8]); // IV (8 bytes for legacy ciphers)
    extra.extend_from_slice(&[0xBB]); // Encrypted data

    let packet = build_secret_key_packet(3, &extra); // CAST5

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_secret_key_legacy_encryption_aes() {
    // Legacy encryption with AES (algo 7-9) uses 16-byte IV
    let mut extra = Vec::new();
    extra.extend_from_slice(&[0x00; 16]); // IV (16 bytes for AES)
    extra.extend_from_slice(&[0xCC]); // Encrypted data

    let packet = build_secret_key_packet(7, &extra); // AES-128

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

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

// ============================================================================
// Field Tests
// ============================================================================

#[test]
fn test_field_constructors() {
    let packet = Field::packet("Test", "Value", (0, 10));
    assert_eq!(packet.indent, 0);
    assert!(packet.color.is_none());

    let field = Field::field("Test", "Value", (0, 10), 5);
    assert_eq!(field.indent, 1);
    assert_eq!(field.color, Some(5));

    let subfield = Field::subfield("Test", "Value", (0, 10), 3);
    assert_eq!(subfield.indent, 2);
    assert_eq!(subfield.color, Some(3));
}

// ============================================================================
// ColorTracker Edge Cases
// ============================================================================

#[test]
fn test_color_tracker_out_of_bounds() {
    let tracker = ColorTracker::new(10);
    assert_eq!(tracker.get_color(100), None); // Beyond size
}

#[test]
fn test_color_tracker_set_field_invalid_range() {
    let mut tracker = ColorTracker::new(10);
    // end > len should not panic, just not color anything
    let color = tracker.set_field(5, 100);
    assert_eq!(color, 0); // Still returns color and advances
    assert_eq!(tracker.get_color(5), None); // But nothing colored
}

#[test]
fn test_color_tracker_empty_range() {
    let mut tracker = ColorTracker::new(10);
    // start == end should not color anything
    let color = tracker.set_field(5, 5);
    assert_eq!(color, 0);
    assert_eq!(tracker.get_color(5), None);
}
