//! PKESK (Public-Key Encrypted Session Key) packet tests - Tag 1

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

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
// V6 PKESK Packets (RFC 9580)
// ============================================================================

/// Build a V6 PKESK packet with new format header
fn build_v6_pkesk_packet(
    key_version: u8,
    key_id_data: &[u8],
    algorithm: u8,
    key_material: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::new();
    // New format header: 0xC0 | tag
    packet.push(0xC0 | 1); // Tag 1 = PKESK

    // Body: version (1) + key_version (1) + key_id_data + algorithm (1) + key_material
    let body_len = 1 + 1 + key_id_data.len() + 1 + key_material.len();

    if body_len < 192 {
        packet.push(body_len as u8);
    } else {
        packet.push(0xFF);
        packet.extend_from_slice(&(body_len as u32).to_be_bytes());
    }

    packet.push(6); // Version 6
    packet.push(key_version);
    packet.extend_from_slice(key_id_data);
    packet.push(algorithm);
    packet.extend_from_slice(key_material);

    packet
}

#[test]
fn test_v6_pkesk_anonymous_x25519() {
    // Anonymous recipient (key_version=0) with X25519
    let mut key_material = vec![0u8; 32]; // 32-byte ephemeral key
    key_material.extend_from_slice(&[0x01, 0x02, 0x03]); // wrapped key

    let packet = build_v6_pkesk_packet(0, &[], 25, &key_material);

    let result = parse_bytes(packet);
    assert!(
        result.is_ok(),
        "V6 PKESK anonymous X25519 failed: {:?}",
        result.err()
    );
}

#[test]
fn test_v6_pkesk_v4_key_id_x25519() {
    // V4 key ID (8 bytes) with X25519
    let key_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut key_material = vec![0u8; 32]; // 32-byte ephemeral key
    key_material.extend_from_slice(&[0x01, 0x02, 0x03]); // wrapped key

    let packet = build_v6_pkesk_packet(4, &key_id, 25, &key_material);

    let result = parse_bytes(packet);
    assert!(
        result.is_ok(),
        "V6 PKESK V4 key ID X25519 failed: {:?}",
        result.err()
    );
}

#[test]
fn test_v6_pkesk_v6_fingerprint_x25519() {
    // V6 fingerprint (32 bytes) with X25519
    let fingerprint = [0u8; 32];
    let mut key_material = vec![0u8; 32]; // 32-byte ephemeral key
    key_material.extend_from_slice(&[0x01, 0x02, 0x03]); // wrapped key

    let packet = build_v6_pkesk_packet(6, &fingerprint, 25, &key_material);

    let result = parse_bytes(packet);
    assert!(
        result.is_ok(),
        "V6 PKESK V6 fingerprint X25519 failed: {:?}",
        result.err()
    );
}

#[test]
fn test_v6_pkesk_x448() {
    // V6 PKESK with X448 (56-byte ephemeral key)
    let fingerprint = [0u8; 32];
    let mut key_material = vec![0u8; 56]; // 56-byte ephemeral key
    key_material.extend_from_slice(&[0x01, 0x02, 0x03]); // wrapped key

    let packet = build_v6_pkesk_packet(6, &fingerprint, 26, &key_material);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V6 PKESK X448 failed: {:?}", result.err());
}

#[test]
fn test_v6_pkesk_rsa() {
    // V6 PKESK with RSA
    let fingerprint = [0u8; 32];
    // RSA: MPI for encrypted session key
    let mut key_material = Vec::new();
    key_material.extend_from_slice(&[0x00, 0x10, 0xAB, 0xCD]); // 16-bit MPI

    let packet = build_v6_pkesk_packet(6, &fingerprint, 1, &key_material);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V6 PKESK RSA failed: {:?}", result.err());
}

#[test]
fn test_v6_pkesk_unknown_key_version() {
    // Unknown key version (should still parse)
    let key_material = vec![0x01, 0x02, 0x03, 0x04];

    let packet = build_v6_pkesk_packet(99, &[], 99, &key_material);

    let result = parse_bytes(packet);
    assert!(
        result.is_ok(),
        "V6 PKESK unknown key version failed: {:?}",
        result.err()
    );
}
