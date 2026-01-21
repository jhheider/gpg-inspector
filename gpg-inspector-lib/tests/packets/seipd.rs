//! SEIPD (Symmetrically Encrypted Integrity Protected Data) packet tests - Tag 18

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

fn build_seipd_v1_packet(encrypted_data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 18); // Tag 18 = SEIPD

    let body_len = 1 + encrypted_data.len(); // version + data
    packet.push(body_len as u8);

    packet.push(1); // Version 1
    packet.extend_from_slice(encrypted_data);

    packet
}

/// Build a V2 SEIPD packet with 32-byte salt (RFC 9580)
fn build_seipd_v2_packet(cipher: u8, aead: u8, chunk_size: u8, encrypted_data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 18); // Tag 18 = SEIPD

    // V2: version + cipher + aead + chunk + 32-byte salt + data
    let body_len = 4 + 32 + encrypted_data.len();

    if body_len < 192 {
        packet.push(body_len as u8);
    } else {
        packet.push(0xFF);
        packet.extend_from_slice(&(body_len as u32).to_be_bytes());
    }

    packet.push(2); // Version 2
    packet.push(cipher);
    packet.push(aead);
    packet.push(chunk_size);
    packet.extend_from_slice(&[0u8; 32]); // 32-byte salt
    packet.extend_from_slice(encrypted_data);

    packet
}

#[test]
fn test_seipd_v1() {
    let packet = build_seipd_v1_packet(&[0xAB, 0xCD, 0xEF]);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(
        packets[0].tag,
        PacketTag::SymmetricallyEncryptedIntegrityProtectedData
    );
}

#[test]
fn test_seipd_v2_aes256_gcm() {
    let packet = build_seipd_v2_packet(9, 3, 10, &[0xAB, 0xCD, 0xEF]); // AES-256, GCM, chunk=2^16

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
}

#[test]
fn test_seipd_v2_aes128_eax() {
    let packet = build_seipd_v2_packet(7, 1, 8, &[0x01, 0x02, 0x03]); // AES-128, EAX, chunk=2^14

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V2 AES128 EAX failed: {:?}", result.err());
}

#[test]
fn test_seipd_v2_aes192_ocb() {
    let packet = build_seipd_v2_packet(8, 2, 12, &[0xDE, 0xAD, 0xBE, 0xEF]); // AES-192, OCB, chunk=2^18

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V2 AES192 OCB failed: {:?}", result.err());
}

#[test]
fn test_seipd_v2_large_data() {
    // Test with larger encrypted data to exercise the length encoding
    let large_data = vec![0xAAu8; 256];
    let packet = build_seipd_v2_packet(9, 3, 10, &large_data);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V2 large data failed: {:?}", result.err());
}
