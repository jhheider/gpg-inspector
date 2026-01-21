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
