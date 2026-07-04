//! Secret Key packet tests - Tag 5

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

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
