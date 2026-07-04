//! Tests for public_key.rs - all key algorithm types

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

/// Build a public key packet with the given algorithm and key material
fn build_public_key_packet(algorithm: u8, key_material: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 6); // Tag 6 = Public Key

    // Body: version (1) + creation_time (4) + algorithm (1) + key_material
    let body_len = 1 + 4 + 1 + key_material.len();

    if body_len < 192 {
        packet.push(body_len as u8);
    } else {
        packet.push(0xFF);
        packet.extend_from_slice(&(body_len as u32).to_be_bytes());
    }

    packet.push(4); // Version 4
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Creation time (some valid timestamp)
    packet.push(algorithm);
    packet.extend_from_slice(key_material);

    packet
}

/// Build MPI (multi-precision integer): 2-byte bit count + data
fn build_mpi(bits: u16, data: &[u8]) -> Vec<u8> {
    let mut mpi = Vec::new();
    mpi.extend_from_slice(&bits.to_be_bytes());
    mpi.extend_from_slice(data);
    mpi
}

// ============================================================================
// RSA Keys (algorithms 1-3)
// ============================================================================

#[test]
fn test_public_key_rsa() {
    // RSA: n (MPI) + e (MPI)
    let mut key_material = Vec::new();
    key_material.extend(build_mpi(16, &[0xAB, 0xCD])); // n: 16 bits
    key_material.extend(build_mpi(8, &[0x11])); // e: 8 bits

    let packet = build_public_key_packet(1, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "RSA parse failed: {:?}", result.err());
    assert_eq!(result.unwrap()[0].tag, PacketTag::PublicKey);
}

#[test]
fn test_public_key_rsa_encrypt_only() {
    let mut key_material = Vec::new();
    key_material.extend(build_mpi(16, &[0xAB, 0xCD]));
    key_material.extend(build_mpi(8, &[0x11]));

    let packet = build_public_key_packet(2, &key_material); // RSA Encrypt-Only
    let result = parse_bytes(packet);
    assert!(result.is_ok());
}

#[test]
fn test_public_key_rsa_sign_only() {
    let mut key_material = Vec::new();
    key_material.extend(build_mpi(16, &[0xAB, 0xCD]));
    key_material.extend(build_mpi(8, &[0x11]));

    let packet = build_public_key_packet(3, &key_material); // RSA Sign-Only
    let result = parse_bytes(packet);
    assert!(result.is_ok());
}

// ============================================================================
// DSA Keys (algorithm 17)
// ============================================================================

#[test]
fn test_public_key_dsa() {
    // DSA: p, q, g, y (all MPIs)
    let mut key_material = Vec::new();
    key_material.extend(build_mpi(16, &[0x00, 0x01])); // p
    key_material.extend(build_mpi(8, &[0x02])); // q
    key_material.extend(build_mpi(8, &[0x03])); // g
    key_material.extend(build_mpi(8, &[0x04])); // y

    let packet = build_public_key_packet(17, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "DSA parse failed: {:?}", result.err());
}

// ============================================================================
// Elgamal Keys (algorithm 16)
// ============================================================================

#[test]
fn test_public_key_elgamal() {
    // Elgamal: p, g, y (all MPIs)
    let mut key_material = Vec::new();
    key_material.extend(build_mpi(16, &[0x00, 0x01])); // p
    key_material.extend(build_mpi(8, &[0x02])); // g
    key_material.extend(build_mpi(8, &[0x03])); // y

    let packet = build_public_key_packet(16, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Elgamal parse failed: {:?}", result.err());
}

// ============================================================================
// ECDSA Keys (algorithm 19)
// ============================================================================

#[test]
fn test_public_key_ecdsa() {
    // ECDSA: OID length + OID + public key MPI
    let mut key_material = Vec::new();
    // OID for P-256
    let oid = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    key_material.push(oid.len() as u8);
    key_material.extend_from_slice(&oid);
    key_material.extend(build_mpi(256, &[0u8; 32])); // public key

    let packet = build_public_key_packet(19, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "ECDSA parse failed: {:?}", result.err());
}

// ============================================================================
// ECDH Keys (algorithm 18)
// ============================================================================

#[test]
fn test_public_key_ecdh() {
    // ECDH: OID length + OID + public key MPI + KDF params length + KDF params
    let mut key_material = Vec::new();
    // OID for Curve25519
    let oid = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
    key_material.push(oid.len() as u8);
    key_material.extend_from_slice(&oid);
    key_material.extend(build_mpi(256, &[0u8; 32])); // public key
    // KDF params: length + reserved + hash algo + sym algo
    key_material.push(3); // KDF params length
    key_material.extend_from_slice(&[0x01, 0x08, 0x07]); // reserved, SHA-256, AES-128

    let packet = build_public_key_packet(18, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "ECDH parse failed: {:?}", result.err());
}

// ============================================================================
// EdDSA Keys (algorithm 22)
// ============================================================================

#[test]
fn test_public_key_eddsa() {
    // EdDSA: OID length + OID + public key MPI
    let mut key_material = Vec::new();
    // OID for Ed25519
    let oid = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
    key_material.push(oid.len() as u8);
    key_material.extend_from_slice(&oid);
    key_material.extend(build_mpi(256, &[0u8; 32])); // public key

    let packet = build_public_key_packet(22, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "EdDSA parse failed: {:?}", result.err());
}

// ============================================================================
// X25519 Keys (algorithm 25)
// ============================================================================

#[test]
fn test_public_key_x25519() {
    // X25519: 32 raw bytes
    let key_material = vec![0u8; 32];

    let packet = build_public_key_packet(25, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "X25519 parse failed: {:?}", result.err());
}

// ============================================================================
// Ed25519 Keys (algorithm 27)
// ============================================================================

#[test]
fn test_public_key_ed25519() {
    // Ed25519: 32 raw bytes
    let key_material = vec![0u8; 32];

    let packet = build_public_key_packet(27, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Ed25519 parse failed: {:?}", result.err());
}

// ============================================================================
// Unknown Algorithm
// ============================================================================

#[test]
fn test_public_key_unknown_algorithm() {
    let key_material = vec![0x01, 0x02, 0x03, 0x04];

    let packet = build_public_key_packet(99, &key_material);
    let result = parse_bytes(packet);
    assert!(
        result.is_ok(),
        "Unknown algo parse failed: {:?}",
        result.err()
    );
}

// ============================================================================
// Public Subkey (Tag 14)
// ============================================================================

#[test]
fn test_public_subkey() {
    let mut key_material = Vec::new();
    key_material.extend(build_mpi(16, &[0xAB, 0xCD]));
    key_material.extend(build_mpi(8, &[0x11]));

    let mut packet = Vec::new();
    packet.push(0xC0 | 14); // Tag 14 = Public Subkey
    let body_len = 1 + 4 + 1 + key_material.len();
    packet.push(body_len as u8);
    packet.push(4);
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    packet.push(1); // RSA
    packet.extend_from_slice(&key_material);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    assert_eq!(result.unwrap()[0].tag, PacketTag::PublicSubkey);
}

// ============================================================================
// Secret Key and Subkey Tags
// ============================================================================

#[test]
fn test_secret_subkey_tag() {
    // Build a minimal secret subkey (tag 7)
    let mut packet = Vec::new();
    packet.push(0xC0 | 7); // Tag 7 = Secret Subkey

    let mut body = Vec::new();
    body.push(4); // Version 4
    body.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Creation time
    body.push(1); // RSA
    body.extend(build_mpi(16, &[0xAB, 0xCD])); // n
    body.extend(build_mpi(8, &[0x11])); // e
    body.push(0); // S2K usage = unencrypted

    packet.push(body.len() as u8);
    packet.extend(body);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    assert_eq!(result.unwrap()[0].tag, PacketTag::SecretSubkey);
}

// ============================================================================
// V6 Public Keys (RFC 9580)
// ============================================================================

/// Build a V6 public key packet with the given algorithm and key material
fn build_v6_public_key_packet(algorithm: u8, key_material: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 6); // Tag 6 = Public Key

    // Body: version (1) + creation_time (4) + algorithm (1) + key_material_len (4) + key_material
    let body_len = 1 + 4 + 1 + 4 + key_material.len();

    if body_len < 192 {
        packet.push(body_len as u8);
    } else {
        packet.push(0xFF);
        packet.extend_from_slice(&(body_len as u32).to_be_bytes());
    }

    packet.push(6); // Version 6
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Creation time
    packet.push(algorithm);
    packet.extend_from_slice(&(key_material.len() as u32).to_be_bytes()); // Key material length
    packet.extend_from_slice(key_material);

    packet
}

#[test]
fn test_v6_public_key_rsa() {
    // RSA: n (MPI) + e (MPI)
    let mut key_material = Vec::new();
    key_material.extend(build_mpi(16, &[0xAB, 0xCD])); // n: 16 bits
    key_material.extend(build_mpi(8, &[0x11])); // e: 8 bits

    let packet = build_v6_public_key_packet(1, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V6 RSA parse failed: {:?}", result.err());
}

#[test]
fn test_v6_public_key_ed25519() {
    // Ed25519: 32 raw bytes
    let key_material = vec![0u8; 32];

    let packet = build_v6_public_key_packet(27, &key_material);
    let result = parse_bytes(packet);
    assert!(
        result.is_ok(),
        "V6 Ed25519 parse failed: {:?}",
        result.err()
    );
}

#[test]
fn test_v6_public_key_x25519() {
    // X25519: 32 raw bytes
    let key_material = vec![0u8; 32];

    let packet = build_v6_public_key_packet(25, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V6 X25519 parse failed: {:?}", result.err());
}

#[test]
fn test_v6_public_key_ed448() {
    // Ed448: 57 raw bytes
    let key_material = vec![0u8; 57];

    let packet = build_v6_public_key_packet(28, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V6 Ed448 parse failed: {:?}", result.err());
}

#[test]
fn test_v6_public_key_x448() {
    // X448: 56 raw bytes
    let key_material = vec![0u8; 56];

    let packet = build_v6_public_key_packet(26, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V6 X448 parse failed: {:?}", result.err());
}

#[test]
fn test_v6_public_key_unknown_algorithm() {
    let key_material = vec![0x01, 0x02, 0x03, 0x04];

    let packet = build_v6_public_key_packet(99, &key_material);
    let result = parse_bytes(packet);
    assert!(
        result.is_ok(),
        "V6 unknown algo parse failed: {:?}",
        result.err()
    );
}

#[test]
fn test_v6_public_key_ecdsa() {
    // V6 ECDSA key to exercise V6 dispatcher with legacy algorithm
    let mut key_material = Vec::new();
    let oid = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]; // P-256
    key_material.push(oid.len() as u8);
    key_material.extend_from_slice(&oid);
    key_material.extend(build_mpi(256, &[0u8; 32]));

    let packet = build_v6_public_key_packet(19, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V6 ECDSA parse failed: {:?}", result.err());
}

#[test]
fn test_v6_public_key_ecdh() {
    // V6 ECDH key
    let mut key_material = Vec::new();
    let oid = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]; // Curve25519
    key_material.push(oid.len() as u8);
    key_material.extend_from_slice(&oid);
    key_material.extend(build_mpi(256, &[0u8; 32]));
    key_material.push(3); // KDF params length
    key_material.extend_from_slice(&[0x01, 0x08, 0x07]);

    let packet = build_v6_public_key_packet(18, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V6 ECDH parse failed: {:?}", result.err());
}

#[test]
fn test_v6_public_key_eddsa_legacy() {
    // V6 with legacy EdDSA (algo 22)
    let mut key_material = Vec::new();
    let oid = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]; // Ed25519
    key_material.push(oid.len() as u8);
    key_material.extend_from_slice(&oid);
    key_material.extend(build_mpi(256, &[0u8; 32]));

    let packet = build_v6_public_key_packet(22, &key_material);
    let result = parse_bytes(packet);
    assert!(
        result.is_ok(),
        "V6 EdDSA legacy parse failed: {:?}",
        result.err()
    );
}

#[test]
fn test_v6_public_key_dsa() {
    // V6 DSA key
    let mut key_material = Vec::new();
    key_material.extend(build_mpi(16, &[0x00, 0x01])); // p
    key_material.extend(build_mpi(8, &[0x02])); // q
    key_material.extend(build_mpi(8, &[0x03])); // g
    key_material.extend(build_mpi(8, &[0x04])); // y

    let packet = build_v6_public_key_packet(17, &key_material);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V6 DSA parse failed: {:?}", result.err());
}

#[test]
fn test_v6_public_key_elgamal() {
    // V6 Elgamal key
    let mut key_material = Vec::new();
    key_material.extend(build_mpi(16, &[0x00, 0x01])); // p
    key_material.extend(build_mpi(8, &[0x02])); // g
    key_material.extend(build_mpi(8, &[0x03])); // y

    let packet = build_v6_public_key_packet(16, &key_material);
    let result = parse_bytes(packet);
    assert!(
        result.is_ok(),
        "V6 Elgamal parse failed: {:?}",
        result.err()
    );
}
