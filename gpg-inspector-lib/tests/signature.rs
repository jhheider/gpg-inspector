//! Tests for signature.rs - signature packets and all subpacket types

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

/// Build a v4 signature packet
fn build_signature_packet(
    sig_type: u8,
    pub_algo: u8,
    hash_algo: u8,
    hashed_subpackets: &[u8],
    unhashed_subpackets: &[u8],
    signature_data: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 2); // Tag 2 = Signature

    let mut body = Vec::new();
    body.push(4); // Version 4
    body.push(sig_type);
    body.push(pub_algo);
    body.push(hash_algo);

    // Hashed subpackets
    body.extend_from_slice(&(hashed_subpackets.len() as u16).to_be_bytes());
    body.extend_from_slice(hashed_subpackets);

    // Unhashed subpackets
    body.extend_from_slice(&(unhashed_subpackets.len() as u16).to_be_bytes());
    body.extend_from_slice(unhashed_subpackets);

    // Hash prefix (2 bytes)
    body.extend_from_slice(&[0xAB, 0xCD]);

    // Signature data
    body.extend_from_slice(signature_data);

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

/// Build a v3 signature packet
fn build_v3_signature_packet(
    sig_type: u8,
    creation_time: u32,
    key_id: &[u8; 8],
    pub_algo: u8,
    hash_algo: u8,
    signature_data: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 2); // Tag 2 = Signature

    let mut body = Vec::new();
    body.push(3); // Version 3
    body.push(5); // Hashed material length (always 5 for v3)
    body.push(sig_type);
    body.extend_from_slice(&creation_time.to_be_bytes());
    body.extend_from_slice(key_id);
    body.push(pub_algo);
    body.push(hash_algo);
    body.extend_from_slice(&[0xAB, 0xCD]); // Hash prefix
    body.extend_from_slice(signature_data);

    packet.push(body.len() as u8);
    packet.extend(body);

    packet
}

/// Build an MPI
fn build_mpi(bits: u16, data: &[u8]) -> Vec<u8> {
    let mut mpi = Vec::new();
    mpi.extend_from_slice(&bits.to_be_bytes());
    mpi.extend_from_slice(data);
    mpi
}

/// Build a subpacket with type and data
fn build_subpacket(sp_type: u8, data: &[u8]) -> Vec<u8> {
    let mut sp = Vec::new();
    let len = 1 + data.len(); // type byte + data
    if len < 192 {
        sp.push(len as u8);
    } else {
        sp.push(0xFF);
        sp.extend_from_slice(&(len as u32).to_be_bytes());
    }
    sp.push(sp_type);
    sp.extend_from_slice(data);
    sp
}

// ============================================================================
// V4 Signatures with different algorithms
// ============================================================================

#[test]
fn test_signature_rsa() {
    let sig_data = build_mpi(16, &[0xAB, 0xCD]);
    let packet = build_signature_packet(0x00, 1, 8, &[], &[], &sig_data);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "RSA sig failed: {:?}", result.err());
    assert_eq!(result.unwrap()[0].tag, PacketTag::Signature);
}

#[test]
fn test_signature_dsa() {
    // DSA: two MPIs (r, s)
    let mut sig_data = Vec::new();
    sig_data.extend(build_mpi(8, &[0x01]));
    sig_data.extend(build_mpi(8, &[0x02]));

    let packet = build_signature_packet(0x00, 17, 8, &[], &[], &sig_data);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "DSA sig failed: {:?}", result.err());
}

#[test]
fn test_signature_ecdsa() {
    // ECDSA: two MPIs (r, s)
    let mut sig_data = Vec::new();
    sig_data.extend(build_mpi(8, &[0x01]));
    sig_data.extend(build_mpi(8, &[0x02]));

    let packet = build_signature_packet(0x00, 19, 8, &[], &[], &sig_data);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "ECDSA sig failed: {:?}", result.err());
}

#[test]
fn test_signature_eddsa() {
    // EdDSA (22): two MPIs (r, s)
    let mut sig_data = Vec::new();
    sig_data.extend(build_mpi(8, &[0x01]));
    sig_data.extend(build_mpi(8, &[0x02]));

    let packet = build_signature_packet(0x00, 22, 8, &[], &[], &sig_data);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "EdDSA sig failed: {:?}", result.err());
}

#[test]
fn test_signature_ed25519() {
    // Ed25519 (27): 64-byte signature
    let sig_data = vec![0u8; 64];

    let packet = build_signature_packet(0x00, 27, 8, &[], &[], &sig_data);
    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Ed25519 sig failed: {:?}", result.err());
}

#[test]
fn test_signature_unknown_algorithm() {
    let sig_data = vec![0x01, 0x02, 0x03];

    let packet = build_signature_packet(0x00, 99, 8, &[], &[], &sig_data);
    let result = parse_bytes(packet);
    assert!(
        result.is_ok(),
        "Unknown algo sig failed: {:?}",
        result.err()
    );
}

// ============================================================================
// V3 Signatures
// ============================================================================

#[test]
fn test_v3_signature_rsa() {
    let sig_data = build_mpi(16, &[0xAB, 0xCD]);
    let packet = build_v3_signature_packet(
        0x00,
        0x60000000,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        1, // RSA
        2, // SHA-1
        &sig_data,
    );

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V3 RSA sig failed: {:?}", result.err());
}

#[test]
fn test_v3_signature_dsa() {
    let mut sig_data = Vec::new();
    sig_data.extend(build_mpi(8, &[0x01]));
    sig_data.extend(build_mpi(8, &[0x02]));

    let packet = build_v3_signature_packet(
        0x00,
        0x60000000,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        17, // DSA
        2,
        &sig_data,
    );

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "V3 DSA sig failed: {:?}", result.err());
}

// ============================================================================
// All Subpacket Types
// ============================================================================

#[test]
fn test_subpacket_signature_creation_time() {
    let sp = build_subpacket(2, &[0x60, 0x00, 0x00, 0x00]);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_signature_expiration_time() {
    let sp = build_subpacket(3, &[0x00, 0x01, 0x51, 0x80]); // ~1 year
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_exportable() {
    let sp = build_subpacket(4, &[0x01]); // exportable = true
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_trust() {
    let sp = build_subpacket(5, &[0x01, 0x3C]); // level=1, amount=60
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_revocable() {
    let sp = build_subpacket(7, &[0x00]); // not revocable
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_key_expiration_time() {
    let sp = build_subpacket(9, &[0x00, 0x00, 0x00, 0x00]); // never expires
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_key_expiration_years() {
    // > 365 days = years format
    let seconds: u32 = 365 * 86400 * 2; // 2 years
    let sp = build_subpacket(9, &seconds.to_be_bytes());
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_key_expiration_days() {
    // > 0 days but < 365 = days format
    let seconds: u32 = 86400 * 30; // 30 days
    let sp = build_subpacket(9, &seconds.to_be_bytes());
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_key_expiration_seconds() {
    // < 1 day = seconds format
    let seconds: u32 = 3600; // 1 hour
    let sp = build_subpacket(9, &seconds.to_be_bytes());
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_preferred_symmetric() {
    let sp = build_subpacket(11, &[9, 8, 7]); // AES-256, AES-192, AES-128
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_revocation_key() {
    let mut data = Vec::new();
    data.push(0x80); // class
    data.push(1); // RSA
    data.extend_from_slice(&[0u8; 20]); // fingerprint
    let sp = build_subpacket(12, &data);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_issuer_key_id() {
    let sp = build_subpacket(16, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_notation_data_text() {
    let mut data = Vec::new();
    data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // flags (human-readable)
    data.extend_from_slice(&[0x00, 0x04]); // name length
    data.extend_from_slice(&[0x00, 0x05]); // value length
    data.extend_from_slice(b"test");
    data.extend_from_slice(b"value");
    let sp = build_subpacket(20, &data);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_notation_data_binary() {
    let mut data = Vec::new();
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags (not human-readable)
    data.extend_from_slice(&[0x00, 0x04]); // name length
    data.extend_from_slice(&[0x00, 0x02]); // value length
    data.extend_from_slice(b"test");
    data.extend_from_slice(&[0xAB, 0xCD]);
    let sp = build_subpacket(20, &data);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_preferred_hash() {
    let sp = build_subpacket(21, &[10, 8, 9]); // SHA-512, SHA-256, SHA-384
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_preferred_compression() {
    let sp = build_subpacket(22, &[2, 1, 0]); // ZLIB, ZIP, uncompressed
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_key_server_preferences() {
    let sp = build_subpacket(23, &[0x80]); // No-modify
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_preferred_key_server() {
    let sp = build_subpacket(24, b"hkps://keys.example.com");
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_primary_user_id() {
    let sp = build_subpacket(25, &[0x01]); // is primary
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_policy_uri() {
    let sp = build_subpacket(26, b"https://example.com/policy");
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_key_flags() {
    let sp = build_subpacket(27, &[0x03]); // Certify + Sign
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_key_flags_empty() {
    let sp = build_subpacket(27, &[]);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_signer_user_id() {
    let sp = build_subpacket(28, b"Test User <test@example.com>");
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_revocation_reason() {
    let mut data = vec![0x01]; // Key superseded
    data.extend_from_slice(b"Upgraded to new key");
    let sp = build_subpacket(29, &data);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_features() {
    let sp = build_subpacket(30, &[0x07]); // MDC + AEAD + v5 keys
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_features_empty() {
    let sp = build_subpacket(30, &[]);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_signature_target() {
    let mut data = Vec::new();
    data.push(1); // RSA
    data.push(8); // SHA-256
    data.extend_from_slice(&[0u8; 32]); // hash
    let sp = build_subpacket(31, &data);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_embedded_signature() {
    let sp = build_subpacket(32, &[0x04, 0x00, 0x01, 0x08]); // minimal embedded sig
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_issuer_fingerprint_v4() {
    let mut data = vec![4]; // Version 4
    data.extend_from_slice(&[0u8; 20]); // 20-byte fingerprint
    let sp = build_subpacket(33, &data);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_issuer_fingerprint_v5() {
    let mut data = vec![5]; // Version 5
    data.extend_from_slice(&[0u8; 32]); // 32-byte fingerprint
    let sp = build_subpacket(33, &data);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_preferred_aead() {
    let sp = build_subpacket(34, &[3, 2, 1]); // GCM, OCB, EAX
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_intended_recipient_v4() {
    let mut data = vec![4]; // Version 4
    data.extend_from_slice(&[0u8; 20]); // fingerprint
    let sp = build_subpacket(35, &data);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_unknown() {
    let sp = build_subpacket(99, &[0x01, 0x02, 0x03]); // Unknown type
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_critical_bit() {
    // Critical bit set: type | 0x80
    let sp = build_subpacket(2 | 0x80, &[0x60, 0x00, 0x00, 0x00]);
    let packet = build_signature_packet(0x00, 1, 8, &sp, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_unhashed_subpackets() {
    let hashed = build_subpacket(2, &[0x60, 0x00, 0x00, 0x00]);
    let unhashed = build_subpacket(16, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let packet = build_signature_packet(0x00, 1, 8, &hashed, &unhashed, &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_multiple_subpackets() {
    let mut subpackets = Vec::new();
    subpackets.extend(build_subpacket(2, &[0x60, 0x00, 0x00, 0x00])); // creation time
    subpackets.extend(build_subpacket(27, &[0x03])); // key flags
    subpackets.extend(build_subpacket(11, &[9, 8, 7])); // preferred symmetric

    let packet = build_signature_packet(0x00, 1, 8, &subpackets, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}

#[test]
fn test_subpacket_zero_length() {
    // Zero-length subpacket should be skipped (continue branch)
    let mut subpackets = Vec::new();
    subpackets.push(0); // Length = 0 (triggers continue)
    subpackets.extend(build_subpacket(2, &[0x60, 0x00, 0x00, 0x00])); // valid subpacket after

    let packet = build_signature_packet(0x00, 1, 8, &subpackets, &[], &build_mpi(8, &[0x01]));
    assert!(parse_bytes(packet).is_ok());
}
