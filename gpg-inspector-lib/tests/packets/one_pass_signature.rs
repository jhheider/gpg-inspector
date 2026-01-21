//! One-Pass Signature packet tests - Tag 4

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

fn build_one_pass_signature_v3(
    sig_type: u8,
    hash_algo: u8,
    pk_algo: u8,
    key_id: &[u8; 8],
    nested: u8,
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 4); // Tag 4 = One-Pass Signature
    packet.push(13); // Body length: 1 + 1 + 1 + 1 + 8 + 1 = 13

    packet.push(3); // Version 3
    packet.push(sig_type);
    packet.push(hash_algo);
    packet.push(pk_algo);
    packet.extend_from_slice(key_id);
    packet.push(nested);

    packet
}

#[test]
fn test_one_pass_signature_basic() {
    let key_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let packet = build_one_pass_signature_v3(0x00, 8, 1, &key_id, 1); // Binary, SHA-256, RSA

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::OnePassSignature);
}

#[test]
fn test_one_pass_signature_version() {
    let key_id = [0x00; 8];
    let packet = build_one_pass_signature_v3(0x00, 8, 1, &key_id, 1);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let version_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Version");
    assert!(version_field.is_some());
    assert!(version_field.unwrap().value.contains('3'));
}

#[test]
fn test_one_pass_signature_binary_type() {
    let key_id = [0x00; 8];
    let packet = build_one_pass_signature_v3(0x00, 8, 1, &key_id, 1); // Binary document

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let sig_type_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Signature Type");
    assert!(sig_type_field.is_some());
    assert!(sig_type_field.unwrap().value.contains("Binary"));
}

#[test]
fn test_one_pass_signature_text_type() {
    let key_id = [0x00; 8];
    let packet = build_one_pass_signature_v3(0x01, 8, 1, &key_id, 1); // Text document

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let sig_type_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Signature Type");
    assert!(sig_type_field.is_some());
    assert!(sig_type_field.unwrap().value.contains("text"));
}

#[test]
fn test_one_pass_signature_hash_sha256() {
    let key_id = [0x00; 8];
    let packet = build_one_pass_signature_v3(0x00, 8, 1, &key_id, 1); // SHA-256

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let hash_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Hash Algorithm");
    assert!(hash_field.is_some());
    assert!(hash_field.unwrap().value.contains("SHA-256"));
}

#[test]
fn test_one_pass_signature_hash_sha512() {
    let key_id = [0x00; 8];
    let packet = build_one_pass_signature_v3(0x00, 10, 1, &key_id, 1); // SHA-512

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let hash_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Hash Algorithm");
    assert!(hash_field.is_some());
    assert!(hash_field.unwrap().value.contains("SHA-512"));
}

#[test]
fn test_one_pass_signature_rsa() {
    let key_id = [0x00; 8];
    let packet = build_one_pass_signature_v3(0x00, 8, 1, &key_id, 1); // RSA

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let pk_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Public-Key Algorithm");
    assert!(pk_field.is_some());
    assert!(pk_field.unwrap().value.contains("RSA"));
}

#[test]
fn test_one_pass_signature_dsa() {
    let key_id = [0x00; 8];
    let packet = build_one_pass_signature_v3(0x00, 8, 17, &key_id, 1); // DSA

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let pk_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Public-Key Algorithm");
    assert!(pk_field.is_some());
    assert!(pk_field.unwrap().value.contains("DSA"));
}

#[test]
fn test_one_pass_signature_ecdsa() {
    let key_id = [0x00; 8];
    let packet = build_one_pass_signature_v3(0x00, 8, 19, &key_id, 1); // ECDSA

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let pk_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Public-Key Algorithm");
    assert!(pk_field.is_some());
    assert!(pk_field.unwrap().value.contains("ECDSA"));
}

#[test]
fn test_one_pass_signature_key_id() {
    let key_id = [0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A];
    let packet = build_one_pass_signature_v3(0x00, 8, 1, &key_id, 1);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let key_id_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Issuer Key ID");
    assert!(key_id_field.is_some());
    assert!(key_id_field.unwrap().value.contains("ABCDEF"));
}

#[test]
fn test_one_pass_signature_nested_last() {
    let key_id = [0x00; 8];
    let packet = build_one_pass_signature_v3(0x00, 8, 1, &key_id, 1); // nested = 1 = last

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let nested_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Nested");
    assert!(nested_field.is_some());
    assert!(nested_field.unwrap().value.contains("last"));
}

#[test]
fn test_one_pass_signature_nested_more() {
    let key_id = [0x00; 8];
    let packet = build_one_pass_signature_v3(0x00, 8, 1, &key_id, 0); // nested = 0 = more follow

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let nested_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Nested");
    assert!(nested_field.is_some());
    assert!(nested_field.unwrap().value.contains("more"));
}

#[test]
fn test_one_pass_signature_ed25519() {
    let key_id = [0x00; 8];
    let packet = build_one_pass_signature_v3(0x00, 8, 27, &key_id, 1); // Ed25519

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let pk_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Public-Key Algorithm");
    assert!(pk_field.is_some());
    assert!(pk_field.unwrap().value.contains("Ed25519"));
}

// =============================================================================
// Version 6 One-Pass Signature Tests
// =============================================================================

fn build_one_pass_signature_v6(
    sig_type: u8,
    hash_algo: u8,
    pk_algo: u8,
    salt: &[u8],
    fingerprint: &[u8; 32],
    nested: u8,
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 4); // Tag 4 = One-Pass Signature

    // Body length: 1 (version) + 1 (sig type) + 1 (hash) + 1 (pk algo) +
    //              1 (salt len) + salt.len() + 32 (fingerprint) + 1 (nested)
    let body_len = 1 + 1 + 1 + 1 + 1 + salt.len() + 32 + 1;
    packet.push(body_len as u8);

    packet.push(6); // Version 6
    packet.push(sig_type);
    packet.push(hash_algo);
    packet.push(pk_algo);
    packet.push(salt.len() as u8);
    packet.extend_from_slice(salt);
    packet.extend_from_slice(fingerprint);
    packet.push(nested);

    packet
}

#[test]
fn test_one_pass_signature_v6_basic() {
    let salt = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    let fingerprint = [0xAB; 32];
    let packet = build_one_pass_signature_v6(0x00, 8, 27, &salt, &fingerprint, 1);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::OnePassSignature);
}

#[test]
fn test_one_pass_signature_v6_version() {
    let salt = [0x00; 16];
    let fingerprint = [0x00; 32];
    let packet = build_one_pass_signature_v6(0x00, 8, 27, &salt, &fingerprint, 1);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let version_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Version");
    assert!(version_field.is_some());
    assert!(version_field.unwrap().value.contains('6'));
}

#[test]
fn test_one_pass_signature_v6_signature_type() {
    let salt = [0x00; 16];
    let fingerprint = [0x00; 32];
    let packet = build_one_pass_signature_v6(0x00, 8, 27, &salt, &fingerprint, 1);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let sig_type_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Signature Type");
    assert!(sig_type_field.is_some());
    assert!(sig_type_field.unwrap().value.contains("Binary"));
}

#[test]
fn test_one_pass_signature_v6_hash_algorithm() {
    let salt = [0x00; 16];
    let fingerprint = [0x00; 32];
    let packet = build_one_pass_signature_v6(0x00, 10, 27, &salt, &fingerprint, 1); // SHA-512

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let hash_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Hash Algorithm");
    assert!(hash_field.is_some());
    assert!(hash_field.unwrap().value.contains("SHA-512"));
}

#[test]
fn test_one_pass_signature_v6_pk_algorithm() {
    let salt = [0x00; 16];
    let fingerprint = [0x00; 32];
    let packet = build_one_pass_signature_v6(0x00, 8, 27, &salt, &fingerprint, 1); // Ed25519

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let pk_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Public-Key Algorithm");
    assert!(pk_field.is_some());
    assert!(pk_field.unwrap().value.contains("Ed25519"));
}

#[test]
fn test_one_pass_signature_v6_salt_length() {
    let salt = [0xAB; 24];
    let fingerprint = [0x00; 32];
    let packet = build_one_pass_signature_v6(0x00, 8, 27, &salt, &fingerprint, 1);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let salt_len_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Salt Length");
    assert!(salt_len_field.is_some());
    assert!(salt_len_field.unwrap().value.contains("24"));
}

#[test]
fn test_one_pass_signature_v6_salt() {
    let salt = [0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A];
    let fingerprint = [0x00; 32];
    let packet = build_one_pass_signature_v6(0x00, 8, 27, &salt, &fingerprint, 1);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let salt_field = packets[0].fields.iter().find(|f| f.name.as_ref() == "Salt");
    assert!(salt_field.is_some());
    assert!(salt_field.unwrap().value.contains("ABCDEF"));
}

#[test]
fn test_one_pass_signature_v6_fingerprint() {
    let salt = [0x00; 16];
    let mut fingerprint = [0x00; 32];
    fingerprint[0] = 0xDE;
    fingerprint[1] = 0xAD;
    fingerprint[2] = 0xBE;
    fingerprint[3] = 0xEF;
    let packet = build_one_pass_signature_v6(0x00, 8, 27, &salt, &fingerprint, 1);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let fp_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Issuer Fingerprint");
    assert!(fp_field.is_some());
    assert!(fp_field.unwrap().value.contains("DEADBEEF"));
}

#[test]
fn test_one_pass_signature_v6_nested_last() {
    let salt = [0x00; 16];
    let fingerprint = [0x00; 32];
    let packet = build_one_pass_signature_v6(0x00, 8, 27, &salt, &fingerprint, 1);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let nested_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Nested");
    assert!(nested_field.is_some());
    assert!(nested_field.unwrap().value.contains("last"));
}

#[test]
fn test_one_pass_signature_v6_nested_more() {
    let salt = [0x00; 16];
    let fingerprint = [0x00; 32];
    let packet = build_one_pass_signature_v6(0x00, 8, 27, &salt, &fingerprint, 0);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let nested_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Nested");
    assert!(nested_field.is_some());
    assert!(nested_field.unwrap().value.contains("more"));
}

#[test]
fn test_one_pass_signature_v6_empty_salt() {
    let salt: [u8; 0] = [];
    let fingerprint = [0x00; 32];
    let packet = build_one_pass_signature_v6(0x00, 8, 27, &salt, &fingerprint, 1);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let salt_len_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Salt Length");
    assert!(salt_len_field.is_some());
    assert!(salt_len_field.unwrap().value.contains('0'));
}
