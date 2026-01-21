//! Symmetric-Key Encrypted Session Key packet tests - Tag 3

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

// Build SKESK v4 with Simple S2K (type 0)
fn build_skesk_v4_simple(cipher: u8, hash: u8, encrypted_key: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 3); // Tag 3 = SKESK

    let body_len = 1 + 1 + 1 + 1 + encrypted_key.len(); // version + cipher + s2k_type + hash + key
    packet.push(body_len as u8);

    packet.push(4); // Version 4
    packet.push(cipher);
    packet.push(0); // S2K type 0 = Simple
    packet.push(hash);
    packet.extend_from_slice(encrypted_key);

    packet
}

// Build SKESK v4 with Salted S2K (type 1)
fn build_skesk_v4_salted(cipher: u8, hash: u8, salt: &[u8; 8], encrypted_key: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 3); // Tag 3 = SKESK

    let body_len = 1 + 1 + 1 + 1 + 8 + encrypted_key.len();
    packet.push(body_len as u8);

    packet.push(4); // Version 4
    packet.push(cipher);
    packet.push(1); // S2K type 1 = Salted
    packet.push(hash);
    packet.extend_from_slice(salt);
    packet.extend_from_slice(encrypted_key);

    packet
}

// Build SKESK v4 with Iterated S2K (type 3)
fn build_skesk_v4_iterated(
    cipher: u8,
    hash: u8,
    salt: &[u8; 8],
    count: u8,
    encrypted_key: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 3); // Tag 3 = SKESK

    let body_len = 1 + 1 + 1 + 1 + 8 + 1 + encrypted_key.len();
    packet.push(body_len as u8);

    packet.push(4); // Version 4
    packet.push(cipher);
    packet.push(3); // S2K type 3 = Iterated
    packet.push(hash);
    packet.extend_from_slice(salt);
    packet.push(count);
    packet.extend_from_slice(encrypted_key);

    packet
}

// Build SKESK v4 with Argon2 S2K (type 4)
fn build_skesk_v4_argon2(
    cipher: u8,
    salt: &[u8; 16],
    t: u8,
    m: u8,
    p: u8,
    encrypted_key: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 3); // Tag 3 = SKESK

    let body_len = 1 + 1 + 1 + 16 + 1 + 1 + 1 + encrypted_key.len();
    packet.push(body_len as u8);

    packet.push(4); // Version 4
    packet.push(cipher);
    packet.push(4); // S2K type 4 = Argon2
    packet.extend_from_slice(salt);
    packet.push(t); // parallelism
    packet.push(m); // memory
    packet.push(p); // iterations
    packet.extend_from_slice(encrypted_key);

    packet
}

#[test]
fn test_skesk_v4_simple_s2k() {
    let packet = build_skesk_v4_simple(9, 8, &[0xAB, 0xCD]); // AES-256, SHA-256

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::SymmetricKeyEncryptedSessionKey);
}

#[test]
fn test_skesk_v4_version() {
    let packet = build_skesk_v4_simple(9, 8, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let version_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Version");
    assert!(version_field.is_some());
    assert!(version_field.unwrap().value.contains('4'));
}

#[test]
fn test_skesk_v4_cipher_aes256() {
    let packet = build_skesk_v4_simple(9, 8, &[]);

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
fn test_skesk_v4_cipher_aes128() {
    let packet = build_skesk_v4_simple(7, 8, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let cipher_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Cipher Algorithm");
    assert!(cipher_field.is_some());
    assert!(cipher_field.unwrap().value.contains("AES-128"));
}

#[test]
fn test_skesk_v4_simple_s2k_type() {
    let packet = build_skesk_v4_simple(9, 8, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let s2k_type_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "S2K Type");
    assert!(s2k_type_field.is_some());
    assert!(s2k_type_field.unwrap().value.contains("Simple"));
}

#[test]
fn test_skesk_v4_simple_s2k_hash() {
    let packet = build_skesk_v4_simple(9, 10, &[]); // SHA-512

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let hash_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "S2K Hash");
    assert!(hash_field.is_some());
    assert!(hash_field.unwrap().value.contains("SHA-512"));
}

#[test]
fn test_skesk_v4_salted_s2k() {
    let salt = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let packet = build_skesk_v4_salted(9, 8, &salt, &[0xAB, 0xCD]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let s2k_type_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "S2K Type");
    assert!(s2k_type_field.is_some());
    assert!(s2k_type_field.unwrap().value.contains("Salted"));
}

#[test]
fn test_skesk_v4_salted_s2k_salt_displayed() {
    let salt = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let packet = build_skesk_v4_salted(9, 8, &salt, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let salt_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "S2K Salt");
    assert!(salt_field.is_some());
    assert!(salt_field.unwrap().value.contains("AABBCCDD"));
}

#[test]
fn test_skesk_v4_iterated_s2k() {
    let salt = [0x00; 8];
    let packet = build_skesk_v4_iterated(9, 8, &salt, 0xFF, &[]); // Max iterations

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let s2k_type_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "S2K Type");
    assert!(s2k_type_field.is_some());
    assert!(s2k_type_field.unwrap().value.contains("Iterated"));
}

#[test]
fn test_skesk_v4_iterated_s2k_iterations() {
    let salt = [0x00; 8];
    // count = 0x60 -> (16 + 0) << (6 + 6) = 16 << 12 = 65536
    let packet = build_skesk_v4_iterated(9, 8, &salt, 0x60, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let iterations_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "S2K Iterations");
    assert!(iterations_field.is_some());
    assert!(iterations_field.unwrap().value.contains("65536"));
}

#[test]
fn test_skesk_v4_argon2_s2k() {
    let salt = [0x00; 16];
    let packet = build_skesk_v4_argon2(9, &salt, 4, 19, 3, &[]); // t=4, m=2^19, p=3

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let s2k_type_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "S2K Type");
    assert!(s2k_type_field.is_some());
    assert!(s2k_type_field.unwrap().value.contains("Argon2"));
}

#[test]
fn test_skesk_v4_argon2_parallelism() {
    let salt = [0x00; 16];
    let packet = build_skesk_v4_argon2(9, &salt, 4, 19, 3, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let t_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Argon2 Parallelism (t)");
    assert!(t_field.is_some());
    assert!(t_field.unwrap().value.contains('4'));
}

#[test]
fn test_skesk_v4_argon2_memory() {
    let salt = [0x00; 16];
    let packet = build_skesk_v4_argon2(9, &salt, 4, 19, 3, &[]); // m=19 -> 2^19 = 524288 KiB

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let m_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Argon2 Memory (m)");
    assert!(m_field.is_some());
    assert!(m_field.unwrap().value.contains("524288"));
}

#[test]
fn test_skesk_v4_argon2_iterations() {
    let salt = [0x00; 16];
    let packet = build_skesk_v4_argon2(9, &salt, 4, 19, 3, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let p_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Argon2 Iterations (p)");
    assert!(p_field.is_some());
    assert!(p_field.unwrap().value.contains('3'));
}

#[test]
fn test_skesk_v4_with_encrypted_key() {
    let packet = build_skesk_v4_simple(9, 8, &[0x11, 0x22, 0x33, 0x44, 0x55]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let key_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Encrypted Session Key");
    assert!(key_field.is_some());
    assert!(key_field.unwrap().value.contains("5 bytes"));
}

#[test]
fn test_skesk_v4_no_encrypted_key() {
    let packet = build_skesk_v4_simple(9, 8, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let key_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Session Key");
    assert!(key_field.is_some());
    assert!(key_field.unwrap().value.contains("Derived"));
}

#[test]
fn test_skesk_v4_cast5() {
    let packet = build_skesk_v4_simple(3, 8, &[]); // CAST5

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let cipher_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Cipher Algorithm");
    assert!(cipher_field.is_some());
    assert!(cipher_field.unwrap().value.contains("CAST5"));
}

#[test]
fn test_skesk_v4_twofish() {
    let packet = build_skesk_v4_simple(10, 8, &[]); // Twofish

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let cipher_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Cipher Algorithm");
    assert!(cipher_field.is_some());
    assert!(cipher_field.unwrap().value.contains("Twofish"));
}

// =============================================================================
// SKESK v6 Tests (RFC 9580 AEAD mode)
// =============================================================================

/// Build SKESK v6 with Iterated S2K (type 3) and AEAD
fn build_skesk_v6(
    cipher: u8,
    aead: u8,
    s2k_type: u8,
    hash: u8,
    salt: &[u8; 8],
    count: u8,
    iv: &[u8],
    encrypted_key: &[u8],
    auth_tag: &[u8; 16],
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 3); // Tag 3 = SKESK

    // S2K info: type(1) + hash(1) + salt(8) + count(1) = 11 bytes for iterated
    let s2k_len = 1 + 1 + 8 + 1;
    let info_len = 1 + 1 + s2k_len; // cipher + aead + s2k_len

    // v6 format: version(1) + count(1) + cipher(1) + aead(1) + s2k_len(1) + s2k + iv + esk + tag
    let actual_body_len = 1 + 1 + 1 + 1 + 1 + s2k_len + iv.len() + encrypted_key.len() + 16;

    packet.push(actual_body_len as u8);
    packet.push(6); // Version 6
    packet.push(info_len as u8); // S2K + Cipher Info Length
    packet.push(cipher);
    packet.push(aead);
    packet.push(s2k_len as u8); // S2K length

    // S2K specifier (Iterated)
    packet.push(s2k_type);
    packet.push(hash);
    packet.extend_from_slice(salt);
    packet.push(count);

    // IV
    packet.extend_from_slice(iv);

    // Encrypted session key
    packet.extend_from_slice(encrypted_key);

    // Auth tag
    packet.extend_from_slice(auth_tag);

    packet
}

/// Build SKESK v6 with Argon2 S2K (type 4)
fn build_skesk_v6_argon2(
    cipher: u8,
    aead: u8,
    argon_salt: &[u8; 16],
    t: u8,
    m: u8,
    p: u8,
    iv: &[u8],
    encrypted_key: &[u8],
    auth_tag: &[u8; 16],
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 3); // Tag 3 = SKESK

    // S2K info for Argon2: type(1) + salt(16) + t(1) + m(1) + p(1) = 20 bytes
    let s2k_len = 1 + 16 + 1 + 1 + 1;
    let info_len = 1 + 1 + s2k_len; // cipher + aead + s2k_len

    let actual_body_len = 1 + 1 + 1 + 1 + 1 + s2k_len + iv.len() + encrypted_key.len() + 16;

    packet.push(actual_body_len as u8);
    packet.push(6); // Version 6
    packet.push(info_len as u8);
    packet.push(cipher);
    packet.push(aead);
    packet.push(s2k_len as u8);

    // S2K specifier (Argon2)
    packet.push(4); // S2K type 4 = Argon2
    packet.extend_from_slice(argon_salt);
    packet.push(t);
    packet.push(m);
    packet.push(p);

    packet.extend_from_slice(iv);
    packet.extend_from_slice(encrypted_key);
    packet.extend_from_slice(auth_tag);

    packet
}

#[test]
fn test_skesk_v6_basic() {
    let salt = [0x11; 8];
    let iv = [0x00; 16]; // EAX IV
    let auth_tag = [0xAB; 16];
    let packet = build_skesk_v6(9, 1, 3, 8, &salt, 0x60, &iv, &[0xCD; 32], &auth_tag);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::SymmetricKeyEncryptedSessionKey);
}

#[test]
fn test_skesk_v6_version() {
    let salt = [0x00; 8];
    let iv = [0x00; 16];
    let auth_tag = [0x00; 16];
    let packet = build_skesk_v6(9, 1, 3, 8, &salt, 0x60, &iv, &[], &auth_tag);

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
fn test_skesk_v6_aead_eax() {
    let salt = [0x00; 8];
    let iv = [0x00; 16];
    let auth_tag = [0x00; 16];
    let packet = build_skesk_v6(9, 1, 3, 8, &salt, 0x60, &iv, &[], &auth_tag); // AEAD 1 = EAX

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let aead_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "AEAD Algorithm");
    assert!(aead_field.is_some());
    assert!(aead_field.unwrap().value.contains("EAX"));
}

#[test]
fn test_skesk_v6_aead_ocb() {
    let salt = [0x00; 8];
    let iv = [0x00; 15]; // OCB uses 15-byte IV
    let auth_tag = [0x00; 16];
    let packet = build_skesk_v6(9, 2, 3, 8, &salt, 0x60, &iv, &[], &auth_tag); // AEAD 2 = OCB

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
fn test_skesk_v6_aead_gcm() {
    let salt = [0x00; 8];
    let iv = [0x00; 12]; // GCM uses 12-byte IV
    let auth_tag = [0x00; 16];
    let packet = build_skesk_v6(9, 3, 3, 8, &salt, 0x60, &iv, &[], &auth_tag); // AEAD 3 = GCM

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
fn test_skesk_v6_cipher_algorithm() {
    let salt = [0x00; 8];
    let iv = [0x00; 16];
    let auth_tag = [0x00; 16];
    let packet = build_skesk_v6(9, 1, 3, 8, &salt, 0x60, &iv, &[], &auth_tag); // Cipher 9 = AES-256

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
fn test_skesk_v6_s2k_length() {
    let salt = [0x00; 8];
    let iv = [0x00; 16];
    let auth_tag = [0x00; 16];
    let packet = build_skesk_v6(9, 1, 3, 8, &salt, 0x60, &iv, &[], &auth_tag);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let s2k_len_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "S2K Length");
    assert!(s2k_len_field.is_some());
}

#[test]
fn test_skesk_v6_iv_field() {
    let salt = [0x00; 8];
    let iv = [
        0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
        0x55,
    ];
    let auth_tag = [0x00; 16];
    let packet = build_skesk_v6(9, 1, 3, 8, &salt, 0x60, &iv, &[], &auth_tag);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let iv_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "IV/Nonce");
    assert!(iv_field.is_some());
    assert!(iv_field.unwrap().value.contains("16 bytes"));
}

#[test]
fn test_skesk_v6_encrypted_session_key() {
    let salt = [0x00; 8];
    let iv = [0x00; 16];
    let auth_tag = [0x00; 16];
    let encrypted_key = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    let packet = build_skesk_v6(9, 1, 3, 8, &salt, 0x60, &iv, &encrypted_key, &auth_tag);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let esk_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Encrypted Session Key");
    assert!(esk_field.is_some());
    assert!(esk_field.unwrap().value.contains("6 bytes"));
}

#[test]
fn test_skesk_v6_auth_tag() {
    let salt = [0x00; 8];
    let iv = [0x00; 16];
    let auth_tag = [0xFF; 16];
    let packet = build_skesk_v6(9, 1, 3, 8, &salt, 0x60, &iv, &[0x00; 16], &auth_tag);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let tag_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Authentication Tag");
    assert!(tag_field.is_some());
    assert!(tag_field.unwrap().value.contains("16 bytes"));
}

#[test]
fn test_skesk_v6_argon2() {
    let argon_salt = [0x12; 16];
    let iv = [0x00; 16];
    let auth_tag = [0x00; 16];
    let packet = build_skesk_v6_argon2(9, 1, &argon_salt, 4, 19, 3, &iv, &[0xAB; 32], &auth_tag);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let s2k_type_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "S2K Type");
    assert!(s2k_type_field.is_some());
    assert!(s2k_type_field.unwrap().value.contains("Argon2"));
}

// =============================================================================
// Unknown S2K Type Test
// =============================================================================

/// Build SKESK v4 with unknown S2K type
fn build_skesk_v4_unknown_s2k(cipher: u8, s2k_type: u8) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 3); // Tag 3 = SKESK

    let body_len = 1 + 1 + 1; // version + cipher + s2k_type
    packet.push(body_len as u8);

    packet.push(4); // Version 4
    packet.push(cipher);
    packet.push(s2k_type); // Unknown S2K type

    packet
}

#[test]
fn test_skesk_v4_unknown_s2k_type() {
    let packet = build_skesk_v4_unknown_s2k(9, 99); // Unknown S2K type 99

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::SymmetricKeyEncryptedSessionKey);

    // Should still parse, but S2K type will be listed as unknown
    let s2k_type_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "S2K Type");
    assert!(s2k_type_field.is_some());
}

#[test]
fn test_skesk_v4_s2k_type_2() {
    // S2K type 2 is reserved/unknown
    let packet = build_skesk_v4_unknown_s2k(9, 2);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::SymmetricKeyEncryptedSessionKey);
}

#[test]
fn test_skesk_unknown_version_fallback() {
    // Unknown version (e.g., 99) should fall back to v4 parsing
    let mut packet = Vec::new();
    packet.push(0xC0 | 3); // Tag 3 = SKESK

    let body_len = 1 + 1 + 1 + 1; // version + cipher + s2k_type + hash
    packet.push(body_len as u8);

    packet.push(99); // Unknown version 99
    packet.push(9); // AES-256
    packet.push(0); // Simple S2K
    packet.push(8); // SHA-256

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::SymmetricKeyEncryptedSessionKey);

    // Should still show version 99
    let version_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Version");
    assert!(version_field.is_some());
    assert!(version_field.unwrap().value.contains("99"));
}

#[test]
fn test_skesk_v6_unknown_aead_algorithm() {
    // Unknown AEAD algorithm (99) should use default 16-byte IV
    let salt = [0x00; 8];
    let iv = [0x00; 16]; // Default IV length for unknown AEAD
    let auth_tag = [0x00; 16];

    // Build v6 with unknown AEAD algorithm
    let mut packet = Vec::new();
    packet.push(0xC0 | 3); // Tag 3 = SKESK

    let s2k_len = 1 + 1 + 8 + 1; // type + hash + salt + count
    let info_len = 1 + 1 + s2k_len; // cipher + aead + s2k_len
    let actual_body_len = 1 + 1 + 1 + 1 + 1 + s2k_len + 16 + 0 + 16;

    packet.push(actual_body_len as u8);
    packet.push(6); // Version 6
    packet.push(info_len as u8);
    packet.push(9); // AES-256
    packet.push(99); // Unknown AEAD algorithm
    packet.push(s2k_len as u8);
    packet.push(3); // Iterated S2K
    packet.push(8); // SHA-256
    packet.extend_from_slice(&salt);
    packet.push(0x60); // iterations
    packet.extend_from_slice(&iv);
    packet.extend_from_slice(&auth_tag);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();

    let aead_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "AEAD Algorithm");
    assert!(aead_field.is_some());
    // Should show unknown algorithm
    assert!(aead_field.unwrap().value.contains("99"));
}

#[test]
fn test_skesk_v6_no_auth_tag() {
    // V6 packet where remaining bytes after ESK is 0, resulting in no auth tag
    let salt = [0x00; 8];
    let iv = [0x00; 16];

    let mut packet = Vec::new();
    packet.push(0xC0 | 3); // Tag 3 = SKESK

    let s2k_len = 1 + 1 + 8 + 1;
    let info_len = 1 + 1 + s2k_len;
    // Body: version + info_len + cipher + aead + s2k_len + s2k + iv + NO ESK + NO auth tag
    let actual_body_len = 1 + 1 + 1 + 1 + 1 + s2k_len + 16;

    packet.push(actual_body_len as u8);
    packet.push(6); // Version 6
    packet.push(info_len as u8);
    packet.push(9); // AES-256
    packet.push(1); // EAX
    packet.push(s2k_len as u8);
    packet.push(3); // Iterated S2K
    packet.push(8); // SHA-256
    packet.extend_from_slice(&salt);
    packet.push(0x60);
    packet.extend_from_slice(&iv);
    // No encrypted session key, no auth tag

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::SymmetricKeyEncryptedSessionKey);

    // Should not have an Authentication Tag field
    let tag_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Authentication Tag");
    assert!(tag_field.is_none());
}
