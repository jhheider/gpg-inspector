//! Tests for lookup.rs - algorithm and type lookups

use gpg_inspector_lib::lookup::*;

// ============================================================================
// Public Key Algorithm - all branches
// ============================================================================

#[test]
fn test_public_key_algorithm_all_values() {
    // Known values
    assert!(lookup_public_key_algorithm(1).name.contains("RSA"));
    assert!(lookup_public_key_algorithm(2).name.contains("RSA Encrypt"));
    assert!(lookup_public_key_algorithm(3).name.contains("RSA Sign"));
    assert!(lookup_public_key_algorithm(16).name.contains("Elgamal"));
    assert!(lookup_public_key_algorithm(17).name.contains("DSA"));
    assert!(lookup_public_key_algorithm(18).name.contains("ECDH"));
    assert!(lookup_public_key_algorithm(19).name.contains("ECDSA"));
    assert!(lookup_public_key_algorithm(20).name.contains("Reserved"));
    assert!(
        lookup_public_key_algorithm(21)
            .name
            .contains("Diffie-Hellman")
    );
    assert!(lookup_public_key_algorithm(22).name.contains("EdDSA"));
    assert!(lookup_public_key_algorithm(23).name.contains("AEDH"));
    assert!(lookup_public_key_algorithm(24).name.contains("AEDSA"));
    assert!(lookup_public_key_algorithm(25).name.contains("X25519"));
    assert!(lookup_public_key_algorithm(26).name.contains("X448"));
    assert!(lookup_public_key_algorithm(27).name.contains("Ed25519"));
    assert!(lookup_public_key_algorithm(28).name.contains("Ed448"));

    // Private/Experimental range
    for id in 100..=110 {
        assert!(lookup_public_key_algorithm(id).name.contains("Private"));
    }

    // Unknown
    assert!(lookup_public_key_algorithm(99).name.contains("Unknown"));
    assert!(lookup_public_key_algorithm(200).name.contains("Unknown"));
}

// ============================================================================
// Symmetric Algorithm - all branches
// ============================================================================

#[test]
fn test_symmetric_algorithm_all_values() {
    assert!(lookup_symmetric_algorithm(0).name.contains("Plaintext"));
    assert!(lookup_symmetric_algorithm(1).name.contains("IDEA"));
    assert!(lookup_symmetric_algorithm(2).name.contains("TripleDES"));
    assert!(lookup_symmetric_algorithm(3).name.contains("CAST5"));
    assert!(lookup_symmetric_algorithm(4).name.contains("Blowfish"));
    assert!(lookup_symmetric_algorithm(5).name.contains("Reserved"));
    assert!(lookup_symmetric_algorithm(6).name.contains("Reserved"));
    assert!(lookup_symmetric_algorithm(7).name.contains("AES-128"));
    assert!(lookup_symmetric_algorithm(8).name.contains("AES-192"));
    assert!(lookup_symmetric_algorithm(9).name.contains("AES-256"));
    assert!(lookup_symmetric_algorithm(10).name.contains("Twofish"));
    assert!(lookup_symmetric_algorithm(11).name.contains("Camellia-128"));
    assert!(lookup_symmetric_algorithm(12).name.contains("Camellia-192"));
    assert!(lookup_symmetric_algorithm(13).name.contains("Camellia-256"));

    // Private range
    for id in 100..=110 {
        assert!(lookup_symmetric_algorithm(id).name.contains("Private"));
    }

    // Unknown
    assert!(lookup_symmetric_algorithm(99).name.contains("Unknown"));
}

// ============================================================================
// Hash Algorithm - all branches
// ============================================================================

#[test]
fn test_hash_algorithm_all_values() {
    assert!(lookup_hash_algorithm(1).name.contains("MD5"));
    assert!(lookup_hash_algorithm(2).name.contains("SHA-1"));
    assert!(lookup_hash_algorithm(3).name.contains("RIPEMD"));
    assert!(lookup_hash_algorithm(4).name.contains("Reserved"));
    assert!(lookup_hash_algorithm(5).name.contains("Reserved"));
    assert!(lookup_hash_algorithm(6).name.contains("Reserved"));
    assert!(lookup_hash_algorithm(7).name.contains("Reserved"));
    assert!(lookup_hash_algorithm(8).name.contains("SHA-256"));
    assert!(lookup_hash_algorithm(9).name.contains("SHA-384"));
    assert!(lookup_hash_algorithm(10).name.contains("SHA-512"));
    assert!(lookup_hash_algorithm(11).name.contains("SHA-224"));
    assert!(lookup_hash_algorithm(12).name.contains("SHA3-256"));
    assert!(lookup_hash_algorithm(13).name.contains("Reserved"));
    assert!(lookup_hash_algorithm(14).name.contains("SHA3-512"));

    // Private range
    for id in 100..=110 {
        assert!(lookup_hash_algorithm(id).name.contains("Private"));
    }

    // Unknown
    assert!(lookup_hash_algorithm(99).name.contains("Unknown"));
}

// ============================================================================
// Compression Algorithm - all branches
// ============================================================================

#[test]
fn test_compression_algorithm_all_values() {
    assert!(
        lookup_compression_algorithm(0)
            .name
            .contains("Uncompressed")
    );
    assert!(lookup_compression_algorithm(1).name.contains("ZIP"));
    assert!(lookup_compression_algorithm(2).name.contains("ZLIB"));
    assert!(lookup_compression_algorithm(3).name.contains("BZip2"));

    // Private range
    for id in 100..=110 {
        assert!(lookup_compression_algorithm(id).name.contains("Private"));
    }

    // Unknown
    assert!(lookup_compression_algorithm(99).name.contains("Unknown"));
}

// ============================================================================
// Signature Type - all branches
// ============================================================================

#[test]
fn test_signature_type_all_values() {
    assert!(lookup_signature_type(0x00).name.contains("Binary"));
    assert!(lookup_signature_type(0x01).name.contains("Canonical"));
    assert!(lookup_signature_type(0x02).name.contains("Standalone"));
    assert!(lookup_signature_type(0x10).name.contains("Generic"));
    assert!(lookup_signature_type(0x11).name.contains("Persona"));
    assert!(lookup_signature_type(0x12).name.contains("Casual"));
    assert!(lookup_signature_type(0x13).name.contains("Positive"));
    assert!(lookup_signature_type(0x18).name.contains("Subkey Binding"));
    assert!(lookup_signature_type(0x19).name.contains("Primary Key"));
    assert!(lookup_signature_type(0x1F).name.contains("Direct"));
    assert!(lookup_signature_type(0x20).name.contains("Key revocation"));
    assert!(
        lookup_signature_type(0x28)
            .name
            .contains("Subkey revocation")
    );
    assert!(
        lookup_signature_type(0x30)
            .name
            .contains("Certification revocation")
    );
    assert!(lookup_signature_type(0x40).name.contains("Timestamp"));
    assert!(lookup_signature_type(0x50).name.contains("Third-Party"));

    // Unknown
    assert!(lookup_signature_type(0xFF).name.contains("Unknown"));
}

// ============================================================================
// Subpacket Type - all branches
// ============================================================================

#[test]
fn test_subpacket_type_all_values() {
    assert!(lookup_subpacket_type(0).name.contains("Reserved"));
    assert!(lookup_subpacket_type(1).name.contains("Reserved"));
    assert!(lookup_subpacket_type(2).name.contains("Creation Time"));
    assert!(lookup_subpacket_type(3).name.contains("Expiration"));
    assert!(lookup_subpacket_type(4).name.contains("Exportable"));
    assert!(lookup_subpacket_type(5).name.contains("Trust"));
    assert!(lookup_subpacket_type(6).name.contains("Regular Expression"));
    assert!(lookup_subpacket_type(7).name.contains("Revocable"));
    assert!(lookup_subpacket_type(8).name.contains("Reserved"));
    assert!(lookup_subpacket_type(9).name.contains("Key Expiration"));
    assert!(lookup_subpacket_type(10).name.contains("backward"));
    assert!(lookup_subpacket_type(11).name.contains("Symmetric"));
    assert!(lookup_subpacket_type(12).name.contains("Revocation Key"));
    assert!(lookup_subpacket_type(13).name.contains("Reserved"));
    assert!(lookup_subpacket_type(14).name.contains("Reserved"));
    assert!(lookup_subpacket_type(15).name.contains("Reserved"));
    assert!(lookup_subpacket_type(16).name.contains("Issuer"));
    assert!(lookup_subpacket_type(17).name.contains("Reserved"));
    assert!(lookup_subpacket_type(18).name.contains("Reserved"));
    assert!(lookup_subpacket_type(19).name.contains("Reserved"));
    assert!(lookup_subpacket_type(20).name.contains("Notation"));
    assert!(lookup_subpacket_type(21).name.contains("Hash"));
    assert!(lookup_subpacket_type(22).name.contains("Compression"));
    assert!(
        lookup_subpacket_type(23)
            .name
            .contains("Key Server Preferences")
    );
    assert!(
        lookup_subpacket_type(24)
            .name
            .contains("Preferred Key Server")
    );
    assert!(lookup_subpacket_type(25).name.contains("Primary User"));
    assert!(lookup_subpacket_type(26).name.contains("Policy"));
    assert!(lookup_subpacket_type(27).name.contains("Key Flags"));
    assert!(lookup_subpacket_type(28).name.contains("Signer"));
    assert!(lookup_subpacket_type(29).name.contains("Revocation"));
    assert!(lookup_subpacket_type(30).name.contains("Features"));
    assert!(lookup_subpacket_type(31).name.contains("Target"));
    assert!(lookup_subpacket_type(32).name.contains("Embedded"));
    assert!(lookup_subpacket_type(33).name.contains("Fingerprint"));
    assert!(lookup_subpacket_type(34).name.contains("AEAD"));
    assert!(lookup_subpacket_type(35).name.contains("Intended"));
    assert!(lookup_subpacket_type(37).name.contains("Attested"));
    assert!(lookup_subpacket_type(38).name.contains("Key Block"));
    assert!(lookup_subpacket_type(39).name.contains("Ciphersuites"));

    // Private range
    for id in 100..=110 {
        assert!(lookup_subpacket_type(id).name.contains("Private"));
    }

    // Unknown
    assert!(lookup_subpacket_type(99).name.contains("Unknown"));
}

// ============================================================================
// Curve OID - all branches
// ============================================================================

#[test]
fn test_curve_oid_all_values() {
    assert!(lookup_curve_oid(&[0x2B, 0x81, 0x04, 0x00, 0x22]).contains("P-384"));
    assert!(lookup_curve_oid(&[0x2B, 0x81, 0x04, 0x00, 0x23]).contains("P-521"));
    assert!(lookup_curve_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]).contains("P-256"));
    assert!(
        lookup_curve_oid(&[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07])
            .contains("brainpoolP256")
    );
    assert!(
        lookup_curve_oid(&[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B])
            .contains("brainpoolP384")
    );
    assert!(
        lookup_curve_oid(&[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D])
            .contains("brainpoolP512")
    );
    assert!(
        lookup_curve_oid(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])
            .contains("Ed25519")
    );
    assert!(
        lookup_curve_oid(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01])
            .contains("Curve25519")
    );

    // Unknown OID
    let unknown = lookup_curve_oid(&[0x01, 0x02, 0x03]);
    assert!(unknown.contains("Unknown"));
    assert!(unknown.contains("010203")); // Hex representation
}

// ============================================================================
// Key Flags - all branches
// ============================================================================

#[test]
fn test_key_flags_all_bits() {
    let flags_01 = lookup_key_flags(0x01);
    assert!(flags_01.contains(&"Certify"));

    let flags_02 = lookup_key_flags(0x02);
    assert!(flags_02.contains(&"Sign"));

    let flags_04 = lookup_key_flags(0x04);
    assert!(flags_04.contains(&"Encrypt Communications"));

    let flags_08 = lookup_key_flags(0x08);
    assert!(flags_08.contains(&"Encrypt Storage"));

    let flags_10 = lookup_key_flags(0x10);
    assert!(flags_10.contains(&"Split Key"));

    let flags_20 = lookup_key_flags(0x20);
    assert!(flags_20.contains(&"Authentication"));

    let flags_80 = lookup_key_flags(0x80);
    assert!(flags_80.contains(&"Shared Key"));

    // Multiple flags
    let flags_ff = lookup_key_flags(0xFF);
    assert!(flags_ff.len() >= 7);

    // No flags
    let flags_00 = lookup_key_flags(0x00);
    assert!(flags_00.is_empty());
}

// ============================================================================
// Revocation Reason - all branches
// ============================================================================

#[test]
fn test_revocation_reason_all_values() {
    assert!(lookup_revocation_reason(0).contains("No reason"));
    assert!(lookup_revocation_reason(1).contains("superseded"));
    assert!(lookup_revocation_reason(2).contains("compromised"));
    assert!(lookup_revocation_reason(3).contains("retired"));
    assert!(lookup_revocation_reason(32).contains("no longer valid"));
    assert!(lookup_revocation_reason(99).contains("Unknown"));
}

// ============================================================================
// S2K Type - all branches
// ============================================================================

#[test]
fn test_s2k_type_all_values() {
    assert!(lookup_s2k_type(0).contains("Simple"));
    assert!(lookup_s2k_type(1).contains("Salted"));
    assert!(lookup_s2k_type(2).contains("Reserved"));
    assert!(lookup_s2k_type(3).contains("Iterated"));
    assert!(lookup_s2k_type(4).contains("Argon2"));

    // Private range
    for id in 100..=110 {
        assert!(lookup_s2k_type(id).contains("Private"));
    }

    // Unknown
    assert!(lookup_s2k_type(99).contains("Unknown"));
}

// ============================================================================
// AEAD Algorithm - all branches
// ============================================================================

#[test]
fn test_aead_algorithm_all_values() {
    assert!(lookup_aead_algorithm(0).name.contains("Reserved"));
    assert!(lookup_aead_algorithm(1).name.contains("EAX"));
    assert!(lookup_aead_algorithm(2).name.contains("OCB"));
    assert!(lookup_aead_algorithm(3).name.contains("GCM"));

    // Private range
    for id in 100..=110 {
        assert!(lookup_aead_algorithm(id).name.contains("Private"));
    }

    // Unknown
    assert!(lookup_aead_algorithm(99).name.contains("Unknown"));
}

// ============================================================================
// V6 Signature Salt Length - all branches
// ============================================================================

#[test]
fn test_v6_signature_salt_len() {
    // SHA-256: 16 bytes
    assert_eq!(get_v6_signature_salt_len(8), 16);
    // SHA3-256: 16 bytes
    assert_eq!(get_v6_signature_salt_len(12), 16);
    // SHA-384: 24 bytes
    assert_eq!(get_v6_signature_salt_len(9), 24);
    // SHA-512: 32 bytes
    assert_eq!(get_v6_signature_salt_len(10), 32);
    // SHA3-512: 32 bytes
    assert_eq!(get_v6_signature_salt_len(14), 32);
    // Unknown/other: defaults to 16 bytes
    assert_eq!(get_v6_signature_salt_len(1), 16); // MD5
    assert_eq!(get_v6_signature_salt_len(2), 16); // SHA-1
    assert_eq!(get_v6_signature_salt_len(99), 16); // Unknown
}

// ============================================================================
// Raw Signature Length - all branches
// ============================================================================

#[test]
fn test_raw_signature_len() {
    // Ed25519: 64 bytes
    assert_eq!(get_raw_signature_len(27), Some(64));
    // Ed448: 114 bytes
    assert_eq!(get_raw_signature_len(28), Some(114));
    // Other algorithms use MPI-encoded signatures
    assert_eq!(get_raw_signature_len(1), None); // RSA
    assert_eq!(get_raw_signature_len(17), None); // DSA
    assert_eq!(get_raw_signature_len(19), None); // ECDSA
    assert_eq!(get_raw_signature_len(22), None); // EdDSA (legacy)
    assert_eq!(get_raw_signature_len(25), None); // X25519 (encryption only)
    assert_eq!(get_raw_signature_len(26), None); // X448 (encryption only)
}
