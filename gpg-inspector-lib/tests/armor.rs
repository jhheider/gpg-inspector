//! Tests for armor.rs - ASCII armor decoding

use gpg_inspector_lib::decode_armor;

#[test]
fn test_armor_checksum_mismatch() {
    // Valid base64 but wrong checksum
    let armor = r#"-----BEGIN PGP MESSAGE-----

YWJj
=AAAA
-----END PGP MESSAGE-----"#;
    let result = decode_armor(armor);
    assert!(result.is_err());
    let err = format!("{:?}", result.err().unwrap());
    assert!(err.contains("Checksum"));
}

#[test]
fn test_armor_invalid_base64_char() {
    let armor = r#"-----BEGIN PGP MESSAGE-----

!!!invalid!!!
-----END PGP MESSAGE-----"#;
    let result = decode_armor(armor);
    assert!(result.is_err());
}

#[test]
fn test_armor_whitespace_in_body() {
    // Base64 with whitespace should be handled
    let armor = r#"-----BEGIN PGP MESSAGE-----

YWJj
ZGVm
-----END PGP MESSAGE-----"#;
    let result = decode_armor(armor);
    assert!(result.is_ok());
}

#[test]
fn test_armor_short_checksum() {
    // Checksum with less than 3 bytes decoded
    let armor = r#"-----BEGIN PGP MESSAGE-----

YWJj
=AA
-----END PGP MESSAGE-----"#;
    let result = decode_armor(armor);
    // Should work (checksum too short to validate, or ignored)
    // Just verify it doesn't panic
    let _ = result;
}

#[test]
fn test_armor_multiple_headers() {
    let armor = r#"-----BEGIN PGP MESSAGE-----
Version: Test
Comment: Test comment
Hash: SHA256

YWJj
-----END PGP MESSAGE-----"#;
    let result = decode_armor(armor);
    assert!(result.is_ok());
}
