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

// Multi-block armor tests

use gpg_inspector_lib::{decode_armor_multi, looks_binary};

const TEST_KEY: &str = include_str!("../../fixtures/test.key");
const TEST_CLEARTEXT: &str = include_str!("../../fixtures/test.cleartext.asc");

#[test]
fn test_multi_single_block_matches_decode_armor() {
    let single = decode_armor(TEST_KEY).unwrap();
    let multi = decode_armor_multi(TEST_KEY).unwrap();

    assert_eq!(&multi.bytes[..], &single.bytes[..]);
    assert_eq!(multi.blocks.len(), 1);
    assert_eq!(multi.blocks[0].armor_type.as_ref(), "PGP PUBLIC KEY BLOCK");
    assert_eq!(multi.blocks[0].range, (0, single.bytes.len()));
    assert!(multi.cleartext.is_none());
}

#[test]
fn test_multi_two_blocks_concatenated() {
    let single = decode_armor(TEST_KEY).unwrap();
    let two = format!("{}\n{}", TEST_KEY, TEST_KEY);
    let multi = decode_armor_multi(&two).unwrap();

    let len = single.bytes.len();
    assert_eq!(multi.blocks.len(), 2);
    assert_eq!(multi.bytes.len(), 2 * len);
    assert_eq!(multi.blocks[0].range, (0, len));
    assert_eq!(multi.blocks[1].range, (len, 2 * len));
    assert_eq!(&multi.bytes[..len], &multi.bytes[len..]);
}

#[test]
fn test_multi_no_blocks_errors() {
    let result = decode_armor_multi("no armor here at all");
    assert!(result.is_err());
    let err = format!("{:?}", result.err().unwrap());
    assert!(err.contains("Missing BEGIN"));
}

#[test]
fn test_multi_bad_second_block_errors() {
    let two = format!(
        "{}\n-----BEGIN PGP MESSAGE-----\n\n!!!bad!!!\n-----END PGP MESSAGE-----",
        TEST_KEY
    );
    assert!(decode_armor_multi(&two).is_err());
}

// Cleartext signed message tests

#[test]
fn test_cleartext_signed_message() {
    let multi = decode_armor_multi(TEST_CLEARTEXT).unwrap();

    // Dash-escaped line is unescaped
    let cleartext = multi.cleartext.expect("cleartext missing");
    assert_eq!(cleartext.as_ref(), "Hello, world\n-----dash escaped");

    // The trailing signature block decodes normally
    assert_eq!(multi.blocks.len(), 1);
    assert_eq!(multi.blocks[0].armor_type.as_ref(), "PGP SIGNATURE");
    assert!(!multi.bytes.is_empty());
}

#[test]
fn test_cleartext_missing_signature_block_errors() {
    let input = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nHello\n";
    let result = decode_armor_multi(input);
    assert!(result.is_err());
    let err = format!("{:?}", result.err().unwrap());
    assert!(err.contains("missing signature block"));
}

#[test]
fn test_cleartext_no_headers() {
    // A cleartext section with no Hash: headers still parses
    let sig_block = TEST_CLEARTEXT
        .split_once("-----BEGIN PGP SIGNATURE-----")
        .unwrap()
        .1;
    let input = format!(
        "-----BEGIN PGP SIGNED MESSAGE-----\n\nplain text\n-----BEGIN PGP SIGNATURE-----{}",
        sig_block
    );
    let multi = decode_armor_multi(&input).unwrap();
    assert_eq!(multi.cleartext.unwrap().as_ref(), "plain text");
}

// Binary detection tests

#[test]
fn test_looks_binary() {
    assert!(!looks_binary(b""));
    assert!(!looks_binary(TEST_KEY.as_bytes()));
    assert!(!looks_binary(b"-----BEGIN PGP MESSAGE-----"));
    // Old-format and new-format packet headers both set the high bit
    assert!(looks_binary(&[0x99, 0x02, 0x0D]));
    assert!(looks_binary(&[0xC6, 0x08]));
}
