//! Integration tests for gpg-inspector-lib
//!
//! These tests use real GPG armored data to verify end-to-end parsing.

mod packets;

use gpg_inspector_lib::{ByteStream, decode_armor, parse, parse_bytes};

const TEST_PUBLIC_KEY: &str = include_str!("../../fixtures/test.key");

// ============================================================================
// Armor Tests
// ============================================================================

#[test]
fn test_decode_armor_public_key() {
    let result = decode_armor(TEST_PUBLIC_KEY);
    assert!(result.is_ok(), "Failed to decode armor: {:?}", result.err());

    let armor = result.unwrap();
    assert_eq!(&*armor.armor_type, "PGP PUBLIC KEY BLOCK");
    assert!(!armor.bytes.is_empty());
}

#[test]
fn test_decode_armor_missing_header() {
    let bad_armor = "not valid armor data";
    let result = decode_armor(bad_armor);
    assert!(result.is_err());
}

#[test]
fn test_decode_armor_missing_footer() {
    let bad_armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nYWJj\n";
    let result = decode_armor(bad_armor);
    assert!(result.is_err());
}

#[test]
fn test_decode_armor_empty_body() {
    let bad_armor = "-----BEGIN PGP MESSAGE-----\n\n-----END PGP MESSAGE-----";
    let result = decode_armor(bad_armor);
    assert!(result.is_err());
}

#[test]
fn test_decode_armor_with_headers() {
    // Armor with Version and Comment headers (no checksum for simplicity)
    let armor_with_headers = r#"-----BEGIN PGP MESSAGE-----
Version: GnuPG v2
Comment: Test

YWJjZGVm
-----END PGP MESSAGE-----"#;
    let result = decode_armor(armor_with_headers);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    assert_eq!(&*result.unwrap().armor_type, "PGP MESSAGE");
}

// ============================================================================
// Parse Tests
// ============================================================================

#[test]
fn test_parse_public_key_block() {
    let result = parse(TEST_PUBLIC_KEY);
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

    let packets = result.unwrap();
    assert!(!packets.is_empty(), "No packets parsed");

    // Should have multiple packets (public key, user ID, signatures)
    assert!(
        packets.len() >= 3,
        "Expected at least 3 packets, got {}",
        packets.len()
    );
}

#[test]
fn test_parse_bytes_directly() {
    let armor = decode_armor(TEST_PUBLIC_KEY).unwrap();
    let result = parse_bytes(armor.bytes);
    assert!(result.is_ok(), "Failed to parse bytes: {:?}", result.err());
}

#[test]
fn test_packet_fields_populated() {
    let packets = parse(TEST_PUBLIC_KEY).unwrap();

    for packet in &packets {
        assert!(!packet.fields.is_empty(), "Packet should have fields");

        // Each field should have a name and value
        for field in &packet.fields {
            assert!(!field.name.is_empty(), "Field name should not be empty");
        }
    }
}

#[test]
fn test_packet_byte_ranges() {
    let packets = parse(TEST_PUBLIC_KEY).unwrap();

    for packet in &packets {
        // Packet end should be after start
        assert!(packet.end > packet.start, "Invalid packet range");

        // Fields should have valid spans
        for field in &packet.fields {
            let (start, end) = field.span;
            assert!(end >= start, "Invalid field span");
        }
    }
}

// ============================================================================
// ByteStream Tests
// ============================================================================

#[test]
fn test_bytestream_basic_reads() {
    let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let mut stream = ByteStream::new(data);

    assert_eq!(stream.octet().unwrap(), 0x01);
    assert_eq!(stream.pos(), 1);

    assert_eq!(stream.uint16().unwrap(), 0x0203);
    assert_eq!(stream.pos(), 3);
}

#[test]
fn test_bytestream_uint32() {
    let data = vec![0x01, 0x02, 0x03, 0x04];
    let mut stream = ByteStream::new(data);

    assert_eq!(stream.uint32().unwrap(), 0x01020304);
}

#[test]
fn test_bytestream_hex() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut stream = ByteStream::new(data);

    let hex = stream.hex(4).unwrap();
    assert_eq!(hex, "DEADBEEF");
}

#[test]
fn test_bytestream_utf8() {
    let data = b"Hello, World!".to_vec();
    let mut stream = ByteStream::new(data);

    let text = stream.utf8(5).unwrap();
    assert_eq!(text, "Hello");
}

#[test]
fn test_bytestream_slice() {
    let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let stream = ByteStream::new(data);

    let slice = stream.slice(1, 4);
    assert_eq!(slice.remaining(), 3);
}

#[test]
fn test_bytestream_remaining() {
    let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let mut stream = ByteStream::new(data);

    assert_eq!(stream.remaining(), 5);
    stream.octet().unwrap();
    assert_eq!(stream.remaining(), 4);
}

#[test]
fn test_bytestream_is_empty() {
    let data = vec![0x01];
    let mut stream = ByteStream::new(data);

    assert!(!stream.is_empty());
    stream.octet().unwrap();
    assert!(stream.is_empty());
}

#[test]
fn test_bytestream_rest() {
    let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let mut stream = ByteStream::new(data);

    stream.octet().unwrap();
    stream.octet().unwrap();

    let rest = stream.rest();
    assert_eq!(rest, vec![0x03, 0x04, 0x05]);
}

#[test]
fn test_bytestream_unexpected_end() {
    let data = vec![0x01];
    let mut stream = ByteStream::new(data);

    let result = stream.uint32();
    assert!(result.is_err());
}

#[test]
fn test_bytestream_variable_length_one_byte() {
    // Length < 192 is stored as single byte
    let data = vec![0x10]; // 16
    let mut stream = ByteStream::new(data);

    assert_eq!(stream.variable_length().unwrap(), 16);
}

#[test]
fn test_bytestream_variable_length_two_bytes() {
    // Length 192-8383 is stored as two bytes
    let data = vec![0xC0, 0x00]; // 192 + 0 = 192
    let mut stream = ByteStream::new(data);

    assert_eq!(stream.variable_length().unwrap(), 192);
}

#[test]
fn test_bytestream_variable_length_five_bytes() {
    // Length >= 8384 uses 5-byte format (0xFF prefix)
    let data = vec![0xFF, 0x00, 0x01, 0x00, 0x00]; // 65536
    let mut stream = ByteStream::new(data);

    assert_eq!(stream.variable_length().unwrap(), 65536);
}

#[test]
fn test_bytestream_mpi() {
    // MPI: 2-byte bit count followed by data
    // 17 bits = 3 bytes of data
    let data = vec![0x00, 0x11, 0x01, 0x23, 0x45];
    let mut stream = ByteStream::new(data);

    let (bits, hex) = stream.multi_precision_integer().unwrap();
    assert_eq!(bits, 17);
    assert_eq!(hex.len(), 6); // 3 bytes = 6 hex chars
}

// ============================================================================
// Lookup Tests
// ============================================================================

mod lookup_tests {
    use gpg_inspector_lib::lookup::*;

    #[test]
    fn test_lookup_public_key_algorithm() {
        let rsa = lookup_public_key_algorithm(1);
        assert_eq!(rsa.value, 1);
        assert!(rsa.name.contains("RSA"));

        let unknown = lookup_public_key_algorithm(255);
        assert!(unknown.name.contains("Unknown"));
    }

    #[test]
    fn test_lookup_symmetric_algorithm() {
        let aes256 = lookup_symmetric_algorithm(9);
        assert_eq!(aes256.value, 9);
        assert!(aes256.name.contains("AES-256"));
    }

    #[test]
    fn test_lookup_hash_algorithm() {
        let sha256 = lookup_hash_algorithm(8);
        assert!(sha256.name.contains("SHA-256"));
    }

    #[test]
    fn test_lookup_compression_algorithm() {
        let zlib = lookup_compression_algorithm(2);
        assert!(zlib.name.contains("ZLIB"));
    }

    #[test]
    fn test_lookup_signature_type() {
        let positive = lookup_signature_type(0x13);
        assert!(positive.name.contains("Positive"));
    }

    #[test]
    fn test_lookup_subpacket_type() {
        let creation = lookup_subpacket_type(2);
        assert!(creation.name.contains("Creation"));
    }

    #[test]
    fn test_lookup_curve_oid() {
        let p256 = lookup_curve_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
        assert!(p256.contains("P-256"));

        let unknown = lookup_curve_oid(&[0x01, 0x02, 0x03]);
        assert!(unknown.contains("Unknown"));
    }

    #[test]
    fn test_lookup_key_flags() {
        let flags = lookup_key_flags(0x03); // Certify + Sign
        assert!(flags.contains(&"Certify"));
        assert!(flags.contains(&"Sign"));

        let empty = lookup_key_flags(0x00);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_lookup_revocation_reason() {
        let superseded = lookup_revocation_reason(1);
        assert!(superseded.contains("superseded"));
    }

    #[test]
    fn test_lookup_s2k_type() {
        let iterated = lookup_s2k_type(3);
        assert!(iterated.contains("Iterated"));
    }

    #[test]
    fn test_lookup_aead_algorithm() {
        let gcm = lookup_aead_algorithm(3);
        assert!(gcm.name.contains("GCM"));
    }

    #[test]
    fn test_lookup_result_display() {
        let result = lookup_public_key_algorithm(1);
        let display = result.display();
        assert!(display.contains("1"));
        assert!(display.contains("RSA"));
    }
}

// ============================================================================
// Error Tests
// ============================================================================

#[test]
fn test_error_display() {
    use gpg_inspector_lib::Error;

    let err = Error::InvalidArmor("test".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Invalid armor"));

    let err = Error::UnexpectedEnd(42);
    let display = format!("{}", err);
    assert!(display.contains("42"));
}
