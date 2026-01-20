//! Integration tests for gpg-inspector-lib
//!
//! These tests use real GPG armored data to verify end-to-end parsing.

use gpg_inspector_lib::{decode_armor, parse, parse_bytes, ColorTracker, ByteStream, PALETTE};

/// Sample GPG public key for testing
const TEST_PUBLIC_KEY: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=mmx4
-----END PGP PUBLIC KEY BLOCK-----"#;

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
    assert!(packets.len() >= 3, "Expected at least 3 packets, got {}", packets.len());
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
// ColorTracker Tests
// ============================================================================

#[test]
fn test_color_tracker_rotation() {
    let mut tracker = ColorTracker::new(100);

    // Set 10 fields, colors should rotate through 8 palette entries
    let colors: Vec<u8> = (0..10)
        .map(|i| tracker.set_field(i * 10, (i + 1) * 10))
        .collect();

    assert_eq!(colors[0], 0);
    assert_eq!(colors[7], 7);
    assert_eq!(colors[8], 0); // Wraps around
    assert_eq!(colors[9], 1);
}

#[test]
fn test_color_tracker_get_color() {
    let mut tracker = ColorTracker::new(50);

    tracker.set_field(0, 10);  // Color 0
    tracker.set_field(10, 20); // Color 1

    assert_eq!(tracker.get_color(5), Some(0));
    assert_eq!(tracker.get_color(15), Some(1));
    assert_eq!(tracker.get_color(25), None); // No color set
}

#[test]
fn test_color_tracker_header_no_color() {
    let mut tracker = ColorTracker::new(50);

    tracker.set_header(0, 10);
    let field_color = tracker.set_field(10, 20);

    // Header bytes should have no color
    assert_eq!(tracker.get_color(5), None);
    // Field bytes should have color
    assert_eq!(tracker.get_color(15), Some(field_color));
}

#[test]
fn test_palette_size() {
    assert_eq!(PALETTE.len(), 8, "Palette should have 8 colors");
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
