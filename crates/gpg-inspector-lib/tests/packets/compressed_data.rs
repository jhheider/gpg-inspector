//! Compressed Data packet tests - Tag 8

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

fn build_compressed_data_packet(algorithm: u8, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 8); // Tag 8 = Compressed Data

    let body_len = 1 + data.len(); // algorithm + compressed data
    packet.push(body_len as u8);

    packet.push(algorithm);
    packet.extend_from_slice(data);

    packet
}

#[test]
fn test_compressed_data_uncompressed() {
    let packet = build_compressed_data_packet(0, b"test data");

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::CompressedData);

    // Check we got the algorithm field
    let algo_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Algorithm");
    assert!(algo_field.is_some());
    assert!(algo_field.unwrap().value.contains("Uncompressed"));
}

#[test]
fn test_compressed_data_zip() {
    let packet = build_compressed_data_packet(1, &[0x78, 0x9C, 0x01, 0x02, 0x03]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let algo_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Algorithm");
    assert!(algo_field.is_some());
    assert!(algo_field.unwrap().value.contains("ZIP"));
}

#[test]
fn test_compressed_data_zlib() {
    let packet = build_compressed_data_packet(2, &[0x78, 0x9C, 0xAB, 0xCD]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let algo_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Algorithm");
    assert!(algo_field.is_some());
    assert!(algo_field.unwrap().value.contains("ZLIB"));
}

#[test]
fn test_compressed_data_bzip2() {
    let packet = build_compressed_data_packet(3, &[0x42, 0x5A, 0x68]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let algo_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Algorithm");
    assert!(algo_field.is_some());
    assert!(algo_field.unwrap().value.contains("BZip2"));
}

#[test]
fn test_compressed_data_empty() {
    let packet = build_compressed_data_packet(0, &[]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::CompressedData);
}

// Decompression + nested packet tests (feature "decompress")

#[cfg(feature = "decompress")]
mod decompress {
    use super::build_compressed_data_packet;
    use gpg_inspector_lib::packet::tags::PacketTag;
    use gpg_inspector_lib::parse_bytes;
    use std::io::Write;

    /// A minimal Literal Data packet (tag 11) holding `data`.
    fn build_literal_packet(data: &[u8]) -> Vec<u8> {
        // Tag 11; body = format + filename len + date + data
        let mut packet = vec![0xC0 | 11, (1 + 1 + 4 + data.len()) as u8, b'b', 0];
        packet.extend_from_slice(&[0, 0, 0, 0]); // date
        packet.extend_from_slice(data);
        packet
    }

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn deflate_compress(data: &[u8]) -> Vec<u8> {
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn bzip2_compress(data: &[u8]) -> Vec<u8> {
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn decompressed_field(packet: &gpg_inspector_lib::Packet) -> &str {
        packet
            .fields
            .iter()
            .find(|f| f.name.as_ref() == "Decompressed")
            .map(|f| f.value.as_ref())
            .expect("no Decompressed field")
    }

    #[test]
    fn test_zlib_nested_literal() {
        let literal = build_literal_packet(b"hello nested");
        let packet = build_compressed_data_packet(2, &zlib_compress(&literal));

        let packets = parse_bytes(packet).unwrap();
        let cd = &packets[0];

        assert_eq!(cd.children.len(), 1);
        assert_eq!(cd.children[0].tag, PacketTag::LiteralData);
        assert_eq!(&cd.child_buffer.as_ref().unwrap()[..], &literal[..]);
        assert!(decompressed_field(cd).contains("1 packets"));

        // Child spans index the decompressed buffer
        assert_eq!(cd.children[0].start, 0);
        assert_eq!(cd.children[0].end, literal.len());
    }

    #[test]
    fn test_deflate_nested_literal() {
        let literal = build_literal_packet(b"zip variant");
        let packet = build_compressed_data_packet(1, &deflate_compress(&literal));

        let packets = parse_bytes(packet).unwrap();
        assert_eq!(packets[0].children.len(), 1);
        assert_eq!(packets[0].children[0].tag, PacketTag::LiteralData);
    }

    #[test]
    fn test_bzip2_nested_literal() {
        let literal = build_literal_packet(b"bzip2 variant");
        let packet = build_compressed_data_packet(3, &bzip2_compress(&literal));

        let packets = parse_bytes(packet).unwrap();
        assert_eq!(packets[0].children.len(), 1);
        assert_eq!(packets[0].children[0].tag, PacketTag::LiteralData);
    }

    #[test]
    fn test_uncompressed_passthrough() {
        let literal = build_literal_packet(b"plain");
        let packet = build_compressed_data_packet(0, &literal);

        let packets = parse_bytes(packet).unwrap();
        assert_eq!(packets[0].children.len(), 1);
        assert_eq!(packets[0].children[0].tag, PacketTag::LiteralData);
    }

    #[test]
    fn test_unknown_algorithm_reports_error() {
        let packet = build_compressed_data_packet(99, b"whatever");

        let packets = parse_bytes(packet).unwrap();
        let cd = &packets[0];
        assert!(cd.children.is_empty());
        assert!(cd.child_buffer.is_none());
        assert!(decompressed_field(cd).contains("unsupported compression algorithm"));
    }

    #[test]
    fn test_truncated_stream_reports_error() {
        let literal = build_literal_packet(b"will be truncated");
        let mut compressed = zlib_compress(&literal);
        compressed.truncate(compressed.len() / 2);
        let packet = build_compressed_data_packet(2, &compressed);

        let packets = parse_bytes(packet).unwrap();
        let cd = &packets[0];
        assert!(cd.children.is_empty());
        assert!(decompressed_field(cd).contains("error"));
    }

    #[test]
    fn test_garbage_payload_reports_error_not_failure() {
        let packet = build_compressed_data_packet(2, &[0xDE, 0xAD, 0xBE, 0xEF]);

        // The parse as a whole must still succeed
        let packets = parse_bytes(packet).unwrap();
        assert!(decompressed_field(&packets[0]).contains("error"));
    }

    #[test]
    fn test_nested_parse_error_reports_error() {
        // Valid zlib, but the decompressed bytes are not a packet stream
        let packet = build_compressed_data_packet(2, &zlib_compress(b"not packets"));

        let packets = parse_bytes(packet).unwrap();
        let cd = &packets[0];
        assert!(cd.children.is_empty());
        assert!(decompressed_field(cd).contains("error"));
    }

    /// Wraps `inner` in a new-format Compressed Data packet with a
    /// variable-length body length (supports >191 bytes).
    fn wrap_compressed(algorithm: u8, inner: &[u8]) -> Vec<u8> {
        let compressed = zlib_compress(inner);
        let body_len = 1 + compressed.len();
        let mut packet = vec![0xC0 | 8];
        if body_len < 192 {
            packet.push(body_len as u8);
        } else {
            packet.push(255);
            packet.extend_from_slice(&(body_len as u32).to_be_bytes());
        }
        packet.push(algorithm);
        packet.extend_from_slice(&compressed);
        packet
    }

    #[test]
    fn test_depth_limit() {
        // 6 levels of nesting; expansion must stop at MAX_DEPTH (4)
        let mut current = build_literal_packet(b"core");
        for _ in 0..6 {
            current = wrap_compressed(2, &current);
        }

        let packets = parse_bytes(current).unwrap();
        let mut node = &packets[0];
        let mut expansions = 0;
        while !node.children.is_empty() {
            node = &node.children[0];
            expansions += 1;
        }
        assert_eq!(expansions, 4, "expected expansion to stop at MAX_DEPTH");
        assert!(decompressed_field(node).contains("max nesting depth"));
    }

    #[test]
    fn test_size_cap() {
        // 65 MiB of zeros compresses tiny but exceeds the 64 MiB cap
        let huge = vec![0u8; 65 * 1024 * 1024];
        let compressed = zlib_compress(&huge);
        let body_len = 1 + compressed.len();
        let mut packet = vec![0xC0 | 8, 255];
        packet.extend_from_slice(&(body_len as u32).to_be_bytes());
        packet.push(2);
        packet.extend_from_slice(&compressed);

        let packets = parse_bytes(packet).unwrap();
        let cd = &packets[0];
        assert!(cd.children.is_empty());
        assert!(decompressed_field(cd).contains("cap"));
    }

    #[test]
    fn test_multiple_children() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&build_literal_packet(b"one"));
        stream.extend_from_slice(&build_literal_packet(b"two"));
        let packet = build_compressed_data_packet(2, &zlib_compress(&stream));

        let packets = parse_bytes(packet).unwrap();
        assert_eq!(packets[0].children.len(), 2);
        assert!(decompressed_field(&packets[0]).contains("2 packets"));
    }
}
