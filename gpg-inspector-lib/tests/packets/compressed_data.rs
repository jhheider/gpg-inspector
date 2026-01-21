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
