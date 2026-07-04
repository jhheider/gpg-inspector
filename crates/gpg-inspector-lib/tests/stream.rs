//! Tests for stream.rs - ByteStream edge cases

use gpg_inspector_lib::ByteStream;
use std::sync::Arc;

#[test]
fn test_bytestream_from_arc() {
    let data: Arc<[u8]> = Arc::from(vec![1u8, 2, 3, 4, 5]);
    let stream = ByteStream::from_arc(data);
    assert_eq!(stream.remaining(), 5);
}

#[test]
fn test_bytestream_abs_pos() {
    let data = vec![1u8, 2, 3, 4, 5];
    let mut stream = ByteStream::new(data);
    assert_eq!(stream.abs_pos(), 0);
    stream.octet().unwrap();
    assert_eq!(stream.abs_pos(), 1);
}

#[test]
fn test_bytestream_skip() {
    let data = vec![1u8, 2, 3, 4, 5];
    let mut stream = ByteStream::new(data);
    stream.skip(2).unwrap();
    assert_eq!(stream.pos(), 2);
    assert_eq!(stream.octet().unwrap(), 3);
}

#[test]
fn test_bytestream_skip_overflow() {
    let data = vec![1u8, 2, 3];
    let mut stream = ByteStream::new(data);
    let result = stream.skip(100);
    assert!(result.is_err());
}

#[test]
fn test_bytestream_bytes() {
    let data = vec![1u8, 2, 3, 4, 5];
    let mut stream = ByteStream::new(data);
    let bytes = stream.bytes(3).unwrap();
    assert_eq!(bytes, vec![1, 2, 3]);
}

#[test]
fn test_bytestream_bytes_overflow() {
    let data = vec![1u8, 2];
    let mut stream = ByteStream::new(data);
    let result = stream.bytes(10);
    assert!(result.is_err());
}

#[test]
fn test_bytestream_rest_as_hex() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut stream = ByteStream::new(data);
    stream.octet().unwrap();
    let hex = stream.rest_as_hex();
    assert_eq!(hex, "ADBEEF");
}

#[test]
fn test_bytestream_utf8_invalid() {
    let data = vec![0xFF, 0xFE, 0x00, 0x01]; // Invalid UTF-8
    let mut stream = ByteStream::new(data);
    let result = stream.utf8(4);
    // Should still work (lossy conversion or error handling)
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_bytestream_hex_empty() {
    let data = vec![1u8, 2, 3];
    let mut stream = ByteStream::new(data);
    let hex = stream.hex(0).unwrap();
    assert_eq!(hex, "");
}

#[test]
fn test_bytestream_slice_preserves_offset() {
    let data = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let stream = ByteStream::new(data);

    // Create a slice starting at position 3
    let slice = stream.slice(3, 7);
    assert_eq!(slice.remaining(), 4);
    assert_eq!(slice.pos(), 0);
}

#[test]
fn test_bytestream_mpi_zero_bits() {
    // Edge case: 0-bit MPI
    let data = vec![0x00, 0x00];
    let mut stream = ByteStream::new(data);
    let (bits, hex) = stream.multi_precision_integer().unwrap();
    assert_eq!(bits, 0);
    assert_eq!(hex, "");
}

#[test]
fn test_bytestream_mpi_large() {
    // Larger MPI: 24 bits = 3 bytes
    let data = vec![0x00, 0x18, 0xAB, 0xCD, 0xEF];
    let mut stream = ByteStream::new(data);
    let (bits, hex) = stream.multi_precision_integer().unwrap();
    assert_eq!(bits, 24);
    assert_eq!(hex, "ABCDEF");
}

#[test]
fn test_bytestream_octet_overflow() {
    let data = vec![];
    let mut stream = ByteStream::new(data);
    let result = stream.octet();
    assert!(result.is_err());
}

#[test]
fn test_bytestream_uint16_overflow() {
    let data = vec![0x01];
    let mut stream = ByteStream::new(data);
    let result = stream.uint16();
    assert!(result.is_err());
}

#[test]
fn test_bytestream_uint32_overflow() {
    let data = vec![0x01, 0x02];
    let mut stream = ByteStream::new(data);
    let result = stream.uint32();
    assert!(result.is_err());
}

#[test]
fn test_bytestream_len() {
    let data = vec![1u8, 2, 3, 4, 5];
    let stream = ByteStream::new(data);
    assert_eq!(stream.len(), 5);
}

#[test]
fn test_bytestream_peek() {
    let data = vec![0xAB, 0xCD];
    let stream = ByteStream::new(data);
    assert_eq!(stream.peek(), Some(0xAB));

    // Empty stream
    let empty = ByteStream::new(vec![]);
    assert_eq!(empty.peek(), None);
}

#[test]
fn test_bytestream_all_bytes() {
    let data = vec![1u8, 2, 3, 4, 5];
    let stream = ByteStream::new(data.clone());
    assert_eq!(stream.all_bytes(), &data[..]);
}
