//! User Attribute packet tests - Tag 17

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

// Build User Attribute with image subpacket (type 1)
fn build_user_attribute_image(image_format: u8, image_data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 17); // Tag 17 = User Attribute

    // Image subpacket structure:
    // - subpacket length (variable)
    // - subpacket type (1 = image)
    // - image header (16 bytes for v1):
    //   - header length (2 bytes, little-endian) = 0x10, 0x00
    //   - header version (1 byte) = 0x01
    //   - image format (1 byte)
    //   - reserved (12 bytes)
    // - image data

    let header_len = 16;
    let subpacket_data_len = 1 + header_len + image_data.len(); // type + header + data

    // Calculate body length
    let subpacket_len_bytes = if subpacket_data_len < 192 { 1 } else { 2 };
    let body_len = subpacket_len_bytes + subpacket_data_len;

    packet.push(body_len as u8);

    // Subpacket length
    if subpacket_data_len < 192 {
        packet.push(subpacket_data_len as u8);
    } else {
        let first = ((subpacket_data_len - 192) >> 8) as u8 + 192;
        let second = ((subpacket_data_len - 192) & 0xFF) as u8;
        packet.push(first);
        packet.push(second);
    }

    // Subpacket type
    packet.push(1); // Image subpacket

    // Image header (v1, 16 bytes)
    packet.push(0x10); // Header length low byte
    packet.push(0x00); // Header length high byte
    packet.push(0x01); // Header version
    packet.push(image_format);
    packet.extend_from_slice(&[0x00; 12]); // Reserved

    // Image data
    packet.extend_from_slice(image_data);

    packet
}

// Build User Attribute with unknown subpacket type
fn build_user_attribute_unknown(subpacket_type: u8, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 17); // Tag 17 = User Attribute

    let subpacket_data_len = 1 + data.len(); // type + data
    let body_len = 1 + subpacket_data_len; // length byte + subpacket

    packet.push(body_len as u8);
    packet.push(subpacket_data_len as u8); // Subpacket length
    packet.push(subpacket_type);
    packet.extend_from_slice(data);

    packet
}

#[test]
fn test_user_attribute_basic() {
    let packet = build_user_attribute_image(1, &[0xFF, 0xD8, 0xFF, 0xE0]); // JPEG magic

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::UserAttribute);
}

#[test]
fn test_user_attribute_jpeg_format() {
    let packet = build_user_attribute_image(1, &[0xFF, 0xD8, 0xFF, 0xE0]); // JPEG magic

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let format_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Format");
    assert!(format_field.is_some());
    assert!(format_field.unwrap().value.contains("JPEG"));
}

#[test]
fn test_user_attribute_jpeg_detected() {
    // Actual JPEG magic bytes
    let packet = build_user_attribute_image(1, &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Data");
    assert!(data_field.is_some());
    assert!(data_field.unwrap().value.contains("JPEG detected"));
}

#[test]
fn test_user_attribute_png_detected() {
    // PNG magic bytes
    let png_magic = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let packet = build_user_attribute_image(1, &png_magic);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Data");
    assert!(data_field.is_some());
    assert!(data_field.unwrap().value.contains("PNG detected"));
}

#[test]
fn test_user_attribute_gif_detected() {
    // GIF magic bytes
    let gif_magic = [0x47, 0x49, 0x46, 0x38, 0x39, 0x61];
    let packet = build_user_attribute_image(1, &gif_magic);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Data");
    assert!(data_field.is_some());
    assert!(data_field.unwrap().value.contains("GIF detected"));
}

#[test]
fn test_user_attribute_bmp_detected() {
    // BMP magic bytes
    let bmp_magic = [0x42, 0x4D, 0x00, 0x00];
    let packet = build_user_attribute_image(1, &bmp_magic);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Data");
    assert!(data_field.is_some());
    assert!(data_field.unwrap().value.contains("BMP detected"));
}

#[test]
fn test_user_attribute_private_format() {
    let packet = build_user_attribute_image(100, &[0x00; 10]); // Private format 100

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let format_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Format");
    assert!(format_field.is_some());
    assert!(format_field.unwrap().value.contains("Private"));
}

#[test]
fn test_user_attribute_unknown_format() {
    let packet = build_user_attribute_image(99, &[0x00; 10]); // Unknown format

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let format_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Format");
    assert!(format_field.is_some());
    assert!(format_field.unwrap().value.contains("Unknown"));
}

#[test]
fn test_user_attribute_unknown_subpacket() {
    let packet = build_user_attribute_unknown(50, &[0xAB, 0xCD, 0xEF]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let subpacket_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Unknown Subpacket");
    assert!(subpacket_field.is_some());
    assert!(subpacket_field.unwrap().value.contains("Type 50"));
}

#[test]
fn test_user_attribute_private_subpacket() {
    let packet = build_user_attribute_unknown(105, &[0x00; 5]); // Private subpacket type

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let subpacket_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Private Subpacket");
    assert!(subpacket_field.is_some());
    assert!(subpacket_field.unwrap().value.contains("Type 105"));
}

#[test]
fn test_user_attribute_image_data_size() {
    let image_data = [0x00; 100];
    let packet = build_user_attribute_image(1, &image_data);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Data");
    assert!(data_field.is_some());
    assert!(data_field.unwrap().value.contains("100 bytes"));
}

#[test]
fn test_user_attribute_header_version() {
    let packet = build_user_attribute_image(1, &[0xFF, 0xD8, 0xFF]);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let subpacket_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Subpacket");
    assert!(subpacket_field.is_some());
    assert!(subpacket_field.unwrap().value.contains("Header v1"));
}

// =============================================================================
// Edge Case Tests
// =============================================================================

/// Build User Attribute with zero-length subpacket
fn build_user_attribute_zero_length() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 17); // Tag 17 = User Attribute

    // Zero-length subpacket followed by a valid image subpacket
    let image_data = [0xFF, 0xD8, 0xFF, 0xE0];
    let header_len = 16;
    let valid_subpacket_data_len = 1 + header_len + image_data.len();

    let body_len = 1 + 1 + valid_subpacket_data_len; // zero len + len byte + valid subpacket
    packet.push(body_len as u8);

    // Zero-length subpacket
    packet.push(0);

    // Valid image subpacket
    packet.push(valid_subpacket_data_len as u8);
    packet.push(1); // Image subpacket type
    packet.push(0x10); // Header length low byte
    packet.push(0x00); // Header length high byte
    packet.push(0x01); // Header version
    packet.push(1); // JPEG format
    packet.extend_from_slice(&[0x00; 12]); // Reserved
    packet.extend_from_slice(&image_data);

    packet
}

#[test]
fn test_user_attribute_zero_length_subpacket() {
    let packet = build_user_attribute_zero_length();

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::UserAttribute);
}

/// Build User Attribute with unknown header version
fn build_user_attribute_unknown_header_version(header_version: u8, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 17); // Tag 17 = User Attribute

    let header_len = 16;
    let subpacket_data_len = 1 + header_len + data.len();
    let body_len = 1 + subpacket_data_len;

    packet.push(body_len as u8);
    packet.push(subpacket_data_len as u8);
    packet.push(1); // Image subpacket type

    // Image header with unknown version
    packet.push(0x10); // Header length low byte
    packet.push(0x00); // Header length high byte
    packet.push(header_version); // Unknown header version
    // For unknown header versions, the rest is raw data
    packet.extend_from_slice(&[0x00; 13]); // Fill to header_len bytes from header start
    packet.extend_from_slice(data);

    packet
}

#[test]
fn test_user_attribute_unknown_header_version() {
    let packet = build_user_attribute_unknown_header_version(99, &[0xAB, 0xCD, 0xEF]);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::UserAttribute);

    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Data");
    assert!(data_field.is_some());
    assert!(data_field.unwrap().value.contains("unknown header v99"));
}

/// Build User Attribute with 2-byte subpacket length
fn build_user_attribute_two_byte_length() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 17); // Tag 17 = User Attribute

    // Create a subpacket with length that requires 2 bytes (192-8383 range)
    // Length = 200 means we need to encode it in 2 bytes
    let subpacket_data_len = 200; // This will require 2-byte length encoding

    // Two-byte length encoding: first byte = ((len - 192) >> 8) + 192
    // second byte = (len - 192) & 0xFF
    // For len = 200: first = ((200-192) >> 8) + 192 = 192, second = 8
    let first_len_byte = ((subpacket_data_len - 192) >> 8) as u8 + 192;
    let second_len_byte = ((subpacket_data_len - 192) & 0xFF) as u8;

    // Body = 2 length bytes + subpacket content
    let body_len = 2 + subpacket_data_len;

    // Use new-format packet length encoding for body
    if body_len < 192 {
        packet.push(body_len as u8);
    } else {
        let first = ((body_len - 192) >> 8) as u8 + 192;
        let second = ((body_len - 192) & 0xFF) as u8;
        packet.push(first);
        packet.push(second);
    }

    // Subpacket length (2-byte encoded)
    packet.push(first_len_byte);
    packet.push(second_len_byte);

    // Subpacket type (unknown)
    packet.push(50);

    // Fill with data to match the length (subpacket_data_len - 1 for type byte)
    packet.extend_from_slice(&vec![0xAB; subpacket_data_len - 1]);

    packet
}

#[test]
fn test_user_attribute_two_byte_length() {
    let packet = build_user_attribute_two_byte_length();

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::UserAttribute);

    let subpacket_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Unknown Subpacket");
    assert!(subpacket_field.is_some());
    assert!(subpacket_field.unwrap().value.contains("199 bytes")); // 200 - 1 for type
}

/// Build User Attribute with small image data (test empty detection path)
fn build_user_attribute_tiny_image() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 17); // Tag 17 = User Attribute

    // Only 2 bytes of image data - too small for format detection
    let image_data = [0x00, 0x00];
    let header_len = 16;
    let subpacket_data_len = 1 + header_len + image_data.len();
    let body_len = 1 + subpacket_data_len;

    packet.push(body_len as u8);
    packet.push(subpacket_data_len as u8);
    packet.push(1); // Image subpacket type
    packet.push(0x10);
    packet.push(0x00);
    packet.push(0x01); // Header version 1
    packet.push(1); // JPEG format
    packet.extend_from_slice(&[0x00; 12]);
    packet.extend_from_slice(&image_data);

    packet
}

#[test]
fn test_user_attribute_tiny_image_no_detection() {
    let packet = build_user_attribute_tiny_image();

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Data");
    assert!(data_field.is_some());
    // Should just show bytes without detection since data is too small
    assert!(data_field.unwrap().value.contains("2 bytes"));
}

/// Build User Attribute with unknown header version and minimal data (remaining = 0)
fn build_user_attribute_unknown_header_no_remaining() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 17); // Tag 17 = User Attribute

    // Subpacket with data_len = 4 (type + 3 header bytes), so remaining = 4 - 3 = 1
    // But we want remaining = 0, so data_len = 3
    // However, we need at least: type(1) + header_len_lo(1) + header_len_hi(1) + header_version(1)
    // So minimum subpacket_data_len = 4, and we read 3 bytes before checking remaining
    // remaining = data_len - 3 = 4 - 3 = 1... still not 0

    // Actually, looking at the code:
    // let remaining = data_len.saturating_sub(3); // Already read 3 bytes
    // We need data_len <= 3 for remaining = 0
    // data_len = subpacket_data_len - 1 (for subpacket type)
    // So we need subpacket_data_len <= 4

    // Let's try subpacket_data_len = 4: type(1) + header_len(2) + version(1) = 4
    // data_len = 4 - 1 = 3, remaining = 3 - 3 = 0
    let subpacket_data_len = 4;
    let body_len = 1 + subpacket_data_len;

    packet.push(body_len as u8);
    packet.push(subpacket_data_len as u8);
    packet.push(1); // Image subpacket type

    // Minimal header: header_len (2 bytes) + header_version (1 byte)
    packet.push(0x03); // Header length low byte (3)
    packet.push(0x00); // Header length high byte
    packet.push(99); // Unknown header version

    // No more data - remaining should be 0

    packet
}

#[test]
fn test_user_attribute_unknown_header_no_remaining_data() {
    let packet = build_user_attribute_unknown_header_no_remaining();

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::UserAttribute);

    // Should have Image Data field with 0 bytes and unknown header version
    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Data");
    assert!(data_field.is_some());
    assert!(data_field.unwrap().value.contains("0 bytes"));
    assert!(data_field.unwrap().value.contains("unknown header v99"));
}

/// Build User Attribute with 5-byte length encoding (length >= 8384)
fn build_user_attribute_five_byte_length() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 17); // Tag 17 = User Attribute

    // For 5-byte length, first byte is 0xFF, then 4-byte big-endian length
    // We need a subpacket with length that requires 5-byte encoding
    // 5-byte encoding is used when length >= 8384 (can't fit in 2-byte encoding)
    // Let's use a length of 300 to keep the packet reasonable but trigger 5-byte path
    // Actually, looking at the code:
    // if first < 192 -> 1 byte
    // else if first < 255 -> 2 byte
    // else (first == 255) -> 5 byte
    // So we need to encode with 0xFF prefix

    let subpacket_data_len: u32 = 300;

    // Body length: 5-byte length encoding + subpacket content
    let body_len = 5 + subpacket_data_len as usize;

    // Use 2-byte packet length for body (body_len = 305)
    let first = ((body_len - 192) >> 8) as u8 + 192;
    let second = ((body_len - 192) & 0xFF) as u8;
    packet.push(first);
    packet.push(second);

    // 5-byte subpacket length: 0xFF + 4-byte big-endian
    packet.push(0xFF);
    packet.extend_from_slice(&subpacket_data_len.to_be_bytes());

    // Subpacket type (unknown)
    packet.push(50);

    // Fill with data (subpacket_data_len - 1 for type byte)
    packet.extend_from_slice(&vec![0xAB; (subpacket_data_len - 1) as usize]);

    packet
}

#[test]
fn test_user_attribute_five_byte_length_encoding() {
    let packet = build_user_attribute_five_byte_length();

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::UserAttribute);

    let subpacket_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Unknown Subpacket");
    assert!(subpacket_field.is_some());
    // 300 - 1 (type byte) = 299 bytes of data
    assert!(subpacket_field.unwrap().value.contains("299 bytes"));
}

/// Build User Attribute where image header claims more data than available (triggers rest() fallback)
fn build_user_attribute_truncated_image() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 17); // Tag 17 = User Attribute

    // We need: image_bytes_available > 0 && stream.remaining() < image_bytes_available
    // image_bytes_available = data_len - header_len
    // data_len = subpacket content length - 1 (type byte)
    //
    // Create a packet where header claims 16 bytes, but we only provide a few bytes of image data
    // then truncate the packet so stream.remaining() < image_bytes_available

    // subpacket_data_len encodes total length after type byte
    // We'll claim header_len=16 in a subpacket that's too short

    // Subpacket: type(1) + header_len_lo(1) + header_len_hi(1) + header_version(1) + format(1) + reserved(12) = 17 bytes
    // But if we claim header_len=16 and provide minimal image data expectation
    // The packet structure should have the stream end before expected image data

    // Actually, let's be more direct:
    // subpacket_data_len = 20 (declared)
    // data_len = 20 - 1 = 19
    // header reads: header_len(2) + version(1) + format(1) + reserved(12) = 16 bytes of header
    // image_bytes_available = 19 - 16 = 3 bytes expected
    // But we only put 1 byte of actual image data after the header
    // stream.remaining() = 1, image_bytes_available = 3 → triggers fallback

    let subpacket_data_len = 20; // Declared length
    let body_len = 1 + 17; // length byte + actual content we provide (less than declared)

    packet.push(body_len as u8); // Body length (actual)
    packet.push(subpacket_data_len as u8); // Subpacket length (claims more than we have)
    packet.push(1); // Image subpacket type

    // Header (16 bytes)
    packet.push(0x10); // Header length low (16)
    packet.push(0x00); // Header length high
    packet.push(0x01); // Header version 1
    packet.push(1); // JPEG format
    packet.extend_from_slice(&[0x00; 12]); // Reserved

    // Only 1 byte of "image data" - but header claims more is coming
    packet.push(0xAB);

    // Stream ends here, but subpacket_data_len claims there should be 2 more bytes

    packet
}

#[test]
fn test_user_attribute_truncated_image_uses_rest() {
    let packet = build_user_attribute_truncated_image();

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::UserAttribute);

    // Should still parse, using whatever bytes are available via rest()
    // In this case, the header claimed more data than exists, so rest() returns
    // whatever is left (0 bytes after header consumed all available data)
    let data_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Image Data");
    assert!(data_field.is_some(), "No Image Data field found");
    let value = &data_field.unwrap().value;
    // rest() was called because stream.remaining() < image_bytes_available
    // This exercises the fallback path at line 173
    assert!(
        value.contains("0 bytes"),
        "Expected '0 bytes' in value: {}",
        value
    );
}
