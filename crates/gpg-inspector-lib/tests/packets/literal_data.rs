//! Literal Data packet tests - Tag 11

use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::parse_bytes;

fn build_literal_data_packet(format: u8, filename: &[u8], date: u32, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0xC0 | 11); // Tag 11 = Literal Data

    let body_len = 1 + 1 + filename.len() + 4 + data.len();
    packet.push(body_len as u8);

    packet.push(format); // format byte
    packet.push(filename.len() as u8); // filename length
    packet.extend_from_slice(filename);
    packet.extend_from_slice(&date.to_be_bytes()); // 4-byte date
    packet.extend_from_slice(data);

    packet
}

#[test]
fn test_literal_data_binary() {
    let packet = build_literal_data_packet(0x62, b"test.bin", 0, &[0xDE, 0xAD, 0xBE, 0xEF]);

    let result = parse_bytes(packet);
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::LiteralData);

    let format_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Format");
    assert!(format_field.is_some());
    assert!(format_field.unwrap().value.contains("Binary"));
}

#[test]
fn test_literal_data_text() {
    let packet = build_literal_data_packet(0x74, b"message.txt", 0, b"Hello, world!");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let format_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Format");
    assert!(format_field.is_some());
    assert!(format_field.unwrap().value.contains("Text"));
}

#[test]
fn test_literal_data_utf8() {
    let packet = build_literal_data_packet(0x75, b"unicode.txt", 0, "UTF-8 текст".as_bytes());

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let format_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Format");
    assert!(format_field.is_some());
    assert!(format_field.unwrap().value.contains("UTF-8"));
}

#[test]
fn test_literal_data_mime() {
    let packet = build_literal_data_packet(0x6D, b"data.mime", 0, b"MIME content");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let format_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Format");
    assert!(format_field.is_some());
    assert!(format_field.unwrap().value.contains("MIME"));
}

#[test]
fn test_literal_data_with_filename() {
    let packet = build_literal_data_packet(0x62, b"important.doc", 0, b"content");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let filename_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Filename");
    assert!(filename_field.is_some());
    assert!(filename_field.unwrap().value.contains("important.doc"));
}

#[test]
fn test_literal_data_console() {
    let packet = build_literal_data_packet(0x62, b"_CONSOLE", 0, b"secret");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let filename_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Filename");
    assert!(filename_field.is_some());
    assert!(filename_field.unwrap().value.contains("for your eyes only"));
}

#[test]
fn test_literal_data_no_filename() {
    let packet = build_literal_data_packet(0x62, b"", 0, b"anonymous data");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    // Should have Filename Length = 0 but no Filename field
    let filename_len_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Filename Length");
    assert!(filename_len_field.is_some());
    assert!(filename_len_field.unwrap().value.contains('0'));
}

#[test]
fn test_literal_data_with_date() {
    // Unix timestamp: 1700000000 = 2023-11-14 22:13:20 UTC
    let packet = build_literal_data_packet(0x62, b"dated.bin", 1700000000, b"data");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let date_field = packets[0].fields.iter().find(|f| f.name.as_ref() == "Date");
    assert!(date_field.is_some());
    assert!(date_field.unwrap().value.contains("2023"));
}

#[test]
fn test_literal_data_no_date() {
    let packet = build_literal_data_packet(0x62, b"nodate.bin", 0, b"data");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let date_field = packets[0].fields.iter().find(|f| f.name.as_ref() == "Date");
    assert!(date_field.is_some());
    assert!(date_field.unwrap().value.contains("unspecified"));
}

#[test]
fn test_literal_data_unknown_format() {
    let packet = build_literal_data_packet(0xFF, b"unknown", 0, b"data");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let format_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Format");
    assert!(format_field.is_some());
    assert!(format_field.unwrap().value.contains("Unknown"));
}

#[test]
fn test_literal_data_text_preview() {
    let packet = build_literal_data_packet(0x74, b"msg.txt", 0, b"Short message");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0].fields.iter().find(|f| f.name.as_ref() == "Data");
    assert!(data_field.is_some());
    // Text format should show preview
    assert!(data_field.unwrap().value.contains("Short message"));
}

#[test]
fn test_literal_data_local_format() {
    let packet = build_literal_data_packet(0x6C, b"local.dat", 0, b"local data");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let format_field = packets[0]
        .fields
        .iter()
        .find(|f| f.name.as_ref() == "Format");
    assert!(format_field.is_some());
    assert!(format_field.unwrap().value.contains("Local"));
    assert!(format_field.unwrap().value.contains("deprecated"));
}

#[test]
fn test_literal_data_long_text_truncated() {
    // Create a text message longer than 64 characters to trigger truncation
    let long_text = "This is a very long text message that exceeds sixty-four characters and should be truncated in the preview display.";
    let packet = build_literal_data_packet(0x74, b"long.txt", 0, long_text.as_bytes());

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0].fields.iter().find(|f| f.name.as_ref() == "Data");
    assert!(data_field.is_some());
    // Should be truncated with "..."
    assert!(data_field.unwrap().value.contains("..."));
    assert!(
        data_field
            .unwrap()
            .value
            .contains(&format!("{} bytes", long_text.len()))
    );
}

#[test]
fn test_literal_data_utf8_long_text() {
    // UTF-8 format with long text
    let long_text = "This UTF-8 text is also quite long and should trigger the preview truncation mechanism when displayed.";
    let packet = build_literal_data_packet(0x75, b"utf8.txt", 0, long_text.as_bytes());

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0].fields.iter().find(|f| f.name.as_ref() == "Data");
    assert!(data_field.is_some());
    assert!(data_field.unwrap().value.contains("..."));
}

#[test]
fn test_literal_data_text_with_newlines() {
    let text_with_newlines = "Line 1\nLine 2\nLine 3";
    let packet =
        build_literal_data_packet(0x74, b"multiline.txt", 0, text_with_newlines.as_bytes());

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0].fields.iter().find(|f| f.name.as_ref() == "Data");
    assert!(data_field.is_some());
    // Newlines should be escaped as \n in preview
    assert!(data_field.unwrap().value.contains("\\n"));
}

#[test]
fn test_literal_data_empty_data() {
    let packet = build_literal_data_packet(0x62, b"empty.bin", 0, b"");

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();
    assert_eq!(packets[0].tag, PacketTag::LiteralData);

    // Empty data should not create a Data field
    let data_field = packets[0].fields.iter().find(|f| f.name.as_ref() == "Data");
    assert!(data_field.is_none());
}

#[test]
fn test_literal_data_binary_no_preview() {
    let binary_data = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let packet = build_literal_data_packet(0x62, b"binary.bin", 0, &binary_data);

    let result = parse_bytes(packet);
    assert!(result.is_ok());
    let packets = result.unwrap();

    let data_field = packets[0].fields.iter().find(|f| f.name.as_ref() == "Data");
    assert!(data_field.is_some());
    // Binary format should just show byte count, not content preview
    assert!(data_field.unwrap().value.contains("8 bytes"));
    assert!(!data_field.unwrap().value.contains("\"")); // No quote marks for binary
}
