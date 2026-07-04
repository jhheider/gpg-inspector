//! Tests for OSC 52 clipboard encoding.

use gpg_inspector::clipboard::{MAX_COPY_BYTES, base64_encode, osc52_sequence};

#[test]
fn test_base64_vectors() {
    // RFC 4648 test vectors
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
    assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
}

#[test]
fn test_base64_binary() {
    assert_eq!(base64_encode(&[0x00, 0xFF, 0x80]), "AP+A");
}

#[test]
fn test_osc52_sequence_shape() {
    let seq = osc52_sequence(b"hello");
    assert!(seq.starts_with("\x1b]52;c;"));
    assert!(seq.ends_with('\x07'));
    assert!(seq.contains("aGVsbG8="));
}

#[test]
fn test_max_copy_is_terminal_safe() {
    assert!(MAX_COPY_BYTES <= 100 * 1024);
}
