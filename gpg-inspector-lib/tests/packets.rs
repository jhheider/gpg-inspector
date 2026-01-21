//! Packet-level tests with raw byte data
//!
//! Tests for packet parsing using constructed byte sequences.

#[path = "packets/compressed_data.rs"]
mod compressed_data;
#[path = "packets/format.rs"]
mod format;
#[path = "packets/literal_data.rs"]
mod literal_data;
#[path = "packets/mdc.rs"]
mod mdc;
#[path = "packets/misc.rs"]
mod misc;
#[path = "packets/one_pass_signature.rs"]
mod one_pass_signature;
#[path = "packets/pkesk.rs"]
mod pkesk;
#[path = "packets/secret_key.rs"]
mod secret_key;
#[path = "packets/seipd.rs"]
mod seipd;
#[path = "packets/skesk.rs"]
mod skesk;
#[path = "packets/tags.rs"]
mod tags;
#[path = "packets/user_attribute.rs"]
mod user_attribute;

use gpg_inspector_lib::Field;

// ============================================================================
// Field Tests
// ============================================================================

#[test]
fn test_field_constructors() {
    let packet = Field::packet("Test", "Value", (0, 10));
    assert_eq!(packet.indent, 0);

    let field = Field::field("Test", "Value", (0, 10));
    assert_eq!(field.indent, 1);

    let subfield = Field::subfield("Test", "Value", (0, 10));
    assert_eq!(subfield.indent, 2);
}

#[test]
fn test_field_spans() {
    let field = Field::field("Test", "Value", (5, 15));
    assert_eq!(field.span, (5, 15));

    let field = Field::new("Custom", "Value", 3, (100, 200));
    assert_eq!(field.indent, 3);
    assert_eq!(field.span, (100, 200));
}
