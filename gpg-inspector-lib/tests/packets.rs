//! Packet-level tests with raw byte data
//!
//! Tests for packet parsing using constructed byte sequences.

#[path = "packets/format.rs"]
mod format;
#[path = "packets/pkesk.rs"]
mod pkesk;
#[path = "packets/secret_key.rs"]
mod secret_key;
#[path = "packets/seipd.rs"]
mod seipd;
#[path = "packets/tags.rs"]
mod tags;

use gpg_inspector_lib::{ColorTracker, Field};

// ============================================================================
// Field Tests
// ============================================================================

#[test]
fn test_field_constructors() {
    let packet = Field::packet("Test", "Value", (0, 10));
    assert_eq!(packet.indent, 0);
    assert!(packet.color.is_none());

    let field = Field::field("Test", "Value", (0, 10), 5);
    assert_eq!(field.indent, 1);
    assert_eq!(field.color, Some(5));

    let subfield = Field::subfield("Test", "Value", (0, 10), 3);
    assert_eq!(subfield.indent, 2);
    assert_eq!(subfield.color, Some(3));
}

// ============================================================================
// ColorTracker Edge Cases
// ============================================================================

#[test]
fn test_color_tracker_out_of_bounds() {
    let tracker = ColorTracker::new(10);
    assert_eq!(tracker.get_color(100), None);
}

#[test]
fn test_color_tracker_set_field_invalid_range() {
    let mut tracker = ColorTracker::new(10);
    let color = tracker.set_field(5, 100);
    assert_eq!(color, 0);
    assert_eq!(tracker.get_color(5), None);
}

#[test]
fn test_color_tracker_empty_range() {
    let mut tracker = ColorTracker::new(10);
    let color = tracker.set_field(5, 5);
    assert_eq!(color, 0);
    assert_eq!(tracker.get_color(5), None);
}
