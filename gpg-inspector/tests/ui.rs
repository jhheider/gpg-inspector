use ratatui::layout::Rect;

use gpg_inspector::ui::colors::{ColorTracker, PALETTE, get_color, get_field_color_index};
use gpg_inspector::ui::{get_data_panel_area, get_hex_panel_area};
use gpg_inspector_lib::packet::PacketBody;
use gpg_inspector_lib::packet::tags::PacketTag;
use gpg_inspector_lib::{Field, Packet};

#[test]
fn test_palette_has_12_colors() {
    assert_eq!(PALETTE.len(), 12);
}

#[test]
fn test_get_color_wraps() {
    let color0 = get_color(0);
    let color12 = get_color(12);
    assert_eq!(color0, color12);

    let color5 = get_color(5);
    let color17 = get_color(17);
    assert_eq!(color5, color17);
}

#[test]
fn test_get_color_all_indices() {
    for i in 0..12 {
        let color = get_color(i);
        assert_eq!(color, PALETTE[i as usize]);
    }
}

#[test]
fn test_layout_areas_valid() {
    let size = Rect::new(0, 0, 120, 40);

    let hex_area = get_hex_panel_area(size);
    let data_area = get_data_panel_area(size);

    // Both areas should have positive dimensions
    assert!(hex_area.width > 0);
    assert!(hex_area.height > 0);
    assert!(data_area.width > 0);
    assert!(data_area.height > 0);

    // Areas shouldn't overlap
    assert!(
        hex_area.y + hex_area.height <= data_area.y || data_area.y + data_area.height <= hex_area.y
    );
}

#[test]
fn test_layout_small_terminal() {
    let size = Rect::new(0, 0, 40, 10);

    let hex_area = get_hex_panel_area(size);
    let data_area = get_data_panel_area(size);

    // Should still produce valid areas
    assert!(hex_area.width > 0);
    assert!(data_area.width > 0);
}

fn make_test_packet() -> Packet {
    Packet {
        start: 0,
        end: 10,
        tag: PacketTag::UserId,
        body: PacketBody::Unknown(vec![]),
        fields: vec![
            Field::packet("Packet: User ID", "8 bytes", (0, 2)),
            Field::field("User ID", "test", (2, 6)),
            Field::subfield("Domain", "example.com", (6, 10)),
        ],
    }
}

#[test]
fn test_color_tracker_field_color_header() {
    let field = Field::packet("Header", "value", (0, 2));
    let color = ColorTracker::field_color(&field, 0);
    assert_eq!(color, None); // Headers get no color
}

#[test]
fn test_color_tracker_field_color_regular_field() {
    let field = Field::field("Name", "value", (0, 2));
    let color = ColorTracker::field_color(&field, 0);
    assert_eq!(color, Some(0));

    let color = ColorTracker::field_color(&field, 5);
    assert_eq!(color, Some(5));

    // Test wrapping
    let color = ColorTracker::field_color(&field, 13);
    assert_eq!(color, Some(1)); // 13 % 12 = 1
}

#[test]
fn test_get_field_color_index_header() {
    let packet = make_test_packet();
    let packets = vec![packet];

    // First field is a header (indent 0)
    let header = &packets[0].fields[0];
    let color = get_field_color_index(&packets, header);
    assert_eq!(color, None);
}

#[test]
fn test_get_field_color_index_regular_fields() {
    let packet = make_test_packet();
    let packets = vec![packet];

    // Second field is regular (indent 1)
    let field1 = &packets[0].fields[1];
    let color = get_field_color_index(&packets, field1);
    assert_eq!(color, Some(0));

    // Third field is subfield (indent 2)
    let field2 = &packets[0].fields[2];
    let color = get_field_color_index(&packets, field2);
    assert_eq!(color, Some(1));
}

#[test]
fn test_get_field_color_index_not_found() {
    let packet = make_test_packet();
    let packets = vec![packet];

    // Create a field that's not in the packet list
    let other_field = Field::field("Other", "value", (100, 200));
    let color = get_field_color_index(&packets, &other_field);
    assert_eq!(color, None);
}
