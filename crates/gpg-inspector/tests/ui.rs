use ratatui::layout::Rect;

use gpg_inspector::app::App;
use gpg_inspector::ui::colors::{ColorTracker, PALETTE, get_color};
use gpg_inspector::ui::data_panel::truncate_chars;
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
    Packet::new(
        0,
        10,
        PacketTag::UserId,
        PacketBody::Unknown(vec![]),
        vec![
            Field::packet("Packet: User ID", "8 bytes", (0, 2)),
            Field::field("User ID", "test", (2, 6)),
            Field::subfield("Domain", "example.com", (6, 10)),
        ],
    )
}

/// Row colors: headers get none, non-header fields rotate, and the row
/// assignment agrees with the byte-level ColorTracker.
#[test]
fn test_row_colors_match_byte_tracker() {
    let mut app = App::new();
    app.packets = vec![make_test_packet()];
    app.raw_bytes = std::sync::Arc::from([0u8; 10]);
    app.rebuild_rows();

    // Header row: no color
    assert_eq!(app.rows[0].color, None);
    assert_eq!(app.get_field_color(0), None);

    // Field and subfield rotate 0, 1
    assert_eq!(app.rows[1].color, Some(0));
    assert_eq!(app.rows[2].color, Some(1));

    // Byte tracker paints the same colors over the spans
    let tracker = ColorTracker::compute_from_packets(&app.packets, 10);
    assert_eq!(tracker.get_color(2), app.rows[1].color);
    assert_eq!(tracker.get_color(6), app.rows[2].color);
    assert_eq!(tracker.get_color(0), None);

    // And the app's per-stream tracker agrees byte-for-byte
    for i in 0..10 {
        assert_eq!(app.color_trackers[0].get_color(i), tracker.get_color(i));
    }
}

#[test]
fn test_truncate_chars() {
    assert_eq!(truncate_chars("short", 10), "short");
    assert_eq!(truncate_chars("exactly-ten", 11), "exactly-ten");
    assert_eq!(truncate_chars("a much longer string", 10), "a much ...");
    // Multi-byte characters must not panic or split
    assert_eq!(truncate_chars("▾ Packet: Public Key", 10), "▾ Packe...");
    assert_eq!(truncate_chars("héllo wörld exträ", 10), "héllo w...");
}

// Theme tests

use gpg_inspector::ui::colors::{LIGHT_PALETTE, Theme};

#[test]
fn test_theme_from_colorfgbg() {
    assert_eq!(Theme::from_colorfgbg(None), Theme::dark());
    assert_eq!(Theme::from_colorfgbg(Some("15;0")), Theme::dark());
    assert_eq!(Theme::from_colorfgbg(Some("0;15")), Theme::light());
    assert_eq!(Theme::from_colorfgbg(Some("0;default;7")), Theme::light());
    assert_eq!(Theme::from_colorfgbg(Some("garbage")), Theme::dark());
    assert_eq!(Theme::from_colorfgbg(Some("")), Theme::dark());
}

#[test]
fn test_theme_resolve() {
    assert_eq!(Theme::resolve("dark", Some("0;15")), Theme::dark());
    assert_eq!(Theme::resolve("light", None), Theme::light());
    assert_eq!(Theme::resolve("auto", Some("0;15")), Theme::light());
    assert_eq!(Theme::resolve("auto", None), Theme::dark());
    assert_eq!(Theme::default(), Theme::dark());
}

#[test]
fn test_theme_color_wraps() {
    let theme = Theme::dark();
    assert_eq!(theme.color(0), theme.color(12));
    assert_eq!(theme.color(0), PALETTE[0]);

    let light = Theme::light();
    assert_eq!(light.color(3), LIGHT_PALETTE[3]);
}

#[test]
fn test_light_palette_distinct() {
    for (i, color) in LIGHT_PALETTE.iter().enumerate() {
        for other in &LIGHT_PALETTE[i + 1..] {
            assert_ne!(color, other);
        }
    }
}
