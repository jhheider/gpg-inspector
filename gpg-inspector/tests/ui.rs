use ratatui::layout::Rect;

use gpg_inspector::ui::colors::{get_color, PALETTE};
use gpg_inspector::ui::{get_data_panel_area, get_hex_panel_area};

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
    assert!(hex_area.y + hex_area.height <= data_area.y || data_area.y + data_area.height <= hex_area.y);
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
