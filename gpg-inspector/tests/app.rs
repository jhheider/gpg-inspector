use gpg_inspector::app::{App, PanelFocus};

const TEST_KEY: &str = include_str!("../../fixtures/test.key");

#[test]
fn test_panel_focus_next() {
    assert_eq!(PanelFocus::Input.next(), PanelFocus::Data);
    assert_eq!(PanelFocus::Data.next(), PanelFocus::Input);
}

#[test]
fn test_app_new() {
    let app = App::new();
    assert!(app.input.is_empty());
    assert_eq!(app.cursor_pos, 0);
    assert!(app.packets.is_empty());
    assert!(app.raw_bytes.is_empty());
    assert_eq!(app.focus, PanelFocus::Input);
    assert_eq!(app.hex_scroll, 0);
    assert_eq!(app.data_scroll, 0);
    assert_eq!(app.selected_line, 0);
    assert!(app.highlighted_bytes.is_none());
    assert!(app.error_message.is_none());
    assert!(!app.should_quit);
}

#[test]
fn test_app_default() {
    let app = App::default();
    assert!(app.input.is_empty());
}

#[test]
fn test_parse_input_empty() {
    let mut app = App::new();
    app.input = "   ".to_string();
    app.parse_input();
    assert!(app.packets.is_empty());
    assert!(app.error_message.is_none());
}

#[test]
fn test_parse_input_valid_public_key() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    assert!(!app.packets.is_empty());
    assert!(app.error_message.is_none());
    assert!(!app.raw_bytes.is_empty());
}

#[test]
fn test_parse_input_invalid_armor() {
    let mut app = App::new();
    app.input = "not valid armor".to_string();
    app.parse_input();
    assert!(app.packets.is_empty());
    assert!(app.error_message.is_some());
    assert!(app.error_message.as_ref().unwrap().contains("Armor error"));
}

#[test]
fn test_parse_input_invalid_packet() {
    let mut app = App::new();
    // Valid armor header but invalid packet data
    app.input = "-----BEGIN PGP MESSAGE-----\n\nABCD\n=XXXX\n-----END PGP MESSAGE-----".to_string();
    app.parse_input();
    assert!(app.error_message.is_some());
    assert!(app.error_message.as_ref().unwrap().contains("error"));
}

#[test]
fn test_parse_input_parse_error() {
    let mut app = App::new();
    // Valid armor with correct CRC but invalid OpenPGP packet data
    // 0x00 byte as first byte is invalid (bit 7 must be set for packet header)
    app.input = "-----BEGIN PGP MESSAGE-----\n\nAA==\n=YWnT\n-----END PGP MESSAGE-----".to_string();
    app.parse_input();
    assert!(app.error_message.is_some(), "Should have error message");
    let msg = app.error_message.as_ref().unwrap();
    assert!(
        msg.contains("Parse error"),
        "Should be Parse error: {}",
        msg
    );
}

#[test]
fn test_get_all_fields() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    let fields = app.get_all_fields();
    assert!(!fields.is_empty());

    // First field should be the packet header
    assert!(fields[0].name.contains("Packet"));
}

#[test]
fn test_get_byte_color() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    // Byte 0 should have a color (packet header)
    // Some bytes will have colors from parsed fields
    let has_colors = (0..app.raw_bytes.len()).any(|i| app.get_byte_color(i).is_some());
    assert!(has_colors);

    // Byte way beyond the data should return None
    assert!(app.get_byte_color(999999).is_none());
}

#[test]
fn test_get_field_color_and_span() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    let fields = app.get_all_fields();
    assert!(!fields.is_empty());

    // Check that we can get color and span for fields
    for (field_idx, field) in fields.iter().enumerate() {
        let span = app.get_field_span(field);
        assert!(span.0 <= span.1, "span start should be <= end");

        // Color may be Some or None depending on field type (headers have no color)
        let _color = app.get_field_color(field_idx);
    }
}

#[test]
fn test_get_field_color_out_of_bounds() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    let fields = app.get_all_fields();
    assert!(!fields.is_empty());

    // Index beyond field count should return None
    let color = app.get_field_color(fields.len() + 100);
    assert_eq!(color, None);
}

#[test]
fn test_update_highlight() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    app.selected_line = 0;
    app.update_highlight();
    assert!(app.highlighted_bytes.is_some());

    // Invalid selection
    app.selected_line = 9999;
    app.update_highlight();
    assert!(app.highlighted_bytes.is_none());
}

#[test]
fn test_scroll_hex_to_highlight() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    // Set highlight to a known range
    app.highlighted_bytes = Some((100, 110));
    app.hex_scroll = 0;

    // Should scroll to show byte 100 (line 100/16 = 6)
    app.scroll_hex_to_highlight(5);
    assert!(app.hex_scroll > 0);
}

#[test]
fn test_scroll_hex_already_visible() {
    let mut app = App::new();
    app.highlighted_bytes = Some((0, 10));
    app.hex_scroll = 0;

    // Already visible, shouldn't change
    app.scroll_hex_to_highlight(10);
    assert_eq!(app.hex_scroll, 0);
}

#[test]
fn test_scroll_hex_up_when_above() {
    let mut app = App::new();
    // Highlight at byte 16 (line 1), but scrolled to line 5
    app.highlighted_bytes = Some((16, 32));
    app.hex_scroll = 5;

    // Should scroll up to show line 1
    app.scroll_hex_to_highlight(3);
    assert_eq!(app.hex_scroll, 1);
}

#[test]
fn test_move_selection_scrolls_up() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    // Start scrolled down
    app.selected_line = 5;
    app.data_scroll = 5;

    // Move up - should adjust scroll
    app.move_selection(-3, 10);
    assert_eq!(app.selected_line, 2);
    assert!(app.data_scroll <= 2);
}

#[test]
fn test_move_selection_down() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    app.selected_line = 0;
    app.move_selection(1, 10);
    assert_eq!(app.selected_line, 1);
}

#[test]
fn test_move_selection_up() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    app.selected_line = 5;
    app.move_selection(-1, 10);
    assert_eq!(app.selected_line, 4);
}

#[test]
fn test_move_selection_bounds() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    // Can't go below 0
    app.selected_line = 0;
    app.move_selection(-10, 10);
    assert_eq!(app.selected_line, 0);

    // Can't go above max
    let max = app.get_all_fields().len().saturating_sub(1);
    app.selected_line = max;
    app.move_selection(100, 10);
    assert_eq!(app.selected_line, max);
}

#[test]
fn test_move_selection_scrolls_data() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    app.selected_line = 0;
    app.data_scroll = 0;

    // Move down past visible area
    app.move_selection(20, 5);
    assert!(app.data_scroll > 0);
}

#[test]
fn test_insert_char() {
    let mut app = App::new();
    app.insert_char('a');
    assert_eq!(app.input, "a");
    assert_eq!(app.cursor_pos, 1);

    app.insert_char('b');
    assert_eq!(app.input, "ab");
    assert_eq!(app.cursor_pos, 2);
}

#[test]
fn test_insert_char_unicode() {
    let mut app = App::new();
    app.insert_char('é');
    assert_eq!(app.input, "é");
    assert_eq!(app.cursor_pos, 2); // é is 2 bytes in UTF-8
}

#[test]
fn test_delete_char() {
    let mut app = App::new();
    app.input = "abc".to_string();
    app.cursor_pos = 3;

    app.delete_char();
    assert_eq!(app.input, "ab");
    assert_eq!(app.cursor_pos, 2);
}

#[test]
fn test_delete_char_at_start() {
    let mut app = App::new();
    app.input = "abc".to_string();
    app.cursor_pos = 0;

    app.delete_char();
    assert_eq!(app.input, "abc"); // No change
    assert_eq!(app.cursor_pos, 0);
}

#[test]
fn test_delete_char_forward() {
    let mut app = App::new();
    app.input = "abc".to_string();
    app.cursor_pos = 1;

    app.delete_char_forward();
    assert_eq!(app.input, "ac");
    assert_eq!(app.cursor_pos, 1);
}

#[test]
fn test_delete_char_forward_at_end() {
    let mut app = App::new();
    app.input = "abc".to_string();
    app.cursor_pos = 3;

    app.delete_char_forward();
    assert_eq!(app.input, "abc"); // No change
}

#[test]
fn test_move_cursor_left() {
    let mut app = App::new();
    app.input = "abc".to_string();
    app.cursor_pos = 2;

    app.move_cursor_left();
    assert_eq!(app.cursor_pos, 1);

    app.move_cursor_left();
    assert_eq!(app.cursor_pos, 0);

    app.move_cursor_left();
    assert_eq!(app.cursor_pos, 0); // Can't go negative
}

#[test]
fn test_move_cursor_right() {
    let mut app = App::new();
    app.input = "abc".to_string();
    app.cursor_pos = 1;

    app.move_cursor_right();
    assert_eq!(app.cursor_pos, 2);

    app.move_cursor_right();
    assert_eq!(app.cursor_pos, 3);

    app.move_cursor_right();
    assert_eq!(app.cursor_pos, 3); // Can't go past end
}

#[test]
fn test_move_cursor_to_start() {
    let mut app = App::new();
    app.input = "abc".to_string();
    app.cursor_pos = 2;

    app.move_cursor_to_start();
    assert_eq!(app.cursor_pos, 0);
}

#[test]
fn test_move_cursor_to_end() {
    let mut app = App::new();
    app.input = "abc".to_string();
    app.cursor_pos = 0;

    app.move_cursor_to_end();
    assert_eq!(app.cursor_pos, 3);
}

#[test]
fn test_paste_text() {
    let mut app = App::new();
    app.input = "ac".to_string();
    app.cursor_pos = 1;

    app.paste_text("b");
    assert_eq!(app.input, "abc");
    assert_eq!(app.cursor_pos, 2);
}

#[test]
fn test_paste_multiline() {
    let mut app = App::new();
    app.paste_text("line1\nline2");
    assert_eq!(app.input, "line1\nline2");
    assert_eq!(app.cursor_pos, 11);
}

#[test]
fn test_clear_input() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.cursor_pos = 50;
    app.parse_input();

    app.clear_input();
    assert!(app.input.is_empty());
    assert_eq!(app.cursor_pos, 0);
    assert!(app.packets.is_empty());
}
