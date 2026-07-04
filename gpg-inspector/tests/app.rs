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

// Selection clamping on reparse

#[test]
fn test_reparse_clamps_selection() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    let total = app.get_all_fields().len();
    app.selected_line = total - 1;
    app.data_scroll = total - 1;
    app.update_highlight();

    // Clearing the input shrinks the field list to zero
    app.clear_input();
    assert_eq!(app.selected_line, 0);
    assert_eq!(app.data_scroll, 0);
    assert_eq!(app.hex_scroll, 0);
    assert!(app.highlighted_bytes.is_none());
}

#[test]
fn test_reparse_keeps_valid_selection() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.selected_line = 3;
    app.update_highlight();

    // Reparsing the same input should not move a still-valid selection
    app.parse_input();
    assert_eq!(app.selected_line, 3);
    assert!(app.highlighted_bytes.is_some());
}

// Search tests

#[test]
fn test_search_matches_empty_query() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    assert!(app.search_matches().is_empty());
}

#[test]
fn test_search_matches_case_insensitive() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();

    app.search_query = "VERSION".to_string();
    let upper = app.search_matches();
    app.search_query = "version".to_string();
    let lower = app.search_matches();

    assert!(!lower.is_empty());
    assert_eq!(upper, lower);
}

#[test]
fn test_search_matches_no_hits() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.search_query = "zzzz-no-such-field".to_string();
    assert!(app.search_matches().is_empty());
}

#[test]
fn test_jump_to_match_no_matches_is_noop() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.selected_line = 2;
    app.search_query = "zzzz-no-such-field".to_string();

    app.jump_to_match(true, 20);
    assert_eq!(app.selected_line, 2);
    app.jump_to_first_match(20);
    assert_eq!(app.selected_line, 2);
}

#[test]
fn test_jump_to_first_match_prefers_at_or_after() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.search_query = "version".to_string();

    let matches = app.search_matches();
    assert!(matches.len() >= 2);

    // From before the second match, land on the second match
    app.selected_line = matches[0] + 1;
    app.jump_to_first_match(20);
    assert_eq!(app.selected_line, matches[1]);

    // From past the last match, wrap to the first
    app.selected_line = *matches.last().unwrap() + 1;
    app.jump_to_first_match(20);
    assert_eq!(app.selected_line, matches[0]);
}

#[test]
fn test_select_line_scrolls_into_view() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    let total = app.get_all_fields().len();
    assert!(total > 5);

    // Jump far down with a small window: view scrolls to contain selection
    app.select_line(total - 1, 5);
    assert_eq!(app.selected_line, total - 1);
    assert_eq!(app.data_scroll, total - 5);
    assert!(app.highlighted_bytes.is_some());

    // Jump back up: scroll follows
    app.select_line(0, 5);
    assert_eq!(app.selected_line, 0);
    assert_eq!(app.data_scroll, 0);

    // Out-of-range line clamps to the last field
    app.select_line(usize::MAX, 5);
    assert_eq!(app.selected_line, total - 1);
}

#[test]
fn test_select_line_empty_noop() {
    let mut app = App::new();
    app.select_line(3, 5);
    assert_eq!(app.selected_line, 0);
}

// Binary input tests

const TEST_KEY_BIN: &[u8] = include_bytes!("../../fixtures/test.key.gpg");
const TEST_COMPRESSED: &[u8] = include_bytes!("../../fixtures/test.compressed.gpg");
const TEST_CLEARTEXT: &str = include_str!("../../fixtures/test.cleartext.asc");

#[test]
fn test_load_binary_parses_and_focuses_data() {
    use gpg_inspector::app::InputSource;

    let mut app = App::new();
    app.load_binary(TEST_KEY_BIN.to_vec(), "test.key.gpg");

    assert!(app.is_binary());
    assert_eq!(
        app.source,
        InputSource::Binary {
            origin: "test.key.gpg".to_string(),
            len: TEST_KEY_BIN.len()
        }
    );
    assert!(!app.packets.is_empty());
    assert!(app.error_message.is_none());
    assert_eq!(app.focus, PanelFocus::Data);
    assert_eq!(app.raw_bytes.len(), TEST_KEY_BIN.len());
}

#[test]
fn test_load_binary_invalid_reports_error() {
    let mut app = App::new();
    // Truncated packet: declares a 32-byte body but provides 1 byte
    app.load_binary(vec![0xC6, 0x20, 0x01], "junk");
    assert!(app.is_binary());
    assert!(app.error_message.is_some());
    assert!(app.packets.is_empty());
}

#[test]
fn test_binary_mode_is_read_only() {
    let mut app = App::new();
    app.load_binary(TEST_KEY_BIN.to_vec(), "test.key.gpg");
    let packet_count = app.packets.len();

    app.insert_char('x');
    app.paste_text("garbage");
    app.delete_char();
    app.delete_char_forward();

    assert!(app.input.is_empty());
    assert!(app.is_binary());
    assert_eq!(app.packets.len(), packet_count);
}

#[test]
fn test_binary_mode_clear_input_resets_to_text() {
    let mut app = App::new();
    app.load_binary(TEST_KEY_BIN.to_vec(), "test.key.gpg");

    app.clear_input();
    assert!(!app.is_binary());
    assert!(app.packets.is_empty());

    // Editing works again
    app.insert_char('a');
    assert_eq!(app.input, "a");
}

// Multi-block and cleartext state tests

#[test]
fn test_parse_input_multi_block_state() {
    let mut app = App::new();
    app.input = format!("{}\n{}", TEST_KEY, TEST_KEY);
    app.parse_input();

    assert_eq!(app.armor_blocks.len(), 2);
    assert!(app.cleartext.is_none());
    assert!(app.error_message.is_none());
}

#[test]
fn test_parse_input_cleartext_state() {
    let mut app = App::new();
    app.input = TEST_CLEARTEXT.to_string();
    app.parse_input();

    assert!(app.cleartext.is_some());
    assert_eq!(app.armor_blocks.len(), 1);
    assert!(app.error_message.is_none());

    // Clearing resets the armor state
    app.clear_input();
    assert!(app.cleartext.is_none());
    assert!(app.armor_blocks.is_empty());
}

// Nested (decompressed) field tests

#[test]
fn test_nested_fields_flattened_and_flagged() {
    let mut app = App::new();
    app.load_binary(TEST_COMPRESSED.to_vec(), "compressed");

    let flagged = app.get_all_fields_flagged();
    assert!(flagged.iter().any(|&(_, child)| child), "no child fields");
    assert!(flagged.iter().any(|&(_, child)| !child));

    // Child fields appear in the plain flatten too
    assert_eq!(app.get_all_fields().len(), flagged.len());

    // The nested Literal Data packet header is present
    assert!(
        flagged
            .iter()
            .any(|&(f, child)| child && f.name.contains("Literal Data"))
    );
}

#[test]
fn test_nested_fields_highlight_in_their_own_stream() {
    let mut app = App::new();
    app.load_binary(TEST_COMPRESSED.to_vec(), "compressed");

    let (child_field_idx, top_idx) = {
        let flagged = app.get_all_fields_flagged();
        (
            flagged
                .iter()
                .position(|&(f, child)| child && f.indent > 0)
                .expect("no non-header child field"),
            flagged
                .iter()
                .position(|&(f, child)| !child && f.indent > 0)
                .unwrap(),
        )
    };

    // The decompressed buffer is registered as a second stream
    assert_eq!(app.streams.len(), 2);
    assert_eq!(app.color_trackers.len(), 2);

    // Selecting a nested field switches the displayed stream and
    // highlights within it (colors restart per stream)
    assert!(app.get_field_color(child_field_idx).is_some());
    app.selected_line = child_field_idx;
    app.update_highlight();
    assert!(app.highlighted_bytes.is_some());
    assert_eq!(app.display_stream(), 1);
    let child_span = app.rows[child_field_idx].span;
    assert!(child_span.1 <= app.display_bytes().len());

    // A top-level field displays the raw stream
    app.selected_line = top_idx;
    app.update_highlight();
    assert_eq!(app.display_stream(), 0);
    assert!(app.highlighted_bytes.is_some());
}
