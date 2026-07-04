use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::layout::Rect;

use gpg_inspector::app::{App, PanelFocus};
use gpg_inspector::event::handle_event;

const TEST_KEY: &str = include_str!("../../fixtures/test.key");

fn key_event(code: KeyCode) -> Event {
    Event::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    })
}

fn key_event_ctrl(code: KeyCode) -> Event {
    Event::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    })
}

fn test_rect() -> Rect {
    Rect::new(0, 0, 120, 40)
}

// Quit tests

#[test]
fn test_ctrl_c_quits() {
    let mut app = App::new();
    handle_event(&mut app, key_event_ctrl(KeyCode::Char('c')), test_rect());
    assert!(app.should_quit);
}

#[test]
fn test_ctrl_q_quits() {
    let mut app = App::new();
    handle_event(&mut app, key_event_ctrl(KeyCode::Char('q')), test_rect());
    assert!(app.should_quit);
}

#[test]
fn test_esc_does_not_quit() {
    // Esc used to quit; it must not, to avoid accidental data loss
    let mut app = App::new();
    handle_event(&mut app, key_event(KeyCode::Esc), test_rect());
    assert!(!app.should_quit);
}

// Help overlay tests

#[test]
fn test_f1_toggles_help() {
    let mut app = App::new();
    handle_event(&mut app, key_event(KeyCode::F(1)), test_rect());
    assert!(app.show_help);
    handle_event(&mut app, key_event(KeyCode::F(1)), test_rect());
    assert!(!app.show_help);
}

#[test]
fn test_question_mark_opens_help_in_data_panel() {
    let mut app = App::new();
    app.focus = PanelFocus::Data;
    handle_event(&mut app, key_event(KeyCode::Char('?')), test_rect());
    assert!(app.show_help);
}

#[test]
fn test_question_mark_is_text_in_input_panel() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    handle_event(&mut app, key_event(KeyCode::Char('?')), test_rect());
    assert!(!app.show_help);
    assert_eq!(app.input, "?");
}

#[test]
fn test_help_swallows_keys_and_closes_on_esc() {
    let mut app = App::new();
    app.show_help = true;
    app.focus = PanelFocus::Input;

    // Other keys are swallowed, not typed into the input
    handle_event(&mut app, key_event(KeyCode::Char('x')), test_rect());
    assert!(app.show_help);
    assert!(app.input.is_empty());

    handle_event(&mut app, key_event(KeyCode::Esc), test_rect());
    assert!(!app.show_help);
    assert!(!app.should_quit);
}

// Detail view tests

#[test]
fn test_enter_opens_detail_in_data_panel() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;

    handle_event(&mut app, key_event(KeyCode::Enter), test_rect());
    assert!(app.show_detail);

    handle_event(&mut app, key_event(KeyCode::Enter), test_rect());
    assert!(!app.show_detail);
}

#[test]
fn test_enter_no_detail_when_empty() {
    let mut app = App::new();
    app.focus = PanelFocus::Data;
    handle_event(&mut app, key_event(KeyCode::Enter), test_rect());
    assert!(!app.show_detail);
}

#[test]
fn test_detail_closes_on_esc() {
    let mut app = App::new();
    app.show_detail = true;
    handle_event(&mut app, key_event(KeyCode::Esc), test_rect());
    assert!(!app.show_detail);
    assert!(!app.should_quit);
}

// Search tests

#[test]
fn test_search_flow() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;

    // `/` opens search
    handle_event(&mut app, key_event(KeyCode::Char('/')), test_rect());
    assert!(app.search_active);

    // Typing builds the query
    for c in "version".chars() {
        handle_event(&mut app, key_event(KeyCode::Char(c)), test_rect());
    }
    assert_eq!(app.search_query, "version");

    // Backspace edits it
    handle_event(&mut app, key_event(KeyCode::Backspace), test_rect());
    assert_eq!(app.search_query, "versio");
    handle_event(&mut app, key_event(KeyCode::Char('n')), test_rect());

    // Enter confirms and jumps to the first match
    handle_event(&mut app, key_event(KeyCode::Enter), test_rect());
    assert!(!app.search_active);
    let matches = app.search_matches();
    assert!(!matches.is_empty());
    assert_eq!(app.selected_line, matches[0]);
}

#[test]
fn test_search_esc_cancels() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;

    handle_event(&mut app, key_event(KeyCode::Char('/')), test_rect());
    handle_event(&mut app, key_event(KeyCode::Char('v')), test_rect());
    handle_event(&mut app, key_event(KeyCode::Esc), test_rect());
    assert!(!app.search_active);
    assert!(app.search_query.is_empty());
    assert!(!app.should_quit);
}

#[test]
fn test_search_next_prev_match() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;
    app.search_query = "version".to_string();

    let matches = app.search_matches();
    assert!(matches.len() >= 2, "test key should have multiple versions");

    app.selected_line = matches[0];
    handle_event(&mut app, key_event(KeyCode::Char('n')), test_rect());
    assert_eq!(app.selected_line, matches[1]);

    handle_event(&mut app, key_event(KeyCode::Char('N')), test_rect());
    assert_eq!(app.selected_line, matches[0]);

    // Wraps around backwards from the first match
    handle_event(&mut app, key_event(KeyCode::Char('N')), test_rect());
    assert_eq!(app.selected_line, *matches.last().unwrap());

    // ... and forwards from the last
    handle_event(&mut app, key_event(KeyCode::Char('n')), test_rect());
    assert_eq!(app.selected_line, matches[0]);
}

#[test]
fn test_search_unknown_key_ignored() {
    let mut app = App::new();
    app.focus = PanelFocus::Data;
    app.search_active = true;
    handle_event(&mut app, key_event(KeyCode::F(5)), test_rect());
    assert!(app.search_active);
}

// Focus tests

#[test]
fn test_tab_cycles_focus() {
    let mut app = App::new();
    assert_eq!(app.focus, PanelFocus::Input);

    handle_event(&mut app, key_event(KeyCode::Tab), test_rect());
    assert_eq!(app.focus, PanelFocus::Data);

    handle_event(&mut app, key_event(KeyCode::Tab), test_rect());
    assert_eq!(app.focus, PanelFocus::Input);
}

#[test]
fn test_backtab_cycles_focus() {
    let mut app = App::new();
    app.focus = PanelFocus::Data;

    handle_event(&mut app, key_event(KeyCode::BackTab), test_rect());
    assert_eq!(app.focus, PanelFocus::Input);

    handle_event(&mut app, key_event(KeyCode::BackTab), test_rect());
    assert_eq!(app.focus, PanelFocus::Data);
}

// Input panel tests

#[test]
fn test_input_char_insert() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;

    handle_event(&mut app, key_event(KeyCode::Char('a')), test_rect());
    assert_eq!(app.input, "a");
}

#[test]
fn test_input_backspace() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "abc".to_string();
    app.cursor_pos = 3;

    handle_event(&mut app, key_event(KeyCode::Backspace), test_rect());
    assert_eq!(app.input, "ab");
}

#[test]
fn test_input_delete() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "abc".to_string();
    app.cursor_pos = 1;

    handle_event(&mut app, key_event(KeyCode::Delete), test_rect());
    assert_eq!(app.input, "ac");
}

#[test]
fn test_input_cursor_left() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "abc".to_string();
    app.cursor_pos = 2;

    handle_event(&mut app, key_event(KeyCode::Left), test_rect());
    assert_eq!(app.cursor_pos, 1);
}

#[test]
fn test_input_cursor_right() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "abc".to_string();
    app.cursor_pos = 1;

    handle_event(&mut app, key_event(KeyCode::Right), test_rect());
    assert_eq!(app.cursor_pos, 2);
}

#[test]
fn test_input_home() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "abc".to_string();
    app.cursor_pos = 2;

    handle_event(&mut app, key_event(KeyCode::Home), test_rect());
    assert_eq!(app.cursor_pos, 0);
}

#[test]
fn test_input_end() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "abc".to_string();
    app.cursor_pos = 0;

    handle_event(&mut app, key_event(KeyCode::End), test_rect());
    assert_eq!(app.cursor_pos, 3);
}

#[test]
fn test_input_enter() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "line1".to_string();
    app.cursor_pos = 5;

    handle_event(&mut app, key_event(KeyCode::Enter), test_rect());
    assert_eq!(app.input, "line1\n");
}

#[test]
fn test_input_ctrl_a() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "abc".to_string();
    app.cursor_pos = 3;

    handle_event(&mut app, key_event_ctrl(KeyCode::Char('a')), test_rect());
    assert_eq!(app.cursor_pos, 0);
}

#[test]
fn test_input_ctrl_e() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "abc".to_string();
    app.cursor_pos = 0;

    handle_event(&mut app, key_event_ctrl(KeyCode::Char('e')), test_rect());
    assert_eq!(app.cursor_pos, 3);
}

#[test]
fn test_input_ctrl_k_clears() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "some text".to_string();
    app.cursor_pos = 5;

    handle_event(&mut app, key_event_ctrl(KeyCode::Char('k')), test_rect());
    assert!(app.input.is_empty());
    assert_eq!(app.cursor_pos, 0);
}

#[test]
fn test_input_ctrl_v_noop() {
    // Ctrl+V is intentionally a no-op; actual paste comes via Event::Paste
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "test".to_string();
    app.cursor_pos = 4;

    handle_event(&mut app, key_event_ctrl(KeyCode::Char('v')), test_rect());
    // Should not change anything
    assert_eq!(app.input, "test");
    assert_eq!(app.cursor_pos, 4);
}

#[test]
fn test_ctrl_unknown_key_noop() {
    // Unknown ctrl key combinations should be ignored
    let mut app = App::new();
    app.focus = PanelFocus::Input;

    handle_event(&mut app, key_event_ctrl(KeyCode::Char('z')), test_rect());
    assert!(!app.should_quit);
}

#[test]
fn test_input_unknown_key_noop() {
    // Unknown keys in input mode should be ignored
    let mut app = App::new();
    app.focus = PanelFocus::Input;
    app.input = "test".to_string();

    handle_event(&mut app, key_event(KeyCode::F(5)), test_rect());
    assert_eq!(app.input, "test");
}

#[test]
fn test_data_unknown_key_noop() {
    // Unknown keys in data mode should be ignored
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;
    app.selected_line = 5;

    handle_event(&mut app, key_event(KeyCode::F(5)), test_rect());
    assert_eq!(app.selected_line, 5);
}

#[test]
fn test_paste_event() {
    let mut app = App::new();
    app.focus = PanelFocus::Input;

    let event = Event::Paste("pasted text".to_string());
    handle_event(&mut app, event, test_rect());
    assert_eq!(app.input, "pasted text");
}

#[test]
fn test_paste_only_in_input_mode() {
    let mut app = App::new();
    app.focus = PanelFocus::Data;

    let event = Event::Paste("should not paste".to_string());
    handle_event(&mut app, event, test_rect());
    assert!(app.input.is_empty());
}

// Data panel tests

#[test]
fn test_data_selection_down() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;
    app.selected_line = 0;

    handle_event(&mut app, key_event(KeyCode::Down), test_rect());
    assert_eq!(app.selected_line, 1);
}

#[test]
fn test_data_selection_up() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;
    app.selected_line = 5;

    handle_event(&mut app, key_event(KeyCode::Up), test_rect());
    assert_eq!(app.selected_line, 4);
}

#[test]
fn test_data_selection_j_k() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;
    app.selected_line = 5;

    handle_event(&mut app, key_event(KeyCode::Char('j')), test_rect());
    assert_eq!(app.selected_line, 6);

    handle_event(&mut app, key_event(KeyCode::Char('k')), test_rect());
    assert_eq!(app.selected_line, 5);
}

#[test]
fn test_data_page_down() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;
    app.selected_line = 0;

    handle_event(&mut app, key_event(KeyCode::PageDown), test_rect());
    assert!(app.selected_line > 0);
}

#[test]
fn test_data_page_up() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;
    app.selected_line = 20;

    handle_event(&mut app, key_event(KeyCode::PageUp), test_rect());
    assert!(app.selected_line < 20);
}

#[test]
fn test_data_home() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;
    app.selected_line = 10;

    handle_event(&mut app, key_event(KeyCode::Home), test_rect());
    assert_eq!(app.selected_line, 0);
}

#[test]
fn test_data_end() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;
    app.selected_line = 0;

    let total_fields = app.get_all_fields().len();
    handle_event(&mut app, key_event(KeyCode::End), test_rect());
    assert_eq!(app.selected_line, total_fields - 1);
}

#[test]
fn test_data_selection_updates_highlight() {
    let mut app = App::new();
    app.input = TEST_KEY.to_string();
    app.parse_input();
    app.focus = PanelFocus::Data;
    app.selected_line = 0;
    app.highlighted_bytes = None;

    handle_event(&mut app, key_event(KeyCode::Down), test_rect());
    assert!(app.highlighted_bytes.is_some());
}

// Binary mode event tests

const TEST_KEY_BIN: &[u8] = include_bytes!("../../fixtures/test.key.gpg");

#[test]
fn test_binary_mode_editing_keys_noop() {
    let mut app = App::new();
    app.load_binary(TEST_KEY_BIN.to_vec(), "test.key.gpg");
    app.focus = PanelFocus::Input;
    let packet_count = app.packets.len();

    handle_event(&mut app, key_event(KeyCode::Char('x')), test_rect());
    handle_event(&mut app, key_event(KeyCode::Backspace), test_rect());
    handle_event(&mut app, key_event(KeyCode::Enter), test_rect());
    handle_event(&mut app, Event::Paste("junk".to_string()), test_rect());

    assert!(app.input.is_empty());
    assert_eq!(app.packets.len(), packet_count);
    assert!(app.is_binary());
}

#[test]
fn test_binary_mode_ctrl_k_resets() {
    let mut app = App::new();
    app.load_binary(TEST_KEY_BIN.to_vec(), "test.key.gpg");
    app.focus = PanelFocus::Input;

    handle_event(&mut app, key_event_ctrl(KeyCode::Char('k')), test_rect());
    assert!(!app.is_binary());
    assert!(app.packets.is_empty());
}
