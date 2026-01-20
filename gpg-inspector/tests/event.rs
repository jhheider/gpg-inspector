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
fn test_esc_quits() {
    let mut app = App::new();
    handle_event(&mut app, key_event(KeyCode::Esc), test_rect());
    assert!(app.should_quit);
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

    handle_event(&mut app, key_event(KeyCode::F(1)), test_rect());
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

    handle_event(&mut app, key_event(KeyCode::F(1)), test_rect());
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
