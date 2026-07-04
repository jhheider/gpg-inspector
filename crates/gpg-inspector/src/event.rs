use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};

use crate::app::{App, PanelFocus};
use crate::clipboard;
use crate::ui::{data_panel, get_data_panel_area, get_hex_panel_area, get_input_panel_area};
use ratatui::layout::{Position, Rect};

pub fn handle_event(app: &mut App, event: Event, size: Rect) {
    match event {
        Event::Key(key) => handle_key(app, key, size),
        Event::Paste(text) => {
            if app.focus == PanelFocus::Input {
                app.paste_text(&text);
            }
        }
        Event::Mouse(mouse) => handle_mouse(app, mouse, size),
        _ => {}
    }
}

fn data_visible_lines(size: Rect) -> usize {
    data_panel::data_panel_visible_lines(get_data_panel_area(size))
}

fn hex_visible_lines(size: Rect) -> usize {
    get_hex_panel_area(size).height.saturating_sub(2) as usize
}

fn handle_key(app: &mut App, key: KeyEvent, size: Rect) {
    // Status feedback (e.g. "Copied ...") lives until the next keypress
    app.status_message = None;

    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('c') | KeyCode::Char('q') => {
                app.should_quit = true;
            }
            KeyCode::Char('a') if app.focus == PanelFocus::Input => {
                app.move_cursor_to_start();
            }
            KeyCode::Char('e') if app.focus == PanelFocus::Input => {
                app.move_cursor_to_end();
            }
            KeyCode::Char('k') if app.focus == PanelFocus::Input => {
                app.clear_input();
            }
            KeyCode::Char('v') if app.focus == PanelFocus::Input => {}
            _ => {}
        }
        return;
    }

    // Modal states swallow all keys until dismissed
    if app.show_help {
        if matches!(
            key.code,
            KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Esc | KeyCode::F(1)
        ) {
            app.show_help = false;
        }
        return;
    }

    if app.show_detail {
        match key.code {
            KeyCode::Enter | KeyCode::Char('q') | KeyCode::Esc => {
                app.show_detail = false;
            }
            KeyCode::Char('y') => yank_value(app),
            KeyCode::Char('Y') => yank_bytes(app),
            _ => {}
        }
        return;
    }

    if app.search_active {
        handle_search_key(app, key, size);
        return;
    }

    match key.code {
        KeyCode::Tab => {
            app.focus = app.focus.next();
        }
        KeyCode::BackTab => {
            app.focus = app.focus.prev();
        }
        KeyCode::F(1) => {
            app.show_help = true;
        }
        // Esc intentionally does nothing; quit is Ctrl+C / Ctrl+Q
        _ => match app.focus {
            PanelFocus::Input => handle_input_key(app, key),
            PanelFocus::Hex => handle_hex_key(app, key, size),
            PanelFocus::Data => handle_data_key(app, key, size),
        },
    }
}

fn handle_search_key(app: &mut App, key: KeyEvent, size: Rect) {
    let visible_lines = data_visible_lines(size);

    match key.code {
        KeyCode::Esc => {
            app.search_active = false;
            app.search_query.clear();
        }
        KeyCode::Enter => {
            app.search_active = false;
            app.jump_to_first_match(visible_lines);
        }
        KeyCode::Backspace => {
            app.search_query.pop();
        }
        KeyCode::Char(c) => {
            app.search_query.push(c);
        }
        _ => {}
    }
}

fn handle_input_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char(c) => {
            app.insert_char(c);
        }
        KeyCode::Backspace => {
            app.delete_char();
        }
        KeyCode::Delete => {
            app.delete_char_forward();
        }
        KeyCode::Left => {
            app.move_cursor_left();
        }
        KeyCode::Right => {
            app.move_cursor_right();
        }
        KeyCode::Home => {
            app.move_cursor_to_start();
        }
        KeyCode::End => {
            app.move_cursor_to_end();
        }
        KeyCode::Enter => {
            app.insert_char('\n');
        }
        _ => {}
    }
}

fn handle_hex_key(app: &mut App, key: KeyEvent, size: Rect) {
    let visible_lines = hex_visible_lines(size);

    match key.code {
        KeyCode::Left | KeyCode::Char('h') => {
            app.move_hex_cursor(-1, visible_lines);
        }
        KeyCode::Right | KeyCode::Char('l') => {
            app.move_hex_cursor(1, visible_lines);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.move_hex_cursor(-16, visible_lines);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.move_hex_cursor(16, visible_lines);
        }
        KeyCode::PageUp => {
            app.move_hex_cursor(-(16 * visible_lines as isize), visible_lines);
        }
        KeyCode::PageDown => {
            app.move_hex_cursor(16 * visible_lines as isize, visible_lines);
        }
        KeyCode::Home | KeyCode::Char('g') => {
            app.set_hex_cursor(0, visible_lines);
        }
        KeyCode::End | KeyCode::Char('G') => {
            app.set_hex_cursor(usize::MAX, visible_lines);
        }
        KeyCode::Enter | KeyCode::Char('f') => {
            app.jump_to_hex_owner(data_visible_lines(size));
        }
        KeyCode::Char('?') => {
            app.show_help = true;
        }
        _ => {}
    }
}

fn handle_data_key(app: &mut App, key: KeyEvent, size: Rect) {
    let visible_lines = data_visible_lines(size);

    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            app.move_selection(-1, visible_lines);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.move_selection(1, visible_lines);
        }
        KeyCode::PageUp => {
            app.move_selection(-(visible_lines as isize), visible_lines);
        }
        KeyCode::PageDown => {
            app.move_selection(visible_lines as isize, visible_lines);
        }
        KeyCode::Home => {
            app.selected_line = 0;
            app.data_scroll = 0;
            app.update_highlight();
            app.scroll_hex_to_highlight(visible_lines);
        }
        KeyCode::End => {
            let total = app.visible.len();
            app.selected_line = total.saturating_sub(1);
            app.data_scroll = total.saturating_sub(visible_lines);
            app.update_highlight();
            app.scroll_hex_to_highlight(visible_lines);
        }
        KeyCode::Enter => {
            if !app.visible.is_empty() {
                app.show_detail = true;
            }
        }
        KeyCode::Char(' ') => {
            app.toggle_fold(visible_lines);
        }
        KeyCode::Char('h') => {
            app.set_fold(true, visible_lines);
        }
        KeyCode::Char('l') => {
            app.set_fold(false, visible_lines);
        }
        KeyCode::Char('/') => {
            app.search_active = true;
            app.search_query.clear();
        }
        KeyCode::Char('n') => {
            app.jump_to_match(true, visible_lines);
        }
        KeyCode::Char('N') => {
            app.jump_to_match(false, visible_lines);
        }
        KeyCode::Char('y') => yank_value(app),
        KeyCode::Char('Y') => yank_bytes(app),
        KeyCode::Char('?') => {
            app.show_help = true;
        }
        _ => {}
    }
}

/// Copies the selected row's value to the clipboard (OSC 52).
fn yank_value(app: &mut App) {
    let Some(row) = app.selected_row() else {
        return;
    };
    let payload = row.value.as_bytes().to_vec();
    let desc = format!("{} chars", row.value.chars().count());
    yank(app, payload, desc);
}

/// Copies the selected row's raw bytes, hex-encoded, to the clipboard.
fn yank_bytes(app: &mut App) {
    let Some(row) = app.selected_row() else {
        return;
    };
    let (start, end) = row.span;
    let Some(stream) = app.streams.get(row.stream) else {
        return;
    };
    if end <= start || end > stream.len() {
        return;
    }
    let hex: String = stream[start..end]
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    let desc = format!("{} bytes as hex", end - start);
    yank(app, hex.into_bytes(), desc);
}

fn yank(app: &mut App, mut payload: Vec<u8>, desc: String) {
    let truncated = payload.len() > clipboard::MAX_COPY_BYTES;
    if truncated {
        payload.truncate(clipboard::MAX_COPY_BYTES);
    }
    let _ = clipboard::copy(&payload);
    app.status_message = Some(if truncated {
        format!("Copied {} (truncated to 64 KB)", desc)
    } else {
        format!("Copied {}", desc)
    });
}

fn handle_mouse(app: &mut App, mouse: MouseEvent, size: Rect) {
    let pos = Position::new(mouse.column, mouse.row);
    let input_area = get_input_panel_area(size);
    let hex_area = get_hex_panel_area(size);
    let data_area = get_data_panel_area(size);

    match mouse.kind {
        MouseEventKind::ScrollUp => {
            if data_area.contains(pos) {
                app.move_selection(-3, data_panel::data_panel_visible_lines(data_area));
            } else if hex_area.contains(pos) {
                app.scroll_hex(-3);
            }
        }
        MouseEventKind::ScrollDown => {
            if data_area.contains(pos) {
                app.move_selection(3, data_panel::data_panel_visible_lines(data_area));
            } else if hex_area.contains(pos) {
                app.scroll_hex(3);
            }
        }
        MouseEventKind::Down(MouseButton::Left) => {
            if input_area.contains(pos) {
                app.focus = PanelFocus::Input;
            } else if hex_area.contains(pos) {
                app.focus = PanelFocus::Hex;
                // Rows inside the border start one line down
                let rel_row = mouse.row.saturating_sub(hex_area.y + 1) as usize;
                let offset = (app.hex_scroll + rel_row) * 16;
                app.set_hex_cursor(offset, hex_area.height.saturating_sub(2) as usize);
            } else if data_area.contains(pos) {
                app.focus = PanelFocus::Data;
                let rel_row = mouse.row.saturating_sub(data_area.y + 1) as usize;
                let line = app.data_scroll + rel_row;
                if line < app.visible.len() {
                    app.select_line(line, data_panel::data_panel_visible_lines(data_area));
                }
            }
        }
        _ => {}
    }
}
