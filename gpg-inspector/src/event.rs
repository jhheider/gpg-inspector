use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, PanelFocus};
use crate::ui::{data_panel, get_data_panel_area};
use ratatui::layout::Rect;

pub fn handle_event(app: &mut App, event: Event, size: Rect) {
    if let Event::Key(key) = event {
        handle_key(app, key, size);
    } else if let Event::Paste(text) = event
        && app.focus == PanelFocus::Input {
            app.paste_text(&text);
        }
}

fn handle_key(app: &mut App, key: KeyEvent, size: Rect) {
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
            KeyCode::Char('v') if app.focus == PanelFocus::Input => {
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Tab => {
            app.focus = app.focus.next();
        }
        KeyCode::BackTab => {
            app.focus = match app.focus {
                PanelFocus::Input => PanelFocus::Data,
                PanelFocus::Data => PanelFocus::Input,
            };
        }
        KeyCode::Esc => {
            app.should_quit = true;
        }
        _ => match app.focus {
            PanelFocus::Input => handle_input_key(app, key),
            PanelFocus::Data => handle_data_key(app, key, size),
        },
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

fn handle_data_key(app: &mut App, key: KeyEvent, size: Rect) {
    let data_area = get_data_panel_area(size);
    let visible_lines = data_panel::data_panel_visible_lines(data_area);

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
            let total = app.get_all_fields().len();
            app.selected_line = total.saturating_sub(1);
            app.data_scroll = total.saturating_sub(visible_lines);
            app.update_highlight();
            app.scroll_hex_to_highlight(visible_lines);
        }
        _ => {}
    }
}
