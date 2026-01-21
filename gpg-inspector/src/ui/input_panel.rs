use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Widget, Wrap},
};

use crate::app::{App, PanelFocus};

pub struct InputPanel<'a> {
    app: &'a App,
}

impl<'a> InputPanel<'a> {
    /// Only used by excluded Widget impl
    #[cfg(not(tarpaulin_include))]
    pub fn new(app: &'a App) -> Self {
        Self { app }
    }
}

/// Renders to terminal buffer - not unit testable
#[cfg(not(tarpaulin_include))]
impl Widget for InputPanel<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let focused = self.app.focus == PanelFocus::Input;

        let border_color = if focused {
            Color::Yellow
        } else {
            Color::DarkGray
        };

        let title = if let Some(ref err) = self.app.error_message {
            format!(" Input - {} ", err)
        } else {
            " Input (paste GPG armored text) ".to_string()
        };

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color));

        let inner = block.inner(area);
        block.render(area, buf);

        if self.app.input.is_empty() {
            let placeholder = Paragraph::new("Paste armored GPG data here...")
                .style(Style::default().fg(Color::DarkGray))
                .wrap(Wrap { trim: false });
            placeholder.render(inner, buf);
        } else {
            let text = &self.app.input;
            let lines: Vec<Line> = text.lines().map(|l| Line::from(l.to_string())).collect();

            let paragraph = Paragraph::new(lines)
                .style(Style::default().fg(Color::White))
                .wrap(Wrap { trim: false });

            paragraph.render(inner, buf);

            if focused {
                let (cursor_x, cursor_y) =
                    calculate_cursor_position(text, self.app.cursor_pos, inner.width as usize);
                if cursor_y < inner.height as usize {
                    let x = inner.x + cursor_x as u16;
                    let y = inner.y + cursor_y as u16;
                    if x < inner.x + inner.width && y < inner.y + inner.height {
                        buf[(x, y)].set_style(Style::default().bg(Color::White).fg(Color::Black));
                    }
                }
            }
        }
    }
}

/// Helper for cursor positioning in render - only called from excluded Widget impl
#[cfg(not(tarpaulin_include))]
fn calculate_cursor_position(text: &str, cursor_pos: usize, width: usize) -> (usize, usize) {
    let before_cursor = &text[..cursor_pos];
    let mut x = 0;
    let mut y = 0;

    for ch in before_cursor.chars() {
        if ch == '\n' {
            x = 0;
            y += 1;
        } else {
            x += 1;
            if x >= width {
                x = 0;
                y += 1;
            }
        }
    }

    (x, y)
}
