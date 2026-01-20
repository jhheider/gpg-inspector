use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Widget},
};

use crate::app::{App, PanelFocus};
use crate::ui::colors::get_color;

pub struct HexPanel<'a> {
    app: &'a App,
}

impl<'a> HexPanel<'a> {
    pub fn new(app: &'a App) -> Self {
        Self { app }
    }
}

impl Widget for HexPanel<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let focused = self.app.focus == PanelFocus::Hex;

        let border_color = if focused {
            Color::Yellow
        } else {
            Color::DarkGray
        };

        let block = Block::default()
            .title(" Hex View ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color));

        let inner = block.inner(area);
        block.render(area, buf);

        if self.app.raw_bytes.is_empty() {
            return;
        }

        let bytes_per_line = 16;
        let visible_lines = inner.height as usize;
        let total_lines = self.app.raw_bytes.len().div_ceil(bytes_per_line);

        let start_line = self.app.hex_scroll.min(total_lines.saturating_sub(visible_lines));
        let end_line = (start_line + visible_lines).min(total_lines);

        for (line_idx, line_num) in (start_line..end_line).enumerate() {
            let y = inner.y + line_idx as u16;
            if y >= inner.y + inner.height {
                break;
            }

            let start_byte = line_num * bytes_per_line;
            let end_byte = (start_byte + bytes_per_line).min(self.app.raw_bytes.len());

            let mut spans = Vec::new();

            spans.push(Span::styled(
                format!("{:04X}  ", start_byte),
                Style::default().fg(Color::DarkGray),
            ));

            for i in start_byte..end_byte {
                let byte = self.app.raw_bytes[i];

                let is_highlighted = self
                    .app
                    .highlighted_bytes
                    .map(|(s, e)| i >= s && i < e)
                    .unwrap_or(false);

                let base_color = self
                    .app
                    .get_byte_color(i)
                    .map(get_color)
                    .unwrap_or(Color::White);

                let style = if is_highlighted {
                    Style::default()
                        .fg(Color::Black)
                        .bg(base_color)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(base_color)
                };

                spans.push(Span::styled(format!("{:02X}", byte), style));

                if i < end_byte - 1 {
                    spans.push(Span::raw(" "));
                }
            }

            for _ in end_byte..start_byte + bytes_per_line {
                spans.push(Span::raw("   "));
            }

            spans.push(Span::raw("  "));

            for i in start_byte..end_byte {
                let byte = self.app.raw_bytes[i];
                let ch = if byte.is_ascii_graphic() || byte == b' ' {
                    byte as char
                } else {
                    '.'
                };

                let is_highlighted = self
                    .app
                    .highlighted_bytes
                    .map(|(s, e)| i >= s && i < e)
                    .unwrap_or(false);

                let base_color = self
                    .app
                    .get_byte_color(i)
                    .map(get_color)
                    .unwrap_or(Color::DarkGray);

                let style = if is_highlighted {
                    Style::default()
                        .fg(Color::Black)
                        .bg(base_color)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(base_color)
                };

                spans.push(Span::styled(ch.to_string(), style));
            }

            let line = Line::from(spans);
            let x = inner.x;
            buf.set_line(x, y, &line, inner.width);
        }
    }
}

pub fn hex_panel_visible_lines(area: Rect) -> usize {
    area.height.saturating_sub(2) as usize
}
