use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Widget},
};

use crate::app::{App, PanelFocus};

pub struct HexPanel<'a> {
    app: &'a App,
}

impl<'a> HexPanel<'a> {
    /// Only used by excluded Widget impl
    #[cfg(not(tarpaulin_include))]
    pub fn new(app: &'a App) -> Self {
        Self { app }
    }
}

/// Renders to terminal buffer - not unit testable
#[cfg(not(tarpaulin_include))]
impl Widget for HexPanel<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Hex panel is display-only, not focusable. It shows the byte
        // stream the selected row lives in (raw input, or a
        // decompressed buffer for nested packets).
        let title = if self.app.display_stream() > 0 {
            let depth = self.app.selected_row().map(|r| r.depth).unwrap_or(1);
            format!(" Hex View — decompressed (depth {}) ", depth)
        } else {
            " Hex View ".to_string()
        };
        let theme = &self.app.theme;
        let focused = self.app.focus == PanelFocus::Hex;
        let border_color = if focused {
            theme.border_focused
        } else {
            theme.border
        };
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color));

        let inner = block.inner(area);
        block.render(area, buf);

        let bytes = std::sync::Arc::clone(self.app.display_bytes());
        if bytes.is_empty() {
            return;
        }

        let bytes_per_line = 16;
        let visible_lines = inner.height as usize;
        let total_lines = bytes.len().div_ceil(bytes_per_line);

        // Offset column grows with the buffer (4 hex digits minimum)
        let offset_width = ((bytes.len().max(1).ilog2() / 4) as usize + 1).max(4);

        let start_line = self
            .app
            .hex_scroll
            .min(total_lines.saturating_sub(visible_lines));
        let end_line = (start_line + visible_lines).min(total_lines);

        for (line_idx, line_num) in (start_line..end_line).enumerate() {
            let y = inner.y + line_idx as u16;
            if y >= inner.y + inner.height {
                break;
            }

            let start_byte = line_num * bytes_per_line;
            let end_byte = (start_byte + bytes_per_line).min(bytes.len());

            let mut spans = Vec::new();

            spans.push(Span::styled(
                format!("{:0width$X}  ", start_byte, width = offset_width),
                Style::default().fg(theme.dim),
            ));

            for i in start_byte..end_byte {
                let byte = bytes[i];

                let is_highlighted = self
                    .app
                    .highlighted_bytes
                    .map(|(s, e)| i >= s && i < e)
                    .unwrap_or(false);

                let base_color = self
                    .app
                    .get_byte_color(i)
                    .map(|c| theme.color(c))
                    .unwrap_or(theme.text);

                let style = if focused && i == self.app.hex_cursor {
                    Style::default()
                        .fg(theme.selection_fg)
                        .bg(theme.border_focused)
                        .add_modifier(Modifier::BOLD)
                } else if is_highlighted {
                    Style::default()
                        .fg(theme.selection_fg)
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
                let byte = bytes[i];
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
                    .map(|c| theme.color(c))
                    .unwrap_or(theme.dim);

                let style = if focused && i == self.app.hex_cursor {
                    Style::default()
                        .fg(theme.selection_fg)
                        .bg(theme.border_focused)
                        .add_modifier(Modifier::BOLD)
                } else if is_highlighted {
                    Style::default()
                        .fg(theme.selection_fg)
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
