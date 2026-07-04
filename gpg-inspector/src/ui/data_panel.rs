use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Widget},
};

use crate::app::{App, PanelFocus};
use crate::ui::colors::get_color;

pub struct DataPanel<'a> {
    app: &'a App,
}

impl<'a> DataPanel<'a> {
    /// Only used by excluded Widget impl
    #[cfg(not(tarpaulin_include))]
    pub fn new(app: &'a App) -> Self {
        Self { app }
    }
}

/// Renders to terminal buffer - not unit testable
#[cfg(not(tarpaulin_include))]
impl Widget for DataPanel<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let focused = self.app.focus == PanelFocus::Data;

        let border_color = if focused {
            Color::Yellow
        } else {
            Color::DarkGray
        };

        let matches = self.app.search_matches();
        let title = if self.app.search_active {
            format!(" Decoded Data — /{}█ ", self.app.search_query)
        } else if !self.app.search_query.is_empty() {
            format!(
                " Decoded Data — /{} ({} match{}) ",
                self.app.search_query,
                matches.len(),
                if matches.len() == 1 { "" } else { "es" }
            )
        } else {
            " Decoded Data ".to_string()
        };

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color));

        let inner = block.inner(area);
        block.render(area, buf);

        let total_lines = self.app.visible.len();
        if total_lines == 0 {
            return;
        }

        let visible_lines = inner.height as usize;

        let start_line = self
            .app
            .data_scroll
            .min(total_lines.saturating_sub(visible_lines));
        let end_line = (start_line + visible_lines).min(total_lines);

        for (line_idx, vis_pos) in (start_line..end_line).enumerate() {
            let y = inner.y + line_idx as u16;
            if y >= inner.y + inner.height {
                break;
            }

            let row_idx = self.app.visible[vis_pos];
            let row = &self.app.rows[row_idx];
            let is_selected = vis_pos == self.app.selected_line;
            let is_match = matches.contains(&row_idx);

            // Nested (decompressed) packets indent two extra columns per level
            let indent = row.indent as usize + row.depth as usize * 2;

            let color = match row.color {
                Some(idx) => get_color(idx),
                None => Color::White, // Headers are white
            };

            // Fold marker on foldable packet header rows
            let name = if row.is_packet_first && self.app.packet_foldable(row.packet_id) {
                let marker = if self.app.collapsed.contains(&row.packet_id) {
                    "▸ "
                } else {
                    "▾ "
                };
                format!("{}{}", marker, row.name)
            } else {
                row.name.to_string()
            };

            let mut name_style = if is_selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(color)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(color)
            };
            if is_match {
                name_style = name_style.add_modifier(Modifier::UNDERLINED);
            }

            let value_style = if is_selected {
                Style::default().fg(Color::Black).bg(Color::DarkGray)
            } else {
                Style::default().fg(Color::Gray)
            };

            // Calculate widths with indentation
            let indent_str = " ".repeat(indent);
            let name_width = 28usize.saturating_sub(indent).min(inner.width as usize / 2);
            let truncated_name = truncate_chars(&name, name_width);

            let value_width = (inner.width as usize).saturating_sub(name_width + indent + 3);
            let truncated_value = truncate_chars(&row.value, value_width);

            let spans = vec![
                Span::raw(&indent_str),
                Span::styled(
                    format!("{:<width$}", truncated_name, width = name_width),
                    name_style,
                ),
                Span::styled(" : ", Style::default().fg(Color::DarkGray)),
                Span::styled(truncated_value, value_style),
            ];

            let line = Line::from(spans);
            buf.set_line(inner.x, y, &line, inner.width);
        }
    }
}

pub fn data_panel_visible_lines(area: Rect) -> usize {
    area.height.saturating_sub(2) as usize
}

/// Truncates to `width` characters with a `...` suffix, respecting
/// UTF-8 char boundaries (names can contain fold markers, values can
/// contain arbitrary text).
pub fn truncate_chars(s: &str, width: usize) -> String {
    if s.chars().count() > width {
        let cut: String = s.chars().take(width.saturating_sub(3)).collect();
        format!("{}...", cut)
    } else {
        s.to_string()
    }
}
