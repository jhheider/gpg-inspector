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

        let block = Block::default()
            .title(" Decoded Data ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color));

        let inner = block.inner(area);
        block.render(area, buf);

        let fields = self.app.get_all_fields();
        if fields.is_empty() {
            return;
        }

        let visible_lines = inner.height as usize;
        let total_lines = fields.len();

        let start_line = self
            .app
            .data_scroll
            .min(total_lines.saturating_sub(visible_lines));
        let end_line = (start_line + visible_lines).min(total_lines);

        for (line_idx, field_idx) in (start_line..end_line).enumerate() {
            let y = inner.y + line_idx as u16;
            if y >= inner.y + inner.height {
                break;
            }

            let field = fields[field_idx];
            let is_selected = field_idx == self.app.selected_line;
            let indent = field.indent as usize;

            // Get the color for this field (None means header/white)
            let color = match self.app.get_field_color(field_idx) {
                Some(idx) => get_color(idx),
                None => Color::White, // Headers are white
            };

            let name_style = if is_selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(color)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(color)
            };

            let value_style = if is_selected {
                Style::default().fg(Color::Black).bg(Color::DarkGray)
            } else {
                Style::default().fg(Color::Gray)
            };

            // Calculate widths with indentation
            let indent_str = " ".repeat(indent);
            let name_width = 28usize.saturating_sub(indent).min(inner.width as usize / 2);
            let truncated_name: String = if field.name.len() > name_width {
                format!("{}...", &field.name[..name_width.saturating_sub(3)])
            } else {
                field.name.to_string()
            };

            let value_width = (inner.width as usize).saturating_sub(name_width + indent + 3);
            let truncated_value: String = if field.value.len() > value_width {
                format!("{}...", &field.value[..value_width.saturating_sub(3)])
            } else {
                field.value.to_string()
            };

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
