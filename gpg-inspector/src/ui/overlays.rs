use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget, Wrap},
};

use crate::app::App;

/// A rectangle of at most `width` x `height`, centered within `area`.
pub fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

pub struct HelpOverlay;

const HELP_TEXT: &[(&str, &str)] = &[
    ("Tab / Shift+Tab", "Switch between Input and Data panels"),
    ("Ctrl+C / Ctrl+Q", "Quit"),
    ("F1", "Toggle this help"),
    ("", ""),
    ("Input panel", ""),
    ("Left/Right Home/End", "Move cursor"),
    ("Ctrl+A / Ctrl+E", "Cursor to start / end"),
    ("Ctrl+K", "Clear input"),
    ("", ""),
    ("Data panel", ""),
    ("Up/Down or k/j", "Move selection"),
    ("PgUp/PgDn Home/End", "Move selection by page / to ends"),
    ("Enter", "Show full field details"),
    ("/", "Search fields (Enter to jump, Esc to cancel)"),
    ("n / N", "Next / previous search match"),
    ("?", "Toggle this help"),
];

/// Renders to terminal buffer - not unit testable
#[cfg(not(tarpaulin_include))]
impl Widget for HelpOverlay {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let popup = centered_rect(56, HELP_TEXT.len() as u16 + 4, area);
        Clear.render(popup, buf);

        let block = Block::default()
            .title(" Help ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow));
        let inner = block.inner(popup);
        block.render(popup, buf);

        let lines: Vec<Line> = HELP_TEXT
            .iter()
            .map(|(key, desc)| {
                if desc.is_empty() {
                    Line::from(Span::styled(
                        key.to_string(),
                        Style::default().add_modifier(Modifier::BOLD),
                    ))
                } else {
                    Line::from(vec![
                        Span::styled(format!("  {:<20}", key), Style::default().fg(Color::Cyan)),
                        Span::raw(desc.to_string()),
                    ])
                }
            })
            .collect();

        let footer = Line::from(Span::styled(
            "press ? or Esc to close",
            Style::default().fg(Color::DarkGray),
        ));
        let mut all_lines = lines;
        all_lines.push(Line::default());
        all_lines.push(footer);

        Paragraph::new(all_lines).render(inner, buf);
    }
}

pub struct DetailOverlay<'a> {
    app: &'a App,
}

impl<'a> DetailOverlay<'a> {
    /// Only used by excluded Widget impl
    #[cfg(not(tarpaulin_include))]
    pub fn new(app: &'a App) -> Self {
        Self { app }
    }
}

/// Renders to terminal buffer - not unit testable
#[cfg(not(tarpaulin_include))]
impl Widget for DetailOverlay<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let fields = self.app.get_all_fields();
        let Some(field) = fields.get(self.app.selected_line) else {
            return;
        };

        let (start, end) = field.span;
        let width = (area.width * 3 / 4).max(20);
        let text_width = width.saturating_sub(2) as usize;
        let value_lines = field.value.len().div_ceil(text_width.max(1)) as u16;
        let height = (value_lines + 6).min(area.height * 3 / 4).max(8);
        let popup = centered_rect(width, height, area);
        Clear.render(popup, buf);

        let block = Block::default()
            .title(format!(" {} ", field.name))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow));
        let inner = block.inner(popup);
        block.render(popup, buf);

        let mut lines = vec![
            Line::from(vec![
                Span::styled("Bytes: ", Style::default().fg(Color::Cyan)),
                Span::raw(format!("{:#x}..{:#x} ({} bytes)", start, end, end - start)),
            ]),
            Line::default(),
        ];
        lines.extend(field.value.lines().map(|l| Line::from(l.to_string())));
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "press Enter or Esc to close",
            Style::default().fg(Color::DarkGray),
        )));

        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .render(inner, buf);
    }
}
