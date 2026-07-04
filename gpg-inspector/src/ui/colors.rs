use gpg_inspector_lib::Packet;
use ratatui::style::Color;

/// A 12-color palette with good contrast for terminal display.
pub const PALETTE: [Color; 12] = [
    Color::Rgb(0xFF, 0x6B, 0x6B), // coral red
    Color::Rgb(0x4E, 0xCB, 0xC4), // teal
    Color::Rgb(0xFF, 0xE6, 0x6D), // yellow
    Color::Rgb(0x95, 0xE1, 0xD3), // mint
    Color::Rgb(0xFC, 0xB9, 0x69), // orange
    Color::Rgb(0xA8, 0xD8, 0xEA), // sky blue
    Color::Rgb(0xD4, 0xA5, 0xF9), // lavender
    Color::Rgb(0x98, 0xD8, 0x93), // sage green
    Color::Rgb(0xFF, 0x8C, 0xB3), // pink
    Color::Rgb(0x7F, 0xDB, 0xFF), // cyan
    Color::Rgb(0xF9, 0xCA, 0xC8), // blush
    Color::Rgb(0xAE, 0xE5, 0xD8), // seafoam
];

/// RGB palette for text output (matches TUI palette colors).
pub const PALETTE_RGB: [(u8, u8, u8); 12] = [
    (0xFF, 0x6B, 0x6B), // coral red
    (0x4E, 0xCB, 0xC4), // teal
    (0xFF, 0xE6, 0x6D), // yellow
    (0x95, 0xE1, 0xD3), // mint
    (0xFC, 0xB9, 0x69), // orange
    (0xA8, 0xD8, 0xEA), // sky blue
    (0xD4, 0xA5, 0xF9), // lavender
    (0x98, 0xD8, 0x93), // sage green
    (0xFF, 0x8C, 0xB3), // pink
    (0x7F, 0xDB, 0xFF), // cyan
    (0xF9, 0xCA, 0xC8), // blush
    (0xAE, 0xE5, 0xD8), // seafoam
];

pub fn get_color(index: u8) -> Color {
    PALETTE[index as usize % PALETTE.len()]
}

/// A 12-color palette tuned for light terminal backgrounds: the same
/// hue order as [`PALETTE`], darkened for contrast on white.
pub const LIGHT_PALETTE: [Color; 12] = [
    Color::Rgb(0xC0, 0x39, 0x2B), // red
    Color::Rgb(0x0E, 0x7C, 0x7B), // teal
    Color::Rgb(0xB8, 0x86, 0x0B), // ochre
    Color::Rgb(0x14, 0x8F, 0x77), // jade
    Color::Rgb(0xD3, 0x54, 0x00), // burnt orange
    Color::Rgb(0x1F, 0x6F, 0xA8), // steel blue
    Color::Rgb(0x7D, 0x3C, 0x98), // purple
    Color::Rgb(0x2E, 0x86, 0x44), // green
    Color::Rgb(0xC2, 0x18, 0x5B), // magenta
    Color::Rgb(0x0B, 0x79, 0xD0), // azure
    Color::Rgb(0xA0, 0x52, 0x52), // rosewood
    Color::Rgb(0x5D, 0x6D, 0x7E), // slate
];

/// Resolved UI colors for the current terminal background.
#[derive(Debug, Clone, PartialEq)]
pub struct Theme {
    /// Field color rotation.
    pub palette: [Color; 12],
    /// Primary text (input text, hex bytes without a field color).
    pub text: Color,
    /// De-emphasized text (borders' labels, offsets, separators).
    pub dim: Color,
    /// Packet header rows.
    pub header: Color,
    /// Unfocused panel borders.
    pub border: Color,
    /// Focused panel borders and overlay frames.
    pub border_focused: Color,
    /// Foreground drawn over a colored selection background.
    pub selection_fg: Color,
    /// Accent for keybinding hints in overlays.
    pub accent: Color,
}

impl Theme {
    /// Colors for dark terminal backgrounds (the default).
    pub fn dark() -> Self {
        Self {
            palette: PALETTE,
            text: Color::White,
            dim: Color::DarkGray,
            header: Color::White,
            border: Color::DarkGray,
            border_focused: Color::Yellow,
            selection_fg: Color::Black,
            accent: Color::Cyan,
        }
    }

    /// Colors for light terminal backgrounds.
    pub fn light() -> Self {
        Self {
            palette: LIGHT_PALETTE,
            text: Color::Black,
            dim: Color::Gray,
            header: Color::Black,
            border: Color::Gray,
            border_focused: Color::Blue,
            selection_fg: Color::White,
            accent: Color::Blue,
        }
    }

    /// Picks a theme from a `COLORFGBG`-style value ("fg;bg" — some
    /// terminals add a middle field). Background colors 7 and 15 mean
    /// a light background; anything else (or no value) means dark.
    pub fn from_colorfgbg(var: Option<&str>) -> Self {
        let is_light = var
            .and_then(|v| v.rsplit(';').next())
            .and_then(|bg| bg.parse::<u8>().ok())
            .is_some_and(|bg| bg == 7 || bg == 15);
        if is_light {
            Self::light()
        } else {
            Self::dark()
        }
    }

    /// Resolves a `--theme` argument; `auto` (or anything unknown)
    /// sniffs `colorfgbg`.
    pub fn resolve(name: &str, colorfgbg: Option<&str>) -> Self {
        match name {
            "dark" => Self::dark(),
            "light" => Self::light(),
            _ => Self::from_colorfgbg(colorfgbg),
        }
    }

    /// Palette color by rotation index.
    pub fn color(&self, index: u8) -> Color {
        self.palette[index as usize % self.palette.len()]
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}

/// Tracks color assignments for each byte position.
///
/// This is computed from field spans after parsing.
#[derive(Clone, Debug, Default)]
pub struct ColorTracker {
    /// The color assignment for each byte position.
    /// `None` indicates no color (typically for headers).
    pub byte_colors: Vec<Option<u8>>,
}

impl ColorTracker {
    /// Creates a new tracker for data of the given size.
    pub fn new(size: usize) -> Self {
        Self {
            byte_colors: vec![None; size],
        }
    }

    /// Computes colors for all bytes based on field spans.
    ///
    /// Fields with indent > 0 get colors in rotation.
    /// Fields with indent == 0 (packet headers) get no color.
    pub fn compute_from_packets(packets: &[Packet], total_bytes: usize) -> Self {
        let mut tracker = Self::new(total_bytes);
        let mut color_index: u8 = 0;

        for packet in packets {
            for field in &packet.fields {
                // Only color non-header fields (indent > 0)
                if field.indent > 0 {
                    let (start, end) = field.span;
                    if end > start && end <= total_bytes {
                        for i in start..end {
                            tracker.byte_colors[i] = Some(color_index);
                        }
                    }
                    color_index = (color_index + 1) % 12;
                }
            }
        }

        tracker
    }

    /// Returns the color index for a byte position, if any.
    pub fn get_color(&self, index: usize) -> Option<u8> {
        self.byte_colors.get(index).copied().flatten()
    }
}
