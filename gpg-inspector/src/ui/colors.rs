use gpg_inspector_lib::{Field, Packet};
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

    /// Returns the color for a field based on its position in the field list.
    ///
    /// Fields with indent == 0 (packet headers) get no color.
    pub fn field_color(field: &Field, field_index: usize) -> Option<u8> {
        if field.indent == 0 {
            None
        } else {
            Some((field_index % 12) as u8)
        }
    }
}

/// Returns the color index for a field based on counting non-header fields before it.
pub fn get_field_color_index(packets: &[Packet], target_field: &Field) -> Option<u8> {
    let mut color_index: u8 = 0;

    for packet in packets {
        for field in &packet.fields {
            if std::ptr::eq(field, target_field) {
                return if field.indent > 0 {
                    Some(color_index)
                } else {
                    None
                };
            }
            if field.indent > 0 {
                color_index = (color_index + 1) % 12;
            }
        }
    }
    None
}
