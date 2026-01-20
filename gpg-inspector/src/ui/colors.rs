use ratatui::style::Color;

// A 12-color palette with good contrast for terminal display
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

pub fn get_color(index: u8) -> Color {
    PALETTE[index as usize % PALETTE.len()]
}
