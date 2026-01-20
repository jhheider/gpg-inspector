pub const PALETTE: [(u8, u8, u8); 8] = [
    (0xf3, 0x9c, 0x12), // orange
    (0x16, 0xa0, 0x85), // teal
    (0xd3, 0x54, 0x00), // burnt orange
    (0x8e, 0x44, 0xad), // purple
    (0x27, 0xae, 0x60), // green
    (0x2c, 0x3e, 0x50), // dark blue
    (0x7f, 0x8c, 0x8d), // gray
    (0xc0, 0x39, 0x2b), // red
];

#[derive(Clone, Debug, Default)]
pub struct ColorTracker {
    color_index: u8,
    pub byte_colors: Vec<Option<u8>>,
}

impl ColorTracker {
    pub fn new(size: usize) -> Self {
        Self {
            color_index: 0,
            byte_colors: vec![None; size],
        }
    }

    /// Set a field with automatic color cycling. Returns the color index used.
    pub fn set_field(&mut self, start: usize, end: usize) -> u8 {
        let color = self.color_index;

        if end > start && end <= self.byte_colors.len() {
            for i in start..end {
                self.byte_colors[i] = Some(color);
            }
        }

        // Always advance to next color for next field
        self.color_index = (self.color_index + 1) % 8;
        color
    }

    /// Set a header field (no color, just white)
    pub fn set_header(&mut self, start: usize, end: usize) {
        // Headers don't color bytes - they're just white text
        // No-op for byte coloring, but we keep this for symmetry
        let _ = (start, end);
    }

    pub fn get_color(&self, index: usize) -> Option<u8> {
        self.byte_colors.get(index).copied().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_rotation() {
        let mut tracker = ColorTracker::new(100);
        let c1 = tracker.set_field(0, 10);
        let c2 = tracker.set_field(10, 20);
        let c3 = tracker.set_field(20, 30);

        // Each field should have a different color
        assert_eq!(c1, 0);
        assert_eq!(c2, 1);
        assert_eq!(c3, 2);

        // Verify byte colors were set
        assert_eq!(tracker.get_color(5), Some(0));
        assert_eq!(tracker.get_color(15), Some(1));
        assert_eq!(tracker.get_color(25), Some(2));
    }

    #[test]
    fn test_header_no_color() {
        let mut tracker = ColorTracker::new(50);
        tracker.set_header(0, 5);
        let body_color = tracker.set_field(5, 45);

        // Header bytes should have no color
        assert_eq!(tracker.get_color(2), None);
        // Body bytes should have a color
        assert_eq!(tracker.get_color(10), Some(body_color));
    }
}
