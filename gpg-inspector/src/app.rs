use std::sync::Arc;

use gpg_inspector_lib::{ArmorBlock, Field, Packet};

use crate::ui::colors::ColorTracker;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelFocus {
    Input,
    Data,
}

/// Where the current data came from. Binary input is read-only: the
/// input panel is a text editor and cannot represent raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSource {
    Text,
    Binary { origin: String, len: usize },
}

impl PanelFocus {
    pub fn next(self) -> Self {
        match self {
            PanelFocus::Input => PanelFocus::Data,
            PanelFocus::Data => PanelFocus::Input,
        }
    }
}

pub struct App {
    pub input: String,
    pub cursor_pos: usize,
    pub source: InputSource,
    pub packets: Vec<Packet>,
    pub raw_bytes: Arc<[u8]>,
    pub armor_blocks: Vec<ArmorBlock>,
    pub cleartext: Option<Arc<str>>,
    pub color_tracker: ColorTracker,
    pub focus: PanelFocus,
    pub hex_scroll: usize,
    pub data_scroll: usize,
    pub selected_line: usize,
    pub highlighted_bytes: Option<(usize, usize)>,
    pub error_message: Option<String>,
    pub should_quit: bool,
    pub show_help: bool,
    pub show_detail: bool,
    pub search_active: bool,
    pub search_query: String,
}

impl App {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            cursor_pos: 0,
            source: InputSource::Text,
            packets: Vec::new(),
            raw_bytes: Arc::from([]),
            armor_blocks: Vec::new(),
            cleartext: None,
            color_tracker: ColorTracker::default(),
            focus: PanelFocus::Input,
            hex_scroll: 0,
            data_scroll: 0,
            selected_line: 0,
            highlighted_bytes: None,
            error_message: None,
            should_quit: false,
            show_help: false,
            show_detail: false,
            search_active: false,
            search_query: String::new(),
        }
    }

    pub fn is_binary(&self) -> bool {
        matches!(self.source, InputSource::Binary { .. })
    }

    /// Loads raw binary PGP data (read-only mode); parses once.
    pub fn load_binary(&mut self, bytes: Vec<u8>, origin: impl Into<String>) {
        let bytes: Arc<[u8]> = bytes.into();
        self.source = InputSource::Binary {
            origin: origin.into(),
            len: bytes.len(),
        };
        self.input.clear();
        self.cursor_pos = 0;
        self.raw_bytes = Arc::clone(&bytes);
        self.armor_blocks = Vec::new();
        self.cleartext = None;

        match gpg_inspector_lib::parse_bytes(bytes) {
            Ok(packets) => {
                self.color_tracker =
                    ColorTracker::compute_from_packets(&packets, self.raw_bytes.len());
                self.packets = packets;
                self.error_message = None;
            }
            Err(e) => {
                self.packets.clear();
                self.color_tracker = ColorTracker::default();
                self.error_message = Some(format!("Parse error: {}", e));
            }
        }
        self.clamp_selection();
        self.focus = PanelFocus::Data;
    }

    pub fn parse_input(&mut self) {
        // Binary input is parsed once at load and never edited
        if self.is_binary() {
            return;
        }

        if self.input.trim().is_empty() {
            self.packets.clear();
            self.raw_bytes = Arc::from([]);
            self.armor_blocks = Vec::new();
            self.cleartext = None;
            self.color_tracker = ColorTracker::default();
            self.error_message = None;
            self.clamp_selection();
            return;
        }

        match gpg_inspector_lib::decode_armor_multi(&self.input) {
            Ok(armor_result) => {
                self.raw_bytes = Arc::clone(&armor_result.bytes);
                self.armor_blocks = armor_result.blocks;
                self.cleartext = armor_result.cleartext;
                match gpg_inspector_lib::parse_bytes(armor_result.bytes) {
                    Ok(packets) => {
                        // Compute colors from field spans
                        self.color_tracker =
                            ColorTracker::compute_from_packets(&packets, self.raw_bytes.len());
                        self.packets = packets;
                        self.error_message = None;
                    }
                    Err(e) => {
                        self.packets.clear();
                        self.color_tracker = ColorTracker::default();
                        self.error_message = Some(format!("Parse error: {}", e));
                    }
                }
            }
            Err(e) => {
                self.packets.clear();
                self.raw_bytes = Arc::from([]);
                self.armor_blocks = Vec::new();
                self.cleartext = None;
                self.color_tracker = ColorTracker::default();
                self.error_message = Some(format!("Armor error: {}", e));
            }
        }
        self.clamp_selection();
    }

    /// Keeps selection and scroll positions valid when the field count changes.
    fn clamp_selection(&mut self) {
        let total = self.get_all_fields().len();
        self.selected_line = self.selected_line.min(total.saturating_sub(1));
        self.data_scroll = self.data_scroll.min(self.selected_line);
        let hex_lines = self.raw_bytes.len().div_ceil(16);
        self.hex_scroll = self.hex_scroll.min(hex_lines.saturating_sub(1));
        self.update_highlight();
    }

    pub fn get_all_fields(&self) -> Vec<&Field> {
        self.get_all_fields_flagged()
            .into_iter()
            .map(|(field, _)| field)
            .collect()
    }

    /// Flattens all packets' fields, including nested (decompressed)
    /// packets' fields, flagging the nested ones. Nested fields' spans
    /// index their packet's decompressed buffer, not `raw_bytes`, so
    /// they are excluded from hex highlighting and coloring until the
    /// hex view can switch buffers.
    pub fn get_all_fields_flagged(&self) -> Vec<(&Field, bool)> {
        fn walk<'a>(packets: &'a [Packet], is_child: bool, out: &mut Vec<(&'a Field, bool)>) {
            for packet in packets {
                for field in &packet.fields {
                    out.push((field, is_child));
                }
                walk(&packet.children, true, out);
            }
        }

        let mut fields = Vec::new();
        walk(&self.packets, false, &mut fields);
        fields
    }

    pub fn get_field_span(&self, field: &Field) -> (usize, usize) {
        field.span
    }

    /// Returns the color index for a field based on its position.
    /// Fields with indent == 0 (packet headers) get no color, and
    /// neither do nested (decompressed) fields — their bytes are not in
    /// `raw_bytes`, so coloring them would desynchronize from the hex view.
    pub fn get_field_color(&self, field_index: usize) -> Option<u8> {
        let fields = self.get_all_fields_flagged();
        if field_index >= fields.len() {
            return None;
        }

        let (field, is_child) = fields[field_index];
        if field.indent == 0 || is_child {
            return None;
        }

        // Count top-level non-header fields before this one; must match
        // ColorTracker::compute_from_packets, which only sees top-level
        // packets' fields.
        let mut color_index: u8 = 0;
        for (i, &(f, child)) in fields.iter().enumerate() {
            if i == field_index {
                return Some(color_index);
            }
            if !child && f.indent > 0 {
                color_index = (color_index + 1) % 12;
            }
        }
        unreachable!(
            "field_index {} is within bounds but not found in iteration",
            field_index
        )
    }

    pub fn get_byte_color(&self, byte_index: usize) -> Option<u8> {
        self.color_tracker.get_color(byte_index)
    }

    pub fn update_highlight(&mut self) {
        let fields = self.get_all_fields_flagged();
        if self.selected_line < fields.len() {
            let (field, is_child) = fields[self.selected_line];
            // Nested fields' spans index the decompressed buffer, not
            // raw_bytes; highlighting them would mark the wrong bytes
            self.highlighted_bytes = if is_child {
                None
            } else {
                Some(self.get_field_span(field))
            };
        } else {
            self.highlighted_bytes = None;
        }
    }

    pub fn scroll_hex_to_highlight(&mut self, visible_lines: usize) {
        if let Some((start, _end)) = self.highlighted_bytes {
            let bytes_per_line = 16;
            let start_line = start / bytes_per_line;

            if start_line < self.hex_scroll {
                self.hex_scroll = start_line;
            } else if start_line >= self.hex_scroll + visible_lines {
                self.hex_scroll = start_line.saturating_sub(visible_lines / 2);
            }
        }
    }

    pub fn move_selection(&mut self, delta: isize, visible_lines: usize) {
        let fields = self.get_all_fields();
        let max_line = fields.len().saturating_sub(1);

        if delta > 0 {
            self.selected_line = (self.selected_line + delta as usize).min(max_line);
        } else {
            self.selected_line = self.selected_line.saturating_sub((-delta) as usize);
        }

        if self.selected_line < self.data_scroll {
            self.data_scroll = self.selected_line;
        } else if self.selected_line >= self.data_scroll + visible_lines {
            self.data_scroll = self.selected_line.saturating_sub(visible_lines - 1);
        }

        self.update_highlight();
        self.scroll_hex_to_highlight(visible_lines);
    }

    /// Moves the selection to a specific field and scrolls it into view.
    pub fn select_line(&mut self, line: usize, visible_lines: usize) {
        let total = self.get_all_fields().len();
        if total == 0 {
            return;
        }
        self.selected_line = line.min(total - 1);

        if self.selected_line < self.data_scroll {
            self.data_scroll = self.selected_line;
        } else if visible_lines > 0 && self.selected_line >= self.data_scroll + visible_lines {
            self.data_scroll = self.selected_line.saturating_sub(visible_lines - 1);
        }

        self.update_highlight();
        self.scroll_hex_to_highlight(visible_lines);
    }

    /// Indices of fields whose name or value contains the search query
    /// (case-insensitive). Empty query matches nothing.
    pub fn search_matches(&self) -> Vec<usize> {
        if self.search_query.is_empty() {
            return Vec::new();
        }
        let query = self.search_query.to_lowercase();
        self.get_all_fields()
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                f.name.to_lowercase().contains(&query) || f.value.to_lowercase().contains(&query)
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Jumps to the first match at or after the current selection.
    pub fn jump_to_first_match(&mut self, visible_lines: usize) {
        let matches = self.search_matches();
        if let Some(&target) = matches
            .iter()
            .find(|&&i| i >= self.selected_line)
            .or_else(|| matches.first())
        {
            self.select_line(target, visible_lines);
        }
    }

    /// Jumps to the next (or previous) match, wrapping around.
    pub fn jump_to_match(&mut self, forward: bool, visible_lines: usize) {
        let matches = self.search_matches();
        if matches.is_empty() {
            return;
        }
        let target = if forward {
            matches
                .iter()
                .copied()
                .find(|&i| i > self.selected_line)
                .unwrap_or(matches[0])
        } else {
            matches
                .iter()
                .rev()
                .copied()
                .find(|&i| i < self.selected_line)
                .unwrap_or(*matches.last().unwrap())
        };
        self.select_line(target, visible_lines);
    }

    pub fn insert_char(&mut self, c: char) {
        if self.is_binary() {
            return;
        }
        self.input.insert(self.cursor_pos, c);
        self.cursor_pos += c.len_utf8();
        self.parse_input();
    }

    pub fn delete_char(&mut self) {
        if self.is_binary() {
            return;
        }
        if self.cursor_pos > 0 {
            let prev_char_boundary = self.input[..self.cursor_pos]
                .char_indices()
                .last()
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.input.remove(prev_char_boundary);
            self.cursor_pos = prev_char_boundary;
            self.parse_input();
        }
    }

    pub fn delete_char_forward(&mut self) {
        if self.is_binary() {
            return;
        }
        if self.cursor_pos < self.input.len() {
            self.input.remove(self.cursor_pos);
            self.parse_input();
        }
    }

    pub fn move_cursor_left(&mut self) {
        if self.cursor_pos > 0 {
            self.cursor_pos = self.input[..self.cursor_pos]
                .char_indices()
                .last()
                .map(|(i, _)| i)
                .unwrap_or(0);
        }
    }

    pub fn move_cursor_right(&mut self) {
        if self.cursor_pos < self.input.len() {
            self.cursor_pos = self.input[self.cursor_pos..]
                .char_indices()
                .nth(1)
                .map(|(i, _)| self.cursor_pos + i)
                .unwrap_or(self.input.len());
        }
    }

    pub fn move_cursor_to_start(&mut self) {
        self.cursor_pos = 0;
    }

    pub fn move_cursor_to_end(&mut self) {
        self.cursor_pos = self.input.len();
    }

    pub fn paste_text(&mut self, text: &str) {
        if self.is_binary() {
            return;
        }
        self.input.insert_str(self.cursor_pos, text);
        self.cursor_pos += text.len();
        self.parse_input();
    }

    /// Clears the input. Also exits read-only binary mode, returning to
    /// an empty editable text buffer.
    pub fn clear_input(&mut self) {
        self.source = InputSource::Text;
        self.input.clear();
        self.cursor_pos = 0;
        self.parse_input();
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
