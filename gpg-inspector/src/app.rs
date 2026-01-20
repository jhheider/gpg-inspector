use std::sync::Arc;

use gpg_inspector_lib::{Field, Packet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelFocus {
    Input,
    Data,
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
    pub packets: Vec<Packet>,
    pub raw_bytes: Arc<[u8]>,
    pub focus: PanelFocus,
    pub hex_scroll: usize,
    pub data_scroll: usize,
    pub selected_line: usize,
    pub highlighted_bytes: Option<(usize, usize)>,
    pub error_message: Option<String>,
    pub should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            cursor_pos: 0,
            packets: Vec::new(),
            raw_bytes: Arc::from([]),
            focus: PanelFocus::Input,
            hex_scroll: 0,
            data_scroll: 0,
            selected_line: 0,
            highlighted_bytes: None,
            error_message: None,
            should_quit: false,
        }
    }

    pub fn parse_input(&mut self) {
        if self.input.trim().is_empty() {
            self.packets.clear();
            self.raw_bytes = Arc::from([]);
            self.error_message = None;
            return;
        }

        match gpg_inspector_lib::decode_armor(&self.input) {
            Ok(armor_result) => {
                self.raw_bytes = Arc::clone(&armor_result.bytes);
                match gpg_inspector_lib::parse_bytes(armor_result.bytes) {
                    Ok(packets) => {
                        self.packets = packets;
                        self.error_message = None;
                    }
                    Err(e) => {
                        self.packets.clear();
                        self.error_message = Some(format!("Parse error: {}", e));
                    }
                }
            }
            Err(e) => {
                self.packets.clear();
                self.raw_bytes = Arc::from([]);
                self.error_message = Some(format!("Armor error: {}", e));
            }
        }
    }

    pub fn get_all_fields(&self) -> Vec<&Field> {
        let mut fields = Vec::new();
        for packet in &self.packets {
            for field in &packet.fields {
                fields.push(field);
            }
        }
        fields
    }

    pub fn get_field_span(&self, field: &Field) -> (usize, usize) {
        field.span
    }

    pub fn get_field_color(&self, field: &Field) -> Option<u8> {
        field.color
    }

    pub fn get_byte_color(&self, byte_index: usize) -> Option<u8> {
        for packet in &self.packets {
            if byte_index >= packet.start && byte_index < packet.end {
                return packet.colors.get_color(byte_index);
            }
        }
        None
    }

    pub fn update_highlight(&mut self) {
        let fields = self.get_all_fields();
        if self.selected_line < fields.len() {
            let field = fields[self.selected_line];
            self.highlighted_bytes = Some(self.get_field_span(field));
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

    pub fn insert_char(&mut self, c: char) {
        self.input.insert(self.cursor_pos, c);
        self.cursor_pos += c.len_utf8();
        self.parse_input();
    }

    pub fn delete_char(&mut self) {
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
        self.input.insert_str(self.cursor_pos, text);
        self.cursor_pos += text.len();
        self.parse_input();
    }

    pub fn clear_input(&mut self) {
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
