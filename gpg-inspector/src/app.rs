use std::collections::HashSet;
use std::sync::Arc;

use gpg_inspector_lib::{ArmorBlock, Packet};

use crate::ui::colors::{ColorTracker, Theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelFocus {
    Input,
    Hex,
    Data,
}

impl PanelFocus {
    /// Tab order matches the visual layout: input, hex, data.
    pub fn next(self) -> Self {
        match self {
            PanelFocus::Input => PanelFocus::Hex,
            PanelFocus::Hex => PanelFocus::Data,
            PanelFocus::Data => PanelFocus::Input,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            PanelFocus::Input => PanelFocus::Data,
            PanelFocus::Hex => PanelFocus::Input,
            PanelFocus::Data => PanelFocus::Hex,
        }
    }
}

/// Where the current data came from. Binary input is read-only: the
/// input panel is a text editor and cannot represent raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSource {
    Text,
    Binary { origin: String, len: usize },
}

/// One display row in the data panel: a flattened view of a packet
/// field (or a synthesized marker), carrying everything the UI needs.
#[derive(Debug, Clone)]
pub struct Row {
    pub name: Arc<str>,
    pub value: Arc<str>,
    /// Byte range within `streams[self.stream]`.
    pub span: (usize, usize),
    /// Field indent level (0 = packet header).
    pub indent: u8,
    /// Compression nesting depth (0 = top level).
    pub depth: u8,
    /// Which byte stream the span indexes (0 = raw input bytes; one
    /// extra stream per decompressed buffer).
    pub stream: usize,
    /// DFS-order id of the packet (or marker) this row belongs to.
    pub packet_id: usize,
    /// True for the first row of its packet — the fold anchor that
    /// stays visible when the packet is collapsed.
    pub is_packet_first: bool,
    /// Palette color index; None for header/marker rows.
    pub color: Option<u8>,
}

pub struct App {
    pub input: String,
    pub cursor_pos: usize,
    pub source: InputSource,
    pub packets: Vec<Packet>,
    pub raw_bytes: Arc<[u8]>,
    pub armor_blocks: Vec<ArmorBlock>,
    pub cleartext: Option<Arc<str>>,
    /// All byte streams: `[0]` is the raw input, followed by one per
    /// decompressed buffer in DFS order.
    pub streams: Vec<Arc<[u8]>>,
    /// Per-stream byte color assignments, parallel to `streams`.
    pub color_trackers: Vec<ColorTracker>,
    /// All display rows, in DFS order.
    pub rows: Vec<Row>,
    /// packet_id -> parent packet_id (None for top level).
    pub packet_parent: Vec<Option<usize>>,
    /// packet_ids currently folded.
    pub collapsed: HashSet<usize>,
    /// Indices into `rows` currently visible (fold-aware).
    pub visible: Vec<usize>,
    pub focus: PanelFocus,
    pub hex_scroll: usize,
    /// Byte offset of the hex panel cursor (when the hex panel is
    /// focused), within the displayed stream.
    pub hex_cursor: usize,
    /// One-shot feedback line (e.g. clipboard confirmation), shown in
    /// the data panel title and cleared on the next keypress.
    pub status_message: Option<String>,
    pub data_scroll: usize,
    /// Index into `visible` of the selected row.
    pub selected_line: usize,
    pub highlighted_bytes: Option<(usize, usize)>,
    pub error_message: Option<String>,
    pub should_quit: bool,
    pub show_help: bool,
    pub show_detail: bool,
    pub search_active: bool,
    pub search_query: String,
    pub theme: Theme,
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
            streams: vec![Arc::from([])],
            color_trackers: vec![ColorTracker::default()],
            rows: Vec::new(),
            packet_parent: Vec::new(),
            collapsed: HashSet::new(),
            visible: Vec::new(),
            focus: PanelFocus::Input,
            hex_scroll: 0,
            hex_cursor: 0,
            status_message: None,
            data_scroll: 0,
            selected_line: 0,
            highlighted_bytes: None,
            error_message: None,
            should_quit: false,
            show_help: false,
            show_detail: false,
            search_active: false,
            search_query: String::new(),
            theme: Theme::default(),
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
                self.packets = packets;
                self.error_message = None;
            }
            Err(e) => {
                self.packets.clear();
                self.error_message = Some(format!("Parse error: {}", e));
            }
        }
        self.rebuild_rows();
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
            self.error_message = None;
            self.rebuild_rows();
            return;
        }

        match gpg_inspector_lib::decode_armor_multi(&self.input) {
            Ok(armor_result) => {
                self.raw_bytes = Arc::clone(&armor_result.bytes);
                self.armor_blocks = armor_result.blocks;
                self.cleartext = armor_result.cleartext;
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
                self.armor_blocks = Vec::new();
                self.cleartext = None;
                self.error_message = Some(format!("Armor error: {}", e));
            }
        }
        self.rebuild_rows();
    }

    /// Rebuilds `rows`, `streams`, `color_trackers`, `packet_parent`,
    /// and `visible` from `packets`. Fold state resets: packet ids are
    /// positional and do not survive a reparse.
    pub fn rebuild_rows(&mut self) {
        self.streams = vec![Arc::clone(&self.raw_bytes)];
        self.rows.clear();
        self.packet_parent.clear();
        self.collapsed.clear();

        let mut counters: Vec<u8> = vec![0];
        let mut next_id = 0usize;

        if let Some(ref cleartext) = self.cleartext {
            let first_line = cleartext.lines().next().unwrap_or("");
            let id = next_id;
            next_id += 1;
            self.packet_parent.push(None);
            self.rows.push(Row {
                name: "Cleartext".into(),
                value: format!("{} ({} chars)", first_line, cleartext.len()).into(),
                span: (0, 0),
                indent: 0,
                depth: 0,
                stream: 0,
                packet_id: id,
                is_packet_first: true,
                color: None,
            });
        }

        // Interleave armor-block markers when the input has several
        let mut block_iter = if self.armor_blocks.len() > 1 {
            self.armor_blocks.as_slice()
        } else {
            &[]
        }
        .iter()
        .peekable();

        let packets = std::mem::take(&mut self.packets);
        for packet in &packets {
            while let Some(block) = block_iter.peek() {
                if block.range.0 <= packet.start {
                    let block = block_iter.next().unwrap();
                    let id = next_id;
                    next_id += 1;
                    self.packet_parent.push(None);
                    self.rows.push(Row {
                        name: format!("Armor Block: {}", block.armor_type).into(),
                        value: format!("{} bytes", block.range.1 - block.range.0).into(),
                        span: block.range,
                        indent: 0,
                        depth: 0,
                        stream: 0,
                        packet_id: id,
                        is_packet_first: true,
                        color: None,
                    });
                } else {
                    break;
                }
            }
            walk_packets(
                std::slice::from_ref(packet),
                0,
                0,
                None,
                &mut next_id,
                &mut self.streams,
                &mut counters,
                &mut self.rows,
                &mut self.packet_parent,
            );
        }
        self.packets = packets;

        self.rebuild_trackers();
        self.rebuild_visible();
    }

    fn rebuild_trackers(&mut self) {
        self.color_trackers = self
            .streams
            .iter()
            .map(|s| ColorTracker::new(s.len()))
            .collect();
        for row in &self.rows {
            if let Some(color) = row.color {
                let (start, end) = row.span;
                let colors = &mut self.color_trackers[row.stream].byte_colors;
                if end > start && end <= colors.len() {
                    for slot in &mut colors[start..end] {
                        *slot = Some(color);
                    }
                }
            }
        }
    }

    /// Recomputes which rows are visible under the current fold state.
    pub fn rebuild_visible(&mut self) {
        self.visible = (0..self.rows.len())
            .filter(|&i| !self.row_hidden(i))
            .collect();
        self.clamp_selection();
    }

    fn row_hidden(&self, row_idx: usize) -> bool {
        let row = &self.rows[row_idx];
        if self.collapsed.contains(&row.packet_id) && !row.is_packet_first {
            return true;
        }
        let mut parent = self.packet_parent.get(row.packet_id).copied().flatten();
        while let Some(pid) = parent {
            if self.collapsed.contains(&pid) {
                return true;
            }
            parent = self.packet_parent.get(pid).copied().flatten();
        }
        false
    }

    /// Keeps selection and scroll positions valid when the visible row
    /// set changes.
    fn clamp_selection(&mut self) {
        self.selected_line = self.selected_line.min(self.visible.len().saturating_sub(1));
        self.data_scroll = self.data_scroll.min(self.selected_line);
        let display_len = self.display_bytes().len();
        let hex_lines = display_len.div_ceil(16);
        self.hex_scroll = self.hex_scroll.min(hex_lines.saturating_sub(1));
        self.hex_cursor = self.hex_cursor.min(display_len.saturating_sub(1));
        self.update_highlight();
    }

    /// All rows, fold-agnostic (packet fields plus synthesized markers).
    pub fn get_all_fields(&self) -> &[Row] {
        &self.rows
    }

    /// All rows flagged with whether they come from a nested
    /// (decompressed) packet.
    pub fn get_all_fields_flagged(&self) -> Vec<(&Row, bool)> {
        self.rows.iter().map(|r| (r, r.depth > 0)).collect()
    }

    /// Palette color for a row by index into `rows`.
    pub fn get_field_color(&self, row_index: usize) -> Option<u8> {
        self.rows.get(row_index).and_then(|r| r.color)
    }

    /// A row's byte span within its stream.
    pub fn get_field_span(&self, row: &Row) -> (usize, usize) {
        row.span
    }

    /// The currently selected row, if any.
    pub fn selected_row(&self) -> Option<&Row> {
        self.visible.get(self.selected_line).map(|&i| &self.rows[i])
    }

    /// The row shown at a visible line position.
    pub fn row_at(&self, visible_line: usize) -> Option<&Row> {
        self.visible.get(visible_line).map(|&i| &self.rows[i])
    }

    /// The stream the hex panel should display: the selected row's.
    pub fn display_stream(&self) -> usize {
        self.selected_row().map(|r| r.stream).unwrap_or(0)
    }

    /// The bytes the hex panel should display.
    pub fn display_bytes(&self) -> &Arc<[u8]> {
        self.streams
            .get(self.display_stream())
            .unwrap_or(&self.raw_bytes)
    }

    /// Byte color within the displayed stream.
    pub fn get_byte_color(&self, byte_index: usize) -> Option<u8> {
        self.color_trackers
            .get(self.display_stream())
            .and_then(|t| t.get_color(byte_index))
    }

    /// True if the packet has anything to fold (more rows than its
    /// header, or nested packets).
    pub fn packet_foldable(&self, packet_id: usize) -> bool {
        self.rows
            .iter()
            .filter(|r| r.packet_id == packet_id)
            .count()
            > 1
            || self.packet_parent.contains(&Some(packet_id))
    }

    /// Collapses or expands the selected row's packet. Selection moves
    /// to the packet's header row.
    pub fn set_fold(&mut self, collapse: bool, visible_lines: usize) {
        let Some(row) = self.selected_row() else {
            return;
        };
        let packet_id = row.packet_id;
        if !self.packet_foldable(packet_id) {
            return;
        }
        if collapse {
            self.collapsed.insert(packet_id);
        } else {
            self.collapsed.remove(&packet_id);
        }
        self.rebuild_visible();

        if let Some(first_row) = self.rows.iter().position(|r| r.packet_id == packet_id)
            && let Some(pos) = self.visible.iter().position(|&i| i == first_row)
        {
            self.select_line(pos, visible_lines);
        }
    }

    /// Toggles the fold state of the selected row's packet.
    pub fn toggle_fold(&mut self, visible_lines: usize) {
        if let Some(row) = self.selected_row() {
            let collapse = !self.collapsed.contains(&row.packet_id);
            self.set_fold(collapse, visible_lines);
        }
    }

    pub fn update_highlight(&mut self) {
        self.highlighted_bytes = self.selected_row().map(|r| r.span);
    }

    /// Moves the hex cursor by `delta` bytes within the displayed
    /// stream; the hex scroll follows the cursor.
    pub fn move_hex_cursor(&mut self, delta: isize, visible_lines: usize) {
        let target = if delta >= 0 {
            self.hex_cursor.saturating_add(delta as usize)
        } else {
            self.hex_cursor.saturating_sub((-delta) as usize)
        };
        self.set_hex_cursor(target, visible_lines);
    }

    /// Places the hex cursor at a byte offset (clamped) and scrolls it
    /// into view.
    pub fn set_hex_cursor(&mut self, offset: usize, visible_lines: usize) {
        let len = self.display_bytes().len();
        if len == 0 {
            return;
        }
        self.hex_cursor = offset.min(len - 1);
        let line = self.hex_cursor / 16;
        if line < self.hex_scroll {
            self.hex_scroll = line;
        } else if visible_lines > 0 && line >= self.hex_scroll + visible_lines {
            self.hex_scroll = line + 1 - visible_lines;
        }
    }

    /// Scrolls the hex view without moving the cursor (mouse wheel).
    pub fn scroll_hex(&mut self, delta: isize) {
        let total_lines = self.display_bytes().len().div_ceil(16);
        let target = if delta >= 0 {
            self.hex_scroll.saturating_add(delta as usize)
        } else {
            self.hex_scroll.saturating_sub((-delta) as usize)
        };
        self.hex_scroll = target.min(total_lines.saturating_sub(1));
    }

    /// Jumps the data selection to the row owning the byte under the
    /// hex cursor: the narrowest containing span in the displayed
    /// stream, preferring deeper-indented rows on ties. Focus moves to
    /// the data panel on success.
    pub fn jump_to_hex_owner(&mut self, data_visible_lines: usize) -> bool {
        let stream = self.display_stream();
        let pos = self.hex_cursor;

        let mut best: Option<(usize, usize, u8)> = None; // (row_idx, size, indent)
        for (i, row) in self.rows.iter().enumerate() {
            if row.stream != stream {
                continue;
            }
            let (start, end) = row.span;
            if pos < start || pos >= end {
                continue;
            }
            let size = end - start;
            let better = match best {
                None => true,
                Some((_, best_size, best_indent)) => {
                    size < best_size || (size == best_size && row.indent > best_indent)
                }
            };
            if better {
                best = Some((i, size, row.indent));
            }
        }

        if let Some((row_idx, _, _)) = best {
            self.select_row_index(row_idx, data_visible_lines);
            self.focus = PanelFocus::Data;
            true
        } else {
            false
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
        let max_line = self.visible.len().saturating_sub(1);

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

    /// Moves the selection to a visible line and scrolls it into view.
    pub fn select_line(&mut self, line: usize, visible_lines: usize) {
        let total = self.visible.len();
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

    /// Expands any folds hiding a row, then selects it.
    pub fn select_row_index(&mut self, row_idx: usize, visible_lines: usize) {
        if row_idx >= self.rows.len() {
            return;
        }
        let mut changed = false;
        let mut pid = Some(self.rows[row_idx].packet_id);
        while let Some(id) = pid {
            if self.collapsed.remove(&id) {
                changed = true;
            }
            pid = self.packet_parent.get(id).copied().flatten();
        }
        if changed {
            self.rebuild_visible();
        }
        if let Some(pos) = self.visible.iter().position(|&i| i == row_idx) {
            self.select_line(pos, visible_lines);
        }
    }

    /// Indices (into `rows`) of rows whose name or value contains the
    /// search query (case-insensitive). Searches hidden rows too; a
    /// jump auto-expands. Empty query matches nothing.
    pub fn search_matches(&self) -> Vec<usize> {
        if self.search_query.is_empty() {
            return Vec::new();
        }
        let query = self.search_query.to_lowercase();
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r.name.to_lowercase().contains(&query) || r.value.to_lowercase().contains(&query)
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// The rows-index of the current selection (for match navigation).
    fn selected_row_index(&self) -> usize {
        self.visible.get(self.selected_line).copied().unwrap_or(0)
    }

    /// Jumps to the first match at or after the current selection.
    pub fn jump_to_first_match(&mut self, visible_lines: usize) {
        let matches = self.search_matches();
        let current = self.selected_row_index();
        if let Some(&target) = matches
            .iter()
            .find(|&&i| i >= current)
            .or_else(|| matches.first())
        {
            self.select_row_index(target, visible_lines);
        }
    }

    /// Jumps to the next (or previous) match, wrapping around.
    pub fn jump_to_match(&mut self, forward: bool, visible_lines: usize) {
        let matches = self.search_matches();
        if matches.is_empty() {
            return;
        }
        let current = self.selected_row_index();
        let target = if forward {
            matches
                .iter()
                .copied()
                .find(|&i| i > current)
                .unwrap_or(matches[0])
        } else {
            matches
                .iter()
                .rev()
                .copied()
                .find(|&i| i < current)
                .unwrap_or(*matches.last().unwrap())
        };
        self.select_row_index(target, visible_lines);
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

/// DFS over packets: assigns packet ids, registers decompressed
/// buffers as streams (with a fresh color rotation each), and emits
/// one row per field.
#[allow(clippy::too_many_arguments)]
fn walk_packets(
    packets: &[Packet],
    stream_idx: usize,
    depth: u8,
    parent: Option<usize>,
    next_id: &mut usize,
    streams: &mut Vec<Arc<[u8]>>,
    counters: &mut Vec<u8>,
    rows: &mut Vec<Row>,
    packet_parent: &mut Vec<Option<usize>>,
) {
    for packet in packets {
        let id = *next_id;
        *next_id += 1;
        packet_parent.push(parent);

        for (i, field) in packet.fields.iter().enumerate() {
            let color = if field.indent > 0 {
                let c = counters[stream_idx];
                counters[stream_idx] = (c + 1) % 12;
                Some(c)
            } else {
                None
            };
            rows.push(Row {
                name: Arc::clone(&field.name),
                value: Arc::clone(&field.value),
                span: field.span,
                indent: field.indent,
                depth,
                stream: stream_idx,
                packet_id: id,
                is_packet_first: i == 0,
                color,
            });
        }

        if let Some(ref buf) = packet.child_buffer {
            streams.push(Arc::clone(buf));
            counters.push(0);
            let child_stream = streams.len() - 1;
            walk_packets(
                &packet.children,
                child_stream,
                depth + 1,
                Some(id),
                next_id,
                streams,
                counters,
                rows,
                packet_parent,
            );
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
