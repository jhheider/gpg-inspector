pub mod colors;
pub mod data_panel;
pub mod hex_panel;
pub mod input_panel;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
};

use crate::app::App;
use data_panel::DataPanel;
use hex_panel::HexPanel;
use input_panel::InputPanel;

/// Requires Frame which needs terminal backend
#[cfg(not(tarpaulin_include))]
pub fn draw(frame: &mut Frame, app: &App) {
    let size = frame.area();

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(size);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[1]);

    frame.render_widget(InputPanel::new(app), main_chunks[0]);
    frame.render_widget(HexPanel::new(app), right_chunks[0]);
    frame.render_widget(DataPanel::new(app), right_chunks[1]);
}

pub fn get_hex_panel_area(size: Rect) -> Rect {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(size);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[1]);

    right_chunks[0]
}

pub fn get_data_panel_area(size: Rect) -> Rect {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(size);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[1]);

    right_chunks[1]
}
