// src/ui/layout.rs
use ratatui::prelude::*;
use std::rc::Rc;

/// Divides the main screen area into chunks for the input and the results.
pub fn create_main_layout(frame_size: Rect) -> Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // For the input box
            Constraint::Min(0),    // For the results area
        ])
        .split(frame_size)
}