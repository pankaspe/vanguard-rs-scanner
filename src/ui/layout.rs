// src/ui/layout.rs

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
};

pub struct AppLayout {
    pub input: Rect,
    pub report: Rect,
    pub summary: Rect,
    pub footer: Rect, // <-- NUOVA AREA
}

/// Creates the complete application layout.
pub fn create_layout(frame_size: Rect) -> AppLayout {
    // Layout verticale principale: [Input], [Contenuto], [Footer]
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Per l'input box
            Constraint::Min(0),    // Per il contenuto principale
            Constraint::Length(1), // <-- Per la nostra nuova footer bar
        ])
        .split(frame_size);

    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(70),
            Constraint::Percentage(30),
        ])
        .split(main_chunks[1]);

    AppLayout {
        input: main_chunks[0],
        report: content_chunks[0],
        summary: content_chunks[1],
        footer: main_chunks[2], // <-- Assegna la nuova area
    }
}