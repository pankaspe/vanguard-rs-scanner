// src/ui/layout.rs

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
};

/// Defines the areas of the application's user interface.
///
/// This struct holds `Rect` objects, each representing a specific
/// widget area on the terminal screen. This approach makes it easy to
/// manage and reference the layout without re-calculating dimensions
/// every time a widget needs to be rendered.
pub struct AppLayout {
    pub input: Rect,
    pub report: Rect,
    pub summary: Rect,
    pub footer: Rect, // <-- NEW AREA
}

/// Creates the complete application layout.
///
/// This function uses `ratatui`'s `Layout` to divide the terminal frame
/// into distinct regions. The layout is split into three main vertical
/// chunks: one for the input box at the top, one for the main content
/// area in the middle, and a new one for the footer at the bottom.
/// The middle content area is then split horizontally to accommodate
/// the analysis report and the summary widgets side-by-side.
///
/// # Arguments
/// * `frame_size` - The `Rect` representing the total size of the terminal frame.
///
/// # Returns
/// An `AppLayout` struct containing the calculated `Rect` for each widget area.
pub fn create_layout(frame_size: Rect) -> AppLayout {
    // Main vertical layout: [Input], [Content], [Footer]
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // For the input box
            Constraint::Min(0),    // For the main content
            Constraint::Length(1), // <-- For our new footer bar
        ])
        .split(frame_size);

    // Horizontal layout for the main content area, splitting it into two.
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(70), // The analysis report will take up 70% of the width.
            Constraint::Percentage(30), // The summary will take up the remaining 30%.
        ])
        .split(main_chunks[1]); // This splits the second chunk from the main vertical layout.

    // Return the AppLayout struct with all calculated areas.
    AppLayout {
        input: main_chunks[0],
        report: content_chunks[0],
        summary: content_chunks[1],
        footer: main_chunks[2], // <-- Assign the new area
    }
}