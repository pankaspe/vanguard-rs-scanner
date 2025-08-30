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
    pub footer: Rect,
    pub log_panel: Rect,
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
pub fn create_layout(frame_size: Rect, show_logs: bool) -> AppLayout { // <-- NUOVO: prende `show_logs`
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame_size);

    // --- NUOVO: Layout Orizzontale Dinamico ---
    let content_constraints = if show_logs {
        // Se i log sono visibili: Report (45%), Summary (20%), Log (35%)
        vec![Constraint::Percentage(45), Constraint::Percentage(20), Constraint::Percentage(35)]
    } else {
        // Altrimenti: Report (70%), Summary (30%)
        vec![Constraint::Percentage(70), Constraint::Percentage(30)]
    };

    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(content_constraints)
        .split(main_chunks[1]);

    AppLayout {
        input: main_chunks[0],
        report: content_chunks[0],
        summary: content_chunks[1],
        // Se i log sono visibili, il pannello dei log è il terzo chunk, altrimenti è un'area vuota.
        log_panel: if show_logs { content_chunks[2] } else { Rect::default() },
        footer: main_chunks[2],
    }
}