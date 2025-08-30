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

/// Creates the complete application layout dynamically based on the current state.
///
/// This function uses `ratatui`'s `Layout` to divide the terminal frame
/// into distinct regions. The main layout is split vertically into three chunks:
/// 1. An input box at the top.
/// 2. A main content area in the middle.
/// 3. A footer at the bottom.
///
/// The middle content area is split horizontally. The proportions of this split
/// are determined by the `show_logs` flag, allowing the layout to adapt
/// to show or hide the log panel.
///
/// # Arguments
/// * `frame_size` - The `Rect` representing the total size of the terminal frame.
/// * `show_logs` - A boolean that determines whether to allocate space for the log panel.
///
/// # Returns
/// An `AppLayout` struct containing the calculated `Rect` for each widget area.
pub fn create_layout(frame_size: Rect, show_logs: bool) -> AppLayout {
    // Define the main vertical layout: input, content, footer.
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Top area for the input box.
            Constraint::Min(0),      // Middle area for dynamic content.
            Constraint::Length(1), // Bottom area for the footer.
        ])
        .split(frame_size);

    // Determine the horizontal layout constraints for the middle content area
    // based on whether the log panel should be visible.
    let content_constraints = if show_logs {
        // With logs visible: Report (45%), Summary (20%), Logs (35%)
        vec![Constraint::Percentage(45), Constraint::Percentage(20), Constraint::Percentage(35)]
    } else {
        // Without logs visible: Report (70%), Summary (30%)
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
        // If logs are visible, assign the third chunk to the log panel;
        // otherwise, assign a default (empty) Rect.
        log_panel: if show_logs { content_chunks[2] } else { Rect::default() },
        footer: main_chunks[2],
    }
}