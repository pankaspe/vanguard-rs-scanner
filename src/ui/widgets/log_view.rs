// src/ui/widgets/log_view.rs

use crate::app::App;
use ratatui::{
    prelude::*,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation},
};

/// Renders the log view panel.
///
/// This widget displays the most recent lines from the application's log file.
/// It includes a horizontal scrollbar to allow viewing of long log lines that
/// might otherwise be truncated. This version applies custom styling to the
/// timestamp part of each log line to improve readability.
///
/// # Arguments
///
/// * `frame` - The mutable frame to render onto.
/// * `app` - A mutable reference to the application's state, containing log content and scroll state.
/// * `area` - The `Rect` in which to render this widget.
pub fn render_log_view(frame: &mut Frame, app: &mut App, area: Rect) {
    // Create the main block for the log panel with a title and borders.
    let block = Block::default()
        .title("Logs (scroll with ← →)")
        .borders(Borders::ALL);
    
    // Get the inner area of the block to render the content within the borders.
    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    // Calculate the maximum width of the log content to configure the scrollbar correctly.
    let max_width = app.log_content.iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);

    // Update the scrollbar's state with the total content length.
    app.log_horizontal_scroll_state = app.log_horizontal_scroll_state.content_length(max_width);

    // --- INIZIO CORREZIONE ---
    // Process each log line to apply custom styling.
    let log_lines: Vec<Line> = app.log_content.iter().map(|line_str| {
        // A typical log line looks like: "DATE TIME LEVEL MESSAGE"
        // We split the line into at most 3 parts based on spaces.
        let mut parts = line_str.splitn(3, ' ');

        // We use a match to safely handle the parts.
        match (parts.next(), parts.next(), parts.next()) {
            // This case matches if we successfully get a date, a time, and the rest of the message.
            (Some(date), Some(time), Some(rest)) => {
                // Recombine the date and time to form the full timestamp.
                let timestamp = format!("{} {}", date, time);
                // The rest of the line needs a leading space to look correct.
                let message = format!(" {}", rest);

                // Create a styled Line with a gray timestamp and a regular message.
                Line::from(vec![
                    Span::styled(timestamp, Style::default().fg(Color::DarkGray)),
                    Span::raw(message),
                ])
            },
            // This is a fallback. If a line doesn't match the expected format,
            // we render it as-is without any special styling.
            _ => Line::from(line_str.as_str()),
        }
    }).collect();
    
    // Create the Paragraph widget from our collection of styled lines.
    let log_paragraph = Paragraph::new(log_lines)
        .scroll((0, app.log_horizontal_scroll as u16));
    // --- FINE CORREZIONE ---
        
    frame.render_widget(log_paragraph, inner_area);

    // Create a horizontal scrollbar to be displayed at the bottom of the panel.
    let scrollbar = Scrollbar::new(ScrollbarOrientation::HorizontalBottom)
        .thumb_symbol("■");

    // Define the specific area for the scrollbar at the bottom edge of the inner area.
    let scrollbar_area = Rect {
        x: inner_area.x,
        y: inner_area.y + inner_area.height.saturating_sub(1),
        width: inner_area.width,
        height: 1,
    };
    
    // Render the stateful scrollbar widget.
    frame.render_stateful_widget(
        scrollbar,
        scrollbar_area,
        &mut app.log_horizontal_scroll_state,
    );
}