// src/ui/widgets/log_view.rs

use crate::app::App;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation},
};

/// Renders the log view panel.
///
/// This widget displays the most recent lines from the application's log file.
/// It includes a horizontal scrollbar to allow viewing of long log lines that
/// might otherwise be truncated.
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

    // Create a single Text object from all log lines.
    let log_text = Text::from(app.log_content.join("\n"));
    
    // Create a Paragraph to display the text, applying the current horizontal scroll offset.
    let log_paragraph = Paragraph::new(log_text)
        .scroll((0, app.log_horizontal_scroll as u16));
        
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