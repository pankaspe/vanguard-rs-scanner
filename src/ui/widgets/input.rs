// src/ui/widgets/input.rs

// 1. Import `Position` from the `ratatui` library, as shown in the example.
use ratatui::{
    layout::Position,
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

use crate::app::{App, AppState};

/// Renders the input box widget.
///
/// This function is responsible for drawing the text input field where the user
/// enters the target domain. It handles rendering the block, the text, and
/// displaying the cursor when the application is in an interactive state.
///
/// # Arguments
///
/// * `frame` - A mutable reference to the `Frame` for rendering.
/// * `app` - A reference to the application's state, containing the input string.
/// * `area` - The `Rect` where the input widget should be rendered.
pub fn render_input(frame: &mut Frame, app: &App, area: Rect) {
    // Create the block with a title and borders.
    let input_block = Block::default().borders(Borders::ALL).title("Target Domain");

    // Create the paragraph widget with the current input text.
    let input_paragraph = Paragraph::new(app.input.as_str())
        .block(input_block)
        .style(Style::default().fg(Color::Yellow));

    // Render the paragraph widget to the frame.
    frame.render_widget(input_paragraph, area);

    // Show the cursor only when the application is in the `Idle` state,
    // which is the only time the user can type.
    if let AppState::Idle = app.state {
        // 2. We use the new `set_cursor_position` method which takes a `Position`.
        // The logic to calculate the x and y coordinates remains the same,
        // offset by the block's padding.
        frame.set_cursor_position(Position::new(
            // `area.x + 1` for the left border, plus the length of the input string.
            area.x + app.input.len() as u16 + 1,
            // `area.y + 1` for the top border.
            area.y + 1,
        ));
    }
}