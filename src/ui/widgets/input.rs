// src/ui/widgets/input.rs

// 1. Importiamo `Position` dalla libreria, come mostrato nell'esempio.
use ratatui::{
    layout::Position,
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

use crate::app::{App, AppState};

/// Renders the input box widget.
pub fn render_input(frame: &mut Frame, app: &App, area: Rect) {
    let input_block = Block::default().borders(Borders::ALL).title("Target Domain");
    let input_paragraph = Paragraph::new(app.input.as_str())
        .block(input_block)
        .style(Style::default().fg(Color::Yellow));
    frame.render_widget(input_paragraph, area);

    // Show the cursor only when in the Idle state.
    if let AppState::Idle = app.state {
        // 2. Usiamo il nuovo metodo `set_cursor_position` che accetta una `Position`.
        // La logica per calcolare x e y rimane identica.
        frame.set_cursor_position(Position::new(
            area.x + app.input.len() as u16 + 1,
            area.y + 1,
        ));
    }
}