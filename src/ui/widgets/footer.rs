// src/ui/widgets/footer.rs

use crate::app::{App, AppState};
use ratatui::{
    prelude::*,
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::Paragraph,
};

/// Renders the footer widget, which displays available actions.
pub fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let spans = match app.state {
        // Quando l'utente sta digitando
        AppState::Idle => Line::from(vec![
            Span::raw("Press "),
            Span::styled("Enter", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to scan, "),
            Span::styled("Q", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to quit."),
        ]),
        // Quando il report è visualizzato
        AppState::Finished => Line::from(vec![
            Span::styled("[N]", Style::new().bold().fg(Color::Yellow)),
            Span::raw("ew Scan, "),
            Span::styled("[E]", Style::new().bold().fg(Color::Yellow)),
            Span::raw("xport (soon), "),
            Span::styled("[Q]", Style::new().bold().fg(Color::Yellow)),
            Span::raw("uit"),
        ]),
        // Durante la scansione
        AppState::Scanning => Line::from("Scanning... Press Q to quit."),
    };

    let footer = Paragraph::new(spans).alignment(Alignment::Center);
    frame.render_widget(footer, area);
}