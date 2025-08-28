// src/ui/widgets/footer.rs

use crate::app::{App, AppState, ExportStatus}; // <-- Importa ExportStatus
use ratatui::{
    prelude::*,
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::Paragraph,
};

pub fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let spans = match app.state {
        AppState::Idle => Line::from(vec![
            Span::raw("Press "),
            Span::styled("Enter", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to scan, "),
            Span::styled("Q", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to quit."),
        ]),
        AppState::Finished => {
            // Controlla prima lo stato dell'export!
            match &app.export_status {
                ExportStatus::Idle => Line::from(vec![
                    Span::styled("[N]", Style::new().bold().fg(Color::Yellow)),
                    Span::raw("ew Scan, "),
                    Span::styled("[E]", Style::new().bold().fg(Color::Yellow)),
                    Span::raw("xport, "),
                    Span::styled("[Q]", Style::new().bold().fg(Color::Yellow)),
                    Span::raw("uit"),
                ]),
                ExportStatus::Success(filename) => Line::from(
                    Span::styled(format!("✓ Exported to {}", filename), Style::new().fg(Color::Green))
                ),
                ExportStatus::Error(e) => Line::from(
                    Span::styled(format!("✗ Error: {}", e), Style::new().fg(Color::Red))
                ),
            }
        }
        AppState::Scanning => Line::from("Scanning... Press Q to quit."),
    };

    let footer = Paragraph::new(spans).alignment(Alignment::Center);
    frame.render_widget(footer, area);
}