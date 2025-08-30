// src/ui/widgets/footer.rs

use crate::app::{App, AppState, ExportStatus};
use ratatui::{
    prelude::*,
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::Paragraph,
};

pub fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let spans = match app.state {
        AppState::Disclaimer => Line::from(vec![
            Span::raw("Press "),
            Span::styled("Enter", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to Acknowledge and Continue"),
        ]),
        
        AppState::Idle => Line::from(vec![
            Span::raw("Press "),
            Span::styled("Enter", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to scan, "),
            Span::styled("Q", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to quit."),
        ]),

        AppState::Finished => {
            match &app.export_status {
                ExportStatus::Idle => {
                    // CORREZIONE: Testo delle istruzioni chiaro e solo per tastiera.
                    let nav_controls = if app.show_logs {
                        "Scroll Logs: [←/→]"
                    } else {
                        "Navigate List: [↑/↓/j/k]"
                    };
                    let main_controls = "[N]ew Scan | [E]xport | [L]ogs | [Q]uit";
                    Line::from(vec![
                        Span::styled(nav_controls, Style::new().fg(Color::Cyan)),
                        Span::raw(" | "),
                        Span::raw(main_controls),
                    ])
                },
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