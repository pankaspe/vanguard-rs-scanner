// src/ui/widgets/footer.rs

use crate::app::{App, AppState, ExportStatus};
use ratatui::{
    prelude::*,
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::Paragraph,
};

/// Renders the footer widget.
///
/// The content of the footer is dynamic and changes based on the application's
/// current state (`AppState`) and the export status (`ExportStatus`). It provides
/// contextual hints and keybindings to the user.
///
/// # Arguments
///
/// * `frame` - The mutable frame to render onto.
/// * `app` - A reference to the application's state.
/// * `area` - The `Rect` in which to render the footer.
pub fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    // Determine the content of the footer based on the application's state.
    let spans = match app.state {
        // In the disclaimer view, show how to proceed.
        AppState::Disclaimer => Line::from(vec![
            Span::raw("Press "),
            Span::styled("Enter", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to Acknowledge and Continue"),
        ]),
        
        // When idle, show the primary actions.
        AppState::Idle => Line::from(vec![
            Span::raw("Press "),
            Span::styled("Enter", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to scan, "),
            Span::styled("Q", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to quit."),
        ]),

        // When the scan is finished, the controls are more complex.
        AppState::Finished => {
            match &app.export_status {
                // If no export action is active, show the main navigation and action keys.
                ExportStatus::Idle => {
                    // Display different navigation hints depending on whether the log view is active.
                    let nav_controls = if app.show_logs {
                        "Scroll Logs: [←/→]"
                    } else {
                        "Navigate List: [↑/↓]"
                    };
                    let main_controls = "[N]ew Scan | [E]xport | [L]ogs | [Q]uit";
                    Line::from(vec![
                        Span::styled(nav_controls, Style::new().fg(Color::Cyan)),
                        Span::raw(" | "),
                        Span::raw(main_controls),
                    ])
                },
                // Show a success message after a successful export.
                ExportStatus::Success(filename) => Line::from(
                    Span::styled(format!("✓ Exported to {}", filename), Style::new().fg(Color::Green))
                ),
                // Show an error message if the export failed.
                ExportStatus::Error(e) => Line::from(
                    Span::styled(format!("✗ Error: {}", e), Style::new().fg(Color::Red))
                ),
            }
        }
        
        // During a scan, provide a way to quit.
        AppState::Scanning => Line::from("Scanning... Press Q to quit."),
    };

    // Create and render the Paragraph widget.
    let footer = Paragraph::new(spans).alignment(Alignment::Center);
    frame.render_widget(footer, area);
}