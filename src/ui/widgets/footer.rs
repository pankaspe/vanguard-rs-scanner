// src/ui/widgets/footer.rs

use crate::app::{App, AppState, ExportStatus};
use ratatui::{
    prelude::*,
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::Paragraph,
};

/// Renders the footer bar at the bottom of the TUI.
///
/// The footer's content is dynamic and changes based on the current state of the application.
/// It provides the user with context-sensitive instructions and status updates.
///
/// # Arguments
/// * `frame` - A mutable reference to the `Frame` used for rendering.
/// * `app` - A reference to the application's state struct.
/// * `area` - The `Rect` where the footer should be rendered.
pub fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let spans = match app.state {
        // Renders the prompt to acknowledge the disclaimer.
        AppState::Disclaimer => Line::from(vec![
            Span::raw("Press "),
            Span::styled("Enter", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to Acknowledge and Continue"),
        ]),
        
        // Renders instructions for the initial idle state.
        AppState::Idle => Line::from(vec![
            Span::raw("Press "),
            Span::styled("Enter", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to scan, "),
            Span::styled("Q", Style::new().bold().fg(Color::Yellow)),
            Span::raw(" to quit."),
        ]),

        // Renders options and status after a scan is completed.
        AppState::Finished => {
            match &app.export_status {
                // Display post-scan options.
                ExportStatus::Idle => Line::from(vec![
                    Span::styled("[N]", Style::new().bold().fg(Color::Yellow)),
                    Span::raw("ew Scan, "),
                    Span::styled("[E]", Style::new().bold().fg(Color::Yellow)),
                    Span::raw("xport, "),
                    Span::styled("[Q]", Style::new().bold().fg(Color::Yellow)),
                    Span::raw("uit"),
                ]),
                // Confirm a successful export.
                ExportStatus::Success(filename) => Line::from(
                    Span::styled(format!("✓ Exported to {}", filename), Style::new().fg(Color::Green))
                ),
                // Display an export error.
                ExportStatus::Error(e) => Line::from(
                    Span::styled(format!("✗ Error: {}", e), Style::new().fg(Color::Red))
                ),
            }
        }
        
        // Renders a simple status message during the scanning process.
        AppState::Scanning => Line::from("Scanning... Press Q to quit."),
    };

    // Create the paragraph widget from the generated text and center it.
    let footer = Paragraph::new(spans).alignment(Alignment::Center);
    
    // Render the widget to the frame at the specified area.
    frame.render_widget(footer, area);
}