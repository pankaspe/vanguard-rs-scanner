// src/ui/widgets/summary.rs

use crate::app::{App, AppState};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, Paragraph},
};

pub fn render_summary(frame: &mut Frame, app: &App, area: Rect) {
    let summary_block = Block::default().borders(Borders::ALL).title("Summary");
    
    // Create an inner vertical layout for the right-hand panel
    let summary_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // For the "Score" title
            Constraint::Length(2), // For the Gauge
            Constraint::Min(3),    // For the issue details
        ])
        .split(summary_block.inner(area)); // Use inner to draw inside the block

    frame.render_widget(summary_block, area);

    // If the scan is not finished, don't show anything inside
    if !matches!(app.state, AppState::Finished) {
        return;
    }

    // --- Score ---
    let score_text = Paragraph::new(Text::from(vec![
        Line::from("Overall Score".bold()),
        Line::from(format!("{}/100", app.summary.score)),
    ])).alignment(Alignment::Center);
    frame.render_widget(score_text, summary_chunks[0]);

    // --- Gauge Chart ---
    let score_gauge = Gauge::default()
        .percent(app.summary.score as u16)
        .label("")
        .style(Style::default().fg(
            if app.summary.score >= 80 { Color::Green }
            else if app.summary.score >= 50 { Color::Yellow }
            else { Color::Red }
        ));
    frame.render_widget(score_gauge, summary_chunks[1]);

    // --- Issue Details ---
    let details_text = Text::from(vec![
        Line::from(""),
        Line::from("Issues Found:".bold()),
        Line::from(vec![
            Span::raw("  Critical: "),
            Span::styled(app.summary.critical_issues.to_string(), Style::default().fg(Color::Red)),
        ]),
        Line::from(vec![
            Span::raw("  Warnings: "),
            Span::styled(app.summary.warning_issues.to_string(), Style::default().fg(Color::Yellow)),
        ]),
    ]);
    frame.render_widget(Paragraph::new(details_text), summary_chunks[2]);
}