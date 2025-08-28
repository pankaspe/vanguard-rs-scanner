// src/ui/widgets/summary.rs

use crate::app::{App, AppState};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, Paragraph},
    text::Line, // Importa Line
};

pub fn render_summary(frame: &mut Frame, app: &App, area: Rect) {
    let summary_block = Block::default().borders(Borders::ALL).title("Summary");
    
    // Modifichiamo il layout per fare spazio al rating
    let summary_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(2), // Per "Overall Score" e il numero
            Constraint::Length(1), // Per il testo di valutazione (es. "Excellent")
            Constraint::Length(2), // Per il Gauge
            Constraint::Min(3),    // Per i dettagli dei problemi
        ])
        .split(summary_block.inner(area));

    frame.render_widget(summary_block, area);

    if !matches!(app.state, AppState::Finished) {
        return;
    }

    // --- Score ---
    let score_text = Paragraph::new(format!("{}/100", app.summary.score))
        .block(Block::default().title("Overall Score"))
        .alignment(Alignment::Center);
    frame.render_widget(score_text, summary_chunks[0]);

    // --- NUOVO: Rating Text ---
    let (rating_text, rating_style) = match app.summary.score {
        90..=100 => ("Excellent", Style::default().fg(Color::Green)),
        75..=89 => ("Good", Style::default().fg(Color::Cyan)),
        50..=74 => ("Needs Improvement", Style::default().fg(Color::Yellow)),
        _ => ("Poor", Style::default().fg(Color::Red)),
    };
    let rating_paragraph = Paragraph::new(rating_text.bold())
        .style(rating_style)
        .alignment(Alignment::Center);
    frame.render_widget(rating_paragraph, summary_chunks[1]);

    // --- Gauge Chart (Animato) ---
    // Ora usa `displayed_score` per il rendering!
    let score_gauge = Gauge::default()
        .percent(app.displayed_score as u16)
        .label("")
        .style(Style::default().fg(
            if app.displayed_score >= 80 { Color::Green }
            else if app.displayed_score >= 50 { Color::Yellow }
            else { Color::Red }
        ));
    frame.render_widget(score_gauge, summary_chunks[2]);

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
    frame.render_widget(Paragraph::new(details_text), summary_chunks[3]);
}