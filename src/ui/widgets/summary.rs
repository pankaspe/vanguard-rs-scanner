// src/ui/widgets/summary.rs

use crate::app::{App, AppState};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, Paragraph}, // Padding non è più necessario qui
    text::Line,
};

pub fn render_summary(frame: &mut Frame, app: &App, area: Rect) {
    let summary_container = Block::default().borders(Borders::ALL).title("Summary");
    frame.render_widget(summary_container, area);

    // Layout con spaziature, invariato rispetto a prima
    let summary_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Score & Rating
            Constraint::Length(1), // Gauge
            Constraint::Length(2), // Spazio
            Constraint::Length(4), // Security Checks
            Constraint::Length(2), // Spazio
            Constraint::Length(3), // Issues Found
            Constraint::Length(2), // Spazio
            Constraint::Min(0),    // Technologies
        ])
        .split(area);

    if !matches!(app.state, AppState::Finished) {
        return;
    }

    // --- Score & Rating ---
    let (rating_text, rating_style) = match app.summary.score {
        90..=100 => ("Excellent", Style::default().fg(Color::Green)),
        75..=89 => ("Good", Style::default().fg(Color::Cyan)),
        50..=74 => ("Needs Improvement", Style::default().fg(Color::Yellow)),
        _ => ("Poor", Style::default().fg(Color::Red)),
    };
    let score_line = Line::from(format!("{}/100 ({})", app.summary.score, rating_text)).style(rating_style);
    let score_text = Text::from(vec![Line::from("Overall Score".bold()), score_line]);
    frame.render_widget(Paragraph::new(score_text).alignment(Alignment::Center), summary_chunks[0]);

    // --- Gauge Chart (Animato) ---
    let score_gauge = Gauge::default()
        .percent(app.displayed_score as u16)
        .label("")
        .style(Style::default().fg(
            if app.displayed_score >= 80 { Color::Green }
            else if app.displayed_score >= 50 { Color::Yellow }
            else { Color::Red }
        ));
    frame.render_widget(score_gauge, summary_chunks[1]);

    // --- Security Checks ---
    // FIX: Rimosso .borders(Borders::TOP) e titolo in maiuscolo
    let checks_block = Block::default()
        .title("SECURITY CHECKS".bold());
    let mut checks_lines = Vec::new();
    let checks_to_render = [
        ("DNS Configuration", app.summary.dns_check_passed),
        ("SSL/TLS Certificate", app.summary.ssl_check_passed),
        ("HTTP Security Headers", app.summary.headers_check_passed),
    ];
    for (name, passed) in checks_to_render {
        let (icon, style) = if passed { ("✓", Style::default().fg(Color::Green)) } else { ("✗", Style::default().fg(Color::Red)) };
        checks_lines.push(Line::from(vec![Span::styled(format!("{} ", icon), style), Span::raw(name)]));
    }
    frame.render_widget(Paragraph::new(checks_lines).block(checks_block), summary_chunks[3]);

    // --- Issue Details ---
    // FIX: Rimosso .borders(Borders::TOP) e titolo in maiuscolo
    let issues_block = Block::default()
        .title("ISSUES FOUND".bold());
    let details_text = Text::from(vec![
        Line::from(vec![Span::raw("Critical: "), Span::styled(app.summary.critical_issues.to_string(), Style::default().fg(Color::Red))]),
        Line::from(vec![Span::raw("Warnings: "), Span::styled(app.summary.warning_issues.to_string(), Style::default().fg(Color::Yellow))]),
    ]);
    frame.render_widget(Paragraph::new(details_text).block(issues_block), summary_chunks[5]);

    // --- Technologies ---
    // FIX: Rimosso .borders(Borders::TOP) e titolo in maiuscolo
    let tech_block = Block::default()
        .title("TECHNOLOGIES".bold());
    let mut tech_lines = Vec::new();
    if let Some(report) = &app.scan_report {
        if !report.fingerprint_results.technologies.is_empty() {
            for tech in &report.fingerprint_results.technologies {
                tech_lines.push(Line::from(vec![Span::raw("- "), Span::styled(tech.name.clone(), Style::default().fg(Color::Cyan))]));
            }
        } else {
            tech_lines.push(Line::from("Not identified."));
        }
    }
    let tech_paragraph = Paragraph::new(tech_lines).block(tech_block);
    frame.render_widget(tech_paragraph, summary_chunks[7]);
}