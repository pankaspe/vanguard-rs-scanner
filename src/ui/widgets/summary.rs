// src/ui/widgets/summary.rs

use crate::app::{App, AppState};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, Paragraph}, // Padding is no longer needed here
    text::Line,
};

/// Renders the summary widget, which provides a high-level overview of the scan results.
///
/// This widget displays a score, a visual gauge, a list of passed/failed security checks,
/// a count of critical/warning issues, and a list of identified technologies.
/// The content is only rendered when the scan is in the `AppState::Finished` state.
///
/// # Arguments
/// * `frame` - A mutable reference to the `Frame` used for rendering the TUI.
/// * `app` - A reference to the application's state struct, containing all the scan data.
/// * `area` - The `Rect` where the summary widget should be rendered.
pub fn render_summary(frame: &mut Frame, app: &App, area: Rect) {
    let summary_container = Block::default().borders(Borders::ALL).title("Summary");
    frame.render_widget(summary_container, area);

    // Define the layout with spacing, unchanged from before.
    let summary_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Score & Rating
            Constraint::Length(1), // Gauge
            Constraint::Length(2), // Spacer
            Constraint::Length(4), // Security Checks
            Constraint::Length(2), // Spacer
            Constraint::Length(3), // Issues Found
            Constraint::Length(2), // Spacer
            Constraint::Min(0),    // Technologies
        ])
        .split(area);

    // Only render the summary content if the scan is finished.
    if !matches!(app.state, AppState::Finished) {
        return;
    }

    // --- Score & Rating ---
    // The rating text and style are determined by the calculated score.
    let (rating_text, rating_style) = match app.summary.score {
        90..=100 => ("Excellent", Style::default().fg(Color::Green)),
        75..=89 => ("Good", Style::default().fg(Color::Cyan)),
        50..=74 => ("Needs Improvement", Style::default().fg(Color::Yellow)),
        _ => ("Poor", Style::default().fg(Color::Red)),
    };
    let score_line = Line::from(format!("{}/100 ({})", app.summary.score, rating_text)).style(rating_style);
    let score_text = Text::from(vec![Line::from("Overall Score".bold()), score_line]);
    frame.render_widget(Paragraph::new(score_text).alignment(Alignment::Center), summary_chunks[0]);

    // --- Gauge Chart (Animated) ---
    // A gauge visually represents the score. The displayed score is animated for a smooth effect.
    let score_gauge = Gauge::default()
        .percent(app.displayed_score as u16)
        .label("") // Label is not needed for this visual
        .style(Style::default().fg(
            // Color of the gauge changes with the score
            if app.displayed_score >= 80 { Color::Green }
            else if app.displayed_score >= 50 { Color::Yellow }
            else { Color::Red }
        ));
    frame.render_widget(score_gauge, summary_chunks[1]);

    // --- Security Checks ---
    // Renders the status of key security checks (DNS, SSL, Headers).
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
    // Displays the count of critical and warning issues found.
    let issues_block = Block::default()
        .title("ISSUES FOUND".bold());
    let details_text = Text::from(vec![
        Line::from(vec![Span::raw("Critical: "), Span::styled(app.summary.critical_issues.to_string(), Style::default().fg(Color::Red))]),
        Line::from(vec![Span::raw("Warnings: "), Span::styled(app.summary.warning_issues.to_string(), Style::default().fg(Color::Yellow))]),
    ]);
    frame.render_widget(Paragraph::new(details_text).block(issues_block), summary_chunks[5]);

    // --- Technologies ---
    // Lists the technologies identified by the fingerprinting scanner.
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