// src/ui/widgets/summary.rs
 
use crate::app::{App, AppState};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, Paragraph},
    text::Line,
};
 
/// Renders the summary widget, which provides a high-level overview of the scan results.
/// 
/// This widget displays the overall score, a progress gauge, and a summary of
/// key security checks and issues found during the scan. It only renders content
/// once the scan has finished.
///
/// # Arguments
/// * `frame` - The `Frame` used for rendering the UI.
/// * `app` - A reference to the application's state, containing all scan data.
/// * `area` - The `Rect` defining the drawable area for this widget.
pub fn render_summary(frame: &mut Frame, app: &App, area: Rect) {
    let summary_container = Block::default().borders(Borders::ALL).title("Summary");
    frame.render_widget(summary_container, area);
 
    // Define the layout for the internal chunks of the widget.
    let summary_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Score & Rating section
            Constraint::Length(1), // Gauge chart
            Constraint::Length(2), // Spacer
            Constraint::Length(4), // Security Checks section
            Constraint::Length(2), // Spacer
            Constraint::Length(3), // Issues Found section
            Constraint::Length(2), // Spacer
            Constraint::Min(0),    // Technologies section
        ])
        .split(area);
 
    // Do not render summary content until the scan is complete.
    if !matches!(app.state, AppState::Finished) {
        return;
    }
 
    // --- Score & Rating Section ---
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
    // The gauge's color changes based on the score threshold.
    let score_gauge = Gauge::default()
        .percent(app.displayed_score as u16)
        .label("")
        .style(Style::default().fg(
            if app.displayed_score >= 80 { Color::Green }
            else if app.displayed_score >= 50 { Color::Yellow }
            else { Color::Red }
        ));
    frame.render_widget(score_gauge, summary_chunks[1]);
 
    // --- Security Checks Section ---
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
 
    // --- Issue Details Section ---
    let issues_block = Block::default()
        .title("ISSUES FOUND".bold());
    let details_text = Text::from(vec![
        Line::from(vec![Span::raw("Critical: "), Span::styled(app.summary.critical_issues.to_string(), Style::default().fg(Color::Red))]),
        Line::from(vec![Span::raw("Warnings: "), Span::styled(app.summary.warning_issues.to_string(), Style::default().fg(Color::Yellow))]),
    ]);
    frame.render_widget(Paragraph::new(details_text).block(issues_block), summary_chunks[5]);
 
    // --- Technologies Section ---
    let tech_block = Block::default()
        .title("TECHNOLOGIES".bold());
    let mut tech_lines = Vec::new();
    // Check if the scan report is available and contains fingerprinting results.
    if let Some(report) = &app.scan_report {
        match &report.fingerprint_results.technologies {
            // Case 1: Scan was successful and technologies were identified.
            Ok(techs) => {
                if techs.is_empty() {
                    tech_lines.push(Line::from("Not identified."));
                } else {
                    for tech in techs {
                        tech_lines.push(Line::from(vec![
                            Span::raw("- "),
                            Span::styled(tech.name.clone(), Style::default().fg(Color::Cyan)),
                        ]));
                    }
                }
            },
            // Case 2: Scan failed, display the error message.
            Err(e) => {
                tech_lines.push(Line::from(
                    Span::styled(format!("Scan failed: {}", e), Style::default().fg(Color::Red))
                ));
            }
        }
    }
    let tech_paragraph = Paragraph::new(tech_lines).block(tech_block);
    frame.render_widget(tech_paragraph, summary_chunks[7]);
}