// src/ui/widgets/results.rs
// (Questo file contiene tutta la logica di rendering dei risultati che avevamo prima)
use ratatui::{prelude::*, widgets::{Block, Borders, Paragraph, Wrap}};
use crate::app::{App, AppState};
use crate::core::models::{AnalysisResult, DnsResults, Severity};

/// Renders the main content area based on the application state.
pub fn render_results(frame: &mut Frame, app: &App, area: Rect) {
    let results_block = Block::default().borders(Borders::ALL).title("Scan Results");
    
    match app.state {
        AppState::Idle => {
            let instructions = Paragraph::new("Enter a domain and press Enter to start the scan.\nPress 'q' to quit.\nClick anywhere to start a new scan.")
                .block(results_block.clone())
                .wrap(Wrap { trim: true });
            frame.render_widget(instructions, area);
        }
        AppState::Scanning => {
            let scanning_text = Paragraph::new("Scanning... Please wait.")
                .block(results_block.clone())
                .style(Style::default().fg(Color::Cyan));
            frame.render_widget(scanning_text, area);
        }
        AppState::Finished => {
            if let Some(dns_results) = &app.dns_results {
                let results_text = build_results_text(dns_results);
                let results_paragraph = Paragraph::new(results_text)
                    .block(results_block.clone())
                    .wrap(Wrap { trim: true });
                frame.render_widget(results_paragraph, area);
            }
        }
    }
}

/// A helper function to transform DnsResults into a colorful, styled Text widget.
fn build_results_text(results: &DnsResults) -> Text {
    let mut lines = Vec::new();

    lines.push(Line::from(Span::styled("DNS Scan Results:", Style::default().bold().underlined())));

    // --- SPF Record ---
    if let Some(spf) = &results.spf {
        let (style, status) = if spf.found {
            (Style::default().fg(Color::Green), "Found")
        } else {
            (Style::default().fg(Color::Yellow), "Not Found")
        };
        lines.push(Line::from(vec![
            Span::raw("SPF Record: "),
            Span::styled(status, style),
        ]));
        if let Some(record) = &spf.record {
            lines.push(Line::from(Span::raw(format!("  Record: {}", record))));
        }
    }

    // --- DMARC Record ---
    if let Some(dmarc) = &results.dmarc {
        let (style, status) = if dmarc.found {
            (Style::default().fg(Color::Green), "Found")
        } else {
            (Style::default().fg(Color::Red), "Not Found") // DMARC missing is more critical
        };
        lines.push(Line::from(vec![
            Span::raw("DMARC Record: "),
            Span::styled(status, style),
        ]));
        if let Some(record) = &dmarc.record {
            lines.push(Line::from(Span::raw(format!("  Record: {}", record))));
        }
    }
    
    lines.push(Line::from("")); // Spacer

    // --- Analysis Section ---
    lines.push(Line::from(Span::styled("Analysis:", Style::default().bold().underlined())));
    if results.analysis.is_empty() {
        lines.push(Line::from(Span::styled("  ✓ No issues found.", Style::default().fg(Color::Green))));
    } else {
        for finding in &results.analysis {
            lines.push(format_analysis_result(finding));
        }
    }

    Text::from(lines)
}

fn format_analysis_result(result: &AnalysisResult) -> Line {
    let (prefix, style) = match result.severity {
        Severity::Critical => ("Critial", Style::default().fg(Color::Red).bold()),
        Severity::Warning => ("Warning", Style::default().fg(Color::Yellow)),
        Severity::Info => ("Info", Style::default().fg(Color::Cyan)),
    };

    // Here you would match on result.code to provide human-readable messages.
    // For now, we'll just display the code.
    let message = match result.code.as_str() {
        "DNS_DMARC_MISSING" => "DMARC record is missing. This is critical for email spoofing protection.",
        "DNS_DMARC_POLICY_NONE" => "DMARC policy is 'none'. It should be 'quarantine' or 'reject' for protection.",
        "DNS_SPF_MISSING" => "SPF record is missing. This can lead to email delivery issues.",
        _ => "Unknown finding."
    };

    Line::from(vec![
        Span::styled(format!("[{}]", prefix), style),
        Span::raw(format!(" {}", message)),
    ])
}
