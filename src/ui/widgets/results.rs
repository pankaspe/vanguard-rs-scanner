// src/ui/widgets/results.rs

use crate::app::{App, AppState};
use crate::core::models::{AnalysisResult, ScanReport, Severity};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};

/// Renders the main content area based on the application state.
pub fn render_results(frame: &mut Frame, app: &App, area: Rect) {
    let results_block = Block::default().borders(Borders::ALL).title("Scan Results");

    match app.state {
        AppState::Idle => {
            let instructions = Paragraph::new(
                "Enter a domain and press Enter to start the scan.\nPress 'q' to quit.\nClick anywhere to start a new scan.",
            )
            .block(results_block)
            .wrap(Wrap { trim: true });
            frame.render_widget(instructions, area);
        }
        AppState::Scanning => {
            let scanning_text = Paragraph::new("Scanning... Please wait.")
                .block(results_block)
                .style(Style::default().fg(Color::Cyan));
            frame.render_widget(scanning_text, area);
        }
        AppState::Finished => {
            if let Some(report) = &app.scan_report {
                let results_text = build_results_text(report);
                let results_paragraph = Paragraph::new(results_text)
                    .block(results_block)
                    .wrap(Wrap { trim: true });
                frame.render_widget(results_paragraph, area);
            }
        }
    }
}

/// A helper function to transform a full ScanReport into a colorful, styled Text widget.
fn build_results_text(report: &ScanReport) -> Text {
    let mut lines = Vec::new();

    // --- DNS Section ---
    if let Some(dns) = &report.dns_results {
        lines.push(Line::from(Span::styled("DNS Scan Results:", Style::default().bold().underlined())));
        if let Some(spf) = &dns.spf {
            let (style, status) = if spf.found { (Style::default().fg(Color::Green), "Found") } else { (Style::default().fg(Color::Yellow), "Not Found") };
            lines.push(Line::from(vec![Span::raw("SPF Record: "), Span::styled(status, style)]));
            if let Some(record) = &spf.record { lines.push(Line::from(format!("  Record: {}", record))); }
        }
        if let Some(dmarc) = &dns.dmarc {
            let (style, status) = if dmarc.found { (Style::default().fg(Color::Green), "Found") } else { (Style::default().fg(Color::Red), "Not Found") };
            lines.push(Line::from(vec![Span::raw("DMARC Record: "), Span::styled(status, style)]));
            if let Some(record) = &dmarc.record { lines.push(Line::from(format!("  Record: {}", record))); }
        }
        lines.push(Line::from("")); // Spacer
    }

    // --- SSL/TLS Section ---
    if let Some(ssl) = &report.ssl_results {
        lines.push(Line::from(Span::styled("SSL/TLS Scan Results:", Style::default().bold().underlined())));
        if ssl.certificate_found {
            let (style, status) = if ssl.is_valid { (Style::default().fg(Color::Green), "Valid") } else { (Style::default().fg(Color::Red), "Invalid/Expired") };
            lines.push(Line::from(vec![Span::raw("Certificate Status: "), Span::styled(status, style)]));
            if let Some(info) = &ssl.certificate_info {
                lines.push(Line::from(format!("  Subject: {}", info.subject_name)));
                lines.push(Line::from(format!("  Issuer:  {}", info.issuer_name)));
                if let Some(days) = info.days_until_expiry {
                    let expiry_style = if days > 30 { Color::Green } else if days > 0 { Color::Yellow } else { Color::Red };
                    lines.push(Line::from(Span::styled(format!("  Expires in: {} days", days), Style::default().fg(expiry_style))));
                }
            }
        } else if let Some(err) = &ssl.error {
            lines.push(Line::from(Span::styled(format!("Error: {}", err), Style::default().fg(Color::Red))));
        }
        lines.push(Line::from("")); // Spacer
    }
    
    // --- Combined Analysis Section ---
    lines.push(Line::from(Span::styled("Analysis:", Style::default().bold().underlined())));
    let all_analyses: Vec<_> = report.dns_results.iter().flat_map(|r| &r.analysis)
        .chain(report.ssl_results.iter().flat_map(|r| &r.analysis))
        .collect();

    if all_analyses.is_empty() {
        lines.push(Line::from(Span::styled("  ✓ No issues found.", Style::default().fg(Color::Green))));
    } else {
        for finding in all_analyses {
            lines.push(format_analysis_result(finding));
        }
    }

    Text::from(lines)
}

/// Formats a single analysis finding with appropriate color based on severity.
fn format_analysis_result(result: &AnalysisResult) -> Line {
    let (prefix, style) = match result.severity {
        Severity::Critical => ("Critical", Style::default().fg(Color::Red).bold()),
        Severity::Warning => ("Warning", Style::default().fg(Color::Yellow)),
        Severity::Info => ("Info", Style::default().fg(Color::Cyan)),
    };

    let message = match result.code.as_str() {
        "DNS_DMARC_MISSING" => "DMARC record is missing. This is critical for email spoofing protection.",
        "DNS_DMARC_POLICY_NONE" => "DMARC policy is 'none'. It should be 'quarantine' or 'reject' for protection.",
        "DNS_SPF_MISSING" => "SPF record is missing. This can lead to email delivery issues.",
        "SSL_HANDSHAKE_FAILED" => "Could not establish a secure TLS connection with the server.",
        "SSL_EXPIRED" => "The SSL certificate is expired or not yet valid.",
        "SSL_EXPIRING_SOON" => "The SSL certificate will expire in less than 30 days.",
        _ => "Unknown finding."
    };

    Line::from(vec![
        Span::styled(format!("[{}]", prefix), style),
        Span::raw(format!(" {}", message)),
    ])
}