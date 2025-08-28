// src/ui/widgets/results.rs

use crate::app::{App, AppState, SPINNER_CHARS};
use crate::core::models::{AnalysisResult, HeaderInfo, ScanReport, Severity};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, Wrap},
    text::Line,
};

pub fn render_results(frame: &mut Frame, app: &mut App, area: Rect) {
    let results_block = Block::default().borders(Borders::ALL).title("Detailed Report (Scroll with ↑/↓)");

    match app.state {
        AppState::Idle => {
            let instructions = Paragraph::new("Enter a domain and press Enter to start...")
                .block(results_block)
                .wrap(Wrap { trim: true })
                .alignment(Alignment::Center);
            frame.render_widget(instructions, area);
        }
        AppState::Scanning => {
            // 2. COSTRUIAMO IL TESTO ANIMATO
            let spinner_char = SPINNER_CHARS[app.spinner_frame];
            let scanning_text = Paragraph::new(
                Line::from(vec![
                    Span::styled(format!("{} ", spinner_char), Style::default().fg(Color::Cyan)),
                    Span::raw("Scanning... Please wait."),
                ])
            )
            .block(results_block)
            .alignment(Alignment::Center);
            frame.render_widget(scanning_text, area);
        }
        AppState::Finished => {
            if let Some(report) = &app.scan_report {
                let results_text = build_results_text(report);
                
                let line_count = results_text.lines.len();
                app.report_scroll_state = app.report_scroll_state.content_length(line_count);

                let results_paragraph = Paragraph::new(results_text)
                    .block(results_block)
                    .wrap(Wrap { trim: true })
                    .scroll((app.scroll_offset as u16, 0)); 
                
                frame.render_widget(results_paragraph, area);

                frame.render_stateful_widget(
                    Scrollbar::new(ScrollbarOrientation::VerticalRight)
                        .begin_symbol(Some("↑"))
                        .end_symbol(Some("↓")),
                    area,
                    &mut app.report_scroll_state,
                );
            }
        }
    }
}

fn build_results_text(report: &ScanReport) -> Text {
    let mut lines = Vec::new();

    // FIX: Removed `if let Some(dns) = ...` as `dns_results` is no longer an Option.
    let dns = &report.dns_results;
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
    lines.push(Line::from(""));

    let ssl = &report.ssl_results;
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
    lines.push(Line::from(""));

    let headers = &report.headers_results;
    lines.push(Line::from(Span::styled("HTTP Security Headers:", Style::default().bold().underlined())));
    if let Some(err) = &headers.error {
        lines.push(Line::from(Span::styled(format!("Error: {}", err), Style::default().fg(Color::Red))));
    } else {
        let mut render_header = |name: &str, info: &Option<HeaderInfo>| {
            if let Some(header_info) = info {
                let (style, status) = if header_info.found { (Style::default().fg(Color::Green), "Present") } else { (Style::default().fg(Color::Yellow), "Missing") };
                lines.push(Line::from(vec![Span::raw(format!("{}: ", name)), Span::styled(status, style)]));
            }
        };
        render_header("Strict-Transport-Security", &headers.hsts);
        render_header("Content-Security-Policy", &headers.csp);
        render_header("X-Frame-Options", &headers.x_frame_options);
        render_header("X-Content-Type-Options", &headers.x_content_type_options);
    }
    lines.push(Line::from(""));

    let fingerprint = &report.fingerprint_results;
    lines.push(Line::from(Span::styled("Technology Fingerprint:", Style::default().bold().underlined())));
    if let Some(err) = &fingerprint.error {
        lines.push(Line::from(Span::styled(format!("Error: {}", err), Style::default().fg(Color::Red))));
    } else if fingerprint.technologies.is_empty() {
        lines.push(Line::from("  No specific technologies identified."));
    } else {
        for tech in &fingerprint.technologies {
            lines.push(Line::from(vec![
                Span::styled(format!("- {}", tech.name), Style::default().fg(Color::Cyan)),
                Span::raw(format!(" ({})", tech.category)),
            ]));
        }
    }
    lines.push(Line::from(""));

    lines.push(Line::from(Span::styled("Analysis:", Style::default().bold().underlined())));
    let all_analyses: Vec<_> = report.dns_results.analysis.iter()
        .chain(report.ssl_results.analysis.iter())
        .chain(report.headers_results.analysis.iter())
        .collect();

    if all_analyses.is_empty() {
        lines.push(Line::from(Span::styled("  ✓ No security issues found.", Style::default().fg(Color::Green))));
    } else {
        for finding in all_analyses {
            lines.push(format_analysis_result(finding));
        }
    }

    Text::from(lines)
}

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
        "HEADERS_REQUEST_FAILED" => "The HTTP request to fetch headers failed. The server might be down.",
        "HEADERS_HSTS_MISSING" => "HSTS header is missing. This weakens protection against protocol downgrade attacks.",
        "HEADERS_CSP_MISSING" => "CSP header is missing. This increases the risk of XSS attacks.",
        "HEADERS_X_FRAME_OPTIONS_MISSING" => "X-Frame-Options header is missing, making the site vulnerable to clickjacking.",
        "HEADERS_X_CONTENT_TYPE_OPTIONS_MISSING" => "X-Content-Type-Options header is missing. (Best Practice)",
        _ => "Unknown finding."
    };

    Line::from(vec![
        Span::styled(format!("[{}]", prefix), style),
        Span::raw(format!(" {}", message)),
    ])
}