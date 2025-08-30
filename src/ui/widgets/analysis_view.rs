// src/ui/widgets/analysis_view.rs

use crate::app::{App, AppState, SPINNER_CHARS};
use crate::core::knowledge_base;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    text::Line,
};

pub fn render_analysis_view(frame: &mut Frame, app: &mut App, area: Rect) {
    // MODIFICATO: Titolo semplificato.
    let main_block = Block::default()
        .borders(Borders::ALL)
        .title("Analysis Report (Navigate with ↑ ↓)");

    if !matches!(app.state, AppState::Finished) {
        let content = match app.state {
            AppState::Idle => Paragraph::new("Scan results will appear here...")
                .alignment(Alignment::Center),
            AppState::Scanning => {
                let spinner_char = SPINNER_CHARS[app.spinner_frame];
                Paragraph::new(
                    Line::from(vec![
                        Span::styled(format!("{} ", spinner_char), Style::default().fg(Color::Cyan)),
                        Span::raw("Scanning... Please wait."),
                    ])
                ).alignment(Alignment::Center)
            },
            _ => Paragraph::new(""),
        };
        frame.render_widget(content.block(main_block), area);
        return;
    }
    
    let inner_area = main_block.inner(area);
    frame.render_widget(main_block, area);

    // MODIFICATO: Layout verticale semplificato, senza spazio per i tab.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Min(0),
        ])
        .split(inner_area);

    // RIMOSSA: Logica per renderizzare i `Tabs`.

    // MODIFICATO: La lista ora usa `app.all_findings`.
    let items: Vec<ListItem> = app.all_findings.iter().map(|f| {
        let default_detail = knowledge_base::FindingDetail {
            code: "",
            title: "Unknown Finding",
            category: knowledge_base::FindingCategory::Http,
            severity: crate::core::models::Severity::Info,
            description: "",
            remediation: ""
        };
        let detail = knowledge_base::get_finding_detail(&f.code).unwrap_or(&default_detail);
        
        let category_prefix = match detail.category {
            knowledge_base::FindingCategory::Dns => "[DNS] ",
            knowledge_base::FindingCategory::Ssl => "[SSL/TLS] ",
            knowledge_base::FindingCategory::Http => "[HTTP] ",
        };

        let title_style = match detail.severity {
            crate::core::models::Severity::Critical => Style::default().fg(Color::Red),
            crate::core::models::Severity::Warning => Style::default().fg(Color::Yellow),
            crate::core::models::Severity::Info => Style::default().fg(Color::Cyan),
        };
        
        let line = Line::from(vec![
            Span::styled(category_prefix, Style::default().fg(Color::DarkGray)),
            Span::styled(detail.title, title_style),
        ]);
        
        ListItem::new(line)
    }).collect();

    let findings_list = List::new(items)
        .block(Block::default())
        .highlight_style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD));
    
    frame.render_stateful_widget(findings_list, chunks[0], &mut app.analysis_list_state);
    
    let detail_block = Block::default().borders(Borders::TOP).title("Details");
    if let Some(selected_index) = app.analysis_list_state.selected() {
        if let Some(selected_finding) = app.all_findings.get(selected_index) {
            if let Some(detail) = knowledge_base::get_finding_detail(&selected_finding.code) {
                let text = vec![
                    Line::from(""),
                    Line::from("WHAT IT IS:".yellow().bold()),
                    Line::from(detail.description),
                    Line::from(""),
                    Line::from("HOW TO FIX:".yellow().bold()),
                    Line::from(detail.remediation),
                ];
                let p = Paragraph::new(text).wrap(Wrap { trim: true }).block(detail_block);
                frame.render_widget(p, chunks[1]);
            }
        }
    } else {
        render_placeholder_details(frame, app, detail_block, chunks[1]);
    }
}

fn render_placeholder_details(frame: &mut Frame, app: &App, block: Block, area: Rect) {
    let total_issues = app.summary.critical_issues + app.summary.warning_issues;
    
    let placeholder_text = if total_issues == 0 { // Semplificato
        Text::from(vec![
            Line::from(""),
            Line::from("✓ EXCELLENT SECURITY POSTURE".bold().fg(Color::Green)),
            Line::from(""),
            Line::from("No critical or warning issues were found during the scan."),
            Line::from(""),
            Line::from("This is the mark of a meticulous and professional setup. Well done!"),
        ])
    } else {
        Text::from("Select an item above to see details.")
    };

    let p = Paragraph::new(placeholder_text).alignment(Alignment::Center).block(block);
    frame.render_widget(p, area);
}