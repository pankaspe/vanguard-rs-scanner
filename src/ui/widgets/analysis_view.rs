// src/ui/widgets/analysis_view.rs

use crate::app::{App, AppState, AnalysisTab, SPINNER_CHARS};
use crate::core::knowledge_base;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Wrap},
    text::Line,
};
use strum::IntoEnumIterator;

pub fn render_analysis_view(frame: &mut Frame, app: &mut App, area: Rect) {
    let main_block = Block::default().borders(Borders::ALL).title("Analysis Report (Navigate with ← → ↑ ↓)");

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

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Percentage(40),
            Constraint::Min(0),
        ])
        .split(inner_area);

    let titles = AnalysisTab::iter().map(|t| format!(" {} ", t));
    let tabs = Tabs::new(titles)
        .select(app.active_analysis_tab as usize)
        .style(Style::default().fg(Color::Gray))
        .highlight_style(Style::default().fg(Color::Yellow).bold());
    frame.render_widget(tabs, chunks[0]);

    let items: Vec<ListItem> = app.filtered_findings.iter().map(|f| {
        let default_detail = knowledge_base::FindingDetail { code: "", title: "Unknown Finding", severity: crate::core::models::Severity::Info, description: "", remediation: "" };
        let detail = knowledge_base::get_finding_detail(&f.code).unwrap_or(&default_detail);
        
        // FIX: Removed the unreachable `_` pattern.
        let style = match detail.severity {
            crate::core::models::Severity::Critical => Style::default().fg(Color::Red),
            crate::core::models::Severity::Warning => Style::default().fg(Color::Yellow),
            crate::core::models::Severity::Info => Style::default().fg(Color::Cyan),
        };
        ListItem::new(Line::from(Span::styled(detail.title, style)))
    }).collect();

    let findings_list = List::new(items)
        .block(Block::default().borders(Borders::TOP))
        .highlight_style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD));
    frame.render_stateful_widget(findings_list, chunks[1], &mut app.analysis_list_state);
    
    let detail_block = Block::default().borders(Borders::TOP).title("Details");
    if let Some(selected_index) = app.analysis_list_state.selected() {
        if let Some(selected_finding) = app.filtered_findings.get(selected_index) {
            // FIX: Changed `.` to `::` to correctly call the function from the module.
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
                frame.render_widget(p, chunks[2]);
            }
        }
    } else {
        // --- NUOVA LOGICA PER I COMPLIMENTI ---
        // Controlliamo se ci sono problemi IN TOTALE.
        let total_issues = app.summary.critical_issues + app.summary.warning_issues;
        
        let placeholder_text = if total_issues == 0 && app.active_analysis_tab == AnalysisTab::All {
            // Se non ci sono problemi di sorta, mostriamo il messaggio di complimenti.
            Text::from(vec![
                Line::from(""),
                Line::from("✓ EXCELLENT SECURITY POSTURE".bold().fg(Color::Green)),
                Line::from(""),
                Line::from("No critical or warning issues were found during the scan."),
                Line::from(""),
                Line::from("This is the mark of a meticulous and professional setup. Well done!"),
            ])
        } else {
            // Altrimenti, mostriamo il messaggio standard "nessun problema in questa categoria".
            Text::from("No issues in this category.")
        };

        let p = Paragraph::new(placeholder_text).alignment(Alignment::Center).block(detail_block);
        frame.render_widget(p, chunks[2]);
    }
}