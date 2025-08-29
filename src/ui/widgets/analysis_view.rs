// src/ui/widgets/analysis_view.rs

use crate::app::{App, AppState, AnalysisTab, SPINNER_CHARS};
use crate::core::knowledge_base;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Wrap},
    text::Line,
};
use strum::IntoEnumIterator;

/// Renders the main analysis view, which includes tabs for filtering,
/// a list of findings, and a details panel for the selected finding.
pub fn render_analysis_view(frame: &mut Frame, app: &mut App, area: Rect) {
    // Create the main container block for the entire analysis section.
    let main_block = Block::default()
        .borders(Borders::ALL)
        .title("Analysis Report (Navigate with ← → ↑ ↓)");

    // --- Handle non-finished states (Idle, Scanning) ---
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
    
    // Draw the main block and get the inner area for content.
    let inner_area = main_block.inner(area);
    frame.render_widget(main_block, area);

    // Define the layout for the analysis view: Tabs, Findings List, Details.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),      // For the tabs
            Constraint::Percentage(40), // For the list of findings
            Constraint::Min(0),         // For the details of the selected finding
        ])
        .split(inner_area);

    // --- Render Tabs ---
    let titles = AnalysisTab::iter().map(|t| format!(" {} ", t));
    let tabs = Tabs::new(titles)
        .select(app.active_analysis_tab as usize)
        .style(Style::default().fg(Color::Gray))
        .highlight_style(Style::default().fg(Color::Yellow).bold());
    frame.render_widget(tabs, chunks[0]);

    // --- NEW: Simplified List Generation with Category Prefix ---
    // This approach is simpler and avoids state management issues with scrolling.
    let items: Vec<ListItem> = app.filtered_findings.iter().map(|f| {
        // Default struct in case a finding is not in the knowledge base.
        let default_detail = knowledge_base::FindingDetail {
            code: "",
            title: "Unknown Finding",
            category: knowledge_base::FindingCategory::Http, // A default category
            severity: crate::core::models::Severity::Info,
            description: "",
            remediation: ""
        };
        let detail = knowledge_base::get_finding_detail(&f.code).unwrap_or(&default_detail);
        
        // Define a short, readable prefix for the category.
        let category_prefix = match detail.category {
            knowledge_base::FindingCategory::Dns => "[DNS] ",
            knowledge_base::FindingCategory::Ssl => "[SSL/TLS] ",
            knowledge_base::FindingCategory::Http => "[HTTP] ",
        };

        // Style for the finding's title based on its severity.
        let title_style = match detail.severity {
            crate::core::models::Severity::Critical => Style::default().fg(Color::Red),
            crate::core::models::Severity::Warning => Style::default().fg(Color::Yellow),
            crate::core::models::Severity::Info => Style::default().fg(Color::Cyan),
        };
        
        // Create a Line with multiple styled parts (Spans).
        // This allows us to have different colors for the prefix and the title.
        let line = Line::from(vec![
            Span::styled(category_prefix, Style::default().fg(Color::DarkGray)),
            Span::styled(detail.title, title_style),
        ]);
        
        ListItem::new(line)
    }).collect();

    // The number of `items` now perfectly matches the number of `filtered_findings`,
    // which fixes the scrolling issue.
    let findings_list = List::new(items)
        .block(Block::default().borders(Borders::TOP))
        .highlight_style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD));
    frame.render_stateful_widget(findings_list, chunks[1], &mut app.analysis_list_state);
    
    // --- Render the Details Panel (This logic remains the same) ---
    let detail_block = Block::default().borders(Borders::TOP).title("Details");
    if let Some(selected_index) = app.analysis_list_state.selected() {
        // We can now safely use the selected_index to get the finding from the original list.
        if let Some(selected_finding) = app.filtered_findings.get(selected_index) {
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
        // Render a placeholder if nothing is selected.
        render_placeholder_details(frame, app, detail_block, chunks[2]);
    }
}


/// Helper function to render the placeholder text in the details panel.
/// This is shown when no finding is selected or when the scan was perfect.
fn render_placeholder_details(frame: &mut Frame, app: &App, block: Block, area: Rect) {
    let total_issues = app.summary.critical_issues + app.summary.warning_issues;
    
    let placeholder_text = if total_issues == 0 && app.active_analysis_tab == AnalysisTab::All {
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