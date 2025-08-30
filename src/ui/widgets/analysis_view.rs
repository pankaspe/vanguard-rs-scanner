// src/ui/widgets/analysis_view.rs

use crate::app::{App, AppState, SPINNER_CHARS};
use crate::core::knowledge_base;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    text::Line,
};

/// Renders the main analysis report panel.
///
/// This widget is the central part of the UI. It displays a placeholder or a spinner
/// during the `Idle` and `Scanning` states, respectively. Once the scan is `Finished`,
/// it shows a two-pane view: a navigable list of all findings at the top, and a
/// detailed description of the selected finding at the bottom.
///
/// # Arguments
///
/// * `frame` - The mutable frame to render onto.
/// * `app` - A mutable reference to the application's state.
/// * `area` - The `Rect` in which to render this widget.
pub fn render_analysis_view(frame: &mut Frame, app: &mut App, area: Rect) {
    // The main container for the analysis view, with a title and border.
    let main_block = Block::default()
        .borders(Borders::ALL)
        .title("Analysis Report (Navigate with ↑ ↓)");

    // Render a placeholder or spinner if the scan is not yet finished.
    if !matches!(app.state, AppState::Finished) {
        let content = match app.state {
            // Display a simple prompt when waiting for input.
            AppState::Idle => Paragraph::new("Scan results will appear here...")
                .alignment(Alignment::Center),
            // Display an animated spinner while the scan is in progress.
            AppState::Scanning => {
                let spinner_char = SPINNER_CHARS[app.spinner_frame];
                Paragraph::new(
                    Line::from(vec![
                        Span::styled(format!("{} ", spinner_char), Style::default().fg(Color::Cyan)),
                        Span::raw("Scanning... Please wait."),
                    ])
                ).alignment(Alignment::Center)
            },
            // Fallback for any other state (should not be reached).
            _ => Paragraph::new(""),
        };
        frame.render_widget(content.block(main_block), area);
        return;
    }
    
    // If the scan is finished, render the main block and prepare to draw the results inside.
    let inner_area = main_block.inner(area);
    frame.render_widget(main_block, area);

    // Split the available area into two vertical panes:
    // one for the list of findings (top) and one for the details (bottom).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40), // Top 40% for the list.
            Constraint::Min(0),         // Remaining space for details.
        ])
        .split(inner_area);

    // Iterate over all findings from the report to create the list items.
    let items: Vec<ListItem> = app.all_findings.iter().map(|f| {
        // Provide a default detail struct in case a finding code is not in the knowledge base.
        let default_detail = knowledge_base::FindingDetail {
            code: "",
            title: "Unknown Finding",
            category: knowledge_base::FindingCategory::Http,
            severity: crate::core::models::Severity::Info,
            description: "",
            remediation: ""
        };
        let detail = knowledge_base::get_finding_detail(&f.code).unwrap_or(&default_detail);
        
        // Add a prefix to indicate the finding's category.
        let category_prefix = match detail.category {
            knowledge_base::FindingCategory::Dns => "[DNS] ",
            knowledge_base::FindingCategory::Ssl => "[SSL/TLS] ",
            knowledge_base::FindingCategory::Http => "[HTTP] ",
        };

        // Style the title based on the finding's severity.
        let title_style = match detail.severity {
            crate::core::models::Severity::Critical => Style::default().fg(Color::Red),
            crate::core::models::Severity::Warning => Style::default().fg(Color::Yellow),
            crate::core::models::Severity::Info => Style::default().fg(Color::Cyan),
        };
        
        // Assemble the final display line for the list item.
        let line = Line::from(vec![
            Span::styled(category_prefix, Style::default().fg(Color::DarkGray)),
            Span::styled(detail.title, title_style),
        ]);
        
        ListItem::new(line)
    }).collect();

    // Create the list widget with a highlight style for the selected item.
    let findings_list = List::new(items)
        .block(Block::default())
        .highlight_style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD));
    
    // Render the stateful list widget in the top pane.
    frame.render_stateful_widget(findings_list, chunks[0], &mut app.analysis_list_state);
    
    let detail_block = Block::default().borders(Borders::TOP).title("Details");

    // Check if an item is selected in the list.
    if let Some(selected_index) = app.analysis_list_state.selected() {
        // If so, get the corresponding finding and its details.
        if let Some(selected_finding) = app.all_findings.get(selected_index) {
            if let Some(detail) = knowledge_base::get_finding_detail(&selected_finding.code) {
                // Format the description and remediation advice for display.
                let text = vec![
                    Line::from(""),
                    Line::from("WHAT IT IS:".yellow().bold()),
                    Line::from(detail.description),
                    Line::from(""),
                    Line::from("HOW TO FIX:".yellow().bold()),
                    Line::from(detail.remediation),
                ];
                let p = Paragraph::new(text).wrap(Wrap { trim: true }).block(detail_block);
                // Render the details in the bottom pane.
                frame.render_widget(p, chunks[1]);
            }
        }
    } else {
        // If no item is selected, render a placeholder in the details pane.
        render_placeholder_details(frame, app, detail_block, chunks[1]);
    }
}

/// Renders the content of the detail pane when no finding is selected.
///
/// If the scan found no critical or warning issues, it displays a positive
/// confirmation message. Otherwise, it prompts the user to select an item
/// from the list above.
///
/// # Arguments
///
/// * `frame` - The mutable frame to render onto.
/// * `app` - A reference to the application's state.
/// * `block` - The `Block` to wrap the placeholder content in.
/// * `area` - The `Rect` in which to render the placeholder.
fn render_placeholder_details(frame: &mut Frame, app: &App, block: Block, area: Rect) {
    let total_issues = app.summary.critical_issues + app.summary.warning_issues;
    
    let placeholder_text = if total_issues == 0 {
        // If no issues were found, display a positive confirmation message.
        Text::from(vec![
            Line::from(""),
            Line::from("✓ EXCELLENT SECURITY POSTURE".bold().fg(Color::Green)),
            Line::from(""),
            Line::from("No critical or warning issues were found during the scan."),
            Line::from(""),
            Line::from("This is the mark of a meticulous and professional setup. Well done!"),
        ])
    } else {
        // Otherwise, prompt the user to select a finding.
        Text::from("Select an item above to see details.")
    };

    let p = Paragraph::new(placeholder_text).alignment(Alignment::Center).block(block);
    frame.render_widget(p, area);
}