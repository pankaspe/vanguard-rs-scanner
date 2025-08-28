// src/app.rs

use crate::core::models::ScanReport;
use ratatui::widgets::ScrollbarState; // <-- 1. IMPORTA LO STATO DELLO SCROLL

pub enum AppState {
    Idle,
    Scanning,
    Finished,
}

#[derive(Debug, Default)]
pub struct ScanSummary {
    pub score: u8,
    pub critical_issues: usize,
    pub warning_issues: usize,
}

pub struct App {
    pub should_quit: bool,
    pub state: AppState,
    pub input: String,
    pub scan_report: Option<ScanReport>,
    pub summary: ScanSummary,
    pub scroll_offset: usize, // Usiamo usize per coerenza con ScrollbarState
    pub report_scroll_state: ScrollbarState, // <-- 2. AGGIUNGI LO STATO
}

impl App {
    pub fn new() -> Self {
        Self {
            should_quit: false,
            state: AppState::Idle,
            input: String::new(),
            scan_report: None,
            summary: ScanSummary::default(),
            scroll_offset: 0,
            report_scroll_state: ScrollbarState::default(), // <-- 3. INIZIALIZZA
        }
    }

    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
        self.report_scroll_state = self.report_scroll_state.position(self.scroll_offset);
    }

    pub fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_add(1);
        self.report_scroll_state = self.report_scroll_state.position(self.scroll_offset);
    }

    pub fn update_summary(&mut self) {
        if let Some(report) = &self.scan_report {
            let all_analyses: Vec<_> = report.dns_results.iter().flat_map(|r| &r.analysis)
                .chain(report.ssl_results.iter().flat_map(|r| &r.analysis))
                .chain(report.headers_results.iter().flat_map(|r| &r.analysis))
                .collect();

            let criticals = all_analyses.iter().filter(|a| matches!(a.severity, crate::core::models::Severity::Critical)).count();
            let warnings = all_analyses.iter().filter(|a| matches!(a.severity, crate::core::models::Severity::Warning)).count();

            let score = 100_i16.saturating_sub((criticals * 15) as i16).saturating_sub((warnings * 5) as i16);
            
            self.summary = ScanSummary {
                score: if score < 0 { 0 } else { score as u8 },
                critical_issues: criticals,
                warning_issues: warnings,
            };
        }
    }

    pub fn on_tick(&mut self) {}

    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    pub fn reset(&mut self) {
        self.state = AppState::Idle;
        self.input = String::new();
        self.scan_report = None;
        self.summary = ScanSummary::default();
        self.scroll_offset = 0;
        self.report_scroll_state = ScrollbarState::default(); // <-- 4. RESETTA ANCHE LO STATO
    }
}