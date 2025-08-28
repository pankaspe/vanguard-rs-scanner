// src/app.rs

use crate::core::models::{AnalysisResult, ScanReport};
use strum::{Display, EnumIter, FromRepr};

pub const SPINNER_CHARS: [char; 4] = ['|', '/', '-', '\\'];

#[derive(Debug, Default, Clone, Copy, Display, FromRepr, EnumIter, PartialEq, Eq)]
pub enum AnalysisTab {
    #[default]
    All,
    Critical,
    Warning,
    Info,
}

pub enum ExportStatus {
    Idle,
    Success(String),
    Error(String),
}

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
    pub export_status: ExportStatus,
    pub spinner_frame: usize,
    pub active_analysis_tab: AnalysisTab,
    pub filtered_findings: Vec<AnalysisResult>,
    pub analysis_list_state: ratatui::widgets::ListState,
    pub displayed_score: u8,
}

impl App {
    pub fn new() -> Self {
        Self {  
            should_quit: false,
            state: AppState::Idle,
            input: String::new(),
            scan_report: None,
            summary: ScanSummary::default(),
            export_status: ExportStatus::Idle,
            spinner_frame: 0,
            active_analysis_tab: AnalysisTab::default(),
            filtered_findings: Vec::new(),
            analysis_list_state: ratatui::widgets::ListState::default(),
            displayed_score: 0,
        }
    }
    
    pub fn next_analysis_tab(&mut self) {
        let current_index = self.active_analysis_tab as usize;
        let next_index = current_index.saturating_add(1);
        self.active_analysis_tab = AnalysisTab::from_repr(next_index).unwrap_or(self.active_analysis_tab);
        self.update_filtered_findings();
    }

    pub fn previous_analysis_tab(&mut self) {
        let current_index = self.active_analysis_tab as usize;
        let previous_index = current_index.saturating_sub(1);
        self.active_analysis_tab = AnalysisTab::from_repr(previous_index).unwrap_or(self.active_analysis_tab);
        self.update_filtered_findings();
    }
    
    pub fn select_next_finding(&mut self) {
        if self.filtered_findings.is_empty() { return; }
        let i = match self.analysis_list_state.selected() {
            Some(i) => (i + 1) % self.filtered_findings.len(),
            None => 0,
        };
        self.analysis_list_state.select(Some(i));
    }

    pub fn select_previous_finding(&mut self) {
        if self.filtered_findings.is_empty() { return; }
        let i = match self.analysis_list_state.selected() {
            Some(i) => if i == 0 { self.filtered_findings.len() - 1 } else { i - 1 },
            None => 0,
        };
        self.analysis_list_state.select(Some(i));
    }
    
    pub fn update_filtered_findings(&mut self) {
        if let Some(report) = &self.scan_report {
            let all_findings: Vec<_> = report.dns_results.analysis.iter()
                .chain(report.ssl_results.analysis.iter())
                .chain(report.headers_results.analysis.iter())
                .cloned().collect();

            self.filtered_findings = if self.active_analysis_tab == AnalysisTab::All {
                all_findings
            } else {
                all_findings.into_iter().filter(|f| {
                    let severity_str = format!("{:?}", f.severity);
                    let tab_str = format!("{:?}", self.active_analysis_tab);
                    severity_str.eq_ignore_ascii_case(&tab_str)
                }).collect()
            };

            // SE LA LISTA NON È VUOTA, SELEZIONA IL PRIMO ELEMENTO
            if !self.filtered_findings.is_empty() {
                self.analysis_list_state.select(Some(0));
            } else {
                self.analysis_list_state.select(None);
            }
        }
    }

    pub fn on_tick(&mut self) {
        if matches!(self.state, AppState::Scanning) {
            self.spinner_frame = (self.spinner_frame + 1) % SPINNER_CHARS.len();
        }

        if matches!(self.state, AppState::Finished) {
            if self.displayed_score < self.summary.score {
                // Incrementa di 2 per un'animazione più veloce
                self.displayed_score = (self.displayed_score + 2).min(self.summary.score);
            }
        }
    }

    pub fn quit(&mut self) { self.should_quit = true; }

    pub fn reset(&mut self) {
        self.state = AppState::Idle;
        self.input = String::new();
        self.scan_report = None;
        self.summary = ScanSummary::default();
        self.export_status = ExportStatus::Idle;
        self.spinner_frame = 0;
        self.active_analysis_tab = AnalysisTab::default();
        self.filtered_findings = Vec::new();
        self.analysis_list_state.select(None);
    }
    
    pub fn update_summary(&mut self) {
        if let Some(report) = &self.scan_report {
            let all_analyses: Vec<_> = report.dns_results.analysis.iter()
                .chain(report.ssl_results.analysis.iter())
                .chain(report.headers_results.analysis.iter())
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
}