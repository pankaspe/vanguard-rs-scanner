// src/app.rs

use crate::core::models::{AnalysisFinding, ScanReport, Severity};
use crate::logging;
use ratatui::widgets::ScrollbarState;
use std::fs;
// RIMOSSO: `strum` non è più necessario perché abbiamo eliminato l'enum `AnalysisTab`.

pub const SPINNER_CHARS: [char; 4] = ['|', '/', '-', '\\'];

// RIMOSSO: L'enum `AnalysisTab` è stato completamente eliminato per semplificare la UI.

pub enum ExportStatus {
    Idle,
    Success(String),
    Error(String),
}

#[derive(Default, PartialEq, Eq)]
pub enum AppState {
    #[default]
    Disclaimer,
    Idle,
    Scanning,
    Finished,
}

#[derive(Debug, Default)]
pub struct ScanSummary {
    pub score: u8,
    pub critical_issues: usize,
    pub warning_issues: usize,
    pub dns_check_passed: bool,
    pub ssl_check_passed: bool,
    pub headers_check_passed: bool,
}

pub struct App {
    pub should_quit: bool,
    pub state: AppState,
    pub input: String,
    pub scan_report: Option<ScanReport>,
    pub summary: ScanSummary,
    pub export_status: ExportStatus,
    pub spinner_frame: usize,
    // MODIFICATO: `filtered_findings` è ora `all_findings` per chiarezza.
    pub all_findings: Vec<AnalysisFinding>,
    pub analysis_list_state: ratatui::widgets::ListState,
    pub displayed_score: u8,
    pub show_logs: bool,
    pub log_content: Vec<String>,
    pub log_horizontal_scroll_state: ScrollbarState,
    pub log_horizontal_scroll: usize,
    // RIMOSSO: `active_analysis_tab` non serve più.
}

impl App {
    pub fn new() -> Self {
        Self {  
            should_quit: false,
            state: AppState::default(),
            input: String::new(),
            scan_report: None,
            summary: ScanSummary::default(),
            export_status: ExportStatus::Idle,
            spinner_frame: 0,
            all_findings: Vec::new(),
            analysis_list_state: ratatui::widgets::ListState::default(),
            displayed_score: 0,
            show_logs: false,
            log_content: Vec::new(),
            log_horizontal_scroll_state: ScrollbarState::default(),
            log_horizontal_scroll: 0,
        }
    }
    
    // RIMOSSO: I metodi `next_analysis_tab` e `previous_analysis_tab` non sono più necessari.
    
    pub fn select_next_finding(&mut self) {
        if self.all_findings.is_empty() { return; }
        let i = match self.analysis_list_state.selected() {
            Some(i) => (i + 1) % self.all_findings.len(),
            None => 0,
        };
        self.analysis_list_state.select(Some(i));
    }

    pub fn select_previous_finding(&mut self) {
        if self.all_findings.is_empty() { return; }
        let i = match self.analysis_list_state.selected() {
            Some(i) => if i == 0 { self.all_findings.len() - 1 } else { i - 1 },
            None => 0,
        };
        self.analysis_list_state.select(Some(i));
    }
    
    // MODIFICATO: Questo metodo ora raccoglie semplicemente tutti i risultati senza filtrare.
    pub fn update_findings(&mut self) {
        if let Some(report) = &self.scan_report {
            self.all_findings = report.dns_results.analysis.iter()
                .chain(report.ssl_results.analysis.iter())
                .chain(report.headers_results.analysis.iter())
                .cloned()
                .collect();

            if !self.all_findings.is_empty() {
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
        self.all_findings = Vec::new();
        self.analysis_list_state.select(None);
        self.log_horizontal_scroll = 0;
        self.log_horizontal_scroll_state = ScrollbarState::default();
    }
    
    pub fn update_summary(&mut self) {
        if let Some(report) = &self.scan_report {
            let all_analyses: Vec<_> = report.dns_results.analysis.iter()
                .chain(report.ssl_results.analysis.iter())
                .chain(report.headers_results.analysis.iter())
                .collect();
            
            let criticals = all_analyses.iter().filter(|a| matches!(a.severity, Severity::Critical)).count();
            let warnings = all_analyses.iter().filter(|a| matches!(a.severity, Severity::Warning)).count();
            let score = 100_i16.saturating_sub((criticals * 15) as i16).saturating_sub((warnings * 5) as i16);
            
            let dns_check_passed = report.dns_results.spf.is_ok() && report.dns_results.dmarc.is_ok() && report.dns_results.dkim.is_ok() && report.dns_results.caa.is_ok();
            let ssl_check_passed = report.ssl_results.scan.is_ok();
            let headers_check_passed = report.headers_results.error.is_none() && report.headers_results.hsts.is_ok() && report.headers_results.csp.is_ok() && report.headers_results.x_frame_options.is_ok() && report.headers_results.x_content_type_options.is_ok();

            self.summary = ScanSummary {
                score: if score < 0 { 0 } else { score as u8 },
                critical_issues: criticals,
                warning_issues: warnings,
                dns_check_passed,
                ssl_check_passed,
                headers_check_passed,
            };
            
            self.displayed_score = 0;
        }
    }

    pub fn refresh_logs(&mut self) {
        let log_path = logging::get_data_dir().join(logging::LOG_FILE.clone());
        match fs::read_to_string(log_path) {
            Ok(content) => {
                self.log_content = content.lines().rev().take(200).map(String::from).collect();
            }
            Err(_) => {
                self.log_content = vec!["Could not read log file.".to_string()];
            }
        }
    }
}