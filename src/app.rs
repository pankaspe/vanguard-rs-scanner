// src/app.rs

// --- MODIFIED: Imported Severity for use in filtering ---
use crate::core::models::{AnalysisFinding, ScanReport, Severity};
use strum::{Display, EnumIter, FromRepr};

pub const SPINNER_CHARS: [char; 4] = ['|', '/', '-', '\\'];

/// Represents the tabs available for filtering analysis findings.
#[derive(Debug, Default, Clone, Copy, Display, FromRepr, EnumIter, PartialEq, Eq)]
pub enum AnalysisTab {
    #[default]
    All,
    Critical,
    Warning,
    Info,
}

/// Represents the status of an export operation.
pub enum ExportStatus {
    Idle,
    Success(String),
    Error(String),
}

/// Represents the overall state of the application.
#[derive(Default, PartialEq, Eq)]
pub enum AppState {
    #[default]
    Disclaimer,
    Idle,
    Scanning,
    Finished,
}

/// A summary of the key scan results for a high-level overview.
#[derive(Debug, Default)]
pub struct ScanSummary {
    pub score: u8,
    pub critical_issues: usize,
    pub warning_issues: usize,
    pub dns_check_passed: bool,
    pub ssl_check_passed: bool,
    pub headers_check_passed: bool,
}

/// The main application struct that holds the entire state.
pub struct App {
    /// Flag to signal the main loop to quit.
    pub should_quit: bool,
    /// The current state of the application.
    pub state: AppState,
    /// The input string from the user.
    pub input: String,
    /// The comprehensive report of all scan results.
    pub scan_report: Option<ScanReport>,
    /// A high-level summary of the scan results.
    pub summary: ScanSummary,
    /// The status of the export operation.
    pub export_status: ExportStatus,
    /// The current frame of the spinning animation.
    pub spinner_frame: usize,
    /// The currently active tab for filtering analysis findings.
    pub active_analysis_tab: AnalysisTab,
    // --- MODIFIED: Changed the type from AnalysisResult to AnalysisFinding ---
    pub filtered_findings: Vec<AnalysisFinding>,
    /// The state of the analysis list widget.
    pub analysis_list_state: ratatui::widgets::ListState,
    /// The score currently displayed on the UI, used for animation.
    pub displayed_score: u8,
}

impl App {
    /// Constructs a new `App` instance with default values.
    pub fn new() -> Self {
        Self {  
            should_quit: false,
            state: AppState::default(),
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
    
    /// Switches to the next analysis tab, wrapping around if at the end.
    pub fn next_analysis_tab(&mut self) {
        let current_index = self.active_analysis_tab as usize;
        let next_index = current_index.saturating_add(1);
        self.active_analysis_tab = AnalysisTab::from_repr(next_index).unwrap_or(self.active_analysis_tab);
        self.update_filtered_findings();
    }

    /// Switches to the previous analysis tab, wrapping around if at the beginning.
    pub fn previous_analysis_tab(&mut self) {
        let current_index = self.active_analysis_tab as usize;
        let previous_index = current_index.saturating_sub(1);
        self.active_analysis_tab = AnalysisTab::from_repr(previous_index).unwrap_or(self.active_analysis_tab);
        self.update_filtered_findings();
    }
    
    /// Selects the next finding in the analysis list.
    pub fn select_next_finding(&mut self) {
        if self.filtered_findings.is_empty() { return; }
        let i = match self.analysis_list_state.selected() {
            Some(i) => (i + 1) % self.filtered_findings.len(),
            None => 0,
        };
        self.analysis_list_state.select(Some(i));
    }

    /// Selects the previous finding in the analysis list.
    pub fn select_previous_finding(&mut self) {
        if self.filtered_findings.is_empty() { return; }
        let i = match self.analysis_list_state.selected() {
            Some(i) => if i == 0 { self.filtered_findings.len() - 1 } else { i - 1 },
            None => 0,
        };
        self.analysis_list_state.select(Some(i));
    }
    
    /// Updates the `filtered_findings` based on the currently active tab.
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
                    // --- FIX: Compare the enum directly, not strings ---
                    match self.active_analysis_tab {
                        AnalysisTab::Critical => matches!(f.severity, Severity::Critical),
                        AnalysisTab::Warning => matches!(f.severity, Severity::Warning),
                        AnalysisTab::Info => matches!(f.severity, Severity::Info),
                        _ => false, // This shouldn't happen
                    }
                }).collect()
            };

            if !self.filtered_findings.is_empty() {
                self.analysis_list_state.select(Some(0));
            } else {
                self.analysis_list_state.select(None);
            }
        }
    }

    /// Updates the application state on each tick of the event loop.
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

    /// Sets the `should_quit` flag to true to exit the application.
    pub fn quit(&mut self) { self.should_quit = true; }

    /// Resets the application state to its initial, idle condition.
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
    
    /// Calculates and updates the scan summary.
    pub fn update_summary(&mut self) {
        if let Some(report) = &self.scan_report {
            let all_analyses: Vec<_> = report.dns_results.analysis.iter()
                .chain(report.ssl_results.analysis.iter())
                .chain(report.headers_results.analysis.iter())
                .collect();
            
            let criticals = all_analyses.iter().filter(|a| matches!(a.severity, Severity::Critical)).count();
            let warnings = all_analyses.iter().filter(|a| matches!(a.severity, Severity::Warning)).count();
            let score = 100_i16.saturating_sub((criticals * 15) as i16).saturating_sub((warnings * 5) as i16);
            
            // --- FIX: Updated logic for `..._check_passed` ---
            // A DNS check passes if NONE of its sub-scans failed (is Err).
            // We could also check that there are no analyses, but the scan error is more important.
            let dns_check_passed = report.dns_results.spf.is_ok()
                && report.dns_results.dmarc.is_ok()
                && report.dns_results.dkim.is_ok()
                && report.dns_results.caa.is_ok();
            
            // An SSL check passes if the scan is Ok (even if Ok(None), which is rare).
            let ssl_check_passed = report.ssl_results.scan.is_ok();

            // An headers check passes if there was no general request error AND
            // none of the sub-scans failed.
            let headers_check_passed = report.headers_results.error.is_none()
                && report.headers_results.hsts.is_ok()
                && report.headers_results.csp.is_ok()
                && report.headers_results.x_frame_options.is_ok()
                && report.headers_results.x_content_type_options.is_ok();

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
}