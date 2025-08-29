// src/app.rs

use crate::core::models::{AnalysisResult, ScanReport};
use strum::{Display, EnumIter, FromRepr};

/// A list of characters used to create a simple text-based spinner for the UI.
pub const SPINNER_CHARS: [char; 4] = ['|', '/', '-', '\\'];

/// Enum representing the available tabs for filtering analysis results.
///
/// `strum` macros are used to automatically implement traits that make it easy
/// to iterate over the enum variants, convert them to strings, and get them
/// from their representation.
#[derive(Debug, Default, Clone, Copy, Display, FromRepr, EnumIter, PartialEq, Eq)]
pub enum AnalysisTab {
    #[default]
    All,
    Critical,
    Warning,
    Info,
}

/// Enum representing the status of a report export operation.
pub enum ExportStatus {
    Idle,
    Success(String),
    Error(String),
}

/// Enum representing the overall state of the application.
///
/// The application's behavior and the UI it displays are determined by its current state.
#[derive(Default, PartialEq, Eq)]
pub enum AppState {
    #[default]
    Disclaimer, // The app now starts in this state to show the disclaimer.
    Idle,
    Scanning,
    Finished,
}

/// A struct to hold a summarized view of the scan results.
///
/// This provides a quick overview of key metrics, like the overall score
/// and the pass/fail status of major security checks.
#[derive(Debug, Default)]
pub struct ScanSummary {
    pub score: u8,
    pub critical_issues: usize,
    pub warning_issues: usize,
    pub dns_check_passed: bool,
    pub ssl_check_passed: bool,
    pub headers_check_passed: bool,
}

/// The main application state struct.
///
/// It holds all the data and state necessary to run the application, including
/// UI state, scan results, and user input.
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
    /// Creates a new `App` instance with default values.
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
    
    /// Switches to the next analysis tab.
    pub fn next_analysis_tab(&mut self) {
        let current_index = self.active_analysis_tab as usize;
        let next_index = current_index.saturating_add(1);
        self.active_analysis_tab = AnalysisTab::from_repr(next_index).unwrap_or(self.active_analysis_tab);
        self.update_filtered_findings();
    }

    /// Switches to the previous analysis tab.
    pub fn previous_analysis_tab(&mut self) {
        let current_index = self.active_analysis_tab as usize;
        let previous_index = current_index.saturating_sub(1);
        self.active_analysis_tab = AnalysisTab::from_repr(previous_index).unwrap_or(self.active_analysis_tab);
        self.update_filtered_findings();
    }
    
    /// Selects the next finding in the filtered list.
    pub fn select_next_finding(&mut self) {
        if self.filtered_findings.is_empty() { return; }
        let i = match self.analysis_list_state.selected() {
            Some(i) => (i + 1) % self.filtered_findings.len(),
            None => 0,
        };
        self.analysis_list_state.select(Some(i));
    }

    /// Selects the previous finding in the filtered list.
    pub fn select_previous_finding(&mut self) {
        if self.filtered_findings.is_empty() { return; }
        let i = match self.analysis_list_state.selected() {
            Some(i) => if i == 0 { self.filtered_findings.len() - 1 } else { i - 1 },
            None => 0,
        };
        self.analysis_list_state.select(Some(i));
    }
    
    /// Updates the `filtered_findings` list based on the active tab.
    pub fn update_filtered_findings(&mut self) {
        if let Some(report) = &self.scan_report {
            // Collect all findings from all scanners into a single vector.
            let all_findings: Vec<_> = report.dns_results.analysis.iter()
                .chain(report.ssl_results.analysis.iter())
                .chain(report.headers_results.analysis.iter())
                .cloned().collect();

            // Filter the findings based on the active tab's severity.
            self.filtered_findings = if self.active_analysis_tab == AnalysisTab::All {
                all_findings
            } else {
                all_findings.into_iter().filter(|f| {
                    let severity_str = format!("{:?}", f.severity);
                    let tab_str = format!("{:?}", self.active_analysis_tab);
                    severity_str.eq_ignore_ascii_case(&tab_str)
                }).collect()
            };

            // Select the first item in the new filtered list, if it's not empty.
            if !self.filtered_findings.is_empty() {
                self.analysis_list_state.select(Some(0));
            } else {
                self.analysis_list_state.select(None);
            }
        }
    }

    /// Ticks the application state, used for animations and periodic updates.
    pub fn on_tick(&mut self) {
        // Update the spinner frame during a scan.
        if matches!(self.state, AppState::Scanning) {
            self.spinner_frame = (self.spinner_frame + 1) % SPINNER_CHARS.len();
        }

        // Animate the score gauge on the summary screen.
        if matches!(self.state, AppState::Finished) {
            if self.displayed_score < self.summary.score {
                // Increment by 2 for a faster animation.
                self.displayed_score = (self.displayed_score + 2).min(self.summary.score);
            }
        }
    }

    /// Sets the flag to quit the application.
    pub fn quit(&mut self) { self.should_quit = true; }

    /// Resets the application to its default `Idle` state.
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
    
    /// Calculates and updates the scan summary based on the results.
    pub fn update_summary(&mut self) {
        if let Some(report) = &self.scan_report {
            // Existing logic to calculate the score.
            let all_analyses: Vec<_> = report.dns_results.analysis.iter()
                .chain(report.ssl_results.analysis.iter())
                .chain(report.headers_results.analysis.iter())
                .collect();
            
            let criticals = all_analyses.iter().filter(|a| matches!(a.severity, crate::core::models::Severity::Critical)).count();
            let warnings = all_analyses.iter().filter(|a| matches!(a.severity, crate::core::models::Severity::Warning)).count();
            let score = 100_i16.saturating_sub((criticals * 15) as i16).saturating_sub((warnings * 5) as i16);
            
            // NEW LOGIC: Determine if each check passed.
            // A check passes if it has NO issues (neither critical nor warning).
            let dns_check_passed = report.dns_results.analysis.is_empty();
            let ssl_check_passed = report.ssl_results.analysis.is_empty();
            let headers_check_passed = report.headers_results.analysis.is_empty();

            self.summary = ScanSummary {
                score: if score < 0 { 0 } else { score as u8 },
                critical_issues: criticals,
                warning_issues: warnings,
                dns_check_passed,
                ssl_check_passed,
                headers_check_passed,
            };
            
            // Reset the animated score to 0 to start the animation again.
            self.displayed_score = 0;
        }
    }
}