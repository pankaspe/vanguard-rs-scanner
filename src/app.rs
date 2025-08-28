// src/app.rs

// We import the DnsResults struct, which will hold our scan data.
use crate::core::models::ScanReport;

/// Represents the different states the application can be in.
pub enum AppState {
    Idle,       // Waiting for user input
    Scanning,   // A scan is in progress
    Finished,   // The scan is complete and results are displayed
}

/// The main application struct that holds all the state.
pub struct App {
    pub should_quit: bool,
    pub state: AppState,
    pub input: String,
    // Ora usiamo la struct del report completo
    pub scan_report: Option<ScanReport>,
}

impl App {
    pub fn new() -> Self {
        Self {
            should_quit: false,
            state: AppState::Idle,
            input: String::new(),
            scan_report: None, // <-- Aggiornato
        }
    }

    pub fn on_tick(&mut self) {}

    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    pub fn reset(&mut self) {
        self.state = AppState::Idle;
        self.input = String::new();
        self.scan_report = None; // <-- Aggiornato
    }
}