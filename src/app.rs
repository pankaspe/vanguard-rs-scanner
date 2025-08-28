// src/app.rs

// We import the DnsResults struct, which will hold our scan data.
use crate::core::models::DnsResults;

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
    /// The text currently in the input box.
    pub input: String,
    /// The results of the last DNS scan.
    /// It's an Option because there are no results before the first scan.
    pub dns_results: Option<DnsResults>,
}

impl App {
    /// Creates a new App instance with default values.
    pub fn new() -> Self {
        Self {
            should_quit: false,
            state: AppState::Idle,
            input: String::new(),
            dns_results: None,
        }
    }

    /// A simple method to be called on each "tick" of the application loop.
    pub fn on_tick(&mut self) {
        // For now, this doesn't do anything, but it's a good placeholder
        // for future logic, like animations or timed updates.
    }

    /// Sets the `should_quit` flag to true, causing the main loop to exit.
    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    pub fn reset(&mut self) {
        self.state = AppState::Idle;
        self.input = String::new();
        self.dns_results = None;
    }
}