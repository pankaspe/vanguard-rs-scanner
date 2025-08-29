// src/main.rs

use crate::app::{App, AppState, ExportStatus};
use chrono::Local;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::prelude::*;
use std::fs;
use std::io::{stdout, Result};
use std::time::Duration;
use tokio::sync::mpsc;
use url::Url;

// Declare the application's modules.
mod app;
mod core;
mod ui;

/// The entry point of the application.
///
/// This function sets up the terminal in a specific raw mode, initializes the TUI
/// application state, and enters the main event loop. It handles rendering the UI,
/// polling for user input and TUI events, and processing messages from the
/// asynchronous scanning tasks.
#[tokio::main]
async fn main() -> Result<()> {
    // --- Setup (identical) ---
    // Enters the raw terminal mode and enables mouse capture.
    stdout().execute(EnterAlternateScreen)?;
    stdout().execute(EnableMouseCapture)?;
    enable_raw_mode()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    terminal.clear()?;

    let mut app = App::new();
    // Creates an asynchronous channel to receive scan reports from the background task.
    let (tx, mut rx) = mpsc::channel(1);

    // The main application loop.
    while !app.should_quit {
        // Renders the UI based on the current application state.
        terminal.draw(|frame| ui::render(&mut app, frame))?;

        // Polls for events with a timeout to allow for periodic updates.
        if event::poll(Duration::from_millis(100))? {
            handle_events(&mut app, &tx).await?;
        }

        // Checks for a completed scan report from the background task.
        if let Ok(report) = rx.try_recv() {
            app.scan_report = Some(report);
            app.state = AppState::Finished;
            app.update_summary();
            app.update_filtered_findings();
        }

        // Performs a tick to update animations or other periodic state.
        app.on_tick();
    }

    // --- Restore Terminal (identical) ---
    // Restores the terminal to its original state before exiting.
    stdout().execute(LeaveAlternateScreen)?;
    stdout().execute(DisableMouseCapture)?;
    disable_raw_mode()?;
    Ok(())
}

/// A separate event handler function to keep the main loop clean.
///
/// It reads key events and delegates handling to a specific function
/// based on the application's current `AppState`.
async fn handle_events(app: &mut App, tx: &mpsc::Sender<core::models::ScanReport>) -> Result<()> {
    if let Event::Key(key) = event::read()? {
        if key.kind == KeyEventKind::Press {
            match app.state {
                // NEW LOGIC: If the disclaimer is active, only listen for `Enter`.
                AppState::Disclaimer => {
                    if key.code == KeyCode::Enter {
                        // Transition to the normal `Idle` state.
                        app.state = AppState::Idle;
                    }
                }
                AppState::Idle => handle_idle_input(app, key.code, tx).await,
                AppState::Finished => handle_finished_input(app, key.code),
                AppState::Scanning => {
                    // Quitting is allowed at any time.
                    if key.code == KeyCode::Char('q') { app.quit(); }
                }
            }
        }
    }
    Ok(())
}

/// Handles user input when the app is in the `Idle` state.
///
/// This function processes character input for the target domain, handles
/// backspace, and initiates a new scan on `Enter`. It also handles clearing
/// any previous export status messages.
async fn handle_idle_input(app: &mut App, key_code: KeyCode, tx: &mpsc::Sender<core::models::ScanReport>) {
    // Clear any previous export message before accepting new input.
    if !matches!(app.export_status, ExportStatus::Idle) {
        app.export_status = ExportStatus::Idle;
    }

    match key_code {
        KeyCode::Char('q') => app.quit(),
        KeyCode::Char(c) => app.input.push(c),
        KeyCode::Backspace => { app.input.pop(); },
        KeyCode::Enter => {
            // Do nothing if the input is empty.
            if app.input.is_empty() { return; }
            app.state = AppState::Scanning;
            let tx_clone = tx.clone();
            let raw_input = app.input.clone();
            
            // Prepares the target domain for scanning, ensuring it has a scheme.
            let input_with_scheme = if !raw_input.starts_with("http://") && !raw_input.starts_with("https://") {
                format!("https://{}", raw_input)
            } else { raw_input };
            let target_domain = Url::parse(&input_with_scheme)
                .ok().and_then(|url| url.host_str().map(String::from))
                .unwrap_or_else(|| app.input.clone());

            // Spawns the scan as a background task to prevent blocking the TUI.
            tokio::spawn(async move {
                let report = core::scanner::run_full_scan(&target_domain).await;
                let _ = tx_clone.send(report).await;
            });
        }
        _ => {}
    }
}

/// Handles user input when the scan report is displayed (`Finished` state).
///
/// This function allows the user to navigate the report, start a new scan,
/// export the report to a JSON file, or quit the application.
fn handle_finished_input(app: &mut App, key_code: KeyCode) {
    // Clear any previous export message.
    if !matches!(app.export_status, ExportStatus::Idle) {
        app.export_status = ExportStatus::Idle;
    }
    
    match key_code {
        KeyCode::Char('q') | KeyCode::Char('Q') => app.quit(),
        KeyCode::Char('n') | KeyCode::Char('N') => app.reset(),
        KeyCode::Char('e') | KeyCode::Char('E') => {
            if let Some(report) = &app.scan_report {
                // Serializes the report to a pretty-printed JSON string.
                match serde_json::to_string_pretty(report) {
                    Ok(json_data) => {
                        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
                        let target_domain = app.input.split_once("://").unwrap_or(("", &app.input)).1;
                        let filename = format!("{}-{}.json", target_domain.replace('/', "_"), timestamp);
                        
                        // Writes the JSON data to a file.
                        match fs::write(&filename, json_data) {
                            Ok(_) => app.export_status = ExportStatus::Success(filename),
                            Err(e) => app.export_status = ExportStatus::Error(e.to_string()),
                        }
                    }
                    Err(e) => app.export_status = ExportStatus::Error(e.to_string()),
                }
            }
        },
        KeyCode::Right | KeyCode::Char('l') => app.next_analysis_tab(),
        KeyCode::Left | KeyCode::Char('h') => app.previous_analysis_tab(),
        KeyCode::Down | KeyCode::Char('j') => app.select_next_finding(),
        KeyCode::Up | KeyCode::Char('k') => app.select_previous_finding(),
        _ => {}
    }
}