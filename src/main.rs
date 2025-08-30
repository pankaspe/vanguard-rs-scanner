// src/main.rs

use color_eyre::eyre::Result;
use tracing::{debug, error, info};
use crate::app::{App, AppState, ExportStatus};
use chrono::Local;
use crossterm::{
    event::{
        self, Event, KeyCode, KeyEventKind,
    },
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::prelude::*;
use std::fs;
use std::io::stdout;
use std::time::Duration;
use tokio::sync::mpsc;
use url::Url;

mod app;
mod core;
mod ui;
mod logging;

/// The main entry point for the application.
///
/// This function performs the following steps:
/// 1. Initializes the logging system.
/// 2. Sets up the terminal for TUI interaction by entering alternate screen mode and enabling raw mode.
/// 3. Creates a new `App` instance to hold the application state.
/// 4. Spawns a channel for asynchronous communication between the scanner task and the main event loop.
/// 5. Enters the main loop, which continues until the application is signaled to quit.
///    - In each iteration, it draws the UI, polls for terminal events, and checks for incoming scan reports.
/// 6. Cleans up by restoring the terminal to its original state before exiting.
#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging infrastructure.
    logging::initialize_logging()?;
    info!("Application starting up");

    // Prepare the terminal for the TUI.
    stdout().execute(EnterAlternateScreen)?;
    enable_raw_mode()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    terminal.clear()?;

    // Initialize the application state.
    let mut app = App::new();
    // Create a channel to receive the scan report from the background task.
    let (tx, mut rx) = mpsc::channel(1);

    // Main application loop.
    while !app.should_quit {
        // Draw the user interface.
        terminal.draw(|frame| {
            ui::render(&mut app, frame);
        })?;

        // Poll for terminal events with a short timeout.
        if event::poll(Duration::from_millis(100))? {
            handle_events(&mut app, &tx).await?;
        }

        // Check for a completed scan report from the scanner task without blocking.
        if let Ok(report) = rx.try_recv() {
            info!(target = %app.input, "Scan finished. Report received.");
            app.scan_report = Some(report);
            app.state = AppState::Finished;
            app.update_summary();
            app.update_findings();
        }

        // Allow the app to perform any work needed on each tick.
        app.on_tick();
    }

    // Gracefully shut down the application.
    info!("Application shutting down gracefully.");
    stdout().execute(LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}


/// Handles terminal events, such as key presses, and updates the application state accordingly.
///
/// It only processes key press events, delegating the logic to state-specific handlers.
///
/// # Arguments
///
/// * `app` - A mutable reference to the `App` struct, representing the application's state.
/// * `tx` - A sender endpoint of a channel, used to initiate the scan task.
async fn handle_events(app: &mut App, tx: &mpsc::Sender<core::models::ScanReport>) -> Result<()> {
    if let Event::Key(key) = event::read()? {
        // Process event only on key press, not release.
        if key.kind == KeyEventKind::Press {
            debug!("Key event received: {:?}", key.code);
            match app.state {
                AppState::Disclaimer => {
                    if key.code == KeyCode::Enter { app.state = AppState::Idle; }
                }
                AppState::Idle => handle_idle_input(app, key.code, tx).await,
                AppState::Finished => handle_finished_keyboard_input(app, key.code),
                AppState::Scanning => {
                    // Allow quitting even while a scan is in progress.
                    if key.code == KeyCode::Char('q') { app.quit(); }
                }
            }
        }
    }
    Ok(())
}

/// Manages keyboard input when the application is in the `AppState::Idle` state.
///
/// This function handles character input for the target URL, backspace for deletion,
/// and the Enter key to start a new scan.
///
/// # Arguments
///
/// * `app` - A mutable reference to the application's state.
/// * `key_code` - The `KeyCode` corresponding to the pressed key.
/// * `tx` - The sender endpoint of the channel to communicate with the scanner task.
async fn handle_idle_input(app: &mut App, key_code: KeyCode, tx: &mpsc::Sender<core::models::ScanReport>) {
    // Reset any lingering export status messages.
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

            // Change state to indicate scanning has started.
            app.state = AppState::Scanning;
            let tx_clone = tx.clone();
            let raw_input = app.input.clone();
            
            // Prepend "https://" to the input if no scheme is present.
            let input_with_scheme = if !raw_input.starts_with("http://") && !raw_input.starts_with("https://") {
                format!("https://{}", raw_input)
            } else { raw_input };

            // Attempt to parse the input as a URL to extract the host. Fallback to the raw input.
            let target_domain = Url::parse(&input_with_scheme)
                .ok().and_then(|url| url.host_str().map(String::from))
                .unwrap_or_else(|| app.input.clone());
            
            info!(target = %target_domain, "Initiating new scan");

            // Spawn a new asynchronous task to run the scan without blocking the UI.
            tokio::spawn(async move {
                let report = core::scanner::run_full_scan(&target_domain).await;
                // Send the completed report back to the main event loop.
                let _ = tx_clone.send(report).await;
            });
        }
        _ => {}
    }
}

/// Manages keyboard input when the application is in the `AppState::Finished` state.
///
/// This function handles navigating findings, exporting the report, starting a new scan,
/// and toggling the log panel.
///
/// # Arguments
///
/// * `app` - A mutable reference to the application's state.
/// * `key_code` - The `KeyCode` corresponding to the pressed key.
fn handle_finished_keyboard_input(app: &mut App, key_code: KeyCode) {
    // Reset any lingering export status messages on new input.
    if !matches!(app.export_status, ExportStatus::Idle) {
        app.export_status = ExportStatus::Idle;
    }

    // If the log panel is visible, specific keys control log scrolling.
    if app.show_logs {
        match key_code {
            // Handle horizontal scrolling for the log view.
            KeyCode::Left => {
                app.log_horizontal_scroll = app.log_horizontal_scroll.saturating_sub(1);
                app.log_horizontal_scroll_state = app.log_horizontal_scroll_state.position(app.log_horizontal_scroll);
                return; // Consume the event to prevent other actions.
            },
            KeyCode::Right => {
                app.log_horizontal_scroll = app.log_horizontal_scroll.saturating_add(1);
                app.log_horizontal_scroll_state = app.log_horizontal_scroll_state.position(app.log_horizontal_scroll);
                return; // Consume the event to prevent other actions.
            },
            _ => {}
        }
    }
    
    match key_code {
        KeyCode::Char('q') | KeyCode::Char('Q') => app.quit(),
        KeyCode::Char('n') | KeyCode::Char('N') => app.reset(),
        KeyCode::Char('e') | KeyCode::Char('E') => {
            // Export the scan report to a JSON file.
            if let Some(report) = &app.scan_report {
                match serde_json::to_string_pretty(report) {
                    Ok(json_data) => {
                        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
                        let target_domain = app.input.split_once("://").unwrap_or(("", &app.input)).1;
                        let filename = format!("{}-{}.json", target_domain.replace('/', "_"), timestamp);
                        
                        match fs::write(&filename, json_data) {
                            Ok(_) => { 
                                info!(filename = %filename, "Report exported successfully"); 
                                app.export_status = ExportStatus::Success(filename); 
                            },
                            Err(e) => { 
                                error!(error = %e, "Failed to write report to file"); 
                                app.export_status = ExportStatus::Error(e.to_string()); 
                            },
                        }
                    }
                    Err(e) => { 
                        error!(error = %e, "Failed to serialize report to JSON"); 
                        app.export_status = ExportStatus::Error(e.to_string()); 
                    },
                }
            }
        },
        // Navigation controls for the findings list.
        KeyCode::Down => app.select_next_finding(),
        KeyCode::Up => app.select_previous_finding(),
        // Toggle the visibility of the log panel.
        KeyCode::Char('l') | KeyCode::Char('L') => {
            app.show_logs = !app.show_logs;
            debug!(visible = %app.show_logs, "Log panel visibility toggled");
            if app.show_logs {
                // Refresh log content when panel becomes visible.
                app.refresh_logs();
            }
        },
        _ => {}
    }
}