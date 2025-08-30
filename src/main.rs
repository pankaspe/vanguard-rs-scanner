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
// RIMOSSO: MouseButton e MouseEventKind non sono più necessari.
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

#[tokio::main]
async fn main() -> Result<()> {
    logging::initialize_logging()?;
    info!("Application starting up");

    stdout().execute(EnterAlternateScreen)?;
    // RIMOSSO: `EnableMouseCapture` non è più necessario.
    enable_raw_mode()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    terminal.clear()?;

    let mut app = App::new();
    let (tx, mut rx) = mpsc::channel(1);

    while !app.should_quit {
        let mut frame_size = Rect::default();
        terminal.draw(|frame| {
            frame_size = frame.area();
            ui::render(&mut app, frame);
        })?;

        if event::poll(Duration::from_millis(100))? {
            handle_events(&mut app, &tx).await?;
        }

        if let Ok(report) = rx.try_recv() {
            info!(target = %app.input, "Scan finished. Report received.");
            app.scan_report = Some(report);
            app.state = AppState::Finished;
            app.update_summary();
            app.update_findings();
        }

        app.on_tick();
    }

    info!("Application shutting down gracefully.");
    stdout().execute(LeaveAlternateScreen)?;
    // RIMOSSO: `DisableMouseCapture` non è più necessario.
    disable_raw_mode()?;
    Ok(())
}

// MODIFICATO: `frame_size` rimosso, non più necessario senza il mouse.
async fn handle_events(app: &mut App, tx: &mpsc::Sender<core::models::ScanReport>) -> Result<()> {
    // MODIFICATO: `match` semplificato, gestisce solo `Event::Key`.
    if let Event::Key(key) = event::read()? {
        if key.kind == KeyEventKind::Press {
            debug!("Key event received: {:?}", key.code);
            match app.state {
                AppState::Disclaimer => {
                    if key.code == KeyCode::Enter { app.state = AppState::Idle; }
                }
                AppState::Idle => handle_idle_input(app, key.code, tx).await,
                AppState::Finished => handle_finished_keyboard_input(app, key.code),
                AppState::Scanning => {
                    if key.code == KeyCode::Char('q') { app.quit(); }
                }
            }
        }
    }
    Ok(())
}

async fn handle_idle_input(app: &mut App, key_code: KeyCode, tx: &mpsc::Sender<core::models::ScanReport>) {
    if !matches!(app.export_status, ExportStatus::Idle) {
        app.export_status = ExportStatus::Idle;
    }

    match key_code {
        KeyCode::Char('q') => app.quit(),
        KeyCode::Char(c) => app.input.push(c),
        KeyCode::Backspace => { app.input.pop(); },
        KeyCode::Enter => {
            if app.input.is_empty() { return; }
            app.state = AppState::Scanning;
            let tx_clone = tx.clone();
            let raw_input = app.input.clone();
            
            let input_with_scheme = if !raw_input.starts_with("http://") && !raw_input.starts_with("https://") {
                format!("https://{}", raw_input)
            } else { raw_input };
            let target_domain = Url::parse(&input_with_scheme)
                .ok().and_then(|url| url.host_str().map(String::from))
                .unwrap_or_else(|| app.input.clone());
            
            info!(target = %target_domain, "Initiating new scan");
            tokio::spawn(async move {
                let report = core::scanner::run_full_scan(&target_domain).await;
                let _ = tx_clone.send(report).await;
            });
        }
        _ => {}
    }
}

fn handle_finished_keyboard_input(app: &mut App, key_code: KeyCode) {
    if !matches!(app.export_status, ExportStatus::Idle) {
        app.export_status = ExportStatus::Idle;
    }

    // Se il pannello dei log è visibile, le frecce controllano lo scroll.
    if app.show_logs {
        match key_code {
            // CORREZIONE: SOLO le frecce controllano lo scroll.
            KeyCode::Left => {
                app.log_horizontal_scroll = app.log_horizontal_scroll.saturating_sub(1);
                app.log_horizontal_scroll_state = app.log_horizontal_scroll_state.position(app.log_horizontal_scroll);
                return;
            },
            KeyCode::Right => {
                app.log_horizontal_scroll = app.log_horizontal_scroll.saturating_add(1);
                app.log_horizontal_scroll_state = app.log_horizontal_scroll_state.position(app.log_horizontal_scroll);
                return;
            },
            _ => {}
        }
    }
    
    match key_code {
        KeyCode::Char('q') | KeyCode::Char('Q') => app.quit(),
        KeyCode::Char('n') | KeyCode::Char('N') => app.reset(),
        KeyCode::Char('e') | KeyCode::Char('E') => {
            if let Some(report) = &app.scan_report {
                match serde_json::to_string_pretty(report) {
                    Ok(json_data) => {
                        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
                        let target_domain = app.input.split_once("://").unwrap_or(("", &app.input)).1;
                        let filename = format!("{}-{}.json", target_domain.replace('/', "_"), timestamp);
                        
                        match fs::write(&filename, json_data) {
                            Ok(_) => { info!(filename = %filename, "Report exported successfully"); app.export_status = ExportStatus::Success(filename); },
                            Err(e) => { error!(error = %e, "Failed to write report to file"); app.export_status = ExportStatus::Error(e.to_string()); },
                        }
                    }
                    Err(e) => { error!(error = %e, "Failed to serialize report to JSON"); app.export_status = ExportStatus::Error(e.to_string()); },
                }
            }
        },
        KeyCode::Down | KeyCode::Char('j') => app.select_next_finding(),
        KeyCode::Up | KeyCode::Char('k') => app.select_previous_finding(),
        // CORREZIONE: `l`/`L` ora servono SOLO per i log e non sono in conflitto.
        KeyCode::Char('l') | KeyCode::Char('L') => {
            app.show_logs = !app.show_logs;
            debug!(visible = %app.show_logs, "Log panel visibility toggled");
            if app.show_logs {
                app.refresh_logs();
            }
        },
        _ => {}
    }
}

