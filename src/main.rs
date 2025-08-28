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

mod app;
mod core;
mod ui;

#[tokio::main]
async fn main() -> Result<()> {
    // --- Setup (identico) ---
    stdout().execute(EnterAlternateScreen)?;
    stdout().execute(EnableMouseCapture)?;
    enable_raw_mode()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    terminal.clear()?;

    let mut app = App::new();
    let (tx, mut rx) = mpsc::channel(1);

    while !app.should_quit {
        terminal.draw(|frame| ui::render(&mut app, frame))?;

        if event::poll(Duration::from_millis(100))? {
            handle_events(&mut app, &tx).await?;
        }

        if let Ok(report) = rx.try_recv() {
            app.scan_report = Some(report);
            app.state = AppState::Finished;
            app.update_summary();
            app.update_filtered_findings();
        }

        app.on_tick();
    }

    // --- Restore Terminal (identico) ---
    stdout().execute(LeaveAlternateScreen)?;
    stdout().execute(DisableMouseCapture)?;
    disable_raw_mode()?;
    Ok(())
}

/// Gestore eventi separato
async fn handle_events(app: &mut App, tx: &mpsc::Sender<core::models::ScanReport>) -> Result<()> {
    if let Event::Key(key) = event::read()? {
        if key.kind == KeyEventKind::Press {
            match app.state {
                // NUOVA LOGICA: Se il disclaimer è attivo, ascolta solo Invio
                AppState::Disclaimer => {
                    if key.code == KeyCode::Enter {
                        // Passa allo stato normale dell'applicazione
                        app.state = AppState::Idle;
                    }
                }
                AppState::Idle => handle_idle_input(app, key.code, tx).await,
                AppState::Finished => handle_finished_input(app, key.code),
                AppState::Scanning => {
                    if key.code == KeyCode::Char('q') { app.quit(); }
                }
            }
        }
    }
    Ok(())
}

/// Gestisce l'input quando l'app è in attesa (Idle)
async fn handle_idle_input(app: &mut App, key_code: KeyCode, tx: &mpsc::Sender<core::models::ScanReport>) {
    // Prima di gestire l'input, se c'era un messaggio di export, lo puliamo.
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

            tokio::spawn(async move {
                let report = core::scanner::run_full_scan(&target_domain).await;
                let _ = tx_clone.send(report).await;
            });
        }
        _ => {}
    }
}

/// Gestisce l'input quando il report è visualizzato (Finished)
fn handle_finished_input(app: &mut App, key_code: KeyCode) {
    // Prima di gestire l'input, se c'era un messaggio di export, lo puliamo.
    if !matches!(app.export_status, ExportStatus::Idle) {
        app.export_status = ExportStatus::Idle;
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