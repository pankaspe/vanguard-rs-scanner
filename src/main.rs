// src/main.rs

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind,
    },
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::prelude::*;
use std::io::{stdout, Result};
use std::time::Duration;
use tokio::sync::mpsc;
use url::Url;

mod app;
mod core;
mod ui;

use app::{App, AppState};

#[tokio::main]
async fn main() -> Result<()> {
    // --- Setup ---
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
            // Unico gestore eventi per mantenere la logica pulita
            handle_events(&mut app, &tx).await?;
        }

        if let Ok(report) = rx.try_recv() {
            app.scan_report = Some(report);
            app.state = AppState::Finished;
            app.update_summary();
        }
    }

    // --- Restore Terminal ---
    stdout().execute(LeaveAlternateScreen)?;
    stdout().execute(DisableMouseCapture)?;
    disable_raw_mode()?;
    Ok(())
}

/// Gestore eventi separato per migliorare la leggibilità
async fn handle_events(app: &mut App, tx: &mpsc::Sender<core::models::ScanReport>) -> Result<()> {
    if let Event::Key(key) = event::read()? {
        if key.kind == KeyEventKind::Press {
            match app.state {
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
    match key_code {
        KeyCode::Char('q') => app.quit(),
        KeyCode::Char('n') => app.reset(), // 'N' per una nuova scansione
        // KeyCode::Char('e') => { /* Logica di export qui */ },
        KeyCode::Up => app.scroll_up(),
        KeyCode::Down => app.scroll_down(),
        _ => {}
    }
}