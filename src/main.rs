// src/main.rs

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseEventKind,
    },
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::prelude::*;
use std::io::{stdout, Result};
use std::time::Duration;
use tokio::sync::mpsc;

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

    // --- Main Loop ---
    while !app.should_quit {
        terminal.draw(|frame| ui::render(&mut app, frame))?;

        // --- Event Handling ---
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                // Event: A key was pressed
                Event::Key(key) => {
                    if key.kind == KeyEventKind::Press {
                        match app.state {
                            AppState::Idle => match key.code {
                                KeyCode::Char('q') => app.quit(),
                                KeyCode::Char(c) => app.input.push(c),
                                KeyCode::Backspace => {
                                    app.input.pop();
                                }
                                KeyCode::Enter => {
                                    app.state = AppState::Scanning;
                                    let tx_clone = tx.clone();
                                    let target = app.input.clone();
                                    tokio::spawn(async move {
                                        // Call the main orchestrator function
                                        let report = core::scanner::run_full_scan(&target).await;
                                        let _ = tx_clone.send(report).await;
                                    });
                                }
                                _ => {}
                            },
                            _ => {
                                if let KeyCode::Char('q') = key.code {
                                    app.quit();
                                }
                            }
                        }
                    }
                }
                // Event: The mouse was used
                Event::Mouse(mouse) => {
                    if matches!(mouse.kind, MouseEventKind::Down(_)) {
                        if matches!(app.state, AppState::Finished) {
                            app.reset();
                        }
                    }
                }
                _ => {}
            }
        }

        // --- Result Handling ---
        if let Ok(report) = rx.try_recv() {
            app.scan_report = Some(report);
            app.state = AppState::Finished;
        }

        app.on_tick();
    }

    // --- Restore Terminal ---
    stdout().execute(LeaveAlternateScreen)?;
    stdout().execute(DisableMouseCapture)?;
    disable_raw_mode()?;
    Ok(())
}