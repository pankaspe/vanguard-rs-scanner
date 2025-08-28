// src/ui/mod.rs

use crate::app::{App, AppState};
use ratatui::prelude::*;

mod layout;
mod widgets;

pub fn render(app: &mut App, frame: &mut Frame) {
    let layout = layout::create_layout(frame.area());

    // Disegniamo sempre la UI principale "sotto"
    widgets::input::render_input(frame, app, layout.input);
    widgets::analysis_view::render_analysis_view(frame, app, layout.report);
    widgets::summary::render_summary(frame, app, layout.summary);
    widgets::footer::render_footer(frame, app, layout.footer);

    // Se siamo nello stato Disclaimer, disegniamo il popup SOPRA a tutto il resto.
    if matches!(app.state, AppState::Disclaimer) {
        widgets::disclaimer_popup::render_disclaimer_popup(frame, frame.area());
    }
}