// src/ui/mod.rs

use crate::app::{App};
use ratatui::prelude::*;

mod layout;
mod widgets;

pub fn render(app: &mut App, frame: &mut Frame) {
    let layout = layout::create_layout(frame.area());

    widgets::input::render_input(frame, app, layout.input);
    
    // Logica condizionale: mostra il vecchio report o la nuova vista di analisi
    widgets::analysis_view::render_analysis_view(frame, app, layout.report);
    
    widgets::summary::render_summary(frame, app, layout.summary);
    widgets::footer::render_footer(frame, app, layout.footer);
}