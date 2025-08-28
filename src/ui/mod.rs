// src/ui/mod.rs

use crate::app::App;
use ratatui::prelude::*;

mod layout;
mod widgets;

/// The main rendering function, orchestrating the entire UI.
pub fn render(app: &mut App, frame: &mut Frame) {
    let layout = layout::create_layout(frame.area());

    widgets::input::render_input(frame, app, layout.input);
    widgets::results::render_results(frame, app, layout.report);
    widgets::summary::render_summary(frame, app, layout.summary);
    widgets::footer::render_footer(frame, app, layout.footer); // <-- RENDERIZZA IL FOOTER
}