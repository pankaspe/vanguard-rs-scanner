// src/ui/mod.rs
use ratatui::prelude::*;
use crate::app::App;

mod layout;
mod widgets;

/// The main rendering function, now acting as a conductor.
pub fn render(app: &mut App, frame: &mut Frame) {
    // 1. Get the layout areas
    // Use .area() instead of .size()
    let main_layout = layout::create_main_layout(frame.area()); 
    let input_area = main_layout[0];
    let results_area = main_layout[1];
    
    // 2. Tell each widget to render itself in its area
    widgets::input::render_input(frame, app, input_area);
    widgets::results::render_results(frame, app, results_area);
}