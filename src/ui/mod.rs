// src/ui/mod.rs

use crate::app::{App, AppState};
use ratatui::prelude::*;

// Declare the modules responsible for UI rendering.
// `layout` is made public as it defines the core layout structure.
pub mod layout;
// `widgets` contains the rendering logic for individual UI components.
// This module is expected to have its own `mod.rs` file (e.g., `src/ui/widgets/mod.rs`)
// that declares sub-modules for each widget.
mod widgets;

/// The main rendering function for the entire user interface.
///
/// This function orchestrates the drawing of all widgets onto the frame.
/// It first calculates the layout based on the current state, then calls the
/// specific rendering functions for each component. It also handles conditional
/// rendering, such as displaying the log panel or the disclaimer popup.
///
/// # Arguments
/// * `app` - A mutable reference to the application's state.
/// * `frame` - A mutable reference to the `Frame` on which to draw.
pub fn render(app: &mut App, frame: &mut Frame) {
    // 1. Calculate the dynamic layout based on whether the log panel is visible.
    let app_layout = layout::create_layout(frame.area(), app.show_logs);

    // 2. Render the primary UI widgets in their designated areas.
    widgets::input::render_input(frame, app, app_layout.input);
    widgets::analysis_view::render_analysis_view(frame, app, app_layout.report);
    widgets::summary::render_summary(frame, app, app_layout.summary);
    widgets::footer::render_footer(frame, app, app_layout.footer);

    // 3. Conditionally render the log panel if it's enabled.
    if app.show_logs {
        widgets::log_view::render_log_view(frame, app, app_layout.log_panel);
    }

    // 4. If the app is in the `Disclaimer` state, render the popup as an overlay.
    if matches!(app.state, AppState::Disclaimer) {
        widgets::disclaimer_popup::render_disclaimer_popup(frame, frame.area());
    }
}