// src/ui/mod.rs

use crate::app::{App, AppState};
use ratatui::prelude::*;

mod layout;
mod widgets;

/// The main render function for the user interface.
///
/// This function acts as the central orchestrator for drawing all the TUI widgets
/// on the screen. It first calculates the layout for all the main components
/// (input, analysis report, summary, footer) and then calls the respective
/// widget rendering functions to draw them.
///
/// A key feature of this function is the conditional rendering of the disclaimer popup.
/// It draws the main UI components first, and then, if the application is in the
/// `AppState::Disclaimer`, it draws the popup on top of the entire frame area,
/// effectively creating a modal dialog that overlays the rest of the interface.
///
/// # Arguments
///
/// * `app` - A mutable reference to the `App` struct, which contains the current
///   state of the application and all the data to be displayed.
/// * `frame` - A mutable reference to the `Frame` provided by the TUI backend,
///   which is the canvas for all drawing operations.
pub fn render(app: &mut App, frame: &mut Frame) {
    // 1. Calculate the layout for all main UI components.
    let layout = layout::create_layout(frame.area());

    // 2. Render the main UI widgets using the calculated layout areas.
    // These are always drawn regardless of the application state.
    widgets::input::render_input(frame, app, layout.input);
    widgets::analysis_view::render_analysis_view(frame, app, layout.report);
    widgets::summary::render_summary(frame, app, layout.summary);
    widgets::footer::render_footer(frame, app, layout.footer);

    // 3. Conditionally render the disclaimer popup.
    // If the state is `AppState::Disclaimer`, the popup widget is drawn on top
    // of the entire frame, which `ratatui` handles seamlessly.
    if matches!(app.state, AppState::Disclaimer) {
        widgets::disclaimer_popup::render_disclaimer_popup(frame, frame.area());
    }
}