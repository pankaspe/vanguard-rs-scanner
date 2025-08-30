// src/ui/widgets/mod.rs

// This file serves as the module declaration for all UI widgets.
// By declaring them here, we make them available to the rest of the `ui` module
// and the main application logic. The `pub mod` statement ensures that
// these modules can be accessed and used publicly by other parts of the crate.

// Declare all of our widget modules here.
pub mod analysis_view; // Our new widget for the analysis report.
pub mod footer;         // The widget for the dynamic footer bar.
pub mod input;          // The widget for the user input field.
pub mod disclaimer_popup; // The widget for the legal disclaimer popup.
pub mod summary;        // The widget that displays the scan summary.
pub mod log_view; // The widget for logs