// src/core/mod.rs

// This makes the `models`, `scanner`, and `knowledge_base` modules available
// to other parts of the application. The `mod.rs` file acts as the root
// of the `core` module, exposing its sub-modules to the crate.

/// Contains all data structures and models used throughout the application,
/// such as `ScanReport`, `Severity`, and various scanner result structs.
pub mod models;

/// Houses the core scanning logic and traits for different types of scans
/// (e.g., DNS, SSL, HTTP headers).
pub mod scanner;

/// Contains the business logic for analyzing scan results and generating
/// findings and recommendations. It acts as a repository of known issues
/// and best practices.
pub mod knowledge_base;