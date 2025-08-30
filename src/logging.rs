// src/logging.rs

use color_eyre::eyre::Result;
use directories::ProjectDirs;
use lazy_static::lazy_static;
use std::path::PathBuf;
use tracing_error::ErrorLayer;
use tracing_subscriber::{self, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

// Lazily evaluated static variables for logging configuration.
lazy_static! {
    /// The project name, derived from the crate name in `Cargo.toml` and converted to uppercase.
    /// Used for constructing environment variable names.
    pub static ref PROJECT_NAME: String = env!("CARGO_CRATE_NAME").to_uppercase().to_string();

    /// The name of the environment variable used to set the log level for the application.
    /// Constructed as `PROJECT_NAME_LOGLEVEL`.
    pub static ref LOG_ENV: String = format!("{}_LOGLEVEL", PROJECT_NAME.clone());

    /// The default filename for the log file, derived from the package name.
    pub static ref LOG_FILE: String = format!("{}.log", env!("CARGO_PKG_NAME"));
}

/// Returns the project-specific directories provided by the `directories` crate.
///
/// This helps in finding standard locations for data, config, and cache files
/// on different operating systems.
fn project_directory() -> Option<ProjectDirs> {
    ProjectDirs::from("com", "vanguard-rs", env!("CARGO_PKG_NAME"))
}

/// Determines the appropriate local data directory for the application.
///
/// It first tries to get the standard system-specific data directory.
/// If that fails (e.g., on unsupported systems), it defaults to a `.data`
/// subdirectory in the current working directory.
pub fn get_data_dir() -> PathBuf {
    if let Some(proj_dirs) = project_directory() {
        proj_dirs.data_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".data")
    }
}

/// Initializes the `tracing` subscriber for file-based logging.
///
/// This function sets up a log file in the application's data directory and configures
/// `tracing_subscriber` to write logs to it. The log level is determined by the
/// `RUST_LOG` or `PROJECT_NAME_LOGLEVEL` environment variables, defaulting to `info`
/// for the current crate if neither is set.
///
/// It also adds an `ErrorLayer` to enhance error reporting with span traces.
///
/// # Returns
///
/// * `Result<()>` - An empty `Ok` on successful initialization, or an `Err` if the
///   data directory or log file cannot be created.
pub fn initialize_logging() -> Result<()> {
    // Determine the data directory and create it if it doesn't exist.
    let directory = get_data_dir();
    std::fs::create_dir_all(&directory)?;

    // Set up the log file path and create the file.
    let log_path = directory.join(LOG_FILE.clone());
    let log_file = std::fs::File::create(log_path)?;

    // Determine the log level from environment variables, with a sensible default.
    let file_log_level = std::env::var("RUST_LOG")
        .or_else(|_| std::env::var(LOG_ENV.clone()))
        .unwrap_or_else(|_| format!("{}=info", env!("CARGO_CRATE_NAME")));

    // Configure the formatting layer for the file subscriber.
    let file_subscriber = tracing_subscriber::fmt::layer()
        .with_writer(log_file)      // Write logs to the created file.
        .with_target(false)         // Do not include the target path in the log output.
        .with_ansi(false)           // Disable ANSI color codes in the file.
        .with_filter(EnvFilter::new(file_log_level)); // Apply the determined log level filter.

    // Build and initialize the global tracing subscriber.
    tracing_subscriber::registry()
        .with(file_subscriber)
        .with(ErrorLayer::default()) // Augments logs with span trace information on errors.
        .init();

    Ok(())
}