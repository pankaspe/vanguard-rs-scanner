// src/core/scanner/mod.rs

// This file acts as the public interface for the `scanner` module.
// It declares and makes all sub-scanner modules public.
pub mod dns_scanner;
pub mod fingerprint_scanner;
pub mod headers_scanner;
pub mod ssl_scanner;

// Imports the necessary data structures and functions from the crate's core modules.
use crate::core::models::ScanReport;
use self::dns_scanner::run_dns_scan;
use self::fingerprint_scanner::run_fingerprint_scan;
use self::headers_scanner::run_headers_scan;
use self::ssl_scanner::run_ssl_scan;

/// Executes all available scans in parallel and aggregates the results into a single report.
///
/// This is the main orchestration function for the scanner. It leverages `tokio::join!`
/// to run each specialized scanner (`dns_scanner`, `ssl_scanner`, `headers_scanner`,
/// and `fingerprint_scanner`) concurrently. This parallel execution is crucial for
/// minimizing the overall scanning time.
///
/// # Arguments
///
/// * `target` - The domain or host to be scanned (e.g., "example.com").
///
/// # Returns
///
/// A `ScanReport` struct containing the results from all individual scans.
pub async fn run_full_scan(target: &str) -> ScanReport {
    // Use `tokio::join!` to run the scans concurrently.
    // The macro waits for all futures to complete before proceeding.
    let (dns_results, ssl_results, headers_results, fingerprint_results) = tokio::join!(
        run_dns_scan(target),
        run_ssl_scan(target),
        run_headers_scan(target),
        run_fingerprint_scan(target)
    );
    
    // Construct and return the final ScanReport with the aggregated results.
    // The previous version incorrectly wrapped each field in `Some()`. This is
    // now corrected to directly use the returned structs, matching the `ScanReport`
    // definition.
    ScanReport {
        dns_results,
        ssl_results,
        headers_results,
        fingerprint_results,
    }
}