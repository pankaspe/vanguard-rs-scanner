// src/core/scanner/headers_scanner.rs

use tracing::{debug, error, info, warn};
use crate::core::models::{AnalysisFinding, HeaderData, HeadersResults, Severity, ScanResult};
use reqwest::header::HeaderMap;

/// Checks for the presence and validity of a specific HTTP header in a `HeaderMap`.
///
/// # Arguments
/// * `headers` - A reference to the `HeaderMap` from the HTTP response.
/// * `name` - The name of the header to check (e.g., "content-security-policy").
///
/// # Returns
/// A `ScanResult<HeaderData>` which is `Ok(Some(HeaderData))` if the header is found,
/// `Ok(None)` if it's not found, or `Err` in case of a lookup error (though this
/// is less common with `reqwest`). It also handles non-UTF-8 header values gracefully.
fn check_header(headers: &HeaderMap, name: &str) -> ScanResult<HeaderData> {
    debug!(header_name = name, "Checking for header.");
    if let Some(value) = headers.get(name) {
        match value.to_str() {
            Ok(s) => {
                debug!(header_name = name, value = s, "Header found.");
                Ok(Some(HeaderData { value: s.to_string() }))
            },
            Err(_) => {
                warn!(header_name = name, "Header found but contained invalid UTF-8.");
                // Return a placeholder value to indicate presence without valid content.
                Ok(Some(HeaderData { value: "[Invalid UTF-8]".to_string() }))
            },
        }
    } else {
        debug!(header_name = name, "Header not found.");
        Ok(None)
    }
}

/// Runs a scan for common security-related HTTP headers.
///
/// This function sends an HTTP GET request to the target, retrieves the response headers,
/// and then checks for the presence of HSTS, CSP, X-Frame-Options, and
/// X-Content-Type-Options headers.
///
/// # Arguments
/// * `target` - The domain or IP address to scan.
///
/// # Returns
/// A `HeadersResults` struct containing the found headers and analysis findings.
pub async fn run_headers_scan(target: &str) -> HeadersResults {
    info!(target, "Starting headers scan.");

    let client = match reqwest::Client::builder()
        .user_agent("VanguardRS/0.1")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            // If the client cannot be built, it's a critical failure for this scan.
            error!(error = %e, "Failed to build HTTP client for headers scan.");
            let mut results = HeadersResults::default();
            results.error = Some(format!("Failed to build HTTP client: {}", e));
            results.analysis = analyze_headers_results(&results);
            return results;
        }
    };

    let url = format!("https://{}", target);

    match client.get(&url).send().await {
        Ok(response) => {
            info!(status = %response.status(), "Received HTTP response for headers scan.");
            let headers = response.headers();
            // Check for each of the target security headers.
            let mut results = HeadersResults {
                error: None,
                hsts: check_header(headers, "strict-transport-security"),
                csp: check_header(headers, "content-security-policy"),
                x_frame_options: check_header(headers, "x-frame-options"),
                x_content_type_options: check_header(headers, "x-content-type-options"),
                analysis: Vec::new(),
            };
            results.analysis = analyze_headers_results(&results);
            info!(findings = %results.analysis.len(), "Headers scan finished.");
            results
        }
        Err(e) => {
            // If the HTTP request fails, populate the error field and analyze.
            error!(url = %url, error = %e, "HTTP request failed for headers scan.");
            let mut results = HeadersResults::default();
            results.error = Some(format!("HTTP request failed: {}", e));
            results.analysis = analyze_headers_results(&results);
            results
        }
    }
}

/// Analyzes the collected header data to generate security findings.
///
/// This function checks for the absence of key security headers and creates findings
/// for each one that is missing.
///
/// # Arguments
/// * `results` - A reference to the `HeadersResults` from the scan.
///
/// # Returns
/// A vector of `AnalysisFinding` structs.
fn analyze_headers_results(results: &HeadersResults) -> Vec<AnalysisFinding> {
    debug!("Analyzing collected header data.");
    let mut analyses = Vec::new();

    // If there was a fundamental error in the request, flag it as a critical issue.
    if results.error.is_some() {
        debug!("Request error detected, adding HEADERS_REQUEST_FAILED finding.");
        analyses.push(AnalysisFinding::new(Severity::Critical, "HEADERS_REQUEST_FAILED"));
        return analyses;
    }

    // Check for missing HSTS header.
    if let Ok(None) = &results.hsts {
        debug!("HSTS header missing, adding Warning finding.");
        analyses.push(AnalysisFinding::new(Severity::Warning, "HEADERS_HSTS_MISSING"));
    }

    // Check for missing CSP header.
    if let Ok(None) = &results.csp {
        debug!("CSP header missing, adding Warning finding.");
        analyses.push(AnalysisFinding::new(Severity::Warning, "HEADERS_CSP_MISSING"));
    }

    // Check for missing X-Frame-Options header.
    if let Ok(None) = &results.x_frame_options {
        debug!("X-Frame-Options header missing, adding Warning finding.");
        analyses.push(AnalysisFinding::new(Severity::Warning, "HEADERS_X_FRAME_OPTIONS_MISSING"));
    }

    // Check for missing X-Content-Type-Options header.
    if let Ok(None) = &results.x_content_type_options {
        debug!("X-Content-Type-Options header missing, adding Info finding.");
        analyses.push(AnalysisFinding::new(Severity::Info, "HEADERS_X_CONTENT_TYPE_OPTIONS_MISSING"));
    }

    analyses
}