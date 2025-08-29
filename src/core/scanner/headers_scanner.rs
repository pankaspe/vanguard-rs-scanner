// src/core/scanner/headers_scanner.rs

use crate::core::models::{AnalysisFinding, HeaderData, HeadersResults, Severity, ScanResult};
use reqwest::header::HeaderMap;

/// Checks for the presence of a specific header in an HTTP response.
///
/// This function attempts to retrieve a header by name and handles the
/// conversion of its value to a `String`, providing a consistent result.
///
/// # Arguments
/// * `headers` - A reference to the `HeaderMap` from the HTTP response.
/// * `name` - The name of the header to check.
///
/// # Returns
/// A `ScanResult<HeaderData>` which is an `Ok(Option<HeaderData>)`.
/// `Ok(Some(HeaderData))` indicates the header was found.
/// `Ok(None)` indicates the header was not found.
/// The `Err` variant is reserved for scanner-level errors.
fn check_header(headers: &HeaderMap, name: &str) -> ScanResult<HeaderData> {
    if let Some(value) = headers.get(name) {
        // Attempt to convert the header value to a UTF-8 string.
        match value.to_str() {
            Ok(s) => Ok(Some(HeaderData { value: s.to_string() })),
            // Handle non-UTF-8 header values gracefully.
            Err(_) => Ok(Some(HeaderData { value: "[Invalid UTF-8]".to_string() })),
        }
    } else {
        // If the header is not present, return None.
        Ok(None)
    }
}

/// Orchestrates the security headers scan for a given target.
///
/// This function performs an asynchronous HTTP GET request to the target URL,
/// inspects the response headers, and then analyzes them for common security
/// misconfigurations or absences.
///
/// # Arguments
/// * `target` - The domain to scan (e.g., "example.com").
///
/// # Returns
/// A `HeadersResults` struct containing the raw header information and analysis findings.
pub async fn run_headers_scan(target: &str) -> HeadersResults {
    // Build the reqwest client with a custom user agent.
    let client = match reqwest::Client::builder()
        .user_agent("VanguardRS/0.1")
        .build()
    {
        Ok(c) => c,
        // If client build fails, return an error result immediately.
        Err(e) => {
            let mut results = HeadersResults::default();
            results.error = Some(format!("Failed to build HTTP client: {}", e));
            results.analysis = analyze_headers_results(&results);
            return results;
        }
    };

    let url = format!("https://{}", target);

    match client.get(&url).send().await {
        Ok(response) => {
            let headers = response.headers();
            // Populate the results struct with the raw header information.
            let mut results = HeadersResults {
                error: None,
                hsts: check_header(headers, "strict-transport-security"),
                csp: check_header(headers, "content-security-policy"),
                x_frame_options: check_header(headers, "x-frame-options"),
                x_content_type_options: check_header(headers, "x-content-type-options"),
                analysis: Vec::new(),
            };
            // Analyze the results and add findings.
            results.analysis = analyze_headers_results(&results);
            results
        }
        Err(e) => {
            // Handle HTTP request failure and return an error result.
            let mut results = HeadersResults::default();
            results.error = Some(format!("HTTP request failed: {}", e));
            results.analysis = analyze_headers_results(&results);
            results
        }
    }
}

/// Analyzes the raw header scan results to produce a list of security findings.
///
/// This function checks for the absence of key security headers and translates
/// those findings into actionable `AnalysisFinding` structs.
///
/// # Arguments
/// * `results` - A reference to the `HeadersResults` from the scan.
///
/// # Returns
/// A `Vec<AnalysisFinding>` containing all identified security findings.
fn analyze_headers_results(results: &HeadersResults) -> Vec<AnalysisFinding> {
    let mut analyses = Vec::new();

    // If there was a request error, report it as a critical finding and exit early.
    if results.error.is_some() {
        analyses.push(AnalysisFinding::new(Severity::Critical, "HEADERS_REQUEST_FAILED"));
        return analyses;
    }

    // Check for the absence of each security header and add a finding if missing.
    // The pattern `Ok(None)` elegantly handles both the `Ok` and `None` cases.
    if let Ok(None) = &results.hsts {
        analyses.push(AnalysisFinding::new(Severity::Warning, "HEADERS_HSTS_MISSING"));
    }

    if let Ok(None) = &results.csp {
        analyses.push(AnalysisFinding::new(Severity::Warning, "HEADERS_CSP_MISSING"));
    }

    if let Ok(None) = &results.x_frame_options {
        analyses.push(AnalysisFinding::new(Severity::Warning, "HEADERS_X_FRAME_OPTIONS_MISSING"));
    }

    if let Ok(None) = &results.x_content_type_options {
        analyses.push(AnalysisFinding::new(Severity::Info, "HEADERS_X_CONTENT_TYPE_OPTIONS_MISSING"));
    }

    analyses
}