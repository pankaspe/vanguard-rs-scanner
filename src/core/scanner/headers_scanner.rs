// src/core/scanner/headers_scanner.rs

use crate::core::models::{AnalysisResult, HeaderInfo, HeadersResults, Severity};
use reqwest::header::HeaderMap;

/// Helper function to check for the presence of a specific header.
///
/// This function simplifies the logic of checking if a header exists and
/// extracting its value.
///
/// # Arguments
/// * `headers` - A reference to the `HeaderMap` from the HTTP response.
/// * `name` - The name of the header to check (e.g., "strict-transport-security").
///
/// # Returns
/// An `Option<HeaderInfo>` containing the result of the check.
fn check_header(headers: &HeaderMap, name: &str) -> Option<HeaderInfo> {
    if let Some(value) = headers.get(name) {
        Some(HeaderInfo {
            found: true,
            // Attempt to convert the header value to a string.
            value: value.to_str().ok().map(String::from),
        })
    } else {
        Some(HeaderInfo { found: false, value: None })
    }
}

/// The main function that orchestrates the security headers scan.
///
/// It performs a single asynchronous HTTP GET request to the target URL,
/// inspects the response headers, and then analyzes them for common security
/// header misconfigurations or absences.
///
/// # Arguments
/// * `target` - The domain to scan (e.g., "example.com").
///
/// # Returns
/// A `HeadersResults` struct containing the raw header info and analysis findings.
pub async fn run_headers_scan(target: &str) -> HeadersResults {
    // reqwest is fully async, so no need for spawn_blocking here.
    let client = match reqwest::Client::builder()
        .user_agent("VanguardRS/0.1")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            // Handle client build failure immediately and return an error result.
            let mut results = HeadersResults {
                error: Some(format!("Failed to build HTTP client: {}", e)),
                ..Default::default()
            };
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
            let mut results = HeadersResults {
                error: Some(format!("HTTP request failed: {}", e)),
                ..Default::default()
            };
            results.analysis = analyze_headers_results(&results);
            results
        }
    }
}

/// Analyzes the raw header scan results and produces a list of recommendations.
///
/// This function checks for the absence of key security headers and translates
/// those findings into actionable `AnalysisResult` structs.
///
/// # Arguments
/// * `results` - A reference to the `HeadersResults` from the scan.
///
/// # Returns
/// A `Vec<AnalysisResult>` containing all identified security findings.
fn analyze_headers_results(results: &HeadersResults) -> Vec<AnalysisResult> {
    let mut analyses = Vec::new();

    // If there was a request error, report it as a critical finding and exit early.
    if results.error.is_some() {
        analyses.push(AnalysisResult {
            severity: Severity::Critical,
            code: "HEADERS_REQUEST_FAILED".to_string(),
        });
        return analyses;
    }

    // Check for the absence of each security header and add a finding if missing.
    if let Some(hsts) = &results.hsts {
        if !hsts.found {
            analyses.push(AnalysisResult {
                severity: Severity::Warning,
                code: "HEADERS_HSTS_MISSING".to_string(),
            });
        }
    }

    if let Some(csp) = &results.csp {
        if !csp.found {
            analyses.push(AnalysisResult {
                severity: Severity::Warning,
                code: "HEADERS_CSP_MISSING".to_string(),
            });
        }
    }

    if let Some(xfo) = &results.x_frame_options {
        if !xfo.found {
            analyses.push(AnalysisResult {
                severity: Severity::Warning,
                code: "HEADERS_X_FRAME_OPTIONS_MISSING".to_string(),
            });
        }
    }

    if let Some(xcto) = &results.x_content_type_options {
        if !xcto.found {
            analyses.push(AnalysisResult {
                severity: Severity::Info,
                code: "HEADERS_X_CONTENT_TYPE_OPTIONS_MISSING".to_string(),
            });
        }
    }

    analyses
}