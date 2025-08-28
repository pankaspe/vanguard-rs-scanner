// src/core/scanner/headers_scanner.rs

use crate::core::models::{AnalysisResult, HeaderInfo, HeadersResults, Severity};
use reqwest::header::HeaderMap;

/// Helper function to check for the presence of a specific header.
fn check_header(headers: &HeaderMap, name: &str) -> Option<HeaderInfo> {
    if let Some(value) = headers.get(name) {
        Some(HeaderInfo {
            found: true,
            value: value.to_str().ok().map(String::from),
        })
    } else {
        Some(HeaderInfo { found: false, value: None })
    }
}

/// The main function that orchestrates the security headers scan.
pub async fn run_headers_scan(target: &str) -> HeadersResults {
    // reqwest is fully async, so no need for spawn_blocking here.
    let client = match reqwest::Client::builder()
        .user_agent("VanguardRS/0.1")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
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
            let mut results = HeadersResults {
                error: None,
                hsts: check_header(headers, "strict-transport-security"),
                csp: check_header(headers, "content-security-policy"),
                x_frame_options: check_header(headers, "x-frame-options"),
                x_content_type_options: check_header(headers, "x-content-type-options"),
                analysis: Vec::new(),
            };
            results.analysis = analyze_headers_results(&results);
            results
        }
        Err(e) => {
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
fn analyze_headers_results(results: &HeadersResults) -> Vec<AnalysisResult> {
    let mut analyses = Vec::new();

    if results.error.is_some() {
        analyses.push(AnalysisResult {
            severity: Severity::Critical,
            code: "HEADERS_REQUEST_FAILED".to_string(),
        });
        return analyses;
    }

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