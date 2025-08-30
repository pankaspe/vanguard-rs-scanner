// src/core/scanner/headers_scanner.rs

// NUOVO: Importiamo i macro di logging necessari.
use tracing::{debug, error, info, warn};

use crate::core::models::{AnalysisFinding, HeaderData, HeadersResults, Severity, ScanResult};
use reqwest::header::HeaderMap;

fn check_header(headers: &HeaderMap, name: &str) -> ScanResult<HeaderData> {
    // NUOVO: Logghiamo quale header stiamo cercando.
    debug!(header_name = name, "Checking for header.");
    if let Some(value) = headers.get(name) {
        match value.to_str() {
            Ok(s) => {
                // NUOVO: Logghiamo il successo nel trovare e leggere l'header.
                debug!(header_name = name, value = s, "Header found.");
                Ok(Some(HeaderData { value: s.to_string() }))
            },
            Err(_) => {
                // NUOVO: Logghiamo un avviso se il valore dell'header non è UTF-8 valido.
                warn!(header_name = name, "Header found but contained invalid UTF-8.");
                Ok(Some(HeaderData { value: "[Invalid UTF-8]".to_string() }))
            },
        }
    } else {
        // NUOVO: Logghiamo esplicitamente che l'header non è stato trovato.
        debug!(header_name = name, "Header not found.");
        Ok(None)
    }
}

pub async fn run_headers_scan(target: &str) -> HeadersResults {
    // NUOVO: Logghiamo l'inizio della scansione degli header.
    info!(target, "Starting headers scan.");

    let client = match reqwest::Client::builder()
        .user_agent("VanguardRS/0.1")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            // NUOVO: Logghiamo l'errore critico nella creazione del client.
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
            // NUOVO: Logghiamo lo status code della risposta.
            info!(status = %response.status(), "Received HTTP response for headers scan.");
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
            // NUOVO: Logghiamo il completamento della scansione.
            info!(findings = %results.analysis.len(), "Headers scan finished.");
            results
        }
        Err(e) => {
            // NUOVO: Logghiamo l'errore critico della richiesta HTTP.
            error!(url = %url, error = %e, "HTTP request failed for headers scan.");
            let mut results = HeadersResults::default();
            results.error = Some(format!("HTTP request failed: {}", e));
            results.analysis = analyze_headers_results(&results);
            results
        }
    }
}

fn analyze_headers_results(results: &HeadersResults) -> Vec<AnalysisFinding> {
    // NUOVO: Logghiamo l'inizio della fase di analisi.
    debug!("Analyzing collected header data.");
    let mut analyses = Vec::new();

    if results.error.is_some() {
        // NUOVO: Logghiamo perché stiamo creando un finding critico.
        debug!("Request error detected, adding HEADERS_REQUEST_FAILED finding.");
        analyses.push(AnalysisFinding::new(Severity::Critical, "HEADERS_REQUEST_FAILED"));
        return analyses;
    }

    if let Ok(None) = &results.hsts {
        debug!("HSTS header missing, adding Warning finding.");
        analyses.push(AnalysisFinding::new(Severity::Warning, "HEADERS_HSTS_MISSING"));
    }

    if let Ok(None) = &results.csp {
        debug!("CSP header missing, adding Warning finding.");
        analyses.push(AnalysisFinding::new(Severity::Warning, "HEADERS_CSP_MISSING"));
    }

    if let Ok(None) = &results.x_frame_options {
        debug!("X-Frame-Options header missing, adding Warning finding.");
        analyses.push(AnalysisFinding::new(Severity::Warning, "HEADERS_X_FRAME_OPTIONS_MISSING"));
    }

    if let Ok(None) = &results.x_content_type_options {
        debug!("X-Content-Type-Options header missing, adding Info finding.");
        analyses.push(AnalysisFinding::new(Severity::Info, "HEADERS_X_CONTENT_TYPE_OPTIONS_MISSING"));
    }

    analyses
}