// src/core/scanner/ssl_scanner.rs

use crate::core::models::{AnalysisFinding, CertificateInfo, Severity, SslData, SslResults, ScanResult};
use chrono::{DateTime, Utc};
use native_tls::TlsConnector;
use std::net::TcpStream;
use tokio::task::spawn_blocking;
use x509_parser::prelude::*;

/// Main function to orchestrate the SSL/TLS scanning process.
/// It offloads the blocking network operations to a separate thread.
///
/// # Arguments
/// * `target` - A string slice representing the host to scan.
///
/// # Returns
/// An `SslResults` struct containing the scan data and analysis findings.
pub async fn run_ssl_scan(target: &str) -> SslResults {
    // The target string must be moved into the new thread, so we create an owned copy.
    let target_owned = target.to_string();

    // The `native_tls` and `TcpStream` operations are blocking, so we use `spawn_blocking`
    // to prevent blocking the main Tokio event loop. This is a crucial best practice.
    let scan_result = spawn_blocking(move || {
        perform_tls_scan(&target_owned)
    }).await
      // Handle potential panics from the blocking task, converting a `JoinError`
      // into a formatted string error for consistent error handling.
      .unwrap_or_else(|e| Err(format!("Task panicked: {}", e)));

    // Initialize the results struct.
    let mut results = SslResults {
        scan: scan_result,
        analysis: Vec::new(),
    };

    // Perform the analysis based on the scan results.
    results.analysis = analyze_ssl_results(&results);
    results
}

/// Performs a TLS connection and retrieves the peer's certificate for analysis.
///
/// # Arguments
/// * `target` - The host to connect to.
///
/// # Returns
/// A `ScanResult<SslData>` which is a `Result<Option<SslData>, String>`.
/// `Ok(Some(...))` indicates a successful scan with data.
/// `Ok(None)` indicates a successful connection but no certificate.
/// `Err(...)` indicates a failure.
fn perform_tls_scan(target: &str) -> ScanResult<SslData> {
    // A more robust approach would be to use a custom error type instead of
    // `format!` for better error propagation and debugging.
    let connector = TlsConnector::new().map_err(|e| format!("TlsConnector Error: {}", e))?;
    
    // Defaulting to port 443 is a good assumption for HTTPS.
    let stream = TcpStream::connect((target, 443)).map_err(|e| format!("TCP Connection Error: {}", e))?;
    
    // The TLS handshake is performed here.
    let stream = connector.connect(target, stream).map_err(|e| format!("TLS Handshake Error: {}", e))?;

    // Attempt to get the peer's certificate.
    let cert = match stream.peer_certificate() {
        Ok(Some(c)) => c,
        // No certificate found is a valid, non-error state.
        Ok(None) => return Ok(None),
        Err(e) => return Err(format!("Could not get peer certificate: {}", e)),
    };

    // Convert the certificate to DER format and parse it for detailed info.
    let cert_der = cert.to_der().map_err(|e| format!("Could not convert certificate to DER: {}", e))?;
    let (_, x509) = parse_x509_certificate(&cert_der).map_err(|e| format!("X.509 Parse Error: {}", e))?;
    
    let validity = x509.validity();
    let not_after = asn1_time_to_chrono_utc(&validity.not_after);
    let not_before = asn1_time_to_chrono_utc(&validity.not_before);
    let days_until_expiry = not_after.signed_duration_since(Utc::now()).num_days();
    
    // Determine if the certificate is currently valid based on its dates.
    let is_valid = Utc::now() > not_before && Utc::now() < not_after;

    // Construct and return the successful result with certificate data.
    Ok(Some(SslData {
        is_valid,
        certificate_info: CertificateInfo {
            subject_name: x509.subject().to_string(),
            issuer_name: x509.issuer().to_string(),
            not_before,
            not_after,
            days_until_expiry,
        },
    }))
}

/// Helper to convert `ASN1Time` to a `DateTime<Utc>`.
///
/// # Arguments
/// * `time` - The `ASN1Time` to convert.
///
/// # Returns
/// A `DateTime<Utc>` representing the same point in time.
fn asn1_time_to_chrono_utc(time: &ASN1Time) -> DateTime<Utc> {
    // Using `unwrap_or_default()` is safe here, but in a library, you might
    // want to return a `Result` to handle parsing failures more explicitly.
    DateTime::from_timestamp(time.timestamp(), 0).unwrap_or_default()
}

/// Analyzes SSL scan results and generates findings.
///
/// # Arguments
/// * `results` - A reference to the `SslResults` struct from the scan.
///
/// # Returns
/// A vector of `AnalysisFinding` structs.
fn analyze_ssl_results(results: &SslResults) -> Vec<AnalysisFinding> {
    let mut analyses = Vec::new();

    // Use a match statement for clean and exhaustive result handling.
    match &results.scan {
        Err(_) => {
            // A critical finding for any scan failure.
            analyses.push(AnalysisFinding::new(Severity::Critical, "SSL_HANDSHAKE_FAILED"));
        },
        Ok(None) => {
            // A warning for a successful connection with no certificate.
            analyses.push(AnalysisFinding::new(Severity::Warning, "SSL_NO_CERTIFICATE_FOUND"));
        },
        Ok(Some(ssl_data)) => {
            // Check for an expired certificate and add a critical finding.
            if !ssl_data.is_valid {
                analyses.push(AnalysisFinding::new(Severity::Critical, "SSL_EXPIRED"));
            }

            // Check for an expiring certificate and add a warning.
            let days_left = ssl_data.certificate_info.days_until_expiry;
            if (0..=30).contains(&days_left) {
                analyses.push(AnalysisFinding::new(Severity::Warning, "SSL_EXPIRING_SOON"));
            }
        }
    }
    
    analyses
}