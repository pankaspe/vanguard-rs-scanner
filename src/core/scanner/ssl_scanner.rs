// src/core/scanner/ssl_scanner.rs

// Import necessary dependencies for this module.
use crate::core::models::{AnalysisResult, CertificateInfo, Severity, SslResults};
use chrono::{DateTime, Utc};
use native_tls::TlsConnector;
use std::net::TcpStream;
use tokio::task::spawn_blocking;
use x509_parser::prelude::*;

/// Executes the complete SSL/TLS scan.
///
/// This function performs a blocking network operation (TCP connection and TLS handshake)
/// within a non-blocking context by using `tokio::task::spawn_blocking`. It attempts to
/// connect to the target on port 443, retrieve the peer's certificate, and parse it.
///
/// # Arguments
/// * `target` - The domain to scan (e.g., "example.com").
///
/// # Returns
/// An `SslResults` struct containing all raw certificate information and analysis findings.
pub async fn run_ssl_scan(target: &str) -> SslResults {
    let target_owned = target.to_string();
    spawn_blocking(move || {
        // Initialize the TLS connector.
        let connector = match TlsConnector::new() {
            Ok(c) => c,
            Err(e) => {
                let mut r = SslResults { error: Some(format!("TlsConnector Error: {}", e)), ..Default::default() };
                r.analysis = analyze_ssl_results(&r);
                return r;
            }
        };

        // Establish a raw TCP connection on port 443.
        let stream = match TcpStream::connect((&target_owned[..], 443)) {
            Ok(s) => s,
            Err(e) => {
                let mut r = SslResults { error: Some(format!("TCP Connection Error: {}", e)), ..Default::default() };
                r.analysis = analyze_ssl_results(&r);
                return r;
            }
        };

        // Perform the TLS handshake and get the TLS stream.
        let stream = match connector.connect(&target_owned, stream) {
            Ok(s) => s,
            Err(e) => {
                let mut r = SslResults { error: Some(format!("TLS Handshake Error: {}", e)), is_valid: false, ..Default::default() };
                r.analysis = analyze_ssl_results(&r);
                return r;
            }
        };

        // Retrieve the peer's certificate from the established TLS stream.
        let cert = match stream.peer_certificate() {
            Ok(Some(c)) => c,
            _ => {
                let mut r = SslResults { error: Some("Server did not provide a certificate.".to_string()), ..Default::default() };
                r.analysis = analyze_ssl_results(&r);
                return r;
            }
        };

        // Convert the certificate to DER format for parsing.
        let cert_der = match cert.to_der() {
            Ok(der) => der,
            Err(_) => return SslResults { error: Some("Could not convert certificate to DER format.".to_string()), ..Default::default() },
        };

        // Parse the raw DER certificate data using `x509-parser`.
        match parse_x509_certificate(&cert_der) {
            Ok((_, x509)) => {
                let validity = x509.validity();
                // Convert ASN1Time to Chrono's UTC DateTime.
                let not_after = asn1_time_to_chrono_utc(&validity.not_after);
                let not_before = asn1_time_to_chrono_utc(&validity.not_before);
                
                // Calculate days until expiry.
                let days_until_expiry = not_after.signed_duration_since(Utc::now()).num_days();
                
                // Determine if the certificate is currently valid based on dates.
                let is_valid = Utc::now() > not_before && Utc::now() < not_after;
                
                // Build the final results struct.
                let mut results = SslResults {
                    certificate_found: true,
                    is_valid,
                    certificate_info: Some(CertificateInfo {
                        subject_name: x509.subject().to_string(),
                        issuer_name: x509.issuer().to_string(),
                        not_before: Some(not_before),
                        not_after: Some(not_after),
                        days_until_expiry: Some(days_until_expiry),
                    }),
                    error: None,
                    analysis: Vec::new(),
                };
                
                // Run the analysis on the collected data.
                results.analysis = analyze_ssl_results(&results);
                results
            }
            Err(e) => SslResults { error: Some(format!("X.509 Certificate Parse Error: {}", e)), ..Default::default() },
        }
    })
    .await
    // Handle potential panics from the spawned blocking task.
    .unwrap_or_else(|e| SslResults { error: Some(format!("Task panicked: {}", e)), ..Default::default() })
}

/// Helper function to convert `ASN1Time` to `DateTime<Utc>`.
fn asn1_time_to_chrono_utc(time: &ASN1Time) -> DateTime<Utc> {
    DateTime::from_timestamp(time.timestamp(), 0).unwrap_or_default()
}

/// Analyzes the raw SSL scan results and generates actionable findings.
///
/// This function checks for common SSL/TLS issues such as handshake failures,
/// expired certificates, or certificates nearing expiration.
///
/// # Arguments
/// * `results` - A reference to the raw `SslResults` from the scan.
///
/// # Returns
/// A `Vec<AnalysisResult>` containing all identified security findings.
fn analyze_ssl_results(results: &SslResults) -> Vec<AnalysisResult> {
    let mut analyses = Vec::new();
    
    // Check for critical connection or certificate errors.
    if !results.certificate_found {
        if results.error.is_some() {
            analyses.push(AnalysisResult {
                severity: Severity::Critical,
                code: "SSL_HANDSHAKE_FAILED".to_string(),
            });
            return analyses;
        }
    }
    
    // If a certificate was found but is not valid (e.g., expired).
    if !results.is_valid {
         analyses.push(AnalysisResult {
            severity: Severity::Critical,
            code: "SSL_EXPIRED".to_string(),
        });
    }

    // Check if the certificate is nearing its expiration date.
    if let Some(days) = results.certificate_info.as_ref().and_then(|ci| ci.days_until_expiry) {
        if (0..=30).contains(&days) {
            analyses.push(AnalysisResult {
                severity: Severity::Warning,
                code: "SSL_EXPIRING_SOON".to_string(),
            });
        }
    }
    
    analyses
}