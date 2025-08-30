// src/core/scanner/ssl_scanner.rs

use tracing::{debug, error, info};
use crate::core::models::{AnalysisFinding, CertificateInfo, Severity, SslData, SslResults, ScanResult};
use chrono::{DateTime, Utc};
use native_tls::TlsConnector;
use std::net::TcpStream;
use tokio::task::spawn_blocking;
use x509_parser::prelude::*;

/// Runs an SSL/TLS scan against the specified target.
///
/// This function initiates a TLS connection to the target on port 443. Since the underlying
/// networking operations are blocking, it spawns them on a dedicated blocking thread
/// to avoid stalling the async runtime. It then analyzes the retrieved certificate for
/// validity and potential issues.
///
/// # Arguments
/// * `target` - The domain or IP address to scan.
///
/// # Returns
/// An `SslResults` struct containing the certificate details and analysis findings.
pub async fn run_ssl_scan(target: &str) -> SslResults {
    info!(target, "Starting SSL/TLS scan.");
    let target_owned = target.to_string();

    debug!("Spawning blocking task for TLS connection.");
    // Offload the blocking network I/O to a separate thread pool.
    let scan_result = spawn_blocking(move || {
        perform_tls_scan(&target_owned)
    }).await
      .unwrap_or_else(|e| {
          // This case handles a panic within the spawned task, which is a severe error.
          error!(panic = %e, "Blocking SSL scan task panicked!");
          Err(format!("Task panicked: {}", e))
      });

    debug!("SSL scan task finished, starting analysis.");
    let mut results = SslResults {
        scan: scan_result,
        analysis: Vec::new(),
    };

    results.analysis = analyze_ssl_results(&results);

    info!(findings = %results.analysis.len(), "SSL/TLS scan finished.");
    results
}

/// Performs the actual blocking TLS connection and certificate parsing.
///
/// This function handles the entire process of establishing a TCP connection,
/// performing the TLS handshake, and parsing the X.509 certificate.
///
/// # Arguments
/// * `target` - The domain name to connect to.
///
/// # Returns
/// A `ScanResult<SslData>` containing the extracted certificate information or an error string.
fn perform_tls_scan(target: &str) -> ScanResult<SslData> {
    debug!(target, "Performing TLS connection and handshake.");

    let connector = TlsConnector::new().map_err(|e| {
        error!(error = %e, "Failed to create TlsConnector");
        format!("TlsConnector Error: {}", e)
    })?;
    
    debug!(target, "Connecting TCP stream to port 443.");
    let stream = TcpStream::connect((target, 443)).map_err(|e| {
        error!(error = %e, "TCP connection failed");
        format!("TCP Connection Error: {}", e)
    })?;
    
    debug!(target, "Performing TLS handshake.");
    let stream = connector.connect(target, stream).map_err(|e| {
        error!(error = %e, "TLS handshake failed");
        format!("TLS Handshake Error: {}", e)
    })?;

    // Retrieve the server's certificate from the TLS session.
    let cert = match stream.peer_certificate() {
        Ok(Some(c)) => {
            debug!("Peer certificate found.");
            c
        },
        Ok(None) => {
            debug!("TLS connection successful, but no peer certificate provided.");
            return Ok(None) // It's a valid state, not an error.
        },
        Err(e) => {
            error!(error = %e, "Failed to retrieve peer certificate from stream");
            return Err(format!("Could not get peer certificate: {}", e))
        },
    };

    // Convert the certificate to DER format for parsing.
    let cert_der = cert.to_der().map_err(|e| {
        error!(error = %e, "Failed to convert certificate to DER format");
        format!("Could not convert certificate to DER: {}", e)
    })?;
    
    // Parse the DER-encoded certificate into a structured X.509 object.
    let (_, x509) = parse_x509_certificate(&cert_der).map_err(|e| {
        error!(error = %e, "Failed to parse X.509 certificate");
        format!("X.509 Parse Error: {}", e)
    })?;

    info!(subject = %x509.subject(), issuer = %x509.issuer(), "Successfully parsed certificate.");
    
    // Extract validity information from the certificate.
    let validity = x509.validity();
    let not_after = asn1_time_to_chrono_utc(&validity.not_after);
    let not_before = asn1_time_to_chrono_utc(&validity.not_before);
    let days_until_expiry = not_after.signed_duration_since(Utc::now()).num_days();
    
    // Check if the current date is within the certificate's validity period.
    let is_valid = Utc::now() > not_before && Utc::now() < not_after;

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

/// A helper function to convert `x509_parser`'s `ASN1Time` to a `chrono::DateTime<Utc>`.
fn asn1_time_to_chrono_utc(time: &ASN1Time) -> DateTime<Utc> {
    DateTime::from_timestamp(time.timestamp(), 0).unwrap_or_default()
}

/// Analyzes the results of the SSL scan to generate security findings.
///
/// This function checks for handshake failures, missing certificates, expired certificates,
/// and certificates that are expiring soon.
///
/// # Arguments
/// * `results` - A reference to the `SslResults` from the scan.
///
/// # Returns
/// A vector of `AnalysisFinding` structs.
fn analyze_ssl_results(results: &SslResults) -> Vec<AnalysisFinding> {
    debug!("Analyzing SSL scan results.");
    let mut analyses = Vec::new();

    match &results.scan {
        // A failure at the connection/handshake level is a critical issue.
        Err(_) => {
            debug!("Scan failed, adding SSL_HANDSHAKE_FAILED finding.");
            analyses.push(AnalysisFinding::new(Severity::Critical, "SSL_HANDSHAKE_FAILED"));
        },
        // Successfully connected, but the server didn't provide a certificate.
        Ok(None) => {
            debug!("No certificate found, adding SSL_NO_CERTIFICATE_FOUND finding.");
            analyses.push(AnalysisFinding::new(Severity::Warning, "SSL_NO_CERTIFICATE_FOUND"));
        },
        // A certificate was found; now analyze its properties.
        Ok(Some(ssl_data)) => {
            if !ssl_data.is_valid {
                debug!(expiry_date = %ssl_data.certificate_info.not_after, "Certificate is expired, adding SSL_EXPIRED finding.");
                analyses.push(AnalysisFinding::new(Severity::Critical, "SSL_EXPIRED"));
            }

            // Flag certificates that are expiring within the next 30 days.
            let days_left = ssl_data.certificate_info.days_until_expiry;
            if (0..=30).contains(&days_left) {
                debug!(days_left, "Certificate is expiring soon, adding SSL_EXPIRING_SOON finding.");
                analyses.push(AnalysisFinding::new(Severity::Warning, "SSL_EXPIRING_SOON"));
            }
        }
    }
    
    analyses
}