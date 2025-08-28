// src/core/scanner/ssl_scanner.rs

// Importiamo solo ciò che serve a questo modulo.
use crate::core::models::{AnalysisResult, CertificateInfo, Severity, SslResults};
use chrono::{DateTime, Utc};
use native_tls::TlsConnector;
use std::net::TcpStream;
use tokio::task::spawn_blocking;
use x509_parser::prelude::*;

/// Esegue la scansione SSL/TLS completa.
pub async fn run_ssl_scan(target: &str) -> SslResults {
    let target_owned = target.to_string();
    spawn_blocking(move || {
        let connector = match TlsConnector::new() {
            Ok(c) => c,
            Err(e) => {
                let mut r = SslResults { error: Some(format!("TlsConnector Error: {}", e)), ..Default::default() };
                r.analysis = analyze_ssl_results(&r);
                return r;
            }
        };
        let stream = match TcpStream::connect((&target_owned[..], 443)) {
            Ok(s) => s,
            Err(e) => {
                let mut r = SslResults { error: Some(format!("TCP Connection Error: {}", e)), ..Default::default() };
                r.analysis = analyze_ssl_results(&r);
                return r;
            }
        };
        let stream = match connector.connect(&target_owned, stream) {
            Ok(s) => s,
            Err(e) => {
                let mut r = SslResults { error: Some(format!("TLS Handshake Error: {}", e)), is_valid: false, ..Default::default() };
                r.analysis = analyze_ssl_results(&r);
                return r;
            }
        };
        let cert = match stream.peer_certificate() {
            Ok(Some(c)) => c,
            _ => {
                let mut r = SslResults { error: Some("Server did not provide a certificate.".to_string()), ..Default::default() };
                r.analysis = analyze_ssl_results(&r);
                return r;
            }
        };
        let cert_der = match cert.to_der() {
            Ok(der) => der,
            Err(_) => return SslResults { error: Some("Could not convert certificate to DER format.".to_string()), ..Default::default() },
        };
        match parse_x509_certificate(&cert_der) {
            Ok((_, x509)) => {
                let validity = x509.validity();
                let not_after = asn1_time_to_chrono_utc(&validity.not_after);
                let not_before = asn1_time_to_chrono_utc(&validity.not_before);
                let days_until_expiry = not_after.signed_duration_since(Utc::now()).num_days();
                let is_valid = Utc::now() > not_before && Utc::now() < not_after;
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
                results.analysis = analyze_ssl_results(&results);
                results
            }
            Err(e) => SslResults { error: Some(format!("X.509 Certificate Parse Error: {}", e)), ..Default::default() },
        }
    })
    .await
    .unwrap_or_else(|e| SslResults { error: Some(format!("Task panicked: {}", e)), ..Default::default() })
}

/// Converte ASN1Time in DateTime<Utc>.
fn asn1_time_to_chrono_utc(time: &ASN1Time) -> DateTime<Utc> {
    DateTime::from_timestamp(time.timestamp(), 0).unwrap_or_default()
}

/// Analizza i risultati grezzi della scansione SSL.
fn analyze_ssl_results(results: &SslResults) -> Vec<AnalysisResult> {
    let mut analyses = Vec::new();
    if !results.certificate_found {
        if results.error.is_some() {
            analyses.push(AnalysisResult {
                severity: Severity::Critical,
                code: "SSL_HANDSHAKE_FAILED".to_string(),
            });
            return analyses;
        }
    }
    if !results.is_valid {
         analyses.push(AnalysisResult {
            severity: Severity::Critical,
            code: "SSL_EXPIRED".to_string(),
        });
    }
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