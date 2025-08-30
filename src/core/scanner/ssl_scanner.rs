// src/core/scanner/ssl_scanner.rs

// NUOVO: Importiamo i macro di logging.
use tracing::{debug, error, info};

use crate::core::models::{AnalysisFinding, CertificateInfo, Severity, SslData, SslResults, ScanResult};
use chrono::{DateTime, Utc};
use native_tls::TlsConnector;
use std::net::TcpStream;
use tokio::task::spawn_blocking;
use x509_parser::prelude::*;

pub async fn run_ssl_scan(target: &str) -> SslResults {
    // NUOVO: Logghiamo l'inizio della scansione SSL.
    info!(target, "Starting SSL/TLS scan.");
    let target_owned = target.to_string();

    // NUOVO: Logghiamo l'intenzione di spostare l'operazione su un thread bloccante.
    debug!("Spawning blocking task for TLS connection.");
    let scan_result = spawn_blocking(move || {
        perform_tls_scan(&target_owned)
    }).await
      .unwrap_or_else(|e| {
          // NUOVO: Logghiamo se il task va in panic, che è un errore grave.
          error!(panic = %e, "Blocking SSL scan task panicked!");
          Err(format!("Task panicked: {}", e))
      });

    // NUOVO: Logghiamo il completamento del task e l'inizio dell'analisi.
    debug!("SSL scan task finished, starting analysis.");
    let mut results = SslResults {
        scan: scan_result,
        analysis: Vec::new(),
    };

    results.analysis = analyze_ssl_results(&results);

    // NUOVO: Logghiamo la fine della scansione con il numero di scoperte.
    info!(findings = %results.analysis.len(), "SSL/TLS scan finished.");
    results
}

fn perform_tls_scan(target: &str) -> ScanResult<SslData> {
    debug!(target, "Performing TLS connection and handshake.");

    // MODIFICATO: Aggiunto logging in caso di errore.
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

    let cert = match stream.peer_certificate() {
        Ok(Some(c)) => {
            debug!("Peer certificate found.");
            c
        },
        Ok(None) => {
            debug!("TLS connection successful, but no peer certificate provided.");
            return Ok(None)
        },
        Err(e) => {
            error!(error = %e, "Failed to retrieve peer certificate from stream");
            return Err(format!("Could not get peer certificate: {}", e))
        },
    };

    let cert_der = cert.to_der().map_err(|e| {
        error!(error = %e, "Failed to convert certificate to DER format");
        format!("Could not convert certificate to DER: {}", e)
    })?;
    
    let (_, x509) = parse_x509_certificate(&cert_der).map_err(|e| {
        error!(error = %e, "Failed to parse X.509 certificate");
        format!("X.509 Parse Error: {}", e)
    })?;

    // NUOVO: Logghiamo i dettagli del certificato parsato con successo.
    info!(subject = %x509.subject(), issuer = %x509.issuer(), "Successfully parsed certificate.");
    
    let validity = x509.validity();
    let not_after = asn1_time_to_chrono_utc(&validity.not_after);
    let not_before = asn1_time_to_chrono_utc(&validity.not_before);
    let days_until_expiry = not_after.signed_duration_since(Utc::now()).num_days();
    
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

fn asn1_time_to_chrono_utc(time: &ASN1Time) -> DateTime<Utc> {
    DateTime::from_timestamp(time.timestamp(), 0).unwrap_or_default()
}

fn analyze_ssl_results(results: &SslResults) -> Vec<AnalysisFinding> {
    debug!("Analyzing SSL scan results.");
    let mut analyses = Vec::new();

    match &results.scan {
        Err(_) => {
            debug!("Scan failed, adding SSL_HANDSHAKE_FAILED finding.");
            analyses.push(AnalysisFinding::new(Severity::Critical, "SSL_HANDSHAKE_FAILED"));
        },
        Ok(None) => {
            debug!("No certificate found, adding SSL_NO_CERTIFICATE_FOUND finding.");
            analyses.push(AnalysisFinding::new(Severity::Warning, "SSL_NO_CERTIFICATE_FOUND"));
        },
        Ok(Some(ssl_data)) => {
            if !ssl_data.is_valid {
                // NUOVO: Logghiamo i dettagli sulla scadenza.
                debug!(expiry_date = %ssl_data.certificate_info.not_after, "Certificate is expired, adding SSL_EXPIRED finding.");
                analyses.push(AnalysisFinding::new(Severity::Critical, "SSL_EXPIRED"));
            }

            let days_left = ssl_data.certificate_info.days_until_expiry;
            if (0..=30).contains(&days_left) {
                debug!(days_left, "Certificate is expiring soon, adding SSL_EXPIRING_SOON finding.");
                analyses.push(AnalysisFinding::new(Severity::Warning, "SSL_EXPIRING_SOON"));
            }
        }
    }
    
    analyses
}