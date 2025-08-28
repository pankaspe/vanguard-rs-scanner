// src/core/scanner/mod.rs

// Dichiariamo i nostri moduli scanner.
pub mod dns_scanner;
pub mod fingerprint_scanner;
pub mod headers_scanner;
pub mod ssl_scanner;

// Importiamo le funzioni pubbliche e i modelli.
use crate::core::models::ScanReport;
use self::dns_scanner::run_dns_scan;
use self::fingerprint_scanner::run_fingerprint_scan;
use self::headers_scanner::run_headers_scan;
use self::ssl_scanner::run_ssl_scan;

/// Esegue tutte le scansioni disponibili in parallelo e aggrega i risultati.
pub async fn run_full_scan(target: &str) -> ScanReport {
    let (dns_results, ssl_results, headers_results, fingerprint_results) = tokio::join!(
        run_dns_scan(target),
        run_ssl_scan(target),
        run_headers_scan(target),
        run_fingerprint_scan(target)
    );
    
    // FIX: Removed the `Some()` wrappers to match the new ScanReport struct.
    ScanReport {
        dns_results,
        ssl_results,
        headers_results,
        fingerprint_results,
    }
}