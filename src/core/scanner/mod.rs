// src/core/scanner/mod.rs

// 1. Dichiariamo tutti i nostri moduli scanner.
pub mod dns_scanner;
pub mod headers_scanner;
pub mod ssl_scanner;

// 2. Importiamo le funzioni pubbliche e i modelli.
use crate::core::models::ScanReport;
use self::dns_scanner::run_dns_scan;
use self::headers_scanner::run_headers_scan;
use self::ssl_scanner::run_ssl_scan;

/// Esegue tutte le scansioni disponibili in parallelo e aggrega i risultati.
pub async fn run_full_scan(target: &str) -> ScanReport {
    // 3. Aggiungiamo la nuova scansione al join. Ora ne eseguiamo 3 in parallelo!
    let (dns_results, ssl_results, headers_results) = tokio::join!(
        run_dns_scan(target),
        run_ssl_scan(target),
        run_headers_scan(target)
    );
    
    ScanReport {
        dns_results: Some(dns_results),
        ssl_results: Some(ssl_results),
        headers_results: Some(headers_results),
    }
}