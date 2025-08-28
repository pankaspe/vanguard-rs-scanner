// src/core/scanner/mod.rs

// 1. Dichiariamo i nostri nuovi file come sottomoduli di `scanner`.
pub mod dns_scanner;
pub mod ssl_scanner;

// 2. Importiamo le funzioni pubbliche dai nostri sottomoduli e i modelli necessari.
use crate::core::models::ScanReport;
use self::dns_scanner::run_dns_scan;
use self::ssl_scanner::run_ssl_scan;

/// Esegue tutte le scansioni disponibili in parallelo e aggrega i risultati.
/// Questa è l'unica funzione che deve essere pubblica all'esterno del modulo `scanner`.
pub async fn run_full_scan(target: &str) -> ScanReport {
    // 3. La logica di orchestrazione rimane qui.
    let (dns_results, ssl_results) = tokio::join!(
        run_dns_scan(target),
        run_ssl_scan(target)
    );
    
    ScanReport {
        dns_results: Some(dns_results),
        ssl_results: Some(ssl_results),
    }
}