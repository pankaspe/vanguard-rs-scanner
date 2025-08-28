// src/core/scanner.rs

// --- IMPORTS ---
// Models: Importiamo tutte le strutture dati di cui abbiamo bisogno.
use crate::core::models::{
    AnalysisResult, CertificateInfo, DmarcRecord, DnsResults, ScanReport, Severity, SpfRecord,
    SslResults,
};
// Libraries: Importiamo le librerie per DNS, SSL, date e operazioni asincrone.
use chrono::{DateTime, Utc};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use native_tls::TlsConnector;
use std::net::TcpStream;
use tokio::task::spawn_blocking; // Cruciale per eseguire codice bloccante in un ambiente async.
use x509_parser::prelude::*;

// --- DNS SCANNER MODULE ---

pub async fn run_dns_scan(target: &str) -> DnsResults {
    let root_target = if let Some(stripped) = target.strip_prefix("www.") {
        stripped
    } else {
        target
    };

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let (spf_result, dmarc_result) = tokio::join!(
        lookup_spf(&resolver, root_target),
        lookup_dmarc(&resolver, root_target)
    );

    let mut results = DnsResults {
        spf: Some(spf_result),
        dmarc: Some(dmarc_result),
        analysis: Vec::new(),
    };

    results.analysis = analyze_dns_results(&results);
    results
}

fn analyze_dns_results(results: &DnsResults) -> Vec<AnalysisResult> {
    let mut analyses = Vec::new();
    if let Some(dmarc) = &results.dmarc {
        if !dmarc.found {
            analyses.push(AnalysisResult {
                severity: Severity::Critical,
                code: "DNS_DMARC_MISSING".to_string(),
            });
        } else if let Some(policy) = &dmarc.policy {
            if policy == "none" {
                analyses.push(AnalysisResult {
                    severity: Severity::Warning,
                    code: "DNS_DMARC_POLICY_NONE".to_string(),
                });
            }
        }
    }
    if let Some(spf) = &results.spf {
        if !spf.found {
            analyses.push(AnalysisResult {
                severity: Severity::Warning,
                code: "DNS_SPF_MISSING".to_string(),
            });
        }
    }
    analyses
}

async fn lookup_spf(resolver: &TokioAsyncResolver, target: &str) -> SpfRecord {
    match resolver.txt_lookup(target).await {
        Ok(txt_records) => {
            for record in txt_records.iter() {
                if record.to_string().starts_with("v=spf1") {
                    return SpfRecord { found: true, record: Some(record.to_string()), ..Default::default() };
                }
            }
            SpfRecord { found: false, error: Some("No SPF TXT record found.".to_string()), ..Default::default() }
        },
        Err(e) => SpfRecord { found: false, error: Some(format!("DNS Error: {}", e)), ..Default::default() }
    }
}

async fn lookup_dmarc(resolver: &TokioAsyncResolver, target: &str) -> DmarcRecord {
    let dmarc_target = format!("_dmarc.{}", target);
    match resolver.txt_lookup(dmarc_target).await {
        Ok(txt_records) => {
            if let Some(record) = txt_records.iter().next() {
                let record_str = record.to_string();
                let policy = record_str.split(';')
                    .find(|s| s.trim().starts_with("p="))
                    .and_then(|s| s.trim().split('=').nth(1))
                    .map(|s| s.to_string());
                DmarcRecord { found: true, record: Some(record_str), policy, error: None }
            } else {
                DmarcRecord { found: false, error: Some("No DMARC record found.".to_string()), ..Default::default() }
            }
        },
        Err(e) => DmarcRecord { found: false, error: Some(format!("DNS Error: {}", e)), ..Default::default() }
    }
}

// --- SSL/TLS SCANNER MODULE ---

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

fn asn1_time_to_chrono_utc(time: &ASN1Time) -> DateTime<Utc> {
    DateTime::from_timestamp(time.timestamp(), 0).unwrap_or_default()
}

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

// --- SCAN ORCHESTRATOR ---

pub async fn run_full_scan(target: &str) -> ScanReport {
    let (dns_results, ssl_results) = tokio::join!(
        run_dns_scan(target),
        run_ssl_scan(target)
    );
    ScanReport {
        dns_results: Some(dns_results),
        ssl_results: Some(ssl_results),
    }
}