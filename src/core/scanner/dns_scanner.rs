// src/core/scanner/dns_scanner.rs

// Importiamo solo ciò che serve a questo modulo.
use crate::core::models::{AnalysisResult, DmarcRecord, DnsResults, Severity, SpfRecord};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

/// Esegue la scansione DNS completa.
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

/// Analizza i risultati grezzi della scansione DNS.
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

/// Esegue la ricerca di un record TXT per SPF.
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

/// Esegue la ricerca di un record TXT per DMARC.
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