// src/core/scanner/dns_scanner.rs

use tracing::{debug, info, warn};

use crate::core::models::{
    AnalysisFinding, DmarcData, DnsResults, Severity, SpfData, DkimRecord, ScanResult,
};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;

const COMMON_DKIM_SELECTORS: &[&str] = &["google", "selector1", "selector2", "default", "dkim"];

pub async fn run_dns_scan(target: &str) -> DnsResults {
    let root_target = if let Some(stripped) = target.strip_prefix("www.") {
        stripped
    } else {
        target
    };

    info!(target = %root_target, "Starting DNS scan.");

    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let (spf_result, dmarc_result, dkim_result, caa_result) = tokio::join!(
        lookup_spf(&resolver, root_target),
        lookup_dmarc(&resolver, root_target),
        lookup_dkim(&resolver, root_target),
        lookup_caa(&resolver, root_target)
    );

    debug!("All DNS lookups completed, starting analysis.");

    let mut results = DnsResults {
        spf: spf_result,
        dmarc: dmarc_result,
        dkim: dkim_result,
        caa: caa_result,
        analysis: Vec::new(),
    };

    results.analysis = analyze_dns_results(&results);
    info!(findings = %results.analysis.len(), "DNS scan finished.");
    results
}

fn analyze_dns_results(results: &DnsResults) -> Vec<AnalysisFinding> {
    let mut analyses = Vec::new();

    match &results.dmarc {
        Ok(Some(dmarc)) => {
            if let Some(policy) = &dmarc.policy {
                if policy == "none" {
                    debug!("DMARC analysis: Found policy 'none', adding Warning.");
                    analyses.push(AnalysisFinding::new(Severity::Warning, "DNS_DMARC_POLICY_NONE"));
                }
            }
        }
        Ok(None) => {
            debug!("DMARC analysis: No record found, adding Critical finding.");
            analyses.push(AnalysisFinding::new(Severity::Critical, "DNS_DMARC_MISSING"));
        }
        Err(_) => {}
    }

    match &results.spf {
        Ok(Some(spf)) => {
            if spf.record.ends_with("~all") {
                debug!("SPF analysis: Found softfail policy '~all', adding Info finding.");
                analyses.push(AnalysisFinding::new(Severity::Info, "DNS_SPF_POLICY_SOFTFAIL"));
            } else if spf.record.ends_with("?all") {
                debug!("SPF analysis: Found neutral policy '?all', adding Info finding.");
                analyses.push(AnalysisFinding::new(Severity::Info, "DNS_SPF_POLICY_NEUTRAL"));
            }
        }
        Ok(None) => {
            debug!("SPF analysis: No record found, adding Warning finding.");
            analyses.push(AnalysisFinding::new(Severity::Warning, "DNS_SPF_MISSING"));
        }
        Err(_) => {}
    }

    if let Ok(None) = &results.dkim {
        debug!("DKIM analysis: No records found, adding Info finding.");
        analyses.push(AnalysisFinding::new(Severity::Info, "DNS_DKIM_MISSING"));
    }

    if let Ok(None) = &results.caa {
        debug!("CAA analysis: No records found, adding Info finding.");
        analyses.push(AnalysisFinding::new(Severity::Info, "DNS_CAA_MISSING"));
    }
    
    analyses
}

async fn lookup_spf(resolver: &TokioAsyncResolver, target: &str) -> ScanResult<SpfData> {
    debug!(target, "Looking up SPF record.");
    match resolver.txt_lookup(target).await {
        Ok(txt_records) => {
            for record in txt_records.iter() {
                let record_str = record.to_string();
                if record_str.starts_with("v=spf1") {
                    debug!(record = %record_str, "SPF record found.");
                    return Ok(Some(SpfData { record: record_str }));
                }
            }
            debug!(target, "No SPF record found among TXT records.");
            Ok(None)
        },
        Err(e) => {
            warn!(target, error = %e, "SPF lookup failed.");
            Err(format!("DNS Error: {}", e))
        }
    }
}

async fn lookup_dmarc(resolver: &TokioAsyncResolver, target: &str) -> ScanResult<DmarcData> {
    let dmarc_target = format!("_dmarc.{}", target);
    debug!(target = %dmarc_target, "Looking up DMARC record.");
    // --- CORREZIONE: Passiamo un riferimento (&str) invece di spostare la String. ---
    match resolver.txt_lookup(&dmarc_target).await {
        Ok(txt_records) => {
            if let Some(record) = txt_records.iter().next() {
                let record_str = record.to_string();
                debug!(record = %record_str, "DMARC record found.");
                let policy = record_str.split(';')
                    .find(|s| s.trim().starts_with("p="))
                    .and_then(|s| s.trim().split('=').nth(1))
                    .map(|s| s.to_string());
                
                return Ok(Some(DmarcData { record: record_str, policy }));
            }
            debug!(target = %dmarc_target, "No DMARC record found.");
            Ok(None)
        },
        Err(e) => {
            // Ora questa chiamata è valida, perché `dmarc_target` non è stato spostato.
            warn!(target = %dmarc_target, error = %e, "DMARC lookup failed.");
            Err(format!("DNS Error: {}", e))
        }
    }
}

async fn lookup_dkim(resolver: &TokioAsyncResolver, target: &str) -> ScanResult<Vec<DkimRecord>> {
    debug!(target, "Looking up DKIM records for common selectors.");
    let mut found_records = Vec::new();
    for selector in COMMON_DKIM_SELECTORS {
        let dkim_target = format!("{selector}._domainkey.{target}");
        debug!(selector, "Checking for DKIM record.");

        // --- CORREZIONE: Stesso fix di ownership anche qui. ---
        match resolver.txt_lookup(&dkim_target).await {
            Ok(txt_records) => {
                for record in txt_records.iter() {
                    let record_str = record.to_string();
                    if record_str.starts_with("v=DKIM1") {
                        debug!(selector, "Found valid DKIM record.");
                        found_records.push(DkimRecord {
                            selector: selector.to_string(),
                            record: record_str,
                        });
                    }
                }
            },
            Err(e) => {
                warn!(selector, target = %dkim_target, error = %e, "DKIM lookup for this selector failed.");
            }
        }
    }

    if found_records.is_empty() {
        debug!(target, "No DKIM records found for any common selector.");
        Ok(None)
    } else {
        info!(count = %found_records.len(), "Found DKIM records.");
        Ok(Some(found_records))
    }
}

async fn lookup_caa(resolver: &TokioAsyncResolver, target: &str) -> ScanResult<Vec<String>> {
    debug!(target, "Looking up CAA records.");
    match resolver.lookup(target, RecordType::CAA).await {
        Ok(caa_lookup) => {
            let records: Vec<String> = caa_lookup.iter().map(|r| r.to_string()).collect();

            if records.is_empty() {
                debug!(target, "No CAA records found.");
                return Ok(None);
            }
            
            info!(count = %records.len(), "Found CAA records.");
            Ok(Some(records))
        },
        Err(e) => {
            warn!(target, error = %e, "CAA lookup failed.");
            Err(format!("DNS Error: {}", e))
        }
    }
}