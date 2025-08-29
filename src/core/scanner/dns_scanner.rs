// src/core/scanner/dns_scanner.rs

use crate::core::models::{
    AnalysisFinding, DmarcData, DnsResults, Severity, SpfData, DkimRecord, ScanResult,
};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;

// A constant array of common DKIM selectors to check. This is a pragmatic
// approach to find DKIM records without knowing the specific selector name.
const COMMON_DKIM_SELECTORS: &[&str] = &["google", "selector1", "selector2", "default", "dkim"];

// The main asynchronous function to orchestrate the entire DNS scan.
// It performs multiple DNS record lookups concurrently.
pub async fn run_dns_scan(target: &str) -> DnsResults {
    // Strips the "www." prefix from the target domain. This is a good practice
    // as most DNS records like SPF and DMARC are defined on the root domain.
    let root_target = if let Some(stripped) = target.strip_prefix("www.") {
        stripped
    } else {
        target
    };

    // Initializes a Tokio-based DNS resolver with default configurations.
    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // Concurrently performs all DNS lookups using `tokio::join!`. This is a highly
    // efficient way to run multiple independent async tasks at once.
    let (spf_result, dmarc_result, dkim_result, caa_result) = tokio::join!(
        lookup_spf(&resolver, root_target),
        lookup_dmarc(&resolver, root_target),
        lookup_dkim(&resolver, root_target),
        lookup_caa(&resolver, root_target)
    );

    // Collects the results into the main `DnsResults` struct.
    let mut results = DnsResults {
        spf: spf_result,
        dmarc: dmarc_result,
        dkim: dkim_result,
        caa: caa_result,
        analysis: Vec::new(),
    };

    // Analyzes the collected DNS data to generate security findings.
    results.analysis = analyze_dns_results(&results);
    results
}

// Analyzes the DNS scan results and generates security findings based on best practices.
// For example, a missing DMARC record is a critical issue, while a DMARC policy of "none" is a warning.
fn analyze_dns_results(results: &DnsResults) -> Vec<AnalysisFinding> {
    let mut analyses = Vec::new();

    // DMARC analysis:
    // A DMARC record is expected.
    match &results.dmarc {
        Ok(Some(dmarc)) => {
            if let Some(policy) = &dmarc.policy {
                if policy == "none" {
                    // A DMARC policy of "none" means no action is taken on failed emails.
                    analyses.push(AnalysisFinding::new(Severity::Warning, "DNS_DMARC_POLICY_NONE"));
                }
            }
        }
        Ok(None) => {
            // Absence of a DMARC record is a critical security vulnerability for email.
            analyses.push(AnalysisFinding::new(Severity::Critical, "DNS_DMARC_MISSING"));
        }
        // DNS lookup errors are not handled in this analysis logic.
        Err(_) => {}
    }

    // SPF analysis:
    // SPF records are highly recommended for email security.
    match &results.spf {
        Ok(Some(spf)) => {
            // A "~all" policy is a "softfail," which is less secure than a hardfail.
            if spf.record.ends_with("~all") {
                analyses.push(AnalysisFinding::new(Severity::Info, "DNS_SPF_POLICY_SOFTFAIL"));
            } else if spf.record.ends_with("?all") {
                // A "?all" policy is "neutral," offering no protection.
                analyses.push(AnalysisFinding::new(Severity::Info, "DNS_SPF_POLICY_NEUTRAL"));
            }
        }
        Ok(None) => {
            // A missing SPF record is a notable issue.
            analyses.push(AnalysisFinding::new(Severity::Warning, "DNS_SPF_MISSING"));
        }
        // DNS lookup errors are not handled in this analysis logic.
        Err(_) => {}
    }

    // DKIM analysis:
    // A missing DKIM record is a notable issue for email deliverability and security.
    if let Ok(None) = &results.dkim {
        analyses.push(AnalysisFinding::new(Severity::Info, "DNS_DKIM_MISSING"));
    }

    // CAA analysis:
    // A missing CAA record means any certificate authority can issue a certificate for the domain.
    // This is a security risk.
    if let Ok(None) = &results.caa {
        analyses.push(AnalysisFinding::new(Severity::Info, "DNS_CAA_MISSING"));
    }
    
    analyses
}

// Asynchronously looks up the SPF record for a given target domain.
async fn lookup_spf(resolver: &TokioAsyncResolver, target: &str) -> ScanResult<SpfData> {
    // SPF records are stored as TXT records.
    match resolver.txt_lookup(target).await {
        Ok(txt_records) => {
            for record in txt_records.iter() {
                let record_str = record.to_string();
                // An SPF record always starts with "v=spf1".
                if record_str.starts_with("v=spf1") {
                    return Ok(Some(SpfData { record: record_str }));
                }
            }
            // No SPF record found.
            Ok(None)
        },
        // Handles DNS lookup errors.
        Err(e) => Err(format!("DNS Error: {}", e)),
    }
}

// Asynchronously looks up the DMARC record for a given target domain.
async fn lookup_dmarc(resolver: &TokioAsyncResolver, target: &str) -> ScanResult<DmarcData> {
    // DMARC records are always located at the `_dmarc` subdomain.
    let dmarc_target = format!("_dmarc.{}", target);
    // DMARC records are also stored as TXT records.
    match resolver.txt_lookup(dmarc_target).await {
        Ok(txt_records) => {
            if let Some(record) = txt_records.iter().next() {
                let record_str = record.to_string();
                // Extracts the `p=` (policy) tag from the DMARC record string.
                let policy = record_str.split(';')
                    .find(|s| s.trim().starts_with("p="))
                    .and_then(|s| s.trim().split('=').nth(1))
                    .map(|s| s.to_string());
                
                return Ok(Some(DmarcData { record: record_str, policy }));
            }
            // No DMARC record found.
            Ok(None)
        },
        // Handles DNS lookup errors.
        Err(e) => Err(format!("DNS Error: {}", e)),
    }
}

// Asynchronously looks up DKIM records for a given target domain using a list of common selectors.
async fn lookup_dkim(resolver: &TokioAsyncResolver, target: &str) -> ScanResult<Vec<DkimRecord>> {
    let mut found_records = Vec::new();
    // Iterates through a predefined list of common selectors.
    for selector in COMMON_DKIM_SELECTORS {
        // Constructs the full DNS query name.
        let dkim_target = format!("{selector}._domainkey.{target}");
        // Looks up a TXT record for each selector.
        if let Ok(txt_records) = resolver.txt_lookup(dkim_target).await {
            for record in txt_records.iter() {
                let record_str = record.to_string();
                // A DKIM record always starts with "v=DKIM1".
                if record_str.starts_with("v=DKIM1") {
                    found_records.push(DkimRecord {
                        selector: selector.to_string(),
                        record: record_str,
                    });
                }
            }
        }
    }

    // Returns `Ok(None)` if no records were found, otherwise returns the found records.
    if found_records.is_empty() {
        Ok(None)
    } else {
        Ok(Some(found_records))
    }
}

// Asynchronously looks up CAA (Certificate Authority Authorization) records.
async fn lookup_caa(resolver: &TokioAsyncResolver, target: &str) -> ScanResult<Vec<String>> {
    // Uses the `lookup` method with the specific `RecordType::CAA`.
    match resolver.lookup(target, RecordType::CAA).await {
        Ok(caa_lookup) => {
            // Collects all found CAA records into a vector of strings.
            let records: Vec<String> = caa_lookup.iter().map(|r| r.to_string()).collect();

            if records.is_empty() {
                return Ok(None);
            }
            
            Ok(Some(records))
        },
        // Handles DNS lookup errors.
        Err(e) => Err(format!("DNS Error: {}", e)),
    }
}

// --- FIX: Blocco duplicato rimosso ---