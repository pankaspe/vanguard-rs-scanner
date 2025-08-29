// src/core/scanner/dns_scanner.rs

use crate::core::models::{
    AnalysisResult, CaaResults, DkimResults, DkimSelectorRecord, DmarcRecord, DnsResults, Severity, SpfRecord,
};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;

// A list of common selectors to check for DKIM records.
/// These are widely-used selectors by major email service providers.
const COMMON_DKIM_SELECTORS: &[&str] = &["google", "selector1", "selector2", "default", "dkim"];

/// Executes the complete and enhanced DNS scan.
///
/// This is the primary entry point for the DNS scanning module. It performs
/// asynchronous lookups for SPF, DMARC, DKIM, and CAA records, aggregates the
/// results, and then runs a detailed analysis to generate actionable findings.
///
/// # Arguments
/// * `target` - The domain to scan (e.g., "example.com" or "www.example.com").
///
/// # Returns
/// A `DnsResults` struct containing all raw lookup data and analysis findings.
pub async fn run_dns_scan(target: &str) -> DnsResults {
    // Strip "www." to ensure the scan is performed on the root domain, as
    // email-related records are typically configured there.
    let root_target = if let Some(stripped) = target.strip_prefix("www.") {
        stripped
    } else {
        target
    };

    // Initialize the asynchronous DNS resolver with default configurations.
    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // Use `tokio::join!` to concurrently perform all DNS lookups,
    // which significantly improves performance.
    let (spf_result, dmarc_result, dkim_result, caa_result) = tokio::join!(
        lookup_spf(&resolver, root_target),
        lookup_dmarc(&resolver, root_target),
        lookup_dkim(&resolver, root_target),
        lookup_caa(&resolver, root_target)
    );

    // Aggregate the results into a single DnsResults struct.
    let mut results = DnsResults {
        spf: Some(spf_result),
        dmarc: Some(dmarc_result),
        dkim: Some(dkim_result),
        caa: Some(caa_result),
        analysis: Vec::new(),
    };

    // Analyze the raw results to generate the final list of security findings.
    results.analysis = analyze_dns_results(&results);
    results
}

/// Analyzes the raw DNS scan results to generate actionable findings.
///
/// This function inspects the presence and content of each DNS record
/// and maps common misconfigurations or missing records to specific
/// `AnalysisResult` codes.
///
/// # Arguments
/// * `results` - A reference to the raw `DnsResults` from the scan.
///
/// # Returns
/// A `Vec<AnalysisResult>` containing all identified security findings.
fn analyze_dns_results(results: &DnsResults) -> Vec<AnalysisResult> {
    let mut analyses = Vec::new();

    if let Some(dmarc) = &results.dmarc {
        if !dmarc.found {
            analyses.push(AnalysisResult::new(Severity::Critical, "DNS_DMARC_MISSING"));
        } else if let Some(policy) = &dmarc.policy {
            if policy == "none" {
                analyses.push(AnalysisResult::new(Severity::Warning, "DNS_DMARC_POLICY_NONE"));
            }
        }
    }

    if let Some(spf) = &results.spf {
        if !spf.found {
            analyses.push(AnalysisResult::new(Severity::Warning, "DNS_SPF_MISSING"));
        } else if let Some(record) = &spf.record {
            if record.ends_with("~all") {
                 analyses.push(AnalysisResult::new(Severity::Info, "DNS_SPF_POLICY_SOFTFAIL"));
            } else if record.ends_with("?all") {
                 analyses.push(AnalysisResult::new(Severity::Info, "DNS_SPF_POLICY_NEUTRAL"));
            }
        }
    }

    if let Some(dkim) = &results.dkim {
        if !dkim.found {
            analyses.push(AnalysisResult::new(Severity::Info, "DNS_DKIM_MISSING"));
        }
    }

    if let Some(caa) = &results.caa {
        if !caa.found {
            analyses.push(AnalysisResult::new(Severity::Info, "DNS_CAA_MISSING"));
        }
    }
    
    analyses
}

/// Asynchronously looks up the SPF TXT record for the target domain.
///
/// # Arguments
/// * `resolver` - A reference to the DNS resolver.
/// * `target` - The domain to query.
///
/// # Returns
/// A `SpfRecord` struct with the lookup result.
async fn lookup_spf(resolver: &TokioAsyncResolver, target: &str) -> SpfRecord {
    match resolver.txt_lookup(target).await {
        Ok(txt_records) => {
            for record in txt_records.iter() {
                let record_str = record.to_string();
                if record_str.starts_with("v=spf1") {
                    return SpfRecord { found: true, record: Some(record_str), ..Default::default() };
                }
            }
            SpfRecord { found: false, error: Some("No SPF TXT record found.".to_string()), ..Default::default() }
        },
        Err(e) => SpfRecord { found: false, error: Some(format!("DNS Error: {}", e)), ..Default::default() }
    }
}

/// Asynchronously looks up the DMARC TXT record.
///
/// DMARC records are always located at `_dmarc.target`. This function
/// constructs the correct subdomain and performs the lookup.
///
/// # Arguments
/// * `resolver` - A reference to the DNS resolver.
/// * `target` - The domain to query.
///
/// # Returns
/// A `DmarcRecord` struct with the lookup result.
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
                return DmarcRecord { found: true, record: Some(record_str), policy, error: None };
            }
            DmarcRecord { found: false, error: Some("No DMARC record found.".to_string()), ..Default::default() }
        },
        Err(e) => DmarcRecord { found: false, error: Some(format!("DNS Error: {}", e)), ..Default::default() }
    }
}

/// Asynchronously looks up DKIM records for a list of common selectors.
///
/// The function iterates through `COMMON_DKIM_SELECTORS` and performs a lookup
/// for each one, aggregating any valid records found.
///
/// # Arguments
/// * `resolver` - A reference to the DNS resolver.
/// * `target` - The domain to query.
///
/// # Returns
/// A `DkimResults` struct with the lookup result.
async fn lookup_dkim(resolver: &TokioAsyncResolver, target: &str) -> DkimResults {
    let mut found_records = Vec::new();
    for selector in COMMON_DKIM_SELECTORS {
        let dkim_target = format!("{_selector}._domainkey.{target}", _selector = selector, target = target);
        if let Ok(txt_records) = resolver.txt_lookup(dkim_target).await {
            for record in txt_records.iter() {
                let record_str = record.to_string();
                if record_str.starts_with("v=DKIM1") {
                    found_records.push(DkimSelectorRecord {
                        selector: selector.to_string(),
                        record: record_str,
                    });
                }
            }
        }
    }

    if found_records.is_empty() {
        DkimResults { found: false, error: Some("No DKIM records found for common selectors.".to_string()), ..Default::default() }
    } else {
        DkimResults { found: true, records: found_records, ..Default::default() }
    }
}

/// Asynchronously looks up CAA records for the target domain.
///
/// # Arguments
/// * `resolver` - A reference to the DNS resolver.
/// * `target` - The domain to query.
///
/// # Returns
/// A `CaaResults` struct with the lookup result.
async fn lookup_caa(resolver: &TokioAsyncResolver, target: &str) -> CaaResults {
    match resolver.lookup(target, RecordType::CAA).await {
        Ok(caa_lookup) => {
            // The iterator gives a `Record`. `.to_string()` on it is the simplest and
            // most robust way to get a string representation, which is what we need.
            let records: Vec<String> = caa_lookup.iter().map(|r| r.to_string()).collect();

            if records.is_empty() {
                return CaaResults { found: false, error: Some("No CAA records found.".to_string()), ..Default::default() };
            }
            
            CaaResults { found: true, records, ..Default::default() }
        },
        Err(e) => CaaResults { found: false, error: Some(format!("DNS Error: {}", e)), ..Default::default() }
    }
}

// Helper implementation for creating AnalysisResult easily.
/// A simple constructor for `AnalysisResult` to reduce boilerplate.
impl AnalysisResult {
    fn new(severity: Severity, code: &str) -> Self {
        Self { severity, code: code.to_string() }
    }
}