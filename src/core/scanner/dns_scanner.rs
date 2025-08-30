// src/core/scanner/dns_scanner.rs

use tracing::{debug, info, warn};

use crate::core::models::{
    AnalysisFinding, DmarcData, DnsResults, Severity, SpfData, DkimRecord, ScanResult,
};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;

/// A list of common DKIM selectors to check for when a specific one is not known.
const COMMON_DKIM_SELECTORS: &[&str] = &["google", "selector1", "selector2", "default", "dkim"];

/// Runs a comprehensive DNS security scan against the specified target domain.
///
/// This function performs parallel lookups for SPF, DMARC, DKIM, and CAA records.
/// After gathering the raw DNS data, it proceeds to analyze the results to identify
/// potential security misconfigurations or areas for improvement.
///
/// # Arguments
/// * `target` - The domain name to be scanned.
///
/// # Returns
/// A `DnsResults` struct containing both the raw lookup data and the analysis findings.
pub async fn run_dns_scan(target: &str) -> DnsResults {
    // Strip "www." prefix to query the root domain, which is standard for these record types.
    let root_target = if let Some(stripped) = target.strip_prefix("www.") {
        stripped
    } else {
        target
    };

    info!(target = %root_target, "Starting DNS scan.");

    // Initialize a Tokio-based asynchronous DNS resolver.
    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // Execute all DNS lookups concurrently for better performance.
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

    // Analyze the collected data to generate security findings.
    results.analysis = analyze_dns_results(&results);
    info!(findings = %results.analysis.len(), "DNS scan finished.");
    results
}

/// Analyzes the collected DNS records and generates security findings.
///
/// # Arguments
/// * `results` - A reference to the `DnsResults` containing the data to analyze.
///
/// # Returns
/// A vector of `AnalysisFinding` structs detailing any issues found.
fn analyze_dns_results(results: &DnsResults) -> Vec<AnalysisFinding> {
    let mut analyses = Vec::new();

    // Analyze DMARC record.
    match &results.dmarc {
        Ok(Some(dmarc)) => {
            // A DMARC policy of "none" offers no protection and should be flagged.
            if let Some(policy) = &dmarc.policy {
                if policy == "none" {
                    debug!("DMARC analysis: Found policy 'none', adding Warning.");
                    analyses.push(AnalysisFinding::new(Severity::Warning, "DNS_DMARC_POLICY_NONE"));
                }
            }
        }
        // A missing DMARC record is a critical security gap.
        Ok(None) => {
            debug!("DMARC analysis: No record found, adding Critical finding.");
            analyses.push(AnalysisFinding::new(Severity::Critical, "DNS_DMARC_MISSING"));
        }
        Err(_) => {} // Errors are already logged during lookup.
    }

    // Analyze SPF record.
    match &results.spf {
        Ok(Some(spf)) => {
            // Softfail (~all) and Neutral (?all) policies are less secure than Hardfail (-all).
            if spf.record.ends_with("~all") {
                debug!("SPF analysis: Found softfail policy '~all', adding Info finding.");
                analyses.push(AnalysisFinding::new(Severity::Info, "DNS_SPF_POLICY_SOFTFAIL"));
            } else if spf.record.ends_with("?all") {
                debug!("SPF analysis: Found neutral policy '?all', adding Info finding.");
                analyses.push(AnalysisFinding::new(Severity::Info, "DNS_SPF_POLICY_NEUTRAL"));
            }
        }
        // A missing SPF record is a notable weakness.
        Ok(None) => {
            debug!("SPF analysis: No record found, adding Warning finding.");
            analyses.push(AnalysisFinding::new(Severity::Warning, "DNS_SPF_MISSING"));
        }
        Err(_) => {}
    }

    // Check for DKIM records.
    if let Ok(None) = &results.dkim {
        debug!("DKIM analysis: No records found, adding Info finding.");
        analyses.push(AnalysisFinding::new(Severity::Info, "DNS_DKIM_MISSING"));
    }

    // Check for CAA records.
    if let Ok(None) = &results.caa {
        debug!("CAA analysis: No records found, adding Info finding.");
        analyses.push(AnalysisFinding::new(Severity::Info, "DNS_CAA_MISSING"));
    }
    
    analyses
}

/// Looks up the SPF (Sender Policy Framework) record for a domain.
/// SPF records are stored in TXT records and start with "v=spf1".
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

/// Looks up the DMARC record for a domain.
/// DMARC records are stored in a TXT record at the `_dmarc` subdomain.
async fn lookup_dmarc(resolver: &TokioAsyncResolver, target: &str) -> ScanResult<DmarcData> {
    let dmarc_target = format!("_dmarc.{}", target);
    debug!(target = %dmarc_target, "Looking up DMARC record.");
    match resolver.txt_lookup(&dmarc_target).await {
        Ok(txt_records) => {
            if let Some(record) = txt_records.iter().next() {
                let record_str = record.to_string();
                debug!(record = %record_str, "DMARC record found.");
                // Parse the policy (p=) tag from the record.
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
            warn!(target = %dmarc_target, error = %e, "DMARC lookup failed.");
            Err(format!("DNS Error: {}", e))
        }
    }
}

/// Looks up DKIM records for a domain using a list of common selectors.
/// DKIM records are stored in TXT records at `selector._domainkey.domain`.
async fn lookup_dkim(resolver: &TokioAsyncResolver, target: &str) -> ScanResult<Vec<DkimRecord>> {
    debug!(target, "Looking up DKIM records for common selectors.");
    let mut found_records = Vec::new();
    // Iterate through a predefined list of common selectors.
    for selector in COMMON_DKIM_SELECTORS {
        let dkim_target = format!("{selector}._domainkey.{target}");
        debug!(selector, "Checking for DKIM record.");

        match resolver.txt_lookup(&dkim_target).await {
            Ok(txt_records) => {
                for record in txt_records.iter() {
                    let record_str = record.to_string();
                    // A valid DKIM record must start with "v=DKIM1".
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
                // It's common for some selectors not to exist, so this is a warning.
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

/// Looks up CAA (Certification Authority Authorization) records for a domain.
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