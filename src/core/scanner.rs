// src/core/scanner.rs

// Import all the necessary data models from our new `models.rs` file.
use crate::core::models::{DnsResults, SpfRecord, DmarcRecord, AnalysisResult, Severity};
// Import the asynchronous resolver from the Hickory library.
use hickory_resolver::TokioAsyncResolver;
// Import the types for the resolver configuration.
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

/// The main function that orchestrates the DNS scan.
/// It accepts a domain name and returns a `DnsResults` struct, complete with analysis.
pub async fn run_dns_scan(target: &str) -> DnsResults {
    // --- STEP 1: Input Normalization ---
    // Many DNS records (like SPF/DMARC) are on the root domain, not on subdomains like 'www'.
    // This logic removes the 'www.' prefix to ensure lookups are performed on the correct domain.
    let root_target = if let Some(stripped) = target.strip_prefix("www.") {
        stripped
    } else {
        target
    };

    // --- STEP 2: DNS Resolver Creation ---
    // Initialize the client that will perform the DNS queries.
    // We use the default configuration for broad compatibility.
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    // --- STEP 3: Parallel Scan Execution ---
    // `tokio::join!` is a powerful macro that runs multiple asynchronous operations concurrently.
    // This significantly speeds up the scan, as we don't have to wait for one query to finish
    // before starting the next.
    let (spf_result, dmarc_result) = tokio::join!(
        lookup_spf(&resolver, root_target),
        lookup_dmarc(&resolver, root_target)
    );

    // --- STEP 4: Assembly and Analysis ---
    // Create a `DnsResults` struct with the raw data obtained.
    let mut results = DnsResults {
        spf: Some(spf_result),
        dmarc: Some(dmarc_result),
        analysis: Vec::new(), // Initialize the 'analysis' field as an empty vector.
    };

    // Call our analysis function to interpret the raw results.
    results.analysis = analyze_dns_results(&results);

    // Return the complete struct, which now contains both the data and the analysis.
    results
}

/// Analyzes the raw DNS scan results and produces a list of findings and recommendations.
fn analyze_dns_results(results: &DnsResults) -> Vec<AnalysisResult> {
    let mut analyses = Vec::new();

    // Rule 1: DMARC record analysis.
    if let Some(dmarc) = &results.dmarc {
        if !dmarc.found {
            // If DMARC is missing, it's a critical issue for email security.
            analyses.push(AnalysisResult {
                severity: Severity::Critical,
                code: "DNS_DMARC_MISSING".to_string(),
            });
        } else if let Some(policy) = &dmarc.policy {
            // If DMARC exists but the policy is 'none', it's a warning, as it's not enforcing protection.
            if policy == "none" {
                analyses.push(AnalysisResult {
                    severity: Severity::Warning,
                    code: "DNS_DMARC_POLICY_NONE".to_string(),
                });
            }
        }
    }

    // Rule 2: SPF record analysis.
    if let Some(spf) = &results.spf {
        if !spf.found {
            // A missing SPF record is a warning, as it weakens email sender verification.
            analyses.push(AnalysisResult {
                severity: Severity::Warning,
                code: "DNS_SPF_MISSING".to_string(),
            });
        }
    }

    // Return the list of all identified issues/recommendations.
    analyses
}


/// Performs a TXT record lookup for SPF.
async fn lookup_spf(resolver: &TokioAsyncResolver, target: &str) -> SpfRecord {
    match resolver.txt_lookup(target).await {
        Ok(txt_records) => {
            // A domain can have multiple TXT records; we need to find the correct one.
            for record in txt_records.iter() {
                if record.to_string().starts_with("v=spf1") {
                    return SpfRecord { found: true, record: Some(record.to_string()), ..Default::default() };
                }
            }
            // If the loop finishes, no SPF record was found.
            SpfRecord { found: false, error: Some("No SPF TXT record found.".to_string()), ..Default::default() }
        },
        Err(e) => SpfRecord { found: false, error: Some(format!("DNS Error: {}", e)), ..Default::default() }
    }
}

/// Performs a TXT record lookup for DMARC.
async fn lookup_dmarc(resolver: &TokioAsyncResolver, target: &str) -> DmarcRecord {
    // By convention, the DMARC record is located on the '_dmarc' subdomain.
    let dmarc_target = format!("_dmarc.{}", target);
    match resolver.txt_lookup(dmarc_target).await {
        Ok(txt_records) => {
            if let Some(record) = txt_records.iter().next() {
                let record_str = record.to_string();
                // We perform a basic parse to extract the policy (p=), which is the most critical piece of information.
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