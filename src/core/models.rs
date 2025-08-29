// src/core/models.rs

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

// --- Core Data Models ---
// These are fundamental types used across multiple scanner modules.

/// Represents the severity of an analysis finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

/// Represents a single, actionable finding from a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// The severity level of the finding.
    pub severity: Severity,
    /// A machine-readable code for the finding (e.g., "DNS_DMARC_MISSING").
    pub code: String,
}

// --- DNS Scanner Models ---

/// Holds the data for a discovered SPF record.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpfRecord {
    pub found: bool,
    pub record: Option<String>,
    pub error: Option<String>,
}

/// Holds the data for a discovered DMARC record.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DmarcRecord {
    pub found: bool,
    pub record: Option<String>,
    /// The extracted policy (p=) value, e.g., "none", "quarantine".
    pub policy: Option<String>,
    pub error: Option<String>,
}

/// A container for all DNS-related scan results.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsResults {
    pub spf: Option<SpfRecord>,
    pub dmarc: Option<DmarcRecord>,
    pub dkim: Option<DkimResults>, // <-- NUOVO
    pub caa: Option<CaaResults>,   // <-- NUOVO
    pub analysis: Vec<AnalysisResult>,
}
// --- SSL/TLS Scanner Models ---

/// Represents key information extracted from an SSL certificate.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertificateInfo {
    pub subject_name: String,
    pub issuer_name: String,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub days_until_expiry: Option<i64>,
}

/// A container for all SSL/TLS related scan results.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SslResults {
    pub certificate_found: bool,
    pub is_valid: bool,
    pub certificate_info: Option<CertificateInfo>,
    pub error: Option<String>,
    pub analysis: Vec<AnalysisResult>,
}

// --- HTTP Headers Scanner Models ---

/// Represents the presence and value of a single HTTP header.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderInfo {
    pub found: bool,
    pub value: Option<String>,
}

/// A container for all HTTP security header scan results.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeadersResults {
    pub hsts: Option<HeaderInfo>,
    pub csp: Option<HeaderInfo>,
    pub x_frame_options: Option<HeaderInfo>,
    pub x_content_type_options: Option<HeaderInfo>,
    pub error: Option<String>,
    pub analysis: Vec<AnalysisResult>,
}

// --- Fingerprint Scanner Models ---

/// Represents a single technology identified on the target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Technology {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
}

/// A container for all technology fingerprinting results.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FingerprintResults {
    pub technologies: Vec<Technology>,
    pub error: Option<String>,
}

// --- Top-Level Report ---

/// The top-level struct that aggregates all scan results into a single report.
/// All fields are guaranteed to be present, even if a scan fails. In case of
/// failure, the respective struct's `error` field will be populated.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanReport {
    pub dns_results: DnsResults,
    pub ssl_results: SslResults,
    pub headers_results: HeadersResults,
    pub fingerprint_results: FingerprintResults,
}

/// Holds data for a discovered DKIM record for a specific selector.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DkimSelectorRecord {
    pub selector: String,
    pub record: String,
}

/// A container for all DKIM-related findings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DkimResults {
    pub found: bool,
    /// A list of all DKIM records found for common selectors.
    pub records: Vec<DkimSelectorRecord>,
    pub error: Option<String>,
}

/// A container for all CAA-related findings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaaResults {
    pub found: bool,
    /// A list of all CAA records found for the domain.
    pub records: Vec<String>,
    pub error: Option<String>,
}