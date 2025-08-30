// src/core/models.rs

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

// A custom type alias for a Result that can hold an optional success value or a String error.
// This is used throughout the scanners to represent operations that might fail or might not
// find a specific piece of data.
pub type ScanResult<T> = Result<Option<T>, String>;

/// Represents the severity level of an analysis finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    /// A critical issue that should be addressed immediately.
    Critical,
    /// A potential issue or a deviation from best practices.
    Warning,
    /// Informational finding, not necessarily a vulnerability.
    Info,
}

/// Represents a single analysis finding, identified by a unique code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisFinding {
    pub severity: Severity,
    pub code: String,
}

impl AnalysisFinding {
    /// Constructs a new `AnalysisFinding`.
    ///
    /// # Arguments
    /// * `severity` - The severity level of the finding.
    /// * `code` - A unique string identifier for the finding.
    pub fn new(severity: Severity, code: &str) -> Self {
        Self { severity, code: code.to_string() }
    }
}

//====================================================================================
// DNS Scanner Models
//====================================================================================

/// Holds data for a Sender Policy Framework (SPF) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfData {
    pub record: String,
}

/// Holds data for a Domain-based Message Authentication, Reporting, and Conformance (DMARC) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcData {
    pub record: String,
    pub policy: Option<String>,
}

/// Holds data for a DomainKeys Identified Mail (DKIM) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimRecord {
    pub selector: String,
    pub record: String,
}

/// Aggregates the results of a DNS scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResults {
    pub spf: ScanResult<SpfData>,
    pub dmarc: ScanResult<DmarcData>,
    pub dkim: ScanResult<Vec<DkimRecord>>,
    pub caa: ScanResult<Vec<String>>,
    pub analysis: Vec<AnalysisFinding>,
}

impl Default for DnsResults {
    /// Provides a default, empty state for `DnsResults`.
    fn default() -> Self {
        Self {
            spf: Ok(None),
            dmarc: Ok(None),
            dkim: Ok(None),
            caa: Ok(None),
            analysis: Vec::new(),
        }
    }
}

//====================================================================================
// SSL/TLS Scanner Models
//====================================================================================

/// Contains detailed information extracted from an SSL/TLS certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject_name: String,
    pub issuer_name: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub days_until_expiry: i64,
}

/// Holds the core data from an SSL/TLS scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslData {
    pub is_valid: bool,
    pub certificate_info: CertificateInfo,
}

/// Aggregates the results of an SSL/TLS scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslResults {
    pub scan: ScanResult<SslData>,
    pub analysis: Vec<AnalysisFinding>,
}

impl Default for SslResults {
    /// Provides a default, empty state for `SslResults`.
    fn default() -> Self {
        Self {
            scan: Ok(None),
            analysis: Vec::new(),
        }
    }
}

//====================================================================================
// HTTP Headers Scanner Models
//====================================================================================

/// A generic struct to hold the value of a single HTTP header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderData {
    pub value: String,
}

/// Aggregates the results of an HTTP security headers scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadersResults {
    pub hsts: ScanResult<HeaderData>,
    pub csp: ScanResult<HeaderData>,
    pub x_frame_options: ScanResult<HeaderData>,
    pub x_content_type_options: ScanResult<HeaderData>,
    pub error: Option<String>,
    pub analysis: Vec<AnalysisFinding>,
}

impl Default for HeadersResults {
    /// Provides a default, empty state for `HeadersResults`.
    fn default() -> Self {
        Self {
            hsts: Ok(None),
            csp: Ok(None),
            x_frame_options: Ok(None),
            x_content_type_options: Ok(None),
            error: None,
            analysis: Vec::new(),
        }
    }
}

//====================================================================================
// Fingerprint Scanner Models
//====================================================================================

/// Holds information about a detected technology (e.g., a web framework, CMS, or library).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Technology {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
}

/// Aggregates the results of a technology fingerprinting scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintResults {
    pub technologies: Result<Vec<Technology>, String>,
}

impl Default for FingerprintResults {
    /// Provides a default, empty state for `FingerprintResults`.
    fn default() -> Self {
        Self {
            technologies: Ok(Vec::new()),
        }
    }
}

//====================================================================================
// Main Scan Report
//====================================================================================

/// The main report struct that combines the results of all individual scanners
/// into a single, comprehensive report.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanReport {
    pub dns_results: DnsResults,
    pub ssl_results: SslResults,
    pub headers_results: HeadersResults,
    pub fingerprint_results: FingerprintResults,
}