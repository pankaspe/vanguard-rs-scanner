// src/core/models.rs

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

// --- Tipi di Risultato Riutilizzabili ---
// Reusable Result Types
// A custom type alias for a Result that can hold an optional success value or a String error.
pub type ScanResult<T> = Result<Option<T>, String>;

// --- Modelli Dati Core ---
// Core Data Models

// An enumeration representing the severity level of a finding.
// The `derive` attributes enable automatic implementation of traits for debugging, cloning,
// serialization/deserialization, and comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

// A struct representing an analysis finding, containing a severity level and a string code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisFinding {
    pub severity: Severity,
    pub code: String,
}

// --- FIX: L'implementazione del costruttore va qui, una sola volta ---
// FIX: The constructor implementation goes here, only once
// An implementation block for the `AnalysisFinding` struct.
impl AnalysisFinding {
    // A constructor function to create a new `AnalysisFinding` instance.
    pub fn new(severity: Severity, code: &str) -> Self {
        Self { severity, code: code.to_string() }
    }
}


// --- Modelli Scanner DNS ---
// DNS Scanner Models

// A struct to hold data for an SPF (Sender Policy Framework) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfData {
    pub record: String,
}

// A struct to hold data for a DMARC (Domain-based Message Authentication, Reporting, and Conformance) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcData {
    pub record: String,
    pub policy: Option<String>,
}

// A struct to hold data for a DKIM (DomainKeys Identified Mail) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimRecord {
    pub selector: String,
    pub record: String,
}

// A struct that aggregates the results of a DNS scan, including SPF, DMARC, DKIM, and CAA records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResults {
    pub spf: ScanResult<SpfData>,
    pub dmarc: ScanResult<DmarcData>,
    pub dkim: ScanResult<Vec<DkimRecord>>,
    pub caa: ScanResult<Vec<String>>,
    pub analysis: Vec<AnalysisFinding>,
}

// Implementation of the `Default` trait for `DnsResults` to provide a default, empty state.
impl Default for DnsResults {
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

// --- Modelli Scanner SSL/TLS ---
// SSL/TLS Scanner Models

// A struct containing detailed information extracted from an SSL/TLS certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject_name: String,
    pub issuer_name: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub days_until_expiry: i64,
}

// A struct to hold the core data for an SSL/TLS scan, including validity and certificate info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslData {
    pub is_valid: bool,
    pub certificate_info: CertificateInfo,
}

// A struct that aggregates the results of an SSL scan, including the raw data and analysis findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslResults {
    pub scan: ScanResult<SslData>,
    pub analysis: Vec<AnalysisFinding>,
}

// Implementation of the `Default` trait for `SslResults`.
impl Default for SslResults {
    fn default() -> Self {
        Self {
            scan: Ok(None),
            analysis: Vec::new(),
        }
    }
}

// --- Modelli Scanner Header HTTP ---
// HTTP Header Scanner Models

// A struct to hold a single header's value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderData {
    pub value: String,
}

// A struct that aggregates the results of an HTTP header scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadersResults {
    pub hsts: ScanResult<HeaderData>,
    pub csp: ScanResult<HeaderData>,
    pub x_frame_options: ScanResult<HeaderData>,
    pub x_content_type_options: ScanResult<HeaderData>,
    pub error: Option<String>,
    pub analysis: Vec<AnalysisFinding>,
}

// Implementation of the `Default` trait for `HeadersResults`.
impl Default for HeadersResults {
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

// --- Modelli Scanner Fingerprint ---
// Fingerprint Scanner Models

// A struct to hold information about a detected technology (e.g., a web framework or CMS).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Technology {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
}

// A struct that aggregates the results of a technology fingerprint scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintResults {
    pub technologies: Result<Vec<Technology>, String>,
}

// Implementation of the `Default` trait for `FingerprintResults`.
impl Default for FingerprintResults {
    fn default() -> Self {
        Self {
            technologies: Ok(Vec::new()),
        }
    }
}

// --- Report Principale ---
// Main Report

// A main report struct that combines the results of all individual scanners into a single, comprehensive report.
// The `Default` trait is derived for easy initialization with empty data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanReport {
    pub dns_results: DnsResults,
    pub ssl_results: SslResults,
    pub headers_results: HeadersResults,
    pub fingerprint_results: FingerprintResults,
}