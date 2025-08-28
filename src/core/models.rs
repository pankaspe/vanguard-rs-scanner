// src/core/models.rs

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Represents the severity of a finding.
/// This will be crucial for coloring the UI output.
/// We derive a few traits:
/// - `Debug`: To allow printing the struct for debugging.
/// - `Clone`: To allow copying the struct.
/// - `Serialize`, `Deserialize`: For potential future use (like saving reports).
/// - `PartialEq`: To allow comparisons (e.g., `severity == Severity::Critical`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

/// Represents a single analysis result or finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub severity: Severity,
    pub code: String, // e.g., "DNS_DMARC_MISSING"
}

/// Holds the raw data and analysis for the SPF record.
/// `Default` is derived to easily create a new, empty instance.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpfRecord {
    pub found: bool,
    pub record: Option<String>,
    pub error: Option<String>,
}

/// Holds the raw data and analysis for the DMARC record.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DmarcRecord {
    pub found: bool,
    pub record: Option<String>,
    pub policy: Option<String>, // e.g., "none", "quarantine", "reject"
    pub error: Option<String>,
}

/// A container for all DNS-related scan results.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsResults {
    pub spf: Option<SpfRecord>,
    pub dmarc: Option<DmarcRecord>,
    pub analysis: Vec<AnalysisResult>,
}


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

/// The top-level struct that holds the entire scan report.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanReport {
    pub dns_results: Option<DnsResults>,
    pub ssl_results: Option<SslResults>,
    pub headers_results: Option<HeadersResults>,
    pub fingerprint_results: Option<FingerprintResults>,
}


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


// --- NUOVE STRUCT PER IL FINGERPRINTING ---

/// Represents a single technology identified on the target.
/// We add a `category` for better reporting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)] // Aggiunto Eq, Hash per HashSet
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
    // Nota: non aggiungiamo `analysis` qui, perché il fingerprinting è informativo,
    // non basato su "problemi" con severità.
}