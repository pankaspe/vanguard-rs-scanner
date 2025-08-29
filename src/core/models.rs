// src/core/models.rs

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

// --- Core Data Models ---
// These are fundamental types used across multiple scanner modules.

/// Represents the severity of an analysis finding.
///
/// This enum defines the possible severity levels for security findings,
/// allowing for a clear, machine-readable classification of issues.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    /// Indicates a critical security vulnerability or configuration error.
    Critical,
    /// Indicates a potential issue or a non-critical misconfiguration.
    Warning,
    /// Indicates an informational finding that is not a security issue.
    Info,
}

/// Represents a single, actionable finding from a scan.
///
/// This struct aggregates a finding's severity with a specific,
/// machine-readable code, making it easy to categorize and process results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// The severity level of the finding.
    pub severity: Severity,
    /// A machine-readable code for the finding (e.g., "DNS_DMARC_MISSING").
    pub code: String,
}

// --- DNS Scanner Models ---

/// Holds the data for a discovered SPF record.
///
/// Captures the presence, value, and any errors encountered while
/// attempting to find or parse an SPF record.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpfRecord {
    /// True if an SPF record was found.
    pub found: bool,
    /// The raw string value of the SPF record, if found.
    pub record: Option<String>,
    /// An error message if the lookup or parsing failed.
    pub error: Option<String>,
}

/// Holds the data for a discovered DMARC record.
///
/// Stores details about a DMARC record, including its presence,
/// full value, and the extracted policy for easy access.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DmarcRecord {
    /// True if a DMARC record was found.
    pub found: bool,
    /// The raw string value of the DMARC record, if found.
    pub record: Option<String>,
    /// The extracted policy (p=) value, e.g., "none", "quarantine".
    pub policy: Option<String>,
    /// An error message if the lookup or parsing failed.
    pub error: Option<String>,
}

/// A container for all DNS-related scan results.
///
/// This struct groups all findings from a DNS scan, providing a consolidated
/// view of a domain's DNS security configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsResults {
    /// The result of the SPF record check.
    pub spf: Option<SpfRecord>,
    /// The result of the DMARC record check.
    pub dmarc: Option<DmarcRecord>,
    /// The result of the DKIM record check.
    pub dkim: Option<DkimResults>,
    /// The result of the CAA record check.
    pub caa: Option<CaaResults>,
    /// A list of analysis findings specific to the DNS scan.
    pub analysis: Vec<AnalysisResult>,
}
// --- SSL/TLS Scanner Models ---

/// Represents key information extracted from an SSL certificate.
///
/// Contains fundamental details about a certificate, such as names,
/// validity dates, and expiration status.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertificateInfo {
    /// The subject name of the certificate.
    pub subject_name: String,
    /// The issuer's name for the certificate.
    pub issuer_name: String,
    /// The date from which the certificate is valid.
    pub not_before: Option<DateTime<Utc>>,
    /// The date after which the certificate is no longer valid.
    pub not_after: Option<DateTime<Utc>>,
    /// The number of days remaining until the certificate expires.
    pub days_until_expiry: Option<i64>,
}

/// A container for all SSL/TLS related scan results.
///
/// This struct holds the outcome of an SSL/TLS scan, including the presence
/// and validity of a certificate, and any associated analysis findings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SslResults {
    /// True if a certificate was found on the target.
    pub certificate_found: bool,
    /// True if the certificate is considered valid (e.g., trusted, not expired).
    pub is_valid: bool,
    /// Detailed information about the certificate, if one was found.
    pub certificate_info: Option<CertificateInfo>,
    /// An error message if the SSL scan failed.
    pub error: Option<String>,
    /// A list of analysis findings specific to the SSL scan.
    pub analysis: Vec<AnalysisResult>,
}

// --- HTTP Headers Scanner Models ---

/// Represents the presence and value of a single HTTP header.
///
/// A simple struct to indicate whether a specific header exists and to
/// store its value if present.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderInfo {
    /// True if the header was found in the response.
    pub found: bool,
    /// The value of the header, if it was found.
    pub value: Option<String>,
}

/// A container for all HTTP security header scan results.
///
/// Groups the results for various security-related HTTP headers,
/// providing a quick overview of the target's header configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeadersResults {
    /// The result for the HTTP Strict Transport Security (HSTS) header.
    pub hsts: Option<HeaderInfo>,
    /// The result for the Content Security Policy (CSP) header.
    pub csp: Option<HeaderInfo>,
    /// The result for the X-Frame-Options header.
    pub x_frame_options: Option<HeaderInfo>,
    /// The result for the X-Content-Type-Options header.
    pub x_content_type_options: Option<HeaderInfo>,
    /// An error message if the header scan failed.
    pub error: Option<String>,
    /// A list of analysis findings specific to the header scan.
    pub analysis: Vec<AnalysisResult>,
}

// --- Fingerprint Scanner Models ---

/// Represents a single technology identified on the target.
///
/// This struct stores the name, category, and an optional version
/// of a detected technology, making it easy to track what's running.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Technology {
    /// The name of the technology (e.g., "Nginx", "WordPress").
    pub name: String,
    /// The category of the technology (e.g., "Web Server", "CMS").
    pub category: String,
    /// The detected version of the technology, if available.
    pub version: Option<String>,
}

/// A container for all technology fingerprinting results.
///
/// Aggregates all identified technologies and any errors encountered
/// during the fingerprinting process.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FingerprintResults {
    /// A list of all technologies found.
    pub technologies: Vec<Technology>,
    /// An error message if the fingerprinting scan failed.
    pub error: Option<String>,
}

// --- Top-Level Report ---

/// The top-level struct that aggregates all scan results into a single report.
///
/// This is the primary output struct of the scanner, combining all
/// individual scan results into a comprehensive, cohesive report.
/// All fields are guaranteed to be present, even if a scan fails. In case of
/// failure, the respective struct's `error` field will be populated.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanReport {
    /// Results from the DNS scan.
    pub dns_results: DnsResults,
    /// Results from the SSL/TLS scan.
    pub ssl_results: SslResults,
    /// Results from the HTTP security headers scan.
    pub headers_results: HeadersResults,
    /// Results from the technology fingerprinting scan.
    pub fingerprint_results: FingerprintResults,
}

/// Holds data for a discovered DKIM record for a specific selector.
///
/// Used within `DkimResults` to represent each individual DKIM record found.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DkimSelectorRecord {
    /// The DKIM selector used to find the record.
    pub selector: String,
    /// The raw string value of the DKIM record.
    pub record: String,
}

/// A container for all DKIM-related findings.
///
/// Stores information about the presence of DKIM records and lists
/// all records found for common selectors.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DkimResults {
    /// True if at least one DKIM record was found.
    pub found: bool,
    /// A list of all DKIM records found for common selectors.
    pub records: Vec<DkimSelectorRecord>,
    /// An error message if the DKIM scan failed.
    pub error: Option<String>,
}

/// A container for all CAA-related findings.
///
/// Provides a clear overview of the CAA records for a domain, including
/// their presence and a list of the records found.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaaResults {
    /// True if at least one CAA record was found.
    pub found: bool,
    /// A list of all CAA records found for the domain.
    pub records: Vec<String>,
    /// An error message if the CAA scan failed.
    pub error: Option<String>,
}