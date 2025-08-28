// src/core/models.rs

use serde::{Serialize, Deserialize};

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