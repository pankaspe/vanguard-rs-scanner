//! This module acts as the central "brain" of the scanner.
//! It contains a static, read-only database of all possible security findings,
//! complete with detailed, human-readable explanations and remediation steps.
//! Making this data-driven allows for easy updates and maintenance of the scanner's intelligence.

use crate::core::models::Severity;
use std::fmt;

/// Defines the high-level categories for security findings.
/// This is used to group related issues together in the user interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingCategory {
    /// Findings related to DNS records (e.g., SPF, DMARC, DKIM, CAA).
    Dns,
    /// Findings related to SSL/TLS certificates and configuration.
    Ssl,
    /// Findings related to HTTP security headers.
    Http,
}

/// Implements the `Display` trait to provide a human-friendly name for each category.
/// This is used for rendering titles in the UI.
impl fmt::Display for FindingCategory {
    /// Formats the `FindingCategory` enum for display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingCategory::Dns => write!(f, "DNS Configuration"),
            FindingCategory::Ssl => write!(f, "SSL/TLS Certificate"),
            FindingCategory::Http => write!(f, "HTTP Security Headers"),
        }
    }
}

/// A struct that holds all the detailed, human-readable information about a specific finding.
///
/// This is the core data structure of the knowledge base, containing all necessary
/// information to present a finding to a user, including its severity, description,
/// and remediation advice.
pub struct FindingDetail {
    /// A unique, machine-readable identifier for the finding (e.g., "DNS_DMARC_MISSING").
    pub code: &'static str,
    /// A short, human-readable title for the finding.
    pub title: &'static str,
    /// The category this finding belongs to.
    pub category: FindingCategory,
    /// The severity level of the finding (e.g., Critical, Warning, Info).
    pub severity: Severity,
    /// A detailed but easy-to-understand explanation of what the finding means and why it's a problem.
    pub description: &'static str,
    /// Clear, actionable steps the user can take to fix the issue.
    pub remediation: &'static str,
}

/// The centralized, static knowledge base of all possible findings.
///
/// This array is the core data that drives the analysis reports. Each entry provides
/// the complete context for a specific `AnalysisResult` code.
static FINDINGS: &[FindingDetail] = &[
    // --- DNS: Email Security & Domain Integrity ---
    FindingDetail {
        code: "DNS_DMARC_MISSING",
        title: "DMARC Record Missing",
        category: FindingCategory::Dns,
        severity: Severity::Critical,
        description: "DMARC is an email authentication policy that protects your domain from being used for email spoofing and phishing. It tells receiving mail servers how to handle emails that fail authentication checks.",
        remediation: "Add a DMARC record to your domain's DNS settings. Start with a monitoring policy like 'v=DMARC1; p=none;' and gradually move to 'p=quarantine' or 'p=reject' after analyzing reports."
    },
    FindingDetail {
        code: "DNS_DMARC_POLICY_NONE",
        title: "DMARC Policy is 'none'",
        category: FindingCategory::Dns,
        severity: Severity::Warning,
        description: "Your DMARC policy is in 'monitoring only' mode. It reports fraudulent emails but does not instruct receivers to block or quarantine them, offering no active protection against spoofing.",
        remediation: "After ensuring your legitimate emails pass SPF/DKIM, update your DMARC policy to 'p=quarantine' (sends to spam) or 'p=reject' (blocks delivery) to actively protect your domain."
    },
    FindingDetail {
        code: "DNS_SPF_MISSING",
        title: "SPF Record Missing",
        category: FindingCategory::Dns,
        severity: Severity::Warning,
        description: "Sender Policy Framework (SPF) is a DNS record that lists all the servers authorized to send email on behalf of your domain. Without it, attackers can more easily spoof emails from your domain.",
        remediation: "Create a TXT record for your domain that defines your authorized mail servers. A simple example for Google Workspace is 'v=spf1 include:_spf.google.com ~all'."
    },
    FindingDetail {
        code: "DNS_SPF_POLICY_SOFTFAIL",
        title: "SPF Policy is 'Softfail'",
        category: FindingCategory::Dns,
        severity: Severity::Info,
        description: "Your SPF record uses '~all' (softfail), which suggests that receiving servers should accept but mark suspicious mail. This is less secure than '-all' (fail), which instructs servers to reject the mail.",
        remediation: "If you are confident your SPF record lists all legitimate mail sources, consider changing the ending from '~all' to '-all' for stricter enforcement."
    },
    FindingDetail {
        code: "DNS_SPF_POLICY_NEUTRAL",
        title: "SPF Policy is 'Neutral'",
        category: FindingCategory::Dns,
        severity: Severity::Info,
        description: "Your SPF record uses '?all' (neutral), which provides no definitive policy on the mail's legitimacy. It essentially tells receivers 'I don't know if this is valid,' offering no protection.",
        remediation: "This policy should be avoided. Change '?all' to '~all' (softfail) or, preferably, '-all' (fail) to provide a clear security policy to receiving mail servers."
    },
    FindingDetail {
        code: "DNS_DKIM_MISSING",
        title: "DKIM Record Missing",
        category: FindingCategory::Dns,
        severity: Severity::Info,
        description: "DKIM (DomainKeys Identified Mail) adds a tamper-proof digital signature to emails. This signature confirms that the email was sent from your domain and that its content has not been altered in transit.",
        remediation: "Enable DKIM signing in your email service provider's control panel. This typically involves generating a key and adding the public part as a TXT record to your DNS."
    },
    FindingDetail {
        code: "DNS_CAA_MISSING",
        title: "CAA Record Missing",
        category: FindingCategory::Dns,
        severity: Severity::Info,
        description: "A Certificate Authority Authorization (CAA) record specifies which Certificate Authorities (CAs) are allowed to issue SSL/TLS certificates for your domain. This acts as a safeguard against certificate mis-issuance.",
        remediation: "Add a CAA record to your DNS to lock down certificate issuance to your chosen provider(s). For example: '0 issue \"letsencrypt.org\"'."
    },

    // --- SSL/TLS: Secure Communication Layer ---
      FindingDetail {
        code: "SSL_HANDSHAKE_FAILED",
        title: "TLS Handshake Failed",
        category: FindingCategory::Ssl,
        severity: Severity::Critical,
        description: "The scanner could not establish a secure TLS connection with the server. This can be caused by an invalid/missing certificate, unsupported cipher suites, or other critical server misconfigurations.",
        remediation: "Ensure a valid, trusted SSL/TLS certificate is installed on the server for the correct domain. Use an online tool like SSL Labs to diagnose TLS configuration issues."
    },
    FindingDetail {
        code: "SSL_EXPIRED",
        title: "SSL Certificate Expired",
        category: FindingCategory::Ssl,
        severity: Severity::Critical,
        description: "The website's SSL certificate is expired. This will cause browsers to show prominent security warnings, block access, and destroy user trust.",
        remediation: "Renew the SSL certificate immediately. Implement automated renewal processes (e.g., via Let's Encrypt / Certbot) to prevent this from happening in the future."
    },
    FindingDetail {
        code: "SSL_EXPIRING_SOON",
        title: "SSL Certificate Expiring Soon",
        category: FindingCategory::Ssl,
        severity: Severity::Warning,
        description: "The SSL certificate will expire in less than 30 days. This is an early warning to prevent service disruption and loss of trust.",
        remediation: "Renew the SSL certificate before it expires. If you have automated renewals, verify that the system is functioning correctly."
    },

    // --- HTTP Headers: Hardening the Application Layer ---
    FindingDetail {
        code: "HEADERS_REQUEST_FAILED",
        title: "HTTP Request Failed",
        category: FindingCategory::Http,
        severity: Severity::Critical,
        description: "The scanner could not connect to the target server to check its HTTP headers. The server might be down, unreachable, or blocking automated requests.",
        remediation: "Verify that the target is online and accessible from the public internet. Check for firewalls or network issues that might be blocking the connection."
    },
    FindingDetail {
        code: "HEADERS_HSTS_MISSING",
        title: "HSTS Header Missing",
        category: FindingCategory::Http,
        severity: Severity::Warning,
        description: "The HTTP Strict-Transport-Security (HSTS) header instructs browsers to only communicate with your site over HTTPS. It protects against protocol downgrade attacks and cookie hijacking.",
        remediation: "Add the 'Strict-Transport-Security' header to your web server responses. A strong value is 'max-age=31536000; includeSubDomains; preload'."
    },
    FindingDetail {
        code: "HEADERS_CSP_MISSING",
        title: "CSP Header Missing",
        category: FindingCategory::Http,
        severity: Severity::Warning,
        description: "Content-Security-Policy (CSP) is a powerful security layer that helps prevent attacks like Cross-Site Scripting (XSS) and data injection by defining which resources a browser is allowed to load.",
        remediation: "Implement a Content-Security-Policy header that defines trusted sources for scripts, styles, and other assets. Start with a restrictive policy and gradually open it up as needed."
    },
    FindingDetail {
        code: "HEADERS_X_FRAME_OPTIONS_MISSING",
        title: "X-Frame-Options Missing",
        category: FindingCategory::Http,
        severity: Severity::Warning,
        description: "This header protects your visitors against 'clickjacking' attacks, where an attacker loads your site in an invisible iframe to trick users into clicking on malicious content.",
        remediation: "Add the 'X-Frame-Options' header and set it to 'DENY' (no framing allowed) or 'SAMEORIGIN' (only you can frame your site)."
    },
    FindingDetail {
        code: "HEADERS_X_CONTENT_TYPE_OPTIONS_MISSING",
        title: "X-Content-Type-Options Missing",
        category: FindingCategory::Http,
        severity: Severity::Info,
        description: "This header prevents browsers from trying to guess the content type of a file (MIME sniffing). This mitigates attacks where a file disguised as an image could be executed as a script.",
        remediation: "Add the 'X-Content-Type-Options' header and set its value to 'nosniff'. It's a simple and effective security enhancement."
    },
];

/// Retrieves the full detail for a given finding code from the static knowledge base.
///
/// # Arguments
///
/// * `code` - The machine-readable code for the finding.
///
/// # Returns
///
/// An `Option` containing a reference to the `FindingDetail` if the code is found,
/// or `None` if the code does not exist in the knowledge base.
pub fn get_finding_detail(code: &str) -> Option<&'static FindingDetail> {
    FINDINGS.iter().find(|f| f.code == code)
}