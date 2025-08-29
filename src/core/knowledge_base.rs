use crate::core::models::Severity;
use std::fmt;

// NUOVO ENUM: Definiamo le categorie dei problemi.
// Aggiungiamo i "derive" per poterle poi ordinare facilmente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingCategory {
    Dns,
    Ssl,
    Http,
}

// NUOVO: Implementiamo il trait Display per stampare un nome leggibile per ogni categoria.
impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingCategory::Dns => write!(f, "DNS Configuration"),
            FindingCategory::Ssl => write!(f, "SSL/TLS Certificate"),
            FindingCategory::Http => write!(f, "HTTP Security Headers"),
        }
    }
}


/// Contains detailed, human-readable information about a specific finding.
pub struct FindingDetail {
    pub code: &'static str,
    pub title: &'static str,
    // NUOVO CAMPO: Aggiungiamo la categoria a ogni problema.
    pub category: FindingCategory,
    pub severity: Severity,
    pub description: &'static str,
    pub remediation: &'static str,
}

/// A centralized knowledge base of all possible findings.
const FINDINGS: &[FindingDetail] = &[
    // --- DNS ---
    FindingDetail {
        code: "DNS_DMARC_MISSING",
        title: "DMARC Record Missing",
        category: FindingCategory::Dns, // <-- Aggiunto
        severity: Severity::Critical,
        description: "WHAT IT IS: DMARC is an email authentication policy that protects your domain from being used for email spoofing, phishing, and other cybercrimes by telling receiving mail servers how to handle unauthenticated mail.",
        remediation: "HOW TO FIX: Add a DMARC record to your domain's DNS settings. Start with a simple policy like 'v=DMARC1; p=none;' and gradually move to 'p=quarantine' or 'p=reject' after monitoring reports."
    },
    FindingDetail {
        code: "DNS_DMARC_POLICY_NONE",
        title: "DMARC Policy is 'none'",
        category: FindingCategory::Dns, // <-- Aggiunto
        severity: Severity::Warning,
        description: "WHAT IT IS: Your DMARC policy is in 'monitoring only' mode. It reports fraudulent emails but does not instruct receivers to block or quarantine them, offering no real protection.",
        remediation: "HOW TO FIX: After ensuring legitimate emails are passing SPF/DKIM checks, update your DMARC policy to 'p=quarantine' (sends to spam) or 'p=reject' (blocks delivery) to actively protect your domain."
    },
    FindingDetail {
        code: "DNS_SPF_MISSING",
        title: "SPF Record Missing",
        category: FindingCategory::Dns, // <-- Aggiunto
        severity: Severity::Warning,
        description: "WHAT IT IS: Sender Policy Framework (SPF) is a DNS record that lists the mail servers authorized to send email on behalf of your domain. Without it, attackers can more easily send emails that appear to come from you.",
        remediation: "HOW TO FIX: Create a TXT record for your domain that defines your authorized mail servers. A simple example for Google Workspace is 'v=spf1 include:_spf.google.com ~all'."
    },
    // --- SSL/TLS ---
     FindingDetail {
        code: "SSL_HANDSHAKE_FAILED",
        title: "TLS Handshake Failed",
        category: FindingCategory::Ssl, // <-- Aggiunto
        severity: Severity::Critical,
        description: "WHAT IT IS: The client could not establish a secure TLS connection. This can be due to an invalid or missing certificate, unsupported cipher suites, or other server misconfigurations.",
        remediation: "HOW TO FIX: Ensure a valid, trusted SSL/TLS certificate is installed on the server for the correct domain. Check your server's TLS configuration for compatibility with modern clients."
    },
    FindingDetail {
        code: "SSL_EXPIRED",
        title: "SSL Certificate Expired",
        category: FindingCategory::Ssl, // <-- Aggiunto
        severity: Severity::Critical,
        description: "WHAT IT IS: The website's SSL certificate is either expired or not yet valid. This will cause browsers to show prominent security warnings, eroding user trust.",
        remediation: "HOW TO FIX: Renew the SSL certificate immediately. Set up automated renewal processes with services like Let's Encrypt to prevent this from happening in the future."
    },
    FindingDetail {
        code: "SSL_EXPIRING_SOON",
        title: "SSL Certificate Expiring Soon",
        category: FindingCategory::Ssl, // <-- Aggiunto
        severity: Severity::Warning,
        description: "WHAT IT IS: The SSL certificate will expire in less than 30 days. This is an early warning to prevent service disruption.",
        remediation: "HOW TO FIX: Renew the SSL certificate before it expires. Verify that your automated renewal systems are functioning correctly."
    },
    // --- HTTP Headers ---
    FindingDetail {
        code: "HEADERS_REQUEST_FAILED",
        title: "HTTP Request Failed",
        category: FindingCategory::Http, // <-- Aggiunto
        severity: Severity::Critical,
        description: "WHAT IT IS: The application could not connect to the target server to check its HTTP headers. The server might be down, unreachable, or blocking requests.",
        remediation: "HOW TO FIX: Verify the target is online and accessible. Check for firewalls or network issues that might be blocking the connection."
    },
    FindingDetail {
        code: "HEADERS_HSTS_MISSING",
        title: "HSTS Header Missing",
        category: FindingCategory::Http, // <-- Aggiunto
        severity: Severity::Warning,
        description: "WHAT IT IS: The HTTP Strict-Transport-Security (HSTS) header forces browsers to use HTTPS, protecting against protocol downgrade attacks and cookie hijacking.",
        remediation: "HOW TO FIX: Add the 'Strict-Transport-Security' header to your web server responses. A common value is 'max-age=31536000; includeSubDomains'."
    },
    // ... continua ad aggiungere `category: FindingCategory::Http` a tutti gli altri finding sugli header
    FindingDetail {
        code: "HEADERS_CSP_MISSING",
        title: "CSP Header Missing",
        category: FindingCategory::Http, // <-- Aggiunto
        severity: Severity::Warning,
        description: "WHAT IT IS: Content-Security-Policy (CSP) is a security layer that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection.",
        remediation: "HOW TO FIX: Implement a Content-Security-Policy header that defines which resources are allowed to be loaded, reducing the risk of malicious script execution."
    },
    FindingDetail {
        code: "HEADERS_X_FRAME_OPTIONS_MISSING",
        title: "X-Frame-Options Missing",
        category: FindingCategory::Http, // <-- Aggiunto
        severity: Severity::Warning,
        description: "WHAT IT IS: This header protects your visitors against 'clickjacking' attacks, where an attacker uses an iframe to trick users into clicking on something malicious.",
        remediation: "HOW TO FIX: Add the 'X-Frame-Options' header and set it to 'DENY' or 'SAMEORIGIN' to prevent your site from being embedded in other pages."
    },
    FindingDetail {
        code: "HEADERS_X_CONTENT_TYPE_OPTIONS_MISSING",
        title: "X-Content-Type-Options Missing",
        category: FindingCategory::Http, // <-- Aggiunto
        severity: Severity::Info,
        description: "WHAT IT IS: This header prevents the browser from interpreting files as a different MIME type than what is specified, which can help mitigate some types of attacks.",
        remediation: "HOW TO FIX: Add the 'X-Content-Type-Options' header and set its value to 'nosniff'."
    },
];

/// Retrieves the full detail for a given finding code.
pub fn get_finding_detail(code: &str) -> Option<&'static FindingDetail> {
    FINDINGS.iter().find(|f| f.code == code)
}