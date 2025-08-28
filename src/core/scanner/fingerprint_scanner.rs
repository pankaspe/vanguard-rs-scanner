// src/core/scanner/fingerprint_scanner.rs

use crate::core::models::{FingerprintResults, Technology};
use reqwest::header::HeaderMap;
use scraper::{Html, Selector};
use std::collections::HashSet;

// Un enum per definire i diversi tipi di controlli che possiamo fare.
enum Check<'a> {
    Header(&'a str, &'a str),       // Header name, pattern in value
    Cookie(&'a str),                // Cookie name
    MetaTag(&'a str, &'a str),      // Meta tag name, pattern in content
    BodyContains(&'a str),          // Simple text in HTML body
    ScriptSrc(&'a str),             // Pattern in a <script> src attribute
}

// Una struct per legare una regola di controllo a una tecnologia.
struct FingerprintRule<'a> {
    tech_name: &'a str,
    category: &'a str,
    check: Check<'a>,
}

// LA NOSTRA "INTELLIGENCE": Una lista di regole per identificare le tecnologie.
// Espandere questa lista è il modo per rendere lo scanner sempre più potente.
const RULES: &[FingerprintRule] = &[
    // Web Servers
    FingerprintRule { tech_name: "Nginx", category: "Web Server", check: Check::Header("server", "nginx") },
    FingerprintRule { tech_name: "Apache", category: "Web Server", check: Check::Header("server", "Apache") },
    FingerprintRule { tech_name: "Cloudflare", category: "CDN / WAF", check: Check::Header("server", "cloudflare") },
    // CMS
    FingerprintRule { tech_name: "WordPress", category: "CMS", check: Check::MetaTag("generator", "WordPress") },
    FingerprintRule { tech_name: "WordPress", category: "CMS", check: Check::BodyContains("/wp-content/") },
    FingerprintRule { tech_name: "Joomla", category: "CMS", check: Check::MetaTag("generator", "Joomla") },
    FingerprintRule { tech_name: "Shopify", category: "E-commerce", check: Check::Header("x-shopid", "") },
    // Frameworks
    FingerprintRule { tech_name: "PHP", category: "Language", check: Check::Cookie("PHPSESSID") },
    FingerprintRule { tech_name: "ASP.NET", category: "Framework", check: Check::Header("x-aspnet-version", "") },
    FingerprintRule { tech_name: "Next.js", category: "Framework", check: Check::Header("x-powered-by", "Next.js") },
    FingerprintRule { tech_name: "Next.js", category: "Framework", check: Check::ScriptSrc("_next/static") },
    // JS Libraries
    FingerprintRule { tech_name: "React", category: "JS Library", check: Check::BodyContains("data-reactroot") },
    FingerprintRule { tech_name: "Vue.js", category: "JS Library", check: Check::BodyContains("data-v-app") },
];

/// The main intelligent fingerprinting scan function.
pub async fn run_fingerprint_scan(target: &str) -> FingerprintResults {
    let client = match reqwest::Client::builder().user_agent("VanguardRS/0.1").build() {
        Ok(c) => c,
        Err(e) => return FingerprintResults { error: Some(format!("HTTP client error: {}", e)), ..Default::default() },
    };

    let url = format!("https://{}", target);
    let response = match client.get(&url).send().await {
        Ok(res) => res,
        Err(e) => return FingerprintResults { error: Some(format!("HTTP request failed: {}", e)), ..Default::default() },
    };

    // Usiamo un HashSet per evitare di aggiungere la stessa tecnologia più volte.
    let mut found_techs = HashSet::new();

    // Raccogliamo tutti i dati una sola volta.
    let headers = response.headers().clone();
    let cookies = headers.get_all("set-cookie").into_iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>();
    
    let body = match response.text().await {
        Ok(text) => text,
        Err(_) => return FingerprintResults { technologies: Vec::new(), error: Some("Failed to read response body.".to_string()) },
    };
    let document = Html::parse_document(&body);

    // Applichiamo tutte le nostre regole.
    for rule in RULES {
        let is_match = match &rule.check {
            Check::Header(name, pattern) => check_header(&headers, name, pattern),
            Check::Cookie(name) => check_cookie(&cookies, name),
            Check::MetaTag(name, pattern) => check_meta_tag(&document, name, pattern),
            Check::BodyContains(pattern) => body.contains(pattern),
            Check::ScriptSrc(pattern) => check_script_src(&document, pattern),
        };
        
        if is_match {
            found_techs.insert(Technology {
                name: rule.tech_name.to_string(),
                category: rule.category.to_string(),
                version: None, // L'estrazione della versione è un passo successivo più complesso
            });
        }
    }

    FingerprintResults {
        error: None,
        technologies: found_techs.into_iter().collect(),
    }
}

// --- Funzioni Helper per i controlli ---

fn check_header(headers: &HeaderMap, name: &str, pattern: &str) -> bool {
    headers.get(name)
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.to_lowercase().contains(&pattern.to_lowercase()))
}

fn check_cookie(cookies: &[&str], name: &str) -> bool {
    cookies.iter().any(|c| c.trim().starts_with(name))
}

fn check_meta_tag(doc: &Html, name: &str, pattern: &str) -> bool {
    let selector_str = format!("meta[name='{}']", name);
    let selector = Selector::parse(&selector_str).unwrap();
    doc.select(&selector)
        .next()
        .and_then(|el| el.value().attr("content"))
        .map_or(false, |c| c.to_lowercase().contains(&pattern.to_lowercase()))
}

fn check_script_src(doc: &Html, pattern: &str) -> bool {
    let selector = Selector::parse("script[src]").unwrap();
    doc.select(&selector)
        .filter_map(|el| el.value().attr("src"))
        .any(|src| src.contains(pattern))
}