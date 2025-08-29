// src/core/scanner/fingerprint_scanner.rs

use crate::core::models::{FingerprintResults, Technology};
use scraper::{Html, Selector};
use std::collections::HashMap;
use regex::Regex;
use once_cell::sync::Lazy;

/// An enum representing the different types of checks to perform for fingerprinting.
///
/// This provides a flexible and extensible way to define a rule, allowing it to
/// target HTTP headers, meta tags, body content, or specific HTML element attributes.
enum Check<'a> {
    /// Checks for a specific HTTP header and uses a regex to find a match and capture a version.
    Header(&'a str, &'a Lazy<Regex>),
    /// Parses the HTML document to find a `<meta>` tag with a given name and checks its content.
    MetaTag(&'a str, &'a Lazy<Regex>),
    /// Checks the entire HTML body for a regex pattern.
    Body(&'a Lazy<Regex>),
    /// Iterates through all `<script>` tags and checks their `src` attribute.
    ScriptSrc(&'a Lazy<Regex>),
    /// Iterates through all `<link>` tags and checks their `href` attribute.
    LinkHref(&'a Lazy<Regex>),
    /// Checks the `Set-Cookie` header for a specific regex pattern.
    Cookie(&'a Lazy<Regex>),
}

/// A struct that defines a single fingerprinting rule.
///
/// Each rule links a technology name and category to a specific `Check` type.
struct FingerprintRule<'a> {
    /// The name of the technology (e.g., "Nginx").
    tech_name: &'a str,
    /// The category of the technology (e.g., "Web Server").
    category: &'a str,
    /// The specific check to perform to identify this technology.
    check: Check<'a>,
}

// --- Massively Expanded "Intelligence" Database ---
// This section uses `once_cell::sync::Lazy` to ensure that Regex objects are
// compiled only once, on first use, which is a performance best practice.

// Web Servers & CDNs
static RE_NGINX: Lazy<Regex> = Lazy::new(|| Regex::new(r"nginx/([\d\.]+)").unwrap());
static RE_NGINX_ERROR: Lazy<Regex> = Lazy::new(|| Regex::new(r"<hr><center>nginx</center>").unwrap()); // Resilient check
static RE_APACHE: Lazy<Regex> = Lazy::new(|| Regex::new(r"Apache/([\d\.]+)").unwrap());
static RE_APACHE_ERROR: Lazy<Regex> = Lazy::new(|| Regex::new(r"Apache Server at").unwrap()); // Resilient check
static RE_CLOUDFLARE: Lazy<Regex> = Lazy::new(|| Regex::new(r"cloudflare").unwrap());
static RE_LITESPEED: Lazy<Regex> = Lazy::new(|| Regex::new(r"LiteSpeed").unwrap());

// CMS & E-commerce
static RE_WORDPRESS: Lazy<Regex> = Lazy::new(|| Regex::new(r"WordPress ([\d\.]+)").unwrap());
static RE_WP_EMBED: Lazy<Regex> = Lazy::new(|| Regex::new(r"/wp-content/|/wp-includes/").unwrap());
static RE_WP_LOGIN: Lazy<Regex> = Lazy::new(|| Regex::new(r"wp-login\.php").unwrap());
static RE_JOOMLA: Lazy<Regex> = Lazy::new(|| Regex::new(r"Joomla!").unwrap());
static RE_SHOPIFY: Lazy<Regex> = Lazy::new(|| Regex::new(r"shopify").unwrap());
static RE_MAGENTO: Lazy<Regex> = Lazy::new(|| Regex::new(r"magento").unwrap());

// Frameworks & Languages
static RE_PHP: Lazy<Regex> = Lazy::new(|| Regex::new(r"PHP/([\d\.]+)").unwrap());
static RE_PHPSESSID: Lazy<Regex> = Lazy::new(|| Regex::new(r"PHPSESSID").unwrap());
static RE_ASPNET: Lazy<Regex> = Lazy::new(|| Regex::new(r"ASP\.NET").unwrap());
static RE_JSESSIONID: Lazy<Regex> = Lazy::new(|| Regex::new(r"JSESSIONID").unwrap()); // For Java
static RE_DJANGO_CSRF: Lazy<Regex> = Lazy::new(|| Regex::new(r"csrftoken").unwrap()); // For Python/Django
static RE_RUBY_RAILS: Lazy<Regex> = Lazy::new(|| Regex::new(r"_rails_session").unwrap());

// JS Frameworks
static RE_NEXTJS: Lazy<Regex> = Lazy::new(|| Regex::new(r"Next\.js ([\d\.]+)").unwrap());
static RE_NEXTJS_SCRIPT: Lazy<Regex> = Lazy::new(|| Regex::new(r"/_next/static/").unwrap());
static RE_NUXTJS: Lazy<Regex> = Lazy::new(|| Regex::new(r"__NUXT__").unwrap()); // For Nuxt.js
static RE_ANGULAR: Lazy<Regex> = Lazy::new(|| Regex::new(r#"ng-version="([\d\.]+)""#).unwrap());
static RE_SOLIDJS: Lazy<Regex> = Lazy::new(|| Regex::new(r"data-hk=").unwrap());
static RE_SVELTE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"class=["']svelte-"#).unwrap());
static RE_GATSBY: Lazy<Regex> = Lazy::new(|| Regex::new(r#"id=["']___gatsby["']"#).unwrap());
static RE_ASTRO: Lazy<Regex> = Lazy::new(|| Regex::new(r"Astro v([\d\.]+)").unwrap()); // Astro generator tag

// JS Libraries & UI
static RE_JQUERY: Lazy<Regex> = Lazy::new(|| Regex::new(r"jquery[\.min|\.slim|\.js|/](-|\?v=)?([\d\.]+)").unwrap());
static RE_JQUERY_FN: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\.fn\.jquery: "([\d\.]+)""#).unwrap());
static RE_REACT: Lazy<Regex> = Lazy::new(|| Regex::new(r"react-dom|data-reactroot|react\.development").unwrap());
static RE_VUE: Lazy<Regex> = Lazy::new(|| Regex::new(r"data-v-app|__VUE_").unwrap());
static RE_BOOTSTRAP: Lazy<Regex> = Lazy::new(|| Regex::new(r"bootstrap.min.css").unwrap());
static RE_GOOGLE_ANALYTICS: Lazy<Regex> = Lazy::new(|| Regex::new(r"google-analytics.com/|googletagmanager.com/").unwrap());

/// The master list of all fingerprinting rules.
///
/// This static array serves as the "knowledge base" for the fingerprinting scan.
static RULES: &[FingerprintRule] = &[
    // Web Servers & CDNs (with resilient fallbacks)
    FingerprintRule { tech_name: "Nginx", category: "Web Server", check: Check::Header("server", &RE_NGINX) },
    FingerprintRule { tech_name: "Nginx", category: "Web Server", check: Check::Body(&RE_NGINX_ERROR) },
    FingerprintRule { tech_name: "Apache", category: "Web Server", check: Check::Header("server", &RE_APACHE) },
    FingerprintRule { tech_name: "Apache", category: "Web Server", check: Check::Body(&RE_APACHE_ERROR) },
    FingerprintRule { tech_name: "Cloudflare", category: "CDN / WAF", check: Check::Header("server", &RE_CLOUDFLARE) },
    FingerprintRule { tech_name: "LiteSpeed", category: "Web Server", check: Check::Header("server", &RE_LITESPEED) },
    
    // CMS (with multiple detection rules)
    FingerprintRule { tech_name: "WordPress", category: "CMS", check: Check::MetaTag("generator", &RE_WORDPRESS) },
    FingerprintRule { tech_name: "WordPress", category: "CMS", check: Check::Body(&RE_WP_EMBED) },
    FingerprintRule { tech_name: "WordPress", category: "CMS", check: Check::Body(&RE_WP_LOGIN) },
    FingerprintRule { tech_name: "Joomla", category: "CMS", check: Check::MetaTag("generator", &RE_JOOMLA) },
    FingerprintRule { tech_name: "Shopify", category: "E-commerce", check: Check::Header("x-shopid", &RE_SHOPIFY) },
    FingerprintRule { tech_name: "Magento", category: "E-commerce", check: Check::Cookie(&RE_MAGENTO) },
    
    // Server-Side Languages & Frameworks
    FingerprintRule { tech_name: "PHP", category: "Language", check: Check::Header("x-powered-by", &RE_PHP) },
    FingerprintRule { tech_name: "PHP", category: "Language", check: Check::Cookie(&RE_PHPSESSID) },
    FingerprintRule { tech_name: "ASP.NET", category: "Framework", check: Check::Header("x-aspnet-version", &RE_ASPNET) },
    FingerprintRule { tech_name: "Java", category: "Language", check: Check::Cookie(&RE_JSESSIONID) },
    FingerprintRule { tech_name: "Python/Django", category: "Framework", check: Check::Cookie(&RE_DJANGO_CSRF) },
    FingerprintRule { tech_name: "Ruby on Rails", category: "Framework", check: Check::Cookie(&RE_RUBY_RAILS) },

    // Modern JS Frameworks
    FingerprintRule { tech_name: "Next.js", category: "JS Framework", check: Check::Header("x-powered-by", &RE_NEXTJS) },
    FingerprintRule { tech_name: "Next.js", category: "JS Framework", check: Check::ScriptSrc(&RE_NEXTJS_SCRIPT) },
    FingerprintRule { tech_name: "Nuxt.js", category: "JS Framework", check: Check::Body(&RE_NUXTJS) },
    FingerprintRule { tech_name: "Angular", category: "JS Framework", check: Check::Body(&RE_ANGULAR) },
    FingerprintRule { tech_name: "SolidJS", category: "JS Framework", check: Check::Body(&RE_SOLIDJS) },
    FingerprintRule { tech_name: "Svelte", category: "JS Framework", check: Check::Body(&RE_SVELTE) },
    FingerprintRule { tech_name: "Gatsby", category: "JS Framework", check: Check::Body(&RE_GATSBY) },
    FingerprintRule { tech_name: "Astro", category: "JS Framework", check: Check::MetaTag("generator", &RE_ASTRO) },
    FingerprintRule { tech_name: "React", category: "JS Library", check: Check::Body(&RE_REACT) },
    FingerprintRule { tech_name: "Vue.js", category: "JS Library", check: Check::Body(&RE_VUE) },

    // JS Libraries, UI & Analytics
    FingerprintRule { tech_name: "jQuery", category: "JS Library", check: Check::ScriptSrc(&RE_JQUERY) },
    FingerprintRule { tech_name: "jQuery", category: "JS Library", check: Check::Body(&RE_JQUERY_FN) },
    FingerprintRule { tech_name: "Bootstrap", category: "UI Framework", check: Check::LinkHref(&RE_BOOTSTRAP) },
    FingerprintRule { tech_name: "Google Analytics", category: "Analytics", check: Check::ScriptSrc(&RE_GOOGLE_ANALYTICS) },
];


/// Executes a technology fingerprinting scan on a given target URL.
///
/// This function makes an HTTP request, retrieves the response headers and body,
/// and then applies a set of predefined rules to identify technologies.
///
/// # Arguments
/// * `target` - The domain to scan (e.g., "example.com").
///
/// # Returns
/// A `FingerprintResults` struct containing a list of found technologies.
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

    let mut found_techs: HashMap<String, Technology> = HashMap::new();
    let headers = response.headers().clone();
    let cookies = headers.get_all("set-cookie").into_iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>().join("; ");
    let body = match response.text().await {
        Ok(text) => text,
        Err(_) => return FingerprintResults { technologies: Vec::new(), error: Some("Failed to read response body.".to_string()) },
    };
    let document = Html::parse_document(&body);

    // Iterate through all rules and apply the appropriate check.
    for rule in RULES {
        let version = match &rule.check {
            Check::Header(name, re) => check_with_regex(headers.get(*name).and_then(|v| v.to_str().ok()), re),
            Check::MetaTag(name, re) => check_meta_tag(&document, name, re),
            Check::Body(re) => check_with_regex(Some(&body), re),
            Check::ScriptSrc(re) => check_script_src(&document, re),
            Check::LinkHref(re) => check_link_href(&document, re),
            Check::Cookie(re) => check_with_regex(Some(&cookies), re),
        };
        
        // If a technology is found, add it to the results, preferring a version if one is found.
        if let Some(v) = version {
            let tech_name_str = rule.tech_name.to_string();
            // Check if we already found this technology via another rule.
            if let Some(existing_tech) = found_techs.get_mut(&tech_name_str) {
                // If the existing entry doesn't have a version but the new one does, update it.
                if existing_tech.version.is_none() && v.is_some() {
                    existing_tech.version = v;
                }
            } else {
                // If it's a new technology, insert it.
                found_techs.insert(tech_name_str, Technology {
                    name: rule.tech_name.to_string(),
                    category: rule.category.to_string(),
                    version: v,
                });
            }
        }
    }

    // Convert the HashMap into a Vec<Technology> for the final report.
    FingerprintResults {
        error: None,
        technologies: found_techs.into_values().collect(),
    }
}

/// A generic helper function to apply a regex to a string and capture a version.
///
/// Returns `Some(Some(version))` if a version is captured, `Some(None)` if a match is found
/// but no version is captured, and `None` if no match is found at all.
fn check_with_regex(text_option: Option<&str>, re: &Regex) -> Option<Option<String>> {
    text_option.and_then(|text| {
        re.captures(text).map(|caps| {
            caps.get(1)
                .map(|m| m.as_str().to_string())
                .filter(|s| !s.is_empty())
        })
    })
}

/// Helper function to check a `<meta>` tag for a matching pattern.
fn check_meta_tag(doc: &Html, name: &str, re: &Regex) -> Option<Option<String>> {
    let selector_str = format!("meta[name='{}']", name);
    if let Ok(selector) = Selector::parse(&selector_str) {
        let content = doc.select(&selector).next().and_then(|el| el.value().attr("content"));
        return check_with_regex(content, re);
    }
    None
}

/// Helper function to check the `src` attribute of `<script>` tags.
fn check_script_src(doc: &Html, re: &Regex) -> Option<Option<String>> {
    if let Ok(selector) = Selector::parse("script[src]") {
        for el in doc.select(&selector) {
            if let Some(src) = el.value().attr("src") {
                if let Some(version) = check_with_regex(Some(src), re) {
                    return Some(version);
                }
            }
        }
    }
    None
}

/// Helper function to check the `href` attribute of `<link>` tags.
fn check_link_href(doc: &Html, re: &Regex) -> Option<Option<String>> {
    if let Ok(selector) = Selector::parse("link[href]") {
        for el in doc.select(&selector) {
            if let Some(href) = el.value().attr("href") {
                if let Some(version) = check_with_regex(Some(href), re) {
                    return Some(version);
                }
            }
        }
    }
    None
}