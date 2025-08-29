// src/core/scanner/fingerprint_scanner.rs

use crate::core::models::{FingerprintResults, Technology};
use reqwest::header::HeaderMap;
use scraper::{Html, Selector};
use std::collections::HashMap;
use regex::Regex;
use once_cell::sync::Lazy;

// Added a new check type for <link href="..."> tags, crucial for CSS frameworks.
enum Check<'a> {
    Header(&'a str, &'a Lazy<Regex>),
    MetaTag(&'a str, &'a Lazy<Regex>),
    Body(&'a Lazy<Regex>),
    ScriptSrc(&'a Lazy<Regex>),
    LinkHref(&'a Lazy<Regex>), // To check CSS frameworks like Bootstrap
    Cookie(&'a Lazy<Regex>),
}

struct FingerprintRule<'a> {
    tech_name: &'a str,
    category: &'a str,
    check: Check<'a>,
}

// --- Massively Expanded "Intelligence" Database ---

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

    for rule in RULES {
        let version = match &rule.check {
            Check::Header(name, re) => check_with_regex(headers.get(*name).and_then(|v| v.to_str().ok()), re),
            Check::MetaTag(name, re) => check_meta_tag(&document, name, re),
            Check::Body(re) => check_with_regex(Some(&body), re),
            Check::ScriptSrc(re) => check_script_src(&document, re),
            Check::LinkHref(re) => check_link_href(&document, re), // Logic for the new check
            Check::Cookie(re) => check_with_regex(Some(&cookies), re),
        };
        
        if let Some(v) = version {
            let tech_name_str = rule.tech_name.to_string();
            if let Some(existing_tech) = found_techs.get_mut(&tech_name_str) {
                if existing_tech.version.is_none() && v.is_some() {
                    existing_tech.version = v;
                }
            } else {
                found_techs.insert(tech_name_str, Technology {
                    name: rule.tech_name.to_string(),
                    category: rule.category.to_string(),
                    version: v,
                });
            }
        }
    }

    FingerprintResults {
        error: None,
        technologies: found_techs.into_values().collect(),
    }
}

fn check_with_regex(text_option: Option<&str>, re: &Regex) -> Option<Option<String>> {
    text_option.and_then(|text| {
        re.captures(text).map(|caps| {
            caps.get(1)
                .map(|m| m.as_str().to_string())
                .filter(|s| !s.is_empty())
        })
    })
}

fn check_meta_tag(doc: &Html, name: &str, re: &Regex) -> Option<Option<String>> {
    let selector_str = format!("meta[name='{}']", name);
    if let Ok(selector) = Selector::parse(&selector_str) {
        let content = doc.select(&selector).next().and_then(|el| el.value().attr("content"));
        return check_with_regex(content, re);
    }
    None
}

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

// Helper function for our new LinkHref check
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