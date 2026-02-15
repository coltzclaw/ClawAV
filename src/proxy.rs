//! API key vault proxy with DLP (Data Loss Prevention) scanning.
//!
//! Provides a reverse proxy that maps virtual API keys to real ones, preventing
//! the AI agent from ever seeing actual credentials. Supports Anthropic (x-api-key)
//! and OpenAI (Bearer token) auth styles.
//!
//! Outbound request bodies are scanned against configurable DLP regex patterns.
//! Matches can trigger blocking (SSN, AWS keys) or redaction (credit cards).

use crate::alerts::{Alert, Severity};
use crate::config::{KeyMapping, ProxyConfig};
use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, StatusCode, Uri};
use regex::Regex;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

struct ProxyState {
    key_mappings: Vec<KeyMapping>,
    dlp_patterns: Vec<CompiledDlpPattern>,
    alert_tx: mpsc::Sender<Alert>,
}

pub(crate) struct CompiledDlpPattern {
    name: String,
    regex: Regex,
    action: String,
}

/// HTTP reverse proxy server that swaps virtual keys for real ones and scans for DLP violations.
pub struct ProxyServer {
    config: ProxyConfig,
    alert_tx: mpsc::Sender<Alert>,
}

impl ProxyServer {
    pub fn new(config: ProxyConfig, alert_tx: mpsc::Sender<Alert>) -> Self {
        Self { config, alert_tx }
    }

    pub async fn start(self) -> Result<()> {
        let compiled_patterns: Vec<CompiledDlpPattern> = self
            .config
            .dlp
            .patterns
            .iter()
            .filter_map(|p| {
                Regex::new(&p.regex).ok().map(|r| CompiledDlpPattern {
                    name: p.name.clone(),
                    regex: r,
                    action: p.action.clone(),
                })
            })
            .collect();

        let state = Arc::new(ProxyState {
            key_mappings: self.config.key_mapping.clone(),
            dlp_patterns: compiled_patterns,
            alert_tx: self.alert_tx,
        });

        let addr: SocketAddr = format!("{}:{}", self.config.bind, self.config.port).parse()?;

        let make_svc = make_service_fn(move |_| {
            let state = state.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    handle_request(req, state.clone())
                }))
            }
        });

        eprintln!("Proxy server listening on {}", addr);
        Server::bind(&addr).serve(make_svc).await?;
        Ok(())
    }
}

/// Look up a virtual key and return (real_key, provider, upstream)
pub fn lookup_virtual_key<'a>(
    mappings: &'a [KeyMapping],
    virtual_key: &str,
) -> Option<(&'a str, &'a str, &'a str)> {
    mappings.iter().find(|m| m.virtual_key == virtual_key).map(|m| {
        (m.real.as_str(), m.provider.as_str(), m.upstream.as_str())
    })
}

/// Extract virtual key from request headers
fn extract_virtual_key(req: &Request<Body>) -> Option<String> {
    // Check x-api-key (Anthropic style)
    if let Some(val) = req.headers().get("x-api-key") {
        return val.to_str().ok().map(|s| s.to_string());
    }
    // Check Authorization: Bearer (OpenAI style)
    if let Some(val) = req.headers().get("authorization") {
        if let Ok(s) = val.to_str() {
            if let Some(token) = s.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Scan body for DLP violations. Returns Err with response if blocked,
/// Ok with (possibly redacted) body otherwise.
pub fn scan_dlp(
    body: &str,
    patterns: &[CompiledDlpPattern],
) -> DlpResult {
    let mut result_body = body.to_string();
    let mut alerts: Vec<(String, Severity, String)> = Vec::new();

    for pattern in patterns {
        if pattern.regex.is_match(&result_body) {
            match pattern.action.as_str() {
                "block" => {
                    return DlpResult::Blocked {
                        pattern_name: pattern.name.clone(),
                    };
                }
                "redact" => {
                    result_body = pattern.regex.replace_all(&result_body, "[REDACTED]").to_string();
                    alerts.push((
                        pattern.name.clone(),
                        Severity::Warning,
                        format!("DLP: redacted '{}' pattern in request", pattern.name),
                    ));
                }
                _ => {}
            }
        }
    }

    DlpResult::Pass {
        body: result_body,
        alerts,
    }
}

/// Result of DLP scanning: either blocked or passed (with possible redactions).
pub enum DlpResult {
    Blocked { pattern_name: String },
    Pass {
        body: String,
        alerts: Vec<(String, Severity, String)>,
    },
}

async fn handle_request(
    req: Request<Body>,
    state: Arc<ProxyState>,
) -> Result<Response<Body>, hyper::Error> {
    // Extract virtual key
    let virtual_key = match extract_virtual_key(&req) {
        Some(k) => k,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Missing API key"))
                .unwrap());
        }
    };

    // Look up mapping
    let (real_key, provider, upstream) = match lookup_virtual_key(&state.key_mappings, &virtual_key) {
        Some(v) => v,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unknown virtual key"))
                .unwrap());
        }
    };

    let real_key = real_key.to_string();
    let provider = provider.to_string();
    let upstream = upstream.to_string();

    // Read body for DLP scanning
    let (parts, body) = req.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await?;
    let body_str = String::from_utf8_lossy(&body_bytes);

    // DLP scan
    let final_body = match scan_dlp(&body_str, &state.dlp_patterns) {
        DlpResult::Blocked { pattern_name } => {
            let alert = Alert::new(
                Severity::Critical,
                "proxy-dlp",
                &format!("BLOCKED: '{}' pattern detected in request", pattern_name),
            );
            let _ = state.alert_tx.send(alert).await;
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(format!("Request blocked by DLP policy: {}", pattern_name)))
                .unwrap());
        }
        DlpResult::Pass { body, alerts } => {
            for (_name, severity, msg) in alerts {
                let alert = Alert::new(severity, "proxy-dlp", &msg);
                let _ = state.alert_tx.send(alert).await;
            }
            body
        }
    };

    // Build upstream URI
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let upstream_uri: Uri = format!("{}{}", upstream, path_and_query)
        .parse()
        .unwrap_or_else(|_| Uri::from_static("http://localhost"));

    // Build forwarded request
    let mut builder = Request::builder()
        .method(parts.method)
        .uri(upstream_uri);

    // Copy headers, replacing auth
    for (key, value) in parts.headers.iter() {
        if key == "host" {
            continue;
        }
        if key == "x-api-key" && provider == "anthropic" {
            continue;
        }
        if key == "authorization" && provider == "openai" {
            continue;
        }
        builder = builder.header(key, value);
    }

    // Set real key
    match provider.as_str() {
        "anthropic" => {
            builder = builder.header("x-api-key", &real_key);
        }
        "openai" => {
            builder = builder.header("authorization", format!("Bearer {}", real_key));
        }
        _ => {}
    }

    let upstream_req = builder.body(Body::from(final_body)).unwrap();

    // Forward to upstream
    let client = Client::builder().build(hyper_tls_connector());
    match client.request(upstream_req).await {
        Ok(resp) => Ok(resp),
        Err(e) => Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from(format!("Upstream error: {}", e)))
            .unwrap()),
    }
}

fn hyper_tls_connector() -> hyper::client::HttpConnector {
    hyper::client::HttpConnector::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeyMapping;

    fn test_mappings() -> Vec<KeyMapping> {
        vec![
            KeyMapping {
                virtual_key: "vk-anthropic-001".to_string(),
                real: "sk-ant-api03-REAL".to_string(),
                provider: "anthropic".to_string(),
                upstream: "https://api.anthropic.com".to_string(),
            },
            KeyMapping {
                virtual_key: "vk-openai-001".to_string(),
                real: "sk-REAL".to_string(),
                provider: "openai".to_string(),
                upstream: "https://api.openai.com".to_string(),
            },
        ]
    }

    fn test_dlp_patterns() -> Vec<CompiledDlpPattern> {
        vec![
            CompiledDlpPattern {
                name: "ssn".to_string(),
                regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                action: "block".to_string(),
            },
            CompiledDlpPattern {
                name: "credit-card".to_string(),
                regex: Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b").unwrap(),
                action: "redact".to_string(),
            },
            CompiledDlpPattern {
                name: "aws-key".to_string(),
                regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                action: "block".to_string(),
            },
        ]
    }

    #[test]
    fn test_virtual_key_lookup_found() {
        let mappings = test_mappings();
        let result = lookup_virtual_key(&mappings, "vk-anthropic-001");
        assert!(result.is_some());
        let (real, provider, upstream) = result.unwrap();
        assert_eq!(real, "sk-ant-api03-REAL");
        assert_eq!(provider, "anthropic");
        assert_eq!(upstream, "https://api.anthropic.com");
    }

    #[test]
    fn test_virtual_key_lookup_openai() {
        let mappings = test_mappings();
        let result = lookup_virtual_key(&mappings, "vk-openai-001");
        assert!(result.is_some());
        let (real, provider, _) = result.unwrap();
        assert_eq!(real, "sk-REAL");
        assert_eq!(provider, "openai");
    }

    #[test]
    fn test_virtual_key_lookup_unknown() {
        let mappings = test_mappings();
        let result = lookup_virtual_key(&mappings, "vk-unknown-999");
        assert!(result.is_none());
    }

    #[test]
    fn test_dlp_ssn_blocked() {
        let patterns = test_dlp_patterns();
        let body = "My SSN is 123-45-6789 please process";
        match scan_dlp(body, &patterns) {
            DlpResult::Blocked { pattern_name } => assert_eq!(pattern_name, "ssn"),
            _ => panic!("Expected block"),
        }
    }

    #[test]
    fn test_dlp_credit_card_redacted() {
        let patterns = test_dlp_patterns();
        // Only credit card, no SSN
        let body = "Card: 4111-1111-1111-1111 thanks";
        match scan_dlp(body, &patterns) {
            DlpResult::Pass { body, alerts } => {
                assert!(body.contains("[REDACTED]"));
                assert!(!body.contains("4111"));
                assert_eq!(alerts.len(), 1);
                assert_eq!(alerts[0].1, Severity::Warning);
            }
            DlpResult::Blocked { .. } => panic!("Expected pass with redaction"),
        }
    }

    #[test]
    fn test_dlp_aws_key_blocked() {
        let patterns = test_dlp_patterns();
        let body = "key is AKIAIOSFODNN7EXAMPLE";
        match scan_dlp(body, &patterns) {
            DlpResult::Blocked { pattern_name } => assert_eq!(pattern_name, "aws-key"),
            _ => panic!("Expected block"),
        }
    }

    #[test]
    fn test_dlp_clean_body_passes() {
        let patterns = test_dlp_patterns();
        let body = "Hello, please summarize this document";
        match scan_dlp(body, &patterns) {
            DlpResult::Pass { body: b, alerts } => {
                assert_eq!(b, body);
                assert!(alerts.is_empty());
            }
            _ => panic!("Expected pass"),
        }
    }
}
