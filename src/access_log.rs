use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use hyper::{Response, header::HeaderValue};
use http_body_util::{BodyExt, Full};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ja4_plus::{Ja4hFingerprint, Ja4tFingerprint};
use crate::utils::tcp_fingerprint::TcpFingerprintData;
use crate::worker::log::{get_log_sender_config, send_event, UnifiedEvent};

// Re-export for compatibility
pub use crate::worker::log::LogSenderConfig;

/// Server certificate information for access logging
#[derive(Debug, Clone)]
pub struct ServerCertInfo {
    pub issuer: String,
    pub subject: String,
    pub not_before: String,  // RFC3339 format
    pub not_after: String,   // RFC3339 format
    pub fingerprint_sha256: String,
}

/// Lightweight access log summary for returning with responses
///
/// # Usage Example
///
/// ```no_run
/// use synapse::access_log::{AccessLogSummary, UpstreamInfo, PerformanceInfo};
/// use chrono::Utc;
///
/// // Create a summary with upstream and performance info
/// let summary = AccessLogSummary {
///     request_id: "req_123".to_string(),
///     timestamp: Utc::now(),
///     upstream: Some(UpstreamInfo {
///         selected: "backend1.example.com".to_string(),
///         method: "round_robin".to_string(),
///         reason: "healthy".to_string(),
///     }),
///     waf: None,
///     threat: None,
///     network: synapse::access_log::NetworkSummary {
///         src_ip: "1.2.3.4".to_string(),
///         dst_ip: "10.0.0.1".to_string(),
///         protocol: "https".to_string(),
///     },
///     performance: PerformanceInfo {
///         request_time_ms: Some(150),
///         upstream_time_ms: Some(120),
///     },
/// };
///
/// // Add to response headers
/// // summary.add_to_response_headers(&mut response);
///
/// // Or get as JSON
/// let json = summary.to_json().unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogSummary {
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub upstream: Option<UpstreamInfo>,
    pub waf: Option<WafInfo>,
    pub threat: Option<ThreatInfo>,
    pub network: NetworkSummary,
    pub performance: PerformanceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamInfo {
    pub selected: String,
    pub method: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafInfo {
    pub action: String,
    pub rule_id: String,
    pub rule_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub score: u32,
    pub confidence: f64,
    pub categories: Vec<String>,
    pub reason: String,
    pub country: Option<String>,
    pub asn: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceInfo {
    pub request_time_ms: Option<u64>,
    pub upstream_time_ms: Option<u64>,
}

impl AccessLogSummary {
    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Convert to compact JSON for headers (excludes null fields)
    pub fn to_compact_json(&self) -> String {
        let mut parts = vec![format!(r#""request_id":"{}""#, self.request_id)];

        if let Some(upstream) = &self.upstream {
            parts.push(format!(r#""upstream":"{}""#, upstream.selected));
            parts.push(format!(r#""upstream_method":"{}""#, upstream.method));
        }

        if let Some(waf) = &self.waf {
            parts.push(format!(r#""waf_action":"{}""#, waf.action));
            parts.push(format!(r#""waf_rule":"{}""#, waf.rule_name));
        }

        if let Some(threat) = &self.threat {
            parts.push(format!(r#""threat_score":{}"#, threat.score));
            parts.push(format!(r#""threat_confidence":{:.2}"#, threat.confidence));
        }

        if let Some(ms) = self.performance.request_time_ms {
            parts.push(format!(r#""request_time_ms":{}"#, ms));
        }

        format!("{{{}}}", parts.join(","))
    }

    /// Add as response headers
    pub fn add_to_response_headers(&self, response: &mut Response<Full<bytes::Bytes>>) {
        let headers = response.headers_mut();

        // Add request ID header
        if let Ok(value) = HeaderValue::from_str(&self.request_id) {
            headers.insert("X-Request-ID", value);
        }

        // Add upstream info
        if let Some(upstream) = &self.upstream {
            if let Ok(value) = HeaderValue::from_str(&upstream.selected) {
                headers.insert("X-Upstream-Server", value);
            }
            if let Ok(value) = HeaderValue::from_str(&upstream.method) {
                headers.insert("X-Upstream-Method", value);
            }
        }

        // Add WAF info
        if let Some(waf) = &self.waf {
            if let Ok(value) = HeaderValue::from_str(&waf.action) {
                headers.insert("X-WAF-Action", value);
            }
            if let Ok(value) = HeaderValue::from_str(&waf.rule_id) {
                headers.insert("X-WAF-Rule-ID", value);
            }
        }

        // Add threat info
        if let Some(threat) = &self.threat {
            if let Ok(value) = HeaderValue::from_str(&threat.score.to_string()) {
                headers.insert("X-Threat-Score", value);
            }
            if let Some(country) = &threat.country {
                if let Ok(value) = HeaderValue::from_str(country) {
                    headers.insert("X-Client-Country", value);
                }
            }
        }

        // Add performance metrics
        if let Some(ms) = self.performance.request_time_ms {
            if let Ok(value) = HeaderValue::from_str(&ms.to_string()) {
                headers.insert("X-Request-Time-Ms", value);
            }
        }

        if let Some(ms) = self.performance.upstream_time_ms {
            if let Ok(value) = HeaderValue::from_str(&ms.to_string()) {
                headers.insert("X-Upstream-Time-Ms", value);
            }
        }

        // Add compact JSON summary
        let compact = self.to_compact_json();
        if let Ok(value) = HeaderValue::from_str(&compact) {
            headers.insert("X-Access-Log", value);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAccessLog {
    pub event_type: String,
    pub schema_version: String,
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
    pub http: HttpDetails,
    pub network: NetworkDetails,
    pub tls: Option<TlsDetails>,
    pub response: ResponseDetails,
    pub remediation: Option<RemediationDetails>,
    pub upstream: Option<UpstreamInfo>,
    pub performance: Option<PerformanceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpDetails {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: String,
    pub query_hash: Option<String>,
    pub headers: HashMap<String, String>,
    pub ja4h: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub body: String,
    pub body_sha256: String,
    pub body_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDetails {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsDetails {
    pub version: String,
    pub cipher: String,
    pub alpn: Option<String>,
    pub sni: Option<String>,
    pub ja4: Option<String>,
    pub ja4_unsorted: Option<String>,
    pub ja4t: Option<String>,
    pub server_cert: Option<ServerCertDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCertDetails {
    pub issuer: String,
    pub subject: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub fingerprint_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDetails {
    pub status: u16,
    pub status_text: String,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationDetails {
    pub waf_action: Option<String>,
    pub waf_rule_id: Option<String>,
    pub waf_rule_name: Option<String>,
    pub threat_score: Option<u32>,
    pub threat_confidence: Option<f64>,
    pub threat_categories: Option<Vec<String>>,
    pub threat_tags: Option<Vec<String>>,
    pub threat_reason_code: Option<String>,
    pub threat_reason_summary: Option<String>,
    pub threat_advice: Option<String>,
    pub ip_country: Option<String>,
    pub ip_asn: Option<u32>,
    pub ip_asn_org: Option<String>,
    pub ip_asn_country: Option<String>,
}

impl HttpAccessLog {
    /// Create access log from request parts and response data
    pub async fn create_from_parts(
        req_parts: &hyper::http::request::Parts,
        req_body_bytes: &bytes::Bytes,
        peer_addr: SocketAddr,
        dst_addr: SocketAddr,
        tls_fingerprint: Option<&crate::ja4_plus::Ja4hFingerprint>,
        tcp_fingerprint_data: Option<&TcpFingerprintData>,
        server_cert_info: Option<&ServerCertInfo>,
        response_data: ResponseData,
        waf_result: Option<&crate::waf::wirefilter::WafResult>,
        threat_data: Option<&crate::threat::ThreatResponse>,
        upstream_info: Option<UpstreamInfo>,
        performance_info: Option<PerformanceInfo>,
        tls_sni: Option<String>,
        tls_alpn: Option<String>,
        tls_cipher: Option<String>,
        tls_ja4: Option<String>,
        tls_ja4_unsorted: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let timestamp = Utc::now();
        let request_id = format!("req_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());

        // Extract request details
        let uri = &req_parts.uri;
        let method = req_parts.method.to_string();

        // Determine scheme: prefer URI scheme, fallback to TLS fingerprint presence, then default to http
        let scheme = uri.scheme().map(|s| s.to_string()).unwrap_or_else(|| {
            if tls_fingerprint.is_some() {
                "https".to_string()
            } else {
                "http".to_string()
            }
        });

        // Extract host from URI, fallback to Host header if URI doesn't have host
        let host = uri.host().map(|h| h.to_string()).unwrap_or_else(|| {
            req_parts.headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });

        // Determine port: prefer URI port, fallback to scheme-based default
        let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
        let path = uri.path().to_string();
        let query = uri.query().unwrap_or("").to_string();

        // Process headers
        let mut headers = HashMap::new();
        let mut user_agent = None;
        let mut content_type = None;

        for (name, value) in req_parts.headers.iter() {
            let key = name.to_string();
            let val = value.to_str().unwrap_or("").to_string();
            headers.insert(key, val.clone());

            if name.as_str().to_lowercase() == "user-agent" {
                user_agent = Some(val.clone());
            }
            if name.as_str().to_lowercase() == "content-type" {
                content_type = Some(val);
            }
        }

        // Generate JA4H fingerprint
        let ja4h_fp = Ja4hFingerprint::from_http_request(
            req_parts.method.as_str(),
            &format!("{:?}", req_parts.version),
            &req_parts.headers
        );

        // Get log sender configuration for body processing
        let log_config = {
            let config_store = get_log_sender_config();
            let config_guard = config_store.read().unwrap();
            config_guard.as_ref().cloned()
        };

        // Process request body with truncation - respect include_request_body setting
        let (body_str, body_sha256, body_truncated) = if let Some(config) = &log_config {
            if !config.include_request_body {
                // Request body logging disabled
                ("".to_string(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(), false)
            } else {
                let max_body_size = config.max_body_size;
                let truncated = req_body_bytes.len() > max_body_size;
                let truncated_body_bytes = if truncated {
            req_body_bytes.slice(..max_body_size)
        } else {
            req_body_bytes.clone()
        };
                let body = String::from_utf8_lossy(&truncated_body_bytes).to_string();

        // Calculate SHA256 hash - handle empty body explicitly
                let hash = if req_body_bytes.is_empty() {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
        } else {
            format!("{:x}", Sha256::digest(req_body_bytes))
                };

                (body, hash, truncated)
            }
        } else {
            // No config, default to disabled
            ("".to_string(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(), false)
        };

        // Generate JA4T from TCP fingerprint data if available
        let ja4t = tcp_fingerprint_data.map(|tcp_data| {
            let ja4t_fp = Ja4tFingerprint::from_tcp_data(
                tcp_data.window_size,
                tcp_data.ttl,
                tcp_data.mss,
                tcp_data.window_scale,
                &tcp_data.options,
            );
            ja4t_fp.fingerprint
        });

        // Process TLS details
        let tls_details = if let Some(fp) = tls_fingerprint {
            // Use actual TLS version from fingerprint if available, otherwise infer from HTTP version
            let tls_version = if scheme == "https" {
                // Check if version looks like TLS version (e.g., "TLS 1.2", "TLS 1.3")
                if fp.version.starts_with("TLS") {
                    fp.version.clone()
                } else {
                    // Otherwise infer from HTTP version
                    match fp.version.as_str() {
                        "2.0" | "2" => "TLS 1.2".to_string(), // HTTP/2 typically uses TLS 1.2+
                        "3.0" | "3" => "TLS 1.3".to_string(), // HTTP/3 uses TLS 1.3
                        _ => "TLS 1.2".to_string(), // Default for HTTPS
                    }
                }
            } else {
                "".to_string() // No TLS for HTTP
            };

            // Determine cipher - use provided cipher or infer from TLS version
            let cipher = if let Some(ref provided_cipher) = tls_cipher {
                provided_cipher.clone()
            } else if scheme == "https" {
                match fp.version.as_str() {
                    "3.0" | "3" => "TLS_AES_256_GCM_SHA384".to_string(), // HTTP/3 uses TLS 1.3
                    "2.0" | "2" => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(), // HTTP/2 typically uses TLS 1.2
                    _ => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(), // Default TLS 1.2 cipher
                }
            } else {
                "".to_string() // No cipher for HTTP
            };

            // Extract server certificate details if available
            let server_cert = extract_server_cert_details(server_cert_info);

            // Extract JA4 from TLS fingerprint data - use tls_ja4 if available
            let ja4_value = tls_ja4.clone();

            Some(TlsDetails {
                version: tls_version,
                cipher,
                alpn: tls_alpn.clone(),
                sni: tls_sni.clone(),
                ja4: ja4_value,
                ja4_unsorted: tls_ja4_unsorted.clone(),
                ja4t: ja4t.clone(),
                server_cert,
            })
        } else if scheme == "https" {
            // Create minimal TLS details for HTTPS connections without fingerprint (e.g., PROXY protocol)
            let server_cert = extract_server_cert_details(server_cert_info);

            Some(TlsDetails {
                version: "TLS 1.3".to_string(),
                cipher: "TLS_AES_256_GCM_SHA384".to_string(),
                alpn: None,
                sni: None,
                ja4: Some("t13d".to_string()),
                ja4_unsorted: Some("t13d".to_string()),
                ja4t: ja4t.clone(),
                server_cert,
            })
        } else {
            None
        };

        // Create HTTP details
        let http_details = HttpDetails {
            method,
            scheme,
            host,
            port,
            path,
            query: query.clone(),
            query_hash: if query.is_empty() { None } else { Some(format!("{:x}", Sha256::digest(query.as_bytes()))) },
            headers,
            ja4h: Some(ja4h_fp.fingerprint.clone()),
            user_agent,
            content_type,
            content_length: Some(req_body_bytes.len() as u64),
            body: body_str,
            body_sha256,
            body_truncated,
        };

        // Create network details
        let network_details = NetworkDetails {
            src_ip: peer_addr.ip().to_string(),
            src_port: peer_addr.port(),
            dst_ip: dst_addr.ip().to_string(),
            dst_port: dst_addr.port(),
        };

        // Create response details from response_data - response body logging disabled
        let response_details = ResponseDetails {
            status: response_data.response_json["status"].as_u64().unwrap_or(0) as u16,
            status_text: response_data.response_json["status_text"].as_str().unwrap_or("Unknown").to_string(),
            content_type: response_data.response_json["content_type"].as_str().map(|s| s.to_string()),
            content_length: response_data.response_json["content_length"].as_u64(),
            body: "".to_string(),
        };

        // Create remediation details
        let remediation_details = Self::create_remediation_details(waf_result, threat_data);

        // Create the access log
        let access_log = HttpAccessLog {
            event_type: "http_access_log".to_string(),
            schema_version: "1.0.0".to_string(),
            timestamp,
            request_id,
            http: http_details,
            network: network_details,
            tls: tls_details,
            response: response_details,
            remediation: remediation_details,
            upstream: upstream_info,
            performance: performance_info,
        };

        // Log to stdout (existing behavior)
        if let Err(e) = access_log.log_to_stdout() {
            log::warn!("Failed to log access log to stdout: {}", e);
        }

        // Send to unified event queue
        send_event(UnifiedEvent::HttpAccessLog(access_log));

        Ok(())
    }

    /// Create remediation details from WAF result and threat intelligence data
    fn create_remediation_details(
        waf_result: Option<&crate::waf::wirefilter::WafResult>,
        threat_data: Option<&crate::threat::ThreatResponse>,
    ) -> Option<RemediationDetails> {
        // Check if we have any data that requires remediation
        let has_remediation_data = match waf_result {
            Some(waf) => matches!(waf.action, crate::waf::wirefilter::WafAction::Block | crate::waf::wirefilter::WafAction::Challenge),
            None => false,
        };

        // If neither WAF result requiring remediation nor threat data is available, return None
        if !has_remediation_data && threat_data.is_none() {
            return None;
        }

        let mut remediation = RemediationDetails {
            waf_action: None,
            waf_rule_id: None,
            waf_rule_name: None,
            threat_score: None,
            threat_confidence: None,
            threat_categories: None,
            threat_tags: None,
            threat_reason_code: None,
            threat_reason_summary: None,
            threat_advice: None,
            ip_country: None,
            ip_asn: None,
            ip_asn_org: None,
            ip_asn_country: None,
        };

        // Populate WAF data if available, but only for actions that require remediation (Block/Challenge)
        // Allow actions don't need remediation details, but we still want to track them for auditing
        if let Some(waf) = waf_result {
            // Only include WAF data in remediation if action is Block or Challenge
            // Allow actions are informational and don't require remediation
            match waf.action {
                crate::waf::wirefilter::WafAction::Block | crate::waf::wirefilter::WafAction::Challenge | crate::waf::wirefilter::WafAction::RateLimit => {
                    remediation.waf_action = Some(format!("{:?}", waf.action).to_lowercase());
                    remediation.waf_rule_id = Some(waf.rule_id.clone());
                    remediation.waf_rule_name = Some(waf.rule_name.clone());
                }
                crate::waf::wirefilter::WafAction::Allow => {
                    // Allow actions don't need remediation details
                    // They're logged for auditing but not included in remediation section
                }
            }
        }

        // Populate threat intelligence data if available
        if let Some(threat) = threat_data {
            remediation.threat_score = Some(threat.intel.score);
            remediation.threat_confidence = Some(threat.intel.confidence);
            remediation.threat_categories = Some(threat.intel.categories.clone());
            remediation.threat_tags = Some(threat.intel.tags.clone());
            remediation.threat_reason_code = Some(threat.intel.reason_code.clone());
            remediation.threat_reason_summary = Some(threat.intel.reason_summary.clone());
            remediation.threat_advice = Some(threat.advice.clone());
            // Use iso_code directly from threat response
            let country_code = threat.context.geo.iso_code.clone();
            remediation.ip_country = Some(country_code);
            remediation.ip_asn = Some(threat.context.asn);
            remediation.ip_asn_org = Some(threat.context.org.clone());
            remediation.ip_asn_country = Some(threat.context.geo.asn_iso_code.clone());
        }

        Some(remediation)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn log_to_stdout(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = self.to_json()?;
        log::info!("{}", json);
        Ok(())
    }

    /// Create a lightweight summary suitable for returning with responses
    pub fn to_summary(&self) -> AccessLogSummary {
        let waf_info = if let Some(remediation) = &self.remediation {
            if let (Some(action), Some(rule_id), Some(rule_name)) =
                (&remediation.waf_action, &remediation.waf_rule_id, &remediation.waf_rule_name) {
                Some(WafInfo {
                    action: action.clone(),
                    rule_id: rule_id.clone(),
                    rule_name: rule_name.clone(),
                })
            } else {
                None
            }
        } else {
            None
        };

        let threat_info = if let Some(remediation) = &self.remediation {
            if let (Some(score), Some(confidence)) =
                (remediation.threat_score, remediation.threat_confidence) {
                Some(ThreatInfo {
                    score,
                    confidence,
                    categories: remediation.threat_categories.clone().unwrap_or_default(),
                    reason: remediation.threat_reason_summary.clone().unwrap_or_default(),
                    country: remediation.ip_country.clone(),
                    asn: remediation.ip_asn,
                })
            } else {
                None
            }
        } else {
            None
        };

        let protocol = if self.tls.is_some() {
            format!("{} over {}", self.http.scheme,
                self.tls.as_ref().map(|t| t.version.as_str()).unwrap_or("TLS"))
        } else {
            self.http.scheme.clone()
        };

        AccessLogSummary {
            request_id: self.request_id.clone(),
            timestamp: self.timestamp,
            upstream: self.upstream.clone(),
            waf: waf_info,
            threat: threat_info,
            network: NetworkSummary {
                src_ip: self.network.src_ip.clone(),
                dst_ip: self.network.dst_ip.clone(),
                protocol,
            },
            performance: self.performance.clone().unwrap_or(PerformanceInfo {
                request_time_ms: None,
                upstream_time_ms: None,
            }),
        }
    }

    /// Add upstream routing information to the access log
    pub fn with_upstream(mut self, upstream: UpstreamInfo) -> Self {
        self.upstream = Some(upstream);
        self
    }

    /// Add performance metrics to the access log
    pub fn with_performance(mut self, performance: PerformanceInfo) -> Self {
        self.performance = Some(performance);
        self
    }
}

/// Helper struct to hold response data for access logging
#[derive(Debug, Clone)]
pub struct ResponseData {
    pub response_json: serde_json::Value,
    pub blocking_info: Option<serde_json::Value>,
    pub waf_result: Option<crate::waf::wirefilter::WafResult>,
    pub threat_data: Option<crate::threat::ThreatResponse>,
}

impl ResponseData {
    /// Create response data for a regular response
    pub async fn from_response(response: Response<Full<bytes::Bytes>>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (response_parts, response_body) = response.into_parts();
        let response_body_bytes = response_body.collect().await?.to_bytes();
        let response_body_str = String::from_utf8_lossy(&response_body_bytes).to_string();

        let response_content_type = response_parts.headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let response_json = serde_json::json!({
            "status": response_parts.status.as_u16(),
            "status_text": response_parts.status.canonical_reason().unwrap_or("Unknown"),
            "content_type": response_content_type,
            "content_length": response_body_bytes.len() as u64,
            "body": response_body_str
        });

        Ok(ResponseData {
            response_json,
            blocking_info: None,
            waf_result: None,
            threat_data: None,
        })
    }

    /// Create response data for a blocked request
    pub fn for_blocked_request(
        block_reason: &str,
        status_code: u16,
        waf_result: Option<crate::waf::wirefilter::WafResult>,
        threat_data: Option<&crate::threat::ThreatResponse>,
    ) -> Self {
        let status_text = match status_code {
            403 => "Forbidden",
            426 => "Upgrade Required",
            429 => "Too Many Requests",
            _ => "Blocked"
        };

        let response_json = serde_json::json!({
            "status": status_code,
            "status_text": status_text,
            "content_type": "application/json",
            "content_length": 0,
            "body": format!("{{\"ok\":false,\"error\":\"{}\"}}", block_reason)
        });

        let blocking_info = serde_json::json!({
            "blocked": true,
            "reason": block_reason,
            "filter_type": "waf"
        });

        ResponseData {
            response_json,
            blocking_info: Some(blocking_info),
            waf_result,
            threat_data: threat_data.cloned(),
        }
    }

    /// Create response data for a malware-blocked request with scan details
    pub fn for_malware_blocked_request(
        signature: Option<String>,
        scan_error: Option<String>,
        waf_result: Option<crate::waf::wirefilter::WafResult>,
        threat_data: Option<&crate::threat::ThreatResponse>,
    ) -> Self {
        let response_json = serde_json::json!({
            "status": 403,
            "status_text": "Forbidden",
            "content_type": "application/json",
            "content_length": 0,
            "body": "{\"ok\":false,\"error\":\"malware_detected\"}"
        });

        let mut blocking_info = serde_json::json!({
            "blocked": true,
            "reason": "malware_detected",
            "filter_type": "content_scanning",
            "malware_detected": true,
        });

        if let Some(sig) = signature {
            blocking_info["malware_signature"] = serde_json::Value::String(sig);
        }

        if let Some(err) = scan_error {
            blocking_info["scan_error"] = serde_json::Value::String(err);
        }

        ResponseData {
            response_json,
            blocking_info: Some(blocking_info),
            waf_result,
            threat_data: threat_data.cloned(),
        }
    }
}


/// Extract server certificate details from server certificate info
fn extract_server_cert_details(server_cert_info: Option<&ServerCertInfo>) -> Option<ServerCertDetails> {
    server_cert_info.map(|cert_info| {
        // Parse the date strings from ServerCertInfo
        let not_before = chrono::DateTime::parse_from_rfc3339(&cert_info.not_before)
            .unwrap_or_else(|_| Utc::now().into())
            .with_timezone(&Utc);
        let not_after = chrono::DateTime::parse_from_rfc3339(&cert_info.not_after)
            .unwrap_or_else(|_| Utc::now().into())
            .with_timezone(&Utc);

        ServerCertDetails {
            issuer: cert_info.issuer.clone(),
            subject: cert_info.subject.clone(),
            not_before,
            not_after,
            fingerprint_sha256: cert_info.fingerprint_sha256.clone(),
        }
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    #[tokio::test]
    async fn test_access_log_creation() {
        // Create a simple request
        let _req = Request::builder()
            .method("GET")
            .uri("https://example.com/test?param=value")
            .header("User-Agent", format!("TestAgent/{}", env!("CARGO_PKG_VERSION")))
            .body(Full::new(bytes::Bytes::new()))
            .unwrap();

        // Create a simple response
        let _response = Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .body(Full::new(bytes::Bytes::from("{\"ok\":true}")))
            .unwrap();

        let _peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let _dst_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

        // This test would need more setup to work properly
        // For now, just test the structure creation
        let log = HttpAccessLog {
            event_type: "http_access_log".to_string(),
            schema_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            request_id: "test_123".to_string(),
            http: HttpDetails {
                method: "GET".to_string(),
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                port: 443,
                path: "/test".to_string(),
                query: "param=value".to_string(),
                query_hash: Some("abc123".to_string()),
                headers: HashMap::new(),
                ja4h: Some("g11n_000000000000_000000000000".to_string()),
                user_agent: Some(format!("TestAgent/{}", env!("CARGO_PKG_VERSION"))),
                content_type: None,
                content_length: None,
                body: "".to_string(),
                body_sha256: "abc123".to_string(),
                body_truncated: false,
            },
            network: NetworkDetails {
                src_ip: "127.0.0.1".to_string(),
                src_port: 12345,
                dst_ip: "127.0.0.1".to_string(),
                dst_port: 443,
            },
            tls: None,
            response: ResponseDetails {
                status: 200,
                status_text: "OK".to_string(),
                content_type: Some("application/json".to_string()),
                content_length: Some(10),
                body: "{\"ok\":true}".to_string(),
            },
            remediation: None,
            upstream: Some(UpstreamInfo {
                selected: "backend1".to_string(),
                method: "round_robin".to_string(),
                reason: "healthy".to_string(),
            }),
            performance: Some(PerformanceInfo {
                request_time_ms: Some(50),
                upstream_time_ms: Some(45),
            }),
        };

        let json = log.to_json().unwrap();
        assert!(json.contains("http_access_log"));
        assert!(json.contains("GET"));
        assert!(json.contains("example.com"));
        assert!(json.contains("backend1"));

        // Test summary creation
        let summary = log.to_summary();
        assert_eq!(summary.request_id, "test_123");
        assert_eq!(summary.upstream.as_ref().unwrap().selected, "backend1");
        assert_eq!(summary.performance.request_time_ms, Some(50));
    }

    #[test]
    fn test_remediation_with_threat_intelligence() {
        use crate::waf::wirefilter::{WafAction, WafResult};
        use crate::threat::{ThreatResponse, ThreatIntel, ThreatContext, GeoInfo};

        // Create a mock threat response
        let threat_response = ThreatResponse {
            schema_version: "1.0.0".to_string(),
            tenant_id: "test-tenant".to_string(),
            ip: "192.168.1.100".to_string(),
            intel: ThreatIntel {
                score: 85,
                confidence: 0.95,
                score_version: "1.0".to_string(),
                categories: vec!["malware".to_string(), "botnet".to_string()],
                tags: vec!["suspicious".to_string()],
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                source_count: 5,
                reason_code: "THREAT_DETECTED".to_string(),
                reason_summary: "IP address associated with malicious activity".to_string(),
                rule_id: "rule-123".to_string(),
            },
            context: ThreatContext {
                asn: 12345,
                org: "Test ISP".to_string(),
                ip_version: 4,
                geo: GeoInfo {
                    country: "United States".to_string(),
                    iso_code: "US".to_string(),
                    asn_iso_code: "US".to_string(),
                },
            },
            advice: "Block this IP address".to_string(),
            ttl_s: 3600,
            generated_at: Utc::now(),
        };

        // Create a WAF result with threat intelligence
        let waf_result = WafResult {
            action: WafAction::Block,
            rule_name: "Threat intelligence - Block".to_string(),
            rule_id: "aa0880fd-4d3a-41a6-a02b-9b8b83ca615a".to_string(),
            rate_limit_config: None,
            threat_response: Some(threat_response.clone()),
        };

        // Test create_remediation_details with threat intelligence
        let remediation = HttpAccessLog::create_remediation_details(
            Some(&waf_result),
            Some(&threat_response),
        );

        assert!(remediation.is_some());
        let remediation = remediation.unwrap();

        // Verify WAF data
        assert_eq!(remediation.waf_action, Some("block".to_string()));
        assert_eq!(remediation.waf_rule_id, Some("aa0880fd-4d3a-41a6-a02b-9b8b83ca615a".to_string()));
        assert_eq!(remediation.waf_rule_name, Some("Threat intelligence - Block".to_string()));

        // Verify threat intelligence data
        assert_eq!(remediation.threat_score, Some(85));
        assert_eq!(remediation.threat_confidence, Some(0.95));
        assert_eq!(remediation.threat_categories, Some(vec!["malware".to_string(), "botnet".to_string()]));
        assert_eq!(remediation.threat_tags, Some(vec!["suspicious".to_string()]));
        assert_eq!(remediation.threat_reason_code, Some("THREAT_DETECTED".to_string()));
        assert_eq!(remediation.threat_reason_summary, Some("IP address associated with malicious activity".to_string()));
        assert_eq!(remediation.threat_advice, Some("Block this IP address".to_string()));
        assert_eq!(remediation.ip_country, Some("US".to_string()));
        assert_eq!(remediation.ip_asn, Some(12345));
        assert_eq!(remediation.ip_asn_org, Some("Test ISP".to_string()));
        assert_eq!(remediation.ip_asn_country, Some("US".to_string()));
    }

    #[test]
    fn test_remediation_with_waf_challenge_and_threat_intelligence() {
        use crate::waf::wirefilter::{WafAction, WafResult};
        use crate::threat::{ThreatResponse, ThreatIntel, ThreatContext, GeoInfo};

        // Create a mock threat response
        let threat_response = ThreatResponse {
            schema_version: "1.0.0".to_string(),
            tenant_id: "test-tenant".to_string(),
            ip: "10.0.0.1".to_string(),
            intel: ThreatIntel {
                score: 60,
                confidence: 0.75,
                score_version: "1.0".to_string(),
                categories: vec!["suspicious".to_string()],
                tags: vec!["review".to_string()],
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                source_count: 2,
                reason_code: "SUSPICIOUS_ACTIVITY".to_string(),
                reason_summary: "Unusual traffic patterns detected".to_string(),
                rule_id: "rule-456".to_string(),
            },
            context: ThreatContext {
                asn: 67890,
                org: "Another ISP".to_string(),
                ip_version: 4,
                geo: GeoInfo {
                    country: "Canada".to_string(),
                    iso_code: "CA".to_string(),
                    asn_iso_code: "CA".to_string(),
                },
            },
            advice: "Challenge with CAPTCHA".to_string(),
            ttl_s: 1800,
            generated_at: Utc::now(),
        };

        // Create a WAF result with challenge action and threat intelligence
        let waf_result = WafResult {
            action: WafAction::Challenge,
            rule_name: "Threat intelligence - Challenge".to_string(),
            rule_id: "1eb12716-6e13-4e23-a1d9-c879f6175317".to_string(),
            rate_limit_config: None,
            threat_response: Some(threat_response.clone()),
        };

        // Test create_remediation_details with challenge action and threat intelligence
        let remediation = HttpAccessLog::create_remediation_details(
            Some(&waf_result),
            Some(&threat_response),
        );

        assert!(remediation.is_some());
        let remediation = remediation.unwrap();

        // Verify WAF data (challenge should be included in remediation)
        assert_eq!(remediation.waf_action, Some("challenge".to_string()));
        assert_eq!(remediation.waf_rule_id, Some("1eb12716-6e13-4e23-a1d9-c879f6175317".to_string()));
        assert_eq!(remediation.waf_rule_name, Some("Threat intelligence - Challenge".to_string()));

        // Verify threat intelligence data
        assert_eq!(remediation.threat_score, Some(60));
        assert_eq!(remediation.threat_confidence, Some(0.75));
        assert_eq!(remediation.threat_categories, Some(vec!["suspicious".to_string()]));
        assert_eq!(remediation.ip_country, Some("CA".to_string()));
        assert_eq!(remediation.ip_asn, Some(67890));
    }

    #[test]
    fn test_remediation_without_threat_intelligence() {
        use crate::waf::wirefilter::{WafAction, WafResult};

        // Create a WAF result without threat intelligence
        let waf_result = WafResult {
            action: WafAction::Block,
            rule_name: "Custom Rule".to_string(),
            rule_id: "custom-rule-123".to_string(),
            rate_limit_config: None,
            threat_response: None,
        };

        // Test create_remediation_details without threat intelligence
        let remediation = HttpAccessLog::create_remediation_details(
            Some(&waf_result),
            None,
        );

        assert!(remediation.is_some());
        let remediation = remediation.unwrap();

        // Verify WAF data is present
        assert_eq!(remediation.waf_action, Some("block".to_string()));
        assert_eq!(remediation.waf_rule_id, Some("custom-rule-123".to_string()));

        // Verify threat intelligence data is null
        assert_eq!(remediation.threat_score, None);
        assert_eq!(remediation.threat_confidence, None);
        assert_eq!(remediation.threat_categories, None);
        assert_eq!(remediation.ip_country, None);
        assert_eq!(remediation.ip_asn, None);
    }

    #[test]
    fn test_remediation_json_serialization_with_threat_intelligence() {
        use crate::waf::wirefilter::{WafAction, WafResult};
        use crate::threat::{ThreatResponse, ThreatIntel, ThreatContext, GeoInfo};

        // Create a mock threat response
        let threat_response = ThreatResponse {
            schema_version: "1.0.0".to_string(),
            tenant_id: "test-tenant".to_string(),
            ip: "192.168.1.100".to_string(),
            intel: ThreatIntel {
                score: 90,
                confidence: 0.98,
                score_version: "1.0".to_string(),
                categories: vec!["malware".to_string()],
                tags: vec!["critical".to_string()],
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                source_count: 10,
                reason_code: "MALWARE_DETECTED".to_string(),
                reason_summary: "Known malware source".to_string(),
                rule_id: "rule-789".to_string(),
            },
            context: ThreatContext {
                asn: 99999,
                org: "Malicious Network".to_string(),
                ip_version: 4,
                geo: GeoInfo {
                    country: "Unknown".to_string(),
                    iso_code: "XX".to_string(),
                    asn_iso_code: "XX".to_string(),
                },
            },
            advice: "Immediate block required".to_string(),
            ttl_s: 7200,
            generated_at: Utc::now(),
        };

        let waf_result = WafResult {
            action: WafAction::Block,
            rule_name: "Threat intelligence - Block".to_string(),
            rule_id: "test-rule-id".to_string(),
            rate_limit_config: None,
            threat_response: Some(threat_response.clone()),
        };

        let remediation = HttpAccessLog::create_remediation_details(
            Some(&waf_result),
            Some(&threat_response),
        ).unwrap();

        // Create a full access log with remediation
        let access_log = HttpAccessLog {
            event_type: "http_access_log".to_string(),
            schema_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            request_id: "test_req_123".to_string(),
            http: HttpDetails {
                method: "GET".to_string(),
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                port: 443,
                path: "/".to_string(),
                query: "".to_string(),
                query_hash: None,
                headers: HashMap::new(),
                ja4h: None,
                user_agent: None,
                content_type: None,
                content_length: None,
                body: "".to_string(),
                body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                body_truncated: false,
            },
            network: NetworkDetails {
                src_ip: "192.168.1.100".to_string(),
                src_port: 12345,
                dst_ip: "10.0.0.1".to_string(),
                dst_port: 443,
            },
            tls: None,
            response: ResponseDetails {
                status: 403,
                status_text: "Forbidden".to_string(),
                content_type: None,
                content_length: None,
                body: "".to_string(),
            },
            remediation: Some(remediation),
            upstream: None,
            performance: None,
        };

        // Serialize to JSON and verify threat intelligence fields are present
        let json = access_log.to_json().unwrap();
        assert!(json.contains("\"threat_score\":90"));
        assert!(json.contains("\"threat_confidence\":0.98"));
        assert!(json.contains("\"threat_categories\":[\"malware\"]"));
        assert!(json.contains("\"ip_country\":\"XX\""));
        assert!(json.contains("\"ip_asn\":99999"));
        assert!(json.contains("\"threat_reason_code\":\"MALWARE_DETECTED\""));
        assert!(json.contains("\"threat_reason_summary\":\"Known malware source\""));
    }
}
