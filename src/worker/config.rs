use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use flate2::read::GzDecoder;
use std::sync::{Arc, OnceLock, RwLock};
use tokio::sync::watch;
use tokio::time::{interval, Duration, MissedTickBehavior};
use crate::content_scanning::ContentScanningConfig;
use crate::http_client::get_global_reqwest_client;
use crate::worker::Worker;

pub type Details = serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfigApiResponse {
    pub success: bool,
    pub config: Config,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub access_rules: AccessRule,
    pub waf_rules: WafRules,
    #[serde(default)]
    pub content_scanning: ContentScanningConfig,
    pub created_at: String,
    pub updated_at: String,
    pub last_modified: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccessRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub allow: RuleSet,
    pub block: RuleSet,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WafRules {
    pub rules: Vec<WafRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WafRule {
    pub id: String,
    pub name: String,
    pub org_id: String,
    pub description: String,
    pub action: String,
    pub expression: String,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    pub period: String,
    pub duration: String,
    pub requests: String,
}

impl RateLimitConfig {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        // Parse from nested structure: {"rateLimit": {"period": "25", ...}}
        if let Some(rate_limit_obj) = value.get("rateLimit") {
            serde_json::from_value(rate_limit_obj.clone())
                .map_err(|e| e.to_string())
        } else {
            Err("rateLimit field not found".to_string())
        }
    }

    pub fn period_secs(&self) -> u64 {
        self.period.parse().unwrap_or(60)
    }

    pub fn duration_secs(&self) -> u64 {
        self.duration.parse().unwrap_or(60)
    }

    pub fn requests_count(&self) -> usize {
        self.requests.parse().unwrap_or(100)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleSet {
    pub asn: Vec<HashMap<String, Vec<String>>>,
    pub country: Vec<HashMap<String, Vec<String>>>,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub details: Details,
    pub error: String,
    pub success: bool,
}

// Global configuration store accessible across services
static GLOBAL_CONFIG: OnceLock<Arc<RwLock<Option<Config>>>> = OnceLock::new();

pub fn global_config() -> Arc<RwLock<Option<Config>>> {
    GLOBAL_CONFIG
        .get_or_init(|| Arc::new(RwLock::new(None)))
        .clone()
}

pub fn set_global_config(cfg: Config) {
    let store = global_config();
    if let Ok(mut guard) = store.write() {
        *guard = Some(cfg);
    }
}

pub async fn fetch_config(
    base_url: String,
    api_key: String,
) -> Result<ConfigApiResponse, Box<dyn std::error::Error>> {
    // Use shared HTTP client with keepalive instead of creating new client
    let client = get_global_reqwest_client()
        .map_err(|e| anyhow::anyhow!("Failed to get global HTTP client: {}", e))?;

    let url = format!("{}/config", base_url);

    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Accept-Encoding", "gzip")
        .send()
        .await?;

    let status = response.status();
    match status {
        StatusCode::OK => {
            // Check if response is gzipped by looking at Content-Encoding header first
            let content_encoding = response.headers()
                .get("content-encoding")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_string(); // Convert to owned String to avoid borrow issues

            let bytes = response.bytes().await?;

            let json_text = if content_encoding.contains("gzip") ||
                (bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b) {
                // Response is gzipped, decompress it
                let mut decoder = GzDecoder::new(&bytes[..]);
                let mut decompressed_bytes = Vec::new();
                decoder.read_to_end(&mut decompressed_bytes)
                    .map_err(|e| format!("Failed to decompress gzipped response: {}", e))?;

                // Check if the decompressed content is also gzipped (double compression)
                let final_bytes = if decompressed_bytes.len() >= 2 && decompressed_bytes[0] == 0x1f && decompressed_bytes[1] == 0x8b {
                    let mut second_decoder = GzDecoder::new(&decompressed_bytes[..]);
                    let mut final_bytes = Vec::new();
                    second_decoder.read_to_end(&mut final_bytes)
                        .map_err(|e| format!("Failed to decompress second gzip layer: {}", e))?;
                    final_bytes
                } else {
                    decompressed_bytes
                };

                // Try to convert to UTF-8 string
                match String::from_utf8(final_bytes) {
                    Ok(text) => text,
                    Err(e) => {
                        return Err(format!("Final decompressed response contains invalid UTF-8: {}", e).into());
                    }
                }
            } else {
                // Response is not gzipped, use as-is
                String::from_utf8(bytes.to_vec())
                    .map_err(|e| format!("Response contains invalid UTF-8: {}", e))?
            };

            // Check if response body is empty
            let json_text = json_text.trim();
            if json_text.is_empty() {
                return Err("API returned empty response body".into());
            }

            let body: ConfigApiResponse = serde_json::from_str(json_text)
                .map_err(|e| {
                    let preview = if json_text.len() > 200 {
                        format!("{}...", &json_text[..200])
                    } else {
                        json_text.to_string()
                    };
                    format!("Failed to parse JSON response: {}. Response preview: {}", e, preview)
                })?;
            // Update global config snapshot
            set_global_config(body.config.clone());
            Ok(body)
        }
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::INTERNAL_SERVER_ERROR => {
            let response_text = response.text().await?;
            let trimmed = response_text.trim();
            let status_code = status.as_u16();
            if trimmed.is_empty() {
                return Err(format!("API returned empty response body with status {}", status_code).into());
            }
            match serde_json::from_str::<ErrorResponse>(trimmed) {
                Ok(body) => Err(format!("API Error: {}", body.error).into()),
                Err(e) => {
                    let preview = if trimmed.len() > 200 {
                        format!("{}...", &trimmed[..200])
                    } else {
                        trimmed.to_string()
                    };
                    Err(format!("API returned status {} but response is not valid JSON: {}. Response preview: {}",
                        status_code, e, preview).into())
                }
            }
        }

        status => Err(format!(
            "Unexpected API status code: {} - {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        )
        .into()),

    }
}

/// Fetch config and run a user-provided callback to apply it.
/// The callback can update WAF rules, BPF maps, caches, etc.
pub async fn fetch_and_apply<F>(
    base_url: String,
    api_key: String,
    mut on_config: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(&ConfigApiResponse) -> Result<(), Box<dyn std::error::Error>>,
{
    let resp = fetch_config(base_url, api_key).await?;
    on_config(&resp)?;
    Ok(())
}

/// Config worker that periodically fetches and applies configuration from API
pub struct ConfigWorker {
    base_url: String,
    api_key: String,
    refresh_interval_secs: u64,
    skels: Vec<Arc<crate::bpf::FilterSkel<'static>>>,
}

impl ConfigWorker {
    pub fn new(base_url: String, api_key: String, refresh_interval_secs: u64, skels: Vec<Arc<crate::bpf::FilterSkel<'static>>>) -> Self {
        Self {
            base_url,
            api_key,
            refresh_interval_secs,
            skels,
        }
    }
}

impl Worker for ConfigWorker {
    fn name(&self) -> &str {
        "config"
    }

    fn run(&self, mut shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        let base_url = self.base_url.clone();
        let api_key = self.api_key.clone();
        let refresh_interval_secs = self.refresh_interval_secs;
        let skels = self.skels.clone();
        let worker_name = self.name().to_string();

        tokio::spawn(async move {
            // Initial fetch on startup
            log::info!("[{}] Starting initial config fetch from API...", worker_name);
            match fetch_config(base_url.clone(), api_key.clone()).await {
                Ok(config_response) => {
                    log::info!("[{}] Successfully fetched initial config (access_rules: {}, waf_rules: {})",
                        worker_name,
                        config_response.config.access_rules.allow.ips.len() + config_response.config.access_rules.block.ips.len(),
                        config_response.config.waf_rules.rules.len()
                    );

                    // Apply rules to BPF maps after fetching config
                    if !skels.is_empty() {
                        if let Err(e) = crate::access_rules::apply_rules_from_global_with_state(&skels) {
                            log::error!("[{}] Failed to apply rules from initial config: {}", worker_name, e);
                        }
                    }
                }
                Err(e) => {
                    log::warn!("[{}] Failed to fetch initial config from API: {}", worker_name, e);
                    log::warn!("[{}] Will retry on next scheduled interval", worker_name);
                }
            }

            // Set up periodic refresh interval
            let mut interval = interval(Duration::from_secs(refresh_interval_secs));
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        log::debug!("[{}] Periodic config refresh triggered", worker_name);
                        match fetch_config(base_url.clone(), api_key.clone()).await {
                            Ok(config_response) => {
                                log::debug!("[{}] Config refreshed successfully (waf_rules: {})",
                                    worker_name,
                                    config_response.config.waf_rules.rules.len()
                                );

                                // Apply rules to BPF maps after fetching config
                                if !skels.is_empty() {
                                    if let Err(e) = crate::access_rules::apply_rules_from_global_with_state(&skels) {
                                        log::error!("[{}] Failed to apply rules from config: {}", worker_name, e);
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("[{}] Failed to fetch config from API: {}", worker_name, e);
                            }
                        }
                    }
                }
            }

            log::info!("[{}] Config fetcher task stopped", worker_name);
        })
    }
}
