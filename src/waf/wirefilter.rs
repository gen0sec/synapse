use std::net::SocketAddr;
use std::sync::{Arc, RwLock, OnceLock};

use anyhow::Result;
use sha2::{Digest, Sha256};
use wirefilter::{ExecutionContext, Scheme, TypedArray, TypedMap};
use crate::worker::config::{Config, fetch_config};
use crate::threat;
use anyhow::anyhow;

/// WAF action types
#[derive(Debug, Clone, PartialEq)]
pub enum WafAction {
    Block,
    Challenge,
    RateLimit,
    Allow,
}

impl WafAction {
    pub fn from_str(action: &str) -> Self {
        match action.to_lowercase().as_str() {
            "block" => WafAction::Block,
            "challenge" => WafAction::Challenge,
            "ratelimit" => WafAction::RateLimit,
            _ => WafAction::Allow,
        }
    }
}

/// WAF rule evaluation result
#[derive(Debug, Clone)]
pub struct WafResult {
    pub action: WafAction,
    pub rule_name: String,
    pub rule_id: String,
    pub rate_limit_config: Option<crate::worker::config::RateLimitConfig>,
    pub threat_response: Option<crate::threat::ThreatResponse>,
}

/// Wirefilter-based HTTP request filtering engine
pub struct HttpFilter {
    scheme: Arc<Scheme>,
    rules: Arc<RwLock<Vec<(wirefilter::Filter, WafAction, String, String, Option<crate::worker::config::RateLimitConfig>)>>>, // (filter, action, name, id, rate_limit_config)
    rules_hash: Arc<RwLock<Option<String>>>,
}

impl HttpFilter {
    /// Create the wirefilter scheme with HTTP request fields
    fn create_scheme() -> Scheme {
        let mut builder = Scheme! {
            http.request.method: Bytes,
            http.request.scheme: Bytes,
            http.request.host: Bytes,
            http.request.port: Int,
            http.request.path: Bytes,
            http.request.uri: Bytes,
            http.request.query: Bytes,
            http.request.user_agent: Bytes,
            http.request.content_type: Bytes,
            http.request.content_length: Int,
            http.request.body: Bytes,
            http.request.body_sha256: Bytes,
            http.request.headers: Map(Array(Bytes)),
            ip.src: Ip,
            ip.src.country: Bytes,
            ip.src.asn: Int,
            ip.src.asn_org: Bytes,
            ip.src.asn_country: Bytes,
            threat.score: Int,
            threat.advice: Bytes,
            signal.ja4: Bytes,
            signal.ja4_raw: Bytes,
            signal.ja4_unsorted: Bytes,
            signal.ja4_raw_unsorted: Bytes,
            signal.tls_version: Bytes,
            signal.cipher_suite: Bytes,
            signal.sni: Bytes,
            signal.alpn: Bytes,
            signal.ja4h: Bytes,
            signal.ja4h_method: Bytes,
            signal.ja4h_version: Bytes,
            signal.ja4h_has_cookie: Int,
            signal.ja4h_has_referer: Int,
            signal.ja4h_header_count: Int,
            signal.ja4h_language: Bytes,
            signal.ja4t: Bytes,
            signal.ja4t_window_size: Int,
            signal.ja4t_ttl: Int,
            signal.ja4t_mss: Int,
            signal.ja4t_window_scale: Int,
            signal.ja4l_client: Bytes,
            signal.ja4l_server: Bytes,
            signal.ja4l_syn_time: Int,
            signal.ja4l_synack_time: Int,
            signal.ja4l_ack_time: Int,
            signal.ja4l_ttl_client: Int,
            signal.ja4l_ttl_server: Int,
            signal.ja4s: Bytes,
            signal.ja4s_proto: Bytes,
            signal.ja4s_version: Bytes,
            signal.ja4s_cipher: Int,
            signal.ja4s_alpn: Bytes,
            signal.ja4x: Bytes,
            signal.ja4x_issuer_rdns: Bytes,
            signal.ja4x_subject_rdns: Bytes,
            signal.ja4x_extensions: Bytes,
        };

        // Register functions used in Cloudflare-style expressions
        builder.add_function("any", wirefilter::AnyFunction::default()).unwrap();
        builder.add_function("all", wirefilter::AllFunction::default()).unwrap();

        builder.add_function("cidr", wirefilter::CIDRFunction::default()).unwrap();
        builder.add_function("concat", wirefilter::ConcatFunction::default()).unwrap();
        builder.add_function("decode_base64", wirefilter::DecodeBase64Function::default()).unwrap();
        builder.add_function("ends_with", wirefilter::EndsWithFunction::default()).unwrap();
        builder.add_function("json_lookup_integer", wirefilter::JsonLookupIntegerFunction::default()).unwrap();
        builder.add_function("json_lookup_string", wirefilter::JsonLookupStringFunction::default()).unwrap();
        builder.add_function("len", wirefilter::LenFunction::default()).unwrap();
        builder.add_function("lower", wirefilter::LowerFunction::default()).unwrap();
        builder.add_function("remove_bytes", wirefilter::RemoveBytesFunction::default()).unwrap();
        builder.add_function("remove_query_args", wirefilter::RemoveQueryArgsFunction::default()).unwrap();
        builder.add_function("starts_with", wirefilter::StartsWithFunction::default()).unwrap();
        builder.add_function("substring", wirefilter::SubstringFunction::default()).unwrap();
        builder.add_function("to_string", wirefilter::ToStringFunction::default()).unwrap();
        builder.add_function("upper", wirefilter::UpperFunction::default()).unwrap();
        builder.add_function("url_decode", wirefilter::UrlDecodeFunction::default()).unwrap();
        builder.add_function("uuid4", wirefilter::UUID4Function::default()).unwrap();
        builder.add_function("wildcard_replace", wirefilter::WildcardReplaceFunction::default()).unwrap();


        builder.build()
    }

    /// Create a new HTTP filter with the given filter expression (static version)
    pub fn new(filter_expr: &'static str) -> Result<Self> {
        // Create the scheme with HTTP request fields
        let scheme = Arc::new(Self::create_scheme());

        // Parse the filter expression
        let ast = scheme.parse(filter_expr)?;

        // Compile the filter
        let filter = ast.compile();

        Ok(Self {
            scheme,
            rules: Arc::new(RwLock::new(vec![
                (filter, WafAction::Block, "default".to_string(), "default".to_string(), None)
            ])),
            rules_hash: Arc::new(RwLock::new(None)),
        })
    }

    /// Create a new HTTP filter from config WAF rules
    pub fn new_from_config(config: &Config) -> Result<Self> {
        // Create the scheme with HTTP request fields
        let scheme = Arc::new(Self::create_scheme());

        if config.waf_rules.rules.is_empty() {
            // If no WAF rules, create a default filter that allows all
            return Ok(Self {
                scheme,
                rules: Arc::new(RwLock::new(vec![])),
                rules_hash: Arc::new(RwLock::new(Some(Self::compute_rules_hash("")))),
            });
        }

        // Validate and compile individual WAF rules
        let mut compiled_rules = Vec::new();
        let mut rules_hash_input = String::new();

        for rule in &config.waf_rules.rules {
            // Basic validation - check if expression is not empty
            if rule.expression.trim().is_empty() {
                log::warn!("Skipping empty WAF rule expression for rule '{}'", rule.name);
                continue;
            }

            // Try to parse the expression to validate it
            if let Err(error) = scheme.parse(&rule.expression) {
                log::warn!("Invalid WAF rule expression for rule '{}': {}: {}", rule.name, rule.expression, error);
                continue;
            }

            // Compile the rule
            let expression = Box::leak(rule.expression.clone().into_boxed_str());
            let ast = scheme.parse(expression)?;
            let filter = ast.compile();
            let action = WafAction::from_str(&rule.action);

            // Parse rate limit config if action is RateLimit
            let rate_limit_config = if action == WafAction::RateLimit {
                rule.config.as_ref().and_then(|cfg| {
                    match crate::worker::config::RateLimitConfig::from_json(cfg) {
                        Ok(config) => {
                            log::debug!("Parsed rate limit config for rule {}: period={}, requests={}",
                                rule.id, config.period, config.requests);
                            Some(config)
                        }
                        Err(e) => {
                            log::error!("Failed to parse rate limit config for rule {}: {}. Config JSON: {}",
                                rule.id, e, serde_json::to_string(cfg).unwrap_or_else(|_| "invalid json".to_string()));
                            None
                        }
                    }
                })
            } else {
                None
            };

            compiled_rules.push((filter, action, rule.name.clone(), rule.id.clone(), rate_limit_config));
            rules_hash_input.push_str(&format!("{}:{}:{};", rule.id, rule.action, rule.expression));
        }

        if compiled_rules.is_empty() {
            log::warn!("No valid WAF rules found, using default filter that allows all");
            return Ok(Self {
                scheme,
                rules: Arc::new(RwLock::new(vec![])),
                rules_hash: Arc::new(RwLock::new(Some(Self::compute_rules_hash("")))),
            });
        }

        let hash = Self::compute_rules_hash(&rules_hash_input);
        Ok(Self {
            scheme,
            rules: Arc::new(RwLock::new(compiled_rules)),
            rules_hash: Arc::new(RwLock::new(Some(hash))),
        })
    }

    /// Update the filter with new WAF rules from config
    pub fn update_from_config(&self, config: &Config) -> Result<()> {
        // Validate and compile individual WAF rules
        let mut compiled_rules = Vec::new();
        let mut rules_hash_input = String::new();

        for rule in &config.waf_rules.rules {
            // Basic validation - check if expression is not empty
            if rule.expression.trim().is_empty() {
                log::warn!("Skipping empty WAF rule expression for rule '{}'", rule.name);
                continue;
            }

            // Try to parse the expression to validate it
            if let Err(error) = self.scheme.parse(&rule.expression) {
                log::warn!("Invalid WAF rule expression for rule '{}': {}: {}", rule.name, rule.expression, error);
                continue;
            }

            // Compile the rule
            let expression = Box::leak(rule.expression.clone().into_boxed_str());
            let ast = self.scheme.parse(expression)?;
            let filter = ast.compile();
            let action = WafAction::from_str(&rule.action);

            // Parse rate limit config if action is RateLimit
            let rate_limit_config = if action == WafAction::RateLimit {
                rule.config.as_ref().and_then(|cfg| {
                    match crate::worker::config::RateLimitConfig::from_json(cfg) {
                        Ok(config) => {
                            log::debug!("Parsed rate limit config for rule {}: period={}, requests={}",
                                rule.id, config.period, config.requests);
                            Some(config)
                        }
                        Err(e) => {
                            log::error!("Failed to parse rate limit config for rule {}: {}. Config JSON: {}",
                                rule.id, e, serde_json::to_string(cfg).unwrap_or_else(|_| "invalid json".to_string()));
                            None
                        }
                    }
                })
            } else {
                None
            };

            compiled_rules.push((filter, action, rule.name.clone(), rule.id.clone(), rate_limit_config));
            rules_hash_input.push_str(&format!("{}:{}:{};", rule.id, rule.action, rule.expression));
        }

        // Compute hash and skip update if unchanged
        let new_hash = Self::compute_rules_hash(&rules_hash_input);
        if let Some(prev) = self.rules_hash.read().unwrap().as_ref() {
            if prev == &new_hash {
                log::debug!("HTTP filter WAF rules unchanged; skipping update");
                return Ok(());
            }
        }

        let rules_count = compiled_rules.len();
        *self.rules.write().unwrap() = compiled_rules;
        *self.rules_hash.write().unwrap() = Some(new_hash);

        log::info!("HTTP filter updated with {} WAF rules from config", rules_count);

        Ok(())
    }

    fn compute_rules_hash(expr: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(expr.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Get the current filter expression (for debugging)
    pub fn get_current_expression(&self) -> String {
        // This is a simplified version - in practice you might want to store the original expression
        "dynamic_filter_from_config".to_string()
    }

    /// Check if the given HTTP request should be blocked using request parts and body bytes
    pub async fn should_block_request_from_parts(
        &self,
        req_parts: &hyper::http::request::Parts,
        body_bytes: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<Option<WafResult>> {
        // Create execution context
        let mut ctx = ExecutionContext::new(&self.scheme);

        // Extract request information
        let method = req_parts.method.as_str();
        let uri = &req_parts.uri;
        let scheme = uri.scheme().map(|s| s.as_str()).unwrap_or("http");
        let host = uri.host().unwrap_or("").to_string();
        let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
        let path = uri.path().to_string();
        let full_uri = uri.to_string();
        let query = uri.query().unwrap_or("").to_string();

        // Extract headers
        let user_agent = req_parts
            .headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        let content_type = req_parts
            .headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Get content length
        let content_length = req_parts
            .headers
            .get("content-length")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(body_bytes.len() as i64);

        // Process request body
        let body_text = String::from_utf8_lossy(body_bytes).to_string();

        // Calculate body SHA256
        let mut hasher = Sha256::new();
        hasher.update(body_bytes);
        let body_sha256_hex = hex::encode(hasher.finalize());

        // Set field values in execution context
        ctx.set_field_value(
            self.scheme.get_field("http.request.method").unwrap(),
            method,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.scheme").unwrap(),
            scheme,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.host").unwrap(),
            host,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.port").unwrap(),
            port as i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.path").unwrap(),
            path,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.uri").unwrap(),
            full_uri,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.query").unwrap(),
            query,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.user_agent").unwrap(),
            user_agent,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.content_type").unwrap(),
            content_type,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.headers").unwrap(),
            {
                let mut headers_map: TypedMap<'_, TypedArray<'_, &[u8]>> = TypedMap::new();
                for (name, value) in req_parts.headers.iter() {
                    let key = name.as_str().to_ascii_lowercase().into_bytes().into_boxed_slice();
                    let entry = headers_map.get_or_insert(key, TypedArray::new());
                    match value.to_str() {
                        Ok(s) => entry.push(s.as_bytes()),
                        Err(_) => entry.push(value.as_bytes()),
                    }
                }
                headers_map
            },
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.content_length").unwrap(),
            content_length,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.body").unwrap(),
            body_text,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.body_sha256").unwrap(),
            body_sha256_hex,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("ip.src").unwrap(),
            peer_addr.ip(),
        )?;

        // Fetch threat intelligence data for the source IP
        // Fetch full threat response for access logging, and WAF fields for rule evaluation
        let threat_response = threat::get_threat_intel(&peer_addr.ip().to_string()).await.ok().flatten();
        let _threat_fields = if let Some(ref threat_resp) = threat_response {
            let waf_fields = threat::WafFields::from(threat_resp);
            // Set threat intelligence fields
            ctx.set_field_value(
                self.scheme.get_field("ip.src.country").unwrap(),
                waf_fields.ip_src_country.clone(),
            )?;
            ctx.set_field_value(
                self.scheme.get_field("ip.src.asn").unwrap(),
                waf_fields.ip_src_asn as i64,
            )?;
            ctx.set_field_value(
                self.scheme.get_field("ip.src.asn_org").unwrap(),
                waf_fields.ip_src_asn_org.clone(),
            )?;
            ctx.set_field_value(
                self.scheme.get_field("ip.src.asn_country").unwrap(),
                waf_fields.ip_src_asn_country.clone(),
            )?;
            ctx.set_field_value(
                self.scheme.get_field("threat.score").unwrap(),
                waf_fields.threat_score as i64,
            )?;
            ctx.set_field_value(
                self.scheme.get_field("threat.advice").unwrap(),
                waf_fields.threat_advice.clone(),
            )?;
            Some(waf_fields)
        } else {
            // No threat data found, set default values
            ctx.set_field_value(
                self.scheme.get_field("ip.src.country").unwrap(),
                "",
            )?;
            ctx.set_field_value(
                self.scheme.get_field("ip.src.asn").unwrap(),
                0i64,
            )?;
            ctx.set_field_value(
                self.scheme.get_field("ip.src.asn_org").unwrap(),
                "",
            )?;
            ctx.set_field_value(
                self.scheme.get_field("ip.src.asn_country").unwrap(),
                "",
            )?;
            ctx.set_field_value(
                self.scheme.get_field("threat.score").unwrap(),
                0i64,
            )?;
            ctx.set_field_value(
                self.scheme.get_field("threat.advice").unwrap(),
                "",
            )?;
            None
        };

        // Extract HTTP version
        let http_version = format!("{:?}", req_parts.version);

        // Generate JA4H fingerprint from HTTP request (available now)
        let ja4h_fp = crate::ja4_plus::Ja4hFingerprint::from_http_request(
            method,
            &http_version,
            &req_parts.headers,
        );

        // Set default empty values for all signal (JA4) fields
        // These fields will be populated when JA4 data is available
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4_raw").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4_unsorted").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4_raw_unsorted").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.tls_version").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.cipher_suite").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.sni").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.alpn").unwrap(),
            "",
        )?;
        // Populate JA4H fields from generated fingerprint
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4h").unwrap(),
            ja4h_fp.fingerprint.clone(),
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4h_method").unwrap(),
            ja4h_fp.method.clone(),
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4h_version").unwrap(),
            ja4h_fp.version.clone(),
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4h_has_cookie").unwrap(),
            if ja4h_fp.has_cookie { 1i64 } else { 0i64 },
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4h_has_referer").unwrap(),
            if ja4h_fp.has_referer { 1i64 } else { 0i64 },
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4h_header_count").unwrap(),
            ja4h_fp.header_count as i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4h_language").unwrap(),
            ja4h_fp.language.clone(),
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4t").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4t_window_size").unwrap(),
            0i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4t_ttl").unwrap(),
            0i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4t_mss").unwrap(),
            0i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4t_window_scale").unwrap(),
            0i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4l_client").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4l_server").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4l_syn_time").unwrap(),
            0i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4l_synack_time").unwrap(),
            0i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4l_ack_time").unwrap(),
            0i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4l_ttl_client").unwrap(),
            0i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4l_ttl_server").unwrap(),
            0i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4s").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4s_proto").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4s_version").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4s_cipher").unwrap(),
            0i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4s_alpn").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4x").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4x_issuer_rdns").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4x_subject_rdns").unwrap(),
            "",
        )?;
        ctx.set_field_value(
            self.scheme.get_field("signal.ja4x_extensions").unwrap(),
            "",
        )?;

        // Execute each rule individually and return the first match
        let rules_guard = self.rules.read().unwrap();
        for (filter, action, rule_name, rule_id, rate_limit_config) in rules_guard.iter() {
            let rule_result = filter.execute(&ctx)?;
            if rule_result {
                return Ok(Some(WafResult {
                    action: action.clone(),
                    rule_name: rule_name.clone(),
                    rule_id: rule_id.clone(),
                    rate_limit_config: rate_limit_config.clone(),
                    threat_response: threat_response.clone(),
                }));
            }
        }

        Ok(None)
    }
}

// Global wirefilter instance for HTTP request filtering
static HTTP_FILTER: OnceLock<HttpFilter> = OnceLock::new();

pub fn get_global_http_filter() -> Option<&'static HttpFilter> {
    HTTP_FILTER.get()
}

pub fn set_global_http_filter(filter: HttpFilter) -> anyhow::Result<()> {
    HTTP_FILTER
        .set(filter)
        .map_err(|_| anyhow!("Failed to initialize HTTP filter"))
}


/// Initialize the global config + HTTP filter from API with retry logic
pub async fn init_config(base_url: String, api_key: String) -> anyhow::Result<()> {
    let mut retry_count = 0;
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_MS: u64 = 1000;

    loop {
        match fetch_config(base_url.clone(), api_key.clone()).await {
            Ok(config_response) => {
                let filter = HttpFilter::new_from_config(&config_response.config)?;
                set_global_http_filter(filter)?;
                log::info!("HTTP filter initialized with {} WAF rules from config", config_response.config.waf_rules.rules.len());
                return Ok(());
            }
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("503") && retry_count < MAX_RETRIES {
                    retry_count += 1;
                    log::warn!("Failed to fetch config for HTTP filter (attempt {}): {}. Retrying in {}ms...", retry_count, error_msg, RETRY_DELAY_MS);
                    tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                    continue;
                } else {
                    log::error!("Failed to fetch config for HTTP filter after {} attempts: {}", retry_count + 1, error_msg);
                    return Err(anyhow!("Failed to initialize HTTP filter: {}", error_msg));
                }
            }
        }
    }
}

/// Update the global HTTP filter with new config with retry logic
pub async fn update_with_config(base_url: String, api_key: String) -> anyhow::Result<()> {
    let mut retry_count = 0;
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_MS: u64 = 1000;

    loop {
        match fetch_config(base_url.clone(), api_key.clone()).await {
            Ok(config_response) => {
                if let Some(filter) = HTTP_FILTER.get() {
                    filter.update_from_config(&config_response.config)?;
                } else {
                    log::warn!("HTTP filter not initialized, cannot update");
                }
                return Ok(());
            }
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("503") && retry_count < MAX_RETRIES {
                    retry_count += 1;
                    log::warn!("Failed to fetch config for HTTP filter update (attempt {}): {}. Retrying in {}ms...", retry_count, error_msg, RETRY_DELAY_MS);
                    tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                    continue;
                } else {
                    log::error!("Failed to fetch config for HTTP filter update after {} attempts: {}", retry_count + 1, error_msg);
                    return Err(anyhow!("Failed to fetch config: {}", error_msg));
                }
            }
        }
    }
}

/// Update the global HTTP filter using an already-fetched Config value
pub fn update_http_filter_from_config_value(config: &Config) -> anyhow::Result<()> {
    if let Some(filter) = HTTP_FILTER.get() {
        filter.update_from_config(config)?;
        Ok(())
    } else {
        log::warn!("HTTP filter not initialized, cannot update");
        Ok(())
    }
}

/// Evaluate WAF rules for a Pingora request
/// This is a convenience function that converts Pingora's RequestHeader to hyper's Parts
pub async fn evaluate_waf_for_pingora_request(
    req_header: &pingora_http::RequestHeader,
    body_bytes: &[u8],
    peer_addr: SocketAddr,
) -> Result<Option<WafResult>> {
    let filter = match get_global_http_filter() {
        Some(f) => {
            // Check if filter has any rules
            let rules_count = f.rules.read().unwrap().len();
            if rules_count == 0 {
                log::debug!("WAF filter initialized but has no rules loaded");
            } else {
                log::debug!("WAF filter has {} rules loaded", rules_count);
            }
            f
        }
        None => {
            log::debug!("WAF filter not initialized, skipping evaluation");
            return Ok(None);
        }
    };

    // Convert Pingora RequestHeader to hyper::http::request::Parts
    // Pingora URIs might be relative, so we need to construct a full URI
    let uri_str = if req_header.uri.scheme().is_some() {
        // Already an absolute URI
        req_header.uri.to_string()
    } else {
        // Construct absolute URI from relative path
        // Use http://localhost as base since we only need the path/query for WAF evaluation
        format!("http://localhost{}", req_header.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"))
    };

    let uri = match uri_str.parse::<hyper::http::Uri>() {
        Ok(u) => u,
        Err(e) => {
            log::error!("WAF: Failed to parse URI '{}': {}", uri_str, e);
            return Err(anyhow!("Failed to parse URI: {}", e));
        }
    };

    let mut builder = hyper::http::request::Builder::new()
        .method(req_header.method.as_str())
        .uri(uri);

    // Copy headers
    for (name, value) in req_header.headers.iter() {
        if let Ok(name_str) = name.as_str().parse::<hyper::http::HeaderName>() {
            if let Ok(value_str) = value.to_str() {
                builder = builder.header(name_str, value_str);
            } else {
                builder = builder.header(name_str, value.as_bytes());
            }
        } else {
            log::debug!("WAF: Failed to parse header name: {}", name.as_str());
        }
    }

    let req = match builder.body(()) {
        Ok(r) => r,
        Err(e) => {
            log::error!("WAF: Failed to build hyper request: {}", e);
            return Err(anyhow!("Failed to build hyper request: {}", e));
        }
    };
    let (req_parts, _) = req.into_parts();

    log::debug!("WAF: Evaluating request - method={}, uri={}, peer={}",
                req_header.method.as_str(), uri_str, peer_addr);

    match filter.should_block_request_from_parts(&req_parts, body_bytes, peer_addr).await {
        Ok(result) => {
            if result.is_some() {
                log::debug!("WAF: Rule matched - {:?}", result);
            }
            Ok(result)
        }
        Err(e) => {
            log::error!("WAF: Evaluation error: {}", e);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::request::Builder;
    use std::net::Ipv4Addr;


    #[tokio::test]
    async fn test_custom_filter() -> Result<()> {
        // Test a custom filter that blocks requests to specific host
        let filter = HttpFilter::new("http.request.host == \"blocked.example.com\"")?;

        let req = Builder::new()
            .method("GET")
            .uri("http://blocked.example.com/test")
            .body(())?;
        let (req_parts, _) = req.into_parts();

        let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);
        let result = filter.should_block_request_from_parts(&req_parts, b"", peer_addr).await?;
        if let Some(waf_result) = result {
            assert_eq!(waf_result.action, WafAction::Block, "Request to blocked host should be blocked");
        } else {
            panic!("Request to blocked host should be blocked");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_content_scanning_integration() -> Result<()> {
        // Test content scanning integration with wirefilter
        let filter = HttpFilter::new("http.request.host == \"example.com\"")?;

        let req = Builder::new()
            .method("POST")
            .uri("http://example.com/test")
            .header("content-type", "text/html")
            .body(())?;
        let (req_parts, _) = req.into_parts();

        let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);

        // Test with clean content (should not be blocked by content scanning)
        let clean_content = b"<html><body>Clean content</body></html>";
        let result = filter.should_block_request_from_parts(&req_parts, clean_content, peer_addr).await?;

        // Should be blocked by host rule, not content scanning
        if let Some(waf_result) = result {
            assert_eq!(waf_result.rule_name, "default", "Request to example.com should be blocked by host rule");
        } else {
            panic!("Request to example.com should be blocked by host rule");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_ja4h_http_version_extraction() -> Result<()> {
        // Test that HTTP version is correctly extracted and used in JA4H fingerprint
        let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);

        // Test HTTP/1.0
        let filter_http10 = HttpFilter::new("signal.ja4h_version == \"HTTP/1.0\"")?;
        let req_http10 = Builder::new()
            .method("GET")
            .uri("http://example.com/test")
            .version(hyper::http::Version::HTTP_10)
            .body(())?;
        let (req_parts_http10, _) = req_http10.into_parts();
        let result_http10 = filter_http10.should_block_request_from_parts(&req_parts_http10, b"", peer_addr).await?;
        if let Some(waf_result) = result_http10 {
            assert_eq!(waf_result.action, WafAction::Block, "HTTP/1.0 request should match version check");
        } else {
            panic!("HTTP/1.0 request should match version check");
        }

        // Test HTTP/1.1
        let filter_http11 = HttpFilter::new("signal.ja4h_version == \"HTTP/1.1\"")?;
        let req_http11 = Builder::new()
            .method("GET")
            .uri("http://example.com/test")
            .version(hyper::http::Version::HTTP_11)
            .body(())?;
        let (req_parts_http11, _) = req_http11.into_parts();
        let result_http11 = filter_http11.should_block_request_from_parts(&req_parts_http11, b"", peer_addr).await?;
        if let Some(waf_result) = result_http11 {
            assert_eq!(waf_result.action, WafAction::Block, "HTTP/1.1 request should match version check");
        } else {
            panic!("HTTP/1.1 request should match version check");
        }

        // Test HTTP/2.0
        let filter_http2 = HttpFilter::new("signal.ja4h_version == \"HTTP/2.0\"")?;
        let req_http2 = Builder::new()
            .method("GET")
            .uri("http://example.com/test")
            .version(hyper::http::Version::HTTP_2)
            .body(())?;
        let (req_parts_http2, _) = req_http2.into_parts();
        let result_http2 = filter_http2.should_block_request_from_parts(&req_parts_http2, b"", peer_addr).await?;
        if let Some(waf_result) = result_http2 {
            assert_eq!(waf_result.action, WafAction::Block, "HTTP/2.0 request should match version check");
        } else {
            panic!("HTTP/2.0 request should match version check");
        }

        // Test that wrong version doesn't match
        let filter_wrong_version = HttpFilter::new("signal.ja4h_version == \"HTTP/1.0\"")?;
        let req_wrong = Builder::new()
            .method("GET")
            .uri("http://example.com/test")
            .version(hyper::http::Version::HTTP_11)
            .body(())?;
        let (req_parts_wrong, _) = req_wrong.into_parts();
        let result_wrong = filter_wrong_version.should_block_request_from_parts(&req_parts_wrong, b"", peer_addr).await?;
        assert!(result_wrong.is_none(), "HTTP/1.1 request should not match HTTP/1.0 version check");

        Ok(())
    }

    #[tokio::test]
    async fn test_ja4h_fingerprint_with_different_versions() -> Result<()> {
        // Test that JA4H fingerprint is correctly generated with different HTTP versions
        let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);

        // Test that JA4H fingerprint starts with correct version code for HTTP/1.0 (should be "10")
        let filter_http10 = HttpFilter::new("starts_with(signal.ja4h, \"ge10\")")?;
        let req_http10 = Builder::new()
            .method("GET")
            .uri("http://example.com/test")
            .version(hyper::http::Version::HTTP_10)
            .body(())?;
        let (req_parts_http10, _) = req_http10.into_parts();
        let result_http10 = filter_http10.should_block_request_from_parts(&req_parts_http10, b"", peer_addr).await?;
        assert!(result_http10.is_some(), "HTTP/1.0 request should generate JA4H starting with 'ge10'");

        // Test that JA4H fingerprint starts with correct version code for HTTP/1.1 (should be "11")
        let filter_http11 = HttpFilter::new("starts_with(signal.ja4h, \"ge11\")")?;
        let req_http11 = Builder::new()
            .method("GET")
            .uri("http://example.com/test")
            .version(hyper::http::Version::HTTP_11)
            .body(())?;
        let (req_parts_http11, _) = req_http11.into_parts();
        let result_http11 = filter_http11.should_block_request_from_parts(&req_parts_http11, b"", peer_addr).await?;
        assert!(result_http11.is_some(), "HTTP/1.1 request should generate JA4H starting with 'ge11'");

        // Test that JA4H fingerprint starts with correct version code for HTTP/2.0 (should be "20")
        let filter_http2 = HttpFilter::new("starts_with(signal.ja4h, \"ge20\")")?;
        let req_http2 = Builder::new()
            .method("GET")
            .uri("http://example.com/test")
            .version(hyper::http::Version::HTTP_2)
            .body(())?;
        let (req_parts_http2, _) = req_http2.into_parts();
        let result_http2 = filter_http2.should_block_request_from_parts(&req_parts_http2, b"", peer_addr).await?;
        assert!(result_http2.is_some(), "HTTP/2.0 request should generate JA4H starting with 'ge20'");

        Ok(())
    }
}
