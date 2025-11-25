use crate::utils::structs::{AppConfig, Extraparams, Headers, InnerMap, UpstreamsDashMap, UpstreamsIdMap};
use crate::http_proxy::gethosts::GetHost;
use crate::waf::wirefilter::{evaluate_waf_for_pingora_request, WafAction};
use crate::waf::actions::captcha::{validate_captcha_token, apply_captcha_challenge_with_token, generate_captcha_token};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::body::Bytes;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use pingora_http::{RequestHeader, ResponseHeader, StatusCode};
use pingora_core::prelude::*;
use pingora_core::ErrorSource::{Upstream, Internal as ErrorSourceInternal};
use pingora_core::{Error, ErrorType::HTTPStatus, RetryType, ImmutStr};
use pingora_core::listeners::ALPN;
use pingora_core::prelude::HttpPeer;
use pingora_limits::rate::Rate;
use pingora_proxy::{ProxyHttp, Session};
use serde_json;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tokio::time::Instant;
use hyper::http;

static RATE_LIMITER: Lazy<Rate> = Lazy::new(|| Rate::new(Duration::from_secs(1)));
static WAF_RATE_LIMITERS: Lazy<DashMap<String, Arc<Rate>>> = Lazy::new(|| DashMap::new());

#[derive(Clone)]
pub struct LB {
    pub ump_upst: Arc<UpstreamsDashMap>,
    pub ump_full: Arc<UpstreamsDashMap>,
    pub ump_byid: Arc<UpstreamsIdMap>,
    pub arxignis_paths: Arc<DashMap<String, (Vec<InnerMap>, AtomicUsize)>>,
    pub headers: Arc<Headers>,
    pub config: Arc<AppConfig>,
    pub extraparams: Arc<ArcSwap<Extraparams>>,
    pub tcp_fingerprint_collector: Option<Arc<crate::utils::tcp_fingerprint::TcpFingerprintCollector>>,
    pub certificates: Option<Arc<ArcSwap<Option<Arc<crate::utils::tls::Certificates>>>>>,
}

pub struct Context {
    backend_id: String,
    start_time: Instant,
    upstream_start_time: Option<Instant>,
    hostname: Option<String>,
    upstream_peer: Option<InnerMap>,
    extraparams: arc_swap::Guard<Arc<Extraparams>>,
    tls_fingerprint: Option<Arc<crate::utils::tls_fingerprint::Fingerprint>>,
    request_body: Vec<u8>,
    malware_detected: bool,
    malware_response_sent: bool,
    waf_result: Option<crate::waf::wirefilter::WafResult>,
    threat_data: Option<crate::threat::ThreatResponse>,
    upstream_time: Option<Duration>,
    disable_access_log: bool,
}

#[async_trait]
impl ProxyHttp for LB {
    type CTX = Context;
    fn new_ctx(&self) -> Self::CTX {
        Context {
            backend_id: String::new(),
            start_time: Instant::now(),
            upstream_start_time: None,
            hostname: None,
            upstream_peer: None,
            extraparams: self.extraparams.load(),
            tls_fingerprint: None,
            request_body: Vec::new(),
            malware_detected: false,
            malware_response_sent: false,
            waf_result: None,
            threat_data: None,
            upstream_time: None,
            disable_access_log: false,
        }
    }
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        // Enable body buffering for content scanning
        session.enable_retry_buffering();

        let ep = _ctx.extraparams.clone();

        // Userland access rules check (fallback when eBPF/XDP is not available)
        // Check if IP is blocked by access rules
        if let Some(peer_addr) = session.client_addr().and_then(|addr| addr.as_inet()) {
            let client_ip: std::net::IpAddr = peer_addr.ip().into();
            
            // Check if IP is blocked
            if crate::access_rules::is_ip_blocked_by_access_rules(client_ip) {
                log::info!("Userland access rules: Blocked request from IP: {} (matched block rule)", client_ip);
                let mut header = ResponseHeader::build(403, None).unwrap();
                header.insert_header("X-Block-Reason", "access_rules").ok();
                session.set_keepalive(None);
                session.write_response_header(Box::new(header), true).await?;
                return Ok(true);
            }
        }

        // Try to get TLS fingerprint if available
        // Use fallback lookup to handle PROXY protocol address mismatches
        if _ctx.tls_fingerprint.is_none() {
            if let Some(peer_addr) = session.client_addr().and_then(|addr| addr.as_inet()) {
                let std_addr = std::net::SocketAddr::new(peer_addr.ip().into(), peer_addr.port());
                if let Some(fingerprint) = crate::utils::tls_client_hello::get_fingerprint_with_fallback(&std_addr) {
                    _ctx.tls_fingerprint = Some(fingerprint.clone());
                    debug!(
                        "TLS Fingerprint retrieved for session - Peer: {}, JA4: {}, SNI: {:?}, ALPN: {:?}",
                        std_addr,
                        fingerprint.ja4,
                        fingerprint.sni,
                        fingerprint.alpn
                    );
                } else {
                    debug!("No TLS fingerprint found in storage for peer: {} (PROXY protocol may cause this)", std_addr);
                }
            }
        }

        // Get threat intelligence data BEFORE WAF evaluation
        // This ensures threat intelligence is available in access logs even when WAF blocks/challenges early
        if let Some(peer_addr) = session.client_addr().and_then(|addr| addr.as_inet()) {
            if _ctx.threat_data.is_none() {
                match crate::threat::get_threat_intel(&peer_addr.ip().to_string()).await {
                    Ok(Some(threat_response)) => {
                        _ctx.threat_data = Some(threat_response);
                        debug!("Threat intelligence retrieved for IP: {}", peer_addr.ip());
                    }
                    Ok(None) => {
                        debug!("No threat intelligence data for IP: {}", peer_addr.ip());
                    }
                    Err(e) => {
                        debug!("Threat intelligence error for IP {}: {}", peer_addr.ip(), e);
                    }
                }
            }
        }

        // Evaluate WAF rules
        if let Some(peer_addr) = session.client_addr().and_then(|addr| addr.as_inet()) {
            let socket_addr = std::net::SocketAddr::new(peer_addr.ip(), peer_addr.port());
            match evaluate_waf_for_pingora_request(session.req_header(), b"", socket_addr).await {
                Ok(Some(waf_result)) => {
                    debug!("WAF rule matched: rule={}, id={}, action={:?}", waf_result.rule_name, waf_result.rule_id, waf_result.action);

                    // Store threat response from WAF result if available (WAF already fetched it)
                    if let Some(threat_resp) = waf_result.threat_response.clone() {
                        _ctx.threat_data = Some(threat_resp);
                        debug!("Threat intelligence retrieved from WAF evaluation for IP: {}", peer_addr.ip());
                    }

                    // Store WAF result in context for access logging
                    _ctx.waf_result = Some(waf_result.clone());

                    match waf_result.action {
                        WafAction::Block => {
                            info!("WAF blocked request: rule={}, id={}, uri={}", waf_result.rule_name, waf_result.rule_id, session.req_header().uri);
                            let mut header = ResponseHeader::build(403, None).unwrap();
                            header.insert_header("X-WAF-Rule", waf_result.rule_name).ok();
                            header.insert_header("X-WAF-Rule-ID", waf_result.rule_id).ok();
                            session.set_keepalive(None);
                            session.write_response_header(Box::new(header), true).await?;
                            return Ok(true);
                        }
                        WafAction::Challenge => {
                            info!("WAF challenge required: rule={}, id={}, uri={}", waf_result.rule_name, waf_result.rule_id, session.req_header().uri);

                            // Check for captcha token in cookies or headers
                            let mut captcha_token: Option<String> = None;

                            // Check cookies for captcha_token
                            if let Some(cookies) = session.req_header().headers.get("cookie") {
                                if let Ok(cookie_str) = cookies.to_str() {
                                    for cookie in cookie_str.split(';') {
                                        let trimmed = cookie.trim();
                                        if let Some(value) = trimmed.strip_prefix("captcha_token=") {
                                            captcha_token = Some(value.to_string());
                                            break;
                                        }
                                    }
                                }
                            }

                            // Check X-Captcha-Token header if not found in cookies
                            if captcha_token.is_none() {
                                if let Some(token_header) = session.req_header().headers.get("x-captcha-token") {
                                    if let Ok(token_str) = token_header.to_str() {
                                        captcha_token = Some(token_str.to_string());
                                    }
                                }
                            }

                            // Validate token if present
                            let token_valid = if let Some(token) = &captcha_token {
                                let user_agent = session.req_header().headers
                                    .get("user-agent")
                                    .and_then(|h| h.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();

                                match validate_captcha_token(token, &peer_addr.ip().to_string(), &user_agent).await {
                                    Ok(valid) => {
                                        if valid {
                                            debug!("Captcha token validated successfully");
                                        } else {
                                            debug!("Captcha token validation failed");
                                        }
                                        valid
                                    }
                                    Err(e) => {
                                        error!("Captcha token validation error: {}", e);
                                        false
                                    }
                                }
                            } else {
                                false
                            };

                            if !token_valid {
                                // Generate a new token (don't reuse invalid token)
                                let jwt_token = {
                                    let user_agent = session.req_header().headers
                                        .get("user-agent")
                                        .and_then(|h| h.to_str().ok())
                                        .unwrap_or("")
                                        .to_string();

                                    match generate_captcha_token(
                                        peer_addr.ip().to_string(),
                                        user_agent,
                                        None, // JA4 fingerprint not available here
                                    ).await {
                                        Ok(token) => token.token,
                                        Err(e) => {
                                            error!("Failed to generate captcha token: {}", e);
                                            // Fallback to challenge without token
                                            match apply_captcha_challenge_with_token("") {
                                                Ok(html) => {
                                                    let mut header = ResponseHeader::build(403, None).unwrap();
                                                    header.insert_header("Content-Type", "text/html; charset=utf-8").ok();
                                                    session.set_keepalive(None);
                                                    session.write_response_header(Box::new(header), false).await?;
                                                    session.write_response_body(Some(Bytes::from(html)), true).await?;
                                                    return Ok(true);
                                                }
                                                Err(e) => {
                                                    error!("Failed to apply captcha challenge: {}", e);
                                                    // Block the request if captcha fails
                                                    let mut header = ResponseHeader::build(403, None).unwrap();
                                                    header.insert_header("X-WAF-Rule", waf_result.rule_name).ok();
                                                    header.insert_header("X-WAF-Rule-ID", waf_result.rule_id).ok();
                                                    session.set_keepalive(None);
                                                    session.write_response_header(Box::new(header), true).await?;
                                                    return Ok(true);
                                                }
                                            }
                                        }
                                    }
                                };

                                // Return captcha challenge page
                                match apply_captcha_challenge_with_token(&jwt_token) {
                                    Ok(html) => {
                                        let mut header = ResponseHeader::build(403, None).unwrap();
                                        header.insert_header("Content-Type", "text/html; charset=utf-8").ok();
                                        header.insert_header("Set-Cookie", format!("captcha_token={}; Path=/; HttpOnly; SameSite=Lax", jwt_token)).ok();
                                        header.insert_header("X-WAF-Rule", waf_result.rule_name).ok();
                                        header.insert_header("X-WAF-Rule-ID", waf_result.rule_id).ok();
                                        session.set_keepalive(None);
                                        session.write_response_header(Box::new(header), false).await?;
                                        session.write_response_body(Some(Bytes::from(html)), true).await?;
                                        return Ok(true);
                                    }
                                    Err(e) => {
                                        error!("Failed to apply captcha challenge: {}", e);
                                        // Block the request if captcha fails
                                        let mut header = ResponseHeader::build(403, None).unwrap();
                                        header.insert_header("X-WAF-Rule", waf_result.rule_name).ok();
                                        header.insert_header("X-WAF-Rule-ID", waf_result.rule_id).ok();
                                        session.set_keepalive(None);
                                        session.write_response_header(Box::new(header), true).await?;
                                        return Ok(true);
                                    }
                                }
                            } else {
                                // Token is valid, allow request to continue
                                debug!("Captcha token validated, allowing request");
                            }
                        }
                        WafAction::RateLimit => {
                            // Get rate limit config from waf_result
                            if let Some(rate_limit_config) = &waf_result.rate_limit_config {
                                let period_secs = rate_limit_config.period_secs();
                                let requests_limit = rate_limit_config.requests_count();

                                // Get or create rate limiter for this rule
                                let rate_limiter = WAF_RATE_LIMITERS
                                    .entry(waf_result.rule_id.clone())
                                    .or_insert_with(|| {
                                        debug!("Creating new rate limiter for rule {}: {} requests per {} seconds",
                                            waf_result.rule_id, requests_limit, period_secs);
                                        Arc::new(Rate::new(Duration::from_secs(period_secs)))
                                    })
                                    .clone();

                                // Use client IP as the rate key
                                let rate_key = peer_addr.ip().to_string();
                                let curr_window_requests = rate_limiter.observe(&rate_key, 1);

                                if curr_window_requests > requests_limit as isize {
                                    info!("Rate limit exceeded: rule={}, id={}, ip={}, requests={}/{}",
                                        waf_result.rule_name, waf_result.rule_id, rate_key, curr_window_requests, requests_limit);

                                    let body = serde_json::json!({
                                        "error": "Too Many Requests",
                                        "message": format!("Rate limit exceeded: {} requests per {} seconds", requests_limit, period_secs),
                                        "rule": &waf_result.rule_name,
                                        "rule_id": &waf_result.rule_id
                                    }).to_string();

                                    let mut header = ResponseHeader::build(429, None).unwrap();
                                    header.insert_header("X-Rate-Limit-Limit", requests_limit.to_string()).ok();
                                    header.insert_header("X-Rate-Limit-Remaining", "0").ok();
                                    header.insert_header("X-Rate-Limit-Reset", period_secs.to_string()).ok();
                                    header.insert_header("X-WAF-Rule", &waf_result.rule_name).ok();
                                    header.insert_header("X-WAF-Rule-ID", &waf_result.rule_id).ok();
                                    header.insert_header("Content-Type", "application/json").ok();

                                    session.set_keepalive(None);
                                    session.write_response_header(Box::new(header), false).await?;
                                    session.write_response_body(Some(Bytes::from(body)), true).await?;
                                    return Ok(true);
                                } else {
                                    debug!("Rate limit check passed: rule={}, id={}, ip={}, requests={}/{}",
                                        waf_result.rule_name, waf_result.rule_id, rate_key, curr_window_requests, requests_limit);
                                }
                            } else {
                                warn!("Rate limit action triggered but no config found for rule {}", waf_result.rule_id);
                            }
                        }
                        WafAction::Allow => {
                            debug!("WAF allowed request: rule={}, id={}", waf_result.rule_name, waf_result.rule_id);
                            // Allow the request to continue
                        }
                    }
                }
                Ok(None) => {
                    // No WAF rules matched, allow request to continue
                    debug!("WAF: No rules matched for uri={}", session.req_header().uri);
                }
                Err(e) => {
                    error!("WAF evaluation error: {}", e);
                    // On error, allow request to continue (fail open)
                }
            }
        } else {
            debug!("WAF: No peer address available for request");
        }

        let hostname = return_header_host(&session);
        _ctx.hostname = hostname;

        let mut backend_id = None;

        if ep.sticky_sessions {
            if let Some(cookies) = session.req_header().headers.get("cookie") {
                if let Ok(cookie_str) = cookies.to_str() {
                    for cookie in cookie_str.split(';') {
                        let trimmed = cookie.trim();
                        if let Some(value) = trimmed.strip_prefix("backend_id=") {
                            backend_id = Some(value);
                            break;
                        }
                    }
                }
            }
        }

        match _ctx.hostname.as_ref() {
            None => return Ok(false),
            Some(host) => {
                // let optioninnermap = self.get_host(host.as_str(), host.as_str(), backend_id);
                let optioninnermap = self.get_host(host.as_str(), session.req_header().uri.path(), backend_id);
                match optioninnermap {
                    None => return Ok(false),
                    Some(ref innermap) => {
                        // Check for HTTPS redirect before rate limiting
                        if ep.https_proxy_enabled.unwrap_or(false) || innermap.https_proxy_enabled {
                            if let Some(stream) = session.stream() {
                                if stream.get_ssl().is_none() {
                                    // HTTP request - redirect to HTTPS
                                    let uri = session.req_header().uri.path_and_query().map_or("/", |pq| pq.as_str());
                                    let port = self.config.proxy_port_tls.unwrap_or(403);
                                    let redirect_url = format!("https://{}:{}{}", host, port, uri);
                                    let mut redirect_response = ResponseHeader::build(StatusCode::MOVED_PERMANENTLY, None)?;
                                    redirect_response.insert_header("Location", redirect_url)?;
                                    redirect_response.insert_header("Content-Length", "0")?;
                                    session.set_keepalive(None);
                                    session.write_response_header(Box::new(redirect_response), false).await?;
                                    return Ok(true);
                                }
                            }
                        }
                        if let Some(rate) = innermap.rate_limit.or(ep.rate_limit) {
                            // let rate_key = session.client_addr().and_then(|addr| addr.as_inet()).map(|inet| inet.ip().to_string()).unwrap_or_else(|| host.to_string());
                            let rate_key = session.client_addr().and_then(|addr| addr.as_inet()).map(|inet| inet.ip());
                            let curr_window_requests = RATE_LIMITER.observe(&rate_key, 1);
                            if curr_window_requests > rate {
                                let mut header = ResponseHeader::build(429, None).unwrap();
                                header.insert_header("X-Rate-Limit-Limit", rate.to_string()).unwrap();
                                header.insert_header("X-Rate-Limit-Remaining", "0").unwrap();
                                header.insert_header("X-Rate-Limit-Reset", "1").unwrap();
                                session.set_keepalive(None);
                                session.write_response_header(Box::new(header), true).await?;
                                debug!("Rate limited: {:?}, {}", rate_key, rate);
                                return Ok(true);
                            }
                        }
                    }
                }
                _ctx.upstream_peer = optioninnermap.clone();
                // Set disable_access_log flag from upstream config
                if let Some(ref innermap) = optioninnermap {
                    _ctx.disable_access_log = innermap.disable_access_log;
                }
            }
        }
        Ok(false)
    }
    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // Check if malware was detected, send JSON response and prevent forwarding
        if ctx.malware_detected && !ctx.malware_response_sent {
            // Check if response has already been written
            if session.response_written().is_some() {
                warn!("Response already written, cannot block malware request in upstream_peer");
                ctx.malware_response_sent = true;
                return Err(Box::new(Error {
                    etype: HTTPStatus(403),
                    esource: Upstream,
                    retry: RetryType::Decided(false),
                    cause: None,
                    context: Option::from(ImmutStr::Static("Malware detected")),
                }));
            }

            info!("Blocking request due to malware detection");

            // Build JSON response
            let json_response = serde_json::json!({
                "success": false,
                "error": "Request blocked",
                "reason": "malware_detected",
                "message": "Malware detected in request"
            });
            let json_body = Bytes::from(json_response.to_string());

            // Build response header
            let mut header = ResponseHeader::build(403, None).unwrap();
            header.insert_header("Content-Type", "application/json").ok();
            header.insert_header("X-Content-Scan-Result", "malware_detected").ok();

            session.set_keepalive(None);

            // Try to write response, handle error if response already sent
            match session.write_response_header(Box::new(header), false).await {
                Ok(_) => {
                    match session.write_response_body(Some(json_body), true).await {
                        Ok(_) => {
                            ctx.malware_response_sent = true;
                        }
                        Err(e) => {
                            warn!("Failed to write response body for malware block in upstream_peer: {}", e);
                            ctx.malware_response_sent = true;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to write response header for malware block in upstream_peer: {}", e);
                    ctx.malware_response_sent = true;
                }
            }

            return Err(Box::new(Error {
                etype: HTTPStatus(403),
                esource: Upstream,
                retry: RetryType::Decided(false),
                cause: None,
                context: Option::from(ImmutStr::Static("Malware detected")),
            }));
        }

        // let host_name = return_header_host(&session);
        match ctx.hostname.as_ref() {
            Some(hostname) => {
                match ctx.upstream_peer.as_ref() {
                    // Some((address, port, ssl, is_h2, https_proxy_enabled)) => {
                    Some(innermap) => {
                        let mut peer = Box::new(HttpPeer::new((innermap.address.clone(), innermap.port.clone()), innermap.ssl_enabled, String::new()));
                        // if session.is_http2() {
                        if innermap.http2_enabled {
                            peer.options.alpn = ALPN::H2;
                        }
                        if innermap.ssl_enabled {
                            peer.sni = hostname.clone();
                            peer.options.verify_cert = false;
                            peer.options.verify_hostname = false;
                        }

                        ctx.backend_id = format!("{}:{}:{}", innermap.address.clone(), innermap.port.clone(), innermap.ssl_enabled);
                        Ok(peer)
                    }
                    None => {
                        if let Err(e) = session.respond_error_with_body(502, Bytes::from("502 Bad Gateway\n")).await {
                            error!("Failed to send error response: {:?}", e);
                        }
                        Err(Box::new(Error {
                            etype: HTTPStatus(502),
                            esource: Upstream,
                            retry: RetryType::Decided(false),
                            cause: None,
                            context: Option::from(ImmutStr::Static("Upstream not found")),
                        }))
                    }
                }
            }
            None => {
                // session.respond_error_with_body(502, Bytes::from("502 Bad Gateway\n")).await.expect("Failed to send error");
                if let Err(e) = session.respond_error_with_body(502, Bytes::from("502 Bad Gateway\n")).await {
                    error!("Failed to send error response: {:?}", e);
                }
                Err(Box::new(Error {
                    etype: HTTPStatus(502),
                    esource: Upstream,
                    retry: RetryType::Decided(false),
                    cause: None,
                    context: None,
                }))
            }
        }
    }

    async fn upstream_request_filter(&self, _session: &mut Session, upstream_request: &mut RequestHeader, ctx: &mut Self::CTX) -> Result<()> {
        // Track when we start upstream request
        ctx.upstream_start_time = Some(Instant::now());

        // Check if config has a Host header before setting default
        let mut config_has_host = false;
        if let Some(hostname) = ctx.hostname.as_ref() {
            let path = _session.req_header().uri.path();
            if let Some(configured_headers) = self.get_header(hostname, path) {
                for (key, _) in configured_headers.iter() {
                    if key.eq_ignore_ascii_case("Host") {
                        config_has_host = true;
                        break;
                    }
                }
            }
        }

        // Only set default Host if config doesn't override it
        if !config_has_host {
            if let Some(hostname) = ctx.hostname.as_ref() {
                upstream_request.insert_header("Host", hostname)?;
            }
        }

        if let Some(peer) = ctx.upstream_peer.as_ref() {
            upstream_request.insert_header("X-Forwarded-For", peer.address.as_str())?;
        }

        // Apply configured headers from upstreams.yaml (will override default Host if present)
        if let Some(hostname) = ctx.hostname.as_ref() {
            let path = _session.req_header().uri.path();
            if let Some(configured_headers) = self.get_header(hostname, path) {
                for (key, value) in configured_headers {
                    // insert_header will override existing headers with the same name
                    let key_clone = key.clone();
                    let value_clone = value.clone();
                    if let Err(e) = upstream_request.insert_header(key_clone, value_clone) {
                        debug!("Failed to insert header {}: {}", key, e);
                    }
                }
            }
        }

        Ok(())
    }


    async fn request_body_filter(&self, _session: &mut Session, body: &mut Option<Bytes>, end_of_stream: bool, ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Accumulate request body for content scanning
        // Copy the body data but don't take it - Pingora will forward it if no malware
        if let Some(body_bytes) = body {
            info!("BODY CHUNK received: {} bytes, total so far: {}, end_of_stream: {}", body_bytes.len(), ctx.request_body.len() + body_bytes.len(), end_of_stream);
            ctx.request_body.extend_from_slice(body_bytes);
        }

        if end_of_stream && !ctx.request_body.is_empty() {
            if let Some(scanner) = crate::content_scanning::get_global_content_scanner() {
                // Get peer address for scanning
                let peer_addr = if let Some(addr) = _session.client_addr().and_then(|a| a.as_inet()) {
                    std::net::SocketAddr::new(addr.ip(), addr.port())
                } else {
                    return Ok(()); // Can't scan without peer address
                };

                // Convert request header to Parts for should_scan check
                let req_header = _session.req_header();
                let method = req_header.method.as_str();
                let uri = req_header.uri.to_string();
                let mut req_builder = hyper::http::Request::builder()
                    .method(method)
                    .uri(&uri);

                // Copy essential headers for content scanning (content-type, content-length)
                if let Some(content_type) = req_header.headers.get("content-type") {
                    if let Ok(ct_str) = content_type.to_str() {
                        req_builder = req_builder.header("content-type", ct_str);
                    }
                }
                if let Some(content_length) = req_header.headers.get("content-length") {
                    if let Ok(cl_str) = content_length.to_str() {
                        req_builder = req_builder.header("content-length", cl_str);
                    }
                }

                let req = match req_builder.body(()) {
                    Ok(req) => req,
                    Err(_) => {
                        warn!("Failed to build request for content scanning, skipping scan");
                        return Ok(());
                    }
                };
                let (req_parts, _) = req.into_parts();

                // Check if we should scan this request
                info!("Content scanner: checking if should scan - body size: {}, method: {}, content-type: {:?}",
                      ctx.request_body.len(), req_parts.method, req_parts.headers.get("content-type"));
                let should_scan = scanner.should_scan(&req_parts, &ctx.request_body, peer_addr);
                if should_scan {
                    info!("Content scanner: WILL SCAN request body (size: {} bytes)", ctx.request_body.len());

                    // Check if content-type is multipart and scan accordingly
                    let content_type = req_parts.headers
                        .get("content-type")
                        .and_then(|h| h.to_str().ok());

                    let scan_result = if let Some(ct) = content_type {
                        info!("Content-Type header: {}", ct);
                        if let Some(boundary) = crate::content_scanning::extract_multipart_boundary(ct) {
                            info!("Detected multipart content with boundary: '{}', scanning parts individually", boundary);
                            scanner.scan_multipart_content(&ctx.request_body, &boundary).await
                        } else {
                            info!("Not multipart or no boundary found, scanning as single blob");
                            scanner.scan_content(&ctx.request_body).await
                        }
                    } else {
                        info!("No Content-Type header, scanning as single blob");
                        scanner.scan_content(&ctx.request_body).await
                    };

                    match scan_result {
                        Ok(scan_result) => {
                            if scan_result.malware_detected {
                                info!("Malware detected in request from {}: {} {} - signature: {:?}",
                                    peer_addr, method, uri, scan_result.signature);

                                // Mark malware detected in context
                                ctx.malware_detected = true;

                                // Send 403 response immediately to block the request
                                let json_response = serde_json::json!({
                                    "success": false,
                                    "error": "Request blocked",
                                    "reason": "malware_detected",
                                    "message": "Malware detected in request"
                                });
                                let json_body = Bytes::from(json_response.to_string());

                                let mut header = ResponseHeader::build(403, None)?;
                                header.insert_header("Content-Type", "application/json")?;
                                header.insert_header("X-Content-Scan-Result", "malware_detected")?;

                                _session.set_keepalive(None);
                                _session.write_response_header(Box::new(header), false).await?;
                                _session.write_response_body(Some(json_body), true).await?;

                                ctx.malware_response_sent = true;

                                // Return error to abort the request
                                return Err(Box::new(Error {
                                    etype: HTTPStatus(403),
                                    esource: ErrorSourceInternal,
                                    retry: RetryType::Decided(false),
                                    cause: None,
                                    context: Option::from(ImmutStr::Static("Malware detected")),
                                }));
                            } else {
                                debug!("Content scan completed: no malware detected");
                            }
                        }
                        Err(e) => {
                            warn!("Content scanning failed: {}", e);
                            // On scanning error, allow the request to proceed (fail open)
                        }
                    }
                } else {
                    debug!("Content scanner: skipping scan (should_scan returned false)");
                }
            }
        }

        Ok(())
    }

    async fn response_filter(&self, session: &mut Session, _upstream_response: &mut ResponseHeader, ctx: &mut Self::CTX) -> Result<()> {
        // Calculate upstream response time
        if let Some(upstream_start) = ctx.upstream_start_time {
            ctx.upstream_time = Some(upstream_start.elapsed());
        }

        // _upstream_response.insert_header("X-Proxied-From", "Fooooooooooooooo").unwrap();
        if ctx.extraparams.sticky_sessions {
            let backend_id = ctx.backend_id.clone();
            if let Some(bid) = self.ump_byid.get(&backend_id) {
                let _ = _upstream_response.insert_header("set-cookie", format!("backend_id={}; Path=/; Max-Age=600; HttpOnly; SameSite=Lax", bid.address));
            }
        }
        match ctx.hostname.as_ref() {
            Some(host) => {
                let path = session.req_header().uri.path();
                let host_header = host;
                let split_header = host_header.split_once(':');

                match split_header {
                    Some(sh) => {
                        let yoyo = self.get_header(sh.0, path);
                        for k in yoyo.iter() {
                            for t in k.iter() {
                                _upstream_response.insert_header(t.0.clone(), t.1.clone()).unwrap();
                            }
                        }
                    }
                    None => {
                        let yoyo = self.get_header(host_header, path);
                        for k in yoyo.iter() {
                            for t in k.iter() {
                                _upstream_response.insert_header(t.0.clone(), t.1.clone()).unwrap();
                            }
                        }
                    }
                }
            }
            None => {}
        }
        session.set_keepalive(Some(300));
        Ok(())
    }

    async fn logging(&self, session: &mut Session, _e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        let response_code = session.response_written().map_or(0, |resp| resp.status.as_u16());

        // Skip logging if disabled for this endpoint
        if ctx.disable_access_log {
            return;
        }

        debug!("{}, response code: {response_code}", self.request_summary(session, ctx));

        // Log TLS fingerprint if available
        if let Some(ref fingerprint) = ctx.tls_fingerprint {
            debug!(
                "Request completed - JA4: {}, JA4_Raw: {}, TLS_Version: {}, Cipher: {:?}, SNI: {:?}, ALPN: {:?}, Response: {}",
                fingerprint.ja4,
                fingerprint.ja4_raw,
                fingerprint.tls_version,
                fingerprint.cipher_suite,
                fingerprint.sni,
                fingerprint.alpn,
                response_code
            );
        }

        let m = &crate::utils::metrics::MetricTypes {
            method: session.req_header().method.to_string(),
            code: session.response_written().map(|resp| resp.status.as_str().to_owned()).unwrap_or("0".to_string()),
            latency: ctx.start_time.elapsed(),
            version: session.req_header().version,
        };
        crate::utils::metrics::calc_metrics(m);

        // Create access log
        if let (Some(peer_addr), Some(local_addr)) = (
            session.client_addr().and_then(|addr| addr.as_inet()),
            session.server_addr().and_then(|addr| addr.as_inet())
        ) {
            let peer_socket_addr = std::net::SocketAddr::new(peer_addr.ip(), peer_addr.port());
            let local_socket_addr = std::net::SocketAddr::new(local_addr.ip(), local_addr.port());

            // Convert request headers to hyper::http::request::Parts
            let mut request_builder = http::Request::builder()
                .method(session.req_header().method.as_str())
                .uri(session.req_header().uri.to_string())
                .version(session.req_header().version);

            // Copy headers
            for (name, value) in session.req_header().headers.iter() {
                request_builder = request_builder.header(name, value);
            }

            let hyper_request = request_builder.body(()).unwrap();
            let (req_parts, _) = hyper_request.into_parts();

            // Convert request body to Bytes
            let req_body_bytes = bytes::Bytes::from(ctx.request_body.clone());

            // Generate JA4H fingerprint from HTTP request
            let ja4h_fingerprint = crate::ja4_plus::Ja4hFingerprint::from_http_request(
                session.req_header().method.as_str(),
                &format!("{:?}", session.req_header().version),
                &session.req_header().headers
            );

            // Try to get TLS fingerprint from context or retrieve it again
            // Priority: 1) Context, 2) Retrieve from storage, 3) None
            let tls_fp_for_log = if let Some(tls_fp) = ctx.tls_fingerprint.as_ref() {
                debug!("TLS fingerprint found in context - JA4: {}, JA4_unsorted: {}, SNI: {:?}, ALPN: {:?}",
                       tls_fp.ja4, tls_fp.ja4_unsorted, tls_fp.sni, tls_fp.alpn);
                Some(tls_fp.clone())
            } else if let Some(peer_addr) = session.client_addr().and_then(|addr| addr.as_inet()) {
                // Try to retrieve TLS fingerprint again if not in context
                // Use fallback lookup to handle PROXY protocol address mismatches
                let std_addr = std::net::SocketAddr::new(peer_addr.ip().into(), peer_addr.port());
                if let Some(fingerprint) = crate::utils::tls_client_hello::get_fingerprint_with_fallback(&std_addr) {
                    debug!("TLS fingerprint retrieved from storage - JA4: {}, JA4_unsorted: {}, SNI: {:?}, ALPN: {:?}",
                           fingerprint.ja4, fingerprint.ja4_unsorted, fingerprint.sni, fingerprint.alpn);
                    // Store in context for future use in this request
                    ctx.tls_fingerprint = Some(fingerprint.clone());
                    Some(fingerprint)
                } else {
                    debug!("No TLS fingerprint found in storage for peer: {} (this may be normal if ClientHello callback didn't fire or PROXY protocol is used)", std_addr);
                    None
                }
            } else {
                debug!("No peer address available for TLS fingerprint retrieval");
                None
            };

            // Use HTTP JA4H fingerprint for tls_fingerprint parameter
            // The TLS JA4 fingerprint will be passed separately via tls_ja4_unsorted
            let tls_fingerprint_for_log = Some(ja4h_fingerprint.clone());

            // Get TCP fingerprint data (if available)
            let tcp_fingerprint_data = if let Some(collector) = crate::utils::tcp_fingerprint::get_global_tcp_fingerprint_collector() {
                collector.lookup_fingerprint(peer_addr.ip(), peer_addr.port())
            } else {
                None
            };

            // Get server certificate info (if available)
            // Try hostname first, then SNI from TLS fingerprint
            let server_cert_info_opt = {
                let hostname_to_use = ctx.hostname.as_ref()
                    .or_else(|| tls_fp_for_log.as_ref().and_then(|fp| fp.sni.as_ref()));

                if let Some(hostname) = hostname_to_use {
                    // Try to get certificate path from certificate store
                    let cert_path = if let Ok(store) = crate::worker::certificate::get_certificate_store().try_read() {
                        if let Some(certs) = store.as_ref() {
                            certs.get_cert_path_for_hostname(hostname)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    // If certificate path found, extract certificate info
                    if let Some(cert_path) = cert_path {
                        crate::utils::tls::extract_cert_info(&cert_path)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            // Build upstream info
            let upstream_info = ctx.upstream_peer.as_ref().map(|peer| {
                crate::access_log::UpstreamInfo {
                    selected: peer.address.clone(),
                    method: "round_robin".to_string(), // TODO: Get actual method from config
                    reason: "healthy".to_string(), // TODO: Get actual reason
                }
            });

            // Build performance info
            let performance_info = crate::access_log::PerformanceInfo {
                request_time_ms: Some(ctx.start_time.elapsed().as_millis() as u64),
                upstream_time_ms: ctx.upstream_time.map(|d| d.as_millis() as u64),
            };

            // Build response data
            let response_data = crate::access_log::ResponseData {
                response_json: serde_json::json!({
                    "status": response_code,
                    "status_text": session.response_written()
                        .and_then(|resp| resp.status.canonical_reason())
                        .unwrap_or("Unknown"),
                    "content_type": session.response_written()
                        .and_then(|resp| resp.headers.get("content-type"))
                        .and_then(|h| h.to_str().ok()),
                    "content_length": session.response_written()
                        .and_then(|resp| resp.headers.get("content-length"))
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0),
                    "body": ""  // Response body not captured
                }),
                blocking_info: None,
                waf_result: ctx.waf_result.clone(),
                threat_data: ctx.threat_data.clone(),
            };

            // Extract SNI, ALPN, cipher, JA4, and JA4_unsorted from TLS fingerprint if available
            // Use the same TLS fingerprint we retrieved above
            let (tls_sni, tls_alpn, tls_cipher, tls_ja4, tls_ja4_unsorted) = if let Some(tls_fp) = tls_fp_for_log.as_ref() {
                // Validate that JA4 values are not empty
                let ja4 = if tls_fp.ja4.is_empty() {
                    warn!("TLS fingerprint found but JA4 is empty - this should not happen");
                    None
                } else {
                    Some(tls_fp.ja4.clone())
                };

                let ja4_unsorted = if tls_fp.ja4_unsorted.is_empty() {
                    warn!("TLS fingerprint found but JA4_unsorted is empty - this should not happen");
                    None
                } else {
                    Some(tls_fp.ja4_unsorted.clone())
                };

                debug!(
                    "TLS fingerprint found for logging - JA4: {:?}, JA4_unsorted: {:?}, SNI: {:?}, ALPN: {:?}, Cipher: {:?}",
                    ja4, ja4_unsorted, tls_fp.sni, tls_fp.alpn, tls_fp.cipher_suite
                );

                // Use SNI from fingerprint, fallback to hostname from context or Host header
                let sni = tls_fp.sni.clone().or_else(|| {
                    ctx.hostname.clone().or_else(|| {
                        session.req_header().headers.get("host")
                            .and_then(|h| h.to_str().ok())
                            .map(|h| h.split(':').next().unwrap_or(h).to_string())
                    })
                });

                (
                    sni,
                    tls_fp.alpn.clone(),
                    tls_fp.cipher_suite.clone(),
                    ja4,
                    ja4_unsorted,
                )
            } else {
                debug!("No TLS fingerprint found for logging - peer: {:?} (JA4/JA4_unsorted will be null)", peer_addr);
                // Fallback: try to extract SNI from Host header if available
                let sni = ctx.hostname.clone().or_else(|| {
                    session.req_header().headers.get("host")
                        .and_then(|h| h.to_str().ok())
                        .map(|h| h.split(':').next().unwrap_or(h).to_string())
                });
                (sni, None, None, None, None)
            };

            // Create access log with upstream and performance info
            if let Err(e) = crate::access_log::HttpAccessLog::create_from_parts(
                &req_parts,
                &req_body_bytes,
                peer_socket_addr,
                local_socket_addr,
                tls_fingerprint_for_log.as_ref(),
                tcp_fingerprint_data.as_ref(),
                server_cert_info_opt.as_ref(),
                response_data,
                ctx.waf_result.as_ref(),
                ctx.threat_data.as_ref(),
                upstream_info,
                Some(performance_info),
                tls_sni,
                tls_alpn,
                tls_cipher,
                tls_ja4,
                tls_ja4_unsorted,
            ).await {
                warn!("Failed to create access log: {}", e);
            }
        }
    }
}

impl LB {}

fn return_header_host(session: &Session) -> Option<String> {
    if session.is_http2() {
        match session.req_header().uri.host() {
            Some(host) => Option::from(host.to_string()),
            None => None,
        }
    } else {
        match session.req_header().headers.get("host") {
            Some(host) => {
                let header_host = host.to_str().unwrap().splitn(2, ':').collect::<Vec<&str>>();
                Option::from(header_host[0].to_string())
            }
            None => None,
        }
    }
}
