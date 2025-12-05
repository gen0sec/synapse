//! Everything required for setting up HTTPS / TLS.
//! Instantiate a server for HTTP-01 check with letsencrypt,
//! checks if certificates are not outdated,
//! persists files on disk.

use crate::acme::{Config, AppConfig, RetryConfig, AtomicServerResult};
use crate::acme::{DomainConfig, DomainReaderFactory};
use crate::acme::{Storage, StorageFactory, StorageType};

use actix_web::{App, HttpServer, HttpResponse, web, Responder};
use anyhow::{anyhow, Context};
use serde::Serialize;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use once_cell::sync::OnceCell;
use tracing::{info, warn, debug};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

/// Global proxy_certificates path (set at startup)
static PROXY_CERTIFICATES_PATH: OnceCell<Arc<StdRwLock<Option<String>>>> = OnceCell::new();

/// Set the proxy_certificates path (called from main.rs)
pub fn set_proxy_certificates_path(path: Option<String>) {
    let path_arc = PROXY_CERTIFICATES_PATH.get_or_init(|| {
        Arc::new(StdRwLock::new(None))
    });
    if let Ok(mut path_guard) = path_arc.write() {
        *path_guard = path;
    }
}

/// Get the proxy_certificates path
fn get_proxy_certificates_path() -> Option<String> {
    PROXY_CERTIFICATES_PATH.get()
        .and_then(|path_arc| {
            path_arc.read().ok()
                .and_then(|guard| guard.clone())
        })
}

/// Normalize PEM certificate chain to ensure proper format
/// - Ensures newline between certificates (END CERTIFICATE and BEGIN CERTIFICATE)
/// - Ensures file ends with newline
fn normalize_pem_chain(chain: &str) -> String {
    let mut normalized = chain.to_string();

    // Ensure newline between END CERTIFICATE and BEGIN CERTIFICATE
    normalized = normalized.replace("-----END CERTIFICATE----------BEGIN CERTIFICATE-----",
                                    "-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----");

    // Ensure newline between END CERTIFICATE and BEGIN PRIVATE KEY (for key files)
    normalized = normalized.replace("-----END CERTIFICATE----------BEGIN PRIVATE KEY-----",
                                    "-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----");

    // Ensure file ends with newline
    if !normalized.ends_with('\n') {
        normalized.push('\n');
    }

    normalized
}

/// Save certificate to proxy_certificates path in the format expected by the proxy
/// Format: {sanitized_domain}.crt and {sanitized_domain}.key
async fn save_cert_to_proxy_path(
    domain: &str,
    fullchain: &str,
    private_key: &str,
    proxy_certificates_path: &str,
) -> anyhow::Result<()> {
    use std::path::Path;
    use tokio::fs;
    use tokio::io::AsyncWriteExt;

    // Create directory if it doesn't exist
    let cert_dir = Path::new(proxy_certificates_path);
    fs::create_dir_all(cert_dir).await
        .with_context(|| format!("Failed to create proxy_certificates directory: {}", proxy_certificates_path))?;

    // Sanitize domain name for filename (replace . with _ and * with _)
    let sanitized_domain = domain.replace('.', "_").replace('*', "_");
    let cert_path = cert_dir.join(format!("{}.crt", sanitized_domain));
    let key_path = cert_dir.join(format!("{}.key", sanitized_domain));

    // Normalize PEM format
    let normalized_fullchain = normalize_pem_chain(fullchain);
    let normalized_key = normalize_pem_chain(private_key);

    // Write certificate file
    let mut cert_file = fs::File::create(&cert_path).await
        .with_context(|| format!("Failed to create certificate file: {}", cert_path.display()))?;
    cert_file.write_all(normalized_fullchain.as_bytes()).await
        .with_context(|| format!("Failed to write certificate file: {}", cert_path.display()))?;
    cert_file.sync_all().await
        .with_context(|| format!("Failed to sync certificate file: {}", cert_path.display()))?;

    // Write key file
    let mut key_file = fs::File::create(&key_path).await
        .with_context(|| format!("Failed to create key file: {}", key_path.display()))?;
    key_file.write_all(normalized_key.as_bytes()).await
        .with_context(|| format!("Failed to write key file: {}", key_path.display()))?;
    key_file.sync_all().await
        .with_context(|| format!("Failed to sync key file: {}", key_path.display()))?;

    info!("Saved certificate for domain '{}' to proxy_certificates path: {} (cert: {}, key: {})",
        domain, proxy_certificates_path, cert_path.display(), key_path.display());

    Ok(())
}

/// Create RUSTLS server config from certificates in storage
pub fn get_https_config(
    config: &Config,
) -> AtomicServerResult<rustls::ServerConfig> {
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    // Create storage backend (file system by default)
    let storage = StorageFactory::create_default(config)?;

    // Read fullchain synchronously (rustls requires sync)
    // Use fullchain which includes both cert and chain
    let fullchain_bytes = storage.read_fullchain_sync()
        .ok_or_else(|| anyhow!("Storage backend does not support synchronous fullchain reading"))??;

    let key_bytes = storage.read_key_sync()
        .ok_or_else(|| anyhow!("Storage backend does not support synchronous key reading"))??;

    let cert_file = &mut BufReader::new(std::io::Cursor::new(fullchain_bytes));
    let key_file = &mut BufReader::new(std::io::Cursor::new(key_bytes));

    let mut cert_chain = Vec::new();
    for cert_result in certs(cert_file) {
        let cert = cert_result.context("Failed to parse certificate")?;
        cert_chain.push(CertificateDer::from(cert));
    }

    let mut keys: Vec<PrivateKeyDer> = pkcs8_private_keys(key_file)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse private key")?
        .into_iter()
        .map(PrivateKeyDer::Pkcs8)
        .collect();

    if keys.is_empty() {
        return Err(anyhow!("No key found. Consider deleting the storage directory and restart to create new keys."));
    }

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys.remove(0))
        .context("Unable to create HTTPS config from certificates")?;

    Ok(server_config)
}

/// Check if a failed certificate should be retried based on exponential backoff
pub async fn should_retry_failed_cert(
    config: &Config,
    retry_config: &RetryConfig,
) -> AtomicServerResult<bool> {
    let storage = StorageFactory::create_default(config)?;

    // Check if there's a failure record
    let last_failure = match storage.get_last_failure().await {
        Ok(Some((timestamp, _))) => timestamp,
        Ok(None) => return Ok(false), // No failure recorded
        Err(e) => {
            warn!("Failed to read failure record: {}", e);
            return Ok(false);
        }
    };

    // Check if max retries exceeded
    let failure_count = storage.get_failure_count().await.unwrap_or(0);
    if retry_config.max_retries > 0 && failure_count >= retry_config.max_retries {
        warn!("Maximum retry count ({}) exceeded for domain {}. Skipping retry.", retry_config.max_retries, config.opts.domain);
        return Ok(false);
    }

    // Calculate exponential backoff delay
    // Formula: min(min_retry_delay * 2^(failure_count - 1), max_retry_delay)
    let base_delay = retry_config.min_retry_delay_seconds as f64;
    let exponential_delay = base_delay * (2.0_f64.powi((failure_count.saturating_sub(1)) as i32));
    let delay_seconds = exponential_delay.min(retry_config.max_retry_delay_seconds as f64) as u64;

    let now = chrono::Utc::now();
    let time_since_failure = now - last_failure;
    let time_since_failure_secs = time_since_failure.num_seconds() as u64;

    if time_since_failure_secs >= delay_seconds {
        info!("Retry delay ({}) has passed for domain {}. Last failure was {} seconds ago. Will retry.", delay_seconds, config.opts.domain, time_since_failure_secs);
        Ok(true)
    } else {
        let remaining = delay_seconds - time_since_failure_secs;
        info!("Retry delay not yet reached for domain {}. Will retry in {} seconds.", config.opts.domain, remaining);
        Ok(false)
    }
}

/// Checks if the certificates need to be renewed.
/// Will be true if there are no certs yet.
pub async fn should_renew_certs_check(config: &Config) -> AtomicServerResult<bool> {
    let storage = StorageFactory::create_default(config)?;

    if !storage.cert_exists().await {
        info!(
            "No HTTPS certificates found, requesting new ones...",
        );
        return Ok(true);
    }

    // Ensure certificate hash exists (generate if missing for backward compatibility)
    if let Err(e) = storage.get_certificate_hash().await {
        warn!("Failed to get or generate certificate hash: {}", e);
    }

    let created_at = match storage.read_created_at().await {
        Ok(dt) => dt,
        Err(_) => {
            // If we can't read the created_at file, assume certificates need renewal
            warn!("Unable to read certificate creation timestamp, assuming renewal needed");
            return Ok(true);
        }
    };

    let certs_age: chrono::Duration = chrono::Utc::now() - created_at;
    // Let's Encrypt certificates are valid for three months, but I think renewing earlier provides a better UX
    let expired = certs_age > chrono::Duration::weeks(4);
    if expired {
        warn!("HTTPS Certificates expired, requesting new ones...")
    };
    Ok(expired)
}

#[derive(Debug, Serialize)]
struct CertificateExpirationInfo {
    domain: String,
    exists: bool,
    created_at: Option<String>,
    expires_at: Option<String>,
    age_days: Option<i64>,
    expires_in_days: Option<i64>,
    needs_renewal: bool,
    #[serde(default)]
    renewing: bool,
}

/// Get certificate expiration information for a domain
async fn get_cert_expiration_info(
    app_config: &AppConfig,
    domain: &str,
    base_https_path: &std::path::PathBuf,
) -> anyhow::Result<CertificateExpirationInfo> {
    let domain_cfg = {
        let domain_config = DomainConfig {
            domain: domain.to_string(),
            email: None,
            dns: false,
            wildcard: false,
        };
        app_config.create_domain_config(&domain_config, base_https_path.clone())
    };

    let storage = StorageFactory::create_default(&domain_cfg)?;
    let exists = storage.cert_exists().await;

    if !exists {
        return Ok(CertificateExpirationInfo {
            domain: domain.to_string(),
            exists: false,
            created_at: None,
            expires_at: None,
            age_days: None,
            expires_in_days: None,
            needs_renewal: true,
            renewing: false,
        });
    }

    // Ensure certificate hash exists (generate if missing for backward compatibility)
    if let Err(e) = storage.get_certificate_hash().await {
        warn!("Failed to get or generate certificate hash for {}: {}", domain, e);
    }

    let created_at = match storage.read_created_at().await {
        Ok(dt) => dt,
        Err(_) => {
            return Ok(CertificateExpirationInfo {
                domain: domain.to_string(),
                exists: true,
                created_at: None,
                expires_at: None,
                age_days: None,
                expires_in_days: None,
                needs_renewal: true,
                renewing: false,
            });
        }
    };

    // Let's Encrypt certificates are valid for 90 days (3 months)
    let expires_at = created_at + chrono::Duration::days(90);
    let now = chrono::Utc::now();
    let age = now - created_at;
    let expires_in = expires_at - now;

    let needs_renewal = age > chrono::Duration::weeks(4);

    Ok(CertificateExpirationInfo {
        domain: domain.to_string(),
        exists: true,
        created_at: Some(created_at.to_rfc3339()),
        expires_at: Some(expires_at.to_rfc3339()),
        age_days: Some(age.num_days()),
        expires_in_days: Some(expires_in.num_days()),
        needs_renewal,
        renewing: false,
    })
}

/// HTTP handler for certificate expiration check (single domain)
async fn check_cert_expiration_handler(
    app_config: web::Data<AppConfig>,
    base_path: web::Data<std::path::PathBuf>,
    path: web::Path<String>,
) -> impl Responder {
    let domain = path.into_inner();
    match get_cert_expiration_info(&app_config, &domain, &base_path).await {
        Ok(mut info) => {
            // If certificate needs renewal, start renewal process in background
            if info.needs_renewal {
                // Read domains to find the domain config
                let domain_reader = match DomainReaderFactory::create(&app_config.domains) {
                    Ok(reader) => reader,
                    Err(e) => {
                        warn!("Error creating domain reader: {}", e);
                        return HttpResponse::Ok().json(info);
                    }
                };

                if let Ok(domains) = domain_reader.read_domains().await {
                    if let Some(domain_config) = domains.iter().find(|d| d.domain == domain) {
                        let app_config_clone = app_config.clone();
                        let base_path_clone = base_path.clone();
                        let domain_config_clone = domain_config.clone();

                        // Spawn renewal task in background
                        tokio::spawn(async move {
                            if let Err(e) = renew_cert_if_needed(&app_config_clone, &domain_config_clone, &base_path_clone).await {
                                warn!("Error renewing certificate for {}: {}", domain_config_clone.domain, e);
                            }
                        });

                        info.renewing = true; // Mark as renewing
                    }
                }
            }
            HttpResponse::Ok().json(info)
        }
        Err(e) => {
            warn!("Error checking certificate expiration for {}: {}", domain, e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to check certificate expiration: {}", e)
            }))
        }
    }
}

/// Renew certificate for a domain if needed
async fn renew_cert_if_needed(
    app_config: &AppConfig,
    domain_config: &DomainConfig,
    base_path: &std::path::PathBuf,
) -> anyhow::Result<()> {
    let domain_cfg = app_config.create_domain_config(domain_config, base_path.clone());

    if should_renew_certs_check(&domain_cfg).await? {
        info!("Certificate for {} is expiring, starting renewal process...", domain_config.domain);
        request_cert(&domain_cfg).await?;
        info!("Certificate renewed successfully for {}!", domain_config.domain);
    }

    Ok(())
}

/// HTTP handler for checking expiration of all domains
async fn check_all_certs_expiration_handler(
    app_config: web::Data<AppConfig>,
    base_path: web::Data<std::path::PathBuf>,
) -> impl Responder {
    // Read domains from the configured source
    let domain_reader = match DomainReaderFactory::create(&app_config.domains) {
        Ok(reader) => reader,
        Err(e) => {
            warn!("Error creating domain reader: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create domain reader: {}", e)
            }));
        }
    };

    let domains = match domain_reader.read_domains().await {
        Ok(domains) => domains,
        Err(e) => {
            warn!("Error reading domains: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to read domains: {}", e)
            }));
        }
    };

    // Check expiration for each domain and renew if needed
    let mut results = Vec::new();
    for domain_config in domains.iter() {
        match get_cert_expiration_info(&app_config, &domain_config.domain, &base_path).await {
            Ok(mut info) => {
                // If certificate needs renewal, start renewal process in background
                if info.needs_renewal {
                    let app_config_clone = app_config.clone();
                    let base_path_clone = base_path.clone();
                    let domain_config_clone = domain_config.clone();

                    // Spawn renewal task in background
                    tokio::spawn(async move {
                        if let Err(e) = renew_cert_if_needed(&app_config_clone, &domain_config_clone, &base_path_clone).await {
                            warn!("Error renewing certificate for {}: {}", domain_config_clone.domain, e);
                        }
                    });

                    info.renewing = true; // Mark as renewing
                }
                results.push(info);
            }
            Err(e) => {
                warn!("Error checking certificate expiration for {}: {}", domain_config.domain, e);
                // Add error info for this domain
                results.push(CertificateExpirationInfo {
                    domain: domain_config.domain.clone(),
                    exists: false,
                    created_at: None,
                    expires_at: None,
                    age_days: None,
                    expires_in_days: None,
                    needs_renewal: true,
                    renewing: false,
                });
            }
        }
    }

    HttpResponse::Ok().json(results)
}

/// Check DNS TXT record for DNS-01 challenge
async fn check_dns_txt_record(record_name: &str, expected_value: &str, max_attempts: u32, delay_seconds: u64) -> bool {
    use trust_dns_resolver::TokioAsyncResolver;

    // Use Google DNS as primary resolver (more reliable than system DNS)
    // This ensures we're querying authoritative DNS servers
    let resolver_config = ResolverConfig::google();

    info!("Checking DNS TXT record: {} (expected value: {})", record_name, expected_value);
    info!("DNS lookup settings: max_attempts={}, delay_seconds={}", max_attempts, delay_seconds);

    for attempt in 1..=max_attempts {
        // Create a new resolver for each attempt to ensure no caching
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.use_hosts_file = true;
        resolver_opts.validate = false; // Don't validate DNSSEC to avoid issues
        resolver_opts.attempts = 3; // Retry attempts per query
        resolver_opts.timeout = std::time::Duration::from_secs(5); // 5 second timeout
        resolver_opts.cache_size = 0; // Disable DNS cache by setting cache size to 0

        // Create a fresh DNS resolver for each attempt to avoid any caching
        let resolver = TokioAsyncResolver::tokio(
            resolver_config.clone(),
            resolver_opts,
        );

        match resolver.txt_lookup(record_name).await {
            Ok(lookup) => {
                let mut found_any = false;
                let mut found_values = Vec::new();

                // Check if any TXT record matches the expected value
                for record in lookup.iter() {
                    for txt_data in record.iter() {
                        let txt_string = String::from_utf8_lossy(txt_data).trim().to_string();
                        found_any = true;
                        found_values.push(txt_string.clone());

                        if txt_string == expected_value {
                            info!("DNS TXT record matches expected value on attempt {}: {}", attempt, txt_string);
                            return true;
                        }
                    }
                }

                if found_any {
                    if attempt == 1 || attempt % 6 == 0 {
                        warn!("DNS record found but value doesn't match. Expected: '{}', Found: {:?}", expected_value, found_values);
                    }
                } else {
                    if attempt % 6 == 0 {
                        info!("DNS record not found yet (attempt {}/{})...", attempt, max_attempts);
                    }
                }
            }
            Err(e) => {
                if attempt == 1 || attempt % 6 == 0 {
                    warn!("DNS lookup error on attempt {}: {}", attempt, e);
                }
            }
        }

        if attempt < max_attempts {
            tokio::time::sleep(tokio::time::Duration::from_secs(delay_seconds)).await;
        }
    }

    warn!("DNS TXT record not found after {} attempts", max_attempts);
    false
}

/// Check if ACME challenge endpoint is available
/// This verifies that the ACME server is running and accessible before requesting certificates
/// Retries with exponential backoff to handle cases where the server is still starting
async fn check_acme_challenge_endpoint(config: &Config) -> anyhow::Result<()> {
    use std::time::Duration;

    // Build the ACME server URL (typically 127.0.0.1:9180)
    let acme_url = format!("http://{}:{}/.well-known/acme-challenge/test-endpoint-check", config.opts.ip, config.opts.port);

    debug!("Checking if ACME challenge endpoint is available at {}", acme_url);

    // Create HTTP client with timeout
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("Failed to create HTTP client for endpoint check")?;

    // Retry logic: try up to 5 times with exponential backoff
    // This handles cases where the ACME server is still starting up
    let max_retries = 5;
    let mut retry_delay = Duration::from_millis(10); // Start with 500ms

    for attempt in 1..=max_retries {
        match client.get(&acme_url).send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() || status.as_u16() == 404 {
                    if attempt > 1 {
                        debug!("ACME challenge endpoint is now available (status: {}) after {} attempt(s)", status, attempt);
                    } else {
                        debug!("ACME challenge endpoint is available (status: {})", status);
                    }
                    return Ok(());
                } else {
                    return Err(anyhow::anyhow!("ACME server returned unexpected status: {}", status));
                }
            }
            Err(e) => {
                let error_msg = e.to_string();
                let is_connection_error = error_msg.contains("Connection refused")
                    || error_msg.contains("connect")
                    || error_msg.contains("connection")
                    || error_msg.contains("refused")
                    || e.is_connect()
                    || e.is_timeout();

                if attempt < max_retries && is_connection_error {
                    debug!("ACME server not ready yet (attempt {}/{}), retrying in {:?}...", attempt, max_retries, retry_delay);
                    tokio::time::sleep(retry_delay).await;
                    // Exponential backoff: 10ms, 20ms, 40ms, 80ms, 160ms (user changed from 500ms)
                    retry_delay = retry_delay * 2;
                    continue;
                }
                // Last attempt or non-connection error - return error
                if attempt >= max_retries {
                    return Err(anyhow::anyhow!("Failed to connect to ACME server at {} after {} attempts: {}", acme_url, max_retries, e));
                } else {
                    return Err(anyhow::anyhow!("Failed to connect to ACME server at {} (non-retryable error): {}", acme_url, e));
                }
            }
        }
    }

    Err(anyhow::anyhow!("Failed to connect to ACME server at {} after {} attempts", acme_url, max_retries))
}

/// Writes challenge file for HTTP-01 challenge
/// The main HTTP server will serve this file - no temporary server needed
async fn cert_init_server(
    config: &Config,
    challenge: &instant_acme::Challenge,
    key_auth: &str,
) -> AtomicServerResult<()> {
    let storage = StorageFactory::create_default(config)?;
    storage.write_challenge(&challenge.token.to_string(), key_auth).await?;

    info!("Challenge file written. Main HTTP server will serve it at /.well-known/acme-challenge/{}", challenge.token);

    Ok(())
}

/// Sends a request to LetsEncrypt to create a certificate
pub async fn request_cert(config: &Config) -> AtomicServerResult<()> {
    // Always use Redis storage (storage_type option is kept for compatibility but always uses Redis)
    let storage_type = StorageType::Redis;

    if storage_type == StorageType::Redis {
        // Use distributed lock for Redis storage to prevent multiple instances from processing the same domain
        // Create RedisStorage directly to access lock methods
        let redis_storage = crate::acme::storage::RedisStorage::new(config)?;

        // Lock TTL from config (default: 900 seconds = 15 minutes)
        let lock_ttl_seconds = config.opts.lock_ttl_seconds.unwrap_or(900);

        return redis_storage.with_lock(lock_ttl_seconds, || async {
            request_cert_internal(config).await
        }).await;
    }

    // Redis storage always uses distributed lock (above)
    request_cert_internal(config).await
}

/// Parse retry-after timestamp from rate limit error message
/// Returns the retry-after timestamp if found, None otherwise
/// Handles both timestamp formats and ISO 8601 duration formats
fn parse_retry_after(error_msg: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{Utc, Duration};

    // Look for "retry after" pattern (case insensitive)
    let error_msg_lower = error_msg.to_lowercase();
    if let Some(pos) = error_msg_lower.find("retry after") {
        // Get the text after "retry after" from the original message (preserve case for parsing)
        let after_pos = error_msg[pos + "retry after".len()..].find(|c: char| !c.is_whitespace())
            .unwrap_or(0);
        let mut after_text_str = error_msg[pos + "retry after".len() + after_pos..].trim().to_string();

        // Try to find the end of the timestamp/duration
        // For timestamps like "2025-11-14 21:13:29 UTC", stop at end of line or before URL/links
        // Look for common patterns that indicate end of timestamp:
        // - End of string
        // - Before URLs (http:// or https://)
        // - Before "see" or ":" followed by URL
        if let Some(url_pos) = after_text_str.find("http://").or_else(|| after_text_str.find("https://")) {
            after_text_str = after_text_str[..url_pos].trim().to_string();
        }
        // Extract timestamp - format is typically "2025-11-14 21:13:29 UTC" followed by ": see https://..."
        // Simplest approach: find " UTC" and take everything up to and including it
        if let Some(utc_pos) = after_text_str.find(" UTC") {
            // Found " UTC", extract up to and including it (this is the complete timestamp)
            after_text_str = after_text_str[..utc_pos + 4].trim().to_string();
        } else {
            // No " UTC" found, try to stop before URLs or "see" keyword
            if let Some(url_pos) = after_text_str.find("http://").or_else(|| after_text_str.find("https://")) {
                after_text_str = after_text_str[..url_pos].trim().to_string();
            }
            if let Some(see_pos) = after_text_str.find(" see ") {
                after_text_str = after_text_str[..see_pos].trim().to_string();
            }
        }

        let after_text = after_text_str.as_str();

        // First, try to parse as timestamp (format: "2025-11-10 18:08:38 UTC")
        // Try with timezone first
        if let Ok(dt) = chrono::DateTime::parse_from_str(after_text, "%Y-%m-%d %H:%M:%S %Z") {
            return Some(dt.with_timezone(&chrono::Utc));
        }
        // Try with "UTC" as separate word (common format: "2025-11-14 21:13:29 UTC")
        if after_text.ends_with(" UTC") {
            let without_tz = &after_text[..after_text.len() - 4].trim();
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(without_tz, "%Y-%m-%d %H:%M:%S") {
                return Some(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
            }
        }
        // Try alternative format without timezone (assume UTC)
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(after_text, "%Y-%m-%d %H:%M:%S") {
            return Some(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
        }
        // Try parsing as RFC3339 format
        if let Ok(dt) = after_text.parse::<chrono::DateTime<chrono::Utc>>() {
            return Some(dt);
        }
        // Try ISO 8601/RFC3339 format (chrono doesn't have parse_from_rfc3339, use parse_from_str with RFC3339 format)
        // RFC3339 format: "2025-11-14T21:13:29Z" or "2025-11-14T21:13:29+00:00"
        if let Ok(dt) = chrono::DateTime::parse_from_str(after_text, "%+") {
            return Some(dt.with_timezone(&chrono::Utc));
        }

        // Try parsing as ISO 8601 duration (e.g., "PT86225.992004616S" or "PT24H")
        // This happens when the error message contains a duration instead of a timestamp
        if after_text.starts_with("PT") {
            // Parse ISO 8601 duration: PT[nH][nM][nS] or PT[n]S
            // Handle case where duration ends with 'S' (seconds)
            let duration_str = if after_text.ends_with('S') && !after_text.ends_with("MS") && !after_text.ends_with("HS") {
                &after_text[2..after_text.len()-1] // Remove "PT" prefix and "S" suffix
            } else {
                &after_text[2..] // Just remove "PT" prefix
            };

            // Try to parse as seconds (e.g., "86225.992004616")
            if let Ok(seconds) = duration_str.parse::<f64>() {
                let duration = Duration::seconds(seconds as i64) + Duration::nanoseconds((seconds.fract() * 1_000_000_000.0) as i64);
                return Some(Utc::now() + duration);
            }

            // Try to parse hours, minutes, seconds separately
            let mut total_seconds = 0.0;
            let mut current_num = String::new();
            let mut current_unit = String::new();

            for ch in duration_str.chars() {
                if ch.is_ascii_digit() || ch == '.' {
                    if !current_unit.is_empty() {
                        // Process previous unit
                        if let Ok(val) = current_num.parse::<f64>() {
                            match current_unit.as_str() {
                                "H" => total_seconds += val * 3600.0,
                                "M" => total_seconds += val * 60.0,
                                "S" => total_seconds += val,
                                _ => {}
                            }
                        }
                        current_num.clear();
                        current_unit.clear();
                    }
                    current_num.push(ch);
                } else if ch.is_ascii_alphabetic() {
                    current_unit.push(ch);
                }
            }

            // Process last unit
            if !current_unit.is_empty() && !current_num.is_empty() {
                if let Ok(val) = current_num.parse::<f64>() {
                    match current_unit.as_str() {
                        "H" => total_seconds += val * 3600.0,
                        "M" => total_seconds += val * 60.0,
                        "S" => total_seconds += val,
                        _ => {}
                    }
                }
            }

            if total_seconds > 0.0 {
                let duration = Duration::seconds(total_seconds as i64) + Duration::nanoseconds((total_seconds.fract() * 1_000_000_000.0) as i64);
                return Some(Utc::now() + duration);
            }
        }
    }
    None
}

/// Helper function to check if an account already exists
async fn check_account_exists(
    email: &str,
    lets_encrypt_url: &str,
) -> Result<Option<(instant_acme::Account, instant_acme::AccountCredentials)>, anyhow::Error> {
    match instant_acme::Account::builder()
        .context("Failed to create account builder")?
        .create(
            &instant_acme::NewAccount {
                contact: &[&format!("mailto:{}", email)],
                terms_of_service_agreed: true,
                only_return_existing: true,
            },
            lets_encrypt_url.to_string(),
            None,
        )
        .await
    {
        Ok((acc, cr)) => Ok(Some((acc, cr))),
        Err(e) => {
            let error_msg = format!("{}", e);
            // If it's a rate limit error, propagate it
            if error_msg.contains("rateLimited") || error_msg.contains("rate limit") || error_msg.contains("too many") {
                return Err(e.into());
            }
            // Otherwise, account doesn't exist
            Ok(None)
        }
    }
}

/// Helper function to create a new Let's Encrypt account and save credentials
/// Handles rate limits by waiting for the retry-after time
async fn create_new_account(
    storage: &Box<dyn Storage>,
    email: &str,
    lets_encrypt_url: &str,
) -> AtomicServerResult<(instant_acme::Account, instant_acme::AccountCredentials)> {
    // First, check if account already exists
    match check_account_exists(email, lets_encrypt_url).await {
        Ok(Some((acc, cr))) => {
            info!("Account already exists for email {}, reusing it", email);
            return Ok((acc, cr));
        }
        Ok(None) => {
            // Account doesn't exist, proceed to create
        }
        Err(e) => {
            // Check if it's a rate limit error
            let error_msg = format!("{}", e);
            if error_msg.contains("rateLimited") || error_msg.contains("rate limit") || error_msg.contains("too many") {
                if let Some(retry_after) = parse_retry_after(&error_msg) {
                    let now = chrono::Utc::now();
                    if retry_after > now {
                        let wait_duration = retry_after - now;
                        let wait_secs = wait_duration.num_seconds().max(0) as u64;
                        warn!("Rate limit hit. Waiting {} seconds until {} before retrying account creation", wait_secs, retry_after);
                        tokio::time::sleep(tokio::time::Duration::from_secs(wait_secs + 1)).await;
                    }
                } else {
                    // Rate limit error but couldn't parse retry-after, wait a default time
                    warn!("Rate limit hit but couldn't parse retry-after time. Waiting 3 hours (10800 seconds) before retrying");
                    tokio::time::sleep(tokio::time::Duration::from_secs(10800)).await;
                }
            } else {
                // Not a rate limit error, propagate it
                return Err(e);
            }
        }
    }

    info!("Creating new LetsEncrypt account with email {}", email);

    // Retry account creation (after waiting for rate limit if needed)
    let max_retries = 3;
    let mut retry_count = 0;

    loop {
        match instant_acme::Account::builder()
            .context("Failed to create account builder")?
            .create(
                &instant_acme::NewAccount {
                    contact: &[&format!("mailto:{}", email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                lets_encrypt_url.to_string(),
                None,
            )
            .await
        {
            Ok((account, creds)) => {
                // Save credentials for future use (store as JSON value for now)
                if let Ok(creds_json) = serde_json::to_string(&creds) {
                    if let Err(e) = storage.write_account_credentials(&creds_json).await {
                        warn!("Failed to save account credentials to storage: {}. Account will be recreated on next run.", e);
                    } else {
                        info!("Saved LetsEncrypt account credentials to storage");
                    }
                } else {
                    warn!("Failed to serialize account credentials. Account will be recreated on next run.");
                }
                return Ok((account, creds));
            }
            Err(e) => {
                let error_msg = format!("{}", e);

                // Check if it's a rate limit error
                if error_msg.contains("rateLimited") || error_msg.contains("rate limit") || error_msg.contains("too many") {
                    if let Some(retry_after) = parse_retry_after(&error_msg) {
                        let now = chrono::Utc::now();
                        if retry_after > now {
                            let wait_duration = retry_after - now;
                            let wait_secs = wait_duration.num_seconds().max(0) as u64;
                            warn!("Rate limit hit during account creation. Waiting {} seconds until {} before retrying", wait_secs, retry_after);
                            tokio::time::sleep(tokio::time::Duration::from_secs(wait_secs + 1)).await;
                            retry_count += 1;
                            if retry_count < max_retries {
                                continue;
                            }
                        }
                    } else {
                        // Rate limit error but couldn't parse retry-after
                        if retry_count < max_retries {
                            let wait_secs = 10800; // 3 hours default
                            warn!("Rate limit hit but couldn't parse retry-after time. Waiting {} seconds before retrying", wait_secs);
                            tokio::time::sleep(tokio::time::Duration::from_secs(wait_secs)).await;
                            retry_count += 1;
                            continue;
                        }
                    }
                }

                // If we've exhausted retries or it's not a rate limit error, return the error
                return Err(e).context("Failed to create account");
            }
        }
    }
}

async fn request_cert_internal(config: &Config) -> AtomicServerResult<()> {
    use instant_acme::OrderStatus;

    // Detect wildcard domain and automatically use DNS-01
    let is_wildcard = config.opts.domain.starts_with("*.");
    let use_dns = config.opts.https_dns || is_wildcard;

    if is_wildcard && !config.opts.https_dns {
        warn!("Wildcard domain detected ({}), automatically using DNS-01 challenge", config.opts.domain);
    }

    let challenge_type = if use_dns {
        debug!("Using DNS-01 challenge");
        instant_acme::ChallengeType::Dns01
    } else {
        debug!("Using HTTP-01 challenge");
        // Check if ACME challenge endpoint is available before proceeding
        if let Err(e) = check_acme_challenge_endpoint(config).await {
            let error_msg = format!("ACME challenge endpoint not available for HTTP-01 challenge: {}. Skipping certificate request.", e);
            warn!("{}", error_msg);
            let storage = StorageFactory::create_default(config)?;
            if let Err(record_err) = storage.record_failure(&error_msg).await {
                warn!("Failed to record failure: {}", record_err);
            }
            return Ok(());
        }
        instant_acme::ChallengeType::Http01
    };

    // Create a new account. This will generate a fresh ECDSA key for you.
    // Alternatively, restore an account from serialized credentials by
    // using `Account::from_credentials()`.

    let lets_encrypt_url = if config.opts.development {
        warn!(
            "Using LetsEncrypt staging server, not production. This is for testing purposes only and will not provide a working certificate."
        );
        instant_acme::LetsEncrypt::Staging.url()
    } else {
        instant_acme::LetsEncrypt::Production.url()
    };

    let email =
        config.opts.email.clone().expect(
            "No email set - required for HTTPS certificate initialization with LetsEncrypt",
        );

    // Try to load existing account credentials from storage
    let storage = StorageFactory::create_default(config)?;
    let existing_creds = storage.read_account_credentials().await
        .context("Failed to read account credentials from storage")?;

    // Try to restore account from stored credentials, but fall back to creating new account if it fails
    let (account, _creds) = match existing_creds {
        Some(creds_json) => {
            // Try to restore account from existing credentials
            debug!("Attempting to restore LetsEncrypt account from stored credentials");

            // First try to parse and restore from stored credentials
            match serde_json::from_str::<instant_acme::AccountCredentials>(&creds_json) {
                Ok(creds) => {
                    // Try to restore account from credentials
                    // Use AccountBuilder to restore from credentials
                    match instant_acme::Account::builder()
                        .context("Failed to create account builder")?
                        .from_credentials(creds)
                        .await
                    {
                        Ok(acc) => {
                            debug!("Successfully restored LetsEncrypt account from stored credentials");
                            // Get the credentials back from the account (they're stored in the account)
                            // For now, we'll use the stored credentials JSON
                            let restored_creds = serde_json::from_str::<instant_acme::AccountCredentials>(&creds_json)
                                .expect("Credentials were just parsed successfully");
                            (acc, restored_creds)
                        }
                        Err(e) => {
                            let error_msg = format!("{}", e);
                            warn!("Failed to restore account from stored credentials: {}. Will check if account exists.", error_msg);

                            // If restoration fails, check if account exists
                            match check_account_exists(&email, lets_encrypt_url).await {
                                Ok(Some((acc, cr))) => {
                                    info!("Account exists but credentials were invalid. Using existing account.");
                                    (acc, cr)
                                }
                                Ok(None) => {
                                    warn!("Stored credentials invalid and account doesn't exist. Creating new account.");
                                    create_new_account(&storage, &email, lets_encrypt_url).await?
                                }
                                Err(e) => {
                                    let error_msg = format!("{}", e);
                                    if error_msg.contains("rateLimited") || error_msg.contains("rate limit") || error_msg.contains("too many") {
                                        warn!("Rate limit hit while checking account. Will wait and retry in create_new_account.");
                                        create_new_account(&storage, &email, lets_encrypt_url).await?
                                    } else {
                                        warn!("Failed to check account existence: {}. Creating new account.", e);
                                        create_new_account(&storage, &email, lets_encrypt_url).await?
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to parse stored credentials: {}. Creating new account.", e);
                    create_new_account(&storage, &email, lets_encrypt_url).await?
                }
            }
        }
        None => {
            // No stored credentials, create a new account
            create_new_account(&storage, &email, lets_encrypt_url).await?
        }
    };

    // Create the ACME order based on the given domain names.
    // Note that this only needs an `&Account`, so the library will let you
    // process multiple orders in parallel for a single account.

    // Prepare domain for ACME order
    // For wildcard domains (*.example.com), we need to request *.example.com
    // For non-wildcard domains with DNS-01, we request the domain as-is
    let domain = config.opts.domain.clone();
    let is_wildcard_domain = domain.starts_with("*.");

    if is_wildcard_domain {
        // Domain already has wildcard prefix, use as-is for ACME order
        // ACME requires *.example.com format for wildcard certificates
        debug!("Requesting wildcard certificate for: {}", domain);
    } else if use_dns {
        // Non-wildcard domain with DNS-01 challenge - use domain as-is
        debug!("Requesting certificate for domain with DNS-01: {}", domain);
    } else {
        // HTTP-01 challenge - use domain as-is
        debug!("Requesting certificate for domain with HTTP-01: {}", domain);
    }

    // Check if we're still in rate limit period before attempting request
    use chrono::{Utc, Duration};
    let storage = StorageFactory::create_default(config)?;
    if let Ok(Some((last_failure_time, last_failure_msg))) = storage.get_last_failure().await {
        // Check if the last failure was a rate limit error
        if last_failure_msg.contains("rateLimited") ||
           last_failure_msg.contains("rate limit") ||
           last_failure_msg.contains("too many certificates") {
            // Parse retry-after time from error message
            if let Some(retry_after) = parse_retry_after(&last_failure_msg) {
                let now = Utc::now();
                if now < retry_after {
                    let wait_duration = retry_after - now;
                    info!("Rate limit still active for domain {}: retry after {} ({} remaining). Skipping certificate request.",
                        config.opts.domain, retry_after, wait_duration);
                    return Ok(());
                } else {
                    debug!("Rate limit period has passed for domain {}. Proceeding with certificate request.", config.opts.domain);
                }
            } else {
                // Log the error message for debugging
                tracing::debug!("Failed to parse retry-after from error message: {}", last_failure_msg);
                // Can't parse retry-after from error message
                // Try to extract duration from the error message if it contains ISO 8601 duration
                // Look for patterns like "PT86225S" or "PT24H" anywhere in the message
                let mut found_duration = None;
                for word in last_failure_msg.split_whitespace() {
                    if word.starts_with("PT") {
                        // Try to parse as ISO 8601 duration
                        if let Some(dt) = parse_retry_after(&format!("retry after {}", word)) {
                            found_duration = Some(dt);
                            break;
                        }
                    }
                }

                if let Some(retry_after) = found_duration {
                    let now = Utc::now();
                    if now < retry_after {
                        let wait_duration = retry_after - now;
                        info!("Rate limit still active for domain {}: retry after {} ({} remaining). Skipping certificate request.",
                            config.opts.domain, retry_after, wait_duration);
                        return Ok(());
                    }
                } else {
                    // Can't parse retry-after at all, use exponential backoff (24 hours minimum for rate limits)
                    let rate_limit_cooldown = Duration::hours(24);
                    let now = Utc::now();
                    if now - last_failure_time < rate_limit_cooldown {
                        let remaining = rate_limit_cooldown - (now - last_failure_time);
                        warn!("Rate limit error detected for domain {} (retry-after time not parseable from: '{}'). Waiting {} before retry. Skipping certificate request.",
                            config.opts.domain, last_failure_msg, remaining);
                        return Ok(());
                    } else {
                        debug!("Rate limit cooldown period has passed for domain {}. Proceeding with certificate request.", config.opts.domain);
                    }
                }
            }
        }
    }

    let identifier = instant_acme::Identifier::Dns(domain.clone());
    let identifiers = vec![identifier];
    let mut order = match account
        .new_order(&instant_acme::NewOrder::new(&identifiers))
        .await
    {
        Ok(order) => order,
        Err(e) => {
            let error_msg = format!("Failed to create new order for domain {}: {}", config.opts.domain, e);
            warn!("{}. Skipping certificate request.", error_msg);

            // If it's a rate limit error, store it with retry-after time
            let is_rate_limit = error_msg.contains("rateLimited") ||
                               error_msg.contains("rate limit") ||
                               error_msg.contains("too many certificates");

            if is_rate_limit {
                if let Some(retry_after) = parse_retry_after(&error_msg) {
                    info!("Rate limit error for domain {}: will retry after {}", config.opts.domain, retry_after);
                } else {
                    warn!("Rate limit error for domain {} but could not parse retry-after time. Will wait 24 hours before retry.", config.opts.domain);
                }
            }

            if let Err(record_err) = storage.record_failure(&error_msg).await {
                warn!("Failed to record failure: {}", record_err);
            }
            return Ok(());
        }
    };

    // Check if order is already ready (from a previous request)
    let initial_state = order.state();

    // Handle unexpected order status
    if !matches!(initial_state.status, instant_acme::OrderStatus::Pending | instant_acme::OrderStatus::Ready) {
        let error_msg = format!("Unexpected order status: {:?} for domain {}", initial_state.status, config.opts.domain);
        warn!("{}. Skipping certificate request.", error_msg);
        if let Err(record_err) = storage.record_failure(&error_msg).await {
            warn!("Failed to record failure: {}", record_err);
        }
        return Ok(());
    }

    // If order is already Ready, skip challenge processing
    let state = if matches!(initial_state.status, instant_acme::OrderStatus::Ready) {
        info!("Order is already in Ready state, skipping challenge processing and proceeding to finalization");
        // Use initial_state as the final state since we're skipping challenge processing
        initial_state
    } else {
        // Order is Pending, proceed with challenge processing
    // Pick the desired challenge type and prepare the response.
    let mut authorizations = order.authorizations();
    let mut challenges_set = Vec::new();

    while let Some(result) = authorizations.next().await {
        let mut authz = match result {
            Ok(authz) => authz,
            Err(e) => {
                warn!("Failed to get authorization: {}. Skipping this authorization.", e);
                continue;
            }
        };
        let domain = authz.identifier().to_string();

        match authz.status {
            instant_acme::AuthorizationStatus::Pending => {}
            instant_acme::AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        let mut challenge = match authz.challenge(challenge_type.clone()) {
            Some(c) => c,
            None => {
                warn!("Domain '{}': No {:?} challenge found, skipping", domain, challenge_type);
                continue;
            }
        };

        let key_auth = challenge.key_authorization().as_str().to_string();
        match challenge_type {
            instant_acme::ChallengeType::Http01 => {
                // Check if existing challenge is expired and clean it up
                let storage = StorageFactory::create_default(config)?;
                let challenge_token = challenge.token.to_string();
                if let Ok(Some(_)) = storage.get_challenge_timestamp(&challenge_token).await {
                    // Challenge exists, check if expired
                    let max_ttl = config.opts.challenge_max_ttl_seconds.unwrap_or(3600);
                    if let Ok(true) = storage.is_challenge_expired(&challenge_token, max_ttl).await {
                        info!("Existing challenge for token {} is expired (TTL: {}s), will be replaced", challenge_token, max_ttl);
                    }
                }

                if let Err(e) = cert_init_server(config, &challenge, &key_auth).await {
                    warn!("Failed to write challenge file for HTTP-01 challenge: {}. Skipping HTTP-01 challenge.", e);
                    continue;
                }
            }
            instant_acme::ChallengeType::Dns01 => {
                // For DNS-01 challenge, the TXT record should be at _acme-challenge.{base_domain}
                // For wildcard domains (*.example.com), use the base domain (example.com)
                // For non-wildcard domains, use the domain as-is
                // Use the is_wildcard flag computed earlier, or check the domain from authorization
                let base_domain = if domain.starts_with("*.") {
                    // Domain from authorization starts with *. - strip it
                    domain.strip_prefix("*.").unwrap_or(&domain)
                } else if is_wildcard {
                    // is_wildcard is true but domain doesn't start with *.
                    // This can happen if ACME returns the base domain instead of wildcard
                    // Use the domain as-is (it's already the base domain)
                    &domain
                } else {
                    // For non-wildcard, use domain as-is
                    &domain
                };
                let dns_record = format!("_acme-challenge.{}", base_domain);
                let dns_value = challenge.key_authorization().dns_value();

                info!("DNS-01 challenge for domain '{}' (base domain: {}, wildcard: {}):", domain, base_domain, is_wildcard);
                info!("  Create DNS TXT record: {} IN TXT {}", dns_record, dns_value);
                info!("  This record must be added to your DNS provider before the challenge can be validated.");

                // Check if existing DNS challenge is expired and clean it up
                let storage = StorageFactory::create_default(config)?;
                if let Ok(Some(_)) = storage.get_dns_challenge_timestamp(&domain).await {
                    // DNS challenge exists, check if expired
                    let max_ttl = config.opts.challenge_max_ttl_seconds.unwrap_or(3600);
                    if let Ok(true) = storage.is_dns_challenge_expired(&domain, max_ttl).await {
                        info!("Existing DNS challenge for domain {} is expired (TTL: {}s), will be replaced", domain, max_ttl);
                    }
                }

                // Save DNS challenge code to storage (Redis or file)
                if let Err(e) = storage.write_dns_challenge(&domain, &dns_record, &dns_value).await {
                    warn!("Failed to save DNS challenge code to storage: {}", e);
                }

                info!("Waiting for DNS record to propagate...");

                // Automatically check DNS records
                let max_attempts = config.opts.dns_lookup_max_attempts.unwrap_or(100);
                let delay_seconds = config.opts.dns_lookup_delay_seconds.unwrap_or(10);
                let dns_ready = check_dns_txt_record(&dns_record, &dns_value, max_attempts, delay_seconds).await;

                if !dns_ready {
                    let error_msg = format!("DNS record not found after checking for domain {}. Record: {} IN TXT {}", domain, dns_record, dns_value);
                    warn!("{}. Please verify the DNS record is set correctly.", error_msg);
                    let storage = StorageFactory::create_default(config)?;
                    if let Err(record_err) = storage.record_failure(&error_msg).await {
                        warn!("Failed to record failure: {}", record_err);
                    }
                    return Ok(());
                }

                info!("DNS record found! Proceeding with challenge validation...");
            }
            instant_acme::ChallengeType::TlsAlpn01 => todo!("TLS-ALPN-01 is not supported"),
            _ => {
                let error_msg = format!("Unsupported challenge type: {:?}", challenge_type);
                warn!("{}", error_msg);
                let storage = StorageFactory::create_default(config)?;
                if let Err(record_err) = storage.record_failure(&error_msg).await {
                    warn!("Failed to record failure: {}", record_err);
                }
                return Ok(());
            }
        }

        // Notify ACME server to validate
        info!("Domain '{}': Notifying ACME server to validate challenge", domain);
        challenge.set_ready().await
            .with_context(|| format!("Failed to set challenge ready for domain {}", domain))?;
        challenges_set.push(domain);
    }

    if challenges_set.is_empty() {
        let error_msg = format!("All domains failed challenge setup for domain {}", config.opts.domain);
        warn!("{}", error_msg);
        let storage = StorageFactory::create_default(config)?;
        if let Err(record_err) = storage.record_failure(&error_msg).await {
            warn!("Failed to record failure: {}", record_err);
        }
        return Ok(());
    }

    // Exponentially back off until the order becomes ready or invalid.
    let mut tries = 0u8;
    let state = loop {
        let state = match order.refresh().await {
            Ok(s) => s,
            Err(e) => {
                if tries >= 10 {
                    let error_msg = format!("Order refresh failed after {} attempts: {}", tries, e);
                    warn!("{}", error_msg);
                    let storage = StorageFactory::create_default(config)?;
                    if let Err(record_err) = storage.record_failure(&error_msg).await {
                        warn!("Failed to record failure: {}", record_err);
                    }
                    return Ok(());
                }
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        info!("Order state: {:#?}", state);
        if let OrderStatus::Ready | OrderStatus::Invalid | OrderStatus::Valid = state.status {
            break state;
        }

        tries += 1;
        if tries >= 10 {
            let error_msg = format!("Giving up: order is not ready after {} attempts for domain {}", tries, config.opts.domain);
            warn!("{}", error_msg);
            let storage = StorageFactory::create_default(config)?;
            if let Err(record_err) = storage.record_failure(&error_msg).await {
                warn!("Failed to record failure: {}", record_err);
            }
            return Ok(());
        }

        let delay = std::time::Duration::from_secs(2 + tries as u64);
        info!("order is not ready, waiting {delay:?}");
        tokio::time::sleep(delay).await;
    };

    if state.status == OrderStatus::Invalid {
        // Try to get more details about why the order is invalid
        let mut error_details = Vec::new();
        if let Some(error) = &state.error {
            error_details.push(format!("Order error: {:?}", error));
        }

        // Fetch authorization details from ACME server if state is None
        for auth in &state.authorizations {
            if let Some(auth_state) = &auth.state {
                // Check authorization status for more details
                match &auth_state.status {
                    instant_acme::AuthorizationStatus::Invalid => {
                        error_details.push(format!("Authorization {} is invalid", auth.url));
                    }
                    instant_acme::AuthorizationStatus::Expired => {
                        error_details.push(format!("Authorization {} expired", auth.url));
                    }
                    instant_acme::AuthorizationStatus::Revoked => {
                        error_details.push(format!("Authorization {} revoked", auth.url));
                    }
                    _ => {}
                }
            } else {
                // Authorization state is None - this means the authorization details weren't included in the order state
                // We can't fetch it again because order.authorizations() was already consumed
                // Log the URL so the user can check it manually
                warn!("Authorization state is None for {}. This usually means the authorization failed or expired. Check the authorization URL for details.", auth.url);
                error_details.push(format!("Authorization {} state unavailable (check URL for details)", auth.url));
            }
        }

        let error_msg = if error_details.is_empty() {
            format!("Order is invalid but no error details available. Order state: {:#?}", state)
        } else {
            format!("Order is invalid. Details: {}", error_details.join("; "))
        };
            warn!("{}", error_msg);
            let storage = StorageFactory::create_default(config)?;
            if let Err(record_err) = storage.record_failure(&error_msg).await {
                warn!("Failed to record failure: {}", record_err);
            }
            return Ok(());
        }

        state
    };

    // Check if state is invalid before proceeding to finalization
    if state.status == OrderStatus::Invalid {
        let error_msg = format!("Order is invalid for domain {}", config.opts.domain);
        warn!("{}", error_msg);
        let storage = StorageFactory::create_default(config)?;
        if let Err(record_err) = storage.record_failure(&error_msg).await {
            warn!("Failed to record failure: {}", record_err);
        }
        return Ok(());
    }

    // If the order is ready, we can provision the certificate.
    // Finalize the order - this will generate a CSR and return the private key PEM.
    let private_key_pem = order.finalize().await
        .context("Failed to finalize ACME order")?;

    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut tries = 1u8;

    let cert_chain_pem = loop {
        match order.certificate().await {
            Ok(Some(cert_chain_pem)) => {
                info!("Certificate ready!");
                break cert_chain_pem;
            }
            Ok(None) => {
                if tries > 10 {
                    let error_msg = format!("Giving up: certificate is still not ready after {} attempts", tries);
                    let storage = StorageFactory::create_default(config)?;
                    if let Err(record_err) = storage.record_failure(&error_msg).await {
                        warn!("Failed to record failure: {}", record_err);
                    }
                    return Err(anyhow!("{}", error_msg));
                }
                tries += 1;
                info!("Certificate not ready yet...");
                continue;
            }
            Err(e) => {
                let error_msg = format!("Error getting certificate: {}", e);
                let storage = StorageFactory::create_default(config)?;
                if let Err(record_err) = storage.record_failure(&error_msg).await {
                    warn!("Failed to record failure: {}", record_err);
                }
                return Err(anyhow!("{}", error_msg));
            }
        }
    };

    write_certs(config, cert_chain_pem, private_key_pem).await
        .context("Failed to write certificates to storage")?;

    // Clear any previous failure records since certificate was successfully generated
    let storage = StorageFactory::create_default(config)?;
    if let Err(clear_err) = storage.clear_failure().await {
        warn!("Failed to clear failure record: {}", clear_err);
    }

    info!("HTTPS TLS Cert init successful! Certificate written to storage.");

    Ok(())
}

async fn write_certs(
    config: &Config,
    cert_chain_pem: String,
    private_key_pem: String,
) -> AtomicServerResult<()> {
    // Always use Redis storage (storage_type option is kept for compatibility but always uses Redis)
    info!("Creating Redis storage backend");
    let storage = StorageFactory::create_default(config)?;
    info!("Storage backend created successfully");

    info!("Writing TLS certificates to storage (certbot-style)");

    // Parse the certificate chain to separate cert from chain
    // The cert_chain_pem contains the domain cert first, followed by intermediate certs
    // It's already in PEM format, so we split it by "-----BEGIN CERTIFICATE-----"
    let cert_parts: Vec<String> = cert_chain_pem
        .split("-----BEGIN CERTIFICATE-----")
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("-----BEGIN CERTIFICATE-----{}", s))
        .collect();

    if cert_parts.is_empty() {
        return Err(anyhow!("No certificates found in chain"));
    }

    // First certificate is the domain certificate
    let domain_cert_pem = cert_parts[0].trim().to_string();

    // Remaining certificates form the chain
    let chain_pem = if cert_parts.len() > 1 {
        cert_parts[1..].join("\n")
    } else {
        String::new()
    };

    // Combine cert and chain to create fullchain
    let mut fullchain = domain_cert_pem.clone();
    if !chain_pem.is_empty() {
        fullchain.push_str("\n");
        fullchain.push_str(&chain_pem);
    }

    info!("Writing certificate to Redis storage backend...");
    storage.write_certs(
        domain_cert_pem.as_bytes(),
        chain_pem.as_bytes(),
        private_key_pem.as_bytes(),
    ).await
        .context("Failed to write certificates to storage backend")?;
    info!("Certificates written successfully to Redis storage backend");

    storage.write_created_at(chrono::Utc::now()).await
        .context("Failed to write created_at timestamp")?;

    // Save certificates to proxy_certificates path
    if let Some(proxy_certificates_path) = get_proxy_certificates_path() {
        if let Err(e) = save_cert_to_proxy_path(
            &config.opts.domain,
            &fullchain,
            &private_key_pem,
            &proxy_certificates_path,
        ).await {
            warn!("Failed to save certificate to proxy_certificates path: {}", e);
        } else {
            info!("Certificate saved to proxy_certificates path: {}", proxy_certificates_path);
        }
    } else {
        warn!("proxy_certificates path not configured, skipping file save");
    }
    info!("Created_at timestamp written successfully");

    Ok(())
}

/// Start HTTP server for ACME challenge requests
/// This server only serves ACME challenge files and keeps running indefinitely
pub async fn start_http_server(app_config: &AppConfig) -> AtomicServerResult<()> {
    let address = format!("{}:{}", app_config.server.ip, app_config.server.port);
    info!("Starting HTTP server for ACME challenges at {}", address);
    info!("Server will only accept ACME challenge requests at /.well-known/acme-challenge/*");
    info!("Certificate expiration check endpoints:");
    info!("  - GET /cert/expiration - Check all domains");
    info!("  - GET /cert/expiration/{{domain}} - Check specific domain");
    info!("To stop the program, press Ctrl+C");

    // Use the base storage path for serving ACME challenges
    // Challenges are stored in a shared location: https_path/well-known/acme-challenge/
    let base_static_path = std::path::PathBuf::from(&app_config.storage.https_path);

    // Build the path to the well-known/acme-challenge directory
    // Files are stored at: base_path/well-known/acme-challenge/{token}
    let mut challenge_static_path = base_static_path.clone();
    challenge_static_path.push("well-known");
    challenge_static_path.push("acme-challenge");

    // Ensure the challenge directory exists (required for actix_files::Files)
    // Even when using Redis storage, challenge files are still written to filesystem for HTTP-01
    tokio::fs::create_dir_all(&challenge_static_path)
        .await
        .with_context(|| format!("Failed to create challenge static path directory: {:?}", challenge_static_path))?;

    let base_https_path = base_static_path.clone();
    let app_config_data = web::Data::new(app_config.clone());
    let base_path_data = web::Data::new(base_https_path);

    // Create HTTP server that only serves ACME challenge files
    // The server will serve from any domain's challenge directory
    let server = HttpServer::new(move || {
        App::new()
            .app_data(app_config_data.clone())
            .app_data(base_path_data.clone())
            .service(
                // Serve ACME challenges from the challenge directory
                // URL: /.well-known/acme-challenge/{token}
                // File: base_path/well-known/acme-challenge/{token}
                // The Files service maps the URL path to the file system path
                actix_files::Files::new("/.well-known/acme-challenge", challenge_static_path.clone())
                    .prefer_utf8(true),
            )
            .route(
                "/cert/expiration",
                web::get().to(check_all_certs_expiration_handler),
            )
            .route(
                "/cert/expiration/{domain}",
                web::get().to(check_cert_expiration_handler),
            )
            // Reject all other requests with 404
            .default_service(web::route().to(|| async {
                HttpResponse::NotFound().body("Not Found")
            }))
    })
    .bind(&address)
    .with_context(|| format!("Failed to bind HTTP server to {}", address))?;

    info!("HTTP server started successfully at {}", address);

    // Keep the server running indefinitely
    server.run().await
        .with_context(|| "HTTP server error")?;

    Ok(())
}
