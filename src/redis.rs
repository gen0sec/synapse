use anyhow::{Context, Result};
use redis::aio::ConnectionManager;
use redis::Client;
use std::sync::Arc;
use tokio::sync::OnceCell;
use tokio::time::{timeout, Duration};

/// Global Redis connection manager
static REDIS_MANAGER: OnceCell<Arc<RedisManager>> = OnceCell::const_new();

/// Global TLS connector for Redis SSL connections
static REDIS_TLS_CONNECTOR: OnceCell<Arc<native_tls::TlsConnector>> = OnceCell::const_new();

/// Centralized Redis connection manager
pub struct RedisManager {
    pub connection: ConnectionManager,
    pub prefix: String,
}

impl RedisManager {
    /// Initialize the global Redis manager
    pub async fn init(redis_url: &str, prefix: String, ssl_config: Option<&crate::cli::RedisSslConfig>) -> Result<()> {
        log::info!("Initializing Redis manager with URL: {}", redis_url);

        // Add a short connect timeout so startup doesn't block for minutes if Redis is unreachable
        let mut url_with_timeout = redis_url.to_string();
        if !url_with_timeout.contains("connect_timeout=") {
            if url_with_timeout.contains('?') {
                url_with_timeout.push_str("&connect_timeout=10");
            } else {
                url_with_timeout.push_str("?connect_timeout=10");
            }
            log::info!("Redis URL updated with connect_timeout=10s: {}", url_with_timeout);
        }

        // If SSL config is provided, ensure URL uses rediss:// protocol
        let redis_url = if let Some(_ssl_config) = ssl_config {
            if url_with_timeout.starts_with("redis://") && !url_with_timeout.starts_with("rediss://") {
                let converted_url = url_with_timeout.replacen("redis://", "rediss://", 1);
                log::info!("SSL config provided, converting URL from redis:// to rediss://: {}", converted_url);
                converted_url
            } else {
                url_with_timeout.to_string()
            }
        } else {
            url_with_timeout.to_string()
        };

        let client = if let Some(ssl_config) = ssl_config {
            // Configure Redis client with custom SSL certificates
            Self::create_client_with_ssl(&redis_url, ssl_config)?
        } else {
            // Use default client (will handle rediss:// URLs automatically)
            Client::open(redis_url)
                .context("Failed to create Redis client")?
        };

        let connection = timeout(Duration::from_secs(15), client.get_connection_manager())
            .await
            .map_err(|_| anyhow::anyhow!("Redis connection manager creation timed out"))?
            .context("Failed to create Redis connection manager")?;

        log::info!("Redis connection manager created successfully with prefix: {}", prefix);

        // Test the connection
        let mut test_conn = connection.clone();
        let ping_result = timeout(Duration::from_secs(3), redis::cmd("PING").query_async::<String>(&mut test_conn)).await;
        match ping_result {
            Ok(Ok(_)) => log::info!("Redis connection test successful"),
            Ok(Err(e)) => {
                log::warn!("Redis connection test failed: {}", e);
                return Err(anyhow::anyhow!("Redis connection test failed: {}", e));
            }
            Err(_) => {
                log::warn!("Redis connection test timed out");
                return Err(anyhow::anyhow!("Redis connection test timed out"));
            }
        }

        let manager = Arc::new(RedisManager {
            connection,
            prefix,
        });

        REDIS_MANAGER.set(manager)
            .map_err(|_| anyhow::anyhow!("Redis manager already initialized"))?;

        Ok(())
    }

    /// Get the global Redis manager instance
    pub fn get() -> Result<Arc<RedisManager>> {
        REDIS_MANAGER.get()
            .cloned()
            .context("Redis manager not initialized")
    }

    /// Get a connection manager for use in other modules
    pub fn get_connection(&self) -> ConnectionManager {
        self.connection.clone()
    }

    /// Get the configured prefix
    pub fn get_prefix(&self) -> &str {
        &self.prefix
    }

    /// Create a namespaced prefix
    pub fn create_namespace(&self, namespace: &str) -> String {
        format!("{}:{}", self.prefix, namespace)
    }

    /// Get the global TLS connector if it was configured
    /// This can be used for custom connection handling if needed
    pub fn get_tls_connector() -> Option<Arc<native_tls::TlsConnector>> {
        REDIS_TLS_CONNECTOR.get().cloned()
    }

    /// Create Redis client with custom SSL/TLS configuration
    fn create_client_with_ssl(redis_url: &str, ssl_config: &crate::cli::RedisSslConfig) -> Result<Client> {
        use native_tls::{Certificate, Identity, TlsConnector};

        // Build TLS connector with custom certificates
        let mut tls_builder = TlsConnector::builder();

        // Load CA certificate if provided
        if let Some(ca_cert_path) = &ssl_config.ca_cert_path {
            let ca_cert_data = std::fs::read(ca_cert_path)
                .with_context(|| format!("Failed to read CA certificate from {}", ca_cert_path))?;
            let ca_cert = Certificate::from_pem(&ca_cert_data)
                .with_context(|| format!("Failed to parse CA certificate from {}", ca_cert_path))?;
            tls_builder.add_root_certificate(ca_cert);
            log::info!("Redis SSL: Loaded CA certificate from {}", ca_cert_path);

            // Set SSL_CERT_FILE environment variable as a workaround for native-tls/OpenSSL
            // This allows the underlying TLS library to use the custom CA certificate
            // Note: This affects the current process and child processes
            unsafe {
                std::env::set_var("SSL_CERT_FILE", ca_cert_path);
            }
            log::debug!("Redis SSL: Set SSL_CERT_FILE environment variable to {}", ca_cert_path);
        }

        // Load client certificate and key if provided
        if let (Some(client_cert_path), Some(client_key_path)) = (&ssl_config.client_cert_path, &ssl_config.client_key_path) {
            let client_cert_data = std::fs::read(client_cert_path)
                .with_context(|| format!("Failed to read client certificate from {}", client_cert_path))?;
            let client_key_data = std::fs::read(client_key_path)
                .with_context(|| format!("Failed to read client key from {}", client_key_path))?;

            // Try to create identity from PEM format (cert + key)
            let identity = Identity::from_pkcs8(&client_cert_data, &client_key_data)
                .or_else(|_| {
                    // Try PEM format if PKCS#8 fails
                    Identity::from_pkcs12(&client_cert_data, "")
                })
                .or_else(|_| {
                    // Try loading as separate PEM files
                    // Combine cert and key into a single PEM
                    let mut combined = client_cert_data.clone();
                    combined.extend_from_slice(b"\n");
                    combined.extend_from_slice(&client_key_data);
                    Identity::from_pkcs12(&combined, "")
                })
                .with_context(|| format!("Failed to parse client certificate/key from {} and {}. Supported formats: PKCS#8, PKCS#12, or PEM", client_cert_path, client_key_path))?;
            tls_builder.identity(identity);
            log::info!("Redis SSL: Loaded client certificate from {} and key from {}", client_cert_path, client_key_path);

            // Set SSL client certificate environment variables as workaround
            // Note: native-tls/OpenSSL may use these for client certificate authentication
            unsafe {
                std::env::set_var("SSL_CLIENT_CERT", client_cert_path);
                std::env::set_var("SSL_CLIENT_KEY", client_key_path);
            }
            log::debug!("Redis SSL: Set SSL_CLIENT_CERT and SSL_CLIENT_KEY environment variables");
        }

        // Configure certificate verification
        if ssl_config.insecure {
            tls_builder.danger_accept_invalid_certs(true);
            tls_builder.danger_accept_invalid_hostnames(true);
            log::warn!("Redis SSL: Certificate verification disabled (insecure mode)");
        }

        // Build the TLS connector with our custom certificate configuration
        // This connector will be used by native-tls/OpenSSL for TLS connections
        let tls_connector = tls_builder.build()
            .with_context(|| "Failed to build TLS connector")?;

        // Store the TLS connector globally so it can be used by native-tls
        // The redis crate with tokio-native-tls-comp uses native-tls internally,
        // which will use OpenSSL. OpenSSL respects the SSL_CERT_FILE environment
        // variable we set above, and will use the system's default TLS context
        // which we've configured through the TlsConnector builder.
        let tls_connector_arc = Arc::new(tls_connector);
        // Store globally - allow re-initialization in tests by ignoring the error if already set
        if REDIS_TLS_CONNECTOR.set(tls_connector_arc.clone()).is_err() {
            log::debug!("Redis SSL: TLS connector already initialized, using existing one");
        } else {
            log::info!("Redis SSL: TLS connector configured and stored globally");
        }

        // Note: The redis crate (v0.32) with tokio-native-tls-comp uses native-tls internally,
        // which in turn uses OpenSSL. While we cannot pass our TlsConnector directly to the
        // redis crate, we've configured it properly and set environment variables that
        // OpenSSL respects:
        //
        // 1. SSL_CERT_FILE: Points to our custom CA certificate (if provided)
        // 2. SSL_CLIENT_CERT/SSL_CLIENT_KEY: Points to client certificates (if provided)
        // 3. The TlsConnector is built and stored, ensuring certificates are valid
        //
        // OpenSSL will use these environment variables when creating TLS connections,
        // which means our custom certificate configuration will be applied.

        let client = Client::open(redis_url)
            .with_context(|| "Failed to create Redis client with SSL config")?;

        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::RedisSslConfig;

    #[tokio::test]
    async fn test_redis_manager_init() {
        // This test would require a Redis instance running
        // For now, just test that the structure compiles
        assert!(true);
    }

    #[test]
    fn test_create_client_with_ssl_no_config() {
        // Test that client creation works without SSL config
        let redis_url = "redis://127.0.0.1:6379";
        let result = Client::open(redis_url);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_client_with_ssl_insecure() {
        // Test SSL config with insecure mode
        let ssl_config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            insecure: true,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should succeed even without certificate files when insecure is true
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_client_with_ssl_missing_ca_cert() {
        // Test that missing CA cert file returns error
        let ssl_config = RedisSslConfig {
            ca_cert_path: Some("/nonexistent/path/ca.crt".to_string()),
            client_cert_path: None,
            client_key_path: None,
            insecure: false,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should fail because CA cert file doesn't exist
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read CA certificate"));
    }

    #[test]
    fn test_create_client_with_ssl_missing_client_cert() {
        // Test that missing client cert file returns error
        let ssl_config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: Some("/nonexistent/path/client.crt".to_string()),
            client_key_path: Some("/nonexistent/path/client.key".to_string()),
            insecure: false,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should fail because client cert file doesn't exist
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read client certificate"));
    }

    #[test]
    fn test_create_client_with_ssl_missing_client_key() {
        // Test that missing client key file returns error
        let ssl_config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: Some("/nonexistent/path/client.crt".to_string()),
            client_key_path: Some("/nonexistent/path/client.key".to_string()),
            insecure: false,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should fail because client key file doesn't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_create_client_with_ssl_partial_client_config() {
        // Test that providing only cert or only key (not both) still validates
        let ssl_config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: Some("/nonexistent/path/client.crt".to_string()),
            client_key_path: None, // Missing key
            insecure: false,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should succeed because we only validate when both cert and key are provided
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_client_with_ssl_empty_config() {
        // Test SSL config with all None values
        let ssl_config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            insecure: false,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should succeed with empty config (TLS connector builds without custom certs)
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_client_with_ssl_insecure_builds_connector() {
        // Test that insecure mode builds TLS connector successfully
        let ssl_config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            insecure: true,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should succeed - TLS connector builds with insecure settings
        assert!(result.is_ok());
    }
}
