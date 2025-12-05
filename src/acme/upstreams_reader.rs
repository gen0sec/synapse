//! Domain reader that reads domains from upstreams.yaml configuration

use anyhow::{Context, Result};
use crate::acme::domain_reader::{DomainConfig, DomainReader};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamsAcmeConfig {
    /// Challenge type: "http-01" or "dns-01"
    #[serde(default = "default_challenge_type")]
    pub challenge_type: String,
    /// Email for ACME account (optional, can be set globally)
    pub email: Option<String>,
    /// Whether this is a wildcard domain
    #[serde(default)]
    pub wildcard: bool,
}

fn default_challenge_type() -> String {
    "http-01".to_string()
}

/// Domain reader that reads from upstreams.yaml
pub struct UpstreamsDomainReader {
    upstreams_path: PathBuf,
    cached_domains: Arc<RwLock<Option<Vec<DomainConfig>>>>,
    /// Global email for ACME (from config)
    global_email: Option<String>,
}

impl UpstreamsDomainReader {
    pub fn new(upstreams_path: impl Into<PathBuf>, global_email: Option<String>) -> Self {
        Self {
            upstreams_path: upstreams_path.into(),
            cached_domains: Arc::new(RwLock::new(None)),
            global_email,
        }
    }

    async fn fetch_domains(&self) -> Result<Vec<DomainConfig>> {
        use serde_yaml;

        let mut domains = Vec::new();

        // Read and parse upstreams.yaml directly to get ACME config
        let yaml_content = tokio::fs::read_to_string(&self.upstreams_path).await
            .with_context(|| format!("Failed to read upstreams file: {:?}", self.upstreams_path))?;

        let parsed: crate::utils::structs::Config = serde_yaml::from_str(&yaml_content)
            .with_context(|| format!("Failed to parse upstreams YAML: {:?}", self.upstreams_path))?;

        if let Some(upstreams) = &parsed.upstreams {
            for (hostname, host_config) in upstreams {
                // Only include domains that need certificates
                if !host_config.needs_certificate() {
                    continue;
                }

                let is_wildcard = hostname.starts_with("*.");
                let acme_wildcard = host_config.acme.as_ref().map(|a| a.wildcard).unwrap_or(false);

                // Determine challenge type from ACME config or auto-detect
                let challenge_type = if let Some(acme_config) = &host_config.acme {
                    acme_config.challenge_type.clone()
                } else if is_wildcard {
                    "dns-01".to_string()
                } else {
                    "http-01".to_string()
                };

                // Determine email from ACME config or use global
                let email = if let Some(acme_config) = &host_config.acme {
                    acme_config.email.clone().or_else(|| self.global_email.clone())
                } else {
                    self.global_email.clone()
                };

                // Determine the domain to use for ACME request
                // If wildcard is true and certificate is specified, use *.{certificate}
                // Otherwise, use the hostname as-is
                let acme_domain = if acme_wildcard && !is_wildcard {
                    // Wildcard is set in config but hostname doesn't start with *.
                    // Use certificate domain if available, otherwise use hostname
                    if let Some(cert_domain) = &host_config.certificate {
                        format!("*.{}", cert_domain)
                    } else {
                        // Extract base domain from hostname (remove subdomain)
                        // For dev01.sub.example.com -> sub.example.com
                        let parts: Vec<&str> = hostname.split('.').collect();
                        if parts.len() >= 3 {
                            // Take last 2 parts as base domain
                            format!("*.{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
                        } else {
                            format!("*.{}", hostname)
                        }
                    }
                } else {
                    hostname.clone()
                };

                domains.push(DomainConfig {
                    domain: acme_domain,
                    email,
                    dns: challenge_type == "dns-01",
                    wildcard: is_wildcard || acme_wildcard,
                });
            }
        }

        Ok(domains)
    }
}

#[async_trait::async_trait]
impl DomainReader for UpstreamsDomainReader {
    async fn read_domains(&self) -> Result<Vec<DomainConfig>> {
        // Try cache first
        {
            let cache = self.cached_domains.read().await;
            if let Some(domains) = cache.as_ref() {
                return Ok(domains.clone());
            }
        }

        // Fetch fresh data
        let domains = self.fetch_domains().await?;

        // Update cache
        {
            let mut cache = self.cached_domains.write().await;
            *cache = Some(domains.clone());
        }

        Ok(domains)
    }
}

