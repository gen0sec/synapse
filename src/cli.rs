use std::{path::PathBuf, env};

use anyhow::Result;
use clap::Parser;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::waf::actions::captcha::CaptchaProvider;

/// TLS operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// TLS is disabled
    Disabled,
}

/// Application operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AppMode {
    /// Agent mode: Only access rules and monitoring (no proxy)
    Agent,
    /// Proxy mode: Full reverse proxy functionality
    Proxy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_mode")]
    pub mode: String,

    // Global server options (moved from server section)
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub arxignis: Gen0SecConfig,
    #[serde(default)]
    pub content_scanning: ContentScanningCliConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub bpf_stats: BpfStatsConfig,
    #[serde(default)]
    pub tcp_fingerprint: TcpFingerprintConfig,
    #[serde(default)]
    pub file_monitor: FileMonitorConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub pingora: PingoraConfig,
    #[serde(default)]
    pub acme: AcmeConfig,
}

fn default_mode() -> String { "proxy".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyProtocolConfig {
    #[serde(default = "default_proxy_protocol_enabled")]
    pub enabled: bool,
    #[serde(default = "default_proxy_protocol_timeout")]
    pub timeout_ms: u64,
}

fn default_proxy_protocol_enabled() -> bool { false }
fn default_proxy_protocol_timeout() -> u64 { 1000 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HealthCheckConfig {
    #[serde(default = "default_health_check_enabled")]
    pub enabled: bool,
    #[serde(default = "default_health_check_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_health_check_port")]
    pub port: String,
    #[serde(default = "default_health_check_methods")]
    pub methods: Vec<String>,
    #[serde(default = "default_health_check_allowed_cidrs")]
    pub allowed_cidrs: Vec<String>,
}

fn default_health_check_enabled() -> bool { true }
fn default_health_check_endpoint() -> String { "/health".to_string() }
fn default_health_check_port() -> String { "0.0.0.0:8080".to_string() }
fn default_health_check_methods() -> Vec<String> { vec!["GET".to_string(), "HEAD".to_string()] }
fn default_health_check_allowed_cidrs() -> Vec<String> { vec![] }


#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RedisConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub prefix: String,
    /// Redis SSL/TLS configuration
    #[serde(default)]
    pub ssl: Option<RedisSslConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisSslConfig {
    /// Path to CA certificate file (PEM format)
    pub ca_cert_path: Option<String>,
    /// Path to client certificate file (PEM format, optional)
    pub client_cert_path: Option<String>,
    /// Path to client private key file (PEM format, optional)
    pub client_key_path: Option<String>,
    /// Skip certificate verification (for testing with self-signed certs)
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    #[serde(default)]
    pub iface: String,
    #[serde(default)]
    pub ifaces: Vec<String>,
    #[serde(default)]
    pub disable_xdp: bool,
    /// IP version support mode: "ipv4", "ipv6", or "both" (default: "both")
    /// Note: XDP requires IPv6 to be enabled at kernel level for attachment,
    /// even in IPv4-only mode. Set to "ipv4" to skip XDP if IPv6 cannot be enabled.
    #[serde(default = "default_ip_version")]
    pub ip_version: String,
}

fn default_ip_version() -> String {
    "both".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Gen0SecConfig {
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_log_sending_enabled")]
    pub log_sending_enabled: bool,
    #[serde(default = "default_include_response_body")]
    pub include_response_body: bool,
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    #[serde(default)]
    pub captcha: CaptchaConfig,
}

fn default_base_url() -> String {
    "https://api.gen0sec.com/v1".to_string()
}

fn default_log_sending_enabled() -> bool {
    true
}

fn default_include_response_body() -> bool {
    true
}

fn default_max_body_size() -> usize {
    1024 * 1024 // 1MB
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContentScanningCliConfig {
    #[serde(default = "default_scanning_enabled")]
    pub enabled: bool,
    #[serde(default = "default_clamav_server")]
    pub clamav_server: String,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize,
    #[serde(default)]
    pub scan_content_types: Vec<String>,
    #[serde(default)]
    pub skip_extensions: Vec<String>,
    #[serde(default = "default_scan_expression")]
    pub scan_expression: String,
}

fn default_scanning_enabled() -> bool { false }
fn default_clamav_server() -> String { "localhost:3310".to_string() }
fn default_max_file_size() -> usize { 10 * 1024 * 1024 }
fn default_scan_expression() -> String { "http.request.method eq \"POST\" or http.request.method eq \"PUT\"".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoggingConfig {
    #[serde(default)]
    pub level: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct FileMonitorConfig {
    /// Turn file integrity monitor on/off
    #[serde(default)]
    pub enabled: bool,

    /// Directories to watch for changes
    #[serde(default)]
    pub paths: Vec<String>,

    /// Whether to watch subdirectories too
    #[serde(default = "default_recursive")]
    pub recursive: bool,

    /// Path to rsure store file (baseline hashes)
    /// e.g. /var/lib/gen0sec/file_integrity.rsure
    #[serde(default)]
    pub rsure_store_path: Option<String>,
}

fn default_recursive() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaptchaConfig {
    #[serde(default)]
    pub site_key: Option<String>,
    #[serde(default)]
    pub secret_key: Option<String>,
    #[serde(default)]
    pub jwt_secret: Option<String>,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub token_ttl: u64,
    #[serde(default)]
    pub cache_ttl: u64,
}

impl Config {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Self {
            mode: "proxy".to_string(),
            redis: RedisConfig {
                url: "redis://127.0.0.1/0".to_string(),
                prefix: "ax:synapse".to_string(),
                ssl: None,
            },
            network: NetworkConfig {
                iface: "eth0".to_string(),
                ifaces: vec![],
                disable_xdp: false,
                ip_version: "both".to_string(),
            },
            arxignis: Gen0SecConfig {
                api_key: "".to_string(),
                base_url: "https://api.gen0sec.com/v1".to_string(),
                log_sending_enabled: true,
                include_response_body: true,
                max_body_size: 1024 * 1024, // 1MB
                captcha: CaptchaConfig {
                    site_key: None,
                    secret_key: None,
                    jwt_secret: None,
                    provider: "hcaptcha".to_string(),
                    token_ttl: 7200,
                    cache_ttl: 300,
                },
            },
            content_scanning: ContentScanningCliConfig {
                enabled: false,
                clamav_server: "localhost:3310".to_string(),
                max_file_size: 10 * 1024 * 1024,
                scan_content_types: vec![
                    "text/html".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                    "multipart/form-data".to_string(),
                    "application/json".to_string(),
                    "text/plain".to_string(),
                ],
                skip_extensions: vec![],
                scan_expression: default_scan_expression(),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
            },
            bpf_stats: BpfStatsConfig::default(),
            tcp_fingerprint: TcpFingerprintConfig::default(),
            file_monitor: FileMonitorConfig::default(),
            daemon: DaemonConfig::default(),
            pingora: PingoraConfig::default(),
            acme: AcmeConfig::default(),
        }
    }

    pub fn merge_with_args(&mut self, args: &Args) {
        // Override config values with command line arguments if provided

        if !args.ifaces.is_empty() {
            self.network.ifaces = args.ifaces.clone();
        }
        if let Some(api_key) = &args.arxignis_api_key {
            self.arxignis.api_key = api_key.clone();
        }
        if !args.arxignis_base_url.is_empty() && args.arxignis_base_url != "https://api.gen0sec.com/v1" {
            self.arxignis.base_url = args.arxignis_base_url.clone();
        }
        if let Some(log_sending_enabled) = args.arxignis_log_sending_enabled {
            self.arxignis.log_sending_enabled = log_sending_enabled;
        }
        self.arxignis.include_response_body = args.arxignis_include_response_body;
        self.arxignis.max_body_size = args.arxignis_max_body_size;
        if args.captcha_site_key.is_some() {
            self.arxignis.captcha.site_key = args.captcha_site_key.clone();
        }
        if args.captcha_secret_key.is_some() {
            self.arxignis.captcha.secret_key = args.captcha_secret_key.clone();
        }
        if args.captcha_jwt_secret.is_some() {
            self.arxignis.captcha.jwt_secret = args.captcha_jwt_secret.clone();
        }
        if let Some(provider) = &args.captcha_provider {
            self.arxignis.captcha.provider = format!("{:?}", provider).to_lowercase();
        }

        // Proxy protocol configuration overrides
        // if args.proxy_protocol_enabled {
        //     self.proxy_protocol.enabled = true;
        // }
        // if args.proxy_protocol_timeout != 1000 {
        //     self.proxy_protocol.timeout_ms = args.proxy_protocol_timeout;
        // }

        // Daemon configuration overrides
        if args.daemon {
            self.daemon.enabled = true;
        }
        if args.daemon_pid_file != "/var/run/synapse.pid" {
            self.daemon.pid_file = args.daemon_pid_file.clone();
        }
        if args.daemon_working_dir != "/" {
            self.daemon.working_directory = args.daemon_working_dir.clone();
        }
        if args.daemon_stdout != "/var/log/synapse.out" {
            self.daemon.stdout = args.daemon_stdout.clone();
        }
        if args.daemon_stderr != "/var/log/synapse.err" {
            self.daemon.stderr = args.daemon_stderr.clone();
        }
        if args.daemon_user.is_some() {
            self.daemon.user = args.daemon_user.clone();
        }
        if args.daemon_group.is_some() {
            self.daemon.group = args.daemon_group.clone();
        }

        // Redis configuration overrides
        if !args.redis_url.is_empty() && args.redis_url != "redis://127.0.0.1/0" {
            self.redis.url = args.redis_url.clone();
        }
        if !args.redis_prefix.is_empty() && args.redis_prefix != "ax:synapse" {
            self.redis.prefix = args.redis_prefix.clone();
        }

        if !args.file_monitor_paths.is_empty() {
            self.file_monitor.enabled = true;
            self.file_monitor.paths.extend(args.file_monitor_paths.clone());
        }
    }

    pub fn validate_required_fields(&mut self, args: &Args) -> Result<()> {
        // Check if arxignis API key is provided - only warn if not provided
        // (to support old config format that doesn't have this field)
        if args.arxignis_api_key.is_none() && self.arxignis.api_key.is_empty() {
            log::warn!("Gen0Sec API key not provided. Some features may not work.");
        }

        Ok(())
    }

    pub fn load_from_args(args: &Args) -> Result<Self> {
        let mut config = if let Some(config_path) = &args.config {
            Self::load_from_file(config_path)?
        } else {
            Self::default()
        };

        config.merge_with_args(args);
        config.apply_env_overrides();
        config.validate_required_fields(args)?;
        Ok(config)
    }

    pub fn apply_env_overrides(&mut self) {
        // Mode override
        if let Ok(val) = env::var("AX_MODE") {
            self.mode = val;
        }

        // Redis configuration overrides
        if let Ok(val) = env::var("AX_REDIS_URL") {
            self.redis.url = val;
        }
        if let Ok(val) = env::var("AX_REDIS_PREFIX") {
            self.redis.prefix = val;
        }

        // Redis SSL configuration overrides
        // Read all SSL environment variables once
        let ca_cert_path = env::var("AX_REDIS_SSL_CA_CERT_PATH").ok();
        let client_cert_path = env::var("AX_REDIS_SSL_CLIENT_CERT_PATH").ok();
        let client_key_path = env::var("AX_REDIS_SSL_CLIENT_KEY_PATH").ok();
        let insecure_val = env::var("AX_REDIS_SSL_INSECURE").ok();

        // If any SSL env var is set, ensure SSL config exists
        if ca_cert_path.is_some()
            || client_cert_path.is_some()
            || client_key_path.is_some()
            || insecure_val.is_some() {

            // Create SSL config if it doesn't exist
            if self.redis.ssl.is_none() {
                // Parse insecure value if provided, default to false
                let insecure_default = insecure_val
                    .as_ref()
                    .and_then(|v| v.parse::<bool>().ok())
                    .unwrap_or(false);

                self.redis.ssl = Some(RedisSslConfig {
                    ca_cert_path: None,
                    client_cert_path: None,
                    client_key_path: None,
                    insecure: insecure_default,
                });
            }

            // Update the SSL config with values from environment variables
            let ssl = self.redis.ssl.as_mut().expect("SSL config should exist here");
            if let Some(val) = ca_cert_path {
                ssl.ca_cert_path = Some(val);
            }
            if let Some(val) = client_cert_path {
                ssl.client_cert_path = Some(val);
            }
            if let Some(val) = client_key_path {
                ssl.client_key_path = Some(val);
            }
            if let Some(val) = insecure_val {
                if let Ok(insecure) = val.parse::<bool>() {
                    ssl.insecure = insecure;
                }
            }
        }

        // Network configuration overrides
        if let Ok(val) = env::var("AX_NETWORK_IFACE") {
            self.network.iface = val;
        }
        if let Ok(val) = env::var("AX_NETWORK_IFACES") {
            self.network.ifaces = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = env::var("AX_NETWORK_DISABLE_XDP") {
            self.network.disable_xdp = val.parse().unwrap_or(false);
        }
        if let Ok(val) = env::var("AX_NETWORK_IP_VERSION") {
            // Validate ip_version value
            match val.as_str() {
                "ipv4" | "ipv6" | "both" => {
                    self.network.ip_version = val;
                }
                _ => {
                    log::warn!("Invalid AX_NETWORK_IP_VERSION value '{}', using default 'both'. Valid values: ipv4, ipv6, both", val);
                }
            }
        }

        // Gen0Sec configuration overrides
        if let Ok(val) = env::var("AX_ARXIGNIS_API_KEY") {
            self.arxignis.api_key = val;
        }
        if let Ok(val) = env::var("AX_ARXIGNIS_BASE_URL") {
            self.arxignis.base_url = val;
        }
        if let Ok(val) = env::var("AX_ARXIGNIS_LOG_SENDING_ENABLED") {
            if let Ok(parsed) = val.parse::<bool>() {
                self.arxignis.log_sending_enabled = parsed;
            }
        }
        if let Ok(val) = env::var("AX_ARXIGNIS_INCLUDE_RESPONSE_BODY") {
            self.arxignis.include_response_body = val.parse().unwrap_or(true);
        }
        if let Ok(val) = env::var("AX_ARXIGNIS_MAX_BODY_SIZE") {
            self.arxignis.max_body_size = val.parse().unwrap_or(1024 * 1024);
        }

        // Logging configuration overrides
        if let Ok(val) = env::var("AX_LOGGING_LEVEL") {
            self.logging.level = val;
        }

        // Content scanning overrides
        if let Ok(val) = env::var("AX_CONTENT_SCANNING_ENABLED") {
            self.content_scanning.enabled = val.parse().unwrap_or(false);
        }
        if let Ok(val) = env::var("AX_CLAMAV_SERVER") {
            self.content_scanning.clamav_server = val;
        }
        if let Ok(val) = env::var("AX_CONTENT_MAX_FILE_SIZE") {
            self.content_scanning.max_file_size = val.parse().unwrap_or(10 * 1024 * 1024);
        }
        if let Ok(val) = env::var("AX_CONTENT_SCAN_CONTENT_TYPES") {
            self.content_scanning.scan_content_types = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = env::var("AX_CONTENT_SKIP_EXTENSIONS") {
            self.content_scanning.skip_extensions = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = env::var("AX_CONTENT_SCAN_EXPRESSION") {
            self.content_scanning.scan_expression = val;
        }

        // Captcha configuration overrides
        if let Ok(val) = env::var("AX_CAPTCHA_SITE_KEY") {
            self.arxignis.captcha.site_key = Some(val);
        }
        if let Ok(val) = env::var("AX_CAPTCHA_SECRET_KEY") {
            self.arxignis.captcha.secret_key = Some(val);
        }
        if let Ok(val) = env::var("AX_CAPTCHA_JWT_SECRET") {
            self.arxignis.captcha.jwt_secret = Some(val);
        }
        if let Ok(val) = env::var("AX_CAPTCHA_PROVIDER") {
            self.arxignis.captcha.provider = val;
        }
        if let Ok(val) = env::var("AX_CAPTCHA_TOKEN_TTL") {
            self.arxignis.captcha.token_ttl = val.parse().unwrap_or(7200);
        }
        if let Ok(val) = env::var("AX_CAPTCHA_CACHE_TTL") {
            self.arxignis.captcha.cache_ttl = val.parse().unwrap_or(300);
        }

        // Proxy protocol configuration overrides
        // if let Ok(val) = env::var("AX_PROXY_PROTOCOL_ENABLED") {
        //     self.proxy_protocol.enabled = val.parse().unwrap_or(false);
        // }
        // if let Ok(val) = env::var("AX_PROXY_PROTOCOL_TIMEOUT") {
        //     self.proxy_protocol.timeout_ms = val.parse().unwrap_or(1000);
        // }

        // Daemon configuration overrides
        if let Ok(val) = env::var("AX_DAEMON_ENABLED") {
            self.daemon.enabled = val.parse().unwrap_or(false);
        }
        if let Ok(val) = env::var("AX_DAEMON_PID_FILE") {
            self.daemon.pid_file = val;
        }
        if let Ok(val) = env::var("AX_DAEMON_WORKING_DIRECTORY") {
            self.daemon.working_directory = val;
        }
        if let Ok(val) = env::var("AX_DAEMON_STDOUT") {
            self.daemon.stdout = val;
        }
        if let Ok(val) = env::var("AX_DAEMON_STDERR") {
            self.daemon.stderr = val;
        }
        if let Ok(val) = env::var("AX_DAEMON_USER") {
            self.daemon.user = Some(val);
        }
        if let Ok(val) = env::var("AX_DAEMON_GROUP") {
            self.daemon.group = Some(val);
        }
        if let Ok(val) = env::var("AX_DAEMON_CHOWN_PID_FILE") {
            self.daemon.chown_pid_file = val.parse().unwrap_or(true);
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to configuration file (YAML format)
    #[arg(long, short = 'c')]
    pub config: Option<PathBuf>,

     /// Redis connection URL for ACME cache storage.
    #[arg(long, default_value = "redis://127.0.0.1/0")]
    pub redis_url: String,

    /// Namespace prefix for Redis ACME cache entries.
    #[arg(long, default_value = "ax:synapse")]
    pub redis_prefix: String,

    /// The network interface to attach the XDP program to.
    #[arg(short, long, default_value = "eth0")]
    pub iface: String,

    /// Additional network interfaces for XDP attach (comma-separated). If set, overrides --iface.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub ifaces: Vec<String>,

    #[arg(long)]
    pub arxignis_api_key: Option<String>,

    /// Base URL for Gen0Sec API.
    #[arg(long, default_value = "https://api.gen0sec.com/v1")]
    pub arxignis_base_url: String,

    /// Enable sending access logs to arxignis server
    #[arg(long)]
    pub arxignis_log_sending_enabled: Option<bool>,

    /// Include response body in access logs
    #[arg(long, default_value_t = true)]
    pub arxignis_include_response_body: bool,

    /// Maximum size for request/response bodies in access logs (bytes)
    #[arg(long, default_value = "1048576")]
    pub arxignis_max_body_size: usize,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Disable XDP packet filtering (run without BPF/XDP)
    #[arg(long, default_value_t = false)]
    pub disable_xdp: bool,

    /// Captcha site key for security verification
    #[arg(long)]
    pub captcha_site_key: Option<String>,

    /// Captcha secret key for security verification
    #[arg(long)]
    pub captcha_secret_key: Option<String>,

    /// JWT secret key for captcha token signing
    #[arg(long)]
    pub captcha_jwt_secret: Option<String>,

    /// Captcha provider (hcaptcha, recaptcha, turnstile)
    #[arg(long, value_enum)]
    pub captcha_provider: Option<CaptchaProvider>,


    /// Captcha token TTL in seconds
    #[arg(long, default_value = "7200")]
    pub captcha_token_ttl: u64,

    /// Captcha validation cache TTL in seconds
    #[arg(long, default_value = "300")]
    pub captcha_cache_ttl: u64,

    /// Extra directories to monitor for file integrity (comma or multi-use)
    #[arg(long = "file-monitor-path", value_delimiter = ',')]
    pub file_monitor_paths: Vec<String>,

    /// Enable PROXY protocol support for TCP connections
    #[arg(long, default_value_t = false)]
    pub proxy_protocol_enabled: bool,

    /// PROXY protocol timeout in milliseconds
    #[arg(long, default_value = "1000")]
    pub proxy_protocol_timeout: u64,

    /// Run as daemon in background
    #[arg(long, short = 'd', default_value_t = false)]
    pub daemon: bool,

    /// PID file path for daemon mode
    #[arg(long, default_value = "/var/run/synapse.pid")]
    pub daemon_pid_file: String,

    /// Working directory for daemon mode
    #[arg(long, default_value = "/")]
    pub daemon_working_dir: String,

    /// Stdout log file for daemon mode
    #[arg(long, default_value = "/var/log/synapse.out")]
    pub daemon_stdout: String,

    /// Stderr log file for daemon mode
    #[arg(long, default_value = "/var/log/synapse.err")]
    pub daemon_stderr: String,

    /// User to run daemon as
    #[arg(long)]
    pub daemon_user: Option<String>,

    /// Group to run daemon as
    #[arg(long)]
    pub daemon_group: Option<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn to_level_filter(self) -> log::LevelFilter {
        match self {
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Trace => log::LevelFilter::Trace,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BpfStatsConfig {
    #[serde(default = "default_bpf_stats_enabled")]
    pub enabled: bool,
    #[serde(default = "default_bpf_stats_log_interval")]
    pub log_interval_secs: u64,
    #[serde(default = "default_bpf_stats_enable_dropped_ip_events")]
    pub enable_dropped_ip_events: bool,
    #[serde(default = "default_bpf_stats_dropped_ip_events_interval")]
    pub dropped_ip_events_interval_secs: u64,
}

fn default_bpf_stats_enabled() -> bool { true }
fn default_bpf_stats_log_interval() -> u64 { 60 }
fn default_bpf_stats_enable_dropped_ip_events() -> bool { true }
fn default_bpf_stats_dropped_ip_events_interval() -> u64 { 30 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TcpFingerprintConfig {
    #[serde(default = "default_tcp_fingerprint_enabled")]
    pub enabled: bool,
    #[serde(default = "default_tcp_fingerprint_log_interval")]
    pub log_interval_secs: u64,
    #[serde(default = "default_tcp_fingerprint_enable_fingerprint_events")]
    pub enable_fingerprint_events: bool,
    #[serde(default = "default_tcp_fingerprint_events_interval")]
    pub fingerprint_events_interval_secs: u64,
    #[serde(default = "default_tcp_fingerprint_min_packet_count")]
    pub min_packet_count: u32,
    #[serde(default = "default_tcp_fingerprint_min_connection_duration")]
    pub min_connection_duration_secs: u64,
}

fn default_tcp_fingerprint_enabled() -> bool { true }
fn default_tcp_fingerprint_log_interval() -> u64 { 60 }
fn default_tcp_fingerprint_enable_fingerprint_events() -> bool { true }
fn default_tcp_fingerprint_events_interval() -> u64 { 30 }
fn default_tcp_fingerprint_min_packet_count() -> u32 { 3 }
fn default_tcp_fingerprint_min_connection_duration() -> u64 { 1 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DaemonConfig {
    #[serde(default = "default_daemon_enabled")]
    pub enabled: bool,
    #[serde(default = "default_daemon_pid_file")]
    pub pid_file: String,
    #[serde(default = "default_daemon_working_directory")]
    pub working_directory: String,
    #[serde(default = "default_daemon_stdout")]
    pub stdout: String,
    #[serde(default = "default_daemon_stderr")]
    pub stderr: String,
    pub user: Option<String>,
    pub group: Option<String>,
    #[serde(default = "default_daemon_chown_pid_file")]
    pub chown_pid_file: bool,
}

fn default_daemon_enabled() -> bool { false }
fn default_daemon_pid_file() -> String { "/var/run/synapse.pid".to_string() }
fn default_daemon_working_directory() -> String { "/".to_string() }
fn default_daemon_stdout() -> String { "/var/log/synapse.out".to_string() }
fn default_daemon_stderr() -> String { "/var/log/synapse.err".to_string() }
fn default_daemon_chown_pid_file() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PingoraConfig {
    #[serde(default)]
    pub proxy_address_http: String,
    #[serde(default)]
    pub proxy_address_tls: Option<String>,
    #[serde(default)]
    pub proxy_certificates: Option<String>,
    #[serde(default = "default_pingora_tls_grade")]
    pub proxy_tls_grade: String,
    #[serde(default)]
    pub default_certificate: Option<String>,
    #[serde(default)]
    pub upstreams_conf: String,
    #[serde(default)]
    pub config_address: String,
    #[serde(default = "default_pingora_config_api_enabled")]
    pub config_api_enabled: bool,
    #[serde(default)]
    pub master_key: String,
    #[serde(default = "default_pingora_log_level")]
    pub log_level: String,
    #[serde(default = "default_pingora_healthcheck_method")]
    pub healthcheck_method: String,
    #[serde(default = "default_pingora_healthcheck_interval")]
    pub healthcheck_interval: u16,
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolConfig,
}

fn default_pingora_tls_grade() -> String { "medium".to_string() }
fn default_pingora_config_api_enabled() -> bool { true }
fn default_pingora_log_level() -> String { "debug".to_string() }
fn default_pingora_healthcheck_method() -> String { "HEAD".to_string() }
fn default_pingora_healthcheck_interval() -> u16 { 2 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Enable embedded ACME server
    #[serde(default = "default_acme_enabled")]
    pub enabled: bool,
    /// Port for ACME server (e.g., 9180)
    #[serde(default = "default_acme_port")]
    pub port: u16,
    /// Email for ACME account
    pub email: Option<String>,
    /// Storage path for certificates
    #[serde(default = "default_acme_storage_path")]
    pub storage_path: String,
    /// Storage type: "file" or "redis" (defaults to "file", or "redis" if redis_url is set)
    pub storage_type: Option<String>,
    /// Use development/staging ACME server
    #[serde(default)]
    pub development: bool,
    /// Redis URL for storage (optional, uses global redis.url if not set)
    pub redis_url: Option<String>,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: default_acme_enabled(),
            port: default_acme_port(),
            email: None,
            storage_path: default_acme_storage_path(),
            storage_type: None,
            development: false,
            redis_url: None,
        }
    }
}

fn default_acme_enabled() -> bool { false }
fn default_acme_port() -> u16 { 9180 }
fn default_acme_storage_path() -> String { "/tmp/synapse-acme".to_string() }

impl PingoraConfig {
    /// Convert PingoraConfig to AppConfig for compatibility with old proxy system
    pub fn to_app_config(&self) -> crate::utils::structs::AppConfig {
        let mut app_config = crate::utils::structs::AppConfig::default();
        app_config.proxy_address_http = self.proxy_address_http.clone();
        app_config.proxy_address_tls = self.proxy_address_tls.clone();
        app_config.proxy_certificates = self.proxy_certificates.clone();
        app_config.proxy_tls_grade = Some(self.proxy_tls_grade.clone());
        app_config.default_certificate = self.default_certificate.clone();
        app_config.upstreams_conf = self.upstreams_conf.clone();
        app_config.config_address = self.config_address.clone();
        app_config.config_api_enabled = self.config_api_enabled;
        app_config.master_key = self.master_key.clone();
        app_config.healthcheck_method = self.healthcheck_method.clone();
        app_config.healthcheck_interval = self.healthcheck_interval;
        app_config.proxy_protocol_enabled = self.proxy_protocol.enabled;

        // Parse config_address to local_server
        if let Some((ip, port_str)) = self.config_address.split_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                app_config.local_server = Some((ip.to_string(), port));
            }
        }

        // Parse proxy_address_tls to proxy_port_tls
        if let Some(ref tls_addr) = self.proxy_address_tls {
            if let Some((_, port_str)) = tls_addr.split_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    app_config.proxy_port_tls = Some(port);
                }
            }
        }

        app_config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use serial_test::serial;

    #[test]
    fn test_redis_ssl_config_deserialize() {
        let yaml = r#"
ca_cert_path: "/path/to/ca.crt"
client_cert_path: "/path/to/client.crt"
client_key_path: "/path/to/client.key"
insecure: true
"#;
        let config: RedisSslConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.ca_cert_path, Some("/path/to/ca.crt".to_string()));
        assert_eq!(config.client_cert_path, Some("/path/to/client.crt".to_string()));
        assert_eq!(config.client_key_path, Some("/path/to/client.key".to_string()));
        assert!(config.insecure);
    }

    #[test]
    fn test_redis_ssl_config_deserialize_minimal() {
        let yaml = r#"
insecure: false
"#;
        let config: RedisSslConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.ca_cert_path, None);
        assert_eq!(config.client_cert_path, None);
        assert_eq!(config.client_key_path, None);
        assert!(!config.insecure);
    }

    #[test]
    fn test_redis_config_with_ssl() {
        let yaml = r#"
url: "rediss://localhost:6379"
prefix: "test:prefix"
ssl:
  ca_cert_path: "/path/to/ca.crt"
  insecure: false
"#;
        let config: RedisConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.url, "rediss://localhost:6379");
        assert_eq!(config.prefix, "test:prefix");
        assert!(config.ssl.is_some());
        let ssl = config.ssl.unwrap();
        assert_eq!(ssl.ca_cert_path, Some("/path/to/ca.crt".to_string()));
        assert!(!ssl.insecure);
    }

    #[test]
    fn test_redis_config_without_ssl() {
        let yaml = r#"
url: "redis://localhost:6379"
prefix: "test:prefix"
"#;
        let config: RedisConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.url, "redis://localhost:6379");
        assert_eq!(config.prefix, "test:prefix");
        assert!(config.ssl.is_none());
    }

    #[test]
    fn test_redis_config_default() {
        let config = RedisConfig::default();
        assert_eq!(config.url, "");
        assert_eq!(config.prefix, "");
        assert!(config.ssl.is_none());
    }

    // Helper function to clean up SSL environment variables for test isolation
    fn cleanup_redis_ssl_env_vars() {
        unsafe {
            env::remove_var("AX_REDIS_SSL_CA_CERT_PATH");
            env::remove_var("AX_REDIS_SSL_CLIENT_CERT_PATH");
            env::remove_var("AX_REDIS_SSL_CLIENT_KEY_PATH");
            env::remove_var("AX_REDIS_SSL_INSECURE");
        }
    }

    #[test]
    #[serial]
    fn test_apply_env_overrides_redis_ssl_ca_cert() {
        cleanup_redis_ssl_env_vars();

        let mut config = Config::default();
        unsafe {
            env::set_var("AX_REDIS_SSL_CA_CERT_PATH", "/test/ca.crt");
        }

        config.apply_env_overrides();

        assert!(config.redis.ssl.is_some());
        assert_eq!(config.redis.ssl.as_ref().unwrap().ca_cert_path, Some("/test/ca.crt".to_string()));

        unsafe {
            env::remove_var("AX_REDIS_SSL_CA_CERT_PATH");
        }
    }

    #[test]
    #[serial]
    fn test_apply_env_overrides_redis_ssl_client_cert() {
        cleanup_redis_ssl_env_vars();

        let mut config = Config::default();
        unsafe {
            env::set_var("AX_REDIS_SSL_CLIENT_CERT_PATH", "/test/client.crt");
            env::set_var("AX_REDIS_SSL_CLIENT_KEY_PATH", "/test/client.key");
        }

        config.apply_env_overrides();

        assert!(config.redis.ssl.is_some());
        let ssl = config.redis.ssl.as_ref().unwrap();
        assert_eq!(ssl.client_cert_path, Some("/test/client.crt".to_string()));
        assert_eq!(ssl.client_key_path, Some("/test/client.key".to_string()));

        unsafe {
            env::remove_var("AX_REDIS_SSL_CLIENT_CERT_PATH");
            env::remove_var("AX_REDIS_SSL_CLIENT_KEY_PATH");
        }
    }

    #[test]
    #[serial]
    fn test_apply_env_overrides_redis_ssl_insecure() {
        cleanup_redis_ssl_env_vars();

        let mut config = Config::default();
        unsafe {
            env::set_var("AX_REDIS_SSL_INSECURE", "true");
        }

        config.apply_env_overrides();

        assert!(config.redis.ssl.is_some());
        assert!(config.redis.ssl.as_ref().unwrap().insecure);

        unsafe {
            env::remove_var("AX_REDIS_SSL_INSECURE");
        }
    }

    #[test]
    #[serial]
    fn test_apply_env_overrides_redis_ssl_insecure_false() {
        cleanup_redis_ssl_env_vars();

        let mut config = Config::default();
        unsafe {
            env::set_var("AX_REDIS_SSL_INSECURE", "false");
        }

        config.apply_env_overrides();

        assert!(config.redis.ssl.is_some());
        assert!(!config.redis.ssl.as_ref().unwrap().insecure);

        unsafe {
            env::remove_var("AX_REDIS_SSL_INSECURE");
        }
    }

    #[test]
    #[serial]
    fn test_apply_env_overrides_redis_ssl_combined() {
        cleanup_redis_ssl_env_vars();
        let mut config = Config::default();
        unsafe {
            env::set_var("AX_REDIS_SSL_CA_CERT_PATH", "/test/ca.crt");
            env::set_var("AX_REDIS_SSL_CLIENT_CERT_PATH", "/test/client.crt");
            env::set_var("AX_REDIS_SSL_CLIENT_KEY_PATH", "/test/client.key");
            env::set_var("AX_REDIS_SSL_INSECURE", "true");
        }

        config.apply_env_overrides();

        assert!(config.redis.ssl.is_some());
        let ssl = config.redis.ssl.as_ref().unwrap();
        assert_eq!(ssl.ca_cert_path, Some("/test/ca.crt".to_string()));
        assert_eq!(ssl.client_cert_path, Some("/test/client.crt".to_string()));
        assert_eq!(ssl.client_key_path, Some("/test/client.key".to_string()));
        assert!(ssl.insecure);

        unsafe {
            env::remove_var("AX_REDIS_SSL_CA_CERT_PATH");
            env::remove_var("AX_REDIS_SSL_CLIENT_CERT_PATH");
            env::remove_var("AX_REDIS_SSL_CLIENT_KEY_PATH");
            env::remove_var("AX_REDIS_SSL_INSECURE");
        }
    }

    #[test]
    fn test_redis_ssl_config_default_insecure() {
        let config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            insecure: false,
        };
        assert!(!config.insecure);
    }
}
