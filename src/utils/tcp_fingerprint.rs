use std::sync::Arc;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::net::Ipv4Addr;
use libbpf_rs::MapCore;
use crate::worker::log::{send_event, UnifiedEvent};

use crate::bpf::FilterSkel;

/// TCP fingerprinting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprintConfig {
    pub enabled: bool,
    pub log_interval_secs: u64,
    pub enable_fingerprint_events: bool,
    pub fingerprint_events_interval_secs: u64,
    pub min_packet_count: u32,
    pub min_connection_duration_secs: u64,
}

impl Default for TcpFingerprintConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_interval_secs: 60,
            enable_fingerprint_events: true,
            fingerprint_events_interval_secs: 30,
            min_packet_count: 3,
            min_connection_duration_secs: 1,
        }
    }
}

impl TcpFingerprintConfig {
    /// Convert from CLI configuration
    pub fn from_cli_config(cli_config: &crate::cli::TcpFingerprintConfig) -> Self {
        Self {
            enabled: cli_config.enabled,
            log_interval_secs: cli_config.log_interval_secs,
            enable_fingerprint_events: cli_config.enable_fingerprint_events,
            fingerprint_events_interval_secs: cli_config.fingerprint_events_interval_secs,
            min_packet_count: cli_config.min_packet_count,
            min_connection_duration_secs: cli_config.min_connection_duration_secs,
        }
    }
}

/// TCP fingerprint data collected from BPF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprintData {
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub packet_count: u32,
    pub ttl: u16,
    pub mss: u16,
    pub window_size: u16,
    pub window_scale: u8,
    pub options_len: u8,
    pub options: Vec<u8>,
}

/// TCP fingerprint key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprintKey {
    pub src_ip: String,
    pub src_port: u16,
    pub fingerprint: String,
}

/// TCP fingerprint entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprintEntry {
    pub key: TcpFingerprintKey,
    pub data: TcpFingerprintData,
}

/// TCP SYN statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSynStats {
    pub total_syns: u64,
    pub unique_fingerprints: u64,
    pub last_reset: DateTime<Utc>,
}

/// TCP fingerprinting statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprintStats {
    pub timestamp: DateTime<Utc>,
    pub syn_stats: TcpSynStats,
    pub fingerprints: Vec<TcpFingerprintEntry>,
    pub total_unique_fingerprints: u64,
}

/// TCP fingerprint event for API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprintEvent {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub src_port: u16,
    pub fingerprint: String,
    pub ttl: u16,
    pub mss: u16,
    pub window_size: u16,
    pub window_scale: u8,
    pub packet_count: u32
}

/// Collection of TCP fingerprint events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprintEvents {
    pub events: Vec<TcpFingerprintEvent>,
    pub total_events: u64,
    pub unique_ips: u64,
}

/// Unique fingerprint pattern statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniqueFingerprintPattern {
    pub pattern: String,
    pub packet_count: u32,
    pub unique_ips: usize,
    pub entries: usize,
}

/// Unique fingerprint statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniqueFingerprintStats {
    pub timestamp: DateTime<Utc>,
    pub total_unique_patterns: usize,
    pub total_unique_ips: usize,
    pub total_packets: u32,
    pub patterns: Vec<UniqueFingerprintPattern>,
}

impl TcpFingerprintEvents {
    /// Get top fingerprints by packet count
    pub fn get_top_fingerprints(&self, limit: usize) -> Vec<TcpFingerprintEvent> {
        let mut events = self.events.clone();
        events.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
        events.into_iter().take(limit).collect()
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Generate summary string
    pub fn summary(&self) -> String {
        format!("TCP Fingerprint Events: {} events from {} unique IPs",
                self.total_events, self.unique_ips)
    }
}

impl TcpFingerprintEvent {
    /// Generate summary string
    pub fn summary(&self) -> String {
        format!("TCP Fingerprint: {}:{} {} (TTL:{}, MSS:{}, Window:{}, Scale:{}, Packets:{})",
                self.src_ip, self.src_port, self.fingerprint,
                self.ttl, self.mss, self.window_size, self.window_scale, self.packet_count)
    }
}

impl UniqueFingerprintStats {
    /// Generate summary string
    pub fn summary(&self) -> String {
        format!("Unique Fingerprint Stats: {} patterns, {} unique IPs, {} total packets",
                self.total_unique_patterns, self.total_unique_ips, self.total_packets)
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl TcpFingerprintStats {
    /// Generate summary string
    pub fn summary(&self) -> String {
        let mut summary = format!("TCP Fingerprint Stats: {} SYN packets, {} unique fingerprints, {} total entries",
                self.syn_stats.total_syns, self.syn_stats.unique_fingerprints, self.total_unique_fingerprints);

        // Add top unique fingerprints if any
        if !self.fingerprints.is_empty() {
            summary.push_str(&format!(", {} unique fingerprints found", self.fingerprints.len()));

            // Show top 5 fingerprints by packet count
            let mut fingerprint_vec: Vec<_> = self.fingerprints.iter().collect();
            fingerprint_vec.sort_by(|a, b| b.data.packet_count.cmp(&a.data.packet_count));

            if !fingerprint_vec.is_empty() {
                summary.push_str(", Top fingerprints: ");
                for (i, entry) in fingerprint_vec.iter().take(5).enumerate() {
                    if i > 0 { summary.push_str(", "); }
                    summary.push_str(&format!("{}:{}:{}:{}",
                        entry.key.src_ip, entry.key.src_port, entry.key.fingerprint, entry.data.packet_count));
                }
            }
        }

        summary
    }
}

/// Global TCP fingerprint collector
static TCP_FINGERPRINT_COLLECTOR: std::sync::OnceLock<Arc<TcpFingerprintCollector>> = std::sync::OnceLock::new();

/// Set the global TCP fingerprint collector
pub fn set_global_tcp_fingerprint_collector(collector: TcpFingerprintCollector) {
    let _ = TCP_FINGERPRINT_COLLECTOR.set(Arc::new(collector));
}

/// Get the global TCP fingerprint collector
pub fn get_global_tcp_fingerprint_collector() -> Option<Arc<TcpFingerprintCollector>> {
    TCP_FINGERPRINT_COLLECTOR.get().cloned()
}

/// TCP fingerprint collector
#[derive(Clone)]
pub struct TcpFingerprintCollector {
    skels: Vec<Arc<FilterSkel<'static>>>,
    enabled: bool,
    config: TcpFingerprintConfig,
}

impl TcpFingerprintCollector {
    /// Create a new TCP fingerprint collector
    pub fn new(skels: Vec<Arc<FilterSkel<'static>>>, enabled: bool) -> Self {
        Self {
            skels,
            enabled,
            config: TcpFingerprintConfig::default(),
        }
    }

    /// Create a new TCP fingerprint collector with configuration
    pub fn new_with_config(skels: Vec<Arc<FilterSkel<'static>>>, config: TcpFingerprintConfig) -> Self {
        Self {
            skels,
            enabled: config.enabled,
            config,
        }
    }

    /// Enable or disable fingerprint collection
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if fingerprint collection is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Lookup TCP fingerprint for a specific source IP and port
    pub fn lookup_fingerprint(&self, src_ip: std::net::IpAddr, src_port: u16) -> Option<TcpFingerprintData> {
        if !self.enabled || self.skels.is_empty() {
            return None;
        }

        match src_ip {
            std::net::IpAddr::V4(ip) => {
                let octets = ip.octets();
                let src_ip_be = u32::from_be_bytes(octets);

                // Try to find fingerprint in any skeleton's IPv4 map
                for skel in &self.skels {
                    if let Ok(iter) = skel.maps.tcp_fingerprints.lookup_batch(1000, libbpf_rs::MapFlags::ANY, libbpf_rs::MapFlags::ANY) {
                        for (key_bytes, value_bytes) in iter {
                            if key_bytes.len() >= 6 && value_bytes.len() >= 32 {
                                // Parse key structure: src_ip (4 bytes BE), src_port (2 bytes BE), fingerprint (14 bytes)
                                // BPF stores IP as __be32 (big-endian), so read as big-endian
                                let key_ip = u32::from_be_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]]);
                                let key_port = u16::from_be_bytes([key_bytes[4], key_bytes[5]]);

                                if key_ip == src_ip_be && key_port == src_port {
                                    // Parse value structure
                                    if value_bytes.len() >= 32 {
                                        let first_seen = u64::from_ne_bytes([
                                            value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3],
                                            value_bytes[4], value_bytes[5], value_bytes[6], value_bytes[7]
                                        ]);
                                        let last_seen = u64::from_ne_bytes([
                                            value_bytes[8], value_bytes[9], value_bytes[10], value_bytes[11],
                                            value_bytes[12], value_bytes[13], value_bytes[14], value_bytes[15]
                                        ]);
                                        let packet_count = u32::from_ne_bytes([
                                            value_bytes[16], value_bytes[17], value_bytes[18], value_bytes[19]
                                        ]);
                                        let ttl = u16::from_ne_bytes([value_bytes[20], value_bytes[21]]);
                                        let mss = u16::from_ne_bytes([value_bytes[22], value_bytes[23]]);
                                        let window_size = u16::from_ne_bytes([value_bytes[24], value_bytes[25]]);
                                        let window_scale = value_bytes[26];
                                        let options_len = value_bytes[27];

                                        let options_size = options_len.min(40) as usize;
                                        let mut options = vec![0u8; options_size];
                                        if value_bytes.len() >= 28 + options_size {
                                            options.copy_from_slice(&value_bytes[28..28 + options_size]);
                                        }

                                        return Some(TcpFingerprintData {
                                            first_seen: DateTime::from_timestamp_nanos(first_seen as i64),
                                            last_seen: DateTime::from_timestamp_nanos(last_seen as i64),
                                            packet_count,
                                            ttl,
                                            mss,
                                            window_size,
                                            window_scale,
                                            options_len,
                                            options,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                None
            }
            std::net::IpAddr::V6(ip) => {
                let octets = ip.octets();

                // Try to find fingerprint in any skeleton's IPv6 map
                for skel in &self.skels {
                    if let Ok(iter) = skel.maps.tcp_fingerprints_v6.lookup_batch(1000, libbpf_rs::MapFlags::ANY, libbpf_rs::MapFlags::ANY) {
                        for (key_bytes, value_bytes) in iter {
                            if key_bytes.len() >= 18 && value_bytes.len() >= 32 {
                                // Parse key structure: src_ip (16 bytes), src_port (2 bytes BE), fingerprint (14 bytes)
                                let mut key_ip = [0u8; 16];
                                key_ip.copy_from_slice(&key_bytes[0..16]);
                                let key_port = u16::from_be_bytes([key_bytes[16], key_bytes[17]]);

                                if key_ip == octets && key_port == src_port {
                                    // Parse value structure (same as IPv4)
                                    if value_bytes.len() >= 32 {
                                        let first_seen = u64::from_ne_bytes([
                                            value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3],
                                            value_bytes[4], value_bytes[5], value_bytes[6], value_bytes[7]
                                        ]);
                                        let last_seen = u64::from_ne_bytes([
                                            value_bytes[8], value_bytes[9], value_bytes[10], value_bytes[11],
                                            value_bytes[12], value_bytes[13], value_bytes[14], value_bytes[15]
                                        ]);
                                        let packet_count = u32::from_ne_bytes([
                                            value_bytes[16], value_bytes[17], value_bytes[18], value_bytes[19]
                                        ]);
                                        let ttl = u16::from_ne_bytes([value_bytes[20], value_bytes[21]]);
                                        let mss = u16::from_ne_bytes([value_bytes[22], value_bytes[23]]);
                                        let window_size = u16::from_ne_bytes([value_bytes[24], value_bytes[25]]);
                                        let window_scale = value_bytes[26];
                                        let options_len = value_bytes[27];

                                        let options_size = options_len.min(40) as usize;
                                        let mut options = vec![0u8; options_size];
                                        if value_bytes.len() >= 28 + options_size {
                                            options.copy_from_slice(&value_bytes[28..28 + options_size]);
                                        }

                                        return Some(TcpFingerprintData {
                                            first_seen: DateTime::from_timestamp_nanos(first_seen as i64),
                                            last_seen: DateTime::from_timestamp_nanos(last_seen as i64),
                                            packet_count,
                                            ttl,
                                            mss,
                                            window_size,
                                            window_scale,
                                            options_len,
                                            options,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                None
            }
        }
    }

    /// Collect TCP fingerprint statistics from all BPF skeletons
    pub fn collect_fingerprint_stats(&self) -> Result<Vec<TcpFingerprintStats>, Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(vec![]);
        }

        let mut stats = Vec::new();
        for (i, skel) in self.skels.iter().enumerate() {
            log::debug!("Collecting TCP fingerprint stats from skeleton {}", i);
            match self.collect_fingerprint_stats_from_skeleton(skel) {
                Ok(stat) => {
                    log::debug!("Skeleton {} collected {} fingerprints", i, stat.fingerprints.len());
                    stats.push(stat);
                }
                Err(e) => {
                    log::warn!("Failed to collect TCP fingerprint stats from skeleton {}: {}", i, e);
                }
            }
        }
        log::debug!("Collected stats from {} skeletons", stats.len());
        Ok(stats)
    }

    /// Collect TCP fingerprint statistics from a single BPF skeleton
    fn collect_fingerprint_stats_from_skeleton(&self, skel: &FilterSkel) -> Result<TcpFingerprintStats, Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(TcpFingerprintStats {
                timestamp: Utc::now(),
                syn_stats: TcpSynStats {
                    total_syns: 0,
                    unique_fingerprints: 0,
                    last_reset: Utc::now(),
                },
                fingerprints: Vec::new(),
                total_unique_fingerprints: 0,
            });
        }

        let mut fingerprints = Vec::new();

        // Read TCP SYN statistics
        log::debug!("Reading TCP SYN statistics from skeleton");
        let syn_stats = self.collect_syn_stats(skel)?;
        log::debug!("TCP SYN stats: {} total_syns, {} unique_fingerprints", syn_stats.total_syns, syn_stats.unique_fingerprints);

        // Read TCP fingerprints from BPF map
        log::debug!("Reading TCP fingerprints from skeleton");
        self.collect_tcp_fingerprints(skel, &mut fingerprints)?;
        log::debug!("Collected {} fingerprints from skeleton", fingerprints.len());

        let total_unique_fingerprints = fingerprints.len() as u64;

        Ok(TcpFingerprintStats {
            timestamp: Utc::now(),
            syn_stats,
            fingerprints,
            total_unique_fingerprints,
        })
    }

    /// Collect aggregated TCP fingerprint statistics across all skeletons
    pub fn collect_aggregated_stats(&self) -> Result<TcpFingerprintStats, Box<dyn std::error::Error>> {
        if !self.enabled {
            return Err("TCP fingerprint collection is disabled".into());
        }

        log::debug!("Collecting aggregated TCP fingerprint statistics from {} skeletons", self.skels.len());
        let individual_stats = self.collect_fingerprint_stats()?;
        log::debug!("Collected {} individual stats", individual_stats.len());

        if individual_stats.is_empty() {
            log::warn!("No TCP fingerprint statistics available from any skeleton");
            return Err("No TCP fingerprint statistics available".into());
        }

        // Aggregate statistics across all skeletons
        let mut aggregated = TcpFingerprintStats {
            timestamp: Utc::now(),
            syn_stats: TcpSynStats {
                total_syns: 0,
                unique_fingerprints: 0,
                last_reset: Utc::now(),
            },
            fingerprints: Vec::new(),
            total_unique_fingerprints: 0,
        };

        let mut all_fingerprints: std::collections::HashMap<String, TcpFingerprintEntry> = std::collections::HashMap::new();

        for stat in individual_stats {
            aggregated.syn_stats.total_syns += stat.syn_stats.total_syns;
            aggregated.syn_stats.unique_fingerprints += stat.syn_stats.unique_fingerprints;

            // Merge fingerprints by key (src_ip:src_port:fingerprint)
            for entry in stat.fingerprints {
                let key = format!("{}:{}:{}", entry.key.src_ip, entry.key.src_port, entry.key.fingerprint);
                match all_fingerprints.get_mut(&key) {
                    Some(existing) => {
                        // Update packet count and timestamps
                        existing.data.packet_count += entry.data.packet_count;
                        if entry.data.first_seen < existing.data.first_seen {
                            existing.data.first_seen = entry.data.first_seen;
                        }
                        if entry.data.last_seen > existing.data.last_seen {
                            existing.data.last_seen = entry.data.last_seen;
                        }
                    }
                    None => {
                        all_fingerprints.insert(key, entry);
                    }
                }
            }
        }

        aggregated.fingerprints = all_fingerprints.into_values().collect();
        aggregated.total_unique_fingerprints = aggregated.fingerprints.len() as u64;

        Ok(aggregated)
    }

    /// Collect TCP SYN statistics
    fn collect_syn_stats(&self, skel: &FilterSkel) -> Result<TcpSynStats, Box<dyn std::error::Error>> {
        let key = 0u32.to_le_bytes();
        let stats_bytes = skel.maps.tcp_syn_stats.lookup(&key, libbpf_rs::MapFlags::ANY)
            .map_err(|e| format!("Failed to read TCP SYN stats: {}", e))?;

        if let Some(bytes) = stats_bytes {
            if bytes.len() >= 24 { // 3 * u64 = 24 bytes
                let total_syns = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                let unique_fingerprints = u64::from_le_bytes([
                    bytes[8], bytes[9], bytes[10], bytes[11],
                    bytes[12], bytes[13], bytes[14], bytes[15],
                ]);
                let _last_reset = u64::from_le_bytes([
                    bytes[16], bytes[17], bytes[18], bytes[19],
                    bytes[20], bytes[21], bytes[22], bytes[23],
                ]);

                Ok(TcpSynStats {
                    total_syns,
                    unique_fingerprints,
                    last_reset: Utc::now(), // Use current time as fallback
                })
            } else {
                Ok(TcpSynStats {
                    total_syns: 0,
                    unique_fingerprints: 0,
                    last_reset: Utc::now(),
                })
            }
        } else {
            Ok(TcpSynStats {
                total_syns: 0,
                unique_fingerprints: 0,
                last_reset: Utc::now(),
            })
        }
    }

    /// Collect TCP fingerprints from BPF map
    fn collect_tcp_fingerprints(&self, skel: &FilterSkel, fingerprints: &mut Vec<TcpFingerprintEntry>) -> Result<(), Box<dyn std::error::Error>> {
        log::debug!("Collecting TCP fingerprints from BPF map (IPv4)");

        match skel.maps.tcp_fingerprints.lookup_batch(1000, libbpf_rs::MapFlags::ANY, libbpf_rs::MapFlags::ANY) {
            Ok(batch_iter) => {
                let mut count = 0;
                let mut skipped_count = 0;
                for (key_bytes, value_bytes) in batch_iter {
                    log::debug!("Processing IPv4 fingerprint entry: key_len={}, value_len={}", key_bytes.len(), value_bytes.len());

                    if key_bytes.len() >= 20 && value_bytes.len() >= 72 { // Key: 4+2+14, Value: 8+8+4+2+2+2+1+1+4(padding)+40
                        let src_ip = Ipv4Addr::from([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]]);
                        let src_port = u16::from_le_bytes([key_bytes[4], key_bytes[5]]);
                        let fingerprint = String::from_utf8_lossy(&key_bytes[6..20]).trim_end_matches('\0').to_string();

                        // Parse fingerprint data
                        let _first_seen = u64::from_le_bytes([
                            value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3],
                            value_bytes[4], value_bytes[5], value_bytes[6], value_bytes[7],
                        ]);
                        let _last_seen = u64::from_le_bytes([
                            value_bytes[8], value_bytes[9], value_bytes[10], value_bytes[11],
                            value_bytes[12], value_bytes[13], value_bytes[14], value_bytes[15],
                        ]);
                        let packet_count = u32::from_le_bytes([
                            value_bytes[16], value_bytes[17], value_bytes[18], value_bytes[19],
                        ]);
                        let ttl = u16::from_le_bytes([value_bytes[20], value_bytes[21]]);
                        let mss = u16::from_le_bytes([value_bytes[22], value_bytes[23]]);
                        let window_size = u16::from_le_bytes([value_bytes[24], value_bytes[25]]);
                        let window_scale = value_bytes[26];
                        let options_len = value_bytes[27];

                        // Only process entries with packet_count > 0 and above threshold
                        if packet_count > 0 && packet_count >= self.config.min_packet_count {
                            let options = value_bytes[32..32 + options_len as usize].to_vec();

                            let entry = TcpFingerprintEntry {
                                key: TcpFingerprintKey {
                                    src_ip: src_ip.to_string(),
                                    src_port,
                                    fingerprint: fingerprint.clone(),
                                },
                                data: TcpFingerprintData {
                                    first_seen: Utc::now(), // Use current time as fallback
                                    last_seen: Utc::now(), // Use current time as fallback
                                    packet_count,
                                    ttl,
                                    mss,
                                    window_size,
                                    window_scale,
                                    options_len,
                                    options,
                                },
                            };

                            // Log new TCP fingerprint at debug level
                            log::debug!("TCP Fingerprint: {}:{} - TTL:{} MSS:{} Window:{} Scale:{} Packets:{} Fingerprint:{}",
                                      src_ip, src_port, ttl, mss, window_size, window_scale, packet_count, fingerprint);

                            fingerprints.push(entry);
                            count += 1;
                        } else {
                            log::debug!("Skipping fingerprint entry with packet_count={} (threshold={}): {}:{}",
                                      packet_count, self.config.min_packet_count, src_ip, src_port);
                            skipped_count += 1;
                        }
                    } else {
                        log::debug!("Skipping fingerprint entry with invalid size: key_len={}, value_len={}", key_bytes.len(), value_bytes.len());
                        skipped_count += 1;
                    }
                }
                log::debug!("Found {} IPv4 TCP fingerprints, skipped {} entries", count, skipped_count);
            }
            Err(e) => {
                log::warn!("Failed to read IPv4 TCP fingerprints: {}", e);
            }
        }

        // Collect IPv6 fingerprints
        log::debug!("Collecting TCP fingerprints from BPF map (IPv6)");

        match skel.maps.tcp_fingerprints_v6.lookup_batch(1000, libbpf_rs::MapFlags::ANY, libbpf_rs::MapFlags::ANY) {
            Ok(batch_iter) => {
                let mut count = 0;
                let mut skipped_count = 0;
                for (key_bytes, value_bytes) in batch_iter {
                    log::debug!("Processing IPv6 fingerprint entry: key_len={}, value_len={}", key_bytes.len(), value_bytes.len());

                    if key_bytes.len() >= 32 && value_bytes.len() >= 72 { // Key: 16+2+14, Value: same as IPv4
                        // Parse IPv6 address (16 bytes)
                        let src_ip: std::net::Ipv6Addr = std::net::Ipv6Addr::from([
                            key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3],
                            key_bytes[4], key_bytes[5], key_bytes[6], key_bytes[7],
                            key_bytes[8], key_bytes[9], key_bytes[10], key_bytes[11],
                            key_bytes[12], key_bytes[13], key_bytes[14], key_bytes[15]
                        ]);
                        let src_port = u16::from_le_bytes([key_bytes[16], key_bytes[17]]);
                        let fingerprint = String::from_utf8_lossy(&key_bytes[18..32]).trim_end_matches('\0').to_string();

                        // Parse fingerprint data (same structure as IPv4)
                        let _first_seen = u64::from_le_bytes([
                            value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3],
                            value_bytes[4], value_bytes[5], value_bytes[6], value_bytes[7],
                        ]);
                        let _last_seen = u64::from_le_bytes([
                            value_bytes[8], value_bytes[9], value_bytes[10], value_bytes[11],
                            value_bytes[12], value_bytes[13], value_bytes[14], value_bytes[15],
                        ]);
                        let packet_count = u32::from_le_bytes([
                            value_bytes[16], value_bytes[17], value_bytes[18], value_bytes[19],
                        ]);
                        let ttl = u16::from_le_bytes([value_bytes[20], value_bytes[21]]);
                        let mss = u16::from_le_bytes([value_bytes[22], value_bytes[23]]);
                        let window_size = u16::from_le_bytes([value_bytes[24], value_bytes[25]]);
                        let window_scale = value_bytes[26];
                        let options_len = value_bytes[27];

                        // Only process entries with packet_count > 0 and above threshold
                        if packet_count > 0 && packet_count >= self.config.min_packet_count {
                            let options = value_bytes[32..32 + options_len as usize].to_vec();

                            let entry = TcpFingerprintEntry {
                                key: TcpFingerprintKey {
                                    src_ip: src_ip.to_string(),
                                    src_port,
                                    fingerprint: fingerprint.clone(),
                                },
                                data: TcpFingerprintData {
                                    first_seen: Utc::now(), // Use current time as fallback
                                    last_seen: Utc::now(), // Use current time as fallback
                                    packet_count,
                                    ttl,
                                    mss,
                                    window_size,
                                    window_scale,
                                    options_len,
                                    options,
                                },
                            };

                            // Log new IPv6 TCP fingerprint at debug level
                            log::debug!("TCP Fingerprint (IPv6): {}:{} - TTL:{} MSS:{} Window:{} Scale:{} Packets:{} Fingerprint:{}",
                                      src_ip, src_port, ttl, mss, window_size, window_scale, packet_count, fingerprint);

                            fingerprints.push(entry);
                            count += 1;
                        } else {
                            log::debug!("Skipping IPv6 fingerprint entry with packet_count={} (threshold={}): {}:{}",
                                      packet_count, self.config.min_packet_count, src_ip, src_port);
                            skipped_count += 1;
                        }
                    } else {
                        log::debug!("Skipping IPv6 fingerprint entry with invalid size: key_len={}, value_len={}", key_bytes.len(), value_bytes.len());
                        skipped_count += 1;
                    }
                }
                log::debug!("Found {} IPv6 TCP fingerprints, skipped {} entries", count, skipped_count);
            }
            Err(e) => {
                log::warn!("Failed to read IPv6 TCP fingerprints: {}", e);
            }
        }

        Ok(())
    }


    /// Log current TCP fingerprint statistics
    pub fn log_stats(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        match self.collect_aggregated_stats() {
            Ok(stats) => {
                log::debug!("{}", stats.summary());

                // Log detailed unique fingerprint information
                if stats.total_unique_fingerprints > 0 {
                    // Group fingerprints by fingerprint string to show unique patterns
                    let mut fingerprint_groups: std::collections::HashMap<String, Vec<&TcpFingerprintEntry>> = std::collections::HashMap::new();
                    for entry in &stats.fingerprints {
                        fingerprint_groups.entry(entry.key.fingerprint.clone()).or_insert_with(Vec::new).push(entry);
                    }

                    log::debug!("Unique fingerprint patterns: {} different patterns found", fingerprint_groups.len());

                    // Show top unique fingerprint patterns by total packet count
                    let mut pattern_stats: Vec<_> = fingerprint_groups.iter().map(|(pattern, entries)| {
                        let total_packets: u32 = entries.iter().map(|e| e.data.packet_count).sum();
                        let unique_ips: std::collections::HashSet<_> = entries.iter().map(|e| &e.key.src_ip).collect();
                        (pattern, total_packets, unique_ips.len(), entries.len())
                    }).collect();

                    pattern_stats.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by packet count

                    log::debug!("Top unique fingerprint patterns:");
                    for (i, (pattern, total_packets, unique_ips, entries)) in pattern_stats.iter().take(10).enumerate() {
                        log::debug!("  {}: {} ({} packets, {} unique IPs, {} entries)",
                                 i + 1, pattern, total_packets, unique_ips, entries);
                    }

                    // Log as JSON for structured logging
                    if let Ok(json) = serde_json::to_string(&stats) {
                        log::debug!("TCP Fingerprint Stats JSON: {}", json);
                    }
                } else {
                    log::debug!("No unique fingerprints found");
                }

                Ok(())
            }
            Err(e) => {
                log::warn!("Failed to collect TCP fingerprint statistics: {}", e);
                Err(e)
            }
        }
    }

    /// Get unique fingerprint statistics
    pub fn get_unique_fingerprint_stats(&self) -> Result<UniqueFingerprintStats, Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(UniqueFingerprintStats {
                timestamp: Utc::now(),
                total_unique_patterns: 0,
                total_unique_ips: 0,
                total_packets: 0,
                patterns: Vec::new(),
            });
        }

        let stats = self.collect_aggregated_stats()?;

        // Group fingerprints by pattern
        let mut fingerprint_groups: std::collections::HashMap<String, Vec<&TcpFingerprintEntry>> = std::collections::HashMap::new();
        for entry in &stats.fingerprints {
            fingerprint_groups.entry(entry.key.fingerprint.clone()).or_insert_with(Vec::new).push(entry);
        }

        let mut patterns = Vec::new();
        let mut total_unique_ips: std::collections::HashSet<&String> = std::collections::HashSet::new();
        let mut total_packets = 0u32;

        for (pattern, entries) in fingerprint_groups {
            let pattern_packets: u32 = entries.iter().map(|e| e.data.packet_count).sum();
            let pattern_ips: std::collections::HashSet<_> = entries.iter().map(|e| &e.key.src_ip).collect();

            total_unique_ips.extend(pattern_ips.iter());
            total_packets += pattern_packets;

            patterns.push(UniqueFingerprintPattern {
                pattern: pattern.clone(),
                packet_count: pattern_packets,
                unique_ips: pattern_ips.len(),
                entries: entries.len(),
            });
        }

        patterns.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));

        Ok(UniqueFingerprintStats {
            timestamp: Utc::now(),
            total_unique_patterns: patterns.len(),
            total_unique_ips: total_unique_ips.len(),
            total_packets,
            patterns,
        })
    }

    /// Log unique fingerprint statistics
    pub fn log_unique_fingerprint_stats(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        match self.get_unique_fingerprint_stats() {
            Ok(stats) => {
                log::debug!("{}", stats.summary());

                if stats.total_unique_patterns > 0 {
                    log::debug!("Top unique fingerprint patterns:");
                    for (i, pattern) in stats.patterns.iter().take(10).enumerate() {
                        log::debug!("  {}: {} ({} packets, {} unique IPs, {} entries)",
                                 i + 1, pattern.pattern, pattern.packet_count, pattern.unique_ips, pattern.entries);
                    }

                    // Log as JSON for structured logging
                    if let Ok(json) = stats.to_json() {
                        log::debug!("Unique Fingerprint Stats JSON: {}", json);
                    }
                } else {
                    log::debug!("No unique fingerprint patterns found");
                }

                Ok(())
            }
            Err(e) => {
                log::warn!("Failed to collect unique fingerprint statistics: {}", e);
                Err(e)
            }
        }
    }

    /// Collect TCP fingerprint events from all BPF skeletons
    pub fn collect_fingerprint_events(&self) -> Result<TcpFingerprintEvents, Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(TcpFingerprintEvents {
                events: Vec::new(),
                total_events: 0,
                unique_ips: 0,
            });
        }

        let mut all_events = Vec::new();
        let mut unique_ips = std::collections::HashSet::new();

        for skel in &self.skels {
            let mut fingerprints = Vec::new();
            self.collect_tcp_fingerprints(skel, &mut fingerprints)?;

            // Convert to events
            for entry in fingerprints {
                let event = TcpFingerprintEvent {
                    event_type: "tcp_fingerprint".to_string(),
                    timestamp: Utc::now(),
                    src_ip: entry.key.src_ip.clone(),
                    src_port: entry.key.src_port,
                    fingerprint: entry.key.fingerprint.clone(),
                    ttl: entry.data.ttl,
                    mss: entry.data.mss,
                    window_size: entry.data.window_size,
                    window_scale: entry.data.window_scale,
                    packet_count: entry.data.packet_count
                };

                unique_ips.insert(event.src_ip.clone());
                all_events.push(event);
            }
        }

        let total_events = all_events.len() as u64;
        let unique_ips_count = unique_ips.len() as u64;

        Ok(TcpFingerprintEvents {
            events: all_events,
            total_events,
            unique_ips: unique_ips_count,
        })
    }

    /// Log TCP fingerprint events
    pub fn log_fingerprint_events(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        let events = self.collect_fingerprint_events()?;

        if events.total_events > 0 {
            log::debug!("{}", events.summary());

            // Log top 5 fingerprints
            let top_fingerprints = events.get_top_fingerprints(5);
            for event in top_fingerprints {
                log::debug!("  {}", event.summary());
            }

            // Log as JSON for structured logging
            if let Ok(json) = events.to_json() {
                log::debug!("TCP Fingerprint Events JSON: {}", json);
            }

            // Send events to unified queue
            for event in events.events {
                send_event(UnifiedEvent::TcpFingerprint(event));
            }

            // Reset the counters after logging
            self.reset_fingerprint_counters()?;
        } else {
            log::debug!("No TCP fingerprint events found");
        }

        Ok(())
    }


    /// Reset TCP fingerprint counters in BPF maps
    pub fn reset_fingerprint_counters(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        log::debug!("Resetting TCP fingerprint counters");

        for skel in &self.skels {
            // Reset TCP fingerprints map
            match skel.maps.tcp_fingerprints.lookup_batch(1000, libbpf_rs::MapFlags::ANY, libbpf_rs::MapFlags::ANY) {
                Ok(batch_iter) => {
                    let mut reset_count = 0;
                    for (key_bytes, _) in batch_iter {
                        if key_bytes.len() >= 20 {
                            // Create zero value for fingerprint data (72 bytes with padding)
                            let zero_value = vec![0u8; 72];
                            if let Err(e) = skel.maps.tcp_fingerprints.update(&key_bytes, &zero_value, libbpf_rs::MapFlags::ANY) {
                                log::warn!("Failed to reset TCP fingerprint counter: {}", e);
                            } else {
                                reset_count += 1;
                            }
                        }
                    }
                    log::debug!("Reset {} TCP fingerprint counters", reset_count);
                }
                Err(e) => {
                    log::warn!("Failed to reset TCP fingerprint counters: {}", e);
                }
            }

            // Reset TCP SYN stats
            let key = 0u32.to_le_bytes();
            let zero_stats = vec![0u8; 24]; // 3 * u64 = 24 bytes
            if let Err(e) = skel.maps.tcp_syn_stats.update(&key, &zero_stats, libbpf_rs::MapFlags::ANY) {
                log::warn!("Failed to reset TCP SYN stats: {}", e);
            } else {
                log::debug!("Reset TCP SYN stats");
            }
        }

        Ok(())
    }

    /// Check if BPF maps are accessible
    pub fn check_maps_accessible(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        for (i, skel) in self.skels.iter().enumerate() {
            log::debug!("Checking accessibility of BPF maps for skeleton {}", i);

            // Check tcp_fingerprints map
            match skel.maps.tcp_fingerprints.lookup_batch(1, libbpf_rs::MapFlags::ANY, libbpf_rs::MapFlags::ANY) {
                Ok(_) => log::debug!("tcp_fingerprints map is accessible for skeleton {}", i),
                Err(e) => log::warn!("tcp_fingerprints map not accessible for skeleton {}: {}", i, e),
            }

            // Check tcp_syn_stats map
            let key = 0u32.to_le_bytes();
            match skel.maps.tcp_syn_stats.lookup(&key, libbpf_rs::MapFlags::ANY) {
                Ok(_) => log::debug!("tcp_syn_stats map is accessible for skeleton {}", i),
                Err(e) => log::warn!("tcp_syn_stats map not accessible for skeleton {}: {}", i, e),
            }
        }

        Ok(())
    }
}

/// Configuration for TCP fingerprint collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprintCollectorConfig {
    pub enabled: bool,
    pub log_interval_secs: u64,
    pub fingerprint_events_interval_secs: u64,
}

impl Default for TcpFingerprintCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_interval_secs: 60, // Log stats every minute
            fingerprint_events_interval_secs: 30, // Send events every 30 seconds
        }
    }
}

impl TcpFingerprintCollectorConfig {
    /// Create a new configuration
    pub fn new(enabled: bool, log_interval_secs: u64, fingerprint_events_interval_secs: u64) -> Self {
        Self {
            enabled,
            log_interval_secs,
            fingerprint_events_interval_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_fingerprint_config_default() {
        let config = TcpFingerprintConfig::default();
        assert!(config.enabled);
        assert_eq!(config.log_interval_secs, 60);
        assert!(config.enable_fingerprint_events);
        assert_eq!(config.fingerprint_events_interval_secs, 30);
    }

    #[test]
    fn test_tcp_fingerprint_collector_config_default() {
        let config = TcpFingerprintCollectorConfig::default();
        assert!(config.enabled);
        assert_eq!(config.log_interval_secs, 60);
        assert_eq!(config.fingerprint_events_interval_secs, 30);
    }

    #[test]
    fn test_tcp_fingerprint_event_summary() {
        let event = TcpFingerprintEvent {
            event_type: "tcp_fingerprint".to_string(),
            timestamp: Utc::now(),
            src_ip: "192.168.1.1".to_string(),
            src_port: 80,
            fingerprint: "64:1460:65535:7".to_string(),
            ttl: 64,
            mss: 1460,
            window_size: 65535,
            window_scale: 7,
            packet_count: 1
        };

        let summary = event.summary();
        assert!(summary.contains("192.168.1.1"));
        assert!(summary.contains("80"));
        assert!(summary.contains("64:1460:65535:7"));
    }

    #[test]
    fn test_unique_fingerprint_stats() {
        let stats = UniqueFingerprintStats {
            timestamp: Utc::now(),
            total_unique_patterns: 2,
            total_unique_ips: 3,
            total_packets: 100,
            patterns: vec![
                UniqueFingerprintPattern {
                    pattern: "64:1460:65535:7".to_string(),
                    packet_count: 60,
                    unique_ips: 2,
                    entries: 2,
                },
                UniqueFingerprintPattern {
                    pattern: "128:1460:32768:8".to_string(),
                    packet_count: 40,
                    unique_ips: 1,
                    entries: 1,
                },
            ],
        };

        let summary = stats.summary();
        assert!(summary.contains("2 patterns"));
        assert!(summary.contains("3 unique IPs"));
        assert!(summary.contains("100 total packets"));

        let json = stats.to_json().unwrap();
        assert!(json.contains("total_unique_patterns"));
        assert!(json.contains("patterns"));
    }
}
