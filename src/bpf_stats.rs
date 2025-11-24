use std::sync::Arc;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use libbpf_rs::MapCore;
use crate::worker::log::{send_event, UnifiedEvent};

use crate::bpf::FilterSkel;

/// BPF statistics collected from kernel-level access rule enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfAccessStats {
    pub timestamp: DateTime<Utc>,
    pub total_packets_processed: u64,
    pub total_packets_dropped: u64,
    pub ipv4_banned_hits: u64,
    pub ipv4_recently_banned_hits: u64,
    pub ipv6_banned_hits: u64,
    pub ipv6_recently_banned_hits: u64,
    pub drop_rate_percentage: f64,
    pub dropped_ip_addresses: DroppedIpAddresses,
}

/// Statistics about dropped IP addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedIpAddresses {
    pub ipv4_addresses: HashMap<String, u64>,  // IP address -> drop count
    pub ipv6_addresses: HashMap<String, u64>,  // IP address -> drop count
    pub total_unique_dropped_ips: u64,
}

/// Individual event for a dropped IP address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedIpEvent {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub ip_version: IpVersion,
    pub drop_count: u64,
    pub drop_reason: DropReason
}

/// IP version enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpVersion {
    IPv4,
    IPv6,
}

/// Reason for dropping packets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DropReason {
    AccessRules,
    RecentlyBannedUdp,
    RecentlyBannedIcmp,
    RecentlyBannedTcpFinRst,
}

/// Collection of dropped IP events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedIpEvents {
    pub timestamp: DateTime<Utc>,
    pub events: Vec<DroppedIpEvent>,
    pub total_events: u64,
    pub unique_ips: u64,
}

impl BpfAccessStats {
    /// Create a new statistics snapshot from BPF maps
    pub fn from_bpf_maps(skel: &FilterSkel) -> Result<Self, Box<dyn std::error::Error>> {
        let timestamp = Utc::now();

        // Read statistics from BPF maps
        let total_packets_processed = Self::read_bpf_counter(&skel.maps.total_packets_processed)?;
        let total_packets_dropped = Self::read_bpf_counter(&skel.maps.total_packets_dropped)?;
        let ipv4_banned_hits = Self::read_bpf_counter(&skel.maps.ipv4_banned_stats)?;
        let ipv4_recently_banned_hits = Self::read_bpf_counter(&skel.maps.ipv4_recently_banned_stats)?;
        let ipv6_banned_hits = Self::read_bpf_counter(&skel.maps.ipv6_banned_stats)?;
        let ipv6_recently_banned_hits = Self::read_bpf_counter(&skel.maps.ipv6_recently_banned_stats)?;

        // Collect dropped IP addresses
        let dropped_ip_addresses = Self::collect_dropped_ip_addresses(skel)?;

        // Calculate drop rate percentage
        let drop_rate_percentage = if total_packets_processed > 0 {
            (total_packets_dropped as f64 / total_packets_processed as f64) * 100.0
        } else {
            0.0
        };

        Ok(BpfAccessStats {
            timestamp,
            total_packets_processed,
            total_packets_dropped,
            ipv4_banned_hits,
            ipv4_recently_banned_hits,
            ipv6_banned_hits,
            ipv6_recently_banned_hits,
            drop_rate_percentage,
            dropped_ip_addresses,
        })
    }

    /// Read a counter value from a BPF array map
    fn read_bpf_counter(map: &impl libbpf_rs::MapCore) -> Result<u64, Box<dyn std::error::Error>> {
        let key = 0u32.to_le_bytes();
        if let Some(value_bytes) = map.lookup(&key, libbpf_rs::MapFlags::ANY)? {
            if value_bytes.len() >= 8 {
                let value = u64::from_le_bytes([
                    value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3],
                    value_bytes[4], value_bytes[5], value_bytes[6], value_bytes[7],
                ]);
                Ok(value)
            } else {
                Ok(0)
            }
        } else {
            Ok(0)
        }
    }

    /// Collect dropped IP addresses from BPF maps
    fn collect_dropped_ip_addresses(skel: &FilterSkel) -> Result<DroppedIpAddresses, Box<dyn std::error::Error>> {
        let mut ipv4_addresses = HashMap::new();
        let mut ipv6_addresses = HashMap::new();

        log::debug!("Collecting dropped IP addresses from BPF maps");

        // Use batch lookup to get all entries from the BPF maps
        // This reads the actual IPs that are being tracked, not hardcoded ranges
        match skel.maps.dropped_ipv4_addresses.lookup_batch(1000, libbpf_rs::MapFlags::ANY, libbpf_rs::MapFlags::ANY) {
            Ok(batch_iter) => {
                log::debug!("Reading IPv4 dropped addresses from BPF map");
                let mut count = 0;
                for (key_bytes, value_bytes) in batch_iter {
                    if key_bytes.len() >= 4 && value_bytes.len() >= 8 {
                        let ip_bytes = [key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]];
                        let ip_addr = Ipv4Addr::from(ip_bytes);
                        let drop_count = u64::from_le_bytes([
                            value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3],
                            value_bytes[4], value_bytes[5], value_bytes[6], value_bytes[7],
                        ]);
                        if drop_count > 0 {
                            log::debug!("Found dropped IPv4: {} (dropped {} times)", ip_addr, drop_count);
                            ipv4_addresses.insert(ip_addr.to_string(), drop_count);
                            count += 1;
                        }
                    }
                }
                log::debug!("Found {} dropped IPv4 addresses", count);
            }
            Err(e) => {
                log::warn!("Failed to read IPv4 dropped addresses: {}", e);
            }
        }

        // Read IPv6 addresses
        match skel.maps.dropped_ipv6_addresses.lookup_batch(1000, libbpf_rs::MapFlags::ANY, libbpf_rs::MapFlags::ANY) {
            Ok(batch_iter) => {
                log::debug!("Reading IPv6 dropped addresses from BPF map");
                let mut count = 0;
                for (key_bytes, value_bytes) in batch_iter {
                    if key_bytes.len() >= 16 && value_bytes.len() >= 8 {
                        let mut ip_bytes = [0u8; 16];
                        ip_bytes.copy_from_slice(&key_bytes[..16]);
                        let ip_addr = Ipv6Addr::from(ip_bytes);
                        let drop_count = u64::from_le_bytes([
                            value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3],
                            value_bytes[4], value_bytes[5], value_bytes[6], value_bytes[7],
                        ]);
                        if drop_count > 0 {
                            log::debug!("Found dropped IPv6: {} (dropped {} times)", ip_addr, drop_count);
                            ipv6_addresses.insert(ip_addr.to_string(), drop_count);
                            count += 1;
                        }
                    }
                }
                log::debug!("Found {} dropped IPv6 addresses", count);
            }
            Err(e) => {
                log::warn!("Failed to read IPv6 dropped addresses: {}", e);
            }
        }

        let total_unique_dropped_ips = ipv4_addresses.len() as u64 + ipv6_addresses.len() as u64;
        log::debug!("Total dropped IP addresses found: {} (IPv4: {}, IPv6: {})",
                  total_unique_dropped_ips, ipv4_addresses.len(), ipv6_addresses.len());

        Ok(DroppedIpAddresses {
            ipv4_addresses,
            ipv6_addresses,
            total_unique_dropped_ips,
        })
    }


    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Create a summary string for logging
    pub fn summary(&self) -> String {
        let mut summary = format!(
            "BPF Stats: {} packets processed, {} dropped ({:.2}%), IPv4 banned: {}, IPv4 recent: {}, IPv6 banned: {}, IPv6 recent: {}",
            self.total_packets_processed,
            self.total_packets_dropped,
            self.drop_rate_percentage,
            self.ipv4_banned_hits,
            self.ipv4_recently_banned_hits,
            self.ipv6_banned_hits,
            self.ipv6_recently_banned_hits
        );

        // Add top dropped IP addresses if any
        if !self.dropped_ip_addresses.ipv4_addresses.is_empty() || !self.dropped_ip_addresses.ipv6_addresses.is_empty() {
            summary.push_str(&format!(", {} unique IPs dropped", self.dropped_ip_addresses.total_unique_dropped_ips));

            // Show top 5 dropped IPv4 addresses
            let mut ipv4_vec: Vec<_> = self.dropped_ip_addresses.ipv4_addresses.iter().collect();
            ipv4_vec.sort_by(|a, b| b.1.cmp(a.1));
            if !ipv4_vec.is_empty() {
                summary.push_str(", Top IPv4 drops: ");
                for (i, (ip, count)) in ipv4_vec.iter().take(5).enumerate() {
                    if i > 0 { summary.push_str(", "); }
                    summary.push_str(&format!("{}:{}", ip, count));
                }
            }

            // Show top 5 dropped IPv6 addresses
            let mut ipv6_vec: Vec<_> = self.dropped_ip_addresses.ipv6_addresses.iter().collect();
            ipv6_vec.sort_by(|a, b| b.1.cmp(a.1));
            if !ipv6_vec.is_empty() {
                summary.push_str(", Top IPv6 drops: ");
                for (i, (ip, count)) in ipv6_vec.iter().take(5).enumerate() {
                    if i > 0 { summary.push_str(", "); }
                    summary.push_str(&format!("{}:{}", ip, count));
                }
            }
        }

        summary
    }
}

impl DroppedIpEvent {
    /// Create a new dropped IP event
    pub fn new(
        ip_address: String,
        ip_version: IpVersion,
        drop_count: u64,
        drop_reason: DropReason,
    ) -> Self {
        let now = Utc::now();
        Self {
            event_type: "dropped_ips".to_string(),
            timestamp: now,
            ip_address,
            ip_version,
            drop_count,
            drop_reason
        }
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Create a summary string for logging
    pub fn summary(&self) -> String {
        format!(
            "IP Drop Event: {} {} dropped {} times (reason: {:?})",
            self.ip_address,
            match self.ip_version {
                IpVersion::IPv4 => "IPv4",
                IpVersion::IPv6 => "IPv6",
            },
            self.drop_count,
            self.drop_reason
        )
    }
}

impl DroppedIpEvents {
    /// Create a new collection of dropped IP events
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            events: Vec::new(),
            total_events: 0,
            unique_ips: 0,
        }
    }

    /// Add a dropped IP event
    pub fn add_event(&mut self, event: DroppedIpEvent) {
        self.events.push(event);
        self.total_events += 1;
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Create a summary string for logging
    pub fn summary(&self) -> String {
        format!(
            "Dropped IP Events: {} events from {} unique IPs",
            self.total_events,
            self.unique_ips
        )
    }

    /// Get top dropped IPs by count
    pub fn get_top_dropped_ips(&self, limit: usize) -> Vec<DroppedIpEvent> {
        let mut events = self.events.clone();
        events.sort_by(|a, b| b.drop_count.cmp(&a.drop_count));
        events.into_iter().take(limit).collect()
    }
}

/// Statistics collector for BPF access rules
#[derive(Clone)]
pub struct BpfStatsCollector {
    skels: Vec<Arc<FilterSkel<'static>>>,
    enabled: bool,
}

impl BpfStatsCollector {
    /// Create a new statistics collector
    pub fn new(skels: Vec<Arc<FilterSkel<'static>>>, enabled: bool) -> Self {
        Self { skels, enabled }
    }

    /// Enable or disable statistics collection
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if statistics collection is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Collect statistics from all BPF skeletons
    pub fn collect_stats(&self) -> Result<Vec<BpfAccessStats>, Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(vec![]);
        }

        let mut stats = Vec::new();
        for skel in &self.skels {
            match BpfAccessStats::from_bpf_maps(skel) {
                Ok(stat) => stats.push(stat),
                Err(e) => {
                    log::warn!("Failed to collect BPF stats from skeleton: {}", e);
                }
            }
        }
        Ok(stats)
    }

    /// Collect aggregated statistics across all skeletons
    pub fn collect_aggregated_stats(&self) -> Result<BpfAccessStats, Box<dyn std::error::Error>> {
        if !self.enabled {
            return Err("Statistics collection is disabled".into());
        }

        let individual_stats = self.collect_stats()?;
        if individual_stats.is_empty() {
            return Err("No statistics available".into());
        }

        // Aggregate statistics across all skeletons
        let mut aggregated = BpfAccessStats {
            timestamp: Utc::now(),
            total_packets_processed: 0,
            total_packets_dropped: 0,
            ipv4_banned_hits: 0,
            ipv4_recently_banned_hits: 0,
            ipv6_banned_hits: 0,
            ipv6_recently_banned_hits: 0,
            drop_rate_percentage: 0.0,
            dropped_ip_addresses: DroppedIpAddresses {
                ipv4_addresses: HashMap::new(),
                ipv6_addresses: HashMap::new(),
                total_unique_dropped_ips: 0,
            },
        };

        for stat in individual_stats {
            aggregated.total_packets_processed += stat.total_packets_processed;
            aggregated.total_packets_dropped += stat.total_packets_dropped;
            aggregated.ipv4_banned_hits += stat.ipv4_banned_hits;
            aggregated.ipv4_recently_banned_hits += stat.ipv4_recently_banned_hits;
            aggregated.ipv6_banned_hits += stat.ipv6_banned_hits;
            aggregated.ipv6_recently_banned_hits += stat.ipv6_recently_banned_hits;

            // Merge IP addresses
            for (ip, count) in stat.dropped_ip_addresses.ipv4_addresses {
                *aggregated.dropped_ip_addresses.ipv4_addresses.entry(ip).or_insert(0) += count;
            }
            for (ip, count) in stat.dropped_ip_addresses.ipv6_addresses {
                *aggregated.dropped_ip_addresses.ipv6_addresses.entry(ip).or_insert(0) += count;
            }
        }

        // Update total unique dropped IPs count
        aggregated.dropped_ip_addresses.total_unique_dropped_ips =
            aggregated.dropped_ip_addresses.ipv4_addresses.len() as u64 +
            aggregated.dropped_ip_addresses.ipv6_addresses.len() as u64;

        // Recalculate drop rate for aggregated data
        aggregated.drop_rate_percentage = if aggregated.total_packets_processed > 0 {
            (aggregated.total_packets_dropped as f64 / aggregated.total_packets_processed as f64) * 100.0
        } else {
            0.0
        };

        Ok(aggregated)
    }

    /// Log current statistics
    pub fn log_stats(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        match self.collect_aggregated_stats() {
            Ok(stats) => {
                // Output as JSON for structured logging
                match stats.to_json() {
                    Ok(json) => {
                        log::info!("{}", json);
                    }
                    Err(e) => {
                        // Fallback to text summary if JSON serialization fails
                        log::warn!("Failed to serialize BPF stats to JSON: {}, using text summary", e);
                        log::info!("{}", stats.summary());
                    }
                }
                Ok(())
            }
            Err(e) => {
                log::warn!("Failed to collect BPF statistics: {}", e);
                Err(e)
            }
        }
    }

    /// Collect dropped IP events from BPF maps
    pub fn collect_dropped_ip_events(&self) -> Result<DroppedIpEvents, Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(DroppedIpEvents::new());
        }

        let mut events = DroppedIpEvents::new();

        for skel in &self.skels {
            let dropped_ips = BpfAccessStats::collect_dropped_ip_addresses(skel)?;

            // Convert IPv4 addresses to events
            for (ip_str, count) in dropped_ips.ipv4_addresses {
                let event = DroppedIpEvent::new(
                    ip_str,
                    IpVersion::IPv4,
                    count,
                    DropReason::AccessRules, // Default reason, could be enhanced
                );
                events.add_event(event);
            }

            // Convert IPv6 addresses to events
            for (ip_str, count) in dropped_ips.ipv6_addresses {
                let event = DroppedIpEvent::new(
                    ip_str,
                    IpVersion::IPv6,
                    count,
                    DropReason::AccessRules, // Default reason, could be enhanced
                );
                events.add_event(event);
            }
        }

        events.unique_ips = events.events.len() as u64;
        Ok(events)
    }

    /// Log dropped IP events
    pub fn log_dropped_ip_events(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        let events = self.collect_dropped_ip_events()?;

        if events.total_events > 0 {
            log::debug!("{}", events.summary());

            // Log top 5 dropped IPs
            let top_ips = events.get_top_dropped_ips(5);
            for event in top_ips {
                log::debug!("  {}", event.summary());
            }

            // Log as JSON for structured logging
            if let Ok(json) = events.to_json() {
                log::debug!("Dropped IP Events JSON: {}", json);
            }

            // Send events to unified queue
            for event in events.events {
                send_event(UnifiedEvent::DroppedIp(event));
            }

            // Reset the counters after logging
            self.reset_dropped_ip_counters()?;
        } else {
            log::debug!("No dropped IP events found");
        }

        Ok(())
    }


    /// Reset dropped IP address counters in BPF maps
    pub fn reset_dropped_ip_counters(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        log::debug!("Resetting dropped IP address counters");

        for skel in &self.skels {
            // Reset IPv4 counters
            match skel.maps.dropped_ipv4_addresses.lookup_batch(1000, libbpf_rs::MapFlags::ANY, libbpf_rs::MapFlags::ANY) {
                Ok(batch_iter) => {
                    let mut reset_count = 0;
                    for (key_bytes, _) in batch_iter {
                        if key_bytes.len() >= 4 {
                            let zero_count = 0u64.to_le_bytes();
                            if let Err(e) = skel.maps.dropped_ipv4_addresses.update(&key_bytes, &zero_count, libbpf_rs::MapFlags::ANY) {
                                log::warn!("Failed to reset IPv4 counter: {}", e);
                            } else {
                                reset_count += 1;
                            }
                        }
                    }
                    log::debug!("Reset {} IPv4 dropped IP counters", reset_count);
                }
                Err(e) => {
                    log::warn!("Failed to reset IPv4 counters: {}", e);
                }
            }

            // Reset IPv6 counters
            match skel.maps.dropped_ipv6_addresses.lookup_batch(1000, libbpf_rs::MapFlags::ANY, libbpf_rs::MapFlags::ANY) {
                Ok(batch_iter) => {
                    let mut reset_count = 0;
                    for (key_bytes, _) in batch_iter {
                        if key_bytes.len() >= 16 {
                            let zero_count = 0u64.to_le_bytes();
                            if let Err(e) = skel.maps.dropped_ipv6_addresses.update(&key_bytes, &zero_count, libbpf_rs::MapFlags::ANY) {
                                log::warn!("Failed to reset IPv6 counter: {}", e);
                            } else {
                                reset_count += 1;
                            }
                        }
                    }
                    log::debug!("Reset {} IPv6 dropped IP counters", reset_count);
                }
                Err(e) => {
                    log::warn!("Failed to reset IPv6 counters: {}", e);
                }
            }
        }

        Ok(())
    }
}

/// Configuration for BPF statistics collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfStatsConfig {
    pub enabled: bool,
    pub log_interval_secs: u64,
}

impl Default for BpfStatsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_interval_secs: 60, // Log stats every minute
        }
    }
}

impl BpfStatsConfig {
    /// Create a new configuration
    pub fn new(enabled: bool, log_interval_secs: u64) -> Self {
        Self {
            enabled,
            log_interval_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_stats_summary() {
        let mut ipv4_addresses = HashMap::new();
        ipv4_addresses.insert("192.168.1.1".to_string(), 10);
        ipv4_addresses.insert("10.0.0.1".to_string(), 5);

        let stats = BpfAccessStats {
            timestamp: Utc::now(),
            total_packets_processed: 1000,
            total_packets_dropped: 50,
            ipv4_banned_hits: 30,
            ipv4_recently_banned_hits: 10,
            ipv6_banned_hits: 5,
            ipv6_recently_banned_hits: 5,
            drop_rate_percentage: 5.0,
            dropped_ip_addresses: DroppedIpAddresses {
                ipv4_addresses,
                ipv6_addresses: HashMap::new(),
                total_unique_dropped_ips: 2,
            },
        };

        let summary = stats.summary();
        assert!(summary.contains("1000 packets processed"));
        assert!(summary.contains("50 dropped"));
        assert!(summary.contains("5.00%"));
        assert!(summary.contains("2 unique IPs dropped"));
        assert!(summary.contains("192.168.1.1:10"));
    }

    #[test]
    fn test_bpf_stats_json() {
        let stats = BpfAccessStats {
            timestamp: Utc::now(),
            total_packets_processed: 100,
            total_packets_dropped: 10,
            ipv4_banned_hits: 5,
            ipv4_recently_banned_hits: 3,
            ipv6_banned_hits: 1,
            ipv6_recently_banned_hits: 1,
            drop_rate_percentage: 10.0,
            dropped_ip_addresses: DroppedIpAddresses {
                ipv4_addresses: HashMap::new(),
                ipv6_addresses: HashMap::new(),
                total_unique_dropped_ips: 0,
            },
        };

        let json = stats.to_json().unwrap();
        assert!(json.contains("total_packets_processed"));
        assert!(json.contains("drop_rate_percentage"));
        assert!(json.contains("dropped_ip_addresses"));
    }
}
