use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::access_log::{get_log_sender_config, LogSenderConfig};
use crate::http_client;

/// Maximum batch size allowed by the API server
const API_MAX_BATCH_SIZE: usize = 1000;

/// Unified event types that can be sent to the /events endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum UnifiedEvent {
    #[serde(rename = "http_access_log")]
    HttpAccessLog(crate::access_log::HttpAccessLog),
    #[serde(rename = "dropped_ip")]
    DroppedIp(crate::bpf_stats::DroppedIpEvent),
    #[serde(rename = "tcp_fingerprint")]
    TcpFingerprint(crate::utils::tcp_fingerprint::TcpFingerprintEvent),
}

impl UnifiedEvent {
    /// Get the event type as a string
    pub fn event_type(&self) -> &'static str {
        match self {
            UnifiedEvent::HttpAccessLog(_) => "http_access_log",
            UnifiedEvent::DroppedIp(_) => "dropped_ip",
            UnifiedEvent::TcpFingerprint(_) => "tcp_fingerprint",
        }
    }

    /// Get the timestamp of the event
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            UnifiedEvent::HttpAccessLog(event) => event.timestamp,
            UnifiedEvent::DroppedIp(event) => event.timestamp,
            UnifiedEvent::TcpFingerprint(event) => event.timestamp,
        }
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Buffer for storing events before batch sending
#[derive(Debug)]
pub struct EventBuffer {
    events: Vec<UnifiedEvent>,
    failed_events: Vec<UnifiedEvent>, // Store events that failed to send
    total_size_bytes: usize,
    failed_size_bytes: usize,
    last_flush_time: Instant,
    last_retry_time: Instant, // Track when we last tried to resend failed events
}

impl EventBuffer {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            failed_events: Vec::new(),
            total_size_bytes: 0,
            failed_size_bytes: 0,
            last_flush_time: Instant::now(),
            last_retry_time: Instant::now(),
        }
    }

    fn add_event(&mut self, event: UnifiedEvent) -> usize {
        // Estimate event size (rough approximation)
        let event_size = estimate_event_size(&event);
        self.events.push(event);
        self.total_size_bytes += event_size;
        self.events.len()
    }

    fn should_flush(&self, config: &LogSenderConfig) -> bool {
        self.events.len() >= config.batch_size_limit ||
        self.total_size_bytes >= config.batch_size_bytes ||
        self.last_flush_time.elapsed().as_secs() >= config.batch_timeout_secs
    }

    fn take_events(&mut self) -> Vec<UnifiedEvent> {
        self.total_size_bytes = 0;
        self.last_flush_time = Instant::now();
        std::mem::take(&mut self.events)
    }

    fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn add_failed_events(&mut self, events: Vec<UnifiedEvent>) {
        for event in events {
            let event_size = estimate_event_size(&event);
            self.failed_events.push(event);
            self.failed_size_bytes += event_size;
        }
    }

    fn should_retry_failed_events(&self) -> bool {
        // Retry failed events every 30 seconds
        !self.failed_events.is_empty() &&
        self.last_retry_time.elapsed().as_secs() >= 30
    }

    fn take_failed_events(&mut self) -> Vec<UnifiedEvent> {
        self.failed_size_bytes = 0;
        self.last_retry_time = Instant::now();
        std::mem::take(&mut self.failed_events)
    }

    fn has_failed_events(&self) -> bool {
        !self.failed_events.is_empty()
    }
}

/// Estimate the size of an event in bytes
fn estimate_event_size(event: &UnifiedEvent) -> usize {
    // Rough estimation based on JSON serialization
    // This is an approximation - actual size may vary
    let base_size = 500; // Base overhead

    match event {
        UnifiedEvent::HttpAccessLog(log) => {
            base_size + log.http.body.len() + log.response.body.len() +
            log.http.headers.len() * 50 // Rough estimate for headers
        }
        UnifiedEvent::DroppedIp(_) => base_size + 200, // Dropped IP events are relatively small
        UnifiedEvent::TcpFingerprint(_) => base_size + 100, // TCP fingerprint events are small
    }
}

/// Global event buffer for batching events
static EVENT_BUFFER: std::sync::OnceLock<Arc<RwLock<EventBuffer>>> = std::sync::OnceLock::new();

/// Channel for sending events to the batch processor
static EVENT_CHANNEL: std::sync::OnceLock<mpsc::UnboundedSender<UnifiedEvent>> = std::sync::OnceLock::new();

pub fn get_event_buffer() -> Arc<RwLock<EventBuffer>> {
    EVENT_BUFFER
        .get_or_init(|| Arc::new(RwLock::new(EventBuffer::new())))
        .clone()
}

pub fn get_event_channel() -> Option<&'static mpsc::UnboundedSender<UnifiedEvent>> {
    EVENT_CHANNEL.get()
}

pub fn set_event_channel(sender: mpsc::UnboundedSender<UnifiedEvent>) {
    let _ = EVENT_CHANNEL.set(sender);
}

/// Send an event to the unified queue
pub fn send_event(event: UnifiedEvent) {
    if let Some(sender) = get_event_channel() {
        if let Err(e) = sender.send(event) {
            log::warn!("Failed to send event to queue: {}", e);
        }
    } else {
        // Event channel not initialized - this is expected when log_sending_enabled is false
        log::trace!("Event channel not initialized, skipping event queuing");
    }
}

/// Send a batch of events to the /events endpoint
/// Automatically splits large batches into chunks of API_MAX_BATCH_SIZE
async fn send_event_batch(events: Vec<UnifiedEvent>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if events.is_empty() {
        return Ok(());
    }

    let config = {
        let config_store = get_log_sender_config();
        let config_guard = config_store.read().unwrap();
        config_guard.as_ref().cloned()
    };

    let config = match config {
        Some(config) => {
            if !config.should_send_logs() {
                return Ok(());
            }
            config
        }
        None => return Ok(()),
    };

    // Use shared HTTP client with keepalive instead of creating new client
    let client = http_client::get_global_reqwest_client()
        .map_err(|e| format!("Failed to get global HTTP client: {}", e))?;

    let url = format!("{}/events", config.base_url);

    // Split events into chunks of API_MAX_BATCH_SIZE to respect API limits
    let chunks: Vec<_> = events.chunks(API_MAX_BATCH_SIZE).collect();
    let total_events = events.len();

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        let json = serde_json::to_string(chunk)?;

        log::debug!("Sending chunk {}/{} ({} events) to {}",
            chunk_idx + 1, chunks.len(), chunk.len(), url);

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", config.api_key))
            .header("Content-Type", "application/json")
            .body(json)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            log::warn!("Failed to send event batch chunk {}/{} to /events endpoint: {} - {} (chunk size: {}, total batch: {})",
                chunk_idx + 1, chunks.len(), status, error_text, chunk.len(), total_events);
            return Err(format!("HTTP {}: {}", status, error_text).into());
        } else {
            log::debug!("Successfully sent event batch chunk {}/{} to /events endpoint (chunk size: {})",
                chunk_idx + 1, chunks.len(), chunk.len());
        }
    }

    log::debug!("Successfully sent all {} events in {} chunk(s) to /events endpoint", total_events, chunks.len());
    Ok(())
}

/// Start the background batch event processor
pub fn start_batch_event_processor() {
    let (sender, mut receiver) = mpsc::unbounded_channel::<UnifiedEvent>();
    set_event_channel(sender);

    tokio::spawn(async move {
        let mut buffer = EventBuffer::new();
        let mut flush_interval = tokio::time::interval(Duration::from_secs(1)); // Check every second

        loop {
            tokio::select! {
                // Receive new events
                event = receiver.recv() => {
                    match event {
                        Some(event) => {
                            let count = buffer.add_event(event);
                            log::trace!("Added event to buffer, total: {}", count);
                        }
                        None => {
                            log::info!("Event channel closed, flushing remaining events");
                            // Flush any remaining events before exiting
                            if !buffer.is_empty() {
                                let events = buffer.take_events();
                                if let Err(e) = send_event_batch(events.clone()).await {
                                    log::warn!("Failed to send final event batch: {}, storing locally", e);
                                    buffer.add_failed_events(events);
                                }
                            }
                            // Also try to flush any remaining failed events
                            if buffer.has_failed_events() {
                                let failed_events = buffer.take_failed_events();
                                log::warn!("Storing {} failed events locally (endpoint unavailable)", failed_events.len());
                                // In a real implementation, you might want to write these to disk
                                // For now, we just log the count
                            }
                            break;
                        }
                    }
                }

                // Periodic flush check
                _ = flush_interval.tick() => {
                    let config = {
                        let config_store = get_log_sender_config();
                        let config_guard = config_store.read().unwrap();
                        config_guard.as_ref().cloned()
                    };

                    if let Some(config) = config {
                        // Handle regular event flushing
                        if buffer.should_flush(&config) {
                            let events = buffer.take_events();
                            if !events.is_empty() {
                                log::debug!("Flushing event batch: {} events", events.len());
                                if let Err(e) = send_event_batch(events.clone()).await {
                                    log::warn!("Failed to send event batch: {}, storing locally for retry", e);
                                    buffer.add_failed_events(events);
                                }
                            }
                        }

                        // Handle retry of failed events
                        if buffer.should_retry_failed_events() {
                            let failed_events = buffer.take_failed_events();
                            if !failed_events.is_empty() {
                                log::debug!("Retrying failed event batch: {} events", failed_events.len());
                                if let Err(e) = send_event_batch(failed_events.clone()).await {
                                    log::warn!("Failed to retry event batch: {}, storing locally again", e);
                                    buffer.add_failed_events(failed_events);
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf_stats::{DroppedIpEvent, IpVersion, DropReason};

    #[test]
    fn test_unified_event_types() {
        let dropped_ip_event = DroppedIpEvent::new(
            "192.168.1.1".to_string(),
            IpVersion::IPv4,
            5,
            DropReason::AccessRules,
        );

        let unified_event = UnifiedEvent::DroppedIp(dropped_ip_event);
        assert_eq!(unified_event.event_type(), "dropped_ip");

        let json = unified_event.to_json().unwrap();
        assert!(json.contains("dropped_ip"));
    }

    #[test]
    fn test_event_buffer_operations() {
        let mut buffer = EventBuffer::new();
        assert!(buffer.is_empty());

        let event = UnifiedEvent::DroppedIp(DroppedIpEvent::new(
            "192.168.1.1".to_string(),
            IpVersion::IPv4,
            5,
            DropReason::AccessRules,
        ));

        let count = buffer.add_event(event);
        assert_eq!(count, 1);
        assert!(!buffer.is_empty());

        let events = buffer.take_events();
        assert_eq!(events.len(), 1);
        assert!(buffer.is_empty());
    }
}
