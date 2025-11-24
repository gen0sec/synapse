use pingora_core::protocols::ClientHelloWrapper;
use crate::utils::tls_fingerprint::Fingerprint;
use log::{debug, warn};
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::Mutex;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// TLS fingerprint entry with timestamp for fallback matching
#[derive(Clone)]
pub struct FingerprintEntry {
    pub fingerprint: Arc<Fingerprint>,
    pub stored_at: SystemTime,
}

/// Global storage for TLS fingerprints keyed by connection peer address
/// This is a temporary storage until the fingerprint can be moved to session context
static TLS_FINGERPRINTS: OnceLock<Mutex<HashMap<String, FingerprintEntry>>> = OnceLock::new();

fn get_fingerprint_map() -> &'static Mutex<HashMap<String, FingerprintEntry>> {
    TLS_FINGERPRINTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Public function to access the fingerprint map
/// This is used by tls_acceptor_wrapper to store fingerprints
pub fn get_fingerprint_map_public() -> &'static Mutex<HashMap<String, FingerprintEntry>> {
    get_fingerprint_map()
}

/// Generate JA4 fingerprint from ClientHello raw bytes
/// This is called after ClientHello is extracted by ClientHelloWrapper
pub fn generate_fingerprint_from_client_hello(
    hello: &pingora_core::protocols::tls::client_hello::ClientHello,
    peer_addr: Option<pingora_core::protocols::l4::socket::SocketAddr>,
) -> Option<Arc<Fingerprint>> {
    let peer_addr_str = peer_addr.as_ref()
        .and_then(|a| a.as_inet())
        .map(|inet| format!("{}:{}", inet.ip(), inet.port()))
        .unwrap_or_else(|| "unknown".to_string());

    debug!("Generating fingerprint from ClientHello: Peer: {}, SNI={:?}, ALPN={:?}, raw_len={}",
           peer_addr_str, hello.sni, hello.alpn, hello.raw.len());

    // Generate JA4 fingerprint from raw ClientHello bytes
    if let Some(mut fingerprint) = crate::utils::tls_fingerprint::fingerprint_client_hello(&hello.raw) {
        // Always prefer SNI and ALPN from Pingora's parsed ClientHello if available
        // Pingora's parsing is more reliable than raw bytes parsing
        if hello.sni.is_some() {
            fingerprint.sni = hello.sni.clone();
        }

        // ALPN: Pingora returns Vec<String>, use first one if available
        if !hello.alpn.is_empty() {
            fingerprint.alpn = hello.alpn.first().cloned();
        }

        let fingerprint_arc: Arc<Fingerprint> = Arc::new(fingerprint);

        // Store fingerprint temporarily if we have peer address
        // Convert pingora SocketAddr to std::net::SocketAddr for storage
        if let Some(ref addr) = peer_addr {
            if let Some(inet) = addr.as_inet() {
                let std_addr = SocketAddr::new(inet.ip().into(), inet.port());
                let key = format!("{}", std_addr);
                if let Ok(mut map) = get_fingerprint_map().lock() {
                    let stored_at = SystemTime::now();
                    let entry = FingerprintEntry {
                        fingerprint: fingerprint_arc.clone(),
                        stored_at,
                    };
                    map.insert(key, entry);
                    debug!("Stored TLS fingerprint for {} at {:?}", std_addr, stored_at);
                }
            }
        }

        // Log fingerprint details at info level
        debug!(
            "TLS Fingerprint extracted - Peer: {}, JA4: {}, JA4_Raw: {}, JA4_Unsorted: {}, JA4_Raw_Unsorted: {}, TLS_Version: {}, Cipher: {:?}, SNI: {:?}, ALPN: {:?}",
            peer_addr_str,
            fingerprint_arc.ja4,
            fingerprint_arc.ja4_raw,
            fingerprint_arc.ja4_unsorted,
            fingerprint_arc.ja4_raw_unsorted,
            fingerprint_arc.tls_version,
            fingerprint_arc.cipher_suite,
            fingerprint_arc.sni,
            fingerprint_arc.alpn
        );

        debug!("Generated JA4 fingerprint: {}", fingerprint_arc.ja4);
        return Some(fingerprint_arc);
    }

    debug!("Failed to generate fingerprint from ClientHello: Peer: {}, raw_len={}", peer_addr_str, hello.raw.len());
    None
}

/// Extract ClientHello from a stream and generate JA4 fingerprint
/// Returns the fingerprint if extraction was successful
/// The stream should be wrapped with ClientHelloWrapper before TLS handshake
#[cfg(unix)]
pub fn extract_and_fingerprint<S: std::os::unix::io::AsRawFd>(
    stream: S,
    peer_addr: Option<std::net::SocketAddr>,
) -> Option<Arc<Fingerprint>> {
    let mut wrapper = ClientHelloWrapper::new(stream);

    match wrapper.extract_client_hello() {
        Ok(Some(hello)) => {
            // Convert std::net::SocketAddr to pingora SocketAddr
            use pingora_core::protocols::l4::socket::SocketAddr as PingoraAddr;
            let pingora_addr = peer_addr.map(|addr| PingoraAddr::Inet(addr));
            generate_fingerprint_from_client_hello(&hello, pingora_addr)
        }
        Ok(None) => {
            debug!("No ClientHello detected in stream");
            None
        }
        Err(e) => {
            debug!("Failed to extract ClientHello: {:?}", e);
            None
        }
    }
}

/// Get stored TLS fingerprint for a peer address
pub fn get_fingerprint(peer_addr: &SocketAddr) -> Option<Arc<Fingerprint>> {
    let key = format!("{}", peer_addr);
    if let Ok(map) = get_fingerprint_map().lock() {
        map.get(&key).map(|entry| entry.fingerprint.clone())
    } else {
        None
    }
}

/// Get stored TLS fingerprint with fallback strategies for PROXY protocol
/// This tries multiple lookup strategies to handle cases where PROXY protocol
/// might cause address mismatches between storage and retrieval
pub fn get_fingerprint_with_fallback(peer_addr: &SocketAddr) -> Option<Arc<Fingerprint>> {
    // First try the exact address match
    if let Some(fp) = get_fingerprint(peer_addr) {
        debug!("Found TLS fingerprint with exact address match: {}", peer_addr);
        return Some(fp);
    }

    // If not found, try to find fingerprints with matching IP (in case port differs)
    // This helps when PROXY protocol causes port mismatches or when ClientHello
    // callback receives a different address than session.client_addr()
    if let Ok(map) = get_fingerprint_map().lock() {
        let peer_ip = peer_addr.ip();
        let mut matching_entries: Vec<(SocketAddr, FingerprintEntry)> = Vec::new();

        for (key, entry) in map.iter() {
            if let Ok(addr) = key.parse::<SocketAddr>() {
                if addr.ip() == peer_ip {
                    matching_entries.push((addr, entry.clone()));
                }
            }
        }

        match matching_entries.len() {
            0 => {
                debug!("No TLS fingerprint found for IP {} (exact match failed, no IP matches)", peer_ip);
            }
            1 => {
                let (matched_addr, entry) = &matching_entries[0];
                debug!("Found TLS fingerprint with matching IP but different port: {} -> {} (fallback lookup)", peer_addr, matched_addr);
                return Some(entry.fingerprint.clone());
            }
            _ => {
                // Multiple matches - use the most recent one (most likely to be the correct connection)
                // This handles cases where PROXY protocol causes address mismatches
                let (matched_addr, entry) = matching_entries.iter()
                    .max_by_key(|(_, e)| e.stored_at)
                    .unwrap();

                warn!("Multiple TLS fingerprints found for IP {} ({} matches), using most recent from {} (stored at {:?})",
                      peer_ip, matching_entries.len(), matched_addr, entry.stored_at);
                return Some(entry.fingerprint.clone());
            }
        }
    }

    None
}

/// Remove stored TLS fingerprint for a peer address
pub fn remove_fingerprint(peer_addr: &SocketAddr) {
    let key = format!("{}", peer_addr);
    if let Ok(mut map) = get_fingerprint_map().lock() {
        map.remove(&key);
    }
}

/// Clean up old fingerprints (older than 5 minutes) to prevent memory leaks
/// This should be called periodically
pub fn cleanup_old_fingerprints() {
    let cutoff = SystemTime::now().checked_sub(std::time::Duration::from_secs(300))
        .unwrap_or(UNIX_EPOCH);

    if let Ok(mut map) = get_fingerprint_map().lock() {
        let initial_len = map.len();
        map.retain(|_, entry| entry.stored_at > cutoff);
        let removed = initial_len - map.len();
        if removed > 0 {
            debug!("Cleaned up {} old TLS fingerprints (kept {} active)", removed, map.len());
        }
    }
}

#[cfg(not(unix))]
pub fn extract_and_fingerprint<S>(
    _stream: S,
    _peer_addr: Option<SocketAddr>,
) -> Option<Arc<Fingerprint>> {
    // ClientHello extraction is only supported on Unix
    None
}



