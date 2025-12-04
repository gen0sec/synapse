use crate::cli::FileMonitorConfig;
use crate::worker::log::{send_event, UnifiedEvent};

use chrono::{DateTime, Utc};
use hotwatch::{Event, EventKind, Hotwatch};
use hotwatch::notify::event::ModifyKind;
use rsure::{parse_store, update, StoreTags};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::watch;
use walkdir::WalkDir;
use serde_json;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKind {
    Created,
    Modified,
    Deleted,
    Renamed,
    Other,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileChangeEvent {
    /// Inner type tag, mainly for human readability; UnifiedEvent will wrap too.
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub root_path: String,
    pub file_path: String,
    pub change_kind: FileChangeKind,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
}

impl FileChangeEvent {
    pub fn new(
        root: &Path,
        file: &Path,
        kind: FileChangeKind,
        old_hash: Option<String>,
        new_hash: Option<String>,
    ) -> Self {
        Self {
            event_type: "file_change".to_string(),
            timestamp: Utc::now(),
            root_path: root.display().to_string(),
            file_path: file.display().to_string(),
            change_kind: kind,
            old_hash,
            new_hash,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

type HashMapState = Arc<Mutex<HashMap<PathBuf, String>>>;

/// Compute SHA256 of a file
fn compute_sha256(path: &Path) -> anyhow::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Build baseline hashes for all regular files under `root`
fn build_baseline_for_root(root: &Path, recursive: bool, state: &HashMapState) -> anyhow::Result<()> {
    let mut updates = Vec::new();

    if root.is_file() {
        if let Ok(h) = compute_sha256(root) {
            updates.push((root.to_path_buf(), h));
        }
    } else if root.is_dir() {
        let mut walker = WalkDir::new(root).follow_links(false);
        if !recursive {
            walker = walker.max_depth(1);
        }

        for entry in walker {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Ok(h) = compute_sha256(path) {
                    updates.push((path.to_path_buf(), h));
                }
            }
        }
    }

    if !updates.is_empty() {
        let mut map = state.lock().unwrap();
        for (path, hash) in updates {
            map.insert(path, hash);
        }
    }

    Ok(())
}

fn load_state(state_path: &Path, state: &HashMapState) -> anyhow::Result<()> {
    if !state_path.exists() {
        return Ok(());
    }
    let data = std::fs::read_to_string(state_path)?;
    let loaded: HashMap<String, String> = serde_json::from_str(&data)?;
    let mut map = state.lock().unwrap();
    for (k, v) in loaded {
        map.insert(PathBuf::from(k), v);
    }
    Ok(())
}

fn persist_state(state: &HashMapState, state_path: &Path) -> anyhow::Result<()> {
    let map = state.lock().unwrap();
    let serializable: HashMap<String, String> = map
        .iter()
        .map(|(k, v)| (k.display().to_string(), v.clone()))
        .collect();
    let data = serde_json::to_string(&serializable)?;
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(state_path, data)?;
    Ok(())
}

fn path_is_in_scope(root: &Path, path: &Path, recursive: bool) -> bool {
    if let Ok(relative) = path.strip_prefix(root) {
        if !recursive && relative.components().count() > 1 {
            return false;
        }
        true
    } else {
        false
    }
}

/// Handle a single hotwatch event: compute new hash, compare to baseline, log & enqueue event
fn handle_event_for_root(
    root: &Path,
    event: &Event,
    state: &HashMapState,
    recursive: bool,
    store_path: Option<&String>,
    store_enabled: Option<&AtomicBool>,
    state_path: Option<&Path>,
) {
    use FileChangeKind::*;

    // helper to update rsure store, disabling after first failure
    let update_store = |root: &Path, store_path: Option<&String>, store_enabled: Option<&AtomicBool>| {
        if let (Some(path), Some(flag)) = (store_path, store_enabled) {
            if !flag.load(Ordering::Relaxed) {
                return;
            }
            let tags = StoreTags::default();
            match parse_store(path) {
                Ok(store) => {
                    if let Err(e) = update(root, store.as_ref(), true, &tags) {
                        log::warn!("Failed to update rsure store for {}: {}", root.display(), e);
                        flag.store(false, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    log::warn!("Failed to open rsure store {}: {}", path, e);
                    flag.store(false, Ordering::Relaxed);
                }
            }
        }
    };

    // Rename events carry both from/to paths; handle them as a single atomic update.
    if matches!(event.kind, EventKind::Modify(ModifyKind::Name(_))) && event.paths.len() >= 2 {
        let from = &event.paths[0];
        let to = &event.paths[1];

        if !path_is_in_scope(root, from, recursive) || !path_is_in_scope(root, to, recursive) {
            return;
        }

        let old_hash = state.lock().unwrap().remove(from);
        let new_hash = compute_sha256(to).ok();

        if let Some(ref h) = new_hash {
            let _ = state.lock().unwrap().insert(to.clone(), h.clone());
        }

        update_store(root, store_path, store_enabled);
        if let Some(p) = state_path {
            let _ = persist_state(state, p);
        }

        let evt = FileChangeEvent::new(root, to, Renamed, old_hash.clone(), new_hash.clone());
        match evt.to_json() {
            Ok(json) => log::warn!("File integrity event: {}", json),
            Err(e) => log::warn!(
                "File integrity event (JSON failed: {}): root={} path={:?} kind={:?} old={:?} new={:?}",
                e,
                evt.root_path,
                to,
                Renamed,
                old_hash,
                new_hash,
            ),
        }
        send_event(UnifiedEvent::FileChange(evt));
        return;
    }

    let kind = match &event.kind {
        EventKind::Create(_) => Some(Created),
        EventKind::Modify(ModifyKind::Data(_))
        | EventKind::Modify(ModifyKind::Any)
        | EventKind::Modify(ModifyKind::Metadata(_)) => Some(Modified),
        EventKind::Remove(_) => Some(Deleted),
        EventKind::Modify(ModifyKind::Name(_)) => None, // already handled above
        _ => None,
    };
    let kind = match kind {
        Some(k) => k,
        None => return,
    };

    for path in &event.paths {
        // Skip directories; we care about files
        if path.is_dir() || !path_is_in_scope(root, path, recursive) {
            continue;
        }

        let old_hash = { state.lock().unwrap().get(path).cloned() };

        let new_hash = match kind {
            Deleted => {
                let _ = state.lock().unwrap().remove(path);
                None
            }
            _ => match compute_sha256(path) {
                Ok(h) => {
                    let _ = state.lock().unwrap().insert(path.clone(), h.clone());
                    Some(h)
                }
                Err(e) => {
                    if e.downcast_ref::<std::io::Error>().map(|ioe| ioe.kind()) == Some(ErrorKind::NotFound) {
                        log::debug!("File missing during hash for {:?}: {}", path, e);
                        None
                    } else {
                        log::warn!("Failed to compute hash for {:?}: {}", path, e);
                        None
                    }
                }
            },
        };

        update_store(root, store_path, store_enabled);
        if let Some(p) = state_path {
            let _ = persist_state(state, p);
        }

        let evt = FileChangeEvent::new(root, path, kind.clone(), old_hash.clone(), new_hash.clone());

        match evt.to_json() {
            Ok(json) => {
                log::warn!("File integrity event: {}", json);
            }
            Err(e) => {
                log::warn!(
                    "File integrity event (JSON failed: {}): root={} path={:?} kind={:?} old={:?} new={:?}",
                    e,
                    evt.root_path,
                    path,
                    kind,
                    old_hash,
                    new_hash,
                );
            }
        }

        send_event(UnifiedEvent::FileChange(evt));
    }
}

/// Start rsure baseline for all configured roots
fn init_rsure_store(config: &FileMonitorConfig) -> anyhow::Result<Option<String>> {
    if config.paths.is_empty() {
        return Ok(None);
    }

    let store_path = match &config.rsure_store_path {
        Some(p) => PathBuf::from(p),
        None => {
            log::warn!(
                "file_monitor.rsure_store_path not configured; rsure baseline will be skipped"
            );
            return Ok(None);
        }
    };

    if let Some(parent) = store_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let store = match parse_store(store_path.to_string_lossy().as_ref()) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "Failed to open rsure store {}: {}; rsure disabled",
                store_path.display(),
                e
            );
            return Ok(None);
        }
    };
    let tags = StoreTags::default();
    let mut any_success = false;

    for root in &config.paths {
        let root_path = PathBuf::from(root);
        if !root_path.exists() {
            log::warn!(
                "Skipping rsure baseline for {}, path does not exist",
                root
            );
            continue;
        }

        if let Err(e) = update(&root_path, store.as_ref(), false, &tags) {
            log::warn!(
                "Failed to initialize rsure baseline for {}: {}",
                root_path.display(),
                e
            );
            continue;
        }
        any_success = true;

        log::info!(
            "Initialized rsure baseline for {} into store {}",
            root_path.display(),
            store_path.display()
        );
    }

    if any_success {
        Ok(Some(store_path.to_string_lossy().to_string()))
    } else {
        log::warn!(
            "rsure baseline could not be created for any configured path; rsure disabled"
        );
        Ok(None)
    }
}

/// Start the file integrity monitor (hotwatch + baseline hashing + rsure)
pub fn start_file_integrity_monitor(
    config: FileMonitorConfig,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    if !config.enabled || config.paths.is_empty() {
        log::info!("File integrity monitor disabled or no paths configured");
        return Ok(tokio::spawn(async {}));
    }

    let store_path = match init_rsure_store(&config) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Failed to initialize rsure baseline: {}", e);
            None
        }
    };
    let store_enabled = Arc::new(AtomicBool::new(store_path.is_some()));
    let state_path = store_path
        .as_ref()
        .and_then(|p| Path::new(p).parent().map(|d| d.join("filemon_state.json")));

    let state: HashMapState = Arc::new(Mutex::new(HashMap::new()));

    if let Some(ref p) = state_path {
        if let Err(e) = load_state(p, &state) {
            log::warn!("Failed to load persisted state {}: {}", p.display(), e);
        }
    }

    for root in &config.paths {
        let root_path = PathBuf::from(root);
        if !root_path.exists() {
            log::warn!("Configured file_monitor path does not exist: {}", root);
            continue;
        }

        if let Err(e) = build_baseline_for_root(&root_path, config.recursive, &state) {
            log::warn!("Failed to build baseline for {}: {}", root, e);
        } else {
            log::info!("Built baseline hashes for {}", root_path.display());
        }
    }

    if let Some(ref p) = state_path {
        if let Err(e) = persist_state(&state, p) {
            log::warn!("Failed to persist state {}: {}", p.display(), e);
        }
    }

    let recursive = config.recursive;
    let handle = tokio::spawn(async move {
        let mut hotwatch = match Hotwatch::new() {
            Ok(h) => h,
            Err(e) => {
                log::error!("Failed to initialize hotwatch: {}", e);
                return;
            }
        };

        for root in &config.paths {
            let root_path = PathBuf::from(root);
            if !root_path.exists() {
                continue;
            }

            let state_clone = Arc::clone(&state);
            let root_for_closure = root_path.clone();
            let store_clone = store_path.clone();
            let store_enabled_clone = store_enabled.clone();
            let state_path_clone = state_path.clone();

            if let Err(e) = hotwatch.watch(root_path.clone(), move |event: Event| {
                handle_event_for_root(
                    &root_for_closure,
                    &event,
                    &state_clone,
                    recursive,
                    store_clone.as_ref(),
                    Some(&store_enabled_clone),
                    state_path_clone.as_deref(),
                );
            }) {
                log::error!(
                    "Failed to add hotwatch for {}: {}",
                    root_path.display(),
                    e
                );
            } else {
                log::info!("File integrity monitor watching {}", root_path.display());
            }
        }

        loop {
            if shutdown.changed().await.is_err() {
                break;
            }
            if *shutdown.borrow() {
                log::info!("File integrity monitor received shutdown signal");
                break;
            }
        }

        log::info!("File integrity monitor stopped");
    });

    Ok(handle)
}
