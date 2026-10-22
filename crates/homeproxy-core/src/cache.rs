use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex, Weak,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder, NamedTempFile};
use tokio::sync::{OwnedRwLockWriteGuard, RwLock};
use tokio_util::sync::CancellationToken;

mod flight;
mod fragments;
pub(crate) mod pins;
mod recovery;
mod revalidate;
#[cfg(test)]
mod store_wait_tests;
mod stream;
pub(crate) mod variants;
pub use flight::{FillClaim, FillGuard, FillRegistry};
pub use recovery::CacheRecoveryToken;
pub use revalidate::CacheSnapshot;
pub use stream::{CacheBody, TeeBody};
pub const MAX_CACHE_ITEM_BYTES: u64 = 1024 * 1024 * 1024;
pub const IO_CHUNK_BYTES: usize = 64 * 1024;

const USAGE_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const MAINTENANCE_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const CACHE_IO_WAIT: Duration = Duration::from_secs(5);
/// Bounded wait of a new store (buffered put, fill admission, 304 refresh) for the
/// exclusive lease. A parallel page load queues many short writers; failing at the
/// first contention stored only a fraction of them. These run before the response
/// is handed to the client and queued writers precede later HIT readers (the tokio
/// RwLock is FIFO), so the cap stays well below CACHE_IO_WAIT. On expiry the
/// response is served uncached as before.
const CACHE_STORE_WAIT: Duration = Duration::from_secs(1);

const MAX_CACHE_ENTRIES: usize = 8_192;
const MAX_ACTIVE_FILLS: usize = 32;
const MAX_CACHE_FILES: usize = MAX_CACHE_ENTRIES * 2 + MAX_ACTIVE_FILLS * 2 + 1;
const MAX_HEADER_COUNT: usize = 128;
const MAX_SERIALIZED_HEADERS_BYTES: usize = 64 * 1024;
const MAX_METADATA_BYTES: usize = MAX_SERIALIZED_HEADERS_BYTES + 1024;

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheUsage {
    /// Logical lengths of bodies, metadata and temporary files, not filesystem allocation.
    pub used_bytes: u64,
    pub entry_count: u64,
    pub pending_maintenance: bool,
    /// False until at least one directory scan completed successfully.
    pub measured: bool,
    pub usage_is_current: bool,
    pub measurement_error: Option<String>,
    pub maintenance_error: Option<String>,
}

struct CacheState {
    epoch: u64,
    readers: BTreeMap<String, usize>,
    reservations: BTreeMap<PathBuf, (String, u64)>,
    pins: pins::PinState,
    invalidated_keys: HashSet<String>,
    key_generations: BTreeMap<String, Weak<AtomicU64>>,
    recovery: recovery::RecoveryState,
    pending_clear: bool,
    pending_prune: bool,
    limit_bytes: u64,
    max_object_bytes: u64,
    limits_configured: bool,
    usage: CacheUsage,
    usage_revision: u64,
    last_measurement_attempt: Option<Instant>,
    maintenance_retry_at: Option<Instant>,
    maintenance_failure: Option<(std::io::ErrorKind, String)>,
    #[cfg(test)]
    scan_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    #[cfg(test)]
    fail_invalidation_persist: bool,
    #[cfg(test)]
    fail_invalidation_stat: bool,
    #[cfg(test)]
    force_refresh_failure: bool,
    #[cfg(test)]
    fail_publication_directory_sync: bool,
    #[cfg(test)]
    commit_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    #[cfg(test)]
    pin_publish_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    #[cfg(test)]
    hit_prepass_gate: Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    #[cfg(test)]
    hit_after_hash_gate: Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    #[cfg(test)]
    fragment_prepass_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    // Test-only: pause after an actual directory scan, before publishing usage.
    #[cfg(test)]
    after_scan_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
}

impl Default for CacheState {
    fn default() -> Self {
        Self {
            epoch: 0,
            readers: BTreeMap::new(),
            reservations: BTreeMap::new(),
            pins: pins::PinState::default(),
            invalidated_keys: HashSet::new(),
            key_generations: BTreeMap::new(),
            recovery: recovery::RecoveryState::default(),
            pending_clear: false,
            pending_prune: false,
            limit_bytes: u64::MAX,
            max_object_bytes: MAX_CACHE_ITEM_BYTES,
            limits_configured: false,
            usage: CacheUsage::default(),
            usage_revision: 0,
            last_measurement_attempt: None,
            maintenance_retry_at: None,
            maintenance_failure: None,
            #[cfg(test)]
            scan_gate: None,
            #[cfg(test)]
            fail_invalidation_persist: false,
            #[cfg(test)]
            fail_invalidation_stat: false,
            #[cfg(test)]
            force_refresh_failure: false,
            #[cfg(test)]
            fail_publication_directory_sync: false,
            #[cfg(test)]
            commit_gate: None,
            #[cfg(test)]
            pin_publish_gate: None,
            #[cfg(test)]
            hit_prepass_gate: None,
            #[cfg(test)]
            hit_after_hash_gate: None,
            #[cfg(test)]
            fragment_prepass_gate: None,
            #[cfg(test)]
            after_scan_gate: None,
        }
    }
}

impl CacheState {
    // Caller holds the publication mutex after both immutable files were renamed.
    // Their directory entries must be durable before a recovery record can close.
    fn confirm_publication(&mut self, root: &Path) -> std::io::Result<()> {
        #[cfg(test)]
        let result = if self.fail_publication_directory_sync {
            Err(std::io::Error::other(
                "injected publication directory sync failure",
            ))
        } else {
            recovery::sync_directory(root)
        };
        #[cfg(not(test))]
        let result = recovery::sync_directory(root);
        if let Err(error) = &result {
            self.recovery.record_persistence_failure(error);
            self.maintenance_failure = Some((error.kind(), error.to_string()));
            self.record_change();
        }
        result
    }

    fn record_change(&mut self) {
        self.usage_revision = self.usage_revision.wrapping_add(1);
        self.last_measurement_attempt = None;
        self.usage.usage_is_current = false;
    }
}

/// A finite request/publication fence. Capture it before awaiting the origin.
#[derive(Clone)]
pub struct CacheKeyGuard {
    generation: Arc<AtomicU64>,
    expected: u64,
    state: Weak<StdMutex<CacheState>>,
    recovery_blocked: Arc<std::sync::atomic::AtomicBool>,
}
impl CacheKeyGuard {
    pub fn retire(&self) {
        if let Some(state) = self.state.upgrade() {
            let _state = state.lock().unwrap();
            let _ = self.generation.compare_exchange(
                self.expected,
                self.expected.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }

    pub fn is_current(&self) -> bool {
        !self.recovery_blocked.load(Ordering::Acquire)
            && self.generation.load(Ordering::Acquire) == self.expected
    }
}

#[derive(Clone)]
pub struct CacheStore {
    pub(crate) fills: FillRegistry,
    pub(crate) variants: variants::VariantIndex,
    dns_answers: crate::lan_dns::Answers,
    root: PathBuf,
    recovery_path: PathBuf,
    io_lock: Arc<RwLock<()>>,
    state: Arc<StdMutex<CacheState>>,
}

impl CacheStore {
    #[cfg(test)]
    pub fn new(root: PathBuf) -> Self {
        let recovery_path = root.join(".cache-recovery-v1");
        Self::new_with_recovery(root, recovery_path)
    }

    pub fn new_with_recovery(root: PathBuf, recovery_path: PathBuf) -> Self {
        let recovery = recovery::RecoveryState::load(&recovery_path);
        let invalidated_keys = recovery.blocked_keys.clone();
        let state = CacheState {
            recovery,
            invalidated_keys,
            ..CacheState::default()
        };
        let cache = Self {
            root,
            recovery_path,
            fills: FillRegistry::default(),
            variants: variants::VariantIndex::default(),
            dns_answers: Arc::default(),
            io_lock: Arc::new(RwLock::new(())),
            state: Arc::new(StdMutex::new(state)),
        };
        cache
            .variants
            .configure_persistence(cache.root.clone(), Arc::downgrade(&cache.state));
        cache
    }

    pub(crate) fn dns_answers(&self) -> crate::lan_dns::Answers {
        self.dns_answers.clone()
    }

    pub fn key_guard(&self, key: &str) -> Option<CacheKeyGuard> {
        if !valid_key(key) {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        if state.recovery.blocks_entry(&self.root, key) {
            return None;
        }
        state
            .key_generations
            .retain(|_, generation| generation.strong_count() > 0);
        let generation = state
            .key_generations
            .get(key)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let generation = Arc::new(AtomicU64::new(0));
                state
                    .key_generations
                    .insert(key.to_owned(), Arc::downgrade(&generation));
                generation
            });
        Some(CacheKeyGuard {
            expected: generation.load(Ordering::Acquire),
            generation,
            state: Arc::downgrade(&self.state),
            recovery_blocked: state.recovery.global_blocked.clone(),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.state.lock().unwrap().epoch
    }

    /// Linearizes cancellation with publication: after return, a bound fill cannot publish.
    pub fn cancel_fill(&self, cancellation: &CancellationToken) {
        let _state = self.state.lock().unwrap();
        cancellation.cancel();
    }

    #[cfg(test)]
    pub(crate) fn set_invalidation_persist_failure(&self, failed: bool) {
        self.state.lock().unwrap().fail_invalidation_persist = failed;
    }

    #[cfg(test)]
    pub(crate) fn set_invalidation_stat_failure(&self, failed: bool) {
        self.state.lock().unwrap().fail_invalidation_stat = failed;
    }

    #[cfg(test)]
    pub(crate) fn set_refresh_failure(&self, failed: bool) {
        self.state.lock().unwrap().force_refresh_failure = failed;
    }

    #[cfg(test)]
    pub(crate) fn set_commit_gate(
        &self,
        gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    ) {
        self.state.lock().unwrap().commit_gate = gate;
    }

    pub fn invalidate(&self) {
        let mut state = self.state.lock().unwrap();
        state.epoch = state.epoch.wrapping_add(1);
        self.fills.cancel_all();
    }

    fn valid_epoch(&self, epoch: u64) -> bool {
        let state = self.state.lock().unwrap();
        state.epoch == epoch
            && !state.pending_clear
            && !state.recovery.global_blocked.load(Ordering::Acquire)
    }

    /// Changes invalidate in-flight fills. Maintenance never deletes an active fill or HIT.
    pub fn configure_limits(&self, limit_bytes: u64, max_object_bytes: u64) {
        let mut state = self.state.lock().unwrap();
        let max_object_bytes = max_object_bytes.min(MAX_CACHE_ITEM_BYTES);
        if !state.limits_configured
            || state.limit_bytes != limit_bytes
            || state.max_object_bytes != max_object_bytes
        {
            state.limits_configured = true;
            state.epoch = state.epoch.wrapping_add(1);
            state.limit_bytes = limit_bytes;
            state.max_object_bytes = max_object_bytes;
            state.pending_prune = true;
            state.maintenance_retry_at = None;
            state.maintenance_failure = None;
        }
    }

    // A prospective listener can exist before SettingsStore::save. Only confirmed
    // configuration controls eviction; unconfigured test stores use the call argument.
    fn disk_limit(&self, fallback: u64) -> u64 {
        let state = self.state.lock().unwrap();
        if state.limits_configured {
            state.limit_bytes
        } else {
            fallback
        }
    }

    fn max_object_bytes(&self) -> u64 {
        self.state.lock().unwrap().max_object_bytes
    }

    /// Opportunistic maintenance for HIT lookups and status polling: never queues
    /// behind other writers, so a busy lease is reported as WouldBlock.
    pub async fn maintain(&self) -> std::io::Result<()> {
        if !self.maintenance_pending()? {
            return Ok(());
        }
        let guard = self.io_lock.clone().try_write_owned().map_err(|_| busy())?;
        self.maintain_locked(guard).await.map(drop)
    }

    /// False when nothing is pending; a recent failure is reported until its retry time.
    fn maintenance_pending(&self) -> std::io::Result<bool> {
        let state = self.state.lock().unwrap();
        if !state.pending_clear && !state.pending_prune {
            return Ok(false);
        }
        if state
            .maintenance_retry_at
            .is_some_and(|retry| Instant::now() < retry)
        {
            if let Some((kind, message)) = &state.maintenance_failure {
                return Err(std::io::Error::new(*kind, message.clone()));
            }
        }
        Ok(true)
    }

    /// Exclusive lease for a new store: waits at most CACHE_STORE_WAIT in the
    /// FIFO queue, then completes pending maintenance under the same lease.
    /// Dropping the future (cancelled request) leaves the queue.
    async fn store_lease(&self) -> std::io::Result<OwnedRwLockWriteGuard<()>> {
        self.maintenance_pending()?;
        let guard = tokio::time::timeout(CACHE_STORE_WAIT, self.io_lock.clone().write_owned())
            .await
            .map_err(|_| busy())?;
        self.maintain_locked(guard).await
    }

    async fn maintain_locked(
        &self,
        guard: OwnedRwLockWriteGuard<()>,
    ) -> std::io::Result<OwnedRwLockWriteGuard<()>> {
        // A writer queued ahead may already have completed or failed maintenance.
        if !self.maintenance_pending()? {
            return Ok(guard);
        }
        let cache = self.clone();
        tokio::task::spawn_blocking(move || {
            let (epoch, clear, limit, max_object) = {
                let state = cache.state.lock().unwrap();
                (
                    state.epoch,
                    state.pending_clear,
                    state.limit_bytes,
                    state.max_object_bytes,
                )
            };
            let result = (|| {
                if clear {
                    if !cache.state.lock().unwrap().readers.is_empty()
                        || !cache.state.lock().unwrap().reservations.is_empty()
                    {
                        return Err(busy());
                    }
                    clear_sync(&cache.root, &cache.recovery_path)?;
                    if cache.root.exists() {
                        recovery::sync_directory(&cache.root)?;
                    }
                    let mut state = cache.state.lock().unwrap();
                    cache.clear_recovery_locked(&mut state)?;
                    state.pins = pins::PinState::default();
                    state.invalidated_keys.clear();
                }
                if cache.root.exists() {
                    cache.prune_locked(limit, MAX_CACHE_ENTRIES, max_object, None)?;
                }
                let mut state = cache.state.lock().unwrap();
                if state.epoch != epoch {
                    return Err(busy());
                }
                state.pending_clear = false;
                state.pending_prune = false;
                state.maintenance_retry_at = None;
                state.maintenance_failure = None;
                state.record_change();
                Ok(())
            })();
            if let Err(error) = &result {
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    let mut state = cache.state.lock().unwrap();
                    if state.epoch == epoch {
                        state.maintenance_retry_at =
                            Some(Instant::now() + MAINTENANCE_RETRY_INTERVAL);
                        state.maintenance_failure = Some((error.kind(), error.to_string()));
                    }
                }
            }
            result.map(|()| guard)
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn usage(&self) -> CacheUsage {
        // Metadata-only scans do not hold io_lock and never deny admission to a fill.
        // Revision changes or a writer during the scan mark the result approximate.
        let _ = self.maintain().await;
        let revision = {
            let mut state = self.state.lock().unwrap();
            let due = state
                .last_measurement_attempt
                .is_none_or(|attempt| attempt.elapsed() >= USAGE_REFRESH_INTERVAL);
            let available =
                self.io_lock.clone().try_read_owned().is_ok() && state.reservations.is_empty();
            if !due || !available {
                state.usage.usage_is_current = false;
                state.usage.pending_maintenance = state.pending_clear || state.pending_prune;
                state.usage.maintenance_error = state
                    .maintenance_failure
                    .as_ref()
                    .map(|(_, message)| message.clone());
                return state.usage.clone();
            }
            state.last_measurement_attempt = Some(Instant::now());
            state.usage_revision
        };
        let root = self.root.clone();
        #[cfg(test)]
        let scan_gate = self.state.lock().unwrap().scan_gate.clone();
        #[cfg(test)]
        let after_scan_gate = self.state.lock().unwrap().after_scan_gate.clone();
        let measured = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if let Some((started, resume)) = scan_gate {
                started.wait();
                resume.wait();
            }
            let result = measure_sync(&root);
            #[cfg(test)]
            if let Some((scanned, publish)) = after_scan_gate {
                scanned.wait();
                publish.wait();
            }
            result
        })
        .await;
        let available = self.io_lock.clone().try_read_owned().is_ok()
            && self.state.lock().unwrap().reservations.is_empty();
        let mut state = self.state.lock().unwrap();
        match measured {
            Ok(Ok(mut usage)) => {
                usage.usage_is_current = available && revision == state.usage_revision;
                state.usage = usage;
            }
            Ok(Err(error)) => {
                state.usage.usage_is_current = false;
                state.usage.measurement_error = Some(error.to_string());
            }
            Err(error) => {
                state.usage.usage_is_current = false;
                state.usage.measurement_error = Some(error.to_string());
            }
        }
        state.usage.pending_maintenance = state.pending_clear || state.pending_prune;
        state.usage.maintenance_error = state
            .maintenance_failure
            .as_ref()
            .map(|(_, message)| message.clone());
        state.usage.clone()
    }

    pub async fn get(&self, key: &str) -> Option<CachedEntry> {
        self.lookup(key, false).await
    }

    pub async fn get_including_stale(&self, key: &str) -> Option<CachedEntry> {
        self.lookup(key, true).await
    }

    async fn lookup(&self, key: &str, include_stale: bool) -> Option<CachedEntry> {
        if !valid_key(key) || {
            let state = self.state.lock().unwrap();
            state.invalidated_keys.contains(key) || state.recovery.blocks_entry(&self.root, key)
        } {
            return None;
        }
        let key_guard = self.key_guard(key)?;
        // Readers may keep running during deferred pruning; the configured object cap
        // is checked before opening/hashing the body even when maintenance is busy.
        let _ = self.maintain().await;
        // Pruning errors need not disable valid HITs. pending_clear is still checked
        // by valid_epoch, so explicitly invalidated entries can never reappear.
        let epoch = self.epoch();
        let guard = tokio::time::timeout(CACHE_IO_WAIT, self.io_lock.clone().read_owned())
            .await
            .ok()?;
        if !self.valid_epoch(epoch) {
            return None;
        }
        let cache = self.clone();
        let requested_key = key;
        let key = key.to_string();
        let mut entry = tokio::task::spawn_blocking(move || {
            let lease = EntryLease::new(&cache, &key);
            drop(guard);
            let entry = get_sync(
                &cache.root,
                &key,
                lease,
                cache.max_object_bytes(),
                include_stale,
            )?;
            #[cfg(test)]
            {
                let gate = cache.state.lock().unwrap().hit_after_hash_gate.clone();
                if let Some((gated_key, started, resume)) = gate {
                    if gated_key == key {
                        started.wait();
                        resume.wait();
                    }
                }
            }
            (cache.valid_epoch(epoch)
                && !cache.state.lock().unwrap().invalidated_keys.contains(&key))
            .then_some(entry)
        })
        .await
        .ok()
        .flatten()?;
        let snapshot = self
            .snapshot_verified_entry(requested_key, epoch, key_guard, &mut entry)
            .await?;
        if !include_stale && snapshot.remaining_ttl.is_zero() {
            return None;
        }
        Some(entry)
    }

    #[cfg(test)]
    pub async fn put(
        &self,
        key: &str,
        status: StatusCode,
        headers: &HeaderMap,
        body: Bytes,
        ttl: Duration,
        limit_bytes: u64,
    ) -> std::io::Result<()> {
        self.put_at_epoch(self.epoch(), key, status, headers, body, ttl, limit_bytes)
            .await
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub async fn put_at_epoch(
        &self,
        epoch: u64,
        key: &str,
        status: StatusCode,
        headers: &HeaderMap,
        body: Bytes,
        ttl: Duration,
        limit_bytes: u64,
    ) -> std::io::Result<()> {
        let guard = self.key_guard(key).ok_or_else(busy)?;
        self.put_at_epoch_guarded(epoch, key, status, headers, body, ttl, limit_bytes, &guard)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_at_epoch_guarded(
        &self,
        epoch: u64,
        key: &str,
        status: StatusCode,
        headers: &HeaderMap,
        body: Bytes,
        ttl: Duration,
        limit_bytes: u64,
        request_guard: &CacheKeyGuard,
    ) -> std::io::Result<()> {
        let publication_guard = self.key_guard(key).ok_or_else(busy)?;
        let request_guard = request_guard.clone();
        if !valid_key(key) || body.len() as u64 > self.max_object_bytes() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid cache entry",
            ));
        }
        if !publication_guard.is_current() || !request_guard.is_current() {
            return Err(busy());
        }
        let limit_bytes = self.disk_limit(limit_bytes);
        let headers = serialize_headers(headers)?;
        let guard = self.store_lease().await?;
        let cache = self.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            cache.load_pins_locked()?;
            if !publication_guard.is_current()
                || !request_guard.is_current()
                || !cache.valid_epoch(epoch)
                || cache.key_protected(&key)
            {
                return Err(busy());
            }
            let result = put_sync(
                &cache.root,
                &key,
                status.as_u16(),
                headers,
                &body,
                ttl,
                limit_bytes,
                (&cache, epoch, &publication_guard, &request_guard),
            );
            if result.is_err() {
                // Pruning or a partial persist may have changed files before failure.
                // Invalidate scans before releasing the writer lease, including errors.
                cache.state.lock().unwrap().record_change();
            }
            result
        })
        .await
        .map_err(std::io::Error::other)?
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_fill(
        &self,
        epoch: u64,
        key: &str,
        status: StatusCode,
        headers: &HeaderMap,
        length: u64,
        ttl: Duration,
        started: Instant,
        limit_bytes: u64,
    ) -> Option<CacheFill> {
        let guard = self.key_guard(key)?;
        self.begin_fill_guarded(
            epoch,
            key,
            status,
            headers,
            length,
            ttl,
            started,
            limit_bytes,
            &guard,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn begin_fill_guarded(
        &self,
        epoch: u64,
        key: &str,
        status: StatusCode,
        headers: &HeaderMap,
        length: u64,
        ttl: Duration,
        started: Instant,
        limit_bytes: u64,
        request_guard: &CacheKeyGuard,
    ) -> Option<CacheFill> {
        let request_guard = request_guard.clone();
        let key_guard = self.key_guard(key)?;
        if !valid_key(key) || length > self.max_object_bytes() {
            return None;
        }
        if !key_guard.is_current() || !request_guard.is_current() {
            return None;
        }
        let limit_bytes = self.disk_limit(limit_bytes);
        let headers = serialize_headers(headers).ok()?;
        if self.state.lock().unwrap().recovery.blocks_headers(&headers) {
            return None;
        }
        let guard = self.store_lease().await.ok()?;
        let cache = self.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            if !key_guard.is_current() || !request_guard.is_current() || !cache.valid_epoch(epoch) {
                return None;
            }
            fs::create_dir_all(&cache.root).ok()?;
            cache.load_pins_locked().ok()?;
            if cache.key_protected(&key) {
                return None;
            }
            let now = unix_seconds();
            let probe = CacheMetadata {
                version: 1,
                status: status.as_u16(),
                headers: headers.clone(),
                stored_unix_seconds: now,
                expires_unix_seconds: now.saturating_add(ttl.as_secs()),
                body_length: length,
                body_sha256: "0".repeat(64),
                fragments: None,
                invalidated: false,
                online_validation_required: ttl.is_zero(),
            };
            // Timestamp digit growth and metadata publication are included in admission.
            let reserved =
                length.checked_add(serde_json::to_vec(&probe).ok()?.len() as u64 + 40)?;
            if cache.state.lock().unwrap().reservations.len() >= MAX_ACTIVE_FILLS {
                return None;
            }
            let remaining = limit_bytes.checked_sub(reserved)?;
            cache
                .prune_locked(
                    remaining,
                    MAX_CACHE_ENTRIES - 1,
                    cache.max_object_bytes(),
                    Some(&key),
                )
                .ok()?;
            let temporary = temporary_file(&cache.root).ok()?;
            let reservation = FillReservation {
                cache: cache.clone(),
                path: temporary.path().to_owned(),
            };
            {
                let mut state = cache.state.lock().unwrap();
                state
                    .reservations
                    .insert(reservation.path.clone(), (key.clone(), reserved));
                state.record_change();
            }
            drop(guard);
            Some(CacheFill {
                cache,
                epoch,
                key,
                status: status.as_u16(),
                headers,
                length,
                ttl,
                started,
                temporary,
                hasher: Sha256::new(),
                written: 0,
                cancellation: None,
                key_guard,
                request_guard: Some(request_guard),
                _reservation: reservation,
            })
        })
        .await
        .ok()
        .flatten()
    }

    pub async fn clear(&self) -> std::io::Result<()> {
        self.variants.clear();
        self.dns_answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        {
            let mut state = self.state.lock().unwrap();
            state.epoch = state.epoch.wrapping_add(1);
            state.pending_clear = true;
            state.maintenance_retry_at = None;
            state.maintenance_failure = None;
        }
        self.fills.cancel_all();
        self.maintain().await
    }

    fn key_protected(&self, key: &str) -> bool {
        let state = self.state.lock().unwrap();
        state.readers.contains_key(key)
            || state.pins.entries.contains_key(key)
            || state.reservations.values().any(|(entry, _)| entry == key)
            || state.recovery.blocks_entry(&self.root, key)
    }

    // Caller holds the short global writer lease. Reservations count the entire
    // future temporary entry; their current files are excluded to avoid double counting.
    fn prune_locked(
        &self,
        limit: u64,
        count: usize,
        max_object: u64,
        extra: Option<&str>,
    ) -> std::io::Result<()> {
        self.load_pins_locked()?;
        let (mut protected, temps, reserved, reserved_count) = {
            let state = self.state.lock().unwrap();
            let keys = state
                .readers
                .keys()
                .chain(state.pins.entries.keys())
                .chain(state.reservations.values().map(|(key, _)| key))
                .cloned()
                .collect::<HashSet<_>>();
            let mut temps = state.reservations.keys().cloned().collect::<HashSet<_>>();
            temps.insert(self.recovery_path.clone());
            let reserved = state
                .reservations
                .values()
                .try_fold(0u64, |total, (_, size)| total.checked_add(*size))
                .ok_or_else(busy)?;
            (keys, temps, reserved, state.reservations.len())
        };
        if let Some(key) = extra {
            protected.insert(key.to_owned());
        }
        let result = prune_storage(
            &self.root,
            limit,
            count.saturating_sub(reserved_count),
            max_object,
            &protected,
            &temps,
            reserved,
            Some(&self.state),
        );
        self.state.lock().unwrap().record_change();
        result?;
        self.check_pin_limits()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn busy() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "Cache se právě používá. Položky jsou zneplatněné; soubory se odstraní po dokončení přenosu při dalším přístupu do cache.",
    )
}

/// Protects only the leased entry, so unrelated fills and hits remain available.
pub(super) struct EntryLease {
    cache: CacheStore,
    key: String,
}
impl EntryLease {
    fn new(cache: &CacheStore, key: &str) -> Self {
        *cache
            .state
            .lock()
            .unwrap()
            .readers
            .entry(key.to_owned())
            .or_default() += 1;
        Self {
            cache: cache.clone(),
            key: key.to_owned(),
        }
    }
}
impl Drop for EntryLease {
    fn drop(&mut self) {
        let mut state = self.cache.state.lock().unwrap();
        if let Some(count) = state.readers.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                state.readers.remove(&self.key);
            }
        }
    }
}
struct FillReservation {
    cache: CacheStore,
    path: PathBuf,
}
impl Drop for FillReservation {
    fn drop(&mut self) {
        let mut state = self.cache.state.lock().unwrap();
        state.reservations.remove(&self.path);
        state.record_change();
    }
}

pub struct CacheFill {
    cache: CacheStore,
    epoch: u64,
    key: String,
    status: u16,
    headers: Vec<(String, String)>,
    length: u64,
    ttl: Duration,
    started: Instant,
    temporary: NamedTempFile,
    hasher: Sha256,
    written: u64,
    cancellation: Option<CancellationToken>,
    key_guard: CacheKeyGuard,
    request_guard: Option<CacheKeyGuard>,
    _reservation: FillReservation,
}

impl CacheFill {
    #[cfg(test)]
    pub fn with_key_guard(mut self, guard: CacheKeyGuard) -> Self {
        self.request_guard = Some(guard);
        self
    }

    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub async fn write(mut self, bytes: Bytes) -> Option<Self> {
        tokio::task::spawn_blocking(move || {
            if !self.cache.valid_epoch(self.epoch)
                || !self.key_guard.is_current()
                || self
                    .request_guard
                    .as_ref()
                    .is_some_and(|guard| !guard.is_current())
                || bytes.len() > IO_CHUNK_BYTES
            {
                return None;
            }
            self.written = self.written.checked_add(bytes.len() as u64)?;
            if self.written > self.length {
                return None;
            }
            self.temporary.write_all(&bytes).ok()?;
            self.hasher.update(&bytes);
            Some(self)
        })
        .await
        .ok()
        .flatten()
    }

    pub async fn commit(mut self) -> bool {
        // Flushing a large immutable temp can be slow. Its reservation protects
        // it while unrelated hits and publishers continue using the cache.
        let Some(this) = tokio::task::spawn_blocking(move || {
            if self.written != self.length
                || !self.cache.valid_epoch(self.epoch)
                || !self.key_guard.is_current()
                || self
                    .request_guard
                    .as_ref()
                    .is_some_and(|guard| !guard.is_current())
            {
                return None;
            }
            self.temporary.as_file_mut().sync_all().ok()?;
            Some(self)
        })
        .await
        .ok()
        .flatten() else {
            return false;
        };
        let Ok(guard) =
            tokio::time::timeout(CACHE_IO_WAIT, this.cache.io_lock.clone().write_owned()).await
        else {
            return false;
        };
        tokio::task::spawn_blocking(move || -> Option<()> {
            let _guard = guard;
            let ttl = this.ttl.saturating_sub(this.started.elapsed());
            let now = unix_seconds();
            let metadata = CacheMetadata {
                version: 1,
                status: this.status,
                headers: this.headers.clone(),
                stored_unix_seconds: now.saturating_sub(this.started.elapsed().as_secs()),
                expires_unix_seconds: now.saturating_add(ttl.as_secs()),
                body_length: this.length,
                body_sha256: hex::encode(this.hasher.clone().finalize()),
                fragments: None,
                invalidated: false,
                online_validation_required: ttl.is_zero(),
            };
            let bytes = serde_json::to_vec(&metadata).ok()?;
            if bytes.len() > MAX_METADATA_BYTES {
                return None;
            }
            let mut temporary_metadata = temporary_file(&this.cache.root).ok()?;
            temporary_metadata.write_all(&bytes).ok()?;
            temporary_metadata.as_file_mut().sync_all().ok()?;
            #[cfg(test)]
            {
                let gate = this.cache.state.lock().unwrap().commit_gate.clone();
                if let Some((started, resume)) = gate {
                    started.wait();
                    resume.wait();
                }
            }
            let mut state = this.cache.state.lock().unwrap();
            if this
                .cancellation
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
                || !this.key_guard.is_current()
                || this
                    .request_guard
                    .as_ref()
                    .is_some_and(|guard| !guard.is_current())
                || state.epoch != this.epoch
                || state.pending_clear
                || state.readers.contains_key(&this.key)
                || state.pins.entries.contains_key(&this.key)
                || state.recovery.blocks(&this.key)
                || state.recovery.blocks_headers(&this.headers)
            {
                return None;
            }
            persist_replace(
                this.temporary,
                &this.cache.root.join(format!("{}.body", this.key)),
            )
            .ok()?;
            persist_replace(
                temporary_metadata,
                &this.cache.root.join(format!("{}.json", this.key)),
            )
            .ok()?;
            state.confirm_publication(&this.cache.root).ok()?;
            state.invalidated_keys.remove(&this.key);
            state.record_change();
            Some(())
        })
        .await
        .ok()
        .flatten()
        .is_some()
    }
}

pub struct CachedEntry {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: CacheBody,
    pub age: Duration,
    pub remaining_ttl: Duration,
}

#[derive(Deserialize, Serialize)]
struct CacheMetadata {
    version: u8,
    #[serde(default)]
    invalidated: bool,
    #[serde(default)]
    online_validation_required: bool,
    status: u16,
    headers: Vec<(String, String)>,
    stored_unix_seconds: u64,
    expires_unix_seconds: u64,
    body_length: u64,
    body_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fragments: Option<fragments::FragmentMetadata>,
}

fn get_sync(
    root: &Path,
    key: &str,
    guard: EntryLease,
    max_object_bytes: u64,
    include_stale: bool,
) -> Option<CachedEntry> {
    get_sync_inner(root, key, guard, max_object_bytes, include_stale, false)
}
fn get_sync_inner(
    root: &Path,
    key: &str,
    guard: EntryLease,
    max_object_bytes: u64,
    include_stale: bool,
    allow_fragment: bool,
) -> Option<CachedEntry> {
    get_sync_verified(
        root,
        key,
        guard,
        max_object_bytes,
        include_stale,
        allow_fragment,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn get_sync_verified(
    root: &Path,
    key: &str,
    guard: EntryLease,
    max_object_bytes: u64,
    include_stale: bool,
    allow_fragment: bool,
    allow_invalidated: bool,
) -> Option<CachedEntry> {
    let metadata_path = root.join(format!("{key}.json"));
    let body_path = root.join(format!("{key}.body"));
    if fs::metadata(&metadata_path).ok()?.len() > MAX_METADATA_BYTES as u64 {
        return None;
    }
    let metadata: CacheMetadata = serde_json::from_slice(&fs::read(&metadata_path).ok()?).ok()?;
    let now = unix_seconds();
    if !allow_invalidated
        && guard
            .cache
            .state
            .lock()
            .unwrap()
            .recovery
            .blocks_headers(&metadata.headers)
    {
        return None;
    }
    if (!allow_invalidated && metadata.invalidated)
        || (!allow_fragment && metadata.fragments.is_some())
        || metadata.version != 1
        || (!include_stale && metadata.expires_unix_seconds <= now)
        || metadata.body_length > max_object_bytes
    {
        return None;
    }
    let mut file = fs::File::open(body_path).ok()?;
    if file.metadata().ok()?.len() != metadata.body_length {
        return None;
    }
    #[cfg(test)]
    {
        let gate = guard.cache.state.lock().unwrap().hit_prepass_gate.clone();
        if let Some((gated_key, started, resume)) = gate {
            if gated_key == key {
                started.wait();
                resume.wait();
            }
        }
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0; IO_CHUNK_BYTES];
    let mut length = 0u64;
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        length += read as u64;
        if length > metadata.body_length {
            return None;
        }
        hasher.update(&buffer[..read]);
    }
    if length != metadata.body_length || hex::encode(hasher.finalize()) != metadata.body_sha256 {
        return None;
    }
    file.rewind().ok()?;
    // A large integrity prepass may consume the remaining freshness lifetime.
    let now = unix_seconds();
    if !include_stale && metadata.expires_unix_seconds <= now {
        return None;
    }
    // Persist recency at most once a minute per entry; no additional metadata writes.
    if file
        .metadata()
        .ok()?
        .modified()
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|elapsed| elapsed >= Duration::from_secs(60))
    {
        let _ = file.set_times(fs::FileTimes::new().set_modified(SystemTime::now()));
    }
    Some(CachedEntry {
        status: StatusCode::from_u16(metadata.status).ok()?,
        headers: deserialize_headers(metadata.headers)?,
        body: CacheBody::file(file, metadata.body_length, guard, metadata.body_sha256),
        age: Duration::from_secs(now.saturating_sub(metadata.stored_unix_seconds)),
        remaining_ttl: Duration::from_secs(metadata.expires_unix_seconds.saturating_sub(now)),
    })
}

#[allow(clippy::too_many_arguments)]
fn put_sync(
    root: &Path,
    key: &str,
    status: u16,
    headers: Vec<(String, String)>,
    body: &[u8],
    ttl: Duration,
    limit_bytes: u64,
    epoch: (&CacheStore, u64, &CacheKeyGuard, &CacheKeyGuard),
) -> std::io::Result<()> {
    fs::create_dir_all(root)?;
    if epoch
        .0
        .state
        .lock()
        .unwrap()
        .recovery
        .blocks_headers(&headers)
    {
        return Err(busy());
    }
    let now = unix_seconds();
    let metadata = CacheMetadata {
        version: 1,
        status,
        headers,
        stored_unix_seconds: now,
        expires_unix_seconds: now.saturating_add(ttl.as_secs()),
        body_length: body.len() as u64,
        body_sha256: hex::encode(Sha256::digest(body)),
        fragments: None,
        invalidated: false,
        online_validation_required: ttl.is_zero(),
    };
    let metadata_bytes = serde_json::to_vec(&metadata).map_err(std::io::Error::other)?;
    if metadata_bytes.len() > MAX_METADATA_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache metadata exceeds size limit",
        ));
    }
    let entry_size = (body.len() as u64)
        .checked_add(metadata_bytes.len() as u64)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "cache entry is too large")
        })?;
    let remaining_limit = limit_bytes.checked_sub(entry_size).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache entry exceeds configured disk limit",
        )
    })?;

    epoch.0.prune_locked(
        remaining_limit,
        MAX_CACHE_ENTRIES.saturating_sub(1),
        epoch.0.max_object_bytes(),
        Some(key),
    )?;

    let body_path = root.join(format!("{key}.body"));
    let metadata_path = root.join(format!("{key}.json"));

    let mut temporary_body = temporary_file(root)?;
    temporary_body.write_all(body)?;
    temporary_body.as_file_mut().sync_all()?;
    let mut temporary_metadata = temporary_file(root)?;
    temporary_metadata.write_all(&metadata_bytes)?;
    temporary_metadata.as_file_mut().sync_all()?;
    let mut state = epoch.0.state.lock().unwrap();
    if state.epoch != epoch.1
        || state.pending_clear
        || !epoch.2.is_current()
        || !epoch.3.is_current()
        || state.readers.contains_key(key)
        || state.pins.entries.contains_key(key)
        || state.recovery.blocks_headers(&metadata.headers)
    {
        return Err(busy());
    }
    persist_replace(temporary_body, &body_path)?;
    persist_replace(temporary_metadata, &metadata_path)?;
    state.confirm_publication(root)?;
    state.invalidated_keys.remove(key);
    state.record_change();

    Ok(())
}

fn temporary_file(root: &Path) -> std::io::Result<NamedTempFile> {
    Builder::new().prefix(".cache-tmp-").tempfile_in(root)
}

fn persist_replace(file: NamedTempFile, destination: &Path) -> std::io::Result<()> {
    match file.persist(destination) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(destination)?;
            error
                .file
                .persist(destination)
                .map(|_| ())
                .map_err(|error| error.error)
        }
        Err(error) => Err(error.error),
    }
}

#[cfg(test)]
fn prune_sync(root: &Path, limit_bytes: u64) -> std::io::Result<()> {
    prune_sync_with_limits(root, limit_bytes, MAX_CACHE_ENTRIES)
}

#[derive(Default)]
struct EntryFiles {
    body: Option<CacheFile>,
    metadata: Option<CacheFile>,
}

struct CacheFile {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

struct CompleteEntry {
    key: String,
    body: CacheFile,
    metadata: CacheFile,
}

#[cfg(test)]
fn prune_sync_with_limits(
    root: &Path,
    limit_bytes: u64,
    max_entries: usize,
) -> std::io::Result<()> {
    prune_sync_with_object_limit(root, limit_bytes, max_entries, MAX_CACHE_ITEM_BYTES)
}

#[cfg(test)]
fn prune_sync_with_object_limit(
    root: &Path,
    limit_bytes: u64,
    max_entries: usize,
    max_object_bytes: u64,
) -> std::io::Result<()> {
    prune_storage(
        root,
        limit_bytes,
        max_entries,
        max_object_bytes,
        &HashSet::new(),
        &HashSet::new(),
        0,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn prune_storage(
    root: &Path,
    limit_bytes: u64,
    max_entries: usize,
    max_object_bytes: u64,
    protected: &HashSet<String>,
    active_temps: &HashSet<PathBuf>,
    reserved_bytes: u64,
    invalidation_state: Option<&StdMutex<CacheState>>,
) -> std::io::Result<()> {
    let mut by_key = BTreeMap::<String, EntryFiles>::new();
    let mut stale_files = Vec::new();
    let mut total = reserved_bytes;
    let mut scanned = 0usize;

    for entry in fs::read_dir(root)? {
        scanned += 1;
        if scanned > MAX_CACHE_FILES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cache directory exceeds file count limit",
            ));
        }
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if active_temps.contains(&path) {
            continue;
        }
        if file_name == pins::MANIFEST_NAME {
            total = total.saturating_add(entry.metadata()?.len());
            continue;
        }
        let kind = if file_name.starts_with(".cache-tmp-")
            || file_name.starts_with(".cache-invalidation-")
        {
            None
        } else if let Some(key) = file_name.strip_suffix(".body") {
            Some((key.to_string(), true))
        } else if let Some(key) = file_name.strip_suffix(".json") {
            Some((key.to_string(), false))
        } else {
            continue;
        };
        let metadata = entry.metadata()?;
        let file = CacheFile {
            path,
            size: metadata.len(),
            modified: metadata.modified().unwrap_or(UNIX_EPOCH),
        };
        total = total.saturating_add(file.size);

        match kind {
            Some((key, is_body)) if valid_key(&key) => {
                let files = by_key.entry(key).or_default();
                if is_body {
                    files.body = Some(file);
                } else {
                    files.metadata = Some(file);
                }
            }
            _ => stale_files.push(file),
        }
    }

    let mut complete = Vec::with_capacity(by_key.len());
    let mut protected_oversized = false;
    for (key, files) in by_key {
        match (files.body, files.metadata) {
            (Some(body), Some(metadata))
                if body.size > max_object_bytes && !protected.contains(&key) =>
            {
                stale_files.push(body);
                stale_files.push(metadata);
            }
            (Some(body), Some(metadata)) => {
                protected_oversized |= body.size > max_object_bytes;
                complete.push(CompleteEntry {
                    key,
                    body,
                    metadata,
                });
            }
            (body, metadata) if protected.contains(&key) => {
                // Fail closed for protected incomplete entries. Their files count toward quota.
                let _ = (body, metadata);
            }
            (body, metadata) => {
                stale_files.extend(body);
                stale_files.extend(metadata);
            }
        }
    }

    stale_files.sort_by(|left, right| left.path.cmp(&right.path));
    for file in stale_files {
        // Synchronous invalidation publishes while holding CacheState. Wait for
        // that publication before cleaning its temp; crash leftovers have no owner.
        let _invalidation_guard = if file
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".cache-invalidation-"))
        {
            invalidation_state.map(|state| state.lock().unwrap())
        } else {
            None
        };
        remove_cache_file(&file.path)?;
        total = total.saturating_sub(file.size);
    }

    complete.sort_by(|left, right| {
        let left_modified = left.body.modified.max(left.metadata.modified);
        let right_modified = right.body.modified.max(right.metadata.modified);
        left_modified
            .cmp(&right_modified)
            .then_with(|| left.key.cmp(&right.key))
    });
    let mut remaining_entries = complete.len();
    for entry in complete {
        if total <= limit_bytes && remaining_entries <= max_entries {
            break;
        }
        if protected.contains(&entry.key) {
            continue;
        }
        remove_cache_file(&entry.body.path)?;
        remove_cache_file(&entry.metadata.path)?;
        total = total.saturating_sub(entry.body.size.saturating_add(entry.metadata.size));
        remaining_entries -= 1;
    }
    if total > limit_bytes || remaining_entries > max_entries || protected_oversized {
        return Err(busy());
    }
    Ok(())
}

fn measure_sync(root: &Path) -> std::io::Result<CacheUsage> {
    let mut usage = CacheUsage {
        measured: true,
        usage_is_current: true,
        ..CacheUsage::default()
    };
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(usage),
        Err(error) => return Err(error),
    };
    let mut pairs = BTreeMap::<String, u8>::new();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_CACHE_FILES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cache directory exceeds file count limit",
            ));
        }
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let kind = name
            .strip_suffix(".body")
            .map(|key| (key, 1))
            .or_else(|| name.strip_suffix(".json").map(|key| (key, 2)));
        if let Some((key, bit)) = kind {
            usage.used_bytes = usage.used_bytes.saturating_add(entry.metadata()?.len());
            if valid_key(key) {
                *pairs.entry(key.to_string()).or_default() |= bit;
            }
        } else if name.starts_with(".cache-tmp-")
            || name.starts_with(".cache-invalidation-")
            || name == pins::MANIFEST_NAME
        {
            usage.used_bytes = usage.used_bytes.saturating_add(entry.metadata()?.len());
        }
    }
    usage.entry_count = pairs.values().filter(|bits| **bits == 3).count() as u64;
    Ok(usage)
}

fn remove_cache_file(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn clear_sync(root: &Path, recovery_path: &Path) -> std::io::Result<()> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let path = entry?.path();
        if path == recovery_path {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        let recognized = matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("body" | "json")
        ) || file_name.starts_with(".cache-tmp-")
            || file_name == pins::MANIFEST_NAME;
        if recognized && path.is_file() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn serialize_headers(headers: &HeaderMap) -> std::io::Result<Vec<(String, String)>> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "response exceeds cache header count limit",
        ));
    }
    let mut serialized = Vec::new();
    let mut raw_size = 0usize;
    for (name, value) in headers {
        raw_size = raw_size
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.as_bytes().len()))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "response exceeds cache header size limit",
                )
            })?;
        if raw_size > MAX_SERIALIZED_HEADERS_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "response exceeds cache header size limit",
            ));
        }
        let value = value.to_str().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response contains a non-text header",
            )
        })?;
        serialized.push((name.as_str().to_string(), value.to_string()));
    }
    let serialized_size = serde_json::to_vec(&serialized)
        .map_err(std::io::Error::other)?
        .len();
    if serialized_size > MAX_SERIALIZED_HEADERS_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "response exceeds cache header size limit",
        ));
    }
    Ok(serialized)
}

fn deserialize_headers(headers: Vec<(String, String)>) -> Option<HeaderMap> {
    if headers.len() > MAX_HEADER_COUNT
        || serde_json::to_vec(&headers).ok()?.len() > MAX_SERIALIZED_HEADERS_BYTES
    {
        return None;
    }
    let mut output = HeaderMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
        let value = HeaderValue::from_str(&value).ok()?;
        output.append(name, value);
    }
    Some(output)
}

fn valid_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: &str) -> String {
        hex::encode(Sha256::digest(value.as_bytes()))
    }

    #[tokio::test]
    async fn unknown_usage_is_not_a_measured_zero_during_first_active_fill() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().into());
        let fill = cache
            .begin_fill(
                cache.epoch(),
                &key("busy"),
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(60),
                Instant::now(),
                1024 * 1024,
            )
            .await
            .unwrap();
        let usage = cache.usage().await;
        assert!(!usage.measured);
        assert!(!usage.usage_is_current);
        assert!(usage.measurement_error.is_none());
        drop(fill);
        let usage = cache.usage().await;
        assert!(usage.measured);
        assert!(usage.usage_is_current);
        assert_eq!(usage.used_bytes, 0);
    }

    #[tokio::test]
    async fn unchanged_usage_is_throttled_and_commits_request_a_refresh() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().into());
        assert!(cache.usage().await.usage_is_current);
        fs::write(
            directory.path().join(format!("{}.body", key("external"))),
            b"abc",
        )
        .unwrap();
        fs::write(
            directory.path().join(format!("{}.json", key("external"))),
            b"{}",
        )
        .unwrap();
        let cached = cache.usage().await;
        assert!(cached.measured);
        assert!(!cached.usage_is_current);
        assert_eq!(cached.entry_count, 0);
        cache.state.lock().unwrap().last_measurement_attempt =
            Some(Instant::now() - USAGE_REFRESH_INTERVAL);
        let refreshed = cache.usage().await;
        assert!(refreshed.usage_is_current);
        assert_eq!(refreshed.entry_count, 1);
        cache
            .put(
                &key("committed"),
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"abc"),
                Duration::from_secs(60),
                1024 * 1024,
            )
            .await
            .unwrap();
        let refreshed = cache.usage().await;
        assert!(refreshed.usage_is_current);
        assert_eq!(refreshed.entry_count, 2);
    }

    #[tokio::test]
    async fn concurrent_usage_scan_does_not_reject_a_fill_or_claim_an_exact_measurement() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().into());
        let started = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        cache.state.lock().unwrap().scan_gate = Some((started.clone(), resume.clone()));
        let measuring = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.usage().await })
        };
        tokio::task::spawn_blocking(move || started.wait())
            .await
            .unwrap();
        let fill = cache
            .begin_fill(
                cache.epoch(),
                &key("concurrent"),
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(60),
                Instant::now(),
                1024 * 1024,
            )
            .await;
        // Always release the test barrier before assertions, including on failure.
        let committed = if let Some(fill) = fill {
            fill.write(Bytes::from_static(b"abc"))
                .await
                .unwrap()
                .commit()
                .await
        } else {
            false
        };
        tokio::task::spawn_blocking(move || resume.wait())
            .await
            .unwrap();
        let usage = measuring.await.unwrap();
        cache.state.lock().unwrap().scan_gate = None;
        assert!(committed, "a metadata scan must not deny cache admission");
        assert!(usage.measured);
        assert!(!usage.usage_is_current);
        assert!(cache.get(&key("concurrent")).await.is_some());
    }

    #[tokio::test]
    async fn failed_pruning_keeps_hits_and_retries_with_backoff_separate_from_measurement() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().into());
        let cache_key = key("retained");
        cache
            .put(
                &cache_key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"abc"),
                Duration::from_secs(60),
                1024 * 1024,
            )
            .await
            .unwrap();
        for index in 0..MAX_CACHE_FILES {
            fs::write(directory.path().join(format!("unexpected-{index}")), []).unwrap();
        }
        cache.configure_limits(1024 * 1024, MAX_CACHE_ITEM_BYTES);
        assert_eq!(
            cache.maintain().await.unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(cache.get(&cache_key).await.is_some());
        let unknown = cache.usage().await;
        assert!(!unknown.measured);
        assert!(unknown.measurement_error.is_some());
        assert!(unknown.maintenance_error.is_some());
        for index in 0..MAX_CACHE_FILES {
            fs::remove_file(directory.path().join(format!("unexpected-{index}"))).unwrap();
        }
        // The directory is repaired, but retrying within the backoff still returns
        // the prior failure: no directory scan on each request. HIT remains usable.
        assert_eq!(
            cache.maintain().await.unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(cache.get(&cache_key).await.is_some());
        cache.state.lock().unwrap().last_measurement_attempt = None;
        let measured = cache.usage().await;
        assert!(measured.measured);
        assert!(measured.usage_is_current);
        assert!(measured.measurement_error.is_none());
        assert!(measured.maintenance_error.is_some());
        assert!(measured.pending_maintenance);
        cache.state.lock().unwrap().maintenance_retry_at = Some(Instant::now());
        cache.maintain().await.unwrap();
        let repaired = cache.usage().await;
        assert!(repaired.maintenance_error.is_none());
        assert!(!repaired.pending_maintenance);
        assert_eq!(repaired.entry_count, 1);
    }

    #[tokio::test]
    async fn committed_disk_limit_ignores_a_prospective_lower_call_argument() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().into());
        cache.configure_limits(1024 * 1024, MAX_CACHE_ITEM_BYTES);
        for value in ["existing", "prospective"] {
            cache
                .put(
                    &key(value),
                    StatusCode::OK,
                    &HeaderMap::new(),
                    Bytes::from_static(b"abc"),
                    Duration::from_secs(60),
                    1,
                )
                .await
                .unwrap();
        }
        assert_eq!(cache.usage().await.entry_count, 2);
        assert!(cache.get(&key("existing")).await.is_some());
        cache.configure_limits(1, MAX_CACHE_ITEM_BYTES);
        cache.maintain().await.unwrap();
        assert_eq!(cache.usage().await.entry_count, 0);
    }

    #[tokio::test]
    async fn configured_object_cap_applies_to_buffered_streamed_and_old_hits() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().into());
        let headers = HeaderMap::new();
        cache.configure_limits(1024 * 1024, 3);
        cache
            .put(
                &key("exact"),
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"abc"),
                Duration::from_secs(60),
                1024 * 1024,
            )
            .await
            .unwrap();
        assert!(cache.get(&key("exact")).await.is_some());
        assert!(cache
            .put(
                &key("over"),
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"abcd"),
                Duration::from_secs(60),
                1024 * 1024
            )
            .await
            .is_err());
        assert!(cache
            .begin_fill(
                cache.epoch(),
                &key("over"),
                StatusCode::OK,
                &headers,
                4,
                Duration::from_secs(60),
                Instant::now(),
                1024 * 1024
            )
            .await
            .is_none());
        let fill = cache
            .begin_fill(
                cache.epoch(),
                &key("stream"),
                StatusCode::OK,
                &headers,
                3,
                Duration::from_secs(60),
                Instant::now(),
                1024 * 1024,
            )
            .await
            .unwrap();
        assert!(
            fill.write(Bytes::from_static(b"abc"))
                .await
                .unwrap()
                .commit()
                .await
        );
        let active = cache.get(&key("stream")).await.unwrap();
        cache.configure_limits(1024 * 1024, 2);
        assert!(cache.get(&key("exact")).await.is_none());
        assert!(cache.usage().await.pending_maintenance);
        drop(active);
        cache.maintain().await.unwrap();
        assert_eq!(cache.usage().await.entry_count, 0);
    }

    #[tokio::test]
    async fn lower_disk_limit_prunes_existing_data_after_reader_release_and_startup() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().into());
        for value in ["one", "two"] {
            cache
                .put(
                    &key(value),
                    StatusCode::OK,
                    &HeaderMap::new(),
                    Bytes::from_static(b"abc"),
                    Duration::from_secs(60),
                    1024 * 1024,
                )
                .await
                .unwrap();
        }
        let before = cache.usage().await;
        assert_eq!(before.entry_count, 2);
        assert!(before.used_bytes > 6); // Includes metadata, not just response payload.
        let active = cache.get(&key("one")).await.unwrap();
        cache.configure_limits(before.used_bytes / 2 - 1, MAX_CACHE_ITEM_BYTES);
        assert_eq!(
            cache.maintain().await.unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(cache.usage().await.pending_maintenance);
        drop(active);
        let after = cache.usage().await;
        assert!(!after.pending_maintenance);
        assert!(after.used_bytes < before.used_bytes / 2);
        assert!(after.entry_count <= 1);
        // A new daemon instance must enforce saved limits before any new fill.
        let restarted = CacheStore::new(directory.path().into());
        restarted.configure_limits(0, MAX_CACHE_ITEM_BYTES);
        let empty = restarted.usage().await;
        assert_eq!(empty.used_bytes, 0);
        assert_eq!(empty.entry_count, 0);
        assert!(empty.usage_is_current);
    }

    #[tokio::test]
    async fn changing_limits_never_deletes_an_active_temporary_fill() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().into());
        let fill = cache
            .begin_fill(
                cache.epoch(),
                &key("old-fill"),
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(60),
                Instant::now(),
                1024 * 1024,
            )
            .await
            .unwrap();
        let fill = fill.write(Bytes::from_static(b"abc")).await.unwrap();
        cache.configure_limits(1, 1);
        let usage = cache.usage().await;
        assert!(usage.pending_maintenance);
        assert!(!usage.usage_is_current);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        assert!(!fill.commit().await);
        cache.maintain().await.unwrap();
        assert_eq!(cache.usage().await.used_bytes, 0);
    }

    #[tokio::test]
    async fn stores_validates_and_clears_an_entry() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().to_path_buf());
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        let cache_key = key("one");
        cache
            .put(
                &cache_key,
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"public"),
                Duration::from_secs(60),
                1024,
            )
            .await
            .unwrap();
        let entry = cache.get(&cache_key).await.unwrap();
        use http_body_util::BodyExt;
        assert_eq!(
            entry.body.collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"public")
        );
        assert_eq!(entry.status, StatusCode::OK);
        cache.clear().await.unwrap();
        assert!(cache.get(&cache_key).await.is_none());
    }

    #[tokio::test]
    async fn rejects_a_tampered_body() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().to_path_buf());
        let cache_key = key("two");
        cache
            .put(
                &cache_key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"original"),
                Duration::from_secs(60),
                1024,
            )
            .await
            .unwrap();
        fs::write(
            directory.path().join(format!("{cache_key}.body")),
            b"changed",
        )
        .unwrap();
        assert!(cache.get(&cache_key).await.is_none());
    }

    #[tokio::test]
    async fn counts_metadata_for_empty_entries_when_pruning() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().to_path_buf());
        let first_key = key("empty-one");
        cache
            .put(
                &first_key,
                StatusCode::NO_CONTENT,
                &HeaderMap::new(),
                Bytes::new(),
                Duration::from_secs(60),
                u64::MAX,
            )
            .await
            .unwrap();
        let one_entry_limit = fs::metadata(directory.path().join(format!("{first_key}.json")))
            .unwrap()
            .len();

        let second_key = key("empty-two");
        cache
            .put(
                &second_key,
                StatusCode::NO_CONTENT,
                &HeaderMap::new(),
                Bytes::new(),
                Duration::from_secs(60),
                one_entry_limit,
            )
            .await
            .unwrap();

        assert!(cache.get(&first_key).await.is_none());
        assert!(cache.get(&second_key).await.is_some());
    }

    #[tokio::test]
    async fn rejects_headers_above_count_or_serialized_size_limits() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().to_path_buf());
        let mut too_many = HeaderMap::new();
        for _ in 0..=MAX_HEADER_COUNT {
            too_many.append("x-repeated", HeaderValue::from_static("value"));
        }
        let error = cache
            .put(
                &key("too-many-headers"),
                StatusCode::OK,
                &too_many,
                Bytes::new(),
                Duration::from_secs(60),
                u64::MAX,
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

        let mut too_large = HeaderMap::new();
        too_large.insert(
            "x-large",
            HeaderValue::from_bytes(&vec![b'a'; MAX_SERIALIZED_HEADERS_BYTES]).unwrap(),
        );
        let error = cache
            .put(
                &key("too-large-headers"),
                StatusCode::OK,
                &too_large,
                Bytes::new(),
                Duration::from_secs(60),
                u64::MAX,
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn prunes_entries_above_the_hard_count_limit() {
        let directory = tempfile::tempdir().unwrap();
        for value in 0..=MAX_CACHE_ENTRIES {
            let key = format!("{value:064x}");
            fs::write(directory.path().join(format!("{key}.body")), []).unwrap();
            fs::write(directory.path().join(format!("{key}.json")), b"{}").unwrap();
        }

        prune_sync(directory.path(), u64::MAX).unwrap();

        let body_count = fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.path().extension().and_then(|value| value.to_str()) == Some("body")
            })
            .count();
        assert_eq!(body_count, MAX_CACHE_ENTRIES);

        // The file bound includes room for the pin manifest and active fill
        // temporaries. Exceed that actual bound, rather than the old pair-only one.
        for value in 0..=(MAX_CACHE_FILES - MAX_CACHE_ENTRIES * 2) {
            fs::write(directory.path().join(format!("unrelated-{value}")), []).unwrap();
        }
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            MAX_CACHE_FILES + 1
        );
        let error = prune_sync(directory.path(), u64::MAX).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn removes_orphaned_and_stale_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let orphan_body = directory.path().join(format!("{}.body", key("body-only")));
        let orphan_metadata = directory
            .path()
            .join(format!("{}.json", key("metadata-only")));
        let stale_temporary = directory.path().join(".cache-tmp-stale");
        let stale_invalidation = directory.path().join(".cache-invalidation-stale");
        fs::write(&orphan_body, b"body").unwrap();
        fs::write(&orphan_metadata, b"metadata").unwrap();
        fs::write(&stale_temporary, b"temporary").unwrap();
        fs::write(&stale_invalidation, b"invalidation temporary").unwrap();

        prune_sync(directory.path(), u64::MAX).unwrap();

        assert!(!orphan_body.exists());
        assert!(!orphan_metadata.exists());
        assert!(!stale_temporary.exists());
        assert!(!stale_invalidation.exists());
    }
    #[tokio::test]
    async fn fill_boundary_quota_and_per_entry_leases_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let headers = HeaderMap::new();
        let cache_key = key("boundary");
        let begin = |length, limit| {
            cache.begin_fill(
                cache.epoch(),
                &cache_key,
                StatusCode::OK,
                &headers,
                length,
                Duration::from_secs(60),
                Instant::now(),
                limit,
            )
        };
        assert!(begin(MAX_CACHE_ITEM_BYTES + 1, u64::MAX).await.is_none());
        assert!(begin(MAX_CACHE_ITEM_BYTES, MAX_CACHE_ITEM_BYTES)
            .await
            .is_none());
        let fill = begin(
            MAX_CACHE_ITEM_BYTES,
            MAX_CACHE_ITEM_BYTES + MAX_METADATA_BYTES as u64,
        )
        .await
        .unwrap();
        assert!(begin(1, u64::MAX).await.is_none());
        assert!(cache.get(&cache_key).await.is_none());
        assert_eq!(
            fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().metadata().unwrap().len())
                .sum::<u64>(),
            0
        );
        drop(fill);
        cache
            .put(
                &cache_key,
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"abc"),
                Duration::from_secs(60),
                1024,
            )
            .await
            .unwrap();
        let hit = cache.get(&cache_key).await.unwrap();
        assert!(begin(1, u64::MAX).await.is_none());
        assert!(cache
            .put(
                &key("unrelated"),
                StatusCode::OK,
                &headers,
                Bytes::new(),
                Duration::from_secs(60),
                1024
            )
            .await
            .is_ok());
        drop(hit);
        assert!(begin(1, u64::MAX).await.is_some());
    }

    #[tokio::test]
    async fn clear_and_disable_invalidate_old_fills_and_small_puts() {
        for clear in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cache = CacheStore::new(dir.path().into());
            let old_epoch = cache.epoch();
            let cache_key = key("old-generation");
            let fill = cache
                .begin_fill(
                    old_epoch,
                    &cache_key,
                    StatusCode::OK,
                    &HeaderMap::new(),
                    3,
                    Duration::from_secs(60),
                    Instant::now(),
                    1024 * 1024,
                )
                .await
                .unwrap();
            let fill = fill.write(Bytes::from_static(b"abc")).await.unwrap();
            if clear {
                assert_eq!(
                    cache.clear().await.unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            } else {
                cache.invalidate();
            }
            assert!(!fill.commit().await);
            assert!(cache.get(&cache_key).await.is_none());
            assert!(cache
                .put_at_epoch(
                    old_epoch,
                    &cache_key,
                    StatusCode::OK,
                    &HeaderMap::new(),
                    Bytes::from_static(b"abc"),
                    Duration::from_secs(60),
                    1024
                )
                .await
                .is_err());
            assert!(cache
                .begin_fill(
                    old_epoch,
                    &cache_key,
                    StatusCode::OK,
                    &HeaderMap::new(),
                    3,
                    Duration::from_secs(60),
                    Instant::now(),
                    1024 * 1024
                )
                .await
                .is_none());
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }

    #[tokio::test]
    async fn pending_clear_blocks_new_admissions_and_retains_active_hit_file() {
        use http_body_util::BodyExt;
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let cache_key = key("active-hit");
        cache
            .put(
                &cache_key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"abc"),
                Duration::from_secs(60),
                1024,
            )
            .await
            .unwrap();
        let entry = cache.get(&cache_key).await.unwrap();
        assert_eq!(
            cache.clear().await.unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(cache.get(&cache_key).await.is_none());
        assert_eq!(entry.body.collect().await.unwrap().to_bytes(), "abc");
        assert!(cache.get(&cache_key).await.is_none());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn fill_time_consumes_freshness_and_cannot_resurrect_expired_response() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let fill = cache
            .begin_fill(
                cache.epoch(),
                &key("expired"),
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(1),
                Instant::now() - Duration::from_secs(2),
                1024 * 1024,
            )
            .await
            .unwrap();
        let fill = fill.write(Bytes::from_static(b"abc")).await.unwrap();
        assert!(fill.commit().await);
        assert!(cache.get(&key("expired")).await.is_none());
        let stale = cache.get_including_stale(&key("expired")).await.unwrap();
        assert_eq!(stale.remaining_ttl, Duration::ZERO);
    }

    // Regression for D-OBS-01. No production failpoint or I/O override:
    // an existing destination directory makes NamedTempFile::persist fail on Linux.
    #[tokio::test]
    async fn obs01_failed_buffered_put_must_not_publish_stale_usage_as_current() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("cache");
        let cache = CacheStore::new(root.clone());
        const BODY_BYTES: usize = 384 * 1024;
        const DISK_BYTES: u64 = 512 * 1024;
        cache.configure_limits(DISK_BYTES, 1024 * 1024);
        let old_key = key("obs01-old");
        let new_key = key("obs01-new");
        cache
            .put(
                &old_key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from(vec![0x41; BODY_BYTES]),
                Duration::from_secs(600),
                DISK_BYTES,
            )
            .await
            .unwrap();
        let before = measure_sync(&root).unwrap();
        assert_eq!(
            before.entry_count, 1,
            "fixture must start with one real entry"
        );
        assert!(before.used_bytes > BODY_BYTES as u64);
        assert!(before.used_bytes < DISK_BYTES);
        let old_body = root.join(format!("{old_key}.body"));
        let old_metadata = root.join(format!("{old_key}.json"));
        let blocked_destination = root.join(format!("{new_key}.body"));
        fs::create_dir(&blocked_destination).unwrap();

        let scanned = Arc::new(std::sync::Barrier::new(2));
        let publish = Arc::new(std::sync::Barrier::new(2));
        cache.state.lock().unwrap().after_scan_gate = Some((scanned.clone(), publish.clone()));
        let measuring = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.usage().await })
        };
        tokio::task::spawn_blocking(move || scanned.wait())
            .await
            .unwrap();

        // The scan now holds actual pre-write filesystem totals, without holding io_lock.
        // The second 384 KiB entry cannot fit beside the first in a 512 KiB cache.
        // Its real put therefore removes the old body+metadata, writes temporaries, then
        // fails to rename a regular file onto the existing .body directory.
        // Do not assert until the publication barrier is released (avoid test hangs).
        let write_result = cache
            .put(
                &new_key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from(vec![0x42; BODY_BYTES]),
                Duration::from_secs(600),
                DISK_BYTES,
            )
            .await;
        let old_body_exists = old_body.exists();
        let old_metadata_exists = old_metadata.exists();
        let actual_result = measure_sync(&root);
        cache.state.lock().unwrap().after_scan_gate = None;
        tokio::task::spawn_blocking(move || publish.wait())
            .await
            .unwrap();
        let observed = measuring.await.unwrap();

        let write_error = write_result.expect_err("fixture must trigger a real persist failure");
        let actual = actual_result.unwrap();
        assert!(
            blocked_destination.is_dir(),
            "persist-failure marker must remain a directory"
        );
        assert!(
            !old_body_exists && !old_metadata_exists,
            "put must actually prune both old files"
        );
        assert_eq!(
            actual.entry_count, 0,
            "no entry may survive the failed post-prune write"
        );
        assert_eq!(
            actual.used_bytes, 0,
            "temporary regular files must be cleaned up"
        );
        assert!(
            observed.measured,
            "the snapshot must come from an actual successful scan"
        );
        assert!(observed.measurement_error.is_none());
        eprintln!(
            "OBS01_EVIDENCE write_error={write_error:?} old_body_exists={old_body_exists} old_metadata_exists={old_metadata_exists} observed={observed:?} actual={actual:?}"
        );
        // Acceptance assertion: a stale scan may be returned, but must never claim to be
        // current while disagreeing with the post-write physical directory contents.
        assert!(
            !observed.usage_is_current
                || (observed.used_bytes == actual.used_bytes
                    && observed.entry_count == actual.entry_count),
            "D-OBS-01: usageIsCurrent=true published pre-prune totals after a real failed buffered write; observed={observed:?}, actual={actual:?}"
        );
        let refreshed = cache.usage().await;
        assert!(refreshed.measured && refreshed.usage_is_current);
        assert!(refreshed.measurement_error.is_none());
        assert_eq!(refreshed.used_bytes, actual.used_bytes);
        assert_eq!(refreshed.entry_count, actual.entry_count);
    }
}

#[cfg(test)]
mod storage_concurrency_tests {
    use super::*;
    use http_body_util::BodyExt;
    fn key(seed: &str) -> String {
        hex::encode(Sha256::digest(seed.as_bytes()))
    }

    #[tokio::test]
    async fn key_invalidation_preserves_unrelated_fill_and_rejects_retired_cold_responses() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let a = key("unrelated-fill");
        let b = key("retired-response");
        let epoch = cache.epoch();
        let begin = |key: String| {
            let cache = cache.clone();
            async move {
                cache
                    .begin_fill(
                        epoch,
                        &key,
                        StatusCode::OK,
                        &HeaderMap::new(),
                        3,
                        Duration::from_secs(60),
                        Instant::now(),
                        100_000,
                    )
                    .await
                    .unwrap()
            }
        };
        let fill = begin(a.clone()).await;
        let retired = begin(b.clone())
            .await
            .write(Bytes::from_static(b"abc"))
            .await
            .unwrap();
        cache.invalidate_key(&b);
        assert_eq!(cache.epoch(), epoch);
        assert!(
            fill.write(Bytes::from_static(b"abc"))
                .await
                .unwrap()
                .commit()
                .await
        );
        assert!(!retired.commit().await);
        assert!(cache.get(&a).await.is_some());
        assert!(cache.get(&b).await.is_none());
        let cold_guard = cache.key_guard(&b).unwrap();
        cache.invalidate_key(&b);
        assert!(cache
            .put_at_epoch_guarded(
                epoch,
                &b,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"old"),
                Duration::from_secs(60),
                100_000,
                &cold_guard
            )
            .await
            .is_err());
        assert!(cache
            .begin_fill_guarded(
                epoch,
                &b,
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(60),
                Instant::now(),
                100_000,
                &cold_guard
            )
            .await
            .is_none());
        let late = begin(b.clone()).await.with_key_guard(cold_guard.clone());
        assert!(late.write(Bytes::from_static(b"old")).await.is_none());
        let new_guard = cache.key_guard(&b).unwrap();
        cold_guard.retire();
        assert!(
            new_guard.is_current(),
            "retiring the old token twice cannot retire a new response"
        );
        cache
            .put_at_epoch_guarded(
                epoch,
                &b,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"new"),
                Duration::from_secs(60),
                100_000,
                &new_guard,
            )
            .await
            .unwrap();
        assert!(cache
            .invalidate_keys_at_epoch_guarded(epoch, std::slice::from_ref(&b), &cold_guard)
            .is_none());
        cache.remove_invalidated(&b).await.unwrap();
        assert_eq!(
            cache
                .get(&b)
                .await
                .unwrap()
                .body
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            "new"
        );
    }

    #[tokio::test]
    async fn unrelated_hit_integrity_prepass_does_not_drop_completed_fill() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let a = key("hashing-hit");
        let b = key("completed-fill");
        cache
            .put(
                &a,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"retained"),
                Duration::from_secs(60),
                100_000,
            )
            .await
            .unwrap();
        let fill = cache
            .begin_fill(
                cache.epoch(),
                &b,
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(60),
                Instant::now(),
                100_000,
            )
            .await
            .unwrap()
            .write(Bytes::from_static(b"abc"))
            .await
            .unwrap();
        let started = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        cache.state.lock().unwrap().hit_prepass_gate =
            Some((a.clone(), started.clone(), resume.clone()));
        let reading = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.get(&a).await })
        };
        tokio::task::spawn_blocking(move || started.wait())
            .await
            .unwrap();
        let committed = fill.commit().await;
        cache.state.lock().unwrap().hit_prepass_gate = None;
        tokio::task::spawn_blocking(move || resume.wait())
            .await
            .unwrap();
        let hit = reading.await.unwrap().unwrap();
        assert!(committed);
        assert_eq!(hit.body.collect().await.unwrap().to_bytes(), "retained");
        assert!(cache.get(&b).await.is_some());
    }

    #[tokio::test]
    async fn ordinary_writer_contention_waits_for_hit_instead_of_reporting_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let cache_key = key("contended-hit");
        cache
            .put(
                &cache_key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"retained"),
                Duration::from_secs(60),
                100_000,
            )
            .await
            .unwrap();
        let writer = cache.io_lock.clone().write_owned().await;
        let mut reading = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.get(&cache_key).await })
        };
        let waited = tokio::time::timeout(Duration::from_millis(25), &mut reading).await;
        drop(writer);
        let hit = match waited {
            Err(_) => reading.await.unwrap(),
            Ok(hit) => hit.unwrap(),
        };
        assert_eq!(
            hit.expect("ordinary writer contention must not turn an existing HIT into a MISS")
                .body
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            "retained"
        );
    }

    #[tokio::test]
    async fn fifty_mib_fill_with_status_polling_keeps_unrelated_hit_available() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let hit_key = key("polling-hit");
        let fill_key = key("fifty-mib-fill");
        const LENGTH: u64 = 50 * 1024 * 1024;
        const LIMIT: u64 = 100 * 1024 * 1024;
        cache.configure_limits(LIMIT, MAX_CACHE_ITEM_BYTES);
        cache
            .put(
                &hit_key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"retained"),
                Duration::from_secs(60),
                LIMIT,
            )
            .await
            .unwrap();
        let mut fill = cache
            .begin_fill(
                cache.epoch(),
                &fill_key,
                StatusCode::OK,
                &HeaderMap::new(),
                LENGTH,
                Duration::from_secs(60),
                Instant::now(),
                LIMIT,
            )
            .await
            .unwrap();
        let polling_cache = cache.clone();
        let polling_key = hit_key.clone();
        let polling = tokio::spawn(async move {
            for _ in 0..64 {
                assert_eq!(
                    polling_cache
                        .status_snapshot(&polling_key)
                        .await
                        .unwrap()
                        .body_length,
                    8
                );
                assert!(polling_cache.list_pins().await.unwrap().is_empty());
                let hit = polling_cache
                    .get(&polling_key)
                    .await
                    .expect("HIT remains available during large fill and UI polls");
                assert_eq!(hit.body.collect().await.unwrap().to_bytes(), "retained");
            }
        });
        let chunk = Bytes::from(vec![b'x'; IO_CHUNK_BYTES]);
        for _ in 0..LENGTH / IO_CHUNK_BYTES as u64 {
            fill = fill.write(chunk.clone()).await.unwrap();
        }
        polling.await.unwrap();
        assert!(fill.commit().await);
        assert_eq!(
            cache.status_snapshot(&fill_key).await.unwrap().body_length,
            LENGTH
        );
    }

    #[tokio::test]
    async fn complete_fill_waits_for_short_writer_contention() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let cache_key = key("writer-contention");
        let fill = cache
            .begin_fill(
                cache.epoch(),
                &cache_key,
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(60),
                Instant::now(),
                100_000,
            )
            .await
            .unwrap()
            .write(Bytes::from_static(b"abc"))
            .await
            .unwrap();
        let writer = cache.io_lock.clone().write_owned().await;
        let committing = tokio::spawn(async move { fill.commit().await });
        tokio::task::yield_now().await;
        drop(writer);
        assert!(committing.await.unwrap());
        assert!(cache.get(&cache_key).await.is_some());
    }

    #[tokio::test]
    async fn cancellation_fences_commit_waiting_to_publish() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let cancellation = CancellationToken::new();
        let cache_key = key("cancel-publication");
        let fill = cache
            .begin_fill(
                cache.epoch(),
                &cache_key,
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(60),
                Instant::now(),
                100_000,
            )
            .await
            .unwrap()
            .with_cancellation(cancellation.clone());
        let fill = fill.write(Bytes::from_static(b"abc")).await.unwrap();
        let started = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        cache.set_commit_gate(Some((started.clone(), resume.clone())));
        let committing = tokio::spawn(async move { fill.commit().await });
        tokio::task::spawn_blocking(move || started.wait())
            .await
            .unwrap();
        cache.cancel_fill(&cancellation);
        cache.set_commit_gate(None);
        tokio::task::spawn_blocking(move || resume.wait())
            .await
            .unwrap();
        assert!(!committing.await.unwrap());
        assert!(cache.get(&cache_key).await.is_none());
        assert!(cache.state.lock().unwrap().reservations.is_empty());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn slow_fill_does_not_block_unrelated_hit_and_read_lease_survives_pruning() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let first = key("hit-a");
        let second = key("fill-b");
        cache
            .put(
                &first,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"retained"),
                Duration::from_secs(60),
                1_000_000,
            )
            .await
            .unwrap();
        let fill = cache
            .begin_fill(
                cache.epoch(),
                &second,
                StatusCode::OK,
                &HeaderMap::new(),
                6,
                Duration::from_secs(60),
                Instant::now(),
                1_000_000,
            )
            .await
            .unwrap();
        let fill = fill.write(Bytes::from_static(b"par")).await.unwrap();
        let hit = tokio::time::timeout(Duration::from_secs(1), cache.get(&first))
            .await
            .unwrap()
            .expect("HIT A must survive slow B");
        // A reader of A must not deny publication of B.
        assert!(
            fill.write(Bytes::from_static(b"tial").slice(..3))
                .await
                .unwrap()
                .commit()
                .await
        );
        assert!(cache.get(&second).await.is_some());
        cache.configure_limits(0, MAX_CACHE_ITEM_BYTES);
        assert_eq!(
            cache.maintain().await.unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(dir.path().join(format!("{first}.body")).exists());
        assert_eq!(hit.body.collect().await.unwrap().to_bytes(), "retained");
        cache.maintain().await.unwrap();
        assert_eq!(cache.usage().await.used_bytes, 0);
    }

    #[tokio::test]
    async fn simultaneous_reservations_count_unwritten_bytes_and_release_after_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache.configure_limits(1700, MAX_CACHE_ITEM_BYTES);
        let headers = HeaderMap::new();
        let a = key("reservation-a");
        let b = key("reservation-b");
        let c = key("reservation-c");
        let first = cache
            .begin_fill(
                cache.epoch(),
                &a,
                StatusCode::OK,
                &headers,
                500,
                Duration::from_secs(60),
                Instant::now(),
                1700,
            )
            .await
            .unwrap();
        let second = cache
            .begin_fill(
                cache.epoch(),
                &b,
                StatusCode::OK,
                &headers,
                500,
                Duration::from_secs(60),
                Instant::now(),
                1700,
            )
            .await
            .unwrap();
        assert!(cache
            .begin_fill(
                cache.epoch(),
                &c,
                StatusCode::OK,
                &headers,
                500,
                Duration::from_secs(60),
                Instant::now(),
                1700
            )
            .await
            .is_none());
        let reservation_sum = cache
            .state
            .lock()
            .unwrap()
            .reservations
            .values()
            .map(|(_, size)| size)
            .sum::<u64>();
        assert!(reservation_sum <= 1700);
        let first = first.write(Bytes::from(vec![b'a'; 500])).await.unwrap();
        let second = second.write(Bytes::from(vec![b'b'; 500])).await.unwrap();
        assert!(first.commit().await);
        assert!(second.commit().await);
        assert!(measure_sync(dir.path()).unwrap().used_bytes <= 1700);
        let old_epoch = cache.epoch();
        let third = cache
            .begin_fill(
                old_epoch,
                &c,
                StatusCode::OK,
                &headers,
                500,
                Duration::from_secs(60),
                Instant::now(),
                1700,
            )
            .await
            .unwrap();
        cache.invalidate();
        assert!(third.write(Bytes::from(vec![b'c'; 500])).await.is_none());
        assert!(cache.state.lock().unwrap().reservations.is_empty());
        assert!(!fs::read_dir(dir.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".cache-tmp-")));
    }

    #[tokio::test]
    async fn zero_ttl_is_persisted_for_validation_and_refresh_never_becomes_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let key = key("validation");
        let mut headers = HeaderMap::new();
        headers.insert(
            "cache-control",
            HeaderValue::from_static("public, no-cache"),
        );
        cache
            .put(
                &key,
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"validate"),
                Duration::ZERO,
                10000,
            )
            .await
            .unwrap();
        assert!(cache.get(&key).await.is_none());
        let snapshot = cache.snapshot(&key).await.unwrap();
        assert!(
            cache
                .refresh(&key, &snapshot, &headers, Duration::ZERO)
                .await
        );
        assert!(cache.get(&key).await.is_none());
        assert_eq!(
            cache
                .get_including_stale(&key)
                .await
                .unwrap()
                .body
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            "validate"
        );
    }
}
