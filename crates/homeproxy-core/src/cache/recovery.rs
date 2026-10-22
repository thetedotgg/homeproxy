use super::*;
use std::sync::atomic::AtomicBool;

const MAX_RECOVERY_RECORDS: usize = 128;
const MAX_RECOVERY_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
struct Record {
    id: u64,
    base: String,
    keys: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize)]
struct Journal {
    version: u8,
    generation: String,
    next_id: u64,
    records: Vec<Record>,
}
impl Default for Journal {
    fn default() -> Self {
        Self {
            version: 1,
            generation: hex::encode(rand::random::<[u8; 16]>()),
            next_id: 1,
            records: Vec::new(),
        }
    }
}

pub(super) struct RecoveryState {
    journal: Journal,
    pub(super) blocked_keys: HashSet<String>,
    pub(super) global_blocked: Arc<AtomicBool>,
    error: Option<String>,
    persistence_error: Option<String>,
}
impl Default for RecoveryState {
    fn default() -> Self {
        Self {
            journal: Journal::default(),
            blocked_keys: HashSet::new(),
            global_blocked: Arc::new(AtomicBool::new(false)),
            error: None,
            persistence_error: None,
        }
    }
}
impl RecoveryState {
    pub(super) fn load(path: &Path) -> Self {
        match read_journal(path) {
            Ok(Some(journal)) => Self {
                blocked_keys: journal
                    .records
                    .iter()
                    .flat_map(|record| record.keys.iter().cloned())
                    .collect(),
                journal,
                ..Self::default()
            },
            Ok(None) => Self::default(),
            Err(error) => Self {
                error: Some(error.to_string()),
                global_blocked: Arc::new(AtomicBool::new(true)),
                ..Self::default()
            },
        }
    }
    pub(super) fn blocks(&self, key: &str) -> bool {
        self.global_blocked.load(Ordering::Acquire) || self.blocked_keys.contains(key)
    }
    pub(super) fn blocks_headers(&self, headers: &[(String, String)]) -> bool {
        self.global_blocked.load(Ordering::Acquire)
            || headers.iter().any(|(name, base)| {
                name == variants::BASE && (!valid_key(base) || self.blocks(base))
            })
    }
    pub(super) fn blocks_entry(&self, root: &Path, key: &str) -> bool {
        if self.blocks(key) {
            return true;
        }
        if self.blocked_keys.is_empty() {
            return false;
        }
        let path = root.join(format!("{key}.json"));
        let metadata = fs::metadata(&path)
            .ok()
            .filter(|metadata| metadata.is_file() && metadata.len() <= MAX_METADATA_BYTES as u64)
            .and_then(|_| fs::read(&path).ok())
            .and_then(|raw| serde_json::from_slice::<CacheMetadata>(&raw).ok());
        metadata.is_some_and(|metadata| self.blocks_headers(&metadata.headers))
    }

    pub(super) fn record_persistence_failure(&mut self, error: &std::io::Error) {
        self.persistence_error = Some(error.to_string());
        self.global_blocked.store(true, Ordering::Release);
    }
    fn healthy(&self) -> std::io::Result<()> {
        if let Some(error) = self.error.as_ref().or(self.persistence_error.as_ref()) {
            return Err(invalid(error));
        }
        Ok(())
    }
}

/// A durable write-ahead record. Dropping this token deliberately retains the
/// journal entry and quarantines its family in RAM. Only an explicit successful
/// finish may remove its own record. Never drop a token while holding CacheState.
pub struct CacheRecoveryToken {
    state: Weak<StdMutex<CacheState>>,
    epoch: u64,
    generation: String,
    id: u64,
}

impl Drop for CacheRecoveryToken {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        // Destruction must not panic during unwinding, or silently skip the
        // publication fence when a writer owns the mutex.
        let mut state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.recovery.journal.generation != self.generation {
            return;
        }
        let Some(record) = state
            .recovery
            .journal
            .records
            .iter()
            .find(|record| record.id == self.id)
            .cloned()
        else {
            return;
        };
        // A configuration epoch change does not resolve a durable record.
        // The base also covers candidates absent from its captured key list.
        let mut keys = record.keys;
        keys.push(record.base);
        keys.sort_unstable();
        keys.dedup();
        for key in keys {
            state.recovery.blocked_keys.insert(key.clone());
            if let Some(generation) = state.key_generations.get(&key).and_then(Weak::upgrade) {
                generation.fetch_add(1, Ordering::AcqRel);
            }
        }
        state.record_change();
    }
}

fn invalid(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}
fn check_parents(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("recovery path has no parent"))?;
    for directory in parent.ancestors() {
        if directory.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(invalid(
                    "recovery parent must be a directory without symlinks",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn validate_file(path: &Path) -> std::io::Result<Option<fs::Metadata>> {
    check_parents(path)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_RECOVERY_BYTES
    {
        return Err(invalid(
            "recovery journal must be a bounded regular file without symlinks",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(invalid("recovery journal permissions must be 0600"));
        }
    }
    Ok(Some(metadata))
}
fn read_journal(path: &Path) -> std::io::Result<Option<Journal>> {
    let Some(_) = validate_file(path)? else {
        return Ok(None);
    };
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_RECOVERY_BYTES {
        return Err(invalid("invalid opened recovery journal"));
    }
    let mut raw = Vec::new();
    file.take(MAX_RECOVERY_BYTES + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_RECOVERY_BYTES {
        return Err(invalid("recovery journal exceeds size limit"));
    }
    let journal: Journal = serde_json::from_slice(&raw).map_err(std::io::Error::other)?;
    let mut ids = HashSet::new();
    if journal.version != 1
        || journal.generation.len() != 32
        || hex::decode(&journal.generation).is_err()
        || journal.next_id == 0
        || journal.records.len() > MAX_RECOVERY_RECORDS
    {
        return Err(invalid("invalid recovery journal"));
    }
    for record in &journal.records {
        if record.id == 0
            || record.id >= journal.next_id
            || !ids.insert(record.id)
            || !valid_key(&record.base)
            || record.keys.is_empty()
            || record.keys.len() > MAX_CACHE_ENTRIES
            || !record.keys.contains(&record.base)
            || record.keys.iter().any(|key| !valid_key(key))
        {
            return Err(invalid("invalid recovery record"));
        }
    }
    Ok(Some(journal))
}

pub(super) fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?
            .sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn persist_journal(path: &Path, journal: &Journal) -> std::io::Result<()> {
    let raw = serde_json::to_vec(journal).map_err(std::io::Error::other)?;
    if raw.len() as u64 > MAX_RECOVERY_BYTES {
        return Err(invalid("recovery journal exceeds size limit"));
    }
    check_parents(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("recovery path has no parent"))?;
    fs::create_dir_all(parent)?;
    check_parents(path)?;
    validate_file(path)?;
    let mut temporary = Builder::new()
        .prefix(".cache-recovery-tmp-")
        .tempfile_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(&raw)?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_directory(parent)
}

impl CacheStore {
    pub(crate) fn recovery_blocks_family(&self, base: &str) -> bool {
        self.state.lock().unwrap().recovery.blocks(base)
    }

    /// Must complete before contacting an origin for an existing cache family.
    pub fn begin_recovery_checkpoint(
        &self,
        expected_epoch: u64,
        base: &str,
        keys: &[String],
        request_guard: &CacheKeyGuard,
    ) -> std::io::Result<CacheRecoveryToken> {
        if !valid_key(base)
            || keys.len() >= MAX_CACHE_ENTRIES
            || keys.iter().any(|key| !valid_key(key))
        {
            return Err(invalid("invalid recovery family"));
        }
        let mut state = self.state.lock().unwrap();
        state.recovery.healthy()?;
        if state.epoch != expected_epoch
            || state.pending_clear
            || !request_guard.is_current()
            || state.recovery.blocks(base)
            || keys.iter().any(|key| state.recovery.blocks(key))
        {
            return Err(busy());
        }
        if state.recovery.journal.records.len() >= MAX_RECOVERY_RECORDS {
            return Err(busy());
        }
        let mut journal = state.recovery.journal.clone();
        let id = journal.next_id;
        journal.next_id = journal
            .next_id
            .checked_add(1)
            .ok_or_else(|| invalid("recovery ID limit exceeded"))?;
        let mut keys = keys.to_vec();
        keys.push(base.to_owned());
        keys.sort_unstable();
        keys.dedup();
        journal.records.push(Record {
            id,
            base: base.to_owned(),
            keys,
        });
        if let Err(error) = persist_journal(&self.recovery_path, &journal) {
            state.recovery.record_persistence_failure(&error);
            state.maintenance_failure = Some((error.kind(), error.to_string()));
            return Err(error);
        }
        state.recovery.journal = journal;
        Ok(CacheRecoveryToken {
            state: Arc::downgrade(&self.state),
            epoch: expected_epoch,
            generation: state.recovery.journal.generation.clone(),
            id,
        })
    }

    pub fn finish_recovery_checkpoint(&self, token: &CacheRecoveryToken) -> std::io::Result<()> {
        if !token
            .state
            .upgrade()
            .is_some_and(|owner| Arc::ptr_eq(&owner, &self.state))
        {
            return Err(busy());
        }
        let mut state = self.state.lock().unwrap();
        state.recovery.healthy()?;
        if state.epoch != token.epoch
            || state.pending_clear
            || state.recovery.journal.generation != token.generation
        {
            return Err(busy());
        }
        let mut journal = state.recovery.journal.clone();
        journal.records.retain(|record| record.id != token.id);
        // An already successfully finished token is idempotent, but never
        // removes another concurrent record with the same family.
        if journal.records.len() == state.recovery.journal.records.len() {
            return Ok(());
        }
        if let Err(error) = persist_journal(&self.recovery_path, &journal) {
            state.recovery.record_persistence_failure(&error);
            state.maintenance_failure = Some((error.kind(), error.to_string()));
            return Err(error);
        }
        state.recovery.journal = journal;
        Ok(())
    }

    pub(super) fn clear_recovery_locked(&self, state: &mut CacheState) -> std::io::Result<()> {
        check_parents(&self.recovery_path)?;
        match fs::symlink_metadata(&self.recovery_path) {
            Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                fs::remove_file(&self.recovery_path)?;
                sync_directory(
                    self.recovery_path
                        .parent()
                        .ok_or_else(|| invalid("recovery path has no parent"))?,
                )?;
            }
            Ok(_) => return Err(invalid("cannot clear a non-regular recovery journal")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // Keep the shared global flag so pre-clear guards observe recovery.
        let global_blocked = state.recovery.global_blocked.clone();
        global_blocked.store(false, Ordering::Release);
        state.recovery = RecoveryState {
            global_blocked,
            ..RecoveryState::default()
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(value: &str) -> String {
        hex::encode(Sha256::digest(value.as_bytes()))
    }
    fn paths(directory: &Path) -> (PathBuf, PathBuf) {
        (
            directory.join("cache"),
            directory.join("config").join("recovery"),
        )
    }
    async fn fixture(root: &Path, recovery: &Path) -> (CacheStore, String, String) {
        let cache = CacheStore::new_with_recovery(root.to_owned(), recovery.to_owned());
        cache.configure_limits(100_000, MAX_CACHE_ITEM_BYTES);
        let base = key("family");
        let selected = key("selected");
        let mut headers = HeaderMap::new();
        headers.insert(variants::BASE, HeaderValue::from_str(&base).unwrap());
        headers.insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=600"),
        );
        cache
            .put(
                &selected,
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"public-body"),
                Duration::from_secs(600),
                100_000,
            )
            .await
            .unwrap();
        cache
            .pin(&selected, &cache.snapshot(&selected).await.unwrap())
            .await
            .unwrap();
        (cache, base, selected)
    }

    #[tokio::test]
    async fn abandoned_checkpoint_blocks_ram_and_restart_while_pin_controls_and_other_family_work()
    {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, base, selected) = fixture(&root, &recovery).await;
        let unrelated = key("unrelated-family");
        cache
            .put(
                &unrelated,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"unrelated"),
                Duration::from_secs(600),
                100_000,
            )
            .await
            .unwrap();
        let unrelated_guard = cache.key_guard(&unrelated).unwrap();
        let expected = cache.snapshot(&selected).await.unwrap();
        let guard = cache.key_guard(&base).unwrap();
        let token = cache
            .begin_recovery_checkpoint(
                cache.epoch(),
                &base,
                std::slice::from_ref(&selected),
                &guard,
            )
            .unwrap();
        let revision = cache.state.lock().unwrap().usage_revision;
        drop(token);
        assert!(!guard.is_current());
        assert!(unrelated_guard.is_current());
        assert!(cache.state.lock().unwrap().usage_revision > revision);
        assert!(!cache
            .state
            .lock()
            .unwrap()
            .recovery
            .global_blocked
            .load(Ordering::Acquire));
        assert!(cache.get(&selected).await.is_none());
        assert!(cache.get_including_stale(&selected).await.is_none());
        assert!(cache.snapshot(&selected).await.is_none());
        assert!(cache.status_snapshot(&selected).await.is_none());
        assert!(cache.key_guard(&selected).is_none());
        assert!(cache.pin(&selected, &expected).await.is_err());
        assert!(cache
            .begin_fill(
                cache.epoch(),
                &selected,
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(60),
                Instant::now(),
                100_000,
            )
            .await
            .is_none());
        assert_eq!(cache.list_pins().await.unwrap().len(), 1);
        assert!(!cache.pin_usage().await.degraded);
        assert!(cache.get(&unrelated).await.is_some());
        assert_eq!(read_journal(&recovery).unwrap().unwrap().records.len(), 1);
        drop(cache);
        let restarted = CacheStore::new_with_recovery(root, recovery);
        assert!(restarted.get(&selected).await.is_none());
        assert!(restarted.snapshot(&selected).await.is_none());
        assert!(restarted.status_snapshot(&selected).await.is_none());
        assert!(restarted.get(&unrelated).await.is_some());
        assert_eq!(restarted.list_pins().await.unwrap().len(), 1);
        assert_eq!(restarted.unpin(&selected).await.unwrap().entry_count, 0);
        assert!(restarted.get(&unrelated).await.is_some());
    }

    #[tokio::test]
    async fn abandonment_after_epoch_change_retires_other_writers_and_other_token_cannot_unblock() {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, base, selected) = fixture(&root, &recovery).await;
        let writing = key("other-same-family-writer");
        let keys = vec![selected.clone(), writing.clone()];
        let guard = cache.key_guard(&base).unwrap();
        let first = cache
            .begin_recovery_checkpoint(cache.epoch(), &base, &keys, &guard)
            .unwrap();
        cache.configure_limits(99_000, MAX_CACHE_ITEM_BYTES);
        assert_ne!(first.epoch, cache.epoch());
        let other_guard = cache.key_guard(&base).unwrap();
        let writer_guard = cache.key_guard(&writing).unwrap();
        let second = cache
            .begin_recovery_checkpoint(cache.epoch(), &base, &keys, &other_guard)
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(variants::BASE, HeaderValue::from_str(&base).unwrap());
        let fill = cache
            .begin_fill_guarded(
                cache.epoch(),
                &writing,
                StatusCode::OK,
                &headers,
                3,
                Duration::from_secs(600),
                Instant::now(),
                99_000,
                &other_guard,
            )
            .await
            .unwrap()
            .write(Bytes::from_static(b"new"))
            .await
            .unwrap();
        drop(first);
        assert!(!guard.is_current());
        assert!(!other_guard.is_current());
        assert!(!writer_guard.is_current());
        assert!(cache.recovery_blocks_family(&base));
        assert!(!fill.commit().await);
        assert!(!root.join(format!("{writing}.json")).exists());
        cache.finish_recovery_checkpoint(&second).unwrap();
        let journal = read_journal(&recovery).unwrap().unwrap();
        assert_eq!(journal.records.len(), 1);
        assert_ne!(journal.records[0].id, second.id);
        drop(second);
        assert!(cache.recovery_blocks_family(&base));
        assert!(cache.get(&selected).await.is_none());
        assert!(cache.key_guard(&base).is_none());
        drop(cache);
        let restarted = CacheStore::new_with_recovery(root, recovery);
        assert!(restarted.get(&selected).await.is_none());
    }

    #[tokio::test]
    async fn abandoned_token_drop_recovers_poisoned_mutex_without_panicking() {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, base, selected) = fixture(&root, &recovery).await;
        let guard = cache.key_guard(&base).unwrap();
        let token = cache
            .begin_recovery_checkpoint(
                cache.epoch(),
                &base,
                std::slice::from_ref(&selected),
                &guard,
            )
            .unwrap();
        let state = cache.state.clone();
        assert!(std::thread::spawn(move || {
            let _state = state.lock().unwrap();
            panic!("injected poisoned publication mutex");
        })
        .join()
        .is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(token))).is_ok());
        let state = cache
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(state.recovery.blocks(&base));
        assert!(state.recovery.blocks(&selected));
        assert!(!guard.is_current());
        assert_eq!(state.recovery.journal.records.len(), 1);
    }
    #[tokio::test]
    async fn metadata_stat_denial_retains_recovery_and_tombstones_without_authorizing_successor() {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, base, selected) = fixture(&root, &recovery).await;
        let guard = cache.key_guard(&base).unwrap();
        let token = cache
            .begin_recovery_checkpoint(
                cache.epoch(),
                &base,
                std::slice::from_ref(&selected),
                &guard,
            )
            .unwrap();
        let older = key("older-tombstone");
        cache
            .state
            .lock()
            .unwrap()
            .invalidated_keys
            .insert(older.clone());
        cache.set_invalidation_stat_failure(true);
        assert!(cache
            .invalidate_keys_and_request_at_epoch(
                cache.epoch(),
                std::slice::from_ref(&selected),
                &guard
            )
            .is_none());
        {
            let state = cache.state.lock().unwrap();
            assert!(state.invalidated_keys.contains(&selected));
            assert!(state.invalidated_keys.contains(&older));
            assert!(state.recovery.global_blocked.load(Ordering::Acquire));
        }
        assert!(cache.finish_recovery_checkpoint(&token).is_err());
        assert_eq!(read_journal(&recovery).unwrap().unwrap().records.len(), 1);
        let metadata: CacheMetadata =
            serde_json::from_slice(&fs::read(root.join(format!("{selected}.json"))).unwrap())
                .unwrap();
        assert!(!metadata.invalidated);
        drop(token);
        drop(cache);
        let restarted = CacheStore::new_with_recovery(root, recovery);
        assert!(restarted.get(&selected).await.is_none());
        assert!(restarted.status_snapshot(&selected).await.is_none());
        assert_eq!(restarted.list_pins().await.unwrap().len(), 1);
        restarted.unpin(&selected).await.unwrap();
    }

    #[tokio::test]
    async fn failed_restrictive_persistence_retains_checkpoint_across_restart_and_unpin_works() {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, base, selected) = fixture(&root, &recovery).await;
        let guard = cache.key_guard(&base).unwrap();
        let token = cache
            .begin_recovery_checkpoint(
                cache.epoch(),
                &base,
                std::slice::from_ref(&selected),
                &guard,
            )
            .unwrap();
        cache.set_invalidation_persist_failure(true);
        assert!(
            cache
                .invalidate_keys_and_request_at_epoch(
                    cache.epoch(),
                    std::slice::from_ref(&selected),
                    &guard
                )
                .is_none(),
            "failed durable invalidation cannot authorize a successor"
        );
        assert!(cache.finish_recovery_checkpoint(&token).is_err());
        let metadata: CacheMetadata =
            serde_json::from_slice(&fs::read(root.join(format!("{selected}.json"))).unwrap())
                .unwrap();
        assert!(
            !metadata.invalidated,
            "fixture must preserve the actual old public metadata after denied write"
        );
        assert_eq!(read_journal(&recovery).unwrap().unwrap().records.len(), 1);
        drop(token);
        drop(guard);
        drop(cache);
        let cache = CacheStore::new_with_recovery(root.clone(), recovery.clone());
        cache.configure_limits(100_000, MAX_CACHE_ITEM_BYTES);
        assert!(cache.get(&selected).await.is_none());
        assert!(cache.get_including_stale(&selected).await.is_none());
        assert!(cache.snapshot(&selected).await.is_none());
        assert!(cache.status_snapshot(&selected).await.is_none());
        assert_eq!(cache.list_pins().await.unwrap().len(), 1);
        assert!(!cache.pin_usage().await.degraded);
        assert_eq!(cache.unpin(&selected).await.unwrap().entry_count, 0);
        assert!(cache
            .begin_fill(
                cache.epoch(),
                &selected,
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(60),
                Instant::now(),
                100_000
            )
            .await
            .is_none());
        cache.clear().await.unwrap();
        assert!(!recovery.exists());
        assert!(!cache.recovery_blocks_family(&base));
    }

    #[tokio::test]
    async fn concurrent_checkpoints_finish_independently_and_drop_is_not_completion() {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, base, selected) = fixture(&root, &recovery).await;
        let guard = cache.key_guard(&base).unwrap();
        let first = cache
            .begin_recovery_checkpoint(
                cache.epoch(),
                &base,
                std::slice::from_ref(&selected),
                &guard,
            )
            .unwrap();
        let second = cache
            .begin_recovery_checkpoint(
                cache.epoch(),
                &base,
                std::slice::from_ref(&selected),
                &guard,
            )
            .unwrap();
        assert_ne!(first.id, second.id);
        cache.finish_recovery_checkpoint(&first).unwrap();
        cache.finish_recovery_checkpoint(&first).unwrap();
        assert_eq!(read_journal(&recovery).unwrap().unwrap().records.len(), 1);
        drop(first);
        drop(second);
        drop(cache);
        let restarted = CacheStore::new_with_recovery(root, recovery);
        assert!(restarted.get_including_stale(&selected).await.is_none());
        assert_eq!(restarted.list_pins().await.unwrap().len(), 1);
        restarted.unpin(&selected).await.unwrap();
    }

    #[tokio::test]
    async fn successful_checkpoint_finish_preserves_normal_offline_reuse() {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, base, selected) = fixture(&root, &recovery).await;
        let guard = cache.key_guard(&base).unwrap();
        let token = cache
            .begin_recovery_checkpoint(
                cache.epoch(),
                &base,
                std::slice::from_ref(&selected),
                &guard,
            )
            .unwrap();
        cache.finish_recovery_checkpoint(&token).unwrap();
        assert!(read_journal(&recovery).unwrap().unwrap().records.is_empty());
        drop(token);
        assert!(guard.is_current());
        assert!(!cache.recovery_blocks_family(&base));
        assert!(cache.get(&selected).await.is_some());
        assert!(cache.status_snapshot(&selected).await.is_some());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&recovery).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(cache);
        let cache = CacheStore::new_with_recovery(root, recovery);
        assert!(cache.get(&selected).await.is_some());
        assert!(cache.status_snapshot(&selected).await.is_some());
        assert_eq!(cache.list_pins().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn recovery_base_blocks_unknown_candidate_published_after_checkpoint_capture() {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, base, selected) = fixture(&root, &recovery).await;
        let guard = cache.key_guard(&base).unwrap();
        let token = cache
            .begin_recovery_checkpoint(
                cache.epoch(),
                &base,
                std::slice::from_ref(&selected),
                &guard,
            )
            .unwrap();
        let later = key("later-candidate");
        let mut headers = HeaderMap::new();
        headers.insert(variants::BASE, HeaderValue::from_str(&base).unwrap());
        cache
            .put(
                &later,
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"later"),
                Duration::from_secs(600),
                100_000,
            )
            .await
            .unwrap();
        assert!(!read_journal(&recovery).unwrap().unwrap().records[0]
            .keys
            .contains(&later));
        drop(token);
        assert!(cache.get(&later).await.is_none());
        assert!(cache.get_including_stale(&later).await.is_none());
        assert!(cache.snapshot(&later).await.is_none());
        assert!(cache.status_snapshot(&later).await.is_none());
        assert!(cache.key_guard(&later).is_none());
        drop(cache);
        let cache = CacheStore::new_with_recovery(root, recovery);
        assert!(cache.get(&later).await.is_none());
        assert!(cache.get_including_stale(&later).await.is_none());
        assert!(cache.snapshot(&later).await.is_none());
        assert!(cache.status_snapshot(&later).await.is_none());
        assert!(cache.key_guard(&later).is_none());
        assert!(cache
            .put(
                &key("new-candidate"),
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"new"),
                Duration::from_secs(60),
                100_000
            )
            .await
            .is_err());
        assert_eq!(cache.list_pins().await.unwrap().len(), 1);
        cache.unpin(&selected).await.unwrap();
    }

    #[tokio::test]
    async fn journal_io_failure_denies_checkpoint_and_reuse_without_breaking_pin_controls() {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, base, selected) = fixture(&root, &recovery).await;
        let guard = cache.key_guard(&base).unwrap();
        fs::create_dir_all(&recovery).unwrap();
        assert!(cache
            .begin_recovery_checkpoint(
                cache.epoch(),
                &base,
                std::slice::from_ref(&selected),
                &guard
            )
            .is_err());
        assert!(cache.get(&selected).await.is_none());
        assert!(cache.status_snapshot(&selected).await.is_none());
        assert_eq!(cache.list_pins().await.unwrap().len(), 1);
        cache.unpin(&selected).await.unwrap();
    }

    #[tokio::test]
    async fn corrupt_journal_blocks_global_reuse_but_unpin_and_explicit_clear_work() {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, _, selected) = fixture(&root, &recovery).await;
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        fs::write(&recovery, b"corrupt journal").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&recovery, fs::Permissions::from_mode(0o600)).unwrap();
        }
        drop(cache);
        let cache = CacheStore::new_with_recovery(root.clone(), recovery.clone());
        assert!(cache.get(&selected).await.is_none());
        assert!(cache.status_snapshot(&selected).await.is_none());
        assert!(cache.key_guard(&key("unrelated")).is_none());
        assert_eq!(cache.list_pins().await.unwrap().len(), 1);
        assert_eq!(cache.unpin(&selected).await.unwrap().entry_count, 0);
        cache.clear().await.unwrap();
        assert!(!recovery.exists());
        cache
            .put(
                &selected,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"recovered"),
                Duration::from_secs(60),
                100_000,
            )
            .await
            .unwrap();
        assert!(cache.get(&selected).await.is_some());
    }

    #[tokio::test]
    async fn late_finish_after_clear_cannot_remove_a_new_session_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, base, selected) = fixture(&root, &recovery).await;
        let guard = cache.key_guard(&base).unwrap();
        let old = cache
            .begin_recovery_checkpoint(
                cache.epoch(),
                &base,
                std::slice::from_ref(&selected),
                &guard,
            )
            .unwrap();
        cache.clear().await.unwrap();
        let guard = cache.key_guard(&base).unwrap();
        let current = cache
            .begin_recovery_checkpoint(cache.epoch(), &base, &[], &guard)
            .unwrap();
        assert_ne!(old.generation, current.generation);
        assert_eq!(
            old.id, current.id,
            "clear reuses IDs only in a new generation"
        );
        assert!(cache.finish_recovery_checkpoint(&old).is_err());
        assert_eq!(read_journal(&recovery).unwrap().unwrap().records.len(), 1);
        drop(old);
        assert!(guard.is_current());
        assert!(!cache.recovery_blocks_family(&base));
        let mut headers = HeaderMap::new();
        headers.insert(variants::BASE, HeaderValue::from_str(&base).unwrap());
        cache
            .put(
                &selected,
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"new-session-public"),
                Duration::from_secs(600),
                100_000,
            )
            .await
            .unwrap();
        assert!(cache.get(&selected).await.is_some());
        assert_eq!(read_journal(&recovery).unwrap().unwrap().records.len(), 1);
        cache.finish_recovery_checkpoint(&current).unwrap();
        assert!(read_journal(&recovery).unwrap().unwrap().records.is_empty());
        drop(current);
        assert!(guard.is_current());
        assert!(cache.get(&selected).await.is_some());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_journal_is_rejected_and_clear_unlinks_only_the_link() {
        let directory = tempfile::tempdir().unwrap();
        let (root, recovery) = paths(directory.path());
        let (cache, _, selected) = fixture(&root, &recovery).await;
        fs::create_dir_all(recovery.parent().unwrap()).unwrap();
        let target = directory.path().join("external");
        fs::write(&target, b"preserve").unwrap();
        std::os::unix::fs::symlink(&target, &recovery).unwrap();
        drop(cache);
        let cache = CacheStore::new_with_recovery(root, recovery.clone());
        assert!(cache.get(&selected).await.is_none());
        assert_eq!(cache.list_pins().await.unwrap().len(), 1);
        cache.unpin(&selected).await.unwrap();
        cache.clear().await.unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"preserve");
        assert!(!recovery.exists());
    }
}
