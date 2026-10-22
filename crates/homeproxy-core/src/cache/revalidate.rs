use super::*;

/// Verified metadata detached from the body lease. It can safely survive an origin roundtrip.
#[derive(Clone)]
pub struct CacheSnapshot {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub online_validation_required: bool,
    pub age: Duration,
    pub remaining_ttl: Duration,
    pub stale_for: Duration,
    pub body_length: u64,
    pub(super) epoch: u64,
    pub(super) key_guard: CacheKeyGuard,
    pub(super) integrity_verified: bool,
    pub(super) fingerprint: Vec<u8>,
}

impl CacheStore {
    pub async fn snapshot(&self, key: &str) -> Option<CacheSnapshot> {
        let epoch = self.epoch();
        let key_guard = self.key_guard(key)?;
        let mut entry = self.get_including_stale(key).await?;
        self.snapshot_verified_entry(key, epoch, key_guard, &mut entry)
            .await
    }

    /// Reconciles metadata with the immutable verified body while its entry
    /// lease is still alive. Refresh may update metadata during body hashing.
    pub(super) async fn snapshot_verified_entry(
        &self,
        key: &str,
        epoch: u64,
        key_guard: CacheKeyGuard,
        entry: &mut CachedEntry,
    ) -> Option<CacheSnapshot> {
        let raw = tokio::fs::read(self.root.join(format!("{key}.json")))
            .await
            .ok()?;
        if raw.len() > MAX_METADATA_BYTES {
            return None;
        }
        let metadata: CacheMetadata = serde_json::from_slice(&raw).ok()?;
        let (length, sha256) = entry.body.verified_representation()?;
        if metadata.version != 1
            || metadata.invalidated
            || metadata.fragments.is_some()
            || metadata.body_length != length
            || metadata.body_sha256 != sha256
            || self
                .state
                .lock()
                .unwrap()
                .recovery
                .blocks_headers(&metadata.headers)
            || !key_guard.is_current()
            || !self.valid_epoch(epoch)
            || self.state.lock().unwrap().invalidated_keys.contains(key)
        {
            return None;
        }
        let now = unix_seconds();
        entry.status = StatusCode::from_u16(metadata.status).ok()?;
        entry.headers = deserialize_headers(metadata.headers)?;
        entry.age = Duration::from_secs(now.saturating_sub(metadata.stored_unix_seconds));
        entry.remaining_ttl =
            Duration::from_secs(metadata.expires_unix_seconds.saturating_sub(now));
        Some(CacheSnapshot {
            status: entry.status,
            headers: entry.headers.clone(),
            online_validation_required: metadata.online_validation_required
                || metadata.expires_unix_seconds <= metadata.stored_unix_seconds,
            key_guard,
            integrity_verified: true,
            age: entry.age,
            remaining_ttl: entry.remaining_ttl,
            stale_for: Duration::from_secs(now.saturating_sub(metadata.expires_unix_seconds)),
            body_length: metadata.body_length,
            epoch,
            fingerprint: Sha256::digest(&raw).to_vec(),
        })
    }

    /// Metadata-only readiness estimate for the control UI. This does not verify
    /// body SHA256 and cannot authorize a HIT, pin or validation refresh.
    pub async fn status_snapshot(&self, key: &str) -> Option<CacheSnapshot> {
        let key_guard = self.key_guard(key)?;
        let epoch = self.epoch();
        let guard = self.io_lock.clone().try_read_owned().ok()?;
        let lease = EntryLease::new(self, key);
        drop(guard);
        let cache = self.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            let metadata_path = cache.root.join(format!("{key}.json"));
            let body_path = cache.root.join(format!("{key}.body"));
            let metadata_stat = fs::symlink_metadata(&metadata_path).ok()?;
            let body_stat = fs::symlink_metadata(&body_path).ok()?;
            if !metadata_stat.is_file()
                || !body_stat.is_file()
                || metadata_stat.len() > MAX_METADATA_BYTES as u64
            {
                return None;
            }
            let modified = body_stat.modified().ok()?;
            let raw = fs::read(&metadata_path).ok()?;
            let metadata: CacheMetadata = serde_json::from_slice(&raw).ok()?;
            if metadata.version != 1
                || metadata.invalidated
                || metadata.fragments.is_some()
                || metadata.body_length > cache.max_object_bytes()
                || metadata.body_length != body_stat.len()
                || !valid_key(&metadata.body_sha256)
                || cache
                    .state
                    .lock()
                    .unwrap()
                    .recovery
                    .blocks_headers(&metadata.headers)
            {
                return None;
            }
            let body_after = fs::symlink_metadata(&body_path).ok()?;
            if !body_after.is_file()
                || body_after.len() != body_stat.len()
                || body_after.modified().ok()? != modified
                || !key_guard.is_current()
                || !cache.valid_epoch(epoch)
                || cache.state.lock().unwrap().invalidated_keys.contains(&key)
            {
                return None;
            }
            let now = unix_seconds();
            Some(CacheSnapshot {
                status: StatusCode::from_u16(metadata.status).ok()?,
                headers: deserialize_headers(metadata.headers)?,
                online_validation_required: metadata.online_validation_required
                    || metadata.expires_unix_seconds <= metadata.stored_unix_seconds,
                age: Duration::from_secs(now.saturating_sub(metadata.stored_unix_seconds)),
                remaining_ttl: Duration::from_secs(
                    metadata.expires_unix_seconds.saturating_sub(now),
                ),
                stale_for: Duration::from_secs(now.saturating_sub(metadata.expires_unix_seconds)),
                body_length: metadata.body_length,
                epoch,
                key_guard,
                integrity_verified: false,
                fingerprint: Sha256::digest(&raw).to_vec(),
            })
        })
        .await
        .ok()
        .flatten()
    }

    pub async fn get_if_snapshot(
        &self,
        key: &str,
        expected: &CacheSnapshot,
    ) -> Option<CachedEntry> {
        if !expected.integrity_verified
            || !expected.key_guard.is_current()
            || !self.valid_epoch(expected.epoch)
        {
            return None;
        }
        let entry = self.get_including_stale(key).await?;
        let raw = tokio::fs::read(self.root.join(format!("{key}.json")))
            .await
            .ok()?;
        if !self.valid_epoch(expected.epoch)
            || !expected.key_guard.is_current()
            || Sha256::digest(&raw).as_slice() != expected.fingerprint.as_slice()
        {
            return None;
        }
        Some(entry)
    }

    /// A restrictive replacement invalidates reuse immediately, even during an active read lease.
    #[cfg(test)]
    pub fn invalidate_key(&self, key: &str) {
        if !valid_key(key) {
            return;
        }
        let mut state = self.state.lock().unwrap();
        let _ = self.invalidate_one_locked(key, &mut state);
    }

    /// Retires only the named entries; unrelated in-flight responses keep their epoch.
    #[cfg(test)]
    pub(crate) fn invalidate_keys_at_epoch(
        &self,
        expected_epoch: u64,
        keys: &[String],
    ) -> Option<u64> {
        let guard = keys.first().and_then(|key| self.key_guard(key));
        match guard {
            Some(guard) => self.invalidate_keys_at_epoch_guarded(expected_epoch, keys, &guard),
            None if keys.is_empty() => Some(self.epoch()),
            None => None,
        }
    }

    pub(crate) fn invalidate_keys_at_epoch_guarded(
        &self,
        expected_epoch: u64,
        keys: &[String],
        request_guard: &CacheKeyGuard,
    ) -> Option<u64> {
        if keys.iter().any(|key| !valid_key(key)) {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        if !request_guard.is_current() || state.epoch != expected_epoch || state.pending_clear {
            return None;
        }
        for key in keys {
            self.invalidate_one_locked(key, &mut state).ok()?;
        }
        Some(state.epoch)
    }

    /// Atomically retires selected entries and the pre-origin request token.
    /// The returned successor authorizes this replacement without adopting a
    /// later invalidation between retirement and a fresh key_guard lookup.
    pub(crate) fn invalidate_keys_and_request_at_epoch(
        &self,
        expected_epoch: u64,
        keys: &[String],
        request_guard: &CacheKeyGuard,
    ) -> Option<(u64, CacheKeyGuard)> {
        if keys.iter().any(|key| !valid_key(key)) {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        if !request_guard.is_current() || state.epoch != expected_epoch || state.pending_clear {
            return None;
        }
        for key in keys {
            self.invalidate_one_locked(key, &mut state).ok()?;
        }
        let _ = request_guard.generation.compare_exchange(
            request_guard.expected,
            request_guard.expected.wrapping_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let successor = CacheKeyGuard {
            generation: request_guard.generation.clone(),
            expected: request_guard.generation.load(Ordering::Acquire),
            state: request_guard.state.clone(),
            recovery_blocked: request_guard.recovery_blocked.clone(),
        };
        Some((state.epoch, successor))
    }

    fn invalidate_one_locked(&self, key: &str, state: &mut CacheState) -> std::io::Result<()> {
        state
            .key_generations
            .retain(|_, generation| generation.strong_count() > 0);
        let active = state.key_generations.get(key).and_then(Weak::upgrade);
        if let Some(generation) = &active {
            generation.fetch_add(1, Ordering::AcqRel);
        }
        #[cfg(test)]
        let metadata_result = if state.fail_invalidation_stat {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "test cache metadata stat denied",
            ))
        } else {
            fs::metadata(self.root.join(format!("{key}.json")))
        };
        #[cfg(not(test))]
        let metadata_result = fs::metadata(self.root.join(format!("{key}.json")));
        let on_disk = match metadata_result {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                state.invalidated_keys.insert(key.to_owned());
                state.recovery.record_persistence_failure(&error);
                state.maintenance_failure = Some((error.kind(), error.to_string()));
                state.record_change();
                return Err(error);
            }
        };
        if !on_disk && active.is_none() {
            return Ok(());
        }
        // Disk metadata is the persistent tombstone. Absent keys need only the
        // finite live generation token; they never consume disk-entry tombstones.
        if on_disk {
            state
                .invalidated_keys
                .retain(|entry| !matches!(fs::metadata(self.root.join(format!("{entry}.json"))), Err(error) if error.kind() == std::io::ErrorKind::NotFound));
            state.invalidated_keys.insert(key.to_owned());
            self.persist_invalidation_locked(key, state)?;
        }
        state.record_change();
        Ok(())
    }

    fn persist_invalidation_locked(
        &self,
        key: &str,
        state: &mut CacheState,
    ) -> std::io::Result<()> {
        let result = (|| -> std::io::Result<()> {
            #[cfg(test)]
            if state.fail_invalidation_persist {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "test cache metadata persistence denied",
                ));
            }
            let path = self.root.join(format!("{key}.json"));
            let raw = match fs::read(&path) {
                Ok(raw) => raw,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
            };
            if raw.len() > MAX_METADATA_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid cache metadata",
                ));
            }
            let mut metadata: CacheMetadata =
                serde_json::from_slice(&raw).map_err(std::io::Error::other)?;
            metadata.invalidated = true;
            let raw = serde_json::to_vec(&metadata).map_err(std::io::Error::other)?;
            // This synchronous invalidation can overlap a pruning scan. A distinct
            // temporary prefix keeps that scan from treating publication as stale.
            let mut temporary = Builder::new()
                .prefix(".cache-invalidation-")
                .tempfile_in(&self.root)?;
            temporary.write_all(&raw)?;
            temporary.as_file_mut().sync_all()?;
            persist_replace(temporary, &path)?;
            recovery::sync_directory(&self.root)?;

            if let Some(pin) = state.pins.entries.get_mut(key) {
                pin.entry_bytes = metadata.body_length.saturating_add(raw.len() as u64);
                pin.bytes = pin.entry_bytes;
            }
            Ok(())
        })();
        if let Err(error) = &result {
            // Deny reuse in this process and surface the persistence failure.
            state.maintenance_failure = Some((error.kind(), error.to_string()));
            state.recovery.record_persistence_failure(error);
            state.record_change();
        }
        result
    }

    pub async fn remove_invalidated(&self, key: &str) -> std::io::Result<()> {
        if !valid_key(key) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid cache key",
            ));
        }
        // Best-effort cleanup: the tombstone already denies reuse and leftover
        // files go on a later call or eviction, so it never queues behind stores.
        let guard = self.io_lock.clone().try_write_owned().map_err(|_| busy())?;
        let cache = self.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            cache.load_pins_locked()?;
            let mut state = cache.state.lock().unwrap();
            let path = cache.root.join(format!("{key}.json"));
            let invalidated = state.invalidated_keys.contains(&key)
                || fs::read(&path)
                    .ok()
                    .and_then(|raw| serde_json::from_slice::<CacheMetadata>(&raw).ok())
                    .is_some_and(|metadata| metadata.invalidated);
            if !invalidated {
                return Ok(());
            }
            if state.readers.contains_key(&key)
                || state.pins.entries.contains_key(&key)
                || state.reservations.values().any(|(entry, _)| entry == &key)
            {
                return Err(busy());
            }
            remove_cache_file(&path)?;
            remove_cache_file(&cache.root.join(format!("{key}.body")))?;
            state.invalidated_keys.remove(&key);
            state.record_change();
            Ok(())
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn refresh(
        &self,
        key: &str,
        expected: &CacheSnapshot,
        headers: &HeaderMap,
        ttl: Duration,
    ) -> bool {
        #[cfg(test)]
        if self.state.lock().unwrap().force_refresh_failure {
            return false;
        }
        if !expected.integrity_verified {
            return false;
        }
        let Ok(headers) = serialize_headers(headers) else {
            return false;
        };
        // A failed refresh retires the validated entry, so ordinary contention
        // from a parallel page load waits briefly instead of discarding it.
        let Ok(guard) =
            tokio::time::timeout(CACHE_STORE_WAIT, self.io_lock.clone().write_owned()).await
        else {
            return false;
        };
        let cache = self.clone();
        let key = key.to_owned();
        let expected = expected.clone();
        tokio::task::spawn_blocking(move || -> Option<()> {
            let _guard = guard;
            if !expected.key_guard.is_current() || !cache.valid_epoch(expected.epoch) {
                return None;
            }
            cache.load_pins_locked().ok()?;
            {
                let state = cache.state.lock().unwrap();
                if state.reservations.values().any(|(entry, _)| entry == &key) {
                    return None;
                }
            }
            let path = cache.root.join(format!("{key}.json"));
            let raw = fs::read(&path).ok()?;
            if Sha256::digest(&raw).as_slice() != expected.fingerprint.as_slice() {
                return None;
            }
            let mut metadata: CacheMetadata = serde_json::from_slice(&raw).ok()?;
            if metadata.invalidated {
                return None;
            }
            metadata.headers = headers;
            metadata.online_validation_required = ttl.is_zero();
            metadata.stored_unix_seconds = unix_seconds();
            metadata.expires_unix_seconds =
                metadata.stored_unix_seconds.saturating_add(ttl.as_secs());
            let raw = serde_json::to_vec(&metadata).ok()?;
            if raw.len() > MAX_METADATA_BYTES {
                return None;
            }
            let growth = raw.len() as u64;
            cache
                .prune_locked(
                    cache.disk_limit(u64::MAX).checked_sub(growth)?,
                    MAX_CACHE_ENTRIES,
                    cache.max_object_bytes(),
                    Some(&key),
                )
                .ok()?;
            {
                let state = cache.state.lock().unwrap();
                if let Some(pin) = state.pins.entries.get(&key) {
                    if pin.body_sha256 != metadata.body_sha256
                        || pin.body_length != metadata.body_length
                    {
                        return None;
                    }
                    let added =
                        (metadata.body_length + raw.len() as u64).saturating_sub(pin.entry_bytes);
                    let used = state
                        .pins
                        .entries
                        .values()
                        .fold(state.pins.manifest_bytes, |total, pin| {
                            total.saturating_add(pin.entry_bytes)
                        });
                    if used.saturating_add(added) > state.limit_bytes / 4 {
                        return None;
                    }
                }
            }
            let mut temporary = temporary_file(&cache.root).ok()?;
            temporary.write_all(&raw).ok()?;
            temporary.as_file_mut().sync_all().ok()?;
            let mut state = cache.state.lock().unwrap();
            if !expected.key_guard.is_current()
                || state.epoch != expected.epoch
                || state.pending_clear
                || state.invalidated_keys.contains(&key)
                || state.recovery.blocks(&key)
            {
                return None;
            }
            // Body leases are safe: publication changes only metadata. A
            // synchronous invalidation can still race the prepass, so compare
            // the exact expected metadata again inside the publication mutex.
            let current = fs::read(&path).ok()?;
            if Sha256::digest(&current).as_slice() != expected.fingerprint.as_slice() {
                return None;
            }
            if let Err(error) = persist_replace(temporary, &path)
                .and_then(|_| recovery::sync_directory(&cache.root))
            {
                state.recovery.record_persistence_failure(&error);
                state.maintenance_failure = Some((error.kind(), error.to_string()));
                state.record_change();
                return None;
            }
            if let Some(pin) = state.pins.entries.get_mut(&key) {
                pin.entry_bytes = metadata.body_length + raw.len() as u64;
                pin.bytes = pin.entry_bytes;
            }
            state.record_change();
            Some(())
        })
        .await
        .ok()
        .flatten()
        .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn restricted_refresh_during_verified_hit_reconciles_metadata_and_never_returns_old_freshness(
    ) {
        use http_body_util::BodyExt;
        for include_stale in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cache = CacheStore::new(dir.path().into());
            let key = "1".repeat(64);
            let mut headers = HeaderMap::new();
            headers.insert(
                "cache-control",
                HeaderValue::from_static("public, max-age=600"),
            );
            cache
                .put(
                    &key,
                    StatusCode::OK,
                    &headers,
                    Bytes::from_static(b"immutable"),
                    Duration::from_secs(600),
                    100_000,
                )
                .await
                .unwrap();
            let expected = cache.snapshot(&key).await.unwrap();
            let started = Arc::new(std::sync::Barrier::new(2));
            let resume = Arc::new(std::sync::Barrier::new(2));
            cache.state.lock().unwrap().hit_after_hash_gate =
                Some((key.clone(), started.clone(), resume.clone()));
            let looking_up = {
                let cache = cache.clone();
                let key = key.clone();
                tokio::spawn(async move {
                    if include_stale {
                        cache.get_including_stale(&key).await
                    } else {
                        cache.get(&key).await
                    }
                })
            };
            tokio::task::spawn_blocking(move || started.wait())
                .await
                .unwrap();
            let mut restrictive = HeaderMap::new();
            restrictive.insert("cache-control", HeaderValue::from_static("no-cache"));
            let refreshed = cache
                .refresh(&key, &expected, &restrictive, Duration::ZERO)
                .await;
            cache.state.lock().unwrap().hit_after_hash_gate = None;
            tokio::task::spawn_blocking(move || resume.wait())
                .await
                .unwrap();
            let entry = looking_up.await.unwrap();
            assert!(
                refreshed,
                "immutable body lease must permit durable metadata-only refresh"
            );
            if include_stale {
                let entry = entry.unwrap();
                assert_eq!(entry.headers["cache-control"], "no-cache");
                assert_eq!(entry.remaining_ttl, Duration::ZERO);
                assert_eq!(entry.body.collect().await.unwrap().to_bytes(), "immutable");
            } else {
                assert!(
                    entry.is_none(),
                    "fresh lookup must not return the pre-refresh public metadata"
                );
            }
            assert!(cache.get(&key).await.is_none());
            let snapshot = cache.snapshot(&key).await.unwrap();
            assert_eq!(snapshot.headers["cache-control"], "no-cache");
            assert!(snapshot.online_validation_required);
            assert_eq!(
                cache.status_snapshot(&key).await.unwrap().remaining_ttl,
                Duration::ZERO
            );
        }
    }

    #[tokio::test]
    async fn metadata_refresh_preserves_active_body_and_pin_but_still_rejects_replacement_reservation(
    ) {
        use http_body_util::BodyExt;
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache.configure_limits(100_000, MAX_CACHE_ITEM_BYTES);
        let key = "0".repeat(64);
        cache
            .put(
                &key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"immutable"),
                Duration::from_secs(600),
                100_000,
            )
            .await
            .unwrap();
        let expected = cache.snapshot(&key).await.unwrap();
        cache.pin(&key, &expected).await.unwrap();
        let active = cache.get(&key).await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("cache-control", HeaderValue::from_static("no-cache"));
        assert!(
            cache
                .refresh(&key, &expected, &headers, Duration::ZERO)
                .await
        );
        assert_eq!(active.body.collect().await.unwrap().to_bytes(), "immutable");
        assert_eq!(cache.list_pins().await.unwrap().len(), 1);
        cache.unpin(&key).await.unwrap();
        let current = cache.snapshot(&key).await.unwrap();
        let replacement = cache
            .begin_fill(
                cache.epoch(),
                &key,
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(60),
                Instant::now(),
                100_000,
            )
            .await
            .unwrap();
        assert!(
            !cache
                .refresh(&key, &current, &HeaderMap::new(), Duration::from_secs(60))
                .await,
            "admitted body replacement retains the metadata generation fence"
        );
        drop(replacement);
        let current = cache.snapshot(&key).await.unwrap();
        assert_eq!(current.headers["cache-control"], "no-cache");
        assert!(current.online_validation_required);
    }

    #[tokio::test]
    async fn snapshot_uses_latest_metadata_on_the_same_verified_body() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let key = "2".repeat(64);
        let mut headers = HeaderMap::new();
        headers.insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=60"),
        );
        cache
            .put(
                &key,
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"same"),
                Duration::from_secs(60),
                100_000,
            )
            .await
            .unwrap();
        let guard = cache.key_guard(&key).unwrap();
        let epoch = cache.epoch();
        let mut entry = cache.get_including_stale(&key).await.unwrap();
        let path = dir.path().join(format!("{key}.json"));
        let mut metadata: CacheMetadata =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        metadata.headers = vec![("cache-control".into(), "no-cache".into())];
        metadata.expires_unix_seconds = metadata.stored_unix_seconds;
        metadata.online_validation_required = true;
        fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        let snapshot = cache
            .snapshot_verified_entry(&key, epoch, guard.clone(), &mut entry)
            .await
            .unwrap();
        assert_eq!(snapshot.headers["cache-control"], "no-cache");
        assert_eq!(entry.headers["cache-control"], "no-cache");
        assert_eq!(snapshot.remaining_ttl, Duration::ZERO);
        assert!(snapshot.online_validation_required);
        metadata.body_sha256 = "0".repeat(64);
        fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        assert!(cache
            .snapshot_verified_entry(&key, epoch, guard, &mut entry)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn atomic_retirement_returns_exact_successor_without_adopting_a_later_generation() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let key = "3".repeat(64);
        let guard = cache.key_guard(&key).unwrap();
        let (epoch, successor) = cache
            .invalidate_keys_and_request_at_epoch(cache.epoch(), &[], &guard)
            .unwrap();
        assert!(!guard.is_current());
        assert!(successor.is_current());
        guard.retire();
        assert!(successor.is_current());
        cache.invalidate_key(&key);
        assert!(!successor.is_current());
        assert!(cache
            .put_at_epoch_guarded(
                epoch,
                &key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"old"),
                Duration::from_secs(60),
                100_000,
                &successor
            )
            .await
            .is_err());
        assert!(cache
            .invalidate_keys_and_request_at_epoch(epoch, &[], &guard)
            .is_none());
        assert!(cache.state.lock().unwrap().invalidated_keys.is_empty());
    }

    #[tokio::test]
    async fn retired_snapshot_cannot_refresh_or_reuse_an_identical_new_generation() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let key = "4".repeat(64);
        cache
            .put(
                &key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"same"),
                Duration::from_secs(60),
                100_000,
            )
            .await
            .unwrap();
        let old = cache.snapshot(&key).await.unwrap();
        cache.invalidate_key(&key);
        cache
            .put(
                &key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"same"),
                Duration::from_secs(60),
                100_000,
            )
            .await
            .unwrap();
        assert!(cache.get_if_snapshot(&key, &old).await.is_none());
        assert!(
            !cache
                .refresh(&key, &old, &HeaderMap::new(), Duration::from_secs(60))
                .await
        );
        assert!(cache.snapshot(&key).await.is_some());
    }

    #[tokio::test]
    async fn readiness_estimate_never_authorizes_unverified_body() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache.configure_limits(20_000, MAX_CACHE_ITEM_BYTES);
        let key = "9".repeat(64);
        cache
            .put(
                &key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"abc"),
                Duration::from_secs(60),
                20_000,
            )
            .await
            .unwrap();
        let estimate = cache.status_snapshot(&key).await.unwrap();
        assert_eq!(estimate.status, StatusCode::OK);
        assert_eq!(estimate.body_length, 3);
        assert!(cache.get_if_snapshot(&key, &estimate).await.is_none());
        assert!(cache.pin(&key, &estimate).await.is_err());
        assert!(
            !cache
                .refresh(&key, &estimate, &HeaderMap::new(), Duration::from_secs(60))
                .await
        );
        fs::write(dir.path().join(format!("{key}.body")), b"bad").unwrap();
        assert!(
            cache.status_snapshot(&key).await.is_some(),
            "UI estimate deliberately performs no full body hash"
        );
        assert!(
            cache.snapshot(&key).await.is_none(),
            "serving snapshot still verifies integrity"
        );
        fs::write(dir.path().join(format!("{key}.body")), b"x").unwrap();
        assert!(cache.status_snapshot(&key).await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn readiness_rejects_symlinked_bodies_and_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let key = "8".repeat(64);
        cache
            .put(
                &key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"abc"),
                Duration::from_secs(60),
                20_000,
            )
            .await
            .unwrap();
        let body = dir.path().join(format!("{key}.body"));
        let target = dir.path().join("external-body");
        fs::rename(&body, &target).unwrap();
        std::os::unix::fs::symlink(&target, &body).unwrap();
        assert!(cache.status_snapshot(&key).await.is_none());
        fs::remove_file(&body).unwrap();
        fs::rename(&target, &body).unwrap();
        let metadata = dir.path().join(format!("{key}.json"));
        let target = dir.path().join("external-metadata");
        fs::rename(&metadata, &target).unwrap();
        std::os::unix::fs::symlink(&target, &metadata).unwrap();
        assert!(cache.status_snapshot(&key).await.is_none());
    }

    #[tokio::test]
    async fn zero_admitted_freshness_requires_online_validation_in_every_publication_path() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let key = "7".repeat(64);
        let mut headers = HeaderMap::new();
        headers.insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=60"),
        );
        headers.insert("age", HeaderValue::from_static("100000"));
        cache
            .put(
                &key,
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"abc"),
                Duration::ZERO,
                100_000,
            )
            .await
            .unwrap();
        assert!(
            cache
                .snapshot(&key)
                .await
                .unwrap()
                .online_validation_required
        );
        assert!(
            cache
                .status_snapshot(&key)
                .await
                .unwrap()
                .online_validation_required
        );
        let snapshot = cache.snapshot(&key).await.unwrap();
        assert!(
            cache
                .refresh(&key, &snapshot, &headers, Duration::from_secs(60))
                .await
        );
        assert!(
            !cache
                .snapshot(&key)
                .await
                .unwrap()
                .online_validation_required
        );
        let snapshot = cache.snapshot(&key).await.unwrap();
        assert!(
            cache
                .refresh(&key, &snapshot, &headers, Duration::ZERO)
                .await
        );
        assert!(
            cache
                .snapshot(&key)
                .await
                .unwrap()
                .online_validation_required
        );
        // Legacy TTL-zero entries infer the validation requirement without the flag.
        let path = dir.path().join(format!("{key}.json"));
        let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        raw.as_object_mut()
            .unwrap()
            .remove("online_validation_required");
        fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
        assert!(
            cache
                .snapshot(&key)
                .await
                .unwrap()
                .online_validation_required
        );
        let fill_key = "6".repeat(64);
        let fill = cache
            .begin_fill(
                cache.epoch(),
                &fill_key,
                StatusCode::OK,
                &headers,
                3,
                Duration::from_secs(1),
                Instant::now() - Duration::from_secs(2),
                100_000,
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
        assert!(
            cache
                .snapshot(&fill_key)
                .await
                .unwrap()
                .online_validation_required
        );
        let fragment_key = "5".repeat(64);
        headers.insert("etag", HeaderValue::from_static("\"zero\""));
        headers.insert("content-range", HeaderValue::from_static("bytes 0-2/6"));
        cache
            .put_fragment_at_epoch(
                cache.epoch(),
                &fragment_key,
                StatusCode::PARTIAL_CONTENT,
                &headers,
                Bytes::from_static(b"abc"),
                Duration::ZERO,
                100_000,
            )
            .await
            .unwrap();
        headers.insert("content-range", HeaderValue::from_static("bytes 3-5/6"));
        cache
            .put_fragment_at_epoch(
                cache.epoch(),
                &fragment_key,
                StatusCode::PARTIAL_CONTENT,
                &headers,
                Bytes::from_static(b"def"),
                Duration::from_secs(60),
                100_000,
            )
            .await
            .unwrap();
        assert!(
            cache
                .snapshot(&fragment_key)
                .await
                .unwrap()
                .online_validation_required
        );
    }
}
