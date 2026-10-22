use super::*;

pub(super) const MANIFEST_NAME: &str = ".cache-pins";
const MAX_PIN_MANIFEST_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PinUsage {
    pub used_bytes: u64,
    pub limit_bytes: u64,
    pub entry_count: u64,
    pub degraded: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PinnedEntry {
    pub key: String,
    pub body_sha256: String,
    pub body_length: u64,
    pub entry_bytes: u64,
    #[serde(default)]
    pub bytes: u64,
}

#[derive(Default)]
pub(super) struct PinState {
    pub loaded: bool,
    pub entries: BTreeMap<String, PinnedEntry>,
    pub error: Option<String>,
    pub manifest_bytes: u64,
}
#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u8,
    entries: Vec<PinnedEntry>,
}

fn invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

impl CacheStore {
    /// Load and verify pins before any eviction. A corrupt manifest blocks all
    /// mutations until explicit clear, rather than silently losing protection.
    pub(super) fn load_pins_locked(&self) -> std::io::Result<()> {
        {
            let state = self.state.lock().unwrap();
            if state.pins.loaded {
                return match &state.pins.error {
                    Some(error) => Err(invalid(error)),
                    None => Ok(()),
                };
            }
        }
        let result = (|| {
            let path = self.root.join(MANIFEST_NAME);
            let size = match fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok((BTreeMap::new(), 0))
                }
                Err(error) => return Err(error),
            };
            if size > MAX_PIN_MANIFEST_BYTES as u64 {
                return Err(invalid("pin manifest exceeds size limit"));
            }
            let manifest: Manifest =
                serde_json::from_slice(&fs::read(path)?).map_err(std::io::Error::other)?;
            if manifest.version != 1 || manifest.entries.len() > MAX_CACHE_ENTRIES {
                return Err(invalid("invalid pin manifest"));
            }
            let mut entries = BTreeMap::new();
            for mut pin in manifest.entries {
                if !valid_key(&pin.key)
                    || !valid_key(&pin.body_sha256)
                    || pin.body_length > MAX_CACHE_ITEM_BYTES
                    || entries.contains_key(&pin.key)
                {
                    return Err(invalid("invalid pin reference"));
                }
                let raw = fs::read(self.root.join(format!("{}.json", pin.key)))?;
                if raw.len() > MAX_METADATA_BYTES {
                    return Err(invalid("invalid pinned metadata"));
                }
                let metadata: CacheMetadata =
                    serde_json::from_slice(&raw).map_err(std::io::Error::other)?;
                if metadata.body_sha256 != pin.body_sha256
                    || metadata.body_length != pin.body_length
                    || metadata.fragments.is_some()
                {
                    return Err(invalid("pinned representation changed"));
                }
                // The integrity prepass verifies every byte, including stale bodies.
                get_sync_verified(
                    &self.root,
                    &pin.key,
                    EntryLease::new(self, &pin.key),
                    MAX_CACHE_ITEM_BYTES,
                    true,
                    false,
                    true,
                )
                .ok_or_else(|| invalid("pinned body failed integrity verification"))?;
                pin.entry_bytes = pin.body_length.saturating_add(raw.len() as u64);
                pin.bytes = pin.entry_bytes;
                entries.insert(pin.key.clone(), pin);
            }
            Ok((entries, size))
        })();
        let mut state = self.state.lock().unwrap();
        state.pins.loaded = true;
        match result {
            Ok((entries, size)) => {
                state.pins.entries = entries;
                state.pins.manifest_bytes = size;
                Ok(())
            }
            Err(error) => {
                state.pins.error = Some(error.to_string());
                Err(error)
            }
        }
    }

    pub(super) fn check_pin_limits(&self) -> std::io::Result<()> {
        let usage = self.pin_usage_sync();
        if usage.degraded {
            return Err(invalid(
                usage
                    .error
                    .as_deref()
                    .unwrap_or("pinned data exceeds configured quota"),
            ));
        }
        Ok(())
    }

    fn pin_usage_sync(&self) -> PinUsage {
        let state = self.state.lock().unwrap();
        let limit = if state.limits_configured {
            state.limit_bytes / 4
        } else {
            0
        };
        let used = state
            .pins
            .entries
            .values()
            .fold(state.pins.manifest_bytes, |size, pin| {
                size.saturating_add(pin.entry_bytes)
            });
        let error = state.pins.error.clone().or_else(|| state.pins.entries.values().any(|pin| pin.body_length > state.max_object_bytes).then(|| "Pinned object exceeds the configured object limit; unpin it or increase the limit".to_owned())).or_else(|| (used > limit).then(|| "Pinned data exceeds 25% of the configured cache limit; unpin items or increase the limit".to_owned()));
        PinUsage {
            used_bytes: used,
            limit_bytes: limit,
            entry_count: state.pins.entries.len() as u64,
            degraded: error.is_some(),
            error,
        }
    }

    pub(crate) async fn pin_usage(&self) -> PinUsage {
        if !self.state.lock().unwrap().pins.loaded {
            {
                let guard = self.io_lock.clone().write_owned().await;
                let cache = self.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let _guard = guard;
                    cache.load_pins_locked()
                })
                .await;
            }
        }
        self.pin_usage_sync()
    }

    pub(crate) async fn list_pins(&self) -> std::io::Result<Vec<PinnedEntry>> {
        {
            let state = self.state.lock().unwrap();
            if state.pins.loaded {
                if let Some(error) = &state.pins.error {
                    return Err(invalid(error));
                }
                return Ok(state.pins.entries.values().cloned().collect());
            }
        }
        let guard = self.io_lock.clone().write_owned().await;
        let cache = self.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            cache.load_pins_locked()?;
            Ok(cache
                .state
                .lock()
                .unwrap()
                .pins
                .entries
                .values()
                .cloned()
                .collect())
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub(crate) async fn pin(
        &self,
        key: &str,
        expected: &CacheSnapshot,
    ) -> std::io::Result<PinUsage> {
        if !valid_key(key) {
            return Err(invalid("invalid pin key"));
        }
        // Verify without a global writer lease; the per-entry body lease keeps
        // this exact snapshot immutable through manifest publication.
        let verified = self
            .get_if_snapshot(key, expected)
            .await
            .ok_or_else(|| invalid("pin requires a complete verified snapshot"))?;
        let guard = self.io_lock.clone().write_owned().await;
        let cache = self.clone();
        let key = key.to_owned();
        let expected = expected.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let _verified = verified;
            cache.load_pins_locked()?;
            if !expected.key_guard.is_current() || !cache.valid_epoch(expected.epoch) {
                return Err(busy());
            }
            {
                let state = cache.state.lock().unwrap();
                if state.invalidated_keys.contains(&key)
                    || state.reservations.values().any(|(entry, _)| entry == &key)
                {
                    return Err(busy());
                }
            }
            let raw = fs::read(cache.root.join(format!("{key}.json")))?;
            if raw.len() > MAX_METADATA_BYTES
                || Sha256::digest(&raw).as_slice() != expected.fingerprint.as_slice()
            {
                return Err(busy());
            }
            let metadata: CacheMetadata =
                serde_json::from_slice(&raw).map_err(std::io::Error::other)?;
            let mut entries = cache.state.lock().unwrap().pins.entries.clone();
            entries.insert(
                key.clone(),
                PinnedEntry {
                    key,
                    body_sha256: metadata.body_sha256,
                    body_length: metadata.body_length,
                    entry_bytes: metadata.body_length.saturating_add(raw.len() as u64),
                    bytes: metadata.body_length.saturating_add(raw.len() as u64),
                },
            );
            cache.publish_pins_locked(entries, expected.epoch, Some(&expected.key_guard))?;
            Ok(cache.pin_usage_sync())
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub(crate) async fn unpin(&self, key: &str) -> std::io::Result<PinUsage> {
        if !valid_key(key) {
            return Err(invalid("invalid pin key"));
        }
        let guard = self.io_lock.clone().write_owned().await;
        let cache = self.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            cache.load_pins_locked()?;
            let epoch = cache.epoch();
            let mut entries = cache.state.lock().unwrap().pins.entries.clone();
            entries.remove(&key);
            cache.publish_pins_locked(entries, epoch, None)?;
            Ok(cache.pin_usage_sync())
        })
        .await
        .map_err(std::io::Error::other)?
    }

    fn publish_pins_locked(
        &self,
        entries: BTreeMap<String, PinnedEntry>,
        epoch: u64,
        key_guard: Option<&CacheKeyGuard>,
    ) -> std::io::Result<()> {
        let raw = serde_json::to_vec(&Manifest {
            version: 1,
            entries: entries.values().cloned().collect(),
        })
        .map_err(std::io::Error::other)?;
        let (limit, old_used) = {
            let state = self.state.lock().unwrap();
            (
                state.limit_bytes,
                state
                    .pins
                    .entries
                    .values()
                    .fold(state.pins.manifest_bytes, |total, pin| {
                        total.saturating_add(pin.entry_bytes)
                    }),
            )
        };
        let used = entries.values().fold(
            if entries.is_empty() {
                0
            } else {
                raw.len() as u64
            },
            |total, pin| total.saturating_add(pin.entry_bytes),
        );
        if raw.len() > MAX_PIN_MANIFEST_BYTES
            || entries.len() > MAX_CACHE_ENTRIES
            || (used > limit / 4 && used >= old_used)
        {
            return Err(invalid("pin exceeds 25% cache quota"));
        }
        // Removing references must remain possible after a limit shrink.
        if entries.is_empty() {
            let mut state = self.state.lock().unwrap();
            if state.epoch != epoch
                || state.pending_clear
                || key_guard.is_some_and(|guard| !guard.is_current())
            {
                return Err(busy());
            }
            remove_cache_file(&self.root.join(MANIFEST_NAME))?;
            state.pins.entries = entries;
            state.pins.manifest_bytes = 0;
            state.record_change();
            return Ok(());
        }
        fs::create_dir_all(&self.root)?;
        // Account existing manifest plus its replacement temp, and all active fills.
        let usage = measure_sync(&self.root)?;
        let extra_reservations = {
            let state = self.state.lock().unwrap();
            state
                .reservations
                .iter()
                .fold(0u64, |total, (path, (_, reserved))| {
                    total.saturating_add(
                        reserved.saturating_sub(fs::metadata(path).map(|m| m.len()).unwrap_or(0)),
                    )
                })
        };
        if used >= old_used
            && usage
                .used_bytes
                .saturating_add(extra_reservations)
                .saturating_add(raw.len() as u64)
                > limit
        {
            return Err(busy());
        }
        let mut temporary = temporary_file(&self.root)?;
        temporary.write_all(&raw)?;
        temporary.as_file_mut().sync_all()?;
        #[cfg(test)]
        {
            let gate = self.state.lock().unwrap().pin_publish_gate.clone();
            if let Some((started, resume)) = gate {
                started.wait();
                resume.wait();
            }
        }
        let mut state = self.state.lock().unwrap();
        if state.epoch != epoch
            || state.pending_clear
            || key_guard.is_some_and(|guard| !guard.is_current())
        {
            return Err(busy());
        }
        persist_replace(temporary, &self.root.join(MANIFEST_NAME))?;
        state.pins.entries = entries;
        state.pins.manifest_bytes = raw.len() as u64;
        state.record_change();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(seed: &str) -> String {
        hex::encode(Sha256::digest(seed.as_bytes()))
    }
    async fn put(cache: &CacheStore, key: &str, body: &'static [u8]) {
        cache
            .put(
                key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(body),
                Duration::from_secs(60),
                20_000,
            )
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn absent_invalidations_never_clear_pins_or_allocate_tombstones() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache.configure_limits(20_000, MAX_CACHE_ITEM_BYTES);
        let pinned = key("absent-invalidation-pin");
        put(&cache, &pinned, b"protected").await;
        cache
            .pin(&pinned, &cache.snapshot(&pinned).await.unwrap())
            .await
            .unwrap();
        let epoch = cache.epoch();
        for index in 0..8260 {
            cache.invalidate_key(&key(&format!("absent-{index}")));
        }
        let mut malformed = HeaderMap::new();
        malformed.insert("etag", HeaderValue::from_static("\"unknown\""));
        malformed.insert("content-range", HeaderValue::from_static("bytes 0-2/*"));
        assert!(cache
            .put_fragment_at_epoch(
                epoch,
                &key("malformed-cold-fragment"),
                StatusCode::PARTIAL_CONTENT,
                &malformed,
                Bytes::from_static(b"abc"),
                Duration::from_secs(60),
                20_000
            )
            .await
            .is_err());
        assert_eq!(cache.epoch(), epoch);
        assert!(!cache.state.lock().unwrap().pending_clear);
        assert!(cache.state.lock().unwrap().invalidated_keys.is_empty());
        assert!(cache.get(&pinned).await.is_some());
        assert_eq!(cache.list_pins().await.unwrap().len(), 1);
        let writer = cache.io_lock.clone().write_owned().await;
        let listed = tokio::time::timeout(Duration::from_secs(1), cache.list_pins()).await;
        drop(writer);
        assert_eq!(
            listed.unwrap().unwrap().len(),
            1,
            "loaded pin status must not acquire the global writer"
        );
    }

    #[tokio::test]
    async fn pin_publication_rechecks_key_generation_and_delayed_cleanup_preserves_new_pin() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache.configure_limits(20_000, MAX_CACHE_ITEM_BYTES);
        let entry = key("pin-retirement-race");
        put(&cache, &entry, b"old").await;
        let expected = cache.snapshot(&entry).await.unwrap();
        let started = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        cache.state.lock().unwrap().pin_publish_gate = Some((started.clone(), resume.clone()));
        let pinning = {
            let cache = cache.clone();
            let entry = entry.clone();
            tokio::spawn(async move { cache.pin(&entry, &expected).await })
        };
        tokio::task::spawn_blocking(move || started.wait())
            .await
            .unwrap();
        cache.invalidate_key(&entry);
        cache.state.lock().unwrap().pin_publish_gate = None;
        tokio::task::spawn_blocking(move || resume.wait())
            .await
            .unwrap();
        assert!(pinning.await.unwrap().is_err());
        assert!(cache.list_pins().await.unwrap().is_empty());
        put(&cache, &entry, b"new").await;
        cache
            .pin(&entry, &cache.snapshot(&entry).await.unwrap())
            .await
            .unwrap();
        cache.remove_invalidated(&entry).await.unwrap();
        assert!(cache.get(&entry).await.is_some());
        assert_eq!(cache.list_pins().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invalidated_pin_survives_restart_denies_reuse_and_can_be_unpinned() {
        for family in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cache = CacheStore::new(dir.path().into());
            cache.configure_limits(20_000, MAX_CACHE_ITEM_BYTES);
            let pinned = key("invalidated-pin");
            put(&cache, &pinned, b"protected").await;
            // Legacy metadata without the new flag remains usable and pinnable.
            let path = dir.path().join(format!("{pinned}.json"));
            let mut legacy: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            legacy.as_object_mut().unwrap().remove("invalidated");
            fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
            assert!(cache.get(&pinned).await.is_some());
            cache
                .pin(&pinned, &cache.snapshot(&pinned).await.unwrap())
                .await
                .unwrap();
            let active = cache.get(&pinned).await.unwrap();
            if family {
                assert!(cache
                    .invalidate_keys_at_epoch(cache.epoch(), std::slice::from_ref(&pinned))
                    .is_some());
            } else {
                cache.invalidate_key(&pinned);
            }
            assert!(cache.get_including_stale(&pinned).await.is_none());
            assert!(cache.snapshot(&pinned).await.is_none());
            assert_eq!(
                cache.remove_invalidated(&pinned).await.unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(dir.path().join(format!("{pinned}.json")).exists());
            assert!(dir.path().join(format!("{pinned}.body")).exists());
            drop(active);
            drop(cache);
            let cache = CacheStore::new(dir.path().into());
            cache.configure_limits(20_000, MAX_CACHE_ITEM_BYTES);
            cache.maintain().await.unwrap();
            assert_eq!(cache.list_pins().await.unwrap().len(), 1);
            assert!(!cache.pin_usage().await.degraded);
            assert!(cache.get(&pinned).await.is_none());
            assert!(cache.get_including_stale(&pinned).await.is_none());
            assert!(cache.snapshot(&pinned).await.is_none());
            put(&cache, &key("unrelated-after-restart"), b"writable").await;
            assert_eq!(cache.unpin(&pinned).await.unwrap().entry_count, 0);
            cache.remove_invalidated(&pinned).await.unwrap();
            put(&cache, &pinned, b"replacement").await;
            assert!(cache.get(&pinned).await.is_some());
        }
    }

    #[tokio::test]
    async fn pinned_lru_survives_pressure_restart_and_safe_metadata_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache.configure_limits(20_000, MAX_CACHE_ITEM_BYTES);
        let pinned = key("pinned");
        put(&cache, &pinned, b"protected").await;
        let snapshot = cache.snapshot(&pinned).await.unwrap();
        let usage = cache.pin(&pinned, &snapshot).await.unwrap();
        assert_eq!(usage.entry_count, 1);
        assert!(usage.used_bytes <= 5000);
        for index in 0..100 {
            put(&cache, &key(&index.to_string()), b"ordinary").await;
        }
        assert!(cache.get(&pinned).await.is_some());
        let snapshot = cache.snapshot(&pinned).await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("etag", HeaderValue::from_static("\"same-body\""));
        assert!(
            cache
                .refresh(&pinned, &snapshot, &headers, Duration::from_secs(120))
                .await
        );
        assert!(cache
            .put(
                &pinned,
                StatusCode::OK,
                &headers,
                Bytes::from_static(b"changed"),
                Duration::from_secs(60),
                20_000
            )
            .await
            .is_err());
        drop(cache);
        let restarted = CacheStore::new(dir.path().into());
        restarted.configure_limits(20_000, MAX_CACHE_ITEM_BYTES);
        restarted.maintain().await.unwrap();
        assert_eq!(restarted.list_pins().await.unwrap().len(), 1);
        assert!(restarted.get(&pinned).await.is_some());
        restarted.configure_limits(1, MAX_CACHE_ITEM_BYTES);
        assert!(restarted.maintain().await.is_err());
        assert!(restarted.pin_usage().await.degraded);
        assert!(dir.path().join(format!("{pinned}.body")).exists());
        restarted.unpin(&pinned).await.unwrap();
        restarted.state.lock().unwrap().maintenance_retry_at = None;
        restarted.maintain().await.unwrap();
        assert_eq!(restarted.usage().await.used_bytes, 0);
    }
    #[tokio::test]
    async fn corrupt_manifest_fails_closed_and_explicit_clear_restores_storage() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache.configure_limits(20_000, MAX_CACHE_ITEM_BYTES);
        let pinned = key("retained");
        put(&cache, &pinned, b"retained").await;
        cache
            .pin(&pinned, &cache.snapshot(&pinned).await.unwrap())
            .await
            .unwrap();
        drop(cache);
        fs::write(dir.path().join(MANIFEST_NAME), b"not-json").unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache.configure_limits(20_000, MAX_CACHE_ITEM_BYTES);
        assert!(cache.maintain().await.is_err());
        assert!(cache.pin_usage().await.degraded);
        assert!(cache.get(&pinned).await.is_some());
        assert!(cache
            .put(
                &key("new"),
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::new(),
                Duration::from_secs(60),
                20_000
            )
            .await
            .is_err());
        assert!(dir.path().join(format!("{pinned}.body")).exists());
        cache.clear().await.unwrap();
        assert!(!cache.pin_usage().await.degraded);
        assert_eq!(cache.list_pins().await.unwrap().len(), 0);
    }
    #[tokio::test]
    async fn pin_budget_and_old_epoch_are_rejected_without_manifest_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache.configure_limits(1600, MAX_CACHE_ITEM_BYTES);
        let entry = key("quota");
        put(&cache, &entry, b"data").await;
        let snapshot = cache.snapshot(&entry).await.unwrap();
        assert!(cache.pin(&entry, &snapshot).await.is_err());
        assert!(!dir.path().join(MANIFEST_NAME).exists());
        cache.configure_limits(20_000, MAX_CACHE_ITEM_BYTES);
        let snapshot = cache.snapshot(&entry).await.unwrap();
        cache.invalidate();
        assert!(cache.pin(&entry, &snapshot).await.is_err());
        assert_eq!(cache.list_pins().await.unwrap().len(), 0);
    }
}

#[cfg(test)]
mod publish_race_tests {
    use super::*;
    use http_body_util::BodyExt;
    #[tokio::test]
    async fn late_reader_or_pin_of_old_snapshot_cannot_replace_protected_generation() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache.configure_limits(20_000, MAX_CACHE_ITEM_BYTES);
        let key = "e".repeat(64);
        cache
            .put(
                &key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"old"),
                Duration::from_secs(60),
                20_000,
            )
            .await
            .unwrap();
        let old = cache.snapshot(&key).await.unwrap();
        let replacement = cache
            .begin_fill(
                cache.epoch(),
                &key,
                StatusCode::OK,
                &HeaderMap::new(),
                3,
                Duration::from_secs(60),
                Instant::now(),
                20_000,
            )
            .await
            .unwrap();
        // A pin must never capture old metadata while the admitted replacement can publish.
        assert!(cache.pin(&key, &old).await.is_err());
        let active = cache.get(&key).await.unwrap();
        assert!(
            !replacement
                .write(Bytes::from_static(b"new"))
                .await
                .unwrap()
                .commit()
                .await
        );
        assert_eq!(active.body.collect().await.unwrap().to_bytes(), "old");
        cache
            .put(
                &key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from_static(b"new"),
                Duration::from_secs(60),
                20_000,
            )
            .await
            .unwrap();
        assert!(cache.pin(&key, &old).await.is_err());
        assert_eq!(
            cache
                .get(&key)
                .await
                .unwrap()
                .body
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            "new"
        );
        assert!(cache.list_pins().await.unwrap().is_empty());
    }
}
