use super::*;
use std::io::SeekFrom;

const MAX_INTERVALS: usize = 64;
#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Interval {
    start: u64,
    end: u64,
}
#[derive(Clone, Deserialize, Serialize)]
pub(super) struct FragmentMetadata {
    total: u64,
    etag: String,
    coding: Vec<String>,
    vary: Vec<String>,
    intervals: Vec<Interval>,
}

fn invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}
fn values(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}
fn descriptor(headers: &HeaderMap, length: u64) -> Option<(FragmentMetadata, Interval)> {
    let etag = single(headers, "etag")?;
    if !etag.starts_with('"')
        || !etag.ends_with('"')
        || etag.len() < 2
        || etag[1..etag.len() - 1]
            .bytes()
            .any(|b| b == b'"' || b < 0x21 || b == 0x7f)
    {
        return None;
    }
    if headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("multipart/"))
    {
        return None;
    }
    let raw = single(headers, "content-range")?.strip_prefix("bytes ")?;
    let (range, total) = raw.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?.checked_add(1)?;
    let total = total.parse::<u64>().ok()?;
    if start >= end || end > total || total > MAX_CACHE_ITEM_BYTES || end - start != length {
        return None;
    }
    if let Some(raw) = headers.get("content-length") {
        if raw.to_str().ok()?.parse::<u64>().ok()? != length {
            return None;
        }
    }
    let interval = Interval { start, end };
    Some((
        FragmentMetadata {
            total,
            etag: etag.to_owned(),
            coding: values(headers, "content-encoding"),
            vary: values(headers, "vary"),
            intervals: vec![interval.clone()],
        },
        interval,
    ))
}
fn valid_fragments(fragment: &FragmentMetadata, body_length: u64) -> bool {
    let mut previous = 0;
    let mut length = 0u64;
    if fragment.total == 0
        || fragment.total > MAX_CACHE_ITEM_BYTES
        || fragment.intervals.is_empty()
        || fragment.intervals.len() > MAX_INTERVALS
    {
        return false;
    }
    for (index, interval) in fragment.intervals.iter().enumerate() {
        if interval.start >= interval.end
            || interval.end > fragment.total
            || (index > 0 && interval.start <= previous)
        {
            return false;
        }
        previous = interval.end;
        let Some(total) = length.checked_add(interval.end - interval.start) else {
            return false;
        };
        length = total;
    }
    length == body_length
}
fn load_metadata(root: &Path, key: &str) -> Option<CacheMetadata> {
    let path = root.join(format!("{key}.json"));
    if fs::metadata(&path).ok()?.len() > MAX_METADATA_BYTES as u64 {
        return None;
    }
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

fn fragment_authorized(cache: &CacheStore, key: &str, epoch: u64, headers: &HeaderMap) -> bool {
    let Ok(headers) = serialize_headers(headers) else {
        return false;
    };
    // Body verification runs outside this mutex. Reauthorize its actual family
    // metadata at the same fence used by publication and checkpoint abandonment.
    let state = cache.state.lock().unwrap();
    state.epoch == epoch
        && !state.pending_clear
        && !state.invalidated_keys.contains(key)
        && !state.recovery.blocks(key)
        && !state.recovery.blocks_headers(&headers)
}

impl CacheStore {
    pub(crate) async fn fragment_total(&self, key: &str) -> Option<u64> {
        if !valid_key(key) || self.state.lock().unwrap().invalidated_keys.contains(key) {
            return None;
        }
        let guard = tokio::time::timeout(CACHE_IO_WAIT, self.io_lock.clone().read_owned())
            .await
            .ok()?;
        let cache = self.clone();
        let key = key.to_owned();
        let epoch = self.epoch();
        tokio::task::spawn_blocking(move || {
            let lease = EntryLease::new(&cache, &key);
            drop(guard);
            let metadata = load_metadata(&cache.root, &key)?;
            if metadata.invalidated {
                return None;
            }
            let fragment = metadata.fragments?;
            let entry = get_sync_inner(
                &cache.root,
                &key,
                lease,
                cache.max_object_bytes(),
                true,
                true,
            )?;
            // Retain the verified body lease until the final authorization gate.
            (valid_fragments(&fragment, metadata.body_length)
                && fragment_authorized(&cache, &key, epoch, &entry.headers))
            .then_some(fragment.total)
        })
        .await
        .ok()
        .flatten()
    }

    /// Only fully covered single ranges are hits. A hole remains a miss.
    pub(crate) async fn get_fragment(
        &self,
        key: &str,
        start: u64,
        end: u64,
        include_stale: bool,
    ) -> Option<CachedEntry> {
        if !valid_key(key)
            || start > end
            || self.state.lock().unwrap().invalidated_keys.contains(key)
        {
            return None;
        }
        let _ = self.maintain().await;
        let epoch = self.epoch();
        let guard = tokio::time::timeout(CACHE_IO_WAIT, self.io_lock.clone().read_owned())
            .await
            .ok()?;
        let cache = self.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            let lease = EntryLease::new(&cache, &key);
            drop(guard);
            let metadata = load_metadata(&cache.root, &key)?;
            if metadata.invalidated {
                return None;
            }
            let fragment = metadata.fragments?;
            if !valid_fragments(&fragment, metadata.body_length) {
                return None;
            }
            let stop = end.checked_add(1)?;
            let mut offset = 0;
            let interval = fragment.intervals.iter().find(|interval| {
                if start >= interval.start && stop <= interval.end {
                    true
                } else {
                    offset += interval.end - interval.start;
                    false
                }
            })?;
            let mut entry = get_sync_inner(
                &cache.root,
                &key,
                lease,
                cache.max_object_bytes(),
                include_stale,
                true,
            )?;
            entry
                .body
                .range(offset + start - interval.start, stop - start)
                .ok()?;
            entry.status = StatusCode::PARTIAL_CONTENT;
            entry.headers.insert(
                "content-range",
                HeaderValue::from_str(&format!("bytes {start}-{end}/{}", fragment.total)).ok()?,
            );
            entry.headers.insert(
                "content-length",
                HeaderValue::from_str(&(stop - start).to_string()).ok()?,
            );
            fragment_authorized(&cache, &key, epoch, &entry.headers).then_some(entry)
        })
        .await
        .ok()
        .flatten()
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn put_fragment_at_epoch(
        &self,
        epoch: u64,
        key: &str,
        status: StatusCode,
        headers: &HeaderMap,
        body: Bytes,
        ttl: Duration,
        limit: u64,
    ) -> std::io::Result<()> {
        let guard = self.key_guard(key).ok_or_else(busy)?;
        self.put_fragment_at_epoch_guarded(epoch, key, status, headers, body, ttl, limit, &guard)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn put_fragment_at_epoch_guarded(
        &self,
        epoch: u64,
        key: &str,
        status: StatusCode,
        headers: &HeaderMap,
        body: Bytes,
        ttl: Duration,
        limit: u64,
        request_guard: &CacheKeyGuard,
    ) -> std::io::Result<()> {
        let request_guard = request_guard.clone();
        let key_guard = self.key_guard(key).ok_or_else(busy)?;
        if !key_guard.is_current() || !request_guard.is_current() {
            return Err(busy());
        }
        if !valid_key(key) || status != StatusCode::PARTIAL_CONTENT {
            return Err(invalid("invalid fragment response"));
        }
        let Some((generation, interval)) = descriptor(headers, body.len() as u64) else {
            self.invalidate_keys_at_epoch_guarded(epoch, &[key.to_owned()], &request_guard);
            return Err(invalid(
                "fragment requires strong ETag, known total and exact single-range body",
            ));
        };
        if generation.total > self.max_object_bytes() {
            return Err(invalid("fragment object exceeds limit"));
        }
        let mut headers = headers.clone();
        headers.remove("content-range");
        headers.remove("content-length");
        let headers = serialize_headers(&headers)?;
        let limit = self.disk_limit(limit);
        self.maintain().await?;
        let guard = self.io_lock.clone().write_owned().await;
        let cache = self.clone();
        let key = key.to_owned();
        // Capture a per-entry lease under the writer, then release the writer before hashing.
        let prepared = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
            if !key_guard.is_current() || !request_guard.is_current() || !cache.valid_epoch(epoch) {
                return Err(busy());
            }
            cache.load_pins_locked()?;
            if cache.key_protected(&key) {
                return Err(busy());
            }
            fs::create_dir_all(&cache.root)?;
            let previous =
                load_metadata(&cache.root, &key).filter(|metadata| !metadata.invalidated);
            let lease = EntryLease::new(&cache, &key);
            drop(guard);
            #[cfg(test)]
            {
                let gate = cache.state.lock().unwrap().fragment_prepass_gate.clone();
                if let Some((started, resume)) = gate {
                    started.wait();
                    resume.wait();
                }
            }
            let mut intervals = generation.intervals.clone();
            let mut old = None;
            let mut online_validation_required = ttl.is_zero();
            let mut stored = unix_seconds();
            let mut expires = stored.saturating_add(ttl.as_secs());
            if let Some(previous) = previous {
                if let Some(fragment) = previous.fragments {
                    if fragment.etag != generation.etag
                        || fragment.total != generation.total
                        || fragment.coding != generation.coding
                        || fragment.vary != generation.vary
                        || !valid_fragments(&fragment, previous.body_length)
                    {
                        cache.invalidate_keys_at_epoch_guarded(
                            epoch,
                            std::slice::from_ref(&key),
                            &request_guard,
                        );
                        return Err(invalid("fragment generation changed"));
                    }
                    let mut file = fs::File::open(cache.root.join(format!("{key}.body")))?;
                    if file.metadata()?.len() != previous.body_length {
                        cache.invalidate_keys_at_epoch_guarded(
                            epoch,
                            std::slice::from_ref(&key),
                            &request_guard,
                        );
                        return Err(invalid("fragment length changed"));
                    }
                    // Verify old compacted bytes and overlapping regions before merging.
                    let mut hash = Sha256::new();
                    let mut buffer = [0u8; IO_CHUNK_BYTES];
                    let mut compact_offset = 0u64;
                    for segment in &fragment.intervals {
                        let mut position = segment.start;
                        while position < segment.end {
                            let length =
                                (segment.end - position).min(IO_CHUNK_BYTES as u64) as usize;
                            file.read_exact(&mut buffer[..length])?;
                            hash.update(&buffer[..length]);
                            let overlap_start = position.max(interval.start);
                            let overlap_end = (position + length as u64).min(interval.end);
                            if overlap_start < overlap_end {
                                let left = &buffer[(overlap_start - position) as usize
                                    ..(overlap_end - position) as usize];
                                let right = &body[(overlap_start - interval.start) as usize
                                    ..(overlap_end - interval.start) as usize];
                                if left != right {
                                    cache.invalidate_keys_at_epoch_guarded(
                                        epoch,
                                        std::slice::from_ref(&key),
                                        &request_guard,
                                    );
                                    return Err(invalid("conflicting fragment overlap"));
                                }
                            }
                            position += length as u64;
                        }
                        compact_offset += segment.end - segment.start;
                    }
                    if compact_offset != previous.body_length
                        || hex::encode(hash.finalize()) != previous.body_sha256
                    {
                        cache.invalidate_keys_at_epoch_guarded(
                            epoch,
                            std::slice::from_ref(&key),
                            &request_guard,
                        );
                        return Err(invalid("fragment integrity failure"));
                    }
                    online_validation_required |= previous.online_validation_required
                        || previous.expires_unix_seconds <= previous.stored_unix_seconds;
                    intervals.extend(fragment.intervals.clone());
                    stored = stored.min(previous.stored_unix_seconds);
                    expires = expires.min(previous.expires_unix_seconds);
                    // Preserve the strictest validation requirement in combined metadata.
                    let old_headers = deserialize_headers(previous.headers)
                        .ok_or_else(|| invalid("invalid previous headers"))?;
                    let old_control = values(&old_headers, "cache-control").join(",");
                    let new_headers = deserialize_headers(headers.clone())
                        .ok_or_else(|| invalid("invalid headers"))?;
                    let mut combined_headers = new_headers;
                    if old_control.to_ascii_lowercase().contains("no-cache")
                        || old_control.to_ascii_lowercase().contains("must-revalidate")
                    {
                        combined_headers.append(
                            "cache-control",
                            HeaderValue::from_str(&old_control).map_err(std::io::Error::other)?,
                        );
                    }
                    old = Some((file, fragment, serialize_headers(&combined_headers)?));
                } else {
                    return Err(invalid("complete representation already exists"));
                }
            }
            intervals.sort_by_key(|interval| interval.start);
            let mut merged: Vec<Interval> = Vec::new();
            for interval in intervals {
                if let Some(last) = merged.last_mut().filter(|last| interval.start <= last.end) {
                    last.end = last.end.max(interval.end);
                } else {
                    merged.push(interval);
                }
            }
            if merged.len() > MAX_INTERVALS {
                return Err(invalid("fragment interval limit exceeded"));
            }
            let length = merged
                .iter()
                .map(|interval| interval.end - interval.start)
                .sum::<u64>();
            let promoted =
                merged.len() == 1 && merged[0].start == 0 && merged[0].end == generation.total;
            let mut generation = generation;
            generation.intervals = merged;
            let mut headers = if let Some((_, _, ref headers)) = old {
                headers.clone()
            } else {
                headers
            };
            headers.push(("content-length".into(), length.to_string()));
            let metadata = CacheMetadata {
                version: 1,
                invalidated: false,
                online_validation_required,
                status: if promoted { 200 } else { 206 },
                headers,
                stored_unix_seconds: stored,
                expires_unix_seconds: expires,
                body_length: length,
                body_sha256: "0".repeat(64),
                fragments: if promoted {
                    None
                } else {
                    Some(generation.clone())
                },
            };
            Ok((
                cache,
                key,
                lease,
                metadata,
                generation,
                interval,
                old,
                body,
                key_guard,
                request_guard,
            ))
        })
        .await
        .map_err(std::io::Error::other)??;
        let guard = self.io_lock.clone().write_owned().await;
        let prepared = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
            let _guard = guard;
            let (
                cache,
                key,
                lease,
                metadata,
                generation,
                interval,
                old,
                body,
                key_guard,
                request_guard,
            ) = prepared;
            // No replacement could pass admission while this lease was active.
            // A clear/configuration change still wins through the epoch check.
            drop(lease);
            if !key_guard.is_current()
                || !request_guard.is_current()
                || !cache.valid_epoch(epoch)
                || cache.key_protected(&key)
            {
                return Err(busy());
            }
            let reserved = metadata
                .body_length
                .checked_add(
                    serde_json::to_vec(&metadata)
                        .map_err(std::io::Error::other)?
                        .len() as u64,
                )
                .ok_or_else(busy)?;
            if cache.state.lock().unwrap().reservations.len() >= MAX_ACTIVE_FILLS {
                return Err(busy());
            }
            cache.prune_locked(
                limit.checked_sub(reserved).ok_or_else(busy)?,
                MAX_CACHE_ENTRIES - 1,
                cache.max_object_bytes(),
                Some(&key),
            )?;
            let temporary = temporary_file(&cache.root)?;
            let reservation = FillReservation {
                cache: cache.clone(),
                path: temporary.path().to_owned(),
            };
            cache
                .state
                .lock()
                .unwrap()
                .reservations
                .insert(reservation.path.clone(), (key.clone(), reserved));
            Ok((
                cache,
                key,
                temporary,
                reservation,
                metadata,
                generation,
                interval,
                old,
                body,
                key_guard,
                request_guard,
            ))
        })
        .await
        .map_err(std::io::Error::other)??;
        // Compaction writes outside the global writer lease. The reservation keeps
        // old entry and temp immutable, including during clear or limit changes.
        let written = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
            let (
                cache,
                key,
                mut temporary,
                reservation,
                mut metadata,
                generation,
                new_interval,
                mut old,
                body,
                key_guard,
                request_guard,
            ) = prepared;
            let mut hash = Sha256::new();
            let mut buffer = [0u8; IO_CHUNK_BYTES];
            for segment in &generation.intervals {
                let mut position = segment.start;
                while position < segment.end {
                    if !key_guard.is_current()
                        || !request_guard.is_current()
                        || !cache.valid_epoch(epoch)
                    {
                        return Err(busy());
                    }
                    let length = (segment.end - position).min(IO_CHUNK_BYTES as u64);
                    let written = if position >= new_interval.start && position < new_interval.end {
                        let length = length.min(new_interval.end - position) as usize;
                        let data = &body[(position - new_interval.start) as usize
                            ..(position - new_interval.start) as usize + length];
                        temporary.write_all(data)?;
                        hash.update(data);
                        length as u64
                    } else {
                        let (file, previous, _) = old
                            .as_mut()
                            .ok_or_else(|| invalid("fragment coverage hole"))?;
                        let mut offset = 0;
                        let source = previous
                            .intervals
                            .iter()
                            .find(|source| {
                                if position >= source.start && position < source.end {
                                    true
                                } else {
                                    offset += source.end - source.start;
                                    false
                                }
                            })
                            .ok_or_else(|| invalid("fragment coverage hole"))?;
                        let mut length = length.min(source.end - position);
                        if position < new_interval.start {
                            length = length.min(new_interval.start - position);
                        }
                        file.seek(SeekFrom::Start(offset + position - source.start))?;
                        file.read_exact(&mut buffer[..length as usize])?;
                        temporary.write_all(&buffer[..length as usize])?;
                        hash.update(&buffer[..length as usize]);
                        length
                    };
                    position += written;
                }
            }
            metadata.body_sha256 = hex::encode(hash.finalize());
            temporary.as_file_mut().sync_all()?;
            Ok((
                cache,
                key,
                temporary,
                reservation,
                metadata,
                key_guard,
                request_guard,
            ))
        })
        .await
        .map_err(std::io::Error::other)??;
        let guard = self.io_lock.clone().write_owned().await;
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let _guard = guard;
            let (cache, key, temporary, _reservation, mut metadata, key_guard, request_guard) =
                written;
            metadata
                .headers
                .retain(|(name, _)| name != "content-length" && name != "content-range");
            metadata
                .headers
                .push(("content-length".into(), metadata.body_length.to_string()));
            let raw = serde_json::to_vec(&metadata).map_err(std::io::Error::other)?;
            if raw.len() > MAX_METADATA_BYTES {
                return Err(invalid("fragment metadata exceeds limit"));
            }
            let mut meta = temporary_file(&cache.root)?;
            meta.write_all(&raw)?;
            meta.as_file_mut().sync_all()?;
            let mut state = cache.state.lock().unwrap();
            if !key_guard.is_current()
                || !request_guard.is_current()
                || state.epoch != epoch
                || state.pending_clear
                || state.readers.contains_key(&key)
                || state.pins.entries.contains_key(&key)
            {
                return Err(busy());
            }
            persist_replace(temporary, &cache.root.join(format!("{key}.body")))?;
            persist_replace(meta, &cache.root.join(format!("{key}.json")))?;
            state.confirm_publication(&cache.root)?;
            state.invalidated_keys.remove(&key);
            state.record_change();
            Ok(())
        })
        .await
        .map_err(std::io::Error::other)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    fn key() -> String {
        "f".repeat(64)
    }
    fn headers(range: &str, etag: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-range", HeaderValue::from_str(range).unwrap());
        headers.insert("etag", HeaderValue::from_str(etag).unwrap());
        headers.insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=60"),
        );
        headers
    }
    async fn put(
        cache: &CacheStore,
        range: &str,
        body: &'static [u8],
        etag: &str,
    ) -> std::io::Result<()> {
        cache
            .put_fragment_at_epoch(
                cache.epoch(),
                &key(),
                StatusCode::PARTIAL_CONTENT,
                &headers(range, etag),
                Bytes::from_static(body),
                Duration::from_secs(60),
                100_000,
            )
            .await
    }

    #[tokio::test]
    async fn abandoned_checkpoint_during_fragment_verification_blocks_hit_and_total_for_known_and_uncaptured_keys(
    ) {
        for total_lookup in [false, true] {
            for captured in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let cache = CacheStore::new_with_recovery(
                    directory.path().join("cache"),
                    directory.path().join("config").join("recovery"),
                );
                let base = "b".repeat(64);
                let known = "c".repeat(64);
                let target = if captured {
                    known.clone()
                } else {
                    "a".repeat(64)
                };
                let unrelated = "d".repeat(64);
                for (key, family) in [(&known, &base), (&target, &base), (&unrelated, &unrelated)] {
                    let mut fragment_headers = headers("bytes 0-2/6", "\"same\"");
                    fragment_headers.insert(variants::BASE, HeaderValue::from_str(family).unwrap());
                    cache
                        .put_fragment_at_epoch(
                            cache.epoch(),
                            key,
                            StatusCode::PARTIAL_CONTENT,
                            &fragment_headers,
                            Bytes::from_static(b"abc"),
                            Duration::from_secs(600),
                            100_000,
                        )
                        .await
                        .unwrap();
                }
                let epoch = cache.epoch();
                let guard = cache.key_guard(&base).unwrap();
                let started = Arc::new(std::sync::Barrier::new(2));
                let resume = Arc::new(std::sync::Barrier::new(2));
                cache.state.lock().unwrap().hit_prepass_gate =
                    Some((target.clone(), started.clone(), resume.clone()));
                let lookup = {
                    let cache = cache.clone();
                    let target = target.clone();
                    tokio::spawn(async move {
                        if total_lookup {
                            cache.fragment_total(&target).await.is_some()
                        } else {
                            cache.get_fragment(&target, 0, 1, false).await.is_some()
                        }
                    })
                };
                tokio::task::spawn_blocking(move || started.wait())
                    .await
                    .unwrap();
                let checkpoint = cache
                    .begin_recovery_checkpoint(epoch, &base, std::slice::from_ref(&known), &guard)
                    .unwrap();
                drop(checkpoint);
                let unrelated_hit = cache.get_fragment(&unrelated, 0, 1, false).await;
                let unrelated_total = cache.fragment_total(&unrelated).await;
                let state_evidence = {
                    let state = cache.state.lock().unwrap();
                    (
                        state.epoch,
                        state.recovery.global_blocked.load(Ordering::Acquire),
                        state.recovery.blocked_keys.contains(&target),
                        state.recovery.blocked_keys.contains(&base),
                        state.invalidated_keys.contains(&target),
                    )
                };
                cache.state.lock().unwrap().hit_prepass_gate = None;
                tokio::task::spawn_blocking(move || resume.wait())
                    .await
                    .unwrap();
                let hit = lookup.await.unwrap();
                assert!(
                    !hit,
                    "abandonment must fence the already verified fragment lookup"
                );
                assert_eq!(state_evidence, (epoch, false, captured, true, false));
                assert_eq!(unrelated_total, Some(6));
                assert_eq!(
                    unrelated_hit
                        .unwrap()
                        .body
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes(),
                    "ab"
                );
                assert!(cache.get_fragment(&target, 0, 1, true).await.is_none());
                assert!(cache.fragment_total(&target).await.is_none());
            }
        }
    }

    #[tokio::test]
    async fn gated_fragment_prepass_allows_unrelated_hits_and_protects_generation() {
        for clear in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cache = CacheStore::new(dir.path().into());
            let first = "a".repeat(64);
            cache
                .put(
                    &first,
                    StatusCode::OK,
                    &HeaderMap::new(),
                    Bytes::from_static(b"retained"),
                    Duration::from_secs(60),
                    100_000,
                )
                .await
                .unwrap();
            put(&cache, "bytes 0-2/6", b"abc", "\"v1\"").await.unwrap();
            let started = Arc::new(std::sync::Barrier::new(2));
            let resume = Arc::new(std::sync::Barrier::new(2));
            cache.state.lock().unwrap().fragment_prepass_gate =
                Some((started.clone(), resume.clone()));
            let merging = {
                let cache = cache.clone();
                tokio::spawn(async move { put(&cache, "bytes 3-5/6", b"def", "\"v1\"").await })
            };
            tokio::task::spawn_blocking(move || started.wait())
                .await
                .unwrap();
            let hit = cache.get(&first).await;
            let replacement = cache
                .put(
                    &key(),
                    StatusCode::OK,
                    &HeaderMap::new(),
                    Bytes::from_static(b"unsafe"),
                    Duration::from_secs(60),
                    100_000,
                )
                .await;
            let old_body_exists = dir.path().join(format!("{}.body", key())).exists();
            let cleared = if clear {
                Some(cache.clear().await)
            } else {
                None
            };
            cache.state.lock().unwrap().fragment_prepass_gate = None;
            tokio::task::spawn_blocking(move || resume.wait())
                .await
                .unwrap();
            let merged = merging.await.unwrap();
            let hit = hit.expect(
                "unrelated cached HIT must be available throughout fragment integrity prepass",
            );
            assert_eq!(hit.body.collect().await.unwrap().to_bytes(), "retained");
            assert_eq!(
                replacement.unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(old_body_exists);
            if let Some(cleared) = cleared {
                assert_eq!(cleared.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
                assert!(merged.is_err());
                cache.maintain().await.unwrap();
                assert!(cache.get(&key()).await.is_none());
                assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
            } else {
                merged.unwrap();
                assert_eq!(
                    cache
                        .get(&key())
                        .await
                        .unwrap()
                        .body
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes(),
                    "abcdef"
                );
            }
        }
    }

    #[tokio::test]
    async fn invalidated_fragment_is_not_resurrected_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        put(&cache, "bytes 0-2/6", b"abc", "\"v1\"").await.unwrap();
        cache.invalidate_key(&key());
        drop(cache);
        let cache = CacheStore::new(dir.path().into());
        assert!(cache.fragment_total(&key()).await.is_none());
        assert!(cache.get_fragment(&key(), 0, 2, true).await.is_none());
    }

    #[tokio::test]
    async fn covered_ranges_hit_holes_miss_and_complete_coverage_promotes_to_200() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        put(&cache, "bytes 0-2/9", b"abc", "\"v1\"").await.unwrap();
        put(&cache, "bytes 6-8/9", b"ghi", "\"v1\"").await.unwrap();
        assert!(cache.get(&key()).await.is_none());
        assert_eq!(cache.fragment_total(&key()).await, Some(9));
        assert!(cache.get_fragment(&key(), 1, 7, false).await.is_none());
        let hit = cache.get_fragment(&key(), 6, 7, false).await.unwrap();
        assert_eq!(hit.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(hit.headers["content-range"], "bytes 6-7/9");
        assert_eq!(hit.body.collect().await.unwrap().to_bytes(), "gh");
        drop(cache);
        let cache = CacheStore::new(dir.path().into());
        assert!(cache.get_fragment(&key(), 3, 5, false).await.is_none());
        put(&cache, "bytes 3-5/9", b"def", "\"v1\"").await.unwrap();
        let full = cache.get(&key()).await.unwrap();
        assert_eq!(full.status, StatusCode::OK);
        assert!(!full.headers.contains_key("content-range"));
        assert_eq!(full.headers["content-length"], "9");
        assert_eq!(full.body.collect().await.unwrap().to_bytes(), "abcdefghi");
    }
    #[tokio::test]
    async fn equal_overlap_merges_but_conflicting_overlap_invalidates_generation() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        put(&cache, "bytes 0-3/10", b"abcd", "\"v1\"")
            .await
            .unwrap();
        put(&cache, "bytes 2-5/10", b"cdef", "\"v1\"")
            .await
            .unwrap();
        assert_eq!(
            cache
                .get_fragment(&key(), 0, 5, false)
                .await
                .unwrap()
                .body
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            "abcdef"
        );
        assert!(put(&cache, "bytes 4-6/10", b"XXg", "\"v1\"").await.is_err());
        assert!(cache.get_fragment(&key(), 0, 5, true).await.is_none());
    }
    #[tokio::test]
    async fn changed_etag_coding_or_vary_never_mix_generations() {
        for change in ["etag", "content-encoding", "vary"] {
            let dir = tempfile::tempdir().unwrap();
            let cache = CacheStore::new(dir.path().into());
            put(&cache, "bytes 0-2/6", b"abc", "\"v1\"").await.unwrap();
            let mut headers = headers("bytes 3-5/6", "\"v1\"");
            headers.insert(
                HeaderName::from_bytes(change.as_bytes()).unwrap(),
                HeaderValue::from_static(if change == "etag" {
                    "\"v2\""
                } else if change == "vary" {
                    "accept-language"
                } else {
                    "gzip"
                }),
            );
            assert!(cache
                .put_fragment_at_epoch(
                    cache.epoch(),
                    &key(),
                    StatusCode::PARTIAL_CONTENT,
                    &headers,
                    Bytes::from_static(b"def"),
                    Duration::from_secs(60),
                    100_000
                )
                .await
                .is_err());
            assert!(cache.get_fragment(&key(), 0, 2, true).await.is_none());
        }
    }
    #[tokio::test]
    async fn weak_unknown_total_bad_length_and_zero_ttl_are_safe() {
        for (range, etag, body) in [
            ("bytes 0-2/*", "\"v1\"", b"abc".as_slice()),
            ("bytes 0-2/6", "W/\"v1\"", b"abc".as_slice()),
            ("bytes 0-2/6", "\"v1\"", b"ab".as_slice()),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let cache = CacheStore::new(dir.path().into());
            assert!(put(&cache, range, body, etag).await.is_err());
            assert!(cache.get_fragment(&key(), 0, 1, true).await.is_none());
        }
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        cache
            .put_fragment_at_epoch(
                cache.epoch(),
                &key(),
                StatusCode::PARTIAL_CONTENT,
                &headers("bytes 0-2/6", "\"v1\""),
                Bytes::from_static(b"abc"),
                Duration::ZERO,
                100_000,
            )
            .await
            .unwrap();
        assert!(cache.get_fragment(&key(), 0, 2, false).await.is_none());
        assert!(cache.get_fragment(&key(), 0, 2, true).await.is_some());
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;
    fn headers(start: u64, total: u64) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("etag", HeaderValue::from_static("\"bounds\""));
        headers.insert(
            "content-range",
            HeaderValue::from_str(&format!("bytes {start}-{start}/{total}")).unwrap(),
        );
        headers
    }
    #[tokio::test]
    async fn interval_count_is_bounded_and_rejection_preserves_verified_generation() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let key = "d".repeat(64);
        for index in 0..MAX_INTERVALS {
            cache
                .put_fragment_at_epoch(
                    cache.epoch(),
                    &key,
                    StatusCode::PARTIAL_CONTENT,
                    &headers(index as u64 * 2, 130),
                    Bytes::from_static(b"x"),
                    Duration::from_secs(60),
                    100_000,
                )
                .await
                .unwrap();
        }
        assert!(cache
            .put_fragment_at_epoch(
                cache.epoch(),
                &key,
                StatusCode::PARTIAL_CONTENT,
                &headers(128, 130),
                Bytes::from_static(b"x"),
                Duration::from_secs(60),
                100_000
            )
            .await
            .is_err());
        assert!(cache.get_fragment(&key, 0, 0, false).await.is_some());
        assert!(cache.get_fragment(&key, 1, 1, false).await.is_none());
        let metadata = load_metadata(dir.path(), &key).unwrap();
        assert_eq!(metadata.fragments.unwrap().intervals.len(), MAX_INTERVALS);
    }
    #[tokio::test]
    async fn replacement_space_counts_old_generation_and_rejects_without_publishing() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let key = "c".repeat(64);
        cache
            .put_fragment_at_epoch(
                cache.epoch(),
                &key,
                StatusCode::PARTIAL_CONTENT,
                &headers(0, 4),
                Bytes::from_static(b"x"),
                Duration::from_secs(60),
                100_000,
            )
            .await
            .unwrap();
        let used = measure_sync(dir.path()).unwrap().used_bytes;
        cache.configure_limits(used + 1, MAX_CACHE_ITEM_BYTES);
        cache.maintain().await.unwrap();
        assert!(cache
            .put_fragment_at_epoch(
                cache.epoch(),
                &key,
                StatusCode::PARTIAL_CONTENT,
                &headers(2, 4),
                Bytes::from_static(b"x"),
                Duration::from_secs(60),
                100_000
            )
            .await
            .is_err());
        assert!(measure_sync(dir.path()).unwrap().used_bytes <= used + 1);
        assert!(cache.get_fragment(&key, 0, 0, false).await.is_some());
        assert!(cache.get_fragment(&key, 2, 2, false).await.is_none());
    }
}

#[cfg(test)]
mod publication_durability_tests {
    use super::*;
    use http_body_util::BodyExt;

    enum Publication {
        Fragment,
        Buffered,
        Streaming,
    }

    fn public_headers(base: &str, no_cache: bool) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cache-control",
            HeaderValue::from_static(if no_cache {
                "public, no-cache, max-age=120"
            } else {
                "public, max-age=120"
            }),
        );
        headers.insert("etag", HeaderValue::from_static("\"same\""));
        headers.insert(variants::BASE, HeaderValue::from_str(base).unwrap());
        headers
    }

    async fn failed_sync_keeps_checkpoint(publication: Publication) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("cache");
        let journal = directory.path().join("config").join("recovery.json");
        let cache = CacheStore::new_with_recovery(root.clone(), journal.clone());
        cache.configure_limits(1024 * 1024, 1024 * 1024);
        let base = "b".repeat(64);
        let selected = "a".repeat(64);
        let pinned = "c".repeat(64);
        cache
            .put(
                &pinned,
                StatusCode::OK,
                &public_headers(&pinned, false),
                Bytes::from_static(b"pin"),
                Duration::from_secs(120),
                1024 * 1024,
            )
            .await
            .unwrap();
        cache
            .pin(&pinned, &cache.snapshot(&pinned).await.unwrap())
            .await
            .unwrap();
        let old_headers = public_headers(&base, false);
        if matches!(publication, Publication::Fragment) {
            let mut headers = old_headers;
            headers.insert("content-range", HeaderValue::from_static("bytes 0-1/8"));
            cache
                .put_fragment_at_epoch(
                    cache.epoch(),
                    &selected,
                    StatusCode::PARTIAL_CONTENT,
                    &headers,
                    Bytes::from_static(b"ab"),
                    Duration::from_secs(120),
                    1024 * 1024,
                )
                .await
                .unwrap();
            assert!(cache.get_fragment(&selected, 0, 1, false).await.is_some());
        } else {
            cache
                .put(
                    &selected,
                    StatusCode::OK,
                    &old_headers,
                    Bytes::from_static(b"old"),
                    Duration::from_secs(120),
                    1024 * 1024,
                )
                .await
                .unwrap();
            assert!(cache.get(&selected).await.is_some());
        }
        let guard = cache.key_guard(&base).unwrap();
        let checkpoint = cache
            .begin_recovery_checkpoint(
                cache.epoch(),
                &base,
                std::slice::from_ref(&selected),
                &guard,
            )
            .unwrap();
        cache.state.lock().unwrap().fail_publication_directory_sync = true;
        let mut headers = public_headers(&base, true);
        let expected_body = match publication {
            Publication::Fragment => {
                headers.insert("content-range", HeaderValue::from_static("bytes 4-5/8"));
                assert!(cache
                    .put_fragment_at_epoch_guarded(
                        cache.epoch(),
                        &selected,
                        StatusCode::PARTIAL_CONTENT,
                        &headers,
                        Bytes::from_static(b"ef"),
                        Duration::ZERO,
                        1024 * 1024,
                        &guard,
                    )
                    .await
                    .is_err());
                b"abef".as_slice()
            }
            Publication::Buffered => {
                assert!(cache
                    .put_at_epoch_guarded(
                        cache.epoch(),
                        &selected,
                        StatusCode::OK,
                        &headers,
                        Bytes::from_static(b"new"),
                        Duration::ZERO,
                        1024 * 1024,
                        &guard,
                    )
                    .await
                    .is_err());
                b"new".as_slice()
            }
            Publication::Streaming => {
                let fill = cache
                    .begin_fill_guarded(
                        cache.epoch(),
                        &selected,
                        StatusCode::OK,
                        &headers,
                        3,
                        Duration::ZERO,
                        Instant::now(),
                        1024 * 1024,
                        &guard,
                    )
                    .await
                    .unwrap();
                assert!(
                    !fill
                        .write(Bytes::from_static(b"new"))
                        .await
                        .unwrap()
                        .commit()
                        .await
                );
                b"new".as_slice()
            }
        };
        // Injection happens after both renames: the new body and restrictive
        // metadata exist, while the independently persisted checkpoint remains.
        let metadata: CacheMetadata =
            serde_json::from_slice(&fs::read(root.join(format!("{selected}.json"))).unwrap())
                .unwrap();
        assert!(metadata.online_validation_required);
        assert!(metadata.headers.iter().any(|(name, value)| {
            name == "cache-control" && value == "public, no-cache, max-age=120"
        }));
        assert_eq!(
            fs::read(root.join(format!("{selected}.body"))).unwrap(),
            expected_body
        );
        assert!(cache.finish_recovery_checkpoint(&checkpoint).is_err());
        let persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        assert_eq!(persisted["records"].as_array().unwrap().len(), 1);
        {
            let state = cache.state.lock().unwrap();
            assert!(state.recovery.global_blocked.load(Ordering::Acquire));
            assert!(state.maintenance_failure.is_some());
        }
        assert!(cache.get_including_stale(&selected).await.is_none());
        assert!(cache.get_fragment(&selected, 0, 1, true).await.is_none());
        assert_eq!(cache.list_pins().await.unwrap().len(), 1);
        drop(checkpoint);
        drop(guard);
        drop(cache);
        let restarted = CacheStore::new_with_recovery(root, journal);
        restarted.configure_limits(1024 * 1024, 1024 * 1024);
        assert!(restarted.recovery_blocks_family(&base));
        assert!(!restarted.recovery_blocks_family(&pinned));
        assert!(restarted.get_including_stale(&selected).await.is_none());
        assert!(restarted
            .get_fragment(&selected, 0, 1, true)
            .await
            .is_none());
        assert!(restarted.status_snapshot(&selected).await.is_none());
        assert_eq!(restarted.list_pins().await.unwrap().len(), 1);
        assert_eq!(
            restarted
                .get(&pinned)
                .await
                .unwrap()
                .body
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            Bytes::from_static(b"pin")
        );
        assert_eq!(restarted.unpin(&pinned).await.unwrap().entry_count, 0);
    }

    #[tokio::test]
    async fn fragment_directory_sync_failure_after_publication_retains_checkpoint_across_restart() {
        failed_sync_keeps_checkpoint(Publication::Fragment).await;
    }

    #[tokio::test]
    async fn buffered_directory_sync_failure_after_publication_retains_checkpoint_across_restart() {
        failed_sync_keeps_checkpoint(Publication::Buffered).await;
    }

    #[tokio::test]
    async fn streaming_directory_sync_failure_after_publication_returns_false_and_retains_checkpoint(
    ) {
        failed_sync_keeps_checkpoint(Publication::Streaming).await;
    }
}
