//! Bounded representation index. A pointer is usable only after verified disk metadata agrees.
use http::{
    header::{ACCEPT_ENCODING, CONTENT_ENCODING, VARY},
    HeaderMap,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

const MAX_BASES: usize = 8192;
const MAX_VARIANTS: usize = 16;
pub(crate) const SCHEMA: &str = "x-homeproxy-variant-schema";
pub(crate) const BASE: &str = "x-homeproxy-variant-base";
pub(crate) const GENERATION: &str = "x-homeproxy-variant-generation";
pub(crate) const SELECTOR: &str = "x-homeproxy-variant-selector";

#[derive(Clone, Default)]
pub(crate) struct VariantIndex {
    state: Arc<Mutex<IndexState>>,
    hydration: Arc<tokio::sync::Mutex<()>>,
}
#[derive(Default)]
struct IndexState {
    families: BTreeMap<String, Family>,
    lru: BTreeSet<(u64, String)>,
    empty_lru: BTreeSet<(u64, String)>,
    // A bounded metadata catalog preserves disk pointers when an active family
    // is evicted. It never authorizes serving an unverified body.
    dormant: BTreeMap<String, Family>,
    dormant_lru: BTreeSet<(u64, String)>,
    clock: u64,
    next_token: u64,
    persistence: Option<PersistenceProbe>,
    hydrated: bool,
    scan_revision: u64,
    #[cfg(test)]
    scans: usize,
    #[cfg(test)]
    metadata_reads: usize,
    #[cfg(test)]
    hydration_gate: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}
struct PersistenceProbe {
    root: std::path::PathBuf,
    state: std::sync::Weak<Mutex<super::CacheState>>,
}
#[derive(Clone, Default)]
struct Family {
    // Admission tokens are process-monotonic and differ from the persisted
    // generation, so eviction/recreation cannot admit an old origin response.
    token: u64,
    guard: Option<super::CacheKeyGuard>,
    touched: u64,
    generation: u64,
    schema: Option<Vec<String>>,
    candidates: Vec<Candidate>,
}
impl IndexState {
    fn token(&mut self) -> u64 {
        let token = self.next_token;
        self.next_token = self
            .next_token
            .checked_add(1)
            .expect("variant token exhausted");
        token
    }
    fn family(&mut self, base: &str) -> &mut Family {
        if !self.families.contains_key(base) {
            if self.families.len() >= MAX_BASES {
                let oldest = self
                    .empty_lru
                    .first()
                    .or_else(|| self.lru.first())
                    .cloned()
                    .unwrap();
                self.lru.remove(&oldest);
                self.empty_lru.remove(&oldest);
                let mut family = self.families.remove(&oldest.1).unwrap();
                if let Some((probe, state)) = self
                    .persistence
                    .as_ref()
                    .and_then(|probe| probe.state.upgrade().map(|state| (probe, state)))
                {
                    // Publication and eviction classification are atomic. Never
                    // catalog an absent speculative pointer, or discard one
                    // that a concurrent fill has just durably published.
                    let state = state.lock().unwrap();
                    family.candidates.retain(|candidate| {
                        let missing = matches!(std::fs::metadata(probe.root.join(format!("{}.json", candidate.key))),
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound);
                        if missing {
                            if let Some(generation) = state.key_generations.get(&candidate.key).and_then(std::sync::Weak::upgrade) {
                                generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                            }
                        }
                        !missing
                    });
                    if let Some(guard) = family.guard.take() {
                        let _ = guard.generation.compare_exchange(
                            guard.expected,
                            guard.expected.wrapping_add(1),
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                    }
                } else if let Some(guard) = family.guard.take() {
                    guard.retire();
                }
                if !family.candidates.is_empty() {
                    if self.dormant.len() >= MAX_BASES {
                        let retired = self.dormant_lru.first().cloned().unwrap();
                        self.dormant_lru.remove(&retired);
                        self.dormant.remove(&retired.1);
                    }
                    self.dormant_lru.insert(oldest.clone());
                    self.dormant.insert(oldest.1, family);
                }
            }
            let mut family = self.dormant.remove(base).unwrap_or_default();
            self.dormant_lru.remove(&(family.touched, base.to_owned()));
            family.token = self.token();
            self.families.insert(base.to_owned(), family);
        }
        let family = self.families.get_mut(base).unwrap();
        self.lru.remove(&(family.touched, base.to_owned()));
        self.empty_lru.remove(&(family.touched, base.to_owned()));
        self.clock = self.clock.checked_add(1).expect("variant clock exhausted");
        family.touched = self.clock;
        self.lru.insert((family.touched, base.to_owned()));
        if family.candidates.is_empty() {
            self.empty_lru.insert((family.touched, base.to_owned()));
        }
        family
    }
    fn refresh_empty(&mut self, base: &str) {
        let family = self.families.get(base).unwrap();
        let entry = (family.touched, base.to_owned());
        if family.candidates.is_empty() {
            self.empty_lru.insert(entry);
        } else {
            self.empty_lru.remove(&entry);
        }
    }
}
#[derive(Clone)]
pub(crate) struct Candidate {
    pub key: String,
    base: String,
    generation: u64,
    schema: String,
    selector: String,
    coding: String,
}
impl Candidate {
    pub fn verifies(&self, headers: &HeaderMap) -> bool {
        headers
            .get(BASE)
            .is_some_and(|value| value.as_bytes() == self.base.as_bytes())
            && headers
                .get(GENERATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                == Some(self.generation)
            && headers
                .get(SCHEMA)
                .is_some_and(|v| v.as_bytes() == self.schema.as_bytes())
            && headers
                .get(SELECTOR)
                .is_some_and(|v| v.as_bytes() == self.selector.as_bytes())
            && coding(headers).as_deref() == Some(&self.coding)
    }
}
impl VariantIndex {
    pub(super) fn configure_persistence(
        &self,
        root: std::path::PathBuf,
        state: std::sync::Weak<Mutex<super::CacheState>>,
    ) {
        self.state.lock().unwrap().persistence = Some(PersistenceProbe { root, state });
    }
    pub fn clear(&self) {
        let mut state = self.state.lock().unwrap();
        for family in state.families.values_mut() {
            if let Some(guard) = family.guard.take() {
                guard.retire();
            }
        }
        state.families.clear();
        state.lru.clear();
        state.empty_lru.clear();
        state.dormant.clear();
        state.dormant_lru.clear();
        state.hydrated = false;
        state.scan_revision = state.scan_revision.wrapping_add(1);
        // Retain the admission clock across clear to fence outstanding responses.
    }
    #[cfg(test)]
    fn restore(&self, base: &str, key: &str, headers: &HeaderMap) {
        self.restore_at_revision(base, key, headers, None);
    }
    fn restore_at_revision(
        &self,
        base: &str,
        key: &str,
        headers: &HeaderMap,
        revision: Option<u64>,
    ) {
        if headers
            .get(BASE)
            .is_none_or(|v| v.as_bytes() != base.as_bytes())
        {
            return;
        }
        let Some(schema) = schema(headers) else {
            return;
        };
        let Some(coding) = coding(headers) else {
            return;
        };
        let Some(generation) = headers
            .get(GENERATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        else {
            return;
        };
        let Some(selected) = headers.get(SELECTOR).and_then(|v| v.to_str().ok()) else {
            return;
        };
        let schema_text = schema.join(",");
        if headers
            .get(SCHEMA)
            .is_none_or(|v| v.as_bytes() != schema_text.as_bytes())
        {
            return;
        }
        let derived = hex::encode(Sha256::digest(
            format!("variant-v1\n{base}\n{generation}\n{schema_text}\n{selected}\n{coding}")
                .as_bytes(),
        ));
        if derived != key {
            return;
        }
        let mut state = self.state.lock().unwrap();
        if revision.is_some_and(|revision| state.scan_revision != revision) {
            return;
        }
        let family = state.family(base);
        if generation < family.generation {
            return;
        }
        if generation > family.generation {
            family.candidates.clear();
            family.generation = generation;
            family.schema = None;
        }
        if family.schema.as_ref().is_some_and(|old| old != &schema) {
            return;
        }
        family.schema = Some(schema);
        if family.candidates.len() < MAX_VARIANTS && !family.candidates.iter().any(|v| v.key == key)
        {
            family.candidates.push(Candidate {
                key: key.into(),
                base: base.into(),
                generation,
                schema: schema_text,
                selector: selected.into(),
                coding,
            });
        }
        state.refresh_empty(base);
    }
    pub fn generation(&self, base: &str) -> u64 {
        self.state.lock().unwrap().family(base).token
    }
    pub fn bind_guard(&self, base: &str, token: u64, guard: super::CacheKeyGuard) -> bool {
        let mut state = self.state.lock().unwrap();
        let Some(family) = state.families.get_mut(base) else {
            return false;
        };
        if family.token != token || !guard.is_current() {
            return false;
        }
        family.guard = Some(guard);
        true
    }
    #[cfg(test)]
    pub(crate) fn scan_counts(&self) -> (usize, usize) {
        let state = self.state.lock().unwrap();
        (state.scans, state.metadata_reads)
    }
    pub fn lookup(&self, base: &str, origin: &HeaderMap, client: &HeaderMap) -> Option<Candidate> {
        let mut state = self.state.lock().unwrap();
        // Misses do not reserve index space; generation() admits a response later.
        if !state.families.contains_key(base) && !state.dormant.contains_key(base) {
            return None;
        }
        let family = state.family(base);
        let schema = family.schema.as_ref()?;
        let selected = selector(schema, origin);
        family
            .candidates
            .iter()
            .find(|c| c.selector == selected && accepts_coding(client, &c.coding))
            .cloned()
    }
    pub fn family_keys(&self, base: &str) -> Vec<String> {
        let state = self.state.lock().unwrap();
        state
            .families
            .get(base)
            .or_else(|| state.dormant.get(base))
            .map(|family| {
                family
                    .candidates
                    .iter()
                    .map(|candidate| candidate.key.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn schema_changed(&self, base: &str, headers: &HeaderMap) -> bool {
        let state = self.state.lock().unwrap();
        state
            .families
            .get(base)
            .or_else(|| state.dormant.get(base))
            .and_then(|family| family.schema.as_ref())
            .is_some_and(|old| schema(headers).as_ref() != Some(old))
    }
    /// Retire outstanding writers after an authoritative replacement of one
    /// representation, keeping the family's persisted selection schema intact.
    pub fn retire_writers(
        &self,
        base: &str,
        expected_token: u64,
        invalidate: impl FnOnce() -> Option<u64>,
    ) -> Option<(u64, u64)> {
        let mut state = self.state.lock().unwrap();
        let family = state.families.get_mut(base)?;
        if family.token != expected_token {
            return None;
        }
        let epoch = invalidate()?;
        if let Some(guard) = family.guard.take() {
            guard.retire();
        }
        let token = state.token();
        state.families.get_mut(base).unwrap().token = token;
        Some((token, epoch))
    }
    /// Retires a rejected representation's whole family before an origin retry.
    /// The guarded disk invalidation runs under the family lock, so an epoch
    /// rejection leaves the index unchanged and a concurrent observation cannot
    /// publish another old-schema candidate between the two invalidations.
    pub fn invalidate_family(
        &self,
        base: &str,
        expected_generation: u64,
        selected_key: &str,
        invalidate: impl FnOnce(&[String]) -> Option<u64>,
    ) -> Option<(u64, u64, Vec<String>)> {
        let mut state = self.state.lock().unwrap();
        let family = state.family(base);
        if family.token != expected_generation {
            return None;
        }
        let mut keys = family
            .candidates
            .iter()
            .map(|candidate| candidate.key.clone())
            .collect::<Vec<_>>();
        // Include a legacy/fallback selected key even if it has no index pointer.
        if !keys.iter().any(|key| key == selected_key) {
            keys.push(selected_key.to_owned());
        }
        let epoch = invalidate(&keys)?;
        if let Some(guard) = family.guard.take() {
            guard.retire();
        }
        family.candidates.clear();
        family.generation = family.generation.wrapping_add(1);
        family.schema = None;
        let token = state.token();
        state.families.get_mut(base).unwrap().token = token;
        state.refresh_empty(base);
        Some((token, epoch, keys))
    }
    #[cfg(test)]
    pub fn observe(
        &self,
        base: &str,
        expected_generation: u64,
        origin: &HeaderMap,
        headers: &mut HeaderMap,
    ) -> Option<(String, Vec<String>, u64)> {
        self.observe_with_invalidation(base, expected_generation, origin, headers, |_| true)
    }
    /// Rejects late fills and atomically retires old disk pointers before
    /// publishing a changed selection schema. The callback must not lock this index.
    pub fn observe_with_invalidation(
        &self,
        base: &str,
        expected_generation: u64,
        origin: &HeaderMap,
        headers: &mut HeaderMap,
        invalidate: impl FnOnce(&[String]) -> bool,
    ) -> Option<(String, Vec<String>, u64)> {
        let schema = schema(headers)?;
        let coding = coding(headers)?;
        let mut state = self.state.lock().unwrap();
        let family = state.family(base);
        if family.token != expected_generation {
            return None;
        }
        let mut invalidated = Vec::new();
        let changed = family.schema.as_ref().is_some_and(|old| old != &schema);
        if changed {
            invalidated = family
                .candidates
                .iter()
                .map(|candidate| candidate.key.clone())
                .collect();
            if !invalidate(&invalidated) {
                return None;
            }
            if let Some(guard) = family.guard.take() {
                guard.retire();
            }
            family.generation = family.generation.wrapping_add(1);
            family.candidates.clear();
        }
        family.schema = Some(schema.clone());
        let selected = selector(&schema, origin);
        let schema_text = schema.join(",");
        let key = hex::encode(Sha256::digest(
            format!(
                "variant-v1\n{base}\n{}\n{schema_text}\n{selected}\n{coding}",
                family.generation
            )
            .as_bytes(),
        ));
        if !family.candidates.iter().any(|c| c.key == key) {
            if family.candidates.len() >= MAX_VARIANTS {
                return None;
            }
            family.candidates.push(Candidate {
                key: key.clone(),
                base: base.into(),
                generation: family.generation,
                schema: schema_text.clone(),
                selector: selected.clone(),
                coding,
            });
        }
        headers.insert(BASE, base.parse().ok()?);
        headers.insert(GENERATION, family.generation.to_string().parse().ok()?);
        headers.insert(SCHEMA, schema_text.parse().ok()?);
        headers.insert(SELECTOR, selected.parse().ok()?);
        if changed {
            let token = state.token();
            state.families.get_mut(base).unwrap().token = token;
        }
        state.refresh_empty(base);
        Some((key, invalidated, state.families.get(base).unwrap().token))
    }
}
impl super::CacheStore {
    /// Reclaim bounded speculative pointers at capacity. Metadata publication,
    /// guard retirement and pointer removal share the publication mutex, so a
    /// concurrently committed (or pinned) representation is never mistaken for
    /// an unpublished candidate. This does not delete any persisted entry.
    pub(crate) fn reclaim_unpublished_variants(&self, base: &str) {
        let mut index = self.variants.state.lock().unwrap();
        let Some(family) = index.families.get_mut(base) else {
            return;
        };
        if family.candidates.len() < MAX_VARIANTS {
            return;
        }
        let state = self.state.lock().unwrap();
        let missing = family
            .candidates
            .iter()
            .filter(|candidate| {
                matches!(std::fs::metadata(self.root.join(format!("{}.json", candidate.key))),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound)
            })
            .map(|candidate| candidate.key.clone())
            .collect::<BTreeSet<_>>();
        if missing.is_empty() {
            return;
        }
        for key in &missing {
            if let Some(generation) = state
                .key_generations
                .get(key)
                .and_then(std::sync::Weak::upgrade)
            {
                generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            }
        }
        if let Some(guard) = family.guard.take() {
            // The CacheState publication mutex is already held; use the same
            // compare/exchange as CacheKeyGuard::retire without relocking it.
            let _ = guard.generation.compare_exchange(
                guard.expected,
                guard.expected.wrapping_add(1),
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            );
        }
        family
            .candidates
            .retain(|candidate| !missing.contains(&candidate.key));
        let token = index.token();
        index.families.get_mut(base).unwrap().token = token;
        index.refresh_empty(base);
    }
    /// Keep the verified body lease with its snapshot so offline serving does
    /// not hash the same body a second time through get_if_snapshot.
    pub(crate) async fn snapshot_entry(
        &self,
        key: &str,
    ) -> Option<(super::CacheSnapshot, super::CachedEntry)> {
        let guard = self.key_guard(key)?;
        let epoch = self.epoch();
        let mut entry = self.get_including_stale(key).await?;
        let snapshot = self
            .snapshot_verified_entry(key, epoch, guard, &mut entry)
            .await?;
        Some((snapshot, entry))
    }
    /// Discover disk pointers once per store load/clear. A pointer is a hint;
    /// cached_key and the serving path still verify the actual representation.
    pub(crate) async fn hydrate_variants(&self, _base: &str) {
        let _scan = self.variants.hydration.lock().await;
        let revision = {
            #[allow(unused_mut)]
            let mut state = self.variants.state.lock().unwrap();
            if state.hydrated {
                return;
            }
            #[cfg(test)]
            {
                state.scans += 1;
            }
            state.scan_revision
        };
        let epoch = self.epoch();
        let Ok(mut entries) = tokio::fs::read_dir(&self.root).await else {
            let mut state = self.variants.state.lock().unwrap();
            if state.scan_revision == revision {
                state.hydrated = true;
            }
            return;
        };
        let mut count = 0;
        let mut metadata_count = 0;
        while let Ok(Some(entry)) = entries.next_entry().await {
            count += 1;
            if count > super::MAX_CACHE_FILES || metadata_count >= super::MAX_CACHE_ENTRIES {
                break;
            }
            if !self.valid_epoch(epoch)
                || self.variants.state.lock().unwrap().scan_revision != revision
            {
                return;
            }
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let Some(key) = path.file_stem().and_then(|name| name.to_str()) else {
                continue;
            };
            if !super::valid_key(key) {
                continue;
            }
            if entry
                .metadata()
                .await
                .ok()
                .is_none_or(|m| m.len() as usize > super::MAX_METADATA_BYTES)
            {
                continue;
            }
            metadata_count += 1;
            #[cfg(test)]
            {
                self.variants.state.lock().unwrap().metadata_reads += 1;
            }
            let Ok(raw) = tokio::fs::read(&path).await else {
                continue;
            };
            let Ok(metadata) = serde_json::from_slice::<super::CacheMetadata>(&raw) else {
                continue;
            };
            if metadata.invalidated || metadata.version != 1 {
                continue;
            }
            let Some(headers) = super::deserialize_headers(metadata.headers) else {
                continue;
            };
            let Some(base) = headers.get(BASE).and_then(|v| v.to_str().ok()) else {
                continue;
            };
            if !super::valid_key(base) {
                continue;
            }
            #[cfg(test)]
            {
                let gate = self.variants.state.lock().unwrap().hydration_gate.take();
                if let Some((reached, resume)) = gate {
                    reached.notify_one();
                    resume.notified().await;
                }
            }
            if self.valid_epoch(epoch) {
                self.variants
                    .restore_at_revision(base, key, &headers, Some(revision));
            }
        }
        let mut state = self.variants.state.lock().unwrap();
        if state.scan_revision == revision {
            state.hydrated = true;
        }
    }
}

pub(crate) fn schema(headers: &HeaderMap) -> Option<Vec<String>> {
    let mut fields = Vec::new();
    for value in headers.get_all(VARY) {
        for name in value.to_str().ok()?.split(',') {
            let name = name.trim().to_ascii_lowercase();
            if name.is_empty()
                || name == "*"
                || http::HeaderName::from_bytes(name.as_bytes()).is_err()
            {
                return None;
            }
            fields.push(name);
        }
    }
    fields.sort();
    fields.dedup();
    Some(fields)
}
fn selector(fields: &[String], headers: &HeaderMap) -> String {
    let mut digest = Sha256::new();
    for name in fields {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        let values = headers.get_all(name).iter().collect::<Vec<_>>();
        digest.update((values.len() as u64).to_be_bytes());
        for value in values {
            digest.update((value.as_bytes().len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
    }
    hex::encode(digest.finalize())
}
pub(crate) fn coding(headers: &HeaderMap) -> Option<String> {
    let values = headers.get_all(CONTENT_ENCODING).iter().collect::<Vec<_>>();
    if values.is_empty() {
        return Some("identity".into());
    }
    if values.len() != 1 {
        return None;
    }
    let name = values[0].to_str().ok()?.trim().to_ascii_lowercase();
    matches!(name.as_str(), "identity" | "gzip" | "br").then_some(name)
}
pub(crate) fn accepts_coding(headers: &HeaderMap, coding: &str) -> bool {
    let mut qualities = BTreeMap::<String, u16>::new();
    for value in headers.get_all(ACCEPT_ENCODING) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        for item in value.split(',') {
            if item.trim().is_empty() {
                continue;
            }
            let mut fields = item.split(';');
            let name = fields.next().unwrap().trim().to_ascii_lowercase();
            let mut quality = 1000;
            let mut saw_quality = false;
            for field in fields {
                let Some((parameter, raw)) = field.trim().split_once('=') else {
                    return false;
                };
                if !parameter.eq_ignore_ascii_case("q") || saw_quality {
                    return false;
                }
                saw_quality = true;
                let raw = raw.trim();
                let (whole, fraction) = raw.split_once('.').unwrap_or((raw, ""));
                if !matches!(whole, "0" | "1")
                    || fraction.len() > 3
                    || !fraction.bytes().all(|v| v.is_ascii_digit())
                {
                    return false;
                }
                if whole == "1" {
                    if fraction.bytes().any(|v| v != b'0') {
                        return false;
                    }
                    quality = 1000;
                } else {
                    quality =
                        fraction.parse::<u16>().unwrap_or(0) * 10u16.pow(3 - fraction.len() as u32);
                }
            }
            if qualities.insert(name, quality).is_some() {
                return false;
            }
        }
    }
    if let Some(q) = qualities.get(coding) {
        return *q > 0;
    }
    if coding == "identity" {
        return qualities.get("*") != Some(&0);
    }
    qualities.get("*").is_some_and(|q| *q > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    #[test]
    fn selector_distinguishes_absent_empty_and_multiple_values() {
        let names = vec!["accept-language".into()];
        let absent = HeaderMap::new();
        let mut empty = HeaderMap::new();
        empty.insert("accept-language", "".parse().unwrap());
        let mut multi = HeaderMap::new();
        multi.append("accept-language", "en".parse().unwrap());
        multi.append("accept-language", "cs".parse().unwrap());
        let mut joined = HeaderMap::new();
        joined.insert("accept-language", "en,cs".parse().unwrap());
        assert_ne!(selector(&names, &absent), selector(&names, &empty));
        assert_ne!(selector(&names, &multi), selector(&names, &joined));
    }
    #[test]
    fn coding_quality_identity_is_not_an_unconditional_fallback() {
        let mut h = HeaderMap::new();
        h.insert(
            ACCEPT_ENCODING,
            "gzip;q=0, br, identity;q=0".parse().unwrap(),
        );
        assert!(!accepts_coding(&h, "identity"));
        assert!(!accepts_coding(&h, "gzip"));
        assert!(accepts_coding(&h, "br"));
    }
    #[tokio::test]
    async fn aborted_family_pressure_beyond_active_and_dormant_limits_preserves_pinned_pointer() {
        let directory = tempfile::tempdir().unwrap();
        let cache = super::super::CacheStore::new(directory.path().join("cache"));
        cache.configure_limits(1024 * 1024, 1024 * 1024);
        let base = "a".repeat(64);
        let request = HeaderMap::new();
        let mut headers = HeaderMap::new();
        let (key, _, _) = cache
            .variants
            .observe(
                &base,
                cache.variants.generation(&base),
                &request,
                &mut headers,
            )
            .unwrap();
        cache
            .put(
                &key,
                http::StatusCode::OK,
                &headers,
                bytes::Bytes::from_static(b"pin"),
                std::time::Duration::from_secs(120),
                1024 * 1024,
            )
            .await
            .unwrap();
        cache
            .pin(&key, &cache.snapshot(&key).await.unwrap())
            .await
            .unwrap();
        for number in 0..MAX_BASES * 2 + 1 {
            let other = format!("aborted-{number}");
            let token = cache.variants.generation(&other);
            cache
                .variants
                .observe(&other, token, &request, &mut HeaderMap::new())
                .unwrap();
        }
        {
            let state = cache.variants.state.lock().unwrap();
            assert_eq!(state.dormant.len(), 1);
            assert!(state.dormant.contains_key(&base));
        }
        assert_eq!(
            cache
                .variants
                .lookup(&base, &request, &request)
                .unwrap()
                .key,
            key
        );
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
            bytes::Bytes::from_static(b"pin")
        );
        let pins = cache.list_pins().await.unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].key, key);
    }
    #[tokio::test]
    async fn sixteen_unpublished_variants_allow_seventeenth_fill_and_preserve_pinned_selector() {
        let directory = tempfile::tempdir().unwrap();
        let cache = super::super::CacheStore::new(directory.path().join("cache"));
        cache.configure_limits(1024 * 1024, 1024 * 1024);
        let base = "a".repeat(64);
        let mut request = HeaderMap::new();
        request.insert("accept-language", "pinned".parse().unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(VARY, "accept-language".parse().unwrap());
        headers.insert(
            http::header::CACHE_CONTROL,
            "public, max-age=120".parse().unwrap(),
        );
        headers.insert(http::header::CONTENT_LENGTH, "3".parse().unwrap());
        let (pinned, _, _) = cache
            .variants
            .observe(
                &base,
                cache.variants.generation(&base),
                &request,
                &mut headers,
            )
            .unwrap();
        cache
            .put(
                &pinned,
                http::StatusCode::OK,
                &headers,
                bytes::Bytes::from_static(b"pin"),
                std::time::Duration::from_secs(120),
                1024 * 1024,
            )
            .await
            .unwrap();
        cache
            .pin(&pinned, &cache.snapshot(&pinned).await.unwrap())
            .await
            .unwrap();
        let mut pending = None;
        let mut retired = None;
        for number in 0..16 {
            cache.reclaim_unpublished_variants(&base);
            let token = cache.variants.generation(&base);
            let guard = cache.key_guard(&base).unwrap();
            assert!(cache.variants.bind_guard(&base, token, guard.clone()));
            request.insert(
                "accept-language",
                format!("failed-{number}").parse().unwrap(),
            );
            let mut response_headers = headers.clone();
            let (key, _, _) = cache
                .variants
                .observe(&base, token, &request, &mut response_headers)
                .unwrap();
            let fill = cache
                .begin_fill_guarded(
                    cache.epoch(),
                    &key,
                    http::StatusCode::OK,
                    &response_headers,
                    3,
                    std::time::Duration::from_secs(120),
                    std::time::Instant::now(),
                    1024 * 1024,
                    &guard,
                )
                .await
                .unwrap_or_else(|| {
                    panic!(
                        "fill {number} was rejected: base guard current={}, token={token}",
                        guard.is_current()
                    )
                });
            if number == 0 {
                pending = Some(fill.write(bytes::Bytes::from_static(b"old")).await.unwrap());
                retired = Some(guard);
            } else {
                drop(fill.write(bytes::Bytes::from_static(b"x")).await.unwrap());
            }
        }
        assert!(!retired.unwrap().is_current());
        assert!(!pending.unwrap().commit().await);
        cache.reclaim_unpublished_variants(&base);
        let token = cache.variants.generation(&base);
        let guard = cache.key_guard(&base).unwrap();
        assert!(cache.variants.bind_guard(&base, token, guard.clone()));
        request.insert("accept-language", "successful-17".parse().unwrap());
        let mut response_headers = headers;
        let (key, _, _) = cache
            .variants
            .observe(&base, token, &request, &mut response_headers)
            .unwrap();
        cache
            .put_at_epoch_guarded(
                cache.epoch(),
                &key,
                http::StatusCode::OK,
                &response_headers,
                bytes::Bytes::from_static(b"new"),
                std::time::Duration::from_secs(120),
                1024 * 1024,
                &guard,
            )
            .await
            .unwrap();
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
            bytes::Bytes::from_static(b"new")
        );
        request.insert("accept-language", "pinned".parse().unwrap());
        assert_eq!(
            cache
                .variants
                .lookup(&base, &request, &request)
                .unwrap()
                .key,
            pinned
        );
        assert_eq!(
            cache
                .get(&pinned)
                .await
                .unwrap()
                .body
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            bytes::Bytes::from_static(b"pin")
        );
        let pins = cache.list_pins().await.unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].key, pinned);
        let restarted = super::super::CacheStore::new(directory.path().join("cache"));
        restarted.hydrate_variants(&base).await;
        assert_eq!(
            restarted
                .variants
                .lookup(&base, &request, &request)
                .unwrap()
                .key,
            pinned
        );
        assert_eq!(restarted.list_pins().await.unwrap().len(), 1);
    }
    #[tokio::test]
    async fn authoritative_replacement_retires_old_writers_using_another_storage_key() {
        let directory = tempfile::tempdir().unwrap();
        let cache = super::super::CacheStore::new(directory.path().join("cache"));
        let base = "a".repeat(64);
        let request = HeaderMap::new();
        let token = cache.variants.generation(&base);
        let guard = cache.key_guard(&base).unwrap();
        assert!(cache.variants.bind_guard(&base, token, guard.clone()));
        let mut headers = HeaderMap::new();
        let (selected, _, _) = cache
            .variants
            .observe(&base, token, &request, &mut headers)
            .unwrap();
        cache
            .put(
                &selected,
                http::StatusCode::OK,
                &headers,
                bytes::Bytes::from_static(b"old"),
                std::time::Duration::from_secs(120),
                1024 * 1024,
            )
            .await
            .unwrap();
        let output = "b".repeat(64);
        let fill = cache
            .begin_fill_guarded(
                cache.epoch(),
                &output,
                http::StatusCode::OK,
                &headers,
                3,
                std::time::Duration::from_secs(120),
                std::time::Instant::now(),
                1024 * 1024,
                &guard,
            )
            .await
            .unwrap()
            .write(bytes::Bytes::from_static(b"old"))
            .await
            .unwrap();
        let mut successor = None;
        let (new_token, epoch) = cache
            .variants
            .retire_writers(&base, token, || {
                let (epoch, new_guard) = cache.invalidate_keys_and_request_at_epoch(
                    cache.epoch(),
                    std::slice::from_ref(&selected),
                    &guard,
                )?;
                successor = Some(new_guard);
                Some(epoch)
            })
            .unwrap();
        assert!(!guard.is_current());
        assert!(!fill.commit().await);
        assert!(cache.snapshot(&output).await.is_none());
        assert!(cache
            .variants
            .observe(&base, token, &request, &mut headers)
            .is_none());
        let successor = successor.unwrap();
        assert!(cache
            .variants
            .bind_guard(&base, new_token, successor.clone()));
        cache
            .put_at_epoch_guarded(
                epoch,
                &selected,
                http::StatusCode::OK,
                &headers,
                bytes::Bytes::from_static(b"new"),
                std::time::Duration::from_secs(120),
                1024 * 1024,
                &successor,
            )
            .await
            .unwrap();
        assert_eq!(
            cache
                .get(&selected)
                .await
                .unwrap()
                .body
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            bytes::Bytes::from_static(b"new")
        );
    }
    #[tokio::test]
    async fn clear_during_startup_scan_cannot_restore_old_disk_pointers() {
        let directory = tempfile::tempdir().unwrap();
        let seed = super::super::CacheStore::new(directory.path().join("cache"));
        let base = "a".repeat(64);
        let mut headers = HeaderMap::new();
        let (key, _, _) = seed
            .variants
            .observe(&base, 0, &HeaderMap::new(), &mut headers)
            .unwrap();
        seed.put(
            &key,
            http::StatusCode::OK,
            &headers,
            bytes::Bytes::from_static(b"abc"),
            std::time::Duration::from_secs(120),
            1024 * 1024,
        )
        .await
        .unwrap();
        let cache = super::super::CacheStore::new(directory.path().join("cache"));
        let reached = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        cache.variants.state.lock().unwrap().hydration_gate =
            Some((reached.clone(), resume.clone()));
        let task_cache = cache.clone();
        let task_base = base.clone();
        let scan = tokio::spawn(async move {
            task_cache.hydrate_variants(&task_base).await;
        });
        reached.notified().await;
        cache.clear().await.unwrap();
        resume.notify_one();
        scan.await.unwrap();
        assert!(cache
            .variants
            .lookup(&base, &HeaderMap::new(), &HeaderMap::new())
            .is_none());
        assert!(cache.variants.state.lock().unwrap().families.is_empty());
        assert!(!cache.variants.state.lock().unwrap().hydrated);
        cache.hydrate_variants(&base).await;
        assert_eq!(cache.variants.scan_counts(), (2, 1));
        assert!(cache.snapshot(&key).await.is_none());
    }
    #[tokio::test]
    async fn lru_eviction_fences_final_fill_publication_and_preserves_disk_generation() {
        let directory = tempfile::tempdir().unwrap();
        let cache = super::super::CacheStore::new(directory.path().join("cache"));
        let index = &cache.variants;
        let base = "a".repeat(64);
        let request = HeaderMap::new();
        let initial_token = index.generation(&base);
        let guard = cache.key_guard(&base).unwrap();
        assert!(index.bind_guard(&base, initial_token, guard.clone()));
        let mut headers = HeaderMap::new();
        headers.insert(VARY, "accept".parse().unwrap());
        let (key, _, token) = index
            .observe(&base, initial_token, &request, &mut headers)
            .unwrap();
        cache
            .put(
                &key,
                http::StatusCode::OK,
                &headers,
                bytes::Bytes::from_static(b"abc"),
                std::time::Duration::from_secs(120),
                1024 * 1024,
            )
            .await
            .unwrap();
        let fill = cache
            .begin_fill(
                cache.epoch(),
                &key,
                http::StatusCode::OK,
                &headers,
                3,
                std::time::Duration::from_secs(120),
                std::time::Instant::now(),
                1024 * 1024,
            )
            .await
            .unwrap()
            .with_key_guard(guard.clone());
        let fill = fill.write(bytes::Bytes::from_static(b"abc")).await.unwrap();
        // Fill the active LRU with nonempty families so the original family is
        // evicted into the bounded dormant metadata catalog.
        for number in 0..MAX_BASES {
            let other = format!("other-{number}");
            let token = index.generation(&other);
            index
                .observe(&other, token, &request, &mut HeaderMap::new())
                .unwrap();
        }
        assert!(!guard.is_current());
        assert!(!fill.commit().await);
        assert!(directory
            .path()
            .join("cache")
            .join(format!("{key}.json"))
            .exists());
        assert!(index
            .observe(&base, token, &request, &mut headers)
            .is_none());
        let restored = index.lookup(&base, &request, &request).unwrap();
        assert_eq!(restored.key, key);
        assert!(restored.verifies(&headers));
        assert_ne!(index.generation(&base), token);
        let current_token = index.generation(&base);
        let mut changed = HeaderMap::new();
        changed.insert(VARY, "accept-language".parse().unwrap());
        let (_, invalidated, _) = index
            .observe(&base, current_token, &request, &mut changed)
            .unwrap();
        assert_eq!(invalidated, vec![key]);
        assert_eq!(changed.get(GENERATION).unwrap(), "1");
        let state = index.state.lock().unwrap();
        assert!(state.families.len() <= MAX_BASES);
        assert!(state.dormant.len() <= MAX_BASES);
    }
    #[test]
    fn empty_family_pressure_preserves_cached_candidates_and_rejects_evicted_responses() {
        let index = VariantIndex::default();
        let request = HeaderMap::new();
        let (key, _, _) = index
            .observe("cached", 0, &request, &mut HeaderMap::new())
            .unwrap();
        let retired = index.generation("empty-0");
        for number in 1..=MAX_BASES + 1 {
            index.generation(&format!("empty-{number}"));
        }
        assert_eq!(index.lookup("cached", &request, &request).unwrap().key, key);
        assert!(index
            .observe("empty-0", retired, &request, &mut HeaderMap::new())
            .is_none());
        let fresh = index.generation("new-public");
        assert!(index
            .observe("new-public", fresh, &request, &mut HeaderMap::new())
            .is_some());
        assert_eq!(index.state.lock().unwrap().families.len(), MAX_BASES);
    }
    #[test]
    fn rejected_family_invalidation_guards_epoch_and_generation_and_rejects_restoration() {
        let index = VariantIndex::default();
        let mut en = HeaderMap::new();
        en.insert("accept-language", "en".parse().unwrap());
        let mut cs = HeaderMap::new();
        cs.insert("accept-language", "cs".parse().unwrap());
        let mut first = HeaderMap::new();
        first.insert(VARY, "accept-language".parse().unwrap());
        let (en_key, _, _) = index.observe("base", 0, &en, &mut first).unwrap();
        let mut second = HeaderMap::new();
        second.insert(VARY, "accept-language".parse().unwrap());
        let (cs_key, _, _) = index.observe("base", 0, &cs, &mut second).unwrap();

        assert!(index
            .invalidate_family("base", 0, &en_key, |_| None)
            .is_none());
        assert_eq!(index.generation("base"), 0);
        assert_eq!(index.lookup("base", &cs, &cs).unwrap().key, cs_key);
        let (generation, epoch, keys) = index
            .invalidate_family("base", 0, "legacy-key", |keys| {
                assert_eq!(keys, &[en_key.clone(), cs_key.clone(), "legacy-key".into()]);
                Some(7)
            })
            .unwrap();
        assert_eq!((generation, epoch), (1, 7));
        assert_eq!(keys.len(), 3);
        assert!(index.lookup("base", &en, &en).is_none());
        assert!(index.lookup("base", &cs, &cs).is_none());
        index.restore("base", &cs_key, &second);
        assert!(index.lookup("base", &cs, &cs).is_none());
        assert!(index.observe("base", 0, &en, &mut first).is_none());

        let mut replacement = HeaderMap::new();
        replacement.insert(VARY, "accept".parse().unwrap());
        let (new_key, old_keys, _) = index
            .observe("base", generation, &en, &mut replacement)
            .unwrap();
        assert!(old_keys.is_empty());
        assert!(index
            .invalidate_family("base", 0, &en_key, |_| panic!(
                "stale invalidation reached disk"
            ))
            .is_none());
        assert_eq!(index.lookup("base", &en, &en).unwrap().key, new_key);
    }
    #[test]
    fn vary_change_rejects_late_fills_and_invalidates_family() {
        let index = VariantIndex::default();
        let request = HeaderMap::new();
        let mut first = HeaderMap::new();
        first.insert(VARY, "accept".parse().unwrap());
        let (key, _, _) = index.observe("base", 0, &request, &mut first).unwrap();
        let mut changed = HeaderMap::new();
        changed.insert(VARY, "accept-language".parse().unwrap());
        assert!(index
            .observe_with_invalidation("base", 0, &request, &mut changed, |keys| {
                assert_eq!(keys, std::slice::from_ref(&key));
                false
            })
            .is_none());
        assert_eq!(index.generation("base"), 0);
        assert_eq!(index.lookup("base", &request, &request).unwrap().key, key);
        let (_, invalid, _) = index.observe("base", 0, &request, &mut changed).unwrap();
        assert_eq!(invalid, vec![key]);
        assert!(index.observe("base", 0, &request, &mut first).is_none());
    }
}
