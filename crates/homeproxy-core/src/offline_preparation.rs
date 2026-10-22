//! Bounded privileged jobs. Only redacted labels and cache references persist;
//! no credentials, query strings, or automatic network resumption after restart.
use crate::{
    cache::CacheStore,
    proxy::prefetch::{self, PrefetchExecutor},
    Settings,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub const MAX_PREPARATION_URLS: usize = 32;
const MAX_JOBS: usize = 8;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_LABEL_BYTES: usize = 320;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfflinePreparationRequest {
    pub urls: Vec<String>,
    pub budget_mib: u32,
    pub pin: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("offline-preparation:{code}")]
pub struct OfflinePreparationError {
    pub code: String,
}
impl OfflinePreparationError {
    fn new(code: &str) -> Self {
        Self { code: code.into() }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedItem {
    pub label: String,
    pub host: String,
    pub scheme: String,
    pub state: String,
    pub received_bytes: u64,
    pub stored_bytes: u64,
    pub cache_key: Option<String>,
    pub pinned: bool,
    #[serde(default)]
    pub offline_ready: bool,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparationJob {
    pub id: String,
    pub state: String,
    pub created_unix_seconds: u64,
    pub budget_bytes: u64,
    pub received_bytes: u64,
    #[serde(default)]
    pub budget_used_bytes: u64,
    pub pin_requested: bool,
    pub items: Vec<PreparedItem>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflinePreparationStatus {
    pub jobs: Vec<PreparationJob>,
    pub active_job: Option<String>,
    pub max_urls: usize,
    pub max_jobs: usize,
    pub pin_usage: serde_json::Value,
    pub error_code: Option<String>,
    pub pins: Vec<PreparedPin>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedPin {
    pub key: String,
    pub label: String,
    pub bytes: u64,
    pub offline_ready: bool,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    next_id: u64,
    jobs: Vec<PreparationJob>,
}
struct State {
    document: Document,
    active: Option<(String, CancellationToken, CacheStore)>,
    error: Option<String>,
}

#[derive(Clone)]
pub(crate) struct OfflinePreparation {
    path: PathBuf,
    state: Arc<Mutex<State>>,
}

impl OfflinePreparation {
    pub(crate) fn new(path: PathBuf) -> Self {
        let loaded = load(&path);
        let (mut document, error) = match loaded {
            Ok(document) => (document, None),
            Err(_) => (
                Document {
                    version: 1,
                    ..Default::default()
                },
                Some("manifest-invalid".into()),
            ),
        };
        for job in &mut document.jobs {
            if matches!(job.state.as_str(), "queued" | "running") {
                job.state = "cancelled".into();
                for item in &mut job.items {
                    if matches!(item.state.as_str(), "queued" | "running") {
                        item.state = "cancelled".into();
                        item.error_code = Some("interrupted".into());
                    }
                }
            }
        }
        Self {
            path,
            state: Arc::new(Mutex::new(State {
                document,
                active: None,
                error,
            })),
        }
    }

    pub(crate) async fn queue(
        &self,
        request: OfflinePreparationRequest,
        executor: PrefetchExecutor,
        cache: CacheStore,
    ) -> Result<String, OfflinePreparationError> {
        if request.urls.is_empty()
            || request.urls.len() > MAX_PREPARATION_URLS
            || !(1..=1024).contains(&request.budget_mib)
        {
            return Err(OfflinePreparationError::new("invalid-input"));
        }
        let mut seen = HashSet::new();
        let mut items = Vec::new();
        for value in &request.urls {
            let uri = executor
                .check_url(value)
                .map_err(|e| OfflinePreparationError::new(e.code))?;
            if !seen.insert(value.clone()) {
                return Err(OfflinePreparationError::new("duplicate-url"));
            }
            let host = uri.host().unwrap_or_default().to_ascii_lowercase();
            items.push(PreparedItem {
                label: bounded_label(&uri),
                host,
                scheme: uri.scheme_str().unwrap().into(),
                state: "queued".into(),
                received_bytes: 0,
                stored_bytes: 0,
                cache_key: None,
                pinned: false,
                offline_ready: false,
                error_code: None,
            });
        }
        let budget = u64::from(request.budget_mib) * 1024 * 1024;
        if request.pin {
            let usage = cache.pin_usage().await;
            if usage.degraded || budget > usage.limit_bytes.saturating_sub(usage.used_bytes) {
                return Err(OfflinePreparationError::new("pin-quota"));
            }
        }
        let mut state = self.state.lock().await;
        if state.error.is_some() {
            return Err(OfflinePreparationError::new("manifest-invalid"));
        }
        if state.active.is_some() {
            return Err(OfflinePreparationError::new("job-active"));
        }
        if state.document.jobs.len() >= MAX_JOBS {
            state.document.jobs.remove(0);
        }
        state.document.next_id = state.document.next_id.wrapping_add(1);
        let id = format!("offline-{}-{}", now(), state.document.next_id);
        let token = CancellationToken::new();
        state.document.jobs.push(PreparationJob {
            id: id.clone(),
            state: "queued".into(),
            created_unix_seconds: now(),
            budget_bytes: budget,
            received_bytes: 0,
            budget_used_bytes: 0,
            pin_requested: request.pin,
            items,
        });
        if self.save(&state.document).await.is_err() {
            state.document.jobs.pop();
            state.error = Some("manifest-write-failed".into());
            return Err(OfflinePreparationError::new("manifest-write-failed"));
        }
        state.active = Some((id.clone(), token.clone(), cache.clone()));
        let manager = self.clone();
        let task_id = id.clone();
        tokio::spawn(async move {
            manager
                .run(task_id, request.urls, executor, cache, token)
                .await;
        });
        Ok(id)
    }

    async fn run(
        &self,
        id: String,
        urls: Vec<String>,
        executor: PrefetchExecutor,
        cache: CacheStore,
        token: CancellationToken,
    ) {
        for (index, url) in urls.into_iter().enumerate() {
            let remaining = {
                let mut state = self.state.lock().await;
                if token.is_cancelled()
                    || state
                        .active
                        .as_ref()
                        .is_none_or(|(active, _, _)| active != &id)
                {
                    break;
                }
                let job = state
                    .document
                    .jobs
                    .iter_mut()
                    .find(|job| job.id == id)
                    .unwrap();
                job.state = "running".into();
                job.items[index].state = "running".into();
                let remaining = job.budget_bytes.saturating_sub(job.budget_used_bytes);
                if self.save(&state.document).await.is_err() {
                    state.error = Some("manifest-write-failed".into());
                    token.cancel();
                    break;
                }
                remaining
            };
            let result = executor.fetch(&url, remaining, token.clone()).await;
            let mut state = self.state.lock().await;
            if state
                .active
                .as_ref()
                .is_none_or(|(active, _, _)| active != &id)
            {
                break;
            }
            let job = state
                .document
                .jobs
                .iter_mut()
                .find(|job| job.id == id)
                .unwrap();
            let item = &mut job.items[index];
            match result {
                Ok(prepared) if !token.is_cancelled() => {
                    job.received_bytes = job.received_bytes.saturating_add(prepared.received_bytes);
                    job.budget_used_bytes = job
                        .budget_used_bytes
                        .saturating_add(prepared.received_bytes);
                    item.received_bytes = prepared.received_bytes;
                    item.stored_bytes = prepared.snapshot.body_length;
                    item.cache_key = Some(prepared.key.clone());
                    item.state = "stored".into();
                    if job.pin_requested {
                        match cache.pin(&prepared.key, &prepared.snapshot).await {
                            Ok(_) => item.pinned = true,
                            Err(_) => {
                                item.error_code = Some("pin-failed".into());
                                item.state = "failed".into();
                            }
                        }
                    }
                }
                Ok(prepared) => {
                    job.received_bytes = job.received_bytes.saturating_add(prepared.received_bytes);
                    job.budget_used_bytes = job
                        .budget_used_bytes
                        .saturating_add(prepared.received_bytes);
                    item.received_bytes = prepared.received_bytes;
                    item.state = "cancelled".into();
                    item.error_code = Some("cancelled".into());
                }
                Err(mut error) => {
                    // Cancellation may also finish a body with an error. Report the
                    // explicit user cancellation consistently instead of a failed job.
                    if token.is_cancelled() {
                        error.code = "cancelled";
                    }
                    job.received_bytes = job.received_bytes.saturating_add(error.received_bytes);
                    job.budget_used_bytes = job
                        .budget_used_bytes
                        .saturating_add(error.budget_used_bytes);
                    item.received_bytes = error.received_bytes;
                    item.state =
                        if matches!(error.code, "cancelled" | "proxy-stopped" | "offline-mode") {
                            "cancelled"
                        } else {
                            "failed"
                        }
                        .into();
                    item.error_code = Some(error.code.into());
                }
            }
            if self.save(&state.document).await.is_err() {
                state.error = Some("manifest-write-failed".into());
                token.cancel();
            }
        }
        let mut state = self.state.lock().await;
        if state
            .active
            .as_ref()
            .is_some_and(|(active, _, _)| active == &id)
        {
            if let Some(job) = state.document.jobs.iter_mut().find(|job| job.id == id) {
                for item in &mut job.items {
                    if matches!(item.state.as_str(), "queued" | "running") {
                        item.state = "cancelled".into();
                        item.error_code = Some("cancelled".into());
                    }
                }
                job.state = if job.items.iter().any(|item| item.state == "cancelled") {
                    "cancelled"
                } else if job.items.iter().any(|item| item.state == "failed") {
                    "failed"
                } else {
                    "completed"
                }
                .into();
            }
            state.active = None;
            if self.save(&state.document).await.is_err() {
                state.error = Some("manifest-write-failed".into());
            }
        }
    }

    pub(crate) async fn cancel(&self, id: &str) -> Result<(), OfflinePreparationError> {
        let state = self.state.lock().await;
        match &state.active {
            Some((active, token, cache)) if active == id => {
                cache.cancel_fill(token);
                Ok(())
            }
            _ => Err(OfflinePreparationError::new("job-not-active")),
        }
    }

    pub(crate) async fn clear(&self) -> Result<(), OfflinePreparationError> {
        let mut state = self.state.lock().await;
        if let Some((_, token, cache)) = state.active.take() {
            cache.cancel_fill(&token);
        }
        state.document.jobs.clear();
        state.error = None;
        self.save(&state.document)
            .await
            .map_err(|_| OfflinePreparationError::new("manifest-write-failed"))
    }

    pub(crate) async fn status(
        &self,
        cache: &CacheStore,
        settings: &Settings,
    ) -> OfflinePreparationStatus {
        let state = self.state.lock().await;
        let mut jobs = state.document.jobs.clone();
        let active_job = state.active.as_ref().map(|(id, _, _)| id.clone());
        let error_code = state.error.clone();
        drop(state);
        let pins = cache.list_pins().await.unwrap_or_default();
        let pinned = pins
            .iter()
            .map(|pin| pin.key.as_str())
            .collect::<HashSet<_>>();
        for job in &mut jobs {
            for item in &mut job.items {
                item.offline_ready = false;
                item.pinned = item
                    .cache_key
                    .as_deref()
                    .is_some_and(|key| pinned.contains(key));
                if let Some(key) = &item.cache_key {
                    if let Some(snapshot) = cache.status_snapshot(key).await {
                        if crate::cache::variants::schema(&snapshot.headers)
                            .is_some_and(|schema| !schema.is_empty())
                            && item.error_code.is_none()
                        {
                            item.error_code = Some("variant-not-prepared".into());
                        }
                        item.offline_ready =
                            prefetch::offline_ready(&snapshot, settings, &item.host)
                                && (item.scheme != "https"
                                    || crate::https_policy::host_is_inspected(
                                        settings, &item.host,
                                    ));
                    }
                }
            }
        }
        let pins = pins
            .into_iter()
            .map(|pin| {
                let item = jobs
                    .iter()
                    .flat_map(|job| &job.items)
                    .find(|item| item.cache_key.as_ref() == Some(&pin.key));
                PreparedPin {
                    label: item
                        .map(|item| item.label.clone())
                        .unwrap_or_else(|| format!("Cache {}", &pin.key[..12])),
                    offline_ready: item.is_some_and(|item| item.offline_ready),
                    key: pin.key,
                    bytes: pin.body_length,
                }
            })
            .collect();
        OfflinePreparationStatus {
            jobs,
            active_job,
            max_urls: MAX_PREPARATION_URLS,
            max_jobs: MAX_JOBS,
            pin_usage: serde_json::to_value(cache.pin_usage().await)
                .unwrap_or(serde_json::Value::Null),
            error_code,
            pins,
        }
    }

    async fn save(&self, document: &Document) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(document).map_err(std::io::Error::other)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(std::io::Error::other("offline manifest too large"));
        }
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let parent = path
                .parent()
                .ok_or_else(|| std::io::Error::other("missing manifest directory"))?;
            let mut file = tempfile::NamedTempFile::new_in(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.as_file()
                    .set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            file.write_all(&bytes)?;
            file.as_file_mut().sync_all()?;
            file.persist(path).map_err(|e| e.error)?;
            Ok(())
        })
        .await
        .map_err(std::io::Error::other)?
    }
}

fn load(path: &PathBuf) -> std::io::Result<Document> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Document {
                version: 1,
                ..Default::default()
            })
        }
        Err(e) => return Err(e),
    };
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(std::io::Error::other("invalid manifest"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::other("unsafe manifest"));
        }
    }
    let document: Document =
        serde_json::from_slice(&fs::read(path)?).map_err(std::io::Error::other)?;
    if document.version != 1
        || document.jobs.len() > MAX_JOBS
        || document.jobs.iter().any(|job| {
            job.items.len() > MAX_PREPARATION_URLS
                || job.id.len() > 128
                || job.items.iter().any(|item| {
                    item.label.len() > 4096
                        || item.label.contains('?')
                        || item.host.len() > 253
                        || item.cache_key.as_ref().is_some_and(|key| {
                            key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                })
        })
    {
        return Err(std::io::Error::other("invalid manifest"));
    }
    Ok(document)
}
// URL admission permits ASCII only, so truncation cannot split a code point.
fn bounded_label(uri: &http::Uri) -> String {
    let mut label = format!(
        "{}://{}{}",
        uri.scheme_str().unwrap_or_default(),
        uri.authority().unwrap(),
        uri.path()
    );
    if label.len() > MAX_LABEL_BYTES {
        label.truncate(MAX_LABEL_BYTES - 3);
        label.push_str("...");
    }
    label
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod bounds_tests {
    use super::*;
    #[test]
    fn longest_admitted_urls_keep_all_retained_job_labels_within_manifest_budget() {
        let uri: http::Uri = format!("https://{}/{}", "a".repeat(250), "x".repeat(3800))
            .parse()
            .unwrap();
        let label = bounded_label(&uri);
        assert_eq!(label.len(), MAX_LABEL_BYTES);
        assert!(label.ends_with("..."));
        let job = PreparationJob {
            id: "offline-10000000000-10000000000".into(),
            state: "completed".into(),
            created_unix_seconds: u64::MAX,
            budget_bytes: u64::MAX,
            received_bytes: u64::MAX,
            budget_used_bytes: u64::MAX,
            pin_requested: true,
            items: (0..MAX_PREPARATION_URLS)
                .map(|_| PreparedItem {
                    label: label.clone(),
                    host: "a".repeat(253),
                    scheme: "https".into(),
                    state: "stored".into(),
                    received_bytes: u64::MAX,
                    stored_bytes: u64::MAX,
                    cache_key: Some("a".repeat(64)),
                    pinned: true,
                    offline_ready: true,
                    error_code: Some("response-not-cacheable".into()),
                })
                .collect(),
        };
        let document = Document {
            version: 1,
            next_id: u64::MAX,
            jobs: vec![job; MAX_JOBS],
        };
        assert!(serde_json::to_vec(&document).unwrap().len() as u64 <= MAX_MANIFEST_BYTES);
    }
}
