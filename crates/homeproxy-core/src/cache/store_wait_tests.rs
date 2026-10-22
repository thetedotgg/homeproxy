//! Store admission under writer contention: a parallel page load must not turn
//! most cacheable responses into `cache-write-failed`, while a writer that holds
//! the exclusive lease too long still yields a bounded bypass.
use super::*;
use http_body_util::BodyExt;

const PARALLEL: usize = 24;
const LIMIT: u64 = 16 * 1024 * 1024;
const BODY: usize = 4096;

fn key(seed: &str) -> String {
    hex::encode(Sha256::digest(seed.as_bytes()))
}

fn keys(prefix: &str) -> Vec<String> {
    (0..PARALLEL)
        .map(|index| key(&format!("{prefix}-{index}")))
        .collect()
}

fn public_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "cache-control",
        HeaderValue::from_static("public, max-age=60"),
    );
    headers
}

async fn buffered_round(cache: &CacheStore, prefix: &str) -> Vec<(usize, std::io::ErrorKind)> {
    let keys = keys(prefix);
    let start = Arc::new(tokio::sync::Barrier::new(PARALLEL));
    let tasks = keys
        .iter()
        .cloned()
        .map(|entry| {
            let cache = cache.clone();
            let start = start.clone();
            tokio::spawn(async move {
                start.wait().await;
                cache
                    .put(
                        &entry,
                        StatusCode::OK,
                        &public_headers(),
                        Bytes::from(vec![b'a'; BODY]),
                        Duration::from_secs(60),
                        LIMIT,
                    )
                    .await
            })
        })
        .collect::<Vec<_>>();
    let mut failures = Vec::new();
    for (index, task) in tasks.into_iter().enumerate() {
        if let Err(error) = task.await.unwrap() {
            failures.push((index, error.kind()));
        }
    }
    if failures.is_empty() {
        for entry in &keys {
            let hit = cache.get(entry).await.expect("stored response is a HIT");
            assert_eq!(hit.body.collect().await.unwrap().to_bytes().len(), BODY);
        }
    }
    failures
}

async fn streaming_round(cache: &CacheStore, prefix: &str) -> Vec<(usize, &'static str)> {
    let keys = keys(prefix);
    let start = Arc::new(tokio::sync::Barrier::new(PARALLEL));
    let tasks = keys
        .iter()
        .cloned()
        .map(|entry| {
            let cache = cache.clone();
            let start = start.clone();
            tokio::spawn(async move {
                start.wait().await;
                let Some(fill) = cache
                    .begin_fill(
                        cache.epoch(),
                        &entry,
                        StatusCode::OK,
                        &public_headers(),
                        BODY as u64,
                        Duration::from_secs(60),
                        Instant::now(),
                        LIMIT,
                    )
                    .await
                else {
                    return Err("admission");
                };
                let fill = fill
                    .write(Bytes::from(vec![b'b'; BODY]))
                    .await
                    .ok_or("write")?;
                fill.commit().await.then_some(()).ok_or("commit")
            })
        })
        .collect::<Vec<_>>();
    let mut failures = Vec::new();
    for (index, task) in tasks.into_iter().enumerate() {
        if let Err(stage) = task.await.unwrap() {
            failures.push((index, stage));
        }
    }
    if failures.is_empty() {
        for entry in &keys {
            let hit = cache.get(entry).await.expect("committed fill is a HIT");
            assert_eq!(hit.body.collect().await.unwrap().to_bytes().len(), BODY);
        }
        assert!(cache.state.lock().unwrap().reservations.is_empty());
    }
    failures
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_page_load_stores_every_buffered_response() {
    let dir = tempfile::tempdir().unwrap();
    let cache = CacheStore::new(dir.path().into());
    // Confirmed limits leave maintenance pending, as after startup or a settings change.
    cache.configure_limits(LIMIT, MAX_CACHE_ITEM_BYTES);
    let pending = buffered_round(&cache, "maintenance-pending").await;
    assert!(!cache.state.lock().unwrap().pending_prune);
    // Second burst: nothing pending, only contention for the exclusive lease.
    let contended = buffered_round(&cache, "lease-contention").await;
    assert!(
        pending.is_empty() && contended.is_empty(),
        "parallel stores failed: {}/{PARALLEL} with maintenance pending {pending:?}, \
         {}/{PARALLEL} on lease contention {contended:?}",
        pending.len(),
        contended.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_page_load_admits_and_commits_every_streaming_fill() {
    let dir = tempfile::tempdir().unwrap();
    let cache = CacheStore::new(dir.path().into());
    cache.configure_limits(LIMIT, MAX_CACHE_ITEM_BYTES);
    let pending = streaming_round(&cache, "maintenance-pending").await;
    assert!(!cache.state.lock().unwrap().pending_prune);
    // Second burst: nothing pending, only contention for the exclusive lease.
    let contended = streaming_round(&cache, "lease-contention").await;
    assert!(
        pending.is_empty() && contended.is_empty(),
        "parallel fills failed: {}/{PARALLEL} with maintenance pending {pending:?}, \
         {}/{PARALLEL} on lease contention {contended:?}",
        pending.len(),
        contended.len()
    );
}

fn assert_gave_up_at_the_cap(started: tokio::time::Instant) {
    let waited = started.elapsed();
    assert!(
        waited >= CACHE_STORE_WAIT && waited < CACHE_STORE_WAIT + Duration::from_millis(10),
        "store admission waited {waited:?}, expected the {CACHE_STORE_WAIT:?} cap"
    );
}

#[tokio::test(start_paused = true)]
async fn writer_held_past_the_cap_yields_a_bounded_bypass() {
    let dir = tempfile::tempdir().unwrap();
    let cache = CacheStore::new(dir.path().into());
    let existing = key("refresh-target");
    cache
        .put(
            &existing,
            StatusCode::OK,
            &public_headers(),
            Bytes::from_static(b"cached"),
            Duration::from_secs(60),
            LIMIT,
        )
        .await
        .unwrap();
    let snapshot = cache.snapshot(&existing).await.unwrap();
    let writer = cache.io_lock.clone().write_owned().await;

    let started = tokio::time::Instant::now();
    let error = cache
        .put(
            &key("blocked-put"),
            StatusCode::OK,
            &public_headers(),
            Bytes::from_static(b"blocked"),
            Duration::from_secs(60),
            LIMIT,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    assert_gave_up_at_the_cap(started);

    let started = tokio::time::Instant::now();
    assert!(cache
        .begin_fill(
            cache.epoch(),
            &key("blocked-fill"),
            StatusCode::OK,
            &public_headers(),
            7,
            Duration::from_secs(60),
            Instant::now(),
            LIMIT,
        )
        .await
        .is_none());
    assert_gave_up_at_the_cap(started);

    let started = tokio::time::Instant::now();
    assert!(
        !cache
            .refresh(
                &existing,
                &snapshot,
                &public_headers(),
                Duration::from_secs(60)
            )
            .await
    );
    assert_gave_up_at_the_cap(started);
    assert!(CACHE_STORE_WAIT < CACHE_IO_WAIT);

    // Best-effort paths used before HIT lookups and cleanups never queue.
    cache.configure_limits(LIMIT, MAX_CACHE_ITEM_BYTES);
    let started = tokio::time::Instant::now();
    assert_eq!(
        cache.maintain().await.unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    cache.invalidate_key(&existing);
    assert_eq!(
        cache
            .remove_invalidated(&existing)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(started.elapsed() < Duration::from_millis(1));

    drop(writer);
    assert!(cache.get(&key("blocked-put")).await.is_none());
    assert!(cache.state.lock().unwrap().reservations.is_empty());
    cache.maintain().await.unwrap();
    cache.remove_invalidated(&existing).await.unwrap();
}

#[tokio::test]
async fn store_waiting_for_a_short_writer_publishes_after_release() {
    let dir = tempfile::tempdir().unwrap();
    let cache = CacheStore::new(dir.path().into());
    let existing = key("short-refresh");
    cache
        .put(
            &existing,
            StatusCode::OK,
            &public_headers(),
            Bytes::from_static(b"cached"),
            Duration::ZERO,
            LIMIT,
        )
        .await
        .unwrap();
    let snapshot = cache.snapshot(&existing).await.unwrap();
    let stored = key("short-put");
    let filled = key("short-fill");
    // Pending maintenance without an epoch change (configure_limits would retire the snapshot).
    cache.state.lock().unwrap().pending_prune = true;
    let writer = cache.io_lock.clone().write_owned().await;
    let putting = {
        let cache = cache.clone();
        let stored = stored.clone();
        tokio::spawn(async move {
            cache
                .put(
                    &stored,
                    StatusCode::OK,
                    &public_headers(),
                    Bytes::from_static(b"stored"),
                    Duration::from_secs(60),
                    LIMIT,
                )
                .await
        })
    };
    let filling = {
        let cache = cache.clone();
        let filled = filled.clone();
        tokio::spawn(async move {
            cache
                .begin_fill(
                    cache.epoch(),
                    &filled,
                    StatusCode::OK,
                    &public_headers(),
                    6,
                    Duration::from_secs(60),
                    Instant::now(),
                    LIMIT,
                )
                .await?
                .write(Bytes::from_static(b"filled"))
                .await?
                .commit()
                .await
                .then_some(())
        })
    };
    let refreshing = {
        let cache = cache.clone();
        let existing = existing.clone();
        tokio::spawn(async move {
            cache
                .refresh(
                    &existing,
                    &snapshot,
                    &public_headers(),
                    Duration::from_secs(60),
                )
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!putting.is_finished() && !filling.is_finished() && !refreshing.is_finished());
    drop(writer);
    putting.await.unwrap().unwrap();
    assert!(filling.await.unwrap().is_some());
    assert!(refreshing.await.unwrap());
    assert!(cache.get(&stored).await.is_some());
    assert!(cache.get(&filled).await.is_some());
    assert!(
        cache.get(&existing).await.is_some(),
        "refresh made it fresh"
    );
    assert!(!cache.state.lock().unwrap().pending_prune);
}

#[tokio::test]
async fn invalidation_while_waiting_for_the_lease_still_fences_publication() {
    let dir = tempfile::tempdir().unwrap();
    let cache = CacheStore::new(dir.path().into());
    let stored = key("fenced-put");
    let filled = key("fenced-fill");
    let writer = cache.io_lock.clone().write_owned().await;
    let epoch = cache.epoch();
    let putting = {
        let cache = cache.clone();
        let stored = stored.clone();
        tokio::spawn(async move {
            cache
                .put_at_epoch(
                    epoch,
                    &stored,
                    StatusCode::OK,
                    &public_headers(),
                    Bytes::from_static(b"old"),
                    Duration::from_secs(60),
                    LIMIT,
                )
                .await
        })
    };
    let filling = {
        let cache = cache.clone();
        let filled = filled.clone();
        tokio::spawn(async move {
            cache
                .begin_fill(
                    epoch,
                    &filled,
                    StatusCode::OK,
                    &public_headers(),
                    3,
                    Duration::from_secs(60),
                    Instant::now(),
                    LIMIT,
                )
                .await
                .is_some()
        })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    cache.invalidate();
    drop(writer);
    assert_eq!(
        putting.await.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(!filling.await.unwrap());
    assert!(cache.get(&stored).await.is_none());
    assert!(cache.state.lock().unwrap().reservations.is_empty());
    assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".cache-tmp-")));
}
