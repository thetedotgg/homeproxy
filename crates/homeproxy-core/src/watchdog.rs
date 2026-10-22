//! Conservative loopback-only observer. Network timeouts never wrap runtime transitions.
use crate::{
    diagnostics::{epoch_ms, HealthState, IncidentReason, Metrics, ProbeResult, RuntimeConfig},
    proxy::{start_proxy, ProxyHandle},
    Engine, RuntimePublication,
};
use std::{
    collections::BTreeSet,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Evidence {
    FreeCapacity(u64),
    OverAge(BTreeSet<u64>),
}
fn evidence(metrics: &Metrics) -> Option<Evidence> {
    if !metrics.consistent() {
        return None;
    }
    if metrics.active_connections < 256 && metrics.loopback_connections < 128 {
        Some(Evidence::FreeCapacity(metrics.rejected_connections))
    } else if metrics.active_connections == 256 && !metrics.over_age_ids.is_empty() {
        Some(Evidence::OverAge(metrics.over_age_ids.clone()))
    } else {
        None
    }
}
fn intersect(previous: &Evidence, next: &Evidence) -> Option<Evidence> {
    match (previous, next) {
        (Evidence::FreeCapacity(a), Evidence::FreeCapacity(b)) if a == b => {
            Some(Evidence::FreeCapacity(*a))
        }
        (Evidence::OverAge(a), Evidence::OverAge(b)) => {
            let ids = a.intersection(b).copied().collect::<BTreeSet<_>>();
            (!ids.is_empty()).then_some(Evidence::OverAge(ids))
        }
        _ => None,
    }
}
#[derive(Default)]
struct Failures {
    generation: Option<u64>,
    consecutive: u8,
    proven: u8,
    evidence: Option<Evidence>,
    reported: bool,
}
impl Failures {
    async fn ensure_reported(
        &mut self,
        diagnostics: &crate::diagnostics::Diagnostics,
        generation: u64,
    ) -> bool {
        if !self.reported || !diagnostics.incident_acknowledged_for(generation) {
            let reason = if matches!(self.evidence, Some(Evidence::OverAge(_))) {
                IncidentReason::OverAgeIdleCapacity
            } else {
                IncidentReason::LocalProbeFailures
            };
            // Cached reporting must not prevent recapture after retention invalidates
            // the durable proof. A timed-out observer still leaves the writer owning it.
            self.reported = diagnostics.incident(reason).await
                && diagnostics.incident_acknowledged_for(generation);
        }
        self.reported
    }
    fn reset(&mut self, generation: u64) {
        *self = Self {
            generation: Some(generation),
            ..Self::default()
        };
    }
    fn failed(&mut self, generation: u64, before: &Metrics, after: &Metrics) {
        if self.generation != Some(generation) {
            self.reset(generation);
        }
        self.consecutive = self.consecutive.saturating_add(1);
        let next = evidence(before).and_then(|a| evidence(after).and_then(|b| intersect(&a, &b)));
        match (&self.evidence, next) {
            (Some(old), Some(next)) => {
                if let Some(shared) = intersect(old, &next) {
                    self.proven = self.proven.saturating_add(1);
                    self.evidence = Some(shared);
                } else {
                    self.proven = 1;
                    self.evidence = Some(next);
                }
            }
            (_, Some(next)) => {
                self.proven = 1;
                self.evidence = Some(next);
            }
            (_, None) => {
                self.proven = 0;
                self.evidence = None;
            }
        }
    }
}

/// Uses normal TCP admission/parser. No origin, DNS, credentials or WAN request.
async fn probe(port: u16) -> bool {
    let nonce = format!("{:016x}", rand::random::<u64>());
    let request=format!("GET /.well-known/homeproxy-health HTTP/1.1\r\nHost: 127.0.0.1\r\nx-homeproxy-health-nonce: {nonce}\r\nConnection: close\r\n\r\n");
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::with_capacity(512);
        stream.take(512).read_to_end(&mut response).await?;
        Ok::<bool, std::io::Error>(valid_response(&response, &nonce))
    })
    .await;
    matches!(result, Ok(Ok(true)))
}
fn valid_response(response: &[u8], nonce: &str) -> bool {
    if response.len() >= 512 {
        return false;
    }
    let Some(split) = response.windows(4).position(|s| s == b"\r\n\r\n") else {
        return false;
    };
    let Ok(headers) = std::str::from_utf8(&response[..split]) else {
        return false;
    };
    let mut lines = headers.split("\r\n");
    let Some(status) = lines.next() else {
        return false;
    };
    if !matches!(
        status
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .as_slice(),
        ["HTTP/1.1" | "HTTP/1.0", "200"]
    ) {
        return false;
    }
    let mut close = false;
    let mut no_store = false;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("connection") && value.trim().eq_ignore_ascii_case("close")
            {
                close = true;
            }
            if key.eq_ignore_ascii_case("cache-control")
                && value
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("no-store"))
            {
                no_store = true;
            }
        }
    }
    close && no_store && &response[split + 4..] == nonce.as_bytes()
}

struct RunningGuard<'a>(&'a std::sync::atomic::AtomicBool);
impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Engine {
    /// Spawn independently of control/history maintenance. A second invocation is a no-op.
    pub async fn run_watchdog(self: Arc<Self>) {
        if self
            .diagnostics
            .watchdog_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let _guard = RunningGuard(&self.diagnostics.watchdog_running);
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut failures = Failures::default();
        let mut warmed_generation = None;
        let mut warming_started = tokio::time::Instant::now();
        loop {
            tokio::select! {biased;_ = self.maintenance_cancellation.cancelled()=>break,_=interval.tick()=>{}}
            let Some(config) = self.diagnostics.config() else {
                self.diagnostics.set_state(HealthState::Unavailable);
                continue;
            };
            if warmed_generation != Some(config.generation) {
                warmed_generation = Some(config.generation);
                warming_started = tokio::time::Instant::now();
                failures.reset(config.generation);
            }
            let metrics = self
                .stats
                .diagnostic_metrics(config.tunnel_idle_timeout_seconds, false);
            if config.transitioning {
                self.diagnostics
                    .set_state_for(config.generation, HealthState::Checking);
                self.diagnostics
                    .sample(config.generation, ProbeResult::NotRun, metrics);
                continue;
            }
            if !config.automatic_recovery
                || !config.running
                || !config.enabled
                || self.diagnostics.suspended()
            {
                let state = if !config.automatic_recovery {
                    HealthState::Disabled
                } else if self.diagnostics.suspended() {
                    HealthState::Suspended
                } else {
                    HealthState::Stopped
                };
                self.diagnostics.set_state_for(config.generation, state);
                self.diagnostics
                    .sample(config.generation, ProbeResult::NotRun, metrics);
                failures.reset(config.generation);
                continue;
            }
            if warming_started.elapsed() < Duration::from_secs(30) {
                self.diagnostics
                    .set_state_for(config.generation, HealthState::WarmingUp);
                self.diagnostics
                    .sample(config.generation, ProbeResult::NotRun, metrics);
                continue;
            }
            self.diagnostics
                .set_state_for(config.generation, HealthState::Checking);
            let healthy = tokio::select! {biased;_ = self.maintenance_cancellation.cancelled()=>break,result=probe(config.proxy_port)=>result};
            if !self.same_runtime(&config) {
                failures.reset(config.generation);
                continue;
            }
            let after = self
                .stats
                .diagnostic_metrics(config.tunnel_idle_timeout_seconds, false);
            if !self.same_runtime(&config) {
                failures.reset(config.generation);
                continue;
            }
            self.diagnostics.sample(
                config.generation,
                if healthy {
                    ProbeResult::Healthy
                } else {
                    ProbeResult::Failed
                },
                after.clone(),
            );
            if healthy {
                failures.reset(config.generation);
                self.diagnostics
                    .set_state_for(config.generation, HealthState::Healthy);
                continue;
            }
            failures.failed(config.generation, &metrics, &after);
            self.diagnostics
                .set_state_for(config.generation, HealthState::Suspected);
            if failures.consecutive < 3 {
                continue;
            }
            if !failures
                .ensure_reported(&self.diagnostics, config.generation)
                .await
            {
                continue;
            }
            if failures.proven < 3 {
                continue;
            }
            let Some(ref evidence) = failures.evidence else {
                continue;
            };
            let Some(recovered) = self.recover_runtime(config.generation, evidence).await else {
                continue;
            };
            let healthy = tokio::select! {biased;_ = self.maintenance_cancellation.cancelled()=>break,result=probe(config.proxy_port)=>result};
            self.finish_recovery(recovered, healthy).await;
            failures.reset(recovered);
        }
    }
    fn same_runtime(&self, config: &RuntimeConfig) -> bool {
        !self.maintenance_cancellation.is_cancelled()
            && self.diagnostics.config().is_some_and(|current| {
                current.generation == config.generation
                    && !current.transitioning
                    && current.running
                    && current.enabled
                    && current.automatic_recovery
            })
    }
    async fn recover_runtime(&self, expected: u64, reason: &Evidence) -> Option<u64> {
        let state = self.state.lock().await;
        if self.maintenance_cancellation.is_cancelled()
            || state.generation != expected
            || !state.settings.enabled
            || !state.settings.automatic_recovery
            || !state.proxy.as_ref().is_some_and(ProxyHandle::is_running)
            || self.diagnostics.suspended()
            || !self.diagnostics.incident_acknowledged_for(expected)
        {
            return None;
        }
        let metrics = self
            .stats
            .diagnostic_metrics(state.settings.tunnel_idle_timeout_seconds, false);
        evidence(&metrics).and_then(|fresh| intersect(reason, &fresh))?;
        let mut budget = self.diagnostics.budget()?;
        if !budget.allows(epoch_ms()) {
            return None;
        }
        budget.record(epoch_ms());
        // Durably reserve the budget before stopping anything. Storage failure is diagnosis-only.
        if !self.diagnostics.save_budget(budget).await
            || !self.diagnostics.incident_acknowledged_for(expected)
            || self.maintenance_cancellation.is_cancelled()
        {
            return None;
        }
        // The single writer grants protection only for exact, fresh evidence.
        // Hold the lease through stop/rebind and all error/cancellation returns.
        let _proof = self.diagnostics.acquire_recovery_proof(expected).await?;
        if self.maintenance_cancellation.is_cancelled() {
            return None;
        }
        let metrics = self
            .stats
            .diagnostic_metrics(state.settings.tunnel_idle_timeout_seconds, false);
        evidence(&metrics).and_then(|fresh| intersect(reason, &fresh))?;
        let mut state = RuntimePublication::new(state, &self.diagnostics);
        self.diagnostics.set_state(HealthState::Recovering);
        if let Some(handle) = state.proxy.take() {
            handle.stop().await;
        }
        // Stop/rebind is one serialized transition, never canceled by an observer timeout.
        // Shutdown may have canceled while stop awaited: do not reopen after that request.
        if self.maintenance_cancellation.is_cancelled() {
            return None;
        }
        match start_proxy(
            state.settings.clone(),
            self.cache.clone(),
            self.stats.clone(),
            self.tls_inspection.clone(),
        )
        .await
        {
            Ok(handle) => {
                if self.maintenance_cancellation.is_cancelled() {
                    handle.stop().await;
                    return None;
                }
                state.proxy = Some(handle);
                state.last_error = None;
                state.listener_error = None;
                Some(state.generation)
            }
            Err(error) => {
                state.listener_error = error.listener_bind_failure();
                state.last_error = Some(error.to_string());
                self.diagnostics.suspend().await;
                None
            }
        }
    }
    async fn finish_recovery(&self, expected: u64, healthy: bool) {
        let state = self.state.lock().await;
        if self.maintenance_cancellation.is_cancelled()
            || state.generation != expected
            || !state.settings.enabled
            || !state.settings.automatic_recovery
        {
            return;
        }
        if healthy {
            self.diagnostics
                .set_state_for(expected, HealthState::Healthy);
        } else {
            self.diagnostics.suspend().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::Budget;
    use tokio::net::{TcpListener, TcpSocket};
    fn complete(active: usize, loopback: usize) -> Metrics {
        Metrics {
            live_available: true,
            traffic_available: true,
            accounting_available: true,
            connection_limit: 256,
            connection_limit_per_peer: 128,
            active_connections: active,
            loopback_connections: loopback,
            ..Metrics::default()
        }
    }
    async fn running_engine() -> (tempfile::TempDir, Arc<Engine>, u16) {
        let root = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let engine = Arc::new(
            Engine::new_headless(root.path().join("config"), root.path().join("cache")).unwrap(),
        );
        let mut settings = engine.state.lock().await.settings.clone();
        settings.proxy_port = port;
        engine.apply_settings(settings).await.unwrap();
        engine.start().await.unwrap();
        (root, engine, port)
    }
    async fn recoverable_engine() -> (tempfile::TempDir, Arc<Engine>, u16) {
        let fixture = running_engine().await;
        assert!(
            fixture
                .1
                .diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        fixture
    }
    #[test]
    fn watchdog_full_active_peer_quota_and_missing_metrics_are_diagnosis_only() {
        for metrics in [
            complete(256, 0),
            complete(128, 128),
            complete(256, 128),
            Metrics::default(),
        ] {
            let mut failures = Failures::default();
            for _ in 0..3 {
                failures.failed(4, &metrics, &metrics);
            }
            assert_eq!(failures.consecutive, 3);
            assert_eq!(failures.proven, 0);
            assert!(failures.evidence.is_none());
        }
        let mut failures = Failures::default();
        let mut metrics = complete(256, 0);
        metrics.over_age_ids.insert(7);
        for _ in 0..3 {
            failures.failed(4, &metrics, &metrics);
        }
        assert_eq!(failures.proven, 3);
        metrics.over_age_ids.clear();
        metrics.over_age_ids.insert(8);
        failures.failed(4, &metrics, &metrics);
        assert_eq!(failures.proven, 1);
        failures.failed(5, &metrics, &metrics);
        assert_eq!(failures.consecutive, 1);
        // A probe rejected during an admission/telemetry gap is quota evidence, even
        // if both live-count snapshots happen to show a free slot.
        let before = complete(255, 0);
        let mut after = before.clone();
        after.rejected_connections = 1;
        let mut racing = Failures::default();
        for _ in 0..3 {
            racing.failed(4, &before, &after);
        }
        assert_eq!(racing.proven, 0);
        let mut missing = complete(0, 0);
        missing.traffic_available = false;
        assert!(evidence(&missing).is_none());
    }
    #[test]
    fn watchdog_probe_parser_requires_nonce_no_store_close_and_bounded_bytes() {
        let nonce = "0123456789abcdef";
        let valid = format!(
            "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{nonce}"
        );
        assert!(valid_response(valid.as_bytes(), nonce));
        assert!(!valid_response(valid.as_bytes(), "fedcba9876543210"));
        assert!(!valid_response(
            valid.replace("no-store", "public").as_bytes(),
            nonce
        ));
        assert!(!valid_response(
            valid.replace("200 OK", "401 Unauthorized").as_bytes(),
            nonce
        ));
        assert!(!valid_response(&vec![b'X'; 513], nonce));
    }
    #[tokio::test]
    async fn watchdog_probe_is_real_local_http_and_rejects_wrong_nonce() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let fixture = tokio::spawn(async move {
            for valid in [true, false] {
                let (mut stream, peer) = listener.accept().await.unwrap();
                assert!(peer.ip().is_loopback());
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with("GET /.well-known/homeproxy-health HTTP/1.1\r\n"));
                assert!(!request.to_ascii_lowercase().contains("authorization"));
                let nonce = request
                    .lines()
                    .find_map(|l| l.strip_prefix("x-homeproxy-health-nonce: "))
                    .unwrap();
                assert_eq!(nonce.len(), 16);
                assert!(nonce.bytes().all(|b| b.is_ascii_hexdigit()));
                let body = if valid { nonce } else { "wrong" };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}"
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        assert!(probe(port).await);
        assert!(!probe(port).await);
        fixture.await.unwrap();
    }
    #[test]
    fn watchdog_budget_cooldown_hour_limit_and_clock_rollback_are_conservative() {
        let mut budget = Budget::default();
        assert!(budget.allows(1_000_000));
        budget.record(1_000_000);
        assert!(!budget.allows(999_999));
        assert!(!budget.allows(1_599_999));
        assert!(budget.allows(1_600_000));
        budget.record(1_600_000);
        budget.record(2_200_000);
        assert!(!budget.allows(2_800_000));
        assert!(budget.allows(4_600_000));
        budget.suspended = true;
        assert!(!budget.allows(9_000_000));
    }
    #[tokio::test]
    async fn watchdog_manual_stop_invalidates_a_queued_recovery() {
        let (_root, engine, _) = recoverable_engine().await;
        let expected = engine.state.lock().await.generation;
        let held = engine.state.lock().await;
        let stopping = tokio::spawn({
            let engine = engine.clone();
            async move {
                engine.stop().await.unwrap();
            }
        });
        tokio::task::yield_now().await;
        let recovering = tokio::spawn({
            let engine = engine.clone();
            async move {
                engine
                    .recover_runtime(expected, &Evidence::FreeCapacity(0))
                    .await
            }
        });
        tokio::task::yield_now().await;
        drop(held);
        stopping.await.unwrap();
        assert!(recovering.await.unwrap().is_none());
        assert!(!engine.state.lock().await.settings.enabled);
        assert_eq!(engine.diagnostics.status()["recoveryCount"], 0);
        engine.shutdown().await;
    }
    #[tokio::test]
    async fn watchdog_settings_change_invalidates_a_queued_recovery() {
        let (_root, engine, _) = recoverable_engine().await;
        let expected = engine.state.lock().await.generation;
        let mut settings = engine.state.lock().await.settings.clone();
        settings.automatic_recovery = false;
        let held = engine.state.lock().await;
        let applying = tokio::spawn({
            let engine = engine.clone();
            async move {
                engine.apply_settings(settings).await.unwrap();
            }
        });
        tokio::task::yield_now().await;
        let recovering = tokio::spawn({
            let engine = engine.clone();
            async move {
                engine
                    .recover_runtime(expected, &Evidence::FreeCapacity(0))
                    .await
            }
        });
        tokio::task::yield_now().await;
        drop(held);
        applying.await.unwrap();
        assert!(recovering.await.unwrap().is_none());
        assert!(engine
            .state
            .lock()
            .await
            .proxy
            .as_ref()
            .unwrap()
            .is_running());
        assert_eq!(engine.diagnostics.status()["state"], "disabled");
        assert_eq!(engine.diagnostics.status()["recoveryCount"], 0);
        engine.shutdown().await;
    }
    #[tokio::test]
    async fn watchdog_shutdown_cancels_recovery_queued_before_the_state_lock() {
        let (_root, engine, _) = recoverable_engine().await;
        let expected = engine.state.lock().await.generation;
        let held = engine.state.lock().await;
        let recovering = tokio::spawn({
            let engine = engine.clone();
            async move {
                engine
                    .recover_runtime(expected, &Evidence::FreeCapacity(0))
                    .await
            }
        });
        tokio::task::yield_now().await;
        let shutdown = tokio::spawn({
            let engine = engine.clone();
            async move {
                engine.shutdown().await;
            }
        });
        tokio::task::yield_now().await;
        assert!(engine.maintenance_cancellation.is_cancelled());
        drop(held);
        assert!(recovering.await.unwrap().is_none());
        shutdown.await.unwrap();
        assert_eq!(engine.diagnostics.status()["recoveryCount"], 0);
    }
    #[tokio::test]
    async fn watchdog_internal_recovery_preserves_saved_enabled_credentials_and_history() {
        let (_root, engine, port) = recoverable_engine().await;
        let config = engine.diagnostics.config().unwrap();
        let saved = std::fs::read(engine.settings_path()).unwrap();
        let original = engine.state.lock().await.settings.clone();
        let history = engine.usage_history().unwrap();
        let recovered = engine
            .recover_runtime(config.generation, &Evidence::FreeCapacity(0))
            .await
            .unwrap();
        assert_ne!(recovered, config.generation);
        assert_eq!(std::fs::read(engine.settings_path()).unwrap(), saved);
        assert_eq!(engine.state.lock().await.settings, original);
        assert_eq!(
            serde_json::to_value(engine.usage_history().unwrap()).unwrap(),
            serde_json::to_value(history).unwrap()
        );
        assert!(TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok());
        assert!(engine
            .recover_runtime(recovered, &Evidence::FreeCapacity(0))
            .await
            .is_none());
        assert_eq!(engine.diagnostics.status()["recoveryCount"], 1);
        engine.shutdown().await;
    }
    #[tokio::test]
    async fn watchdog_failed_post_recovery_probe_suspends_and_manual_start_clears_only_suspension()
    {
        let (root, engine, _) = recoverable_engine().await;
        let expected = engine.state.lock().await.generation;
        let recovered = engine
            .recover_runtime(expected, &Evidence::FreeCapacity(0))
            .await
            .unwrap();
        let attempts = engine.diagnostics.budget().unwrap().attempts;
        let held = engine.diagnostics.hold_memory_for_test();
        engine.finish_recovery(recovered, false).await;
        assert_eq!(engine.diagnostics.status()["state"], "suspended");
        assert!(engine.diagnostics.suspended());
        drop(held);
        let handle = engine.state.lock().await.proxy.take().unwrap();
        handle.stop().await;
        engine.start_saved().await.unwrap();
        assert!(engine.state.lock().await.proxy.is_none());
        let reloaded =
            Engine::new_headless(root.path().join("config"), root.path().join("cache2")).unwrap();
        reloaded.start_saved().await.unwrap();
        assert!(reloaded.state.lock().await.proxy.is_none());
        assert_eq!(reloaded.diagnostics.budget().unwrap().attempts, attempts);
        assert_eq!(reloaded.diagnostics.budget().unwrap().recovery_count, 1);
        engine.start().await.unwrap();
        assert!(!engine.diagnostics.suspended());
        assert_eq!(engine.diagnostics.budget().unwrap().attempts, attempts);
        assert_eq!(engine.diagnostics.budget().unwrap().recovery_count, 1);
        assert!(!engine.diagnostics.budget().unwrap().allows(epoch_ms()));
        engine.shutdown().await;
    }
    #[tokio::test]
    async fn watchdog_failed_rebind_blocks_saved_enabled_retry() {
        let (root, engine, _) = recoverable_engine().await;
        let occupied = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let expected = {
            let mut state = engine.state.lock().await;
            state.settings.socks5_enabled = true;
            state.settings.socks5_port = occupied.local_addr().unwrap().port();
            state.generation
        };
        let held = engine.diagnostics.hold_memory_for_test();
        assert!(engine
            .recover_runtime(expected, &Evidence::FreeCapacity(0))
            .await
            .is_none());
        assert!(engine.diagnostics.suspended());
        assert_eq!(engine.diagnostics.status()["state"], "suspended");
        drop(held);
        assert!(engine.state.lock().await.settings.enabled);
        assert!(engine.state.lock().await.proxy.is_none());
        drop(occupied);
        engine.start_saved().await.unwrap();
        assert!(engine.state.lock().await.proxy.is_none());
        let reloaded =
            Engine::new_headless(root.path().join("config"), root.path().join("cache2")).unwrap();
        reloaded.start_saved().await.unwrap();
        assert!(reloaded.state.lock().await.proxy.is_none());
        assert_eq!(reloaded.diagnostics.budget().unwrap().recovery_count, 1);
        assert_eq!(
            reloaded.diagnostics.budget().unwrap().attempts,
            engine.diagnostics.budget().unwrap().attempts
        );
        engine.shutdown().await;
    }
    #[tokio::test]
    async fn watchdog_failed_incident_then_successful_budget_never_recovers_runtime() {
        let (_root, engine, _) = recoverable_engine().await;
        let expected = engine.state.lock().await.generation;
        engine.diagnostics.fail_next_incident_for_test().await;
        assert!(
            !engine
                .diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        let budget = engine.diagnostics.budget().unwrap();
        assert!(engine.diagnostics.save_budget(budget).await);
        assert_eq!(engine.diagnostics.status()["storageAvailable"], false);
        let exported = engine.diagnostics.export();
        assert_eq!(exported["incidents"].as_array().unwrap().len(), 2);
        assert!(!engine.diagnostics.incident_acknowledged_for(expected));
        assert!(engine
            .recover_runtime(expected, &Evidence::FreeCapacity(0))
            .await
            .is_none());
        let state = engine.state.lock().await;
        assert_eq!(state.generation, expected);
        assert!(state.proxy.as_ref().unwrap().is_running());
        assert_eq!(engine.diagnostics.status()["recoveryCount"], 0);
        drop(state);
        // Retry durably records the same memory incident before recovery is allowed.
        assert!(
            engine
                .diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert_eq!(
            engine.diagnostics.export()["incidents"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(engine
            .recover_runtime(expected, &Evidence::FreeCapacity(0))
            .await
            .is_some());
        engine.shutdown().await;
    }
    #[tokio::test]
    async fn watchdog_retention_expiry_during_budget_write_blocks_stop() {
        let (root, engine, port) = recoverable_engine().await;
        let expected = engine.state.lock().await.generation;
        let at = engine.diagnostics.status()["lastIncidentAt"]
            .as_u64()
            .unwrap();
        let release = engine.diagnostics.pause_writer_for_test().await;
        let recovering = {
            let engine = engine.clone();
            tokio::spawn(async move {
                engine
                    .recover_runtime(expected, &Evidence::FreeCapacity(0))
                    .await
            })
        };
        // Budget mutation proves recovery passed its initial ACK check. Its real
        // disk write remains blocked while the incident crosses the retention edge.
        tokio::time::timeout(Duration::from_secs(1), async {
            while engine.diagnostics.status()["recoveryCount"] != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        engine
            .diagnostics
            .set_retention_time_for_test(at + 7 * 24 * 60 * 60 * 1000 + 1);
        release.send(()).unwrap();
        assert!(recovering.await.unwrap().is_none());
        engine.diagnostics.set_retention_time_for_test(at);
        assert!(!engine.diagnostics.incident_acknowledged_for(expected));
        assert_eq!(engine.diagnostics.status()["storageAvailable"], true);
        let state = engine.state.lock().await;
        assert_eq!(state.generation, expected);
        assert!(state.proxy.as_ref().unwrap().is_running());
        drop(state);
        assert!(TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok());
        assert!(std::fs::read_dir(root.path().join("config/diagnostics"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("incident-")));
        engine.shutdown().await;
    }
    #[tokio::test]
    async fn watchdog_retention_invalid_ack_recaptures_even_when_already_reported() {
        let (_root, engine, _) = recoverable_engine().await;
        let expected = engine.state.lock().await.generation;
        let old_at = engine.diagnostics.status()["lastIncidentAt"]
            .as_u64()
            .unwrap();
        let fresh_at = old_at + 7 * 24 * 60 * 60 * 1000 + 1;
        engine.diagnostics.set_retention_time_for_test(fresh_at);
        let mut failures = Failures {
            reported: true,
            ..Failures::default()
        };
        engine.diagnostics.fail_next_incident_for_test().await;
        assert!(
            !failures
                .ensure_reported(&engine.diagnostics, expected)
                .await
        );
        assert_eq!(engine.diagnostics.status()["lastIncidentAt"], fresh_at);
        assert!(!engine.diagnostics.incident_acknowledged_for(expected));
        assert!(engine
            .recover_runtime(expected, &Evidence::FreeCapacity(0))
            .await
            .is_none());
        assert_eq!(engine.state.lock().await.generation, expected);
        assert!(
            failures
                .ensure_reported(&engine.diagnostics, expected)
                .await
        );
        assert!(engine.diagnostics.incident_acknowledged_for(expected));
        assert!(engine
            .recover_runtime(expected, &Evidence::FreeCapacity(0))
            .await
            .is_some());
        engine.shutdown().await;
    }
    #[tokio::test]
    async fn watchdog_recovery_requires_writer_lease_before_stopping() {
        let (_root, engine, port) = recoverable_engine().await;
        let expected = engine.state.lock().await.generation;
        let held = engine
            .diagnostics
            .acquire_recovery_proof(expected)
            .await
            .unwrap();
        // Initial ACK and durable budget are valid, but a second lease is denied.
        assert!(engine.diagnostics.incident_acknowledged_for(expected));
        assert!(engine
            .recover_runtime(expected, &Evidence::FreeCapacity(0))
            .await
            .is_none());
        assert_eq!(engine.diagnostics.status()["storageAvailable"], true);
        let state = engine.state.lock().await;
        assert_eq!(state.generation, expected);
        assert!(state.proxy.as_ref().unwrap().is_running());
        drop(state);
        assert!(TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok());
        drop(held);
        engine.shutdown().await;
    }
    #[tokio::test]
    async fn watchdog_recovery_proof_writer_timeout_never_stops_runtime() {
        let (_root, engine, port) = recoverable_engine().await;
        let expected = engine.state.lock().await.generation;
        let release_budget = engine.diagnostics.pause_writer_for_test().await;
        let recovering = {
            let engine = engine.clone();
            tokio::spawn(async move {
                engine
                    .recover_runtime(expected, &Evidence::FreeCapacity(0))
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while engine.diagnostics.status()["recoveryCount"] != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Queue a second real writer barrier behind the budget. Its successful
        // ACK can reach recovery, but acquisition itself must now time out.
        let (proof_wait, release_proof) = engine.diagnostics.queue_pause_writer_for_test();
        release_budget.send(()).unwrap();
        proof_wait.await.unwrap();
        assert!(recovering.await.unwrap().is_none());
        let state = engine.state.lock().await;
        assert_eq!(state.generation, expected);
        assert!(state.proxy.as_ref().unwrap().is_running());
        drop(state);
        assert!(TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok());
        release_proof.send(()).unwrap();
        assert!(
            engine
                .diagnostics
                .save_budget(engine.diagnostics.budget().unwrap())
                .await
        );
        // The timed-out acquisition cannot reserve protection when it later runs.
        assert!(engine
            .diagnostics
            .acquire_recovery_proof(expected)
            .await
            .is_some());
        engine.shutdown().await;
    }
    #[tokio::test]
    async fn watchdog_failed_rebind_releases_recovery_evidence_lease() {
        let (root, engine, _) = recoverable_engine().await;
        let occupied = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let expected = {
            let mut state = engine.state.lock().await;
            state.settings.socks5_enabled = true;
            state.settings.socks5_port = occupied.local_addr().unwrap().port();
            state.generation
        };
        let at = engine.diagnostics.status()["lastIncidentAt"]
            .as_u64()
            .unwrap();
        assert!(engine
            .recover_runtime(expected, &Evidence::FreeCapacity(0))
            .await
            .is_none());
        assert!(engine.diagnostics.suspended());
        engine
            .diagnostics
            .set_retention_time_for_test(at + 7 * 24 * 60 * 60 * 1000 + 1);
        assert!(
            engine
                .diagnostics
                .save_budget(engine.diagnostics.budget().unwrap())
                .await
        );
        assert!(std::fs::read_dir(root.path().join("config/diagnostics"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("incident-")));
        engine.shutdown().await;
    }
    async fn wait_connections(engine: &Engine, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if engine
                    .stats
                    .diagnostic_metrics(60, false)
                    .active_connections
                    == expected
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn watchdog_actual_256_live_clients_and_128_loopback_clients_do_not_restart() {
        let (_root, engine, port) = recoverable_engine().await;
        let expected = engine.state.lock().await.generation;
        let mut clients = Vec::new();
        for index in 0..256 {
            let socket = TcpSocket::new_v4().unwrap();
            let ip = std::net::Ipv4Addr::new(127, 0, 0, if index < 128 { 2 } else { 3 });
            socket.bind((ip, 0).into()).unwrap();
            clients.push(
                socket
                    .connect((std::net::Ipv4Addr::LOCALHOST, port).into())
                    .await
                    .unwrap(),
            );
        }
        wait_connections(&engine, 256).await;
        assert!(engine
            .recover_runtime(expected, &Evidence::FreeCapacity(0))
            .await
            .is_none());
        assert_eq!(engine.state.lock().await.generation, expected);
        assert_eq!(engine.diagnostics.status()["recoveryCount"], 0);
        drop(clients);
        wait_connections(&engine, 0).await;
        let mut clients = Vec::new();
        for _ in 0..128 {
            clients.push(
                TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                    .await
                    .unwrap(),
            );
        }
        wait_connections(&engine, 128).await;
        assert!(engine
            .recover_runtime(expected, &Evidence::FreeCapacity(0))
            .await
            .is_none());
        assert_eq!(engine.diagnostics.status()["recoveryCount"], 0);
        drop(clients);
        engine.shutdown().await;
    }
    #[tokio::test(start_paused = true)]
    async fn watchdog_warmup_and_single_runner_cancel_with_maintenance() {
        let (_root, engine, _) = running_engine().await;
        let runner = tokio::spawn(engine.clone().run_watchdog());
        tokio::task::yield_now().await;
        assert_eq!(engine.diagnostics.status()["state"], "warmingUp");
        assert!(engine.diagnostics.watchdog_running.load(Ordering::Acquire));
        tokio::time::timeout(Duration::from_millis(100), engine.clone().run_watchdog())
            .await
            .unwrap();
        tokio::time::advance(Duration::from_secs(15)).await;
        tokio::task::yield_now().await;
        let samples = engine.diagnostics.export()["samples"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(samples.len(), 2);
        assert!(samples.iter().all(|sample| sample["probe"] == "notRun"));
        engine.shutdown().await;
        runner.await.unwrap();
        assert!(!engine.diagnostics.watchdog_running.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn watchdog_overage_evidence_must_still_hold_under_the_state_lock() {
        let (_root, engine, _) = recoverable_engine().await;
        // The storage writer uses wall time; only the evidence scenario is paused.
        tokio::time::pause();
        let expected = engine.state.lock().await.generation;
        let guards = (1..=256)
            .map(|id| {
                engine
                    .stats
                    .track_connection(id, "192.168.1.2".parse().unwrap())
            })
            .collect::<Vec<_>>();
        tokio::time::advance(Duration::from_secs(1831)).await;
        let held = engine.state.lock().await;
        let recovering = tokio::spawn({
            let engine = engine.clone();
            async move {
                engine
                    .recover_runtime(expected, &Evidence::OverAge(BTreeSet::from([1])))
                    .await
            }
        });
        tokio::task::yield_now().await;
        engine.stats.connection_progress(1);
        drop(held);
        assert!(recovering.await.unwrap().is_none());
        assert_eq!(engine.diagnostics.status()["recoveryCount"], 0);
        drop(guards);
        engine.shutdown().await;
    }
    #[tokio::test]
    async fn watchdog_generation_publication_and_export_do_not_wait_for_engine_state() {
        let (_root, engine, _) = recoverable_engine().await;
        let state = engine.state.lock().await;
        let started = std::time::Instant::now();
        let exported = engine.diagnostics.export();
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(
            exported["current"]["config"]["generation"],
            state.generation
        );
        drop(state);
        engine.shutdown().await;
    }
}
