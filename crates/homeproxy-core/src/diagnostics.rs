//! Private, bounded diagnostics. Only these typed records may cross the export/storage boundary.
use crate::{stats::Stats, CacheMode, DnsMode, HttpsMode, Settings};
#[path = "diagnostics/process.rs"]
mod process;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, VecDeque},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
        mpsc::{sync_channel, RecvTimeoutError, SyncSender},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_INCIDENTS: usize = 10;
const MAX_FILE: u64 = 2 * 1024 * 1024;
const MAX_STORAGE: u64 = 20 * 1024 * 1024;
const RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
// Recovery requires a recent snapshot, while reports themselves have a 7-day TTL.
const RECOVERY_PROOF_MAX_AGE_MS: u64 = 5 * 60 * 1000;
pub(crate) fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeConfig {
    pub generation: u64,
    pub published_at: u64,
    pub started_at: Option<u64>,
    pub enabled: bool,
    pub running: bool,
    #[serde(default)]
    pub transitioning: bool,
    pub automatic_recovery: bool,
    pub proxy_port: u16,
    pub socks5_enabled: bool,
    pub socks5_port: u16,
    pub tunnel_idle_timeout_seconds: u32,
    pub lan_enabled: bool,
    pub listen_ips: Vec<Ipv4Addr>,
    pub cache_enabled: bool,
    pub cache_mode: CacheMode,
    pub dns_mode: DnsMode,
    pub https_mode: HttpsMode,
    pub lan_dns_enabled: bool,
    pub upstream_proxy_count: usize,
    pub upstream_direct_fallback: bool,
    pub device_profile_count: usize,
    pub denied_device_count: usize,
    pub domain_rule_count: usize,
}
impl RuntimeConfig {
    pub(crate) fn new(
        settings: &Settings,
        generation: u64,
        running: bool,
        started_at: Option<u64>,
    ) -> Self {
        Self {
            generation,
            published_at: epoch_ms(),
            started_at,
            enabled: settings.enabled,
            running,
            transitioning: false,
            automatic_recovery: settings.automatic_recovery,
            proxy_port: settings.proxy_port,
            socks5_enabled: settings.socks5_enabled,
            socks5_port: settings.socks5_port,
            tunnel_idle_timeout_seconds: settings.tunnel_idle_timeout_seconds,
            lan_enabled: settings.lan_enabled,
            listen_ips: settings
                .listen_ips
                .iter()
                .take(64)
                .filter_map(|ip| ip.parse().ok())
                .collect(),
            cache_enabled: settings.cache_enabled,
            cache_mode: settings.cache_mode,
            dns_mode: settings.dns_mode,
            https_mode: settings.https_mode,
            lan_dns_enabled: settings.lan_dns_enabled,
            upstream_proxy_count: settings.upstream_proxies.len(),
            upstream_direct_fallback: settings.upstream_direct_fallback,
            device_profile_count: settings.device_profiles.len(),
            denied_device_count: settings.denied_client_ips.len(),
            domain_rule_count: settings.allow_domains.len() + settings.block_domains.len(),
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Protocol {
    Tcp,
    Http,
    Connect,
    Socks5,
    Socks5Udp,
    Websocket,
    Inspect,
}
impl Protocol {
    pub(crate) fn from_label(label: &str) -> Self {
        match label {
            "http" => Self::Http,
            "connect" => Self::Connect,
            "socks5" => Self::Socks5,
            "socks5-udp" => Self::Socks5Udp,
            "websocket" => Self::Websocket,
            "inspect" => Self::Inspect,
            _ => Self::Tcp,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Connection {
    pub id: u64,
    pub peer_ip: IpAddr,
    pub protocol: Protocol,
    pub age_ms: u64,
    pub idle_ms: u64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Metrics {
    pub live_available: bool,
    pub traffic_available: bool,
    #[serde(default)]
    pub accounting_available: bool,
    pub active_connections: usize,
    pub loopback_connections: usize,
    pub connection_limit: usize,
    pub connection_limit_per_peer: usize,
    pub over_age_idle_connections: usize,
    pub idle_connections_closed: u64,
    pub keepalive_configuration_failures: u64,
    pub listener_runtime_errors: u64,
    pub listener_error_present: bool,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub cache_hits: u64,
    pub successful_external_requests: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub rejected_connections: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_connections: Option<Vec<Connection>>,
    #[serde(skip)]
    pub over_age_ids: BTreeSet<u64>,
}
impl Metrics {
    pub(crate) fn consistent(&self) -> bool {
        self.live_available
            && self.traffic_available
            && self.accounting_available
            && self.connection_limit == 256
            && self.connection_limit_per_peer == 128
            && self.active_connections <= 256
            && self.loopback_connections <= 128
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Sample {
    at: u64,
    generation: u64,
    probe: ProbeResult,
    metrics: Metrics,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ProbeResult {
    Healthy,
    Failed,
    NotRun,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Current {
    at: u64,
    service_version: String,
    process: process::ProcessFacts,
    config_available: bool,
    config: Option<RuntimeConfig>,
    metrics: Metrics,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Incident {
    schema_version: u8,
    at: u64,
    reason: IncidentReason,
    current: Current,
    samples: Vec<Sample>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum IncidentReason {
    LocalProbeFailures,
    OverAgeIdleCapacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum HealthState {
    WarmingUp,
    Healthy,
    Stopped,
    Checking,
    Suspected,
    Recovering,
    Suspended,
    Disabled,
    Unavailable,
}
impl HealthState {
    fn label(value: u8) -> &'static str {
        match value {
            0 => "warmingUp",
            1 => "healthy",
            2 => "stopped",
            3 => "checking",
            4 => "suspected",
            5 => "recovering",
            6 => "suspended",
            7 => "disabled",
            _ => "unavailable",
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Budget {
    pub revision: u64,
    pub recovery_count: u64,
    pub attempts: Vec<u64>,
    pub suspended: bool,
}
impl Budget {
    pub(crate) fn allows(&self, now: u64) -> bool {
        !self.suspended
            && self.attempts.len() <= 3
            && self
                .attempts
                .last()
                .is_none_or(|last| now >= *last && now - *last >= 600_000)
            && self
                .attempts
                .iter()
                .filter(|at| now.saturating_sub(**at) < 3_600_000 || now < **at)
                .count()
                < 3
    }
    pub(crate) fn record(&mut self, now: u64) {
        self.attempts
            .retain(|at| now.saturating_sub(*at) < 3_600_000 || now < *at);
        self.attempts.push(now);
        self.recovery_count = self.recovery_count.saturating_add(1);
        self.revision = self.revision.saturating_add(1);
    }
}
enum WriteJob {
    #[cfg(test)]
    FailNextIncident(tokio::sync::oneshot::Sender<()>),
    #[cfg(test)]
    PauseWriter(
        tokio::sync::oneshot::Sender<()>,
        std::sync::mpsc::Receiver<()>,
    ),
    Incident(Box<PendingIncident>, tokio::sync::oneshot::Sender<bool>),
    Budget(Budget, tokio::sync::oneshot::Sender<bool>),
    AcquireRecoveryProof {
        generation: u64,
        ack: tokio::sync::oneshot::Sender<Option<RecoveryProof>>,
    },
}
/// The writer protects one immutable record until the runtime transition completes.
/// Releasing a lease is nonblocking and cannot be lost to a full/disconnected queue.
#[must_use]
pub(crate) struct RecoveryProof {
    active: Arc<AtomicBool>,
}
impl Drop for RecoveryProof {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}
struct ProtectedIncident {
    record_name: String,
    active: Arc<AtomicBool>,
}
#[derive(Clone)]
struct PendingIncident {
    incident: Incident,
    record_id: u64,
}
struct PendingBudget {
    value: Budget,
    dirty: bool,
}
struct Memory {
    samples: VecDeque<Sample>,
    incidents: VecDeque<Incident>,
    pending_incident: Option<PendingIncident>,
}
/// Synchronous observation is independent of Engine state, cache and history locks.
pub struct Diagnostics {
    started: std::time::Instant,
    stats: Arc<Stats>,
    config: Mutex<RuntimeConfig>,
    memory: Mutex<Memory>,
    budget: Arc<Mutex<PendingBudget>>,
    suspension: AtomicBool,
    pending_incident_at: Arc<AtomicU64>,
    durable_incident_at: Arc<AtomicU64>,
    durable_incident_generation: Arc<AtomicU64>,
    retained_incident: Arc<AtomicBool>,
    incident_inflight: Arc<AtomicBool>,
    enabled: AtomicBool,
    state: AtomicU8,
    storage_available: Arc<AtomicBool>,
    recovery_count: AtomicU64,
    last_incident_at: AtomicU64,
    writer: Option<SyncSender<WriteJob>>,
    #[cfg(test)]
    retention_clock: Arc<AtomicU64>,
    pub(crate) watchdog_running: AtomicBool,
}
impl Diagnostics {
    pub(crate) fn new(directory: PathBuf, stats: Arc<Stats>, settings: &Settings) -> Arc<Self> {
        Self::new_with_prune_interval(
            directory,
            stats,
            settings,
            std::time::Duration::from_secs(60),
        )
    }
    fn new_with_prune_interval(
        directory: PathBuf,
        stats: Arc<Stats>,
        settings: &Settings,
        prune_interval: std::time::Duration,
    ) -> Arc<Self> {
        let storage = PrivateDirectory::open(&directory).ok();
        #[cfg(test)]
        let retention_clock = storage.as_ref().map_or_else(
            || Arc::new(AtomicU64::new(0)),
            |s| s.retention_clock.clone(),
        );
        let (incidents, budget, available) = storage.as_ref().map(|s| s.load()).unwrap_or_default();
        let storage_available = Arc::new(AtomicBool::new(available));
        let budget = Arc::new(Mutex::new(PendingBudget {
            value: budget,
            dirty: false,
        }));
        let last_incident_at = incidents.back().map_or(0, |i| i.at);
        let pending_incident_at = Arc::new(AtomicU64::new(last_incident_at));
        let durable_incident_at = Arc::new(AtomicU64::new(last_incident_at));
        // Retained reports belong to a previous runtime, not this process's generation.
        let durable_incident_generation = Arc::new(AtomicU64::new(u64::MAX));
        let retained_incident = Arc::new(AtomicBool::new(false));
        let incident_inflight = Arc::new(AtomicBool::new(false));
        let writer = storage.and_then(|storage| {
            let (sender, receiver) = sync_channel(2);
            let available = storage_available.clone();
            let pending_budget = budget.clone();
            let pending_incident = pending_incident_at.clone();
            let durable_incident = durable_incident_at.clone();
            let durable_generation = durable_incident_generation.clone();
            let retained = retained_incident.clone();
            let inflight = incident_inflight.clone();
            std::thread::Builder::new()
                .name("homeproxy-diagnostics".into())
                .spawn(move || {
                    let mut storage = storage;
                    if storage.prune().is_err() {
                        available.store(false, Ordering::Release);
                    }
                    let mut proof = None;
                    let mut last_prune = std::time::Instant::now();
                    #[cfg(test)]
                    let mut fail_next_incident = false;
                    loop {
                        // Check even under a steady stream of jobs. Idle retention uses
                        // this same bounded OS worker, independently of budget dirtiness.
                        if last_prune.elapsed() >= prune_interval {
                            let pruned = storage.prune();
                            let checked = storage.refresh_retained(proof, &retained);
                            if pruned.is_err() || checked.is_err() {
                                available.store(false, Ordering::Release);
                            }
                            last_prune = std::time::Instant::now();
                        }
                        let wait = std::time::Duration::from_secs(1)
                            .min(prune_interval.saturating_sub(last_prune.elapsed()));
                        let job = match receiver.recv_timeout(wait) {
                            Ok(job) => job,
                            Err(RecvTimeoutError::Disconnected) => {
                                storage.persist_pending_budget(&pending_budget, &available);
                                if storage.refresh_retained(proof, &retained).is_err() {
                                    available.store(false, Ordering::Release);
                                }
                                break;
                            }
                            Err(RecvTimeoutError::Timeout) => {
                                // One existing worker retries the latest mutation, including a
                                // suspension whose immediate queue insertion failed.
                                storage.persist_pending_budget(&pending_budget, &available);
                                if storage.refresh_retained(proof, &retained).is_err() {
                                    available.store(false, Ordering::Release);
                                }
                                continue;
                            }
                        };
                        let result = match job {
                            #[cfg(test)]
                            WriteJob::FailNextIncident(ack) => {
                                fail_next_incident = true;
                                let _ = ack.send(());
                                continue;
                            }
                            #[cfg(test)]
                            WriteJob::PauseWriter(ready, release) => {
                                let _ = ready.send(());
                                let _ = release.recv();
                                continue;
                            }
                            WriteJob::Incident(value, ack) => {
                                let written = storage
                                    .write_incident(
                                        &value,
                                        #[cfg(test)]
                                        &mut fail_next_incident,
                                    )
                                    .and_then(|_| storage.prune())
                                    .is_ok();
                                if written {
                                    retained.store(false, Ordering::Release);
                                    proof = Some((value.incident.at, value.record_id));
                                    durable_generation.store(
                                        value
                                            .incident
                                            .current
                                            .config
                                            .as_ref()
                                            .map_or(u64::MAX, |c| c.generation),
                                        Ordering::Release,
                                    );
                                    durable_incident.store(value.incident.at, Ordering::Release);
                                }
                                // A successful write may have immediately expired or been
                                // pruned. Only its exact surviving record can authorize recovery.
                                let checked = storage.refresh_retained(proof, &retained).is_ok();
                                let ok = written && checked;
                                inflight.store(false, Ordering::Release);
                                available.store(ok, Ordering::Release);
                                let _ = ack.send(ok && retained.load(Ordering::Acquire));
                                ok
                            }
                            WriteJob::AcquireRecoveryProof { generation, ack } => {
                                if ack.is_closed() {
                                    continue;
                                }
                                let current = durable_generation.load(Ordering::Acquire)
                                    == generation
                                    && proof.is_some_and(|(at, _)| {
                                        pending_incident.load(Ordering::Acquire) == at
                                    });
                                let lease = if current {
                                    match storage.acquire_recovery_proof(proof, &retained) {
                                        Ok(lease) => lease,
                                        Err(_) => {
                                            available.store(false, Ordering::Release);
                                            None
                                        }
                                    }
                                } else {
                                    None
                                };
                                // Failed send (or a dropped receiver after send) drops the
                                // owned guard, so an observer timeout cannot orphan a pin.
                                let _ = ack.send(lease);
                                continue;
                            }
                            WriteJob::Budget(value, ack) => {
                                let persisted = storage.persist_budget(&pending_budget, &value);
                                let checked = storage.refresh_retained(proof, &retained).is_ok();
                                let ok = persisted && checked;
                                available.store(ok, Ordering::Release);
                                let _ = ack.send(ok);
                                ok
                            }
                        };
                        available.store(result, Ordering::Release);
                    }
                })
                .ok()
                .map(|_| sender)
        });
        if writer.is_none() {
            storage_available.store(false, Ordering::Release);
        }
        let recovery_count = budget.lock().unwrap().value.recovery_count;
        let suspended = budget.lock().unwrap().value.suspended;
        Arc::new(Self {
            started: std::time::Instant::now(),
            stats,
            config: Mutex::new(RuntimeConfig::new(settings, 0, false, None)),
            memory: Mutex::new(Memory {
                samples: VecDeque::new(),
                incidents,
                pending_incident: None,
            }),
            budget,
            suspension: AtomicBool::new(suspended),
            pending_incident_at,
            durable_incident_at,
            durable_incident_generation,
            retained_incident,
            incident_inflight,
            enabled: AtomicBool::new(settings.automatic_recovery),
            state: AtomicU8::new(if suspended {
                HealthState::Suspended
            } else if settings.automatic_recovery {
                HealthState::Stopped
            } else {
                HealthState::Disabled
            } as u8),
            storage_available,
            recovery_count: AtomicU64::new(recovery_count),
            last_incident_at: AtomicU64::new(last_incident_at),
            writer,
            #[cfg(test)]
            retention_clock,
            watchdog_running: AtomicBool::new(false),
        })
    }
    pub fn status(&self) -> Value {
        let at = self.last_incident_at.load(Ordering::Acquire);
        json!({"enabled":self.enabled.load(Ordering::Acquire),"state":HealthState::label(self.state.load(Ordering::Acquire)),"recoveryCount":self.recovery_count.load(Ordering::Acquire),"lastIncidentAt":if at==0 {None} else {Some(at)},"storageAvailable":self.storage_available.load(Ordering::Acquire) && self.pending_incident_at.load(Ordering::Acquire) == self.durable_incident_at.load(Ordering::Acquire)})
    }
    fn current(&self) -> Current {
        let config = self.config();
        let metrics = self.stats.diagnostic_metrics(
            config
                .as_ref()
                .map_or(u32::MAX - 30, |c| c.tunnel_idle_timeout_seconds),
            true,
        );
        // If a transition overlapped the metric read, explicitly mark the config unavailable.
        let config = if self.config() == config {
            config
        } else {
            None
        };
        Current {
            at: epoch_ms(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            process: process::ProcessFacts::collect(self.started),
            config_available: config.is_some(),
            config,
            metrics,
        }
    }
    pub fn export(&self) -> Value {
        let current = self.current();
        let (available, samples, incidents) = match self.memory.try_lock() {
            Ok(mut m) => {
                m.incidents
                    .retain(|i| epoch_ms().saturating_sub(i.at) <= RETENTION_MS);
                (
                    true,
                    m.samples.iter().cloned().collect::<Vec<_>>(),
                    m.incidents.iter().cloned().collect::<Vec<_>>(),
                )
            }
            Err(_) => (false, Vec::new(), Vec::new()),
        };
        json!({"schemaVersion":1,"status":self.status(),"current":current,"retainedAvailable":available,"samples":samples,"incidents":incidents})
    }
    pub(crate) fn config(&self) -> Option<RuntimeConfig> {
        self.config.try_lock().ok().map(|c| c.clone())
    }
    pub(crate) fn publish(&self, config: RuntimeConfig) {
        self.enabled
            .store(config.automatic_recovery, Ordering::Release);
        if let Ok(mut current) = self.config.lock() {
            *current = config;
        }
    }
    pub(crate) fn set_state_for(&self, generation: u64, state: HealthState) {
        if let Ok(config) = self.config.try_lock() {
            if config.generation == generation {
                self.set_state(state);
            }
        }
    }
    pub(crate) fn set_state(&self, state: HealthState) {
        self.state.store(state as u8, Ordering::Release);
    }
    pub(crate) fn suspended(&self) -> bool {
        self.suspension.load(Ordering::Acquire)
    }
    pub(crate) fn budget(&self) -> Option<Budget> {
        self.budget.try_lock().ok().map(|p| p.value.clone())
    }
    pub(crate) fn sample(&self, generation: u64, probe: ProbeResult, mut metrics: Metrics) {
        metrics.live_connections = None;
        metrics.over_age_ids.clear();
        if let Ok(mut m) = self.memory.try_lock() {
            if m.samples.len() == 60 {
                m.samples.pop_front();
            }
            m.samples.push_back(Sample {
                at: epoch_ms(),
                generation,
                probe,
                metrics,
            });
        }
    }
    fn retention_now(&self) -> u64 {
        #[cfg(test)]
        {
            let now = self.retention_clock.load(Ordering::Acquire);
            if now != 0 {
                return now;
            }
        }
        epoch_ms()
    }
    #[cfg(test)]
    pub(crate) fn set_retention_time_for_test(&self, now: u64) {
        self.retention_clock.store(now, Ordering::Release);
    }
    pub(crate) async fn incident(&self, reason: IncidentReason) -> bool {
        let current = self.current();
        let value = if let Ok(mut m) = self.memory.try_lock() {
            let now = self.retention_now();
            if m.pending_incident
                .as_ref()
                .is_some_and(|p| now.saturating_sub(p.incident.at) > RECOVERY_PROOF_MAX_AGE_MS)
            {
                // Never replace a record still owned by a slow writer. After it finishes,
                // recapture current-generation evidence instead of retrying an expired file.
                if self.incident_inflight.load(Ordering::Acquire) {
                    return false;
                }
                m.pending_incident = None;
                m.incidents
                    .retain(|i| now.saturating_sub(i.at) <= RETENTION_MS);
            }
            if let Some(pending) = &m.pending_incident {
                pending.clone()
            } else {
                let incident = Incident {
                    schema_version: 1,
                    at: self.retention_now().max(
                        self.last_incident_at
                            .load(Ordering::Acquire)
                            .saturating_add(1),
                    ),
                    reason,
                    current,
                    samples: m.samples.iter().cloned().collect(),
                };
                self.last_incident_at.store(incident.at, Ordering::Release);
                self.pending_incident_at
                    .store(incident.at, Ordering::Release);
                if m.incidents.len() == MAX_INCIDENTS {
                    m.incidents.pop_front();
                }
                m.incidents.push_back(incident.clone());
                let pending = PendingIncident {
                    incident,
                    record_id: rand::random(),
                };
                m.pending_incident = Some(pending.clone());
                pending
            }
        } else {
            return false;
        };
        let at = value.incident.at;
        let acknowledged = if self.durable_incident_at.load(Ordering::Acquire) == at
            && self.retained_incident.load(Ordering::Acquire)
            && self.retention_now().saturating_sub(at) <= RECOVERY_PROOF_MAX_AGE_MS
        {
            true
        } else {
            // A timeout leaves the writer owning this exact record. Do not queue
            // duplicates while it is busy, or create new memory incidents on retry.
            if self
                .incident_inflight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return false;
            }
            let (ack, wait) = tokio::sync::oneshot::channel();
            let sent = self
                .writer
                .as_ref()
                .is_some_and(|w| w.try_send(WriteJob::Incident(Box::new(value), ack)).is_ok());
            if !sent {
                self.incident_inflight.store(false, Ordering::Release);
            }
            self.observe_write(sent, wait).await
        };
        if acknowledged {
            if let Ok(mut m) = self.memory.try_lock() {
                if m.pending_incident
                    .as_ref()
                    .is_some_and(|p| p.incident.at == at)
                {
                    m.pending_incident = None;
                }
            }
        }
        acknowledged
    }
    pub(crate) fn incident_acknowledged_for(&self, generation: u64) -> bool {
        let durable = self.durable_incident_at.load(Ordering::Acquire);
        self.retained_incident.load(Ordering::Acquire)
            && durable != 0
            && self.retention_now().saturating_sub(durable) <= RECOVERY_PROOF_MAX_AGE_MS
            && self.pending_incident_at.load(Ordering::Acquire) == durable
            && self.durable_incident_generation.load(Ordering::Acquire) == generation
    }
    pub(crate) async fn acquire_recovery_proof(&self, generation: u64) -> Option<RecoveryProof> {
        let (ack, wait) = tokio::sync::oneshot::channel();
        let sent = self.writer.as_ref().is_some_and(|writer| {
            writer
                .try_send(WriteJob::AcquireRecoveryProof { generation, ack })
                .is_ok()
        });
        if sent {
            if let Ok(Ok(lease)) =
                tokio::time::timeout(std::time::Duration::from_secs(2), wait).await
            {
                // Missing/expired proof is distinct from unhealthy storage.
                return lease;
            }
        }
        self.storage_available.store(false, Ordering::Release);
        None
    }
    #[cfg(test)]
    pub(crate) async fn fail_next_incident_for_test(&self) {
        let (ack, wait) = tokio::sync::oneshot::channel();
        assert!(self
            .writer
            .as_ref()
            .unwrap()
            .try_send(WriteJob::FailNextIncident(ack))
            .is_ok());
        wait.await.unwrap();
    }
    #[cfg(test)]
    pub(crate) async fn pause_writer_for_test(&self) -> SyncSender<()> {
        let (wait, release) = self.queue_pause_writer_for_test();
        wait.await.unwrap();
        release
    }
    #[cfg(test)]
    pub(crate) fn queue_pause_writer_for_test(
        &self,
    ) -> (tokio::sync::oneshot::Receiver<()>, SyncSender<()>) {
        let (ready, wait) = tokio::sync::oneshot::channel();
        let (release, blocked) = sync_channel(1);
        assert!(self
            .writer
            .as_ref()
            .unwrap()
            .try_send(WriteJob::PauseWriter(ready, blocked))
            .is_ok());
        (wait, release)
    }
    #[cfg(test)]
    pub(crate) fn hold_memory_for_test(&self) -> impl Drop + '_ {
        self.memory.lock().unwrap()
    }
    async fn observe_write(&self, sent: bool, wait: tokio::sync::oneshot::Receiver<bool>) -> bool {
        if sent {
            if let Ok(Ok(ok)) = tokio::time::timeout(std::time::Duration::from_secs(2), wait).await
            {
                // The writer publishes actual I/O health. False can also mean the
                // incident was intentionally pruned, which is not a disk failure.
                return ok;
            }
        }
        self.storage_available.store(false, Ordering::Release);
        false
    }

    pub(crate) async fn save_budget(&self, mut budget: Budget) -> bool {
        {
            // Mutations use a separate, short-held lock; exports never hold it.
            let Ok(mut pending) = self.budget.lock() else {
                return false;
            };
            if budget.revision < pending.value.revision {
                return false;
            }
            if budget.suspended {
                self.suspension.store(true, Ordering::Release);
            }
            budget.suspended |= self.suspended();
            pending.value = budget.clone();
            pending.dirty = true;
        }
        self.recovery_count
            .store(budget.recovery_count, Ordering::Release);
        self.write_budget(budget).await
    }
    async fn write_budget(&self, budget: Budget) -> bool {
        let (ack, wait) = tokio::sync::oneshot::channel();
        let sent = self
            .writer
            .as_ref()
            .is_some_and(|w| w.try_send(WriteJob::Budget(budget, ack)).is_ok());
        self.observe_write(sent, wait).await
    }
    pub(crate) async fn suspend(&self) {
        // This latch is authoritative before any lock, observer or persistence.
        self.suspension.store(true, Ordering::Release);
        self.set_state(HealthState::Suspended);
        let budget = {
            let Ok(mut pending) = self.budget.lock() else {
                return;
            };
            if !pending.value.suspended {
                pending.value.suspended = true;
                pending.value.revision = pending.value.revision.saturating_add(1);
            }
            pending.dirty = true;
            pending.value.clone()
        };
        self.write_budget(budget).await;
    }
    pub(crate) fn clear_suspension(&self) {
        let Ok(mut pending) = self.budget.lock() else {
            return;
        };
        if self.suspended() || pending.value.suspended {
            pending.value.suspended = false;
            pending.value.revision = pending.value.revision.saturating_add(1);
            pending.dirty = true;
            self.suspension.store(false, Ordering::Release);
            let (ack, _) = tokio::sync::oneshot::channel();
            let sent = self.writer.as_ref().is_some_and(|w| {
                w.try_send(WriteJob::Budget(pending.value.clone(), ack))
                    .is_ok()
            });
            if !sent {
                self.storage_available.store(false, Ordering::Release);
            }
        }
    }
}

/// Linux operations use the pinned directory descriptor, including retention deletion.
/// No arbitrary caller paths enter record names, and immutable records use create_new.
struct PrivateDirectory {
    _handle: File,
    path: PathBuf,
    protected: Option<ProtectedIncident>,
    #[cfg(test)]
    retention_clock: Arc<AtomicU64>,
}
impl PrivateDirectory {
    fn open(path: &Path) -> io::Result<Self> {
        let builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        match builder.create(path) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Open the directory itself, including junction/reparse inspection below.
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
            options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
        }
        let handle = options.open(path)?;
        let metadata = handle.metadata()?;
        if !metadata.is_dir() || std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid takes no pointers and only reads the process effective UID.
            if metadata.mode() & 0o777 != 0o700 || metadata.uid() != unsafe { libc::geteuid() } {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
        }
        #[cfg(target_os = "linux")]
        let path = {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", handle.as_raw_fd()))
        };
        #[cfg(not(target_os = "linux"))]
        let path = path.to_owned();
        Ok(Self {
            _handle: handle,
            path,
            protected: None,
            #[cfg(test)]
            retention_clock: Arc::new(AtomicU64::new(0)),
        })
    }
    fn entries(&self) -> io::Result<Vec<(String, u64)>> {
        let mut entries = Vec::new();
        for (index, entry) in std::fs::read_dir(&self.path)?.take(1025).enumerate() {
            if index >= 1024 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if entries.len() >= 1024 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if valid_name(&name) {
                let metadata = std::fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                if metadata.is_file() {
                    entries.push((name, metadata.len()));
                }
            }
        }
        Ok(entries)
    }
    fn read<T: serde::de::DeserializeOwned>(&self, name: &str) -> io::Result<T> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut file = options.open(self.path.join(name))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_FILE {
            return Err(io::ErrorKind::InvalidData.into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid takes no pointers and only reads the process effective UID.
            if metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_FILE + 1)
            .read_to_end(&mut bytes)?;
        serde_json::from_slice(&bytes).map_err(|_| io::ErrorKind::InvalidData.into())
    }
    fn load(&self) -> (VecDeque<Incident>, Budget, bool) {
        let Ok(mut entries) = self.entries() else {
            return (
                VecDeque::new(),
                Budget {
                    suspended: true,
                    ..Budget::default()
                },
                false,
            );
        };
        entries.sort_by(|a, b| b.0.cmp(&a.0));
        let mut incident_count = 0;
        let mut budget_count = 0;
        entries.retain(|(name, _)| {
            if name.starts_with("incident-") {
                incident_count += 1;
                incident_count <= MAX_INCIDENTS
            } else {
                budget_count += 1;
                budget_count <= 2
            }
        });
        let mut incidents = Vec::new();
        let mut budget = Budget::default();
        let mut valid = true;
        for (name, _) in entries {
            if name.starts_with("incident-") {
                match self.read::<Incident>(&name) {
                    Ok(i) if i.valid() => incidents.push(i),
                    _ => valid = false,
                }
            } else if name.starts_with("budget-") {
                match self.read::<Budget>(&name) {
                    Ok(b) if b.attempts.len() <= 3 => {
                        if b.revision >= budget.revision {
                            budget = b;
                        }
                    }
                    _ => {
                        valid = false;
                        budget.suspended = true;
                    }
                }
            }
        }
        incidents.sort_by_key(|i| i.at);
        incidents.retain(|i| epoch_ms().saturating_sub(i.at) <= RETENTION_MS);
        let start = incidents.len().saturating_sub(MAX_INCIDENTS);
        let incidents = incidents.drain(start..).collect();
        if !valid {
            budget.suspended = true;
        }
        (incidents, budget, valid)
    }
    fn write_incident(
        &self,
        value: &PendingIncident,
        #[cfg(test)] fail_next: &mut bool,
    ) -> io::Result<()> {
        #[cfg(test)]
        if std::mem::take(fail_next) {
            return Err(io::ErrorKind::StorageFull.into());
        }
        self.write_record_id(
            "incident",
            value.incident.at,
            value.record_id,
            &value.incident,
        )
    }
    fn write_record(&self, prefix: &str, order: u64, value: &impl Serialize) -> io::Result<()> {
        self.write_record_id(prefix, order, rand::random(), value)
    }
    fn persist_pending_budget(&self, pending: &Mutex<PendingBudget>, available: &AtomicBool) {
        let value = pending
            .lock()
            .ok()
            .and_then(|p| p.dirty.then(|| p.value.clone()));
        if let Some(value) = value {
            available.store(self.persist_budget(pending, &value), Ordering::Release);
        }
    }
    fn persist_budget(&self, pending: &Mutex<PendingBudget>, value: &Budget) -> bool {
        let ok = self
            .write_record("budget", value.revision, value)
            .and_then(|_| self.prune())
            .is_ok();
        if ok {
            if let Ok(mut pending) = pending.lock() {
                if pending.value.revision == value.revision {
                    pending.dirty = false;
                }
            }
        }
        ok
    }
    fn write_record_id(
        &self,
        prefix: &str,
        order: u64,
        record_id: u64,
        value: &impl Serialize,
    ) -> io::Result<()> {
        let bytes = serde_json::to_vec(value).map_err(|_| io::ErrorKind::InvalidData)?;
        if bytes.len() as u64 > MAX_FILE {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let name = format!("{prefix}-{:016x}-{:016x}.json", order, record_id);
        let path = self.path.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                // Retry the same immutable incident after a prune/observer failure.
                // Read uses the same ownership, mode, link and size validation.
                let existing: Value = self.read(path.file_name().unwrap().to_str().unwrap())?;
                if existing
                    != serde_json::to_value(value).map_err(|_| io::ErrorKind::InvalidData)?
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                options.create_new(false);
                options.open(&path)?.sync_all()?;
                return self.sync_directory();
            }
            Err(error) => return Err(error),
        };
        if let Err(e) = file
            .write_all(&bytes)
            .and_then(|_| file.sync_all())
            .and_then(|_| self.sync_directory())
        {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        Ok(())
    }
    fn sync_directory(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            self._handle.sync_all()
        }
        // Windows directory handles cannot be flushed through std::fs. The file itself
        // is synced above; creation inherits the app's private state-directory ACL.
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
    fn retention_now(&self) -> u64 {
        #[cfg(test)]
        {
            let now = self.retention_clock.load(Ordering::Acquire);
            if now != 0 {
                return now;
            }
        }
        epoch_ms()
    }
    fn acquire_recovery_proof(
        &mut self,
        proof: Option<(u64, u64)>,
        retained: &AtomicBool,
    ) -> io::Result<Option<RecoveryProof>> {
        if self
            .protected
            .as_ref()
            .is_some_and(|p| p.active.load(Ordering::Acquire))
        {
            return Ok(None);
        }
        self.refresh_retained(proof, retained)?;
        let Some((at, id)) = proof else {
            return Ok(None);
        };
        if !retained.load(Ordering::Acquire)
            || self.retention_now().saturating_sub(at) > RECOVERY_PROOF_MAX_AGE_MS
        {
            return Ok(None);
        }
        let active = Arc::new(AtomicBool::new(true));
        self.protected = Some(ProtectedIncident {
            record_name: format!("incident-{at:016x}-{id:016x}.json"),
            active: active.clone(),
        });
        Ok(Some(RecoveryProof { active }))
    }
    fn refresh_retained(&self, proof: Option<(u64, u64)>, retained: &AtomicBool) -> io::Result<()> {
        let result = proof
            .map(|(at, id)| {
                let name = format!("incident-{at:016x}-{id:016x}.json");
                match std::fs::symlink_metadata(self.path.join(name)) {
                    Ok(metadata) => {
                        if !metadata.is_file() || metadata.len() > MAX_FILE {
                            return Err(io::ErrorKind::InvalidData.into());
                        }
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            // SAFETY: geteuid only reads the process effective UID.
                            if metadata.mode() & 0o777 != 0o600
                                || metadata.nlink() != 1
                                || metadata.uid() != unsafe { libc::geteuid() }
                            {
                                return Err(io::ErrorKind::PermissionDenied.into());
                            }
                        }
                        Ok(self.retention_now().saturating_sub(at) <= RETENTION_MS)
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                    Err(error) => Err(error),
                }
            })
            .transpose();
        retained.store(matches!(result, Ok(Some(true))), Ordering::Release);
        result.map(|_| ())
    }
    fn prune(&self) -> io::Result<()> {
        let mut entries = self.entries()?;
        entries.sort_by(|a, b| b.0.cmp(&a.0));
        // Reserve the protected record's slot/bytes before considering other files,
        // including when it is oldest or the wall clock jumps past its TTL.
        let protected = self
            .protected
            .as_ref()
            .filter(|p| p.active.load(Ordering::Acquire))
            .map(|p| p.record_name.as_str());
        let protected_size = entries
            .iter()
            .find(|(name, _)| Some(name.as_str()) == protected)
            .map(|(_, len)| *len);
        let mut count = usize::from(protected_size.is_some());
        let mut size = protected_size.unwrap_or(0);
        let mut budget_count = 0;
        for (name, len) in entries {
            if Some(name.as_str()) == protected {
                continue;
            }
            let keep = if name.starts_with("budget-") {
                budget_count += 1;
                budget_count <= 2 && len <= MAX_FILE
            } else {
                count += 1;
                size += len;
                let at = u64::from_str_radix(&name[9..25], 16).unwrap_or(0);
                count <= MAX_INCIDENTS
                    && size <= MAX_STORAGE
                    && len <= MAX_FILE
                    && self.retention_now().saturating_sub(at) <= RETENTION_MS
            };
            if !keep {
                std::fs::remove_file(self.path.join(name))?;
            }
        }
        Ok(())
    }
}
fn valid_name(name: &str) -> bool {
    let suffix = if let Some(s) = name.strip_prefix("incident-") {
        s
    } else if let Some(s) = name.strip_prefix("budget-") {
        s
    } else {
        return false;
    };
    suffix.len() == 38
        && suffix.as_bytes()[16] == b'-'
        && suffix.ends_with(".json")
        && suffix.as_bytes()[..16]
            .iter()
            .copied()
            .chain(suffix.as_bytes()[17..33].iter().copied())
            .all(|b| b.is_ascii_hexdigit())
}
impl Incident {
    fn valid(&self) -> bool {
        self.schema_version == 1
            && self.samples.len() <= 60
            && self.current.valid()
            && self
                .samples
                .iter()
                .all(|s| s.metrics.live_connections.is_none())
    }
}
impl Current {
    fn valid(&self) -> bool {
        self.service_version.len() <= 32
            && self
                .service_version
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'.')
            && self
                .config
                .as_ref()
                .is_none_or(|c| c.listen_ips.len() <= 64)
            && self
                .metrics
                .live_connections
                .as_ref()
                .is_none_or(|c| c.len() <= 256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observer(root: &Path) -> Arc<Diagnostics> {
        Diagnostics::new(
            root.join("diagnostics"),
            Arc::new(Stats::default()),
            &Settings::default(),
        )
    }
    #[tokio::test]
    async fn diagnostics_exports_allowlist_and_retains_incident_after_restart() {
        let root = tempfile::tempdir().unwrap();
        let settings = Settings {
            proxy_username: "PRIVACY_USERNAME_SENTINEL".into(),
            proxy_password: "PRIVACY_PASSWORD_SENTINEL".into(),
            listen_ips: vec!["192.168.1.23".into(), "PRIVACY_DOMAIN_SENTINEL".into()],
            allow_domains: vec!["PRIVACY_DOMAIN_SENTINEL".into()],
            https_inspect_hosts: vec!["PRIVACY_CA_SENTINEL".into()],
            ..Settings::default()
        };
        let stats = Arc::new(Stats::default());
        let id = stats.begin_activity(
            "192.168.1.23".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
        );
        stats.describe_activity(id, "private-host-sentinel.example", "http");
        assert_eq!(
            stats.snapshot().activity[0].host,
            "private-host-sentinel.example"
        );
        stats.activity_error(id, "PRIVACY_ERROR_SENTINEL");
        stats.listener_runtime_error("PRIVACY_ERROR_SENTINEL".into());
        let diagnostics = Diagnostics::new(root.path().join("diagnostics"), stats, &settings);
        for _ in 0..100 {
            diagnostics.sample(0, ProbeResult::Failed, Metrics::default());
        }
        diagnostics
            .incident(IncidentReason::LocalProbeFailures)
            .await;
        let exported = diagnostics.export();
        assert_eq!(exported["samples"].as_array().unwrap().len(), 60);
        assert_eq!(exported["incidents"].as_array().unwrap().len(), 1);
        let text = exported.to_string();
        for sentinel in [
            "PRIVACY_USERNAME_SENTINEL",
            "PRIVACY_PASSWORD_SENTINEL",
            "PRIVACY_DOMAIN_SENTINEL",
            "PRIVACY_URL_SENTINEL",
            "private-host-sentinel.example",
            "PRIVACY_ERROR_SENTINEL",
            "PRIVACY_CA_SENTINEL",
        ] {
            assert!(!text.contains(sentinel));
        }
        assert!(diagnostics.status()["storageAvailable"].as_bool().unwrap());
        let reloaded = observer(root.path());
        assert_eq!(reloaded.export()["incidents"].as_array().unwrap().len(), 1);
        assert!(reloaded.status()["lastIncidentAt"].as_u64().is_some());
    }
    #[test]
    fn diagnostics_try_lock_export_marks_unavailable_without_waiting() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        let _config = diagnostics.config.lock().unwrap();
        let _memory = diagnostics.memory.lock().unwrap();
        let started = std::time::Instant::now();
        let export = diagnostics.export();
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        assert_eq!(export["current"]["configAvailable"], false);
        assert_eq!(export["retainedAvailable"], false);
        assert_eq!(diagnostics.status()["enabled"], true);
    }
    #[tokio::test]
    async fn diagnostics_disk_failure_preserves_memory_and_blocks_budget_recovery() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("diagnostics"), b"foreign file").unwrap();
        let diagnostics = observer(root.path());
        diagnostics
            .incident(IncidentReason::LocalProbeFailures)
            .await;
        assert_eq!(
            diagnostics.export()["incidents"].as_array().unwrap().len(),
            1
        );
        assert_eq!(diagnostics.status()["storageAvailable"], false);
        let mut budget = Budget::default();
        budget.record(epoch_ms());
        assert!(!diagnostics.save_budget(budget).await);
        assert_eq!(
            std::fs::read(root.path().join("diagnostics")).unwrap(),
            b"foreign file"
        );
    }
    #[tokio::test]
    async fn diagnostics_private_files_and_retention_are_bounded() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        for _ in 0..14 {
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await;
        }
        assert_eq!(
            diagnostics.export()["incidents"].as_array().unwrap().len(),
            10
        );
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        let entries = storage.entries().unwrap();
        assert_eq!(entries.len(), 10);
        assert!(entries.iter().all(|(_, n)| *n <= MAX_FILE));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(root.path().join("diagnostics"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            for (name, _) in entries {
                assert_eq!(
                    std::fs::metadata(storage.path.join(name))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        let incident = diagnostics.memory.lock().unwrap().incidents[0].clone();
        storage
            .write_record("incident", epoch_ms() - RETENTION_MS - 1, &incident)
            .unwrap();
        storage.prune().unwrap();
        assert!(
            storage
                .entries()
                .unwrap()
                .iter()
                .all(|(n, _)| u64::from_str_radix(&n[9..25], 16).unwrap()
                    >= epoch_ms() - RETENTION_MS)
        );
        let oversized = "x".repeat(MAX_FILE as usize);
        assert!(storage
            .write_record("incident", epoch_ms(), &oversized)
            .is_err());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn diagnostics_symlinks_and_hardlinks_are_never_followed_or_clobbered() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let foreign = root.path().join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        symlink(&foreign, root.path().join("diagnostics")).unwrap();
        let diagnostics = observer(root.path());
        diagnostics
            .incident(IncidentReason::LocalProbeFailures)
            .await;
        assert_eq!(diagnostics.status()["storageAvailable"], false);
        assert_eq!(std::fs::read_dir(&foreign).unwrap().count(), 0);
        std::fs::remove_file(root.path().join("diagnostics")).unwrap();
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        let protected = root.path().join("protected");
        std::fs::write(&protected, b"DO_NOT_CLOBBER").unwrap();
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o600)).unwrap();
        let name = "budget-0000000000000001-0000000000000001.json";
        symlink(&protected, storage.path.join(name)).unwrap();
        assert!(!storage.load().2);
        assert!(storage.load().1.suspended);
        assert!(storage.read::<Budget>(name).is_err());
        assert!(storage.prune().is_err());
        std::fs::remove_file(storage.path.join(name)).unwrap();
        std::fs::hard_link(&protected, storage.path.join(name)).unwrap();
        assert!(storage.read::<Budget>(name).is_err());
        assert_eq!(std::fs::read(protected).unwrap(), b"DO_NOT_CLOBBER");
    }
    #[tokio::test]
    async fn diagnostics_budget_survives_restart_and_same_millisecond_revisions() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        let mut budget = Budget::default();
        budget.record(epoch_ms());
        assert!(diagnostics.save_budget(budget.clone()).await);
        budget.suspended = true;
        budget.revision += 1;
        assert!(diagnostics.save_budget(budget.clone()).await);
        diagnostics.clear_suspension();
        let mut budget = diagnostics.budget().unwrap();
        budget.record(epoch_ms() + 600_000);
        assert!(diagnostics.save_budget(budget.clone()).await);
        let reloaded = observer(root.path());
        let loaded = reloaded.budget().unwrap();
        assert_eq!(loaded.revision, budget.revision);
        assert_eq!(loaded.recovery_count, 2);
        assert!(!loaded.suspended);
        assert!(!loaded.allows(epoch_ms()));
    }
    #[tokio::test(start_paused = true)]
    async fn diagnostics_writer_timeout_keeps_the_single_queued_mutation_and_memory() {
        let root = tempfile::tempdir().unwrap();
        let mut diagnostics = observer(root.path());
        let (sender, receiver) = sync_channel(2);
        Arc::get_mut(&mut diagnostics).unwrap().writer = Some(sender);
        assert!(
            !diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert_eq!(
            diagnostics.export()["incidents"].as_array().unwrap().len(),
            1
        );
        assert_eq!(diagnostics.status()["storageAvailable"], false);
        let WriteJob::Incident(value, ack) = receiver.try_recv().unwrap() else {
            panic!("one incident write expected")
        };
        assert_eq!(
            value.incident.current.config.as_ref().unwrap().generation,
            0
        );
        assert!(
            ack.send(true).is_err(),
            "only the observer expired; the writer still owns the record"
        );
        assert!(receiver.try_recv().is_err());
        let mut budget = Budget::default();
        budget.record(epoch_ms());
        assert!(!diagnostics.save_budget(budget).await);
        let WriteJob::Budget(value, _) = receiver.try_recv().unwrap() else {
            panic!("one budget write expected")
        };
        assert_eq!(value.recovery_count, 1);
        assert_eq!(diagnostics.budget().unwrap().recovery_count, 1);
    }
    #[tokio::test]
    async fn diagnostics_incident_storage_failure_stays_visible_after_budget_success_and_retries_once(
    ) {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        diagnostics.fail_next_incident_for_test().await;
        assert!(
            !diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        let at = diagnostics.status()["lastIncidentAt"].clone();
        let mut budget = Budget::default();
        budget.record(epoch_ms());
        assert!(diagnostics.save_budget(budget).await);
        assert_eq!(
            diagnostics.export()["incidents"].as_array().unwrap().len(),
            1
        );
        assert_eq!(diagnostics.status()["storageAvailable"], false);
        assert!(!diagnostics.incident_acknowledged_for(0));
        diagnostics.fail_next_incident_for_test().await;
        assert!(
            !diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert_eq!(diagnostics.status()["lastIncidentAt"], at);
        assert_eq!(
            diagnostics.export()["incidents"].as_array().unwrap().len(),
            1
        );
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert!(diagnostics.incident_acknowledged_for(0));
        assert_eq!(diagnostics.status()["storageAvailable"], true);
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        assert_eq!(
            storage
                .entries()
                .unwrap()
                .iter()
                .filter(|(name, _)| name.starts_with("incident-"))
                .count(),
            1
        );
        assert_eq!(
            observer(root.path()).export()["incidents"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    #[tokio::test]
    async fn diagnostics_pending_previous_generation_is_not_current_recovery_evidence() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        diagnostics.fail_next_incident_for_test().await;
        assert!(
            !diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        let mut config = diagnostics.config().unwrap();
        config.generation = 1;
        diagnostics.publish(config);
        // Preserve and finish the original failed report before capturing a new one.
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert!(!diagnostics.incident_acknowledged_for(1));
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert!(diagnostics.incident_acknowledged_for(1));
        assert_eq!(
            diagnostics.export()["incidents"].as_array().unwrap().len(),
            2
        );
        assert!(!observer(root.path()).incident_acknowledged_for(1));
    }
    #[tokio::test]
    async fn diagnostics_retention_refreshes_expired_failed_pending_incident() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        diagnostics.fail_next_incident_for_test().await;
        assert!(
            !diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        let old_at = diagnostics.last_incident_at.load(Ordering::Acquire);
        let fresh_at = old_at + RETENTION_MS + 1;
        diagnostics.set_retention_time_for_test(fresh_at);
        let mut config = diagnostics.config().unwrap();
        config.generation = 7;
        diagnostics.publish(config);
        assert!(!diagnostics.incident_acknowledged_for(7));
        // Another real writer failure must keep recovery blocked even after recapture.
        diagnostics.fail_next_incident_for_test().await;
        assert!(
            !diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert_eq!(
            diagnostics.last_incident_at.load(Ordering::Acquire),
            fresh_at
        );
        assert!(!diagnostics.incident_acknowledged_for(7));
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert!(diagnostics.incident_acknowledged_for(7));
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        let records = storage.entries().unwrap();
        assert_eq!(records.len(), 1);
        let record: Incident = storage.read(&records[0].0).unwrap();
        assert_eq!(record.at, fresh_at);
        assert_eq!(record.current.config.unwrap().generation, 7);
    }
    #[tokio::test]
    async fn diagnostics_retention_queued_expired_write_is_not_ack_or_disk_failure() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        let release = diagnostics.pause_writer_for_test().await;
        let writing = {
            let diagnostics = diagnostics.clone();
            tokio::spawn(async move {
                diagnostics
                    .incident(IncidentReason::LocalProbeFailures)
                    .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !diagnostics.incident_inflight.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let at = diagnostics.last_incident_at.load(Ordering::Acquire);
        diagnostics.set_retention_time_for_test(at + RETENTION_MS + 1);
        release.send(()).unwrap();
        assert!(!writing.await.unwrap());
        assert!(!diagnostics.incident_acknowledged_for(0));
        assert_eq!(diagnostics.status()["storageAvailable"], true);
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        assert!(storage.entries().unwrap().is_empty());
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert!(diagnostics.incident_acknowledged_for(0));
    }
    #[tokio::test]
    async fn diagnostics_retention_five_minute_proof_refreshes_before_runtime_transition() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        let at = diagnostics.last_incident_at.load(Ordering::Acquire);
        diagnostics.set_retention_time_for_test(at + RECOVERY_PROOF_MAX_AGE_MS + 1);
        assert!(!diagnostics.incident_acknowledged_for(0));
        assert!(diagnostics.acquire_recovery_proof(0).await.is_none());
        assert_eq!(diagnostics.status()["storageAvailable"], true);
        // The report is still retained; its age only prevents runtime authorization.
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        assert_eq!(storage.entries().unwrap().len(), 1);
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert!(diagnostics.incident_acknowledged_for(0));
        assert!(diagnostics.last_incident_at.load(Ordering::Acquire) > at);
    }
    #[tokio::test]
    async fn diagnostics_retention_budget_prune_invalidates_ack_without_storage_failure() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert!(diagnostics.incident_acknowledged_for(0));
        let at = diagnostics.last_incident_at.load(Ordering::Acquire);
        diagnostics.set_retention_time_for_test(at + RETENTION_MS + 1);
        assert!(diagnostics.save_budget(diagnostics.budget().unwrap()).await);
        // Returning the observation clock to a fresh age cannot resurrect a deleted proof.
        diagnostics.set_retention_time_for_test(at);
        assert!(!diagnostics.incident_acknowledged_for(0));
        assert_eq!(diagnostics.status()["storageAvailable"], true);
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        assert!(storage
            .entries()
            .unwrap()
            .iter()
            .all(|(name, _)| !name.starts_with("incident-")));
    }
    #[tokio::test]
    async fn diagnostics_recovery_lease_protects_exact_record_across_budget_and_idle_prune() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = Diagnostics::new_with_prune_interval(
            root.path().join("diagnostics"),
            Arc::new(Stats::default()),
            &Settings::default(),
            std::time::Duration::from_millis(50),
        );
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert!(diagnostics.acquire_recovery_proof(1).await.is_none());
        assert_eq!(diagnostics.status()["storageAvailable"], true);
        let lease = diagnostics.acquire_recovery_proof(0).await.unwrap();
        let active = lease.active.clone();
        // Only one protected record is permitted at a time.
        assert!(diagnostics.acquire_recovery_proof(0).await.is_none());
        let at = diagnostics.last_incident_at.load(Ordering::Acquire);
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        let protected_name = storage.entries().unwrap()[0].0.clone();
        let mut old: Incident = storage.read(&protected_name).unwrap();
        diagnostics.set_retention_time_for_test(at + RETENTION_MS + 1);
        assert!(diagnostics.save_budget(diagnostics.budget().unwrap()).await);
        assert!(storage.path.join(&protected_name).is_file());
        assert!(!diagnostics.budget.lock().unwrap().dirty);
        // An unprotected expired file proves the periodic prune actually ran while
        // the lease was active; no new budget or incident job triggers its removal.
        old.at = at - 1;
        storage
            .write_record_id("incident", old.at, 123, &old)
            .unwrap();
        let unprotected_name = format!("incident-{:016x}-{:016x}.json", old.at, 123);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while storage.path.join(&unprotected_name).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(storage.path.join(&protected_name).is_file());
        assert!(active.load(Ordering::Acquire));
        assert_eq!(diagnostics.status()["storageAvailable"], true);
        drop(lease);
        assert!(!active.load(Ordering::Acquire));
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while storage.path.join(&protected_name).exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("released proof must become eligible for idle retention");
        assert_eq!(diagnostics.status()["storageAvailable"], true);
    }
    #[tokio::test]
    async fn diagnostics_recovery_lease_retention_counts_protected_slot_and_bytes() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        let lease = diagnostics.acquire_recovery_proof(0).await.unwrap();
        let at = diagnostics.last_incident_at.load(Ordering::Acquire);
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        let protected_name = storage.entries().unwrap()[0].0.clone();
        // Make the protected file the oldest; it still consumes one of ten slots.
        for _ in 0..12 {
            assert!(
                diagnostics
                    .incident(IncidentReason::LocalProbeFailures)
                    .await
            );
        }
        let entries = storage.entries().unwrap();
        assert_eq!(entries.len(), MAX_INCIDENTS);
        assert!(entries.iter().any(|(name, _)| name == &protected_name));
        assert!(entries.iter().map(|(_, len)| len).sum::<u64>() <= MAX_STORAGE);
        drop(lease);
        diagnostics.set_retention_time_for_test(at + RETENTION_MS + 1000);
        assert!(diagnostics.save_budget(diagnostics.budget().unwrap()).await);
        assert!(!storage.path.join(&protected_name).exists());
    }
    #[tokio::test]
    async fn diagnostics_recovery_lease_dropped_receivers_do_not_orphan_protection() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        // Drop a queued observer before the real writer handles the request.
        let release = diagnostics.pause_writer_for_test().await;
        let (ack, wait) = tokio::sync::oneshot::channel();
        diagnostics
            .writer
            .as_ref()
            .unwrap()
            .try_send(WriteJob::AcquireRecoveryProof { generation: 0, ack })
            .unwrap();
        drop(wait);
        release.send(()).unwrap();
        let lease = diagnostics.acquire_recovery_proof(0).await.unwrap();
        drop(lease);
        // Leave the granted guard in the oneshot buffer. The following writer
        // barrier proves it was granted, then dropping the receiver releases it.
        let (ack, wait) = tokio::sync::oneshot::channel();
        diagnostics
            .writer
            .as_ref()
            .unwrap()
            .try_send(WriteJob::AcquireRecoveryProof { generation: 0, ack })
            .unwrap();
        let release = diagnostics.pause_writer_for_test().await;
        drop(wait);
        release.send(()).unwrap();
        assert!(diagnostics.acquire_recovery_proof(0).await.is_some());
    }
    #[tokio::test]
    async fn diagnostics_recovery_lease_actual_writer_timeout_does_not_leave_a_pin() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        let release = diagnostics.pause_writer_for_test().await;
        let started = std::time::Instant::now();
        assert!(diagnostics.acquire_recovery_proof(0).await.is_none());
        assert!(started.elapsed() >= std::time::Duration::from_secs(2));
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        release.send(()).unwrap();
        let lease = diagnostics.acquire_recovery_proof(0).await.unwrap();
        drop(lease);
        let at = diagnostics.last_incident_at.load(Ordering::Acquire);
        diagnostics.set_retention_time_for_test(at + RETENTION_MS + 1);
        assert!(diagnostics.save_budget(diagnostics.budget().unwrap()).await);
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        assert!(storage
            .entries()
            .unwrap()
            .iter()
            .all(|(name, _)| !name.starts_with("incident-")));
        assert_eq!(diagnostics.status()["storageAvailable"], true);
    }
    #[tokio::test]
    async fn diagnostics_recovery_lease_failed_ack_send_releases_granted_guard() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        let lease = diagnostics.acquire_recovery_proof(0).await.unwrap();
        let active = lease.active.clone();
        let (ack, wait) = tokio::sync::oneshot::channel();
        drop(wait);
        // This is the writer's owned-guard send path if the receiver disappears
        // between is_closed() and send(), after the pin has already been granted.
        let _ = ack.send(Some(lease));
        assert!(!active.load(Ordering::Acquire));
        assert!(diagnostics.acquire_recovery_proof(0).await.is_some());
    }
    #[tokio::test]
    async fn diagnostics_retention_idle_writer_prunes_without_budget_or_new_writes() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = Diagnostics::new_with_prune_interval(
            root.path().join("diagnostics"),
            Arc::new(Stats::default()),
            &Settings::default(),
            std::time::Duration::from_millis(50),
        );
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        let at = diagnostics.last_incident_at.load(Ordering::Acquire);
        diagnostics.set_retention_time_for_test(at + RETENTION_MS + 1);
        assert!(!diagnostics.budget.lock().unwrap().dirty);
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while storage
                .entries()
                .unwrap()
                .iter()
                .any(|(name, _)| name.starts_with("incident-"))
            {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("idle OS writer must enforce retention without any new write");
        diagnostics.set_retention_time_for_test(at);
        assert!(!diagnostics.incident_acknowledged_for(0));
        assert_eq!(diagnostics.status()["storageAvailable"], true);
        assert!(!diagnostics.budget.lock().unwrap().dirty);
    }
    #[tokio::test]
    async fn diagnostics_actual_busy_writer_timeout_does_not_acknowledge_or_duplicate_incident() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        let release = diagnostics.pause_writer_for_test().await;
        // The actual single writer is blocked, rather than a replacement mock sender.
        assert!(
            !diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        assert!(!diagnostics.incident_acknowledged_for(0));
        for _ in 0..3 {
            assert!(
                !diagnostics
                    .incident(IncidentReason::LocalProbeFailures)
                    .await
            );
        }
        assert_eq!(
            diagnostics.export()["incidents"].as_array().unwrap().len(),
            1
        );
        assert_eq!(diagnostics.status()["storageAvailable"], false);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !diagnostics.incident_acknowledged_for(0) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            diagnostics
                .incident(IncidentReason::LocalProbeFailures)
                .await
        );
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        assert_eq!(storage.entries().unwrap().len(), 1);
        assert_eq!(
            diagnostics.export()["incidents"].as_array().unwrap().len(),
            1
        );
    }
    #[tokio::test]
    async fn diagnostics_queue_full_suspension_persists_latest_budget_and_manual_clear_preserves_attempts(
    ) {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        let mut budget = Budget::default();
        budget.record(epoch_ms());
        assert!(diagnostics.save_budget(budget.clone()).await);
        let release = diagnostics.pause_writer_for_test().await;
        // Fill the bounded queue with old mutations. Suspension must not depend
        // on a successful queue insertion, and old queued values must not undo it.
        for _ in 0..2 {
            let (ack, _) = tokio::sync::oneshot::channel();
            diagnostics
                .writer
                .as_ref()
                .unwrap()
                .try_send(WriteJob::Budget(budget.clone(), ack))
                .unwrap();
        }
        let held = diagnostics.hold_memory_for_test();
        diagnostics.suspend().await;
        assert!(diagnostics.suspended());
        assert_eq!(diagnostics.status()["state"], "suspended");
        drop(held);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let loaded = PrivateDirectory::open(&root.path().join("diagnostics"))
                    .unwrap()
                    .load()
                    .1;
                if loaded.suspended && loaded.recovery_count == 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(diagnostics.budget().unwrap().attempts, budget.attempts);
        let held = diagnostics.hold_memory_for_test();
        diagnostics.clear_suspension();
        assert!(!diagnostics.suspended());
        assert_eq!(diagnostics.budget().unwrap().attempts, budget.attempts);
        assert_eq!(diagnostics.budget().unwrap().recovery_count, 1);
        drop(held);
        // A stale suspended mutation cannot relatch after manual clear.
        let mut stale = budget.clone();
        stale.suspended = true;
        assert!(!diagnostics.save_budget(stale).await);
        assert!(!diagnostics.suspended());
        let cleared = diagnostics.budget().unwrap();
        assert!(diagnostics.save_budget(cleared.clone()).await);
        let loaded = observer(root.path()).budget().unwrap();
        assert!(!loaded.suspended);
        assert_eq!(loaded.attempts, budget.attempts);
        assert_eq!(loaded.recovery_count, 1);
    }
    #[tokio::test]
    async fn diagnostics_disconnected_writer_flushes_suspension_not_queued_due_to_capacity() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        let mut budget = Budget::default();
        budget.record(epoch_ms());
        assert!(diagnostics.save_budget(budget.clone()).await);
        let release = diagnostics.pause_writer_for_test().await;
        for _ in 0..2 {
            let (ack, _) = tokio::sync::oneshot::channel();
            diagnostics
                .writer
                .as_ref()
                .unwrap()
                .try_send(WriteJob::Budget(budget.clone(), ack))
                .unwrap();
        }
        diagnostics.suspend().await;
        assert!(diagnostics.suspended());
        drop(diagnostics);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let loaded = PrivateDirectory::open(&root.path().join("diagnostics"))
                    .unwrap()
                    .load()
                    .1;
                if loaded.suspended
                    && loaded.recovery_count == 1
                    && loaded.attempts == budget.attempts
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    #[test]
    fn diagnostics_retry_of_same_durable_record_is_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        let storage = PrivateDirectory::open(&root.path().join("diagnostics")).unwrap();
        let incident = Incident {
            schema_version: 1,
            at: epoch_ms(),
            reason: IncidentReason::LocalProbeFailures,
            current: diagnostics.current(),
            samples: Vec::new(),
        };
        storage
            .write_record_id("incident", incident.at, 123, &incident)
            .unwrap();
        storage
            .write_record_id("incident", incident.at, 123, &incident)
            .unwrap();
        assert_eq!(storage.entries().unwrap().len(), 1);
        assert_eq!(storage.load().0.len(), 1);
    }
    #[test]
    fn diagnostics_busy_incident_memory_is_explicitly_not_captured() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = observer(root.path());
        let _memory = diagnostics.memory.lock().unwrap();
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let future = std::pin::pin!(diagnostics.incident(IncidentReason::LocalProbeFailures));
        assert!(matches!(
            std::future::Future::poll(future, &mut context),
            std::task::Poll::Ready(false)
        ));
    }
    #[test]
    fn diagnostics_generated_name_validation_is_total_on_unicode() {
        assert!(!valid_name(
            "incident-000000000000000é-0000000000000001.json"
        ));
        assert!(!valid_name("incident-../../etc/passwd.json"));
        assert!(valid_name(
            "incident-0000000000000001-0000000000000001.json"
        ));
    }
}
