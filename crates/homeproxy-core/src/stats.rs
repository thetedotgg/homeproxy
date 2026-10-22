use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

#[derive(Default)]
pub struct Stats {
    total_requests: AtomicU64,
    blocked_requests: AtomicU64,
    cache_hits: AtomicU64,
    cache_bytes_saved: AtomicU64,
    compressed_images: AtomicU64,
    compression_bytes_saved: AtomicU64,
    connect_tunnels: AtomicU64,
    socks5_connections: AtomicU64,
    authenticated_external_requests: AtomicU64,
    successful_external_requests: AtomicU64,
    inspection_fail_open_remembered: AtomicU64,
    clients: Mutex<HashMap<IpAddr, u64>>,
    traffic: Mutex<TrafficState>,
    live: Mutex<LiveState>,
    runtime: Mutex<Option<RuntimeAccounting>>,
    profile_buckets: Mutex<HashMap<String, crate::traffic::Buckets>>,
}

const MAX_LIVE_CONNECTIONS: usize = 256;
const MAX_LISTENER_ERROR_BYTES: usize = 256;
/// Distinct bypass reason codes kept in the aggregate, including the overflow bucket.
const MAX_CACHE_BYPASS_REASONS: usize = 64;
const MAX_CACHE_BYPASS_REASON_BYTES: usize = 64;
const CACHE_BYPASS_REASON_OTHER: &str = "other";
const CACHE_BYPASS_REASON_UNSPECIFIED: &str = "unspecified";

/// Reason codes are fixed internal labels. Anything else collapses into a
/// bounded bucket so the aggregate can never carry host, URL or header data.
fn cache_bypass_reason_key(reasons: &BTreeMap<String, u64>, reason: Option<&str>) -> String {
    let reason = reason.unwrap_or(CACHE_BYPASS_REASON_UNSPECIFIED);
    let valid = !reason.is_empty()
        && reason.len() <= MAX_CACHE_BYPASS_REASON_BYTES
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid {
        return CACHE_BYPASS_REASON_OTHER.into();
    }
    // Reserve one slot for the overflow bucket.
    if reasons.contains_key(reason) || reasons.len() < MAX_CACHE_BYPASS_REASONS - 1 {
        reason.into()
    } else {
        CACHE_BYPASS_REASON_OTHER.into()
    }
}

#[derive(Default)]
struct LiveState {
    connections: HashMap<u64, LiveConnection>,
    connection_limit: usize,
    connection_limit_per_peer: usize,
    idle_connections_closed: u64,
    keepalive_configuration_failures: u64,
    listener_runtime_error: Option<String>,
    listener_accept_errors: BTreeMap<SocketAddr, String>,
    listener_runtime_errors: u64,
}

impl LiveState {
    fn listener_error(&self) -> Option<String> {
        self.listener_runtime_error.clone().or_else(|| {
            self.listener_accept_errors
                .first_key_value()
                .map(|(_, error)| error.clone())
        })
    }
}

fn bounded_listener_error(error: &str) -> String {
    let mut end = error.len().min(MAX_LISTENER_ERROR_BYTES);
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    error[..end].to_owned()
}

struct LiveConnection {
    owner: Arc<()>,
    peer: IpAddr,
    protocol: &'static str,
    started: tokio::time::Instant,
    progress: tokio::time::Instant,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveConnectionSnapshot {
    pub id: u64,
    pub peer_ip: IpAddr,
    pub protocol: &'static str,
    pub age_ms: u64,
    pub idle_ms: u64,
}

/// Keep this guard in the shared connection permit, including upgraded relays.
/// Historical activity completion does not establish that the socket is closed.
pub struct ConnectionGuard {
    stats: Arc<Stats>,
    registration: Option<(u64, Arc<()>)>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let Some((id, owner)) = self.registration.take() else {
            return;
        };
        let mut live = self.stats.live.lock().unwrap_or_else(|e| e.into_inner());
        if live
            .connections
            .get(&id)
            .is_some_and(|entry| Arc::ptr_eq(&entry.owner, &owner))
        {
            live.connections.remove(&id);
        }
    }
}

fn elapsed_ms(now: tokio::time::Instant, earlier: tokio::time::Instant) -> u64 {
    now.saturating_duration_since(earlier)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

impl Stats {
    /// A separate allowlisted observer: never waits for traffic/history/accounting locks.
    pub(crate) fn diagnostic_metrics(
        &self,
        idle_seconds: u32,
        include_live: bool,
    ) -> crate::diagnostics::Metrics {
        use crate::diagnostics::{Connection, Metrics, Protocol};
        let mut result = Metrics {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            blocked_requests: self.blocked_requests.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            successful_external_requests: self.successful_external_requests.load(Ordering::Relaxed),
            ..Metrics::default()
        };
        if let Ok(live) = self.live.try_lock() {
            result.live_available = true;
            result.active_connections = live.connections.len();
            result.connection_limit = live.connection_limit;
            result.connection_limit_per_peer = live.connection_limit_per_peer;
            result.idle_connections_closed = live.idle_connections_closed;
            result.keepalive_configuration_failures = live.keepalive_configuration_failures;
            result.listener_runtime_errors = live.listener_runtime_errors;
            result.listener_error_present =
                live.listener_runtime_error.is_some() || !live.listener_accept_errors.is_empty();
            let now = tokio::time::Instant::now();
            let mut connections = Vec::new();
            for (&id, entry) in live.connections.iter().take(MAX_LIVE_CONNECTIONS) {
                let idle_ms = elapsed_ms(now, entry.progress);
                result.loopback_connections +=
                    usize::from(entry.peer == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
                if entry.protocol != "socks5-udp" && idle_ms > (u64::from(idle_seconds) + 30) * 1000
                {
                    result.over_age_ids.insert(id);
                }
                if include_live {
                    connections.push(Connection {
                        id,
                        peer_ip: entry.peer,
                        protocol: Protocol::from_label(entry.protocol),
                        age_ms: elapsed_ms(now, entry.started),
                        idle_ms,
                    });
                }
            }
            result.over_age_idle_connections = result.over_age_ids.len();
            if include_live {
                connections.sort_unstable_by_key(|entry| entry.id);
                result.live_connections = Some(connections);
            }
        }
        // Only test availability; never read or clone history/accounting data. Admission
        // registers telemetry after begin_activity, so a busy accounting lock may hide
        // an already-reserved permit from the live registry.
        result.accounting_available = self.runtime.try_lock().is_ok();
        if let Ok(traffic) = self.traffic.try_lock() {
            result.traffic_available = true;
            result.upload_bytes = traffic.total.up;
            result.download_bytes = traffic.total.down;
            result.rejected_connections = traffic.rejected_connections;
        }
        result
    }

    /// IDs come from begin_activity. Refusing telemetry admission on misuse
    /// never gives the returned guard ownership of an existing registration.
    pub fn track_connection(self: &Arc<Self>, id: u64, peer: IpAddr) -> ConnectionGuard {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        let registration = if live.connections.len() < MAX_LIVE_CONNECTIONS {
            if let std::collections::hash_map::Entry::Vacant(entry) = live.connections.entry(id) {
                let owner = Arc::new(());
                let now = tokio::time::Instant::now();
                entry.insert(LiveConnection {
                    owner: owner.clone(),
                    peer,
                    protocol: "tcp",
                    started: now,
                    progress: now,
                });
                Some((id, owner))
            } else {
                None
            }
        } else {
            None
        };
        ConnectionGuard {
            stats: self.clone(),
            registration,
        }
    }

    /// Call only after positive socket I/O, never on a readiness poll or EOF.
    pub fn connection_progress(&self, id: u64) {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = live.connections.get_mut(&id) {
            entry.progress = tokio::time::Instant::now();
        }
    }

    pub fn connection_protocol(&self, id: u64, protocol: &'static str) {
        // Only fixed protocol labels belong in live telemetry, never host data.
        let protocol = match protocol {
            "tcp" | "http" | "connect" | "socks5" | "socks5-udp" | "websocket" | "inspect" => {
                protocol
            }
            _ => "tcp",
        };
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = live.connections.get_mut(&id) {
            entry.protocol = protocol;
        }
    }

    pub fn connection_limits(&self, global: usize, per_peer: usize) {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.connection_limit = global;
        live.connection_limit_per_peer = per_peer;
    }

    pub fn connection_idle_closed(&self, id: u64) {
        {
            let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            live.idle_connections_closed = live.idle_connections_closed.saturating_add(1);
        }
        self.activity_error(id, "tunnel-idle-timeout");
    }

    pub fn keepalive_configuration_failed(&self) {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.keepalive_configuration_failures =
            live.keepalive_configuration_failures.saturating_add(1);
    }

    /// The caller supplies an OS-only diagnostic, without addresses or secrets.
    pub fn listener_runtime_error(&self, error: String) {
        // Do not retain the caller's potentially oversized String allocation.
        let error = bounded_listener_error(&error);
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.listener_runtime_error = Some(error);
        live.listener_runtime_errors = live.listener_runtime_errors.saturating_add(1);
    }

    pub(crate) fn listener_error(&self) -> Option<String> {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .listener_error()
    }

    pub(crate) fn listener_accept_error(&self, listener: SocketAddr, error: String) {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        // Production has at most 66 TCP listeners; keep diagnostics bounded even on misuse.
        if live.listener_accept_errors.len() < MAX_LIVE_CONNECTIONS
            || live.listener_accept_errors.contains_key(&listener)
        {
            live.listener_accept_errors
                .insert(listener, bounded_listener_error(&error));
        }
        live.listener_runtime_errors = live.listener_runtime_errors.saturating_add(1);
    }

    pub(crate) fn listener_accept_recovered(&self, listener: SocketAddr) {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .listener_accept_errors
            .remove(&listener);
    }

    /// Starting a new listener set or explicitly retiring it clears current errors.
    pub fn listener_recovered(&self) {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.listener_runtime_error = None;
        live.listener_accept_errors.clear();
    }
}

impl Stats {
    pub fn request(&self, _peer: IpAddr) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn client_seen(&self, peer: IpAddr) {
        let last_seen_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or_default();
        if let Ok(mut clients) = self.clients.lock() {
            if clients.len() >= 1024 && !clients.contains_key(&peer) {
                if let Some(oldest) = clients
                    .iter()
                    .min_by_key(|(_, seen)| **seen)
                    .map(|(ip, _)| *ip)
                {
                    clients.remove(&oldest);
                }
            }
            clients.insert(peer, last_seen_unix_ms);
        }
    }

    pub fn blocked(&self) {
        self.blocked_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn cache_saved_bytes(&self, bytes: u64) {
        self.cache_bytes_saved.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn cache_hit(&self, bytes: u64) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        self.cache_bytes_saved.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn compressed(&self, bytes_saved: u64) {
        self.compressed_images.fetch_add(1, Ordering::Relaxed);
        self.compression_bytes_saved
            .fetch_add(bytes_saved, Ordering::Relaxed);
    }

    pub fn tunnel(&self) {
        self.connect_tunnels.fetch_add(1, Ordering::Relaxed);
    }

    pub fn socks5_connection(&self) {
        self.socks5_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn authenticated_external_request(&self) {
        self.authenticated_external_requests
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn successful_external_request(&self) {
        self.successful_external_requests
            .fetch_add(1, Ordering::SeqCst);
    }

    /// An HTTPS inspection failure was remembered and later connections to the
    /// host fall back to a raw tunnel. Carries no host data; saturates.
    pub fn inspection_fail_open_remembered(&self) {
        let _ = self.inspection_fail_open_remembered.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_add(1)),
        );
    }

    /// Reset only the displayed transfer totals. Keep cumulative meters for
    /// diagnostics and their rate samples, client accounting and history intact.
    pub fn reset_transfer_stats(&self) {
        let mut traffic = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        traffic.transfer_baseline = (traffic.total.up, traffic.total.down);
        traffic.transfer_stats_reset_unix_ms = Some(unix_ms());
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        // Release the live lock before reading traffic/accounting state. Socket
        // lifetime is independent of the bounded historical activity list.
        let (
            live_connections,
            connection_limit,
            connection_limit_per_peer,
            idle_connections_closed,
            keepalive_configuration_failures,
            listener_runtime_error,
            listener_runtime_errors,
        ) = {
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            let now = tokio::time::Instant::now();
            let mut connections = live
                .connections
                .iter()
                .map(|(&id, entry)| LiveConnectionSnapshot {
                    id,
                    peer_ip: entry.peer,
                    protocol: entry.protocol,
                    age_ms: elapsed_ms(now, entry.started),
                    idle_ms: elapsed_ms(now, entry.progress),
                })
                .collect::<Vec<_>>();
            connections.sort_unstable_by_key(|entry| entry.id);
            (
                connections,
                live.connection_limit,
                live.connection_limit_per_peer,
                live.idle_connections_closed,
                live.keepalive_configuration_failures,
                live.listener_error(),
                live.listener_runtime_errors,
            )
        };
        let mut clients = self
            .clients
            .lock()
            .map(|clients| {
                clients
                    .iter()
                    .map(|(ip, last_seen_unix_ms)| ClientSnapshot {
                        ip: *ip,
                        last_seen_unix_ms: *last_seen_unix_ms,
                        ..ClientSnapshot::default()
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        clients.sort_by(|left, right| {
            right
                .last_seen_unix_ms
                .cmp(&left.last_seen_unix_ms)
                .then_with(|| left.ip.to_string().cmp(&right.ip.to_string()))
        });
        let mut traffic = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        let (upload_bytes_per_second, download_bytes_per_second) = traffic.total.rates();
        for client in &mut clients {
            if let Some(meter) = traffic.clients.get_mut(&client.ip) {
                client.upload_bytes = meter.up;
                client.download_bytes = meter.down;
                (
                    client.upload_bytes_per_second,
                    client.download_bytes_per_second,
                ) = meter.rates();
            }
        }
        let activity = traffic
            .activity
            .iter_mut()
            .map(|entry| {
                let (up, down) = entry.meter.rates();
                entry.snapshot.upload_bytes_per_second = up;
                entry.snapshot.download_bytes_per_second = down;
                entry.snapshot.clone()
            })
            .collect();
        let unique_clients = clients.len() as u64;
        let cache_bytes_saved = self.cache_bytes_saved.load(Ordering::Relaxed);
        let compression_bytes_saved = self.compression_bytes_saved.load(Ordering::Relaxed);
        StatsSnapshot {
            active_connections: live_connections.len() as u64,
            connection_limit,
            connection_limit_per_peer,
            live_connections,
            idle_connections_closed,
            keepalive_configuration_failures,
            listener_runtime_error,
            listener_runtime_errors,
            rejected_connections: traffic.rejected_connections,
            latest_connection_rejection: traffic.latest_connection_rejection.clone(),
            upload_bytes: traffic.total.up.saturating_sub(traffic.transfer_baseline.0),
            download_bytes: traffic
                .total
                .down
                .saturating_sub(traffic.transfer_baseline.1),
            transfer_stats_reset_unix_ms: traffic.transfer_stats_reset_unix_ms,
            upload_bytes_per_second,
            download_bytes_per_second,
            activity,
            origin_bytes: traffic.origin_bytes,
            delivered_bytes: traffic.delivered_bytes,
            cache_misses: traffic.cache_misses,
            cache_bypasses: traffic.cache_bypasses,
            cache_bypass_reasons: traffic.cache_bypass_reasons.clone(),
            inspection_fail_open_remembered: self
                .inspection_fail_open_remembered
                .load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            blocked_requests: self.blocked_requests.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_bytes_saved,
            compressed_images: self.compressed_images.load(Ordering::Relaxed),
            compression_bytes_saved,
            connect_tunnels: self.connect_tunnels.load(Ordering::Relaxed),
            socks5_connections: self.socks5_connections.load(Ordering::Relaxed),
            authenticated_external_requests: self
                .authenticated_external_requests
                .load(Ordering::Relaxed),
            successful_external_requests: self.successful_external_requests.load(Ordering::SeqCst),
            unique_clients,
            clients,
            saved_bytes: cache_bytes_saved.saturating_add(compression_bytes_saved),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSnapshot {
    pub ip: IpAddr,
    pub last_seen_unix_ms: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionRejectionReason {
    PeerLimit,
    GlobalLimit,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionRejectionSnapshot {
    pub peer_ip: IpAddr,
    pub listener_ip: IpAddr,
    pub unix_ms: u64,
    pub reason: ConnectionRejectionReason,
    pub limit: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsSnapshot {
    pub active_connections: u64,
    pub connection_limit: usize,
    pub connection_limit_per_peer: usize,
    pub live_connections: Vec<LiveConnectionSnapshot>,
    pub idle_connections_closed: u64,
    pub keepalive_configuration_failures: u64,
    pub listener_runtime_error: Option<String>,
    pub listener_runtime_errors: u64,
    pub rejected_connections: u64,
    pub latest_connection_rejection: Option<ConnectionRejectionSnapshot>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub transfer_stats_reset_unix_ms: Option<u64>,
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
    pub origin_bytes: u64,
    pub delivered_bytes: u64,
    pub cache_misses: u64,
    pub cache_bypasses: u64,
    /// Cumulative bypass count per fixed reason code, bounded to
    /// `MAX_CACHE_BYPASS_REASONS` keys including `other`.
    pub cache_bypass_reasons: BTreeMap<String, u64>,
    pub inspection_fail_open_remembered: u64,
    pub activity: Vec<ActivitySnapshot>,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub cache_hits: u64,
    pub cache_bytes_saved: u64,
    pub compressed_images: u64,
    pub compression_bytes_saved: u64,
    pub connect_tunnels: u64,
    pub socks5_connections: u64,
    pub authenticated_external_requests: u64,
    pub successful_external_requests: u64,
    pub unique_clients: u64,
    pub clients: Vec<ClientSnapshot>,
    pub saved_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::Stats;

    #[test]
    fn transfer_reset_only_changes_displayed_totals_and_timestamp() {
        let stats = std::sync::Arc::new(Stats::default());
        let peer = "192.168.1.2".parse().unwrap();
        let id = stats.begin_activity(peer, peer);
        let _live = stats.track_connection(id, peer);
        stats.connection_limits(256, 128);
        stats.request(peer);
        stats.blocked();
        stats.cache_hit(500);
        stats.compressed(100);
        stats.tunnel();
        stats.socks5_connection();
        stats.authenticated_external_request();
        stats.successful_external_request();
        stats.traffic(peer, id, 100, 200);
        stats.body_bytes(id, 300, 200);
        stats.cache_outcome(id, "MISS", None);
        stats.connection_rejected(peer, peer, super::ConnectionRejectionReason::PeerLimit, 128);
        stats.listener_runtime_error("test listener error".into());
        stats.connection_idle_closed(id);
        stats.keepalive_configuration_failed();
        let before = stats.snapshot();
        assert!(before.transfer_stats_reset_unix_ms.is_none());
        let samples = stats.traffic.lock().unwrap().total.samples.clone();
        stats.reset_transfer_stats();
        {
            let traffic = stats.traffic.lock().unwrap();
            assert_eq!(traffic.total.samples, samples);
            assert_eq!((traffic.total.up, traffic.total.down), (100, 200));
        }
        let after = stats.snapshot();
        assert_eq!((after.upload_bytes, after.download_bytes), (0, 0));
        assert!(after
            .transfer_stats_reset_unix_ms
            .is_some_and(|time| time > 0));
        let diagnostic = stats.diagnostic_metrics(60, true);
        assert_eq!(
            (diagnostic.upload_bytes, diagnostic.download_bytes),
            (100, 200)
        );
        let mut before = serde_json::to_value(before).unwrap();
        let mut after = serde_json::to_value(after).unwrap();
        for value in [&mut before, &mut after] {
            let object = value.as_object_mut().unwrap();
            for field in [
                "uploadBytes",
                "downloadBytes",
                "transferStatsResetUnixMs",
                "uploadBytesPerSecond",
                "downloadBytesPerSecond",
            ] {
                object.remove(field);
            }
            // Rates and live ages naturally advance with time. Their source
            // samples were compared directly above, without a timing assumption.
            for field in ["clients", "activity"] {
                for entry in value[field].as_array_mut().unwrap() {
                    entry
                        .as_object_mut()
                        .unwrap()
                        .remove("uploadBytesPerSecond");
                    entry
                        .as_object_mut()
                        .unwrap()
                        .remove("downloadBytesPerSecond");
                }
            }
            for live in value["liveConnections"].as_array_mut().unwrap() {
                live.as_object_mut().unwrap().remove("ageMs");
                live.as_object_mut().unwrap().remove("idleMs");
            }
        }
        assert_eq!(before, after);
    }

    #[test]
    fn transfer_reset_counts_subsequent_traffic_and_can_be_repeated() {
        let stats = Stats::default();
        let peer = "192.168.1.2".parse().unwrap();
        assert!(
            serde_json::to_value(stats.snapshot()).unwrap()["transferStatsResetUnixMs"].is_null()
        );
        stats.reset_transfer_stats();
        assert_eq!(stats.snapshot().upload_bytes, 0);
        let id = stats.begin_activity(peer, peer);
        stats.traffic(peer, id, 100, 200);
        stats.reset_transfer_stats();
        stats.traffic(peer, id, 30, 40);
        let snapshot = stats.snapshot();
        assert_eq!((snapshot.upload_bytes, snapshot.download_bytes), (30, 40));
        assert_eq!(
            (
                snapshot.clients[0].upload_bytes,
                snapshot.clients[0].download_bytes
            ),
            (130, 240)
        );
        assert_eq!(
            (
                snapshot.activity[0].upload_bytes,
                snapshot.activity[0].download_bytes
            ),
            (130, 240)
        );
        stats.reset_transfer_stats();
        let snapshot = stats.snapshot();
        assert_eq!((snapshot.upload_bytes, snapshot.download_bytes), (0, 0));
        let diagnostic = stats.diagnostic_metrics(60, false);
        assert_eq!(
            (diagnostic.upload_bytes, diagnostic.download_bytes),
            (130, 240)
        );
        // The baseline is process-local, matching the existing restart behavior.
        assert!(Stats::default()
            .snapshot()
            .transfer_stats_reset_unix_ms
            .is_none());
    }

    #[test]
    fn transfer_reset_and_concurrent_traffic_keep_the_pair_consistent() {
        let stats = std::sync::Arc::new(Stats::default());
        let peer = "192.168.1.2".parse().unwrap();
        let id = stats.begin_activity(peer, peer);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let writer_stats = stats.clone();
        let writer_barrier = barrier.clone();
        let writer = std::thread::spawn(move || {
            writer_stats.traffic(peer, id, 10, 20);
            writer_barrier.wait();
            // Deterministically keep the next increment after the first reset.
            writer_barrier.wait();
            for _ in 0..1000 {
                writer_stats.traffic(peer, id, 1, 2);
                std::thread::yield_now();
            }
        });
        barrier.wait();
        stats.reset_transfer_stats();
        let reset = stats.snapshot();
        assert_eq!((reset.upload_bytes, reset.download_bytes), (0, 0));
        barrier.wait();
        for _ in 0..1000 {
            stats.reset_transfer_stats();
            let snapshot = stats.snapshot();
            assert_eq!(snapshot.download_bytes, snapshot.upload_bytes * 2);
            std::thread::yield_now();
        }
        writer.join().unwrap();
        let diagnostic = stats.diagnostic_metrics(60, false);
        assert_eq!(
            (diagnostic.upload_bytes, diagnostic.download_bytes),
            (1010, 2020)
        );
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.download_bytes, snapshot.upload_bytes * 2);
        stats.traffic(peer, id, 7, 14);
        let continued = stats.snapshot();
        assert_eq!(continued.upload_bytes, snapshot.upload_bytes + 7);
        assert_eq!(continued.download_bytes, snapshot.download_bytes + 14);
    }

    #[test]
    fn connection_rejections_retain_one_typed_record_and_clear_private_metadata() {
        let stats = Stats::default();
        let listener = "192.168.1.1".parse().unwrap();
        stats.begin_activity(listener, listener);
        for index in 0..10_000 {
            let peer = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192,
                168,
                (index / 256) as u8,
                (index % 256) as u8,
            ));
            stats.connection_rejected(
                peer,
                listener,
                super::ConnectionRejectionReason::PeerLimit,
                128,
            );
        }
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.rejected_connections, 10_000);
        assert_eq!(
            snapshot.activity.len(),
            1,
            "rejections must not displace live activity"
        );
        let value = serde_json::to_value(&snapshot).unwrap();
        let latest = value["latestConnectionRejection"].as_object().unwrap();
        assert_eq!(latest.len(), 5);
        assert_eq!(latest["peerIp"], "192.168.39.15");
        assert_eq!(latest["listenerIp"], "192.168.1.1");
        assert_eq!(latest["reason"], "peer-limit");
        assert_eq!(latest["limit"], 128);
        assert!(latest["unixMs"].as_u64().unwrap() > 0);
        stats.clear_activity();
        let cleared = stats.snapshot();
        assert_eq!(cleared.rejected_connections, 10_000);
        assert!(cleared.latest_connection_rejection.is_none());
        assert!(cleared.activity.is_empty());
    }

    #[test]
    fn malformed_activity_host_never_retains_embedded_sensitive_data() {
        let stats = Stats::default();
        let peer = "192.168.1.2".parse().unwrap();
        let id = stats.begin_activity(peer, peer);
        for host in [
            "example.test?secret",
            "user:password@example.test",
            "example.test/private",
            "bad..test",
            "-bad.test",
        ] {
            stats.describe_activity(id, host, "SOCKS5");
            assert_eq!(stats.snapshot().activity[0].host, "[invalid-host]");
        }
        for host in [
            "example.test",
            "127.0.0.1",
            "::1",
            "[::1]",
            "xn--d1acufc.xn--p1ai",
            "example.test.",
        ] {
            stats.describe_activity(id, host, "SOCKS5");
            assert_eq!(stats.snapshot().activity[0].host, host);
        }
    }

    #[test]
    fn activity_is_bounded_host_only_and_clear_does_not_reset_totals() {
        let stats = Stats::default();
        let peer = "192.168.1.2".parse().unwrap();
        for _ in 0..300 {
            let id = stats.begin_activity(peer, peer);
            stats.describe_activity(id, "example.test", "HTTP");
            stats.traffic(peer, id, 10, 20);
            stats.body_bytes(id, 40, 20);
            stats.cache_outcome(id, "bypass", Some("request-private-or-ineligible"));
        }
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.activity.len(), 256);
        assert_eq!(
            (snapshot.upload_bytes, snapshot.download_bytes),
            (3000, 6000)
        );
        assert_eq!(
            (snapshot.origin_bytes, snapshot.delivered_bytes),
            (12000, 6000)
        );
        let json = serde_json::to_value(&snapshot.activity[0]).unwrap();
        for forbidden in ["url", "query", "cookie", "authorization", "body", "path"] {
            assert!(json.get(forbidden).is_none());
        }
        stats.clear_activity();
        assert!(stats.snapshot().activity.is_empty());
        assert_eq!(stats.snapshot().download_bytes, 6000);
    }

    #[test]
    fn authenticated_external_requests_are_reported_separately() {
        let stats = Stats::default();
        stats.authenticated_external_request();
        stats.authenticated_external_request();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.authenticated_external_requests, 2);
        assert_eq!(snapshot.successful_external_requests, 0);
        assert_eq!(snapshot.total_requests, 0);

        stats.successful_external_request();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.authenticated_external_requests, 2);
        assert_eq!(snapshot.successful_external_requests, 1);
    }

    #[test]
    fn external_devices_include_ip_and_last_activity() {
        let stats = Stats::default();
        let client = "192.168.68.81".parse().unwrap();

        stats.client_seen(client);
        let snapshot = stats.snapshot();

        assert_eq!(snapshot.unique_clients, 1);
        assert_eq!(snapshot.clients.len(), 1);
        assert_eq!(snapshot.clients[0].ip, client);
        assert!(snapshot.clients[0].last_seen_unix_ms > 0);
    }

    #[test]
    fn socks5_connections_are_reported_separately() {
        let stats = Stats::default();
        stats.socks5_connection();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.socks5_connections, 1);
        assert_eq!(snapshot.authenticated_external_requests, 0);
        assert_eq!(snapshot.successful_external_requests, 0);
    }
}

#[cfg(test)]
mod live_connection_tests {
    use super::*;
    use std::time::Duration;

    fn peer() -> IpAddr {
        "192.168.1.2".parse().unwrap()
    }

    #[test]
    fn live_connections_survive_activity_eviction_completion_and_clear() {
        let stats = Arc::new(Stats::default());
        stats.connection_limits(256, 128);
        let ids = (0..3)
            .map(|_| stats.begin_activity(peer(), peer()))
            .collect::<Vec<_>>();
        let guards = ids
            .iter()
            .map(|&id| stats.track_connection(id, peer()))
            .collect::<Vec<_>>();
        for _ in 0..300 {
            let id = stats.begin_activity(peer(), peer());
            stats.finish_activity(id, None);
        }
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.activity.len(), 256);
        assert_eq!(snapshot.active_connections, 3);
        assert_eq!(
            (
                snapshot.connection_limit,
                snapshot.connection_limit_per_peer
            ),
            (256, 128)
        );
        assert_eq!(
            snapshot
                .live_connections
                .iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>(),
            ids
        );
        let id = stats.begin_activity(peer(), peer());
        let last = stats.track_connection(id, peer());
        stats.finish_activity(id, None);
        assert_eq!(stats.snapshot().active_connections, 4);
        stats.clear_activity();
        let cleared = stats.snapshot();
        assert!(cleared.activity.is_empty());
        assert_eq!(cleared.active_connections, 4);
        assert_eq!(cleared.live_connections.len(), 4);
        drop(last);
        drop(guards);
        assert_eq!(stats.snapshot().active_connections, 0);
    }

    #[test]
    fn shared_permit_retains_guard_until_last_upgrade_owner_drops() {
        struct Permit {
            _connection: ConnectionGuard,
        }
        let stats = Arc::new(Stats::default());
        let id = stats.begin_activity(peer(), peer());
        let permit = Arc::new(Permit {
            _connection: stats.track_connection(id, peer()),
        });
        let upgrade = permit.clone();
        stats.finish_activity(id, None);
        drop(permit);
        assert_eq!(stats.snapshot().active_connections, 1);
        drop(upgrade);
        assert!(stats.snapshot().live_connections.is_empty());
        assert_eq!(stats.snapshot().active_connections, 0);
    }

    #[test]
    fn duplicate_and_capacity_rejected_guards_cannot_remove_valid_registrations() {
        let stats = Arc::new(Stats::default());
        let id = stats.begin_activity(peer(), peer());
        let first = stats.track_connection(id, peer());
        let duplicate = stats.track_connection(id, "192.168.1.3".parse().unwrap());
        drop(duplicate);
        assert_eq!(stats.snapshot().live_connections[0].peer_ip, peer());
        let mut guards = (1..MAX_LIVE_CONNECTIONS)
            .map(|_| {
                let id = stats.begin_activity(peer(), peer());
                stats.track_connection(id, peer())
            })
            .collect::<Vec<_>>();
        let overflow_id = stats.begin_activity(peer(), peer());
        let rejected = stats.track_connection(overflow_id, peer());
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.active_connections, MAX_LIVE_CONNECTIONS as u64);
        assert_eq!(snapshot.live_connections.len(), MAX_LIVE_CONNECTIONS);
        assert!(!snapshot
            .live_connections
            .iter()
            .any(|entry| entry.id == overflow_id));
        drop(first);
        let replacement = stats.track_connection(overflow_id, peer());
        drop(rejected);
        assert_eq!(
            stats.snapshot().active_connections,
            MAX_LIVE_CONNECTIONS as u64
        );
        assert!(stats
            .snapshot()
            .live_connections
            .iter()
            .any(|entry| entry.id == overflow_id));
        guards.clear();
        drop(replacement);
        assert_eq!(stats.snapshot().active_connections, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn monotonic_age_and_idle_advance_and_only_positive_traffic_resets_idle() {
        let stats = Arc::new(Stats::default());
        let id = stats.begin_activity(peer(), peer());
        let _guard = stats.track_connection(id, peer());
        tokio::time::advance(Duration::from_secs(100)).await;
        let live = &stats.snapshot().live_connections[0];
        assert_eq!((live.age_ms, live.idle_ms), (100_000, 100_000));
        stats.traffic_accounted(peer(), id, 0, 0);
        assert_eq!(stats.snapshot().live_connections[0].idle_ms, 100_000);
        stats.traffic(peer(), id, 1, 0);
        tokio::time::advance(Duration::from_secs(23)).await;
        let live = &stats.snapshot().live_connections[0];
        assert_eq!((live.age_ms, live.idle_ms), (123_000, 23_000));
        stats.traffic_accounted(peer(), id, 0, 1);
        tokio::time::advance(Duration::from_secs(17)).await;
        let live = &stats.snapshot().live_connections[0];
        assert_eq!((live.age_ms, live.idle_ms), (140_000, 17_000));
        stats.connection_progress(id);
        assert_eq!(stats.snapshot().live_connections[0].idle_ms, 0);
    }

    #[test]
    fn live_telemetry_contains_only_fixed_protocol_and_peer_metadata() {
        let stats = Arc::new(Stats::default());
        let id = stats.begin_activity(peer(), peer());
        let _guard = stats.track_connection(id, peer());
        stats.describe_activity(id, "example.test", "HTTP");
        stats.connection_protocol(id, "websocket");
        let json = serde_json::to_value(&stats.snapshot().live_connections[0]).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 5);
        assert_eq!(json["peerIp"], "192.168.1.2");
        assert_eq!(json["protocol"], "websocket");
        for forbidden in [
            "host",
            "url",
            "query",
            "cookie",
            "authorization",
            "body",
            "path",
        ] {
            assert!(json.get(forbidden).is_none());
        }
        stats.connection_protocol(id, "user:password@example.test/private?secret");
        assert_eq!(stats.snapshot().live_connections[0].protocol, "tcp");
        let json = serde_json::to_value(stats.snapshot()).unwrap();
        assert_eq!(json["activeConnections"], 1);
        assert!(json["liveConnections"].is_array());
    }

    #[test]
    fn diagnostics_are_bounded_cumulative_and_do_not_end_live_socket_lifetime() {
        let stats = Arc::new(Stats::default());
        let id = stats.begin_activity(peer(), peer());
        let guard = stats.track_connection(id, peer());
        stats.connection_idle_closed(id);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.idle_connections_closed, 1);
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(
            snapshot.activity[0].error.as_deref(),
            Some("tunnel-idle-timeout")
        );
        stats.finish_activity(id, None);
        assert_eq!(stats.snapshot().active_connections, 1);
        for _ in 0..10_000 {
            stats.keepalive_configuration_failed();
            stats.listener_runtime_error("accept-resource-unavailable".into());
        }
        stats.listener_runtime_error("ě".repeat(1000));
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.keepalive_configuration_failures, 10_000);
        assert_eq!(snapshot.listener_runtime_errors, 10_001);
        assert!(snapshot.listener_runtime_error.unwrap().len() <= MAX_LISTENER_ERROR_BYTES);
        assert!(
            stats
                .live
                .lock()
                .unwrap()
                .listener_runtime_error
                .as_ref()
                .unwrap()
                .capacity()
                <= MAX_LISTENER_ERROR_BYTES
        );
        stats.clear_activity();
        assert!(stats.snapshot().listener_runtime_error.is_some());
        assert!(stats.listener_error().is_some());
        stats.listener_recovered();
        assert!(stats.listener_error().is_none());
        let recovered = stats.snapshot();
        assert!(recovered.listener_runtime_error.is_none());
        assert_eq!(recovered.listener_runtime_errors, 10_001);
        assert_eq!(recovered.idle_connections_closed, 1);
        drop(guard);
        assert_eq!(stats.snapshot().active_connections, 0);
    }

    #[test]
    fn listener_recovery_does_not_hide_another_listener_failure() {
        let stats = Stats::default();
        let http = "127.0.0.1:8080".parse().unwrap();
        let socks = "127.0.0.1:1080".parse().unwrap();
        stats.listener_accept_error(http, "http-resource-unavailable".into());
        stats.listener_accept_error(socks, "socks-resource-unavailable".into());
        stats.listener_accept_recovered(http);
        assert_eq!(
            stats.listener_error().as_deref(),
            Some("socks-resource-unavailable")
        );
        assert_eq!(
            stats.snapshot().listener_runtime_error.as_deref(),
            Some("socks-resource-unavailable")
        );
        stats.listener_accept_recovered(socks);
        assert!(stats.listener_error().is_none());
        stats.listener_runtime_error("listener-fatal".into());
        stats.listener_accept_recovered(http);
        assert_eq!(stats.listener_error().as_deref(), Some("listener-fatal"));
        stats.listener_recovered();
        assert!(stats.listener_error().is_none());
        assert_eq!(stats.snapshot().listener_runtime_errors, 3);
    }

    #[test]
    fn diagnostic_counters_saturate() {
        let stats = Stats::default();
        {
            let mut live = stats.live.lock().unwrap();
            live.idle_connections_closed = u64::MAX;
            live.keepalive_configuration_failures = u64::MAX;
            live.listener_runtime_errors = u64::MAX;
        }
        stats.connection_idle_closed(1);
        stats.keepalive_configuration_failed();
        stats.listener_runtime_error("accept-resource-unavailable".into());
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.idle_connections_closed, u64::MAX);
        assert_eq!(snapshot.keepalive_configuration_failures, u64::MAX);
        assert_eq!(snapshot.listener_runtime_errors, u64::MAX);
    }

    #[test]
    fn inspection_fail_open_remembered_counts_and_saturates() {
        let stats = Stats::default();
        assert_eq!(stats.snapshot().inspection_fail_open_remembered, 0);
        stats.inspection_fail_open_remembered();
        stats.inspection_fail_open_remembered();
        assert_eq!(stats.snapshot().inspection_fail_open_remembered, 2);
        stats
            .inspection_fail_open_remembered
            .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
        stats.inspection_fail_open_remembered();
        let json = serde_json::to_value(stats.snapshot()).unwrap();
        assert_eq!(json["inspectionFailOpenRemembered"], u64::MAX);
    }

    #[test]
    fn cache_bypass_reasons_aggregate_only_bypasses_per_fixed_code() {
        let stats = Stats::default();
        let peer = "192.168.1.2".parse().unwrap();
        let first = stats.begin_activity(peer, peer);
        let second = stats.begin_activity(peer, peer);
        stats.cache_outcome(first, "bypass", Some("request-cookie"));
        stats.cache_outcome(first, "bypass", Some("request-cookie"));
        stats.cache_outcome(second, "bypass", Some("response-set-cookie"));
        stats.cache_outcome(second, "MISS", Some("cold-miss"));
        stats.cache_outcome(second, "validation", Some("cold-miss"));
        stats.cache_outcome(second, "HIT", None);
        stats.cache_outcome(second, "bypass", None);
        // Free-form text never reaches the aggregate.
        stats.cache_outcome(second, "bypass", Some("https://example.test/?q=secret"));
        stats.cache_outcome(second, "bypass", Some(""));
        stats.cache_outcome(second, "bypass", Some(&"a".repeat(65)));
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.cache_bypasses, 7);
        assert_eq!(
            snapshot.cache_bypass_reasons.values().sum::<u64>(),
            snapshot.cache_bypasses
        );
        assert_eq!(snapshot.cache_bypass_reasons["request-cookie"], 2);
        assert_eq!(snapshot.cache_bypass_reasons["response-set-cookie"], 1);
        assert_eq!(snapshot.cache_bypass_reasons["unspecified"], 1);
        assert_eq!(snapshot.cache_bypass_reasons["other"], 3);
        assert!(!snapshot.cache_bypass_reasons.contains_key("cold-miss"));
        // The per-activity view keeps only the latest reason; the aggregate keeps all.
        assert_eq!(
            snapshot.activity[0].cache_bypass_reason.as_deref(),
            Some("request-cookie")
        );
        assert_eq!(snapshot.activity[1].cache_status, "bypass");
        let json = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(json["cacheBypassReasons"]["request-cookie"], 2);
        // Clearing the activity list keeps cumulative cache counters.
        stats.clear_activity();
        stats.reset_transfer_stats();
        assert_eq!(stats.snapshot().cache_bypass_reasons["request-cookie"], 2);
    }

    #[test]
    fn cache_bypass_reasons_are_bounded_with_overflow_bucket() {
        let stats = Stats::default();
        let peer = "192.168.1.2".parse().unwrap();
        let id = stats.begin_activity(peer, peer);
        for index in 0..200 {
            stats.cache_outcome(id, "bypass", Some(&format!("reason-{index}")));
        }
        stats.cache_outcome(id, "bypass", Some("reason-0"));
        let reasons = stats.snapshot().cache_bypass_reasons;
        assert_eq!(reasons.len(), super::MAX_CACHE_BYPASS_REASONS);
        assert_eq!(reasons["reason-0"], 2);
        assert_eq!(
            reasons["other"],
            200 - (super::MAX_CACHE_BYPASS_REASONS as u64 - 1)
        );
        assert_eq!(reasons.values().sum::<u64>(), 201);
    }

    #[test]
    fn empty_snapshot_serializes_additive_fields_with_defaults() {
        let json = serde_json::to_value(Stats::default().snapshot()).unwrap();
        assert_eq!(json["cacheBypassReasons"], serde_json::json!({}));
        assert_eq!(json["inspectionFailOpenRemembered"], 0);
    }
}

impl Default for ClientSnapshot {
    fn default() -> Self {
        Self {
            ip: IpAddr::from([0, 0, 0, 0]),
            last_seen_unix_ms: 0,
            upload_bytes: 0,
            download_bytes: 0,
            upload_bytes_per_second: 0,
            download_bytes_per_second: 0,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivitySnapshot {
    pub id: u64,
    pub peer_ip: String,
    pub listener_ip: String,
    pub host: String,
    pub protocol: String,
    pub started_unix_ms: u64,
    pub ended_unix_ms: Option<u64>,
    pub status: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
    pub error: Option<String>,
    pub cache_status: String,
    pub cache_bypass_reason: Option<String>,
    pub origin_bytes: u64,
    pub delivered_bytes: u64,
}

#[derive(Default)]
struct Meter {
    up: u64,
    down: u64,
    samples: VecDeque<(Instant, u64, u64)>,
}
impl Meter {
    fn record(&mut self, up: u64, down: u64) {
        self.up = self.up.saturating_add(up);
        self.down = self.down.saturating_add(down);
        let now = Instant::now();
        if let Some((time, old_up, old_down)) = self.samples.back_mut() {
            if now.duration_since(*time).as_millis() < 100 {
                *old_up += up;
                *old_down += down;
                return;
            }
        }
        self.samples.push_back((now, up, down));
        self.expire();
    }
    fn expire(&mut self) {
        while self
            .samples
            .front()
            .is_some_and(|(time, _, _)| time.elapsed().as_secs_f64() >= 1.0)
        {
            self.samples.pop_front();
        }
    }
    fn rates(&mut self) -> (u64, u64) {
        self.expire();
        self.samples
            .iter()
            .fold((0, 0), |(up, down), (_, u, d)| (up + u, down + d))
    }
}
#[derive(Default)]
struct TrafficState {
    rejected_connections: u64,
    latest_connection_rejection: Option<ConnectionRejectionSnapshot>,
    next_id: u64,
    total: Meter,
    transfer_baseline: (u64, u64),
    transfer_stats_reset_unix_ms: Option<u64>,
    clients: HashMap<IpAddr, Meter>,
    activity: VecDeque<ActivityEntry>,
    origin_bytes: u64,
    delivered_bytes: u64,
    cache_misses: u64,
    cache_bypasses: u64,
    cache_bypass_reasons: BTreeMap<String, u64>,
}
struct ActivityEntry {
    snapshot: ActivitySnapshot,
    meter: Meter,
}
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
impl Stats {
    pub fn begin_activity(&self, peer: IpAddr, listener: IpAddr) -> u64 {
        let mut state = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        state.next_id += 1;
        let id = state.next_id;
        if state.activity.len() >= 256 {
            state.activity.pop_front();
        }
        state.activity.push_back(ActivityEntry {
            snapshot: ActivitySnapshot {
                id,
                peer_ip: peer.to_string(),
                listener_ip: listener.to_string(),
                started_unix_ms: unix_ms(),
                status: "active".into(),
                cache_status: "bypass".into(),
                ..ActivitySnapshot::default()
            },
            meter: Meter::default(),
        });
        drop(state);
        if let Ok(mut runtime) = self.runtime.lock() {
            if let Some(runtime) = runtime.as_mut() {
                if runtime.bindings.len() < 8192 {
                    let profile_id = match peer {
                        IpAddr::V4(ip) => {
                            crate::policy::resolve_profile(&runtime.settings, None, ip)
                                .map(|p| p.id.clone())
                        }
                        _ => None,
                    };
                    runtime.bindings.insert(
                        id,
                        ActivityBinding {
                            peer,
                            profile_id,
                            principal: None,
                            admitted: false,
                            host: String::new(),
                        },
                    );
                }
            }
        }
        id
    }
    pub fn describe_activity(&self, id: u64, host: &str, protocol: &str) {
        if let Ok(mut runtime) = self.runtime.lock() {
            if let Some(runtime) = runtime.as_mut() {
                if let Some(binding) = runtime.bindings.get_mut(&id) {
                    binding.host = if host.is_empty() || crate::dns::valid_host(host) {
                        host.to_string()
                    } else {
                        "[invalid-host]".into()
                    };
                }
            }
        }
        let mut state = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = state
            .activity
            .iter_mut()
            .find(|entry| entry.snapshot.id == id)
        {
            // Store host only, never arbitrary URI, credentials or query data.
            entry.snapshot.host = if host.is_empty() || crate::dns::valid_host(host) {
                host.to_owned()
            } else {
                "[invalid-host]".into()
            };
            entry.snapshot.protocol = protocol.into();
        }
    }
    pub fn finish_activity(&self, id: u64, error: Option<&str>) {
        if let Ok(mut runtime) = self.runtime.lock() {
            if let Some(runtime) = runtime.as_mut() {
                runtime.bindings.remove(&id);
            }
        }
        let mut state = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = state
            .activity
            .iter_mut()
            .find(|entry| entry.snapshot.id == id)
        {
            entry.snapshot.ended_unix_ms = Some(unix_ms());
            if entry.snapshot.error.is_none() {
                entry.snapshot.error = error.map(str::to_owned);
            }
            entry.snapshot.status = if entry.snapshot.error.is_some() {
                "error"
            } else {
                "completed"
            }
            .into();
        }
    }
    pub fn activity_error(&self, id: u64, error: &str) {
        let mut state = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = state
            .activity
            .iter_mut()
            .find(|entry| entry.snapshot.id == id)
        {
            entry.snapshot.error = Some(error.into());
            entry.snapshot.status = "error".into();
        }
    }
    pub fn activity_authentication(&self, id: u64, authenticated: bool) {
        let mut state = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = state
            .activity
            .iter_mut()
            .find(|entry| entry.snapshot.id == id)
        {
            // A Digest challenge can recover on the same connection. Neither
            // the challenge nor its recovery may replace a genuine error.
            if entry.snapshot.ended_unix_ms.is_some()
                || entry
                    .snapshot
                    .error
                    .as_deref()
                    .is_some_and(|error| error != "authentication-required")
            {
                return;
            }
            entry.snapshot.error = (!authenticated).then(|| "authentication-required".into());
            entry.snapshot.status = if authenticated { "active" } else { "error" }.into();
        }
    }
    pub fn traffic(&self, peer: IpAddr, id: u64, up: u64, down: u64) {
        self.record_history_counters(
            id,
            peer,
            crate::usage_history::UsageCounters {
                upload_bytes: up,
                download_bytes: down,
                ..Default::default()
            },
        );
        self.traffic_accounted(peer, id, up, down);
    }
    /// Live counters for transfer already settled through a quota reservation.
    pub fn traffic_accounted(&self, peer: IpAddr, id: u64, up: u64, down: u64) {
        if up > 0 || down > 0 {
            self.connection_progress(id);
        }
        self.client_seen(peer);
        let mut state = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        state.total.record(up, down);
        if state.clients.len() < 1024 || state.clients.contains_key(&peer) {
            state.clients.entry(peer).or_default().record(up, down);
        }
        if let Some(entry) = state
            .activity
            .iter_mut()
            .find(|entry| entry.snapshot.id == id)
        {
            entry.meter.record(up, down);
            entry.snapshot.upload_bytes += up;
            entry.snapshot.download_bytes += down;
        }
    }
    pub fn cache_outcome(&self, id: u64, outcome: &str, reason: Option<&str>) {
        let mut state = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        if outcome == "MISS" {
            state.cache_misses += 1;
        }
        if outcome == "bypass" {
            state.cache_bypasses += 1;
            let key = cache_bypass_reason_key(&state.cache_bypass_reasons, reason);
            let count = state.cache_bypass_reasons.entry(key).or_default();
            *count = count.saturating_add(1);
        }
        if let Some(entry) = state
            .activity
            .iter_mut()
            .find(|entry| entry.snapshot.id == id)
        {
            entry.snapshot.cache_status = outcome.into();
            entry.snapshot.cache_bypass_reason = reason.map(str::to_owned);
        }
    }
    pub fn body_bytes(&self, id: u64, origin: u64, delivered: u64) {
        let mut state = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        state.origin_bytes += origin;
        state.delivered_bytes += delivered;
        if let Some(entry) = state
            .activity
            .iter_mut()
            .find(|entry| entry.snapshot.id == id)
        {
            entry.snapshot.origin_bytes += origin;
            entry.snapshot.delivered_bytes += delivered;
        }
    }
    pub(crate) fn connection_rejected(
        &self,
        peer: IpAddr,
        listener: IpAddr,
        reason: ConnectionRejectionReason,
        limit: usize,
    ) {
        let mut state = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        state.rejected_connections = state.rejected_connections.saturating_add(1);
        state.latest_connection_rejection = Some(ConnectionRejectionSnapshot {
            peer_ip: peer,
            listener_ip: listener,
            unix_ms: unix_ms(),
            reason,
            limit,
        });
    }

    pub fn clear_activity(&self) {
        let mut state = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        state.activity.clear();
        state.latest_connection_rejection = None;
    }
}

struct RuntimeAccounting {
    path: std::path::PathBuf,
    settings: crate::config::Settings,
    history: crate::usage_history::UsageHistory,
    bindings: HashMap<u64, ActivityBinding>,
}
#[derive(Clone)]
struct ActivityBinding {
    peer: IpAddr,
    profile_id: Option<String>,
    principal: Option<String>,
    // A prior anonymous admission also excludes first-admission diagnostics.
    admitted: bool,
    host: String,
}
pub(crate) struct TransferContext {
    pub identity: String,
    pub profile_id: Option<String>,
    pub history: crate::usage_history::UsageHistory,
    pub timestamp: i64,
    pub daily_quota_mib: u64,
    pub monthly_quota_mib: u64,
    pub decision: crate::policy::PolicyDecision,
}
fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}
fn denied_decision(reason: crate::policy::PolicyReason) -> crate::policy::PolicyDecision {
    crate::policy::PolicyDecision {
        allowed: false,
        reason,
        upload_bytes_per_second: 0,
        download_bytes_per_second: 0,
        no_cache: true,
        explicit_allow: false,
        quota_warning: false,
    }
}
impl Stats {
    pub fn configure_history(
        &self,
        path: std::path::PathBuf,
        settings: &crate::config::Settings,
    ) -> Result<(), crate::usage_history::HistoryError> {
        let mut runtime = self.runtime.lock().map_err(|_| {
            crate::usage_history::HistoryError::Unavailable("Zámek historie byl poškozen.".into())
        })?;
        if let Some(runtime) = runtime.as_mut() {
            if runtime.path != path {
                return Err(crate::usage_history::HistoryError::Unavailable(
                    "Cestu živé historie nelze měnit.".into(),
                ));
            }
            if runtime.history.retention_days() != settings.history_retention_days {
                runtime
                    .history
                    .set_retention_days(settings.history_retention_days)?;
            }
            runtime.settings = settings.clone();
            if let Ok(mut buckets) = self.profile_buckets.lock() {
                buckets.retain(|id, _| settings.device_profiles.iter().any(|p| &p.id == id));
            }
        } else {
            let history = crate::usage_history::UsageHistory::open(
                path.clone(),
                settings.history_retention_days,
            );
            *runtime = Some(RuntimeAccounting {
                path,
                settings: settings.clone(),
                history,
                bindings: HashMap::new(),
            });
        }
        Ok(())
    }
    pub fn checkpoint_history(&self) -> Result<(), crate::usage_history::HistoryError> {
        let snapshot = self
            .runtime
            .lock()
            .map_err(|_| {
                crate::usage_history::HistoryError::Unavailable(
                    "Zámek historie byl poškozen.".into(),
                )
            })?
            .as_ref()
            .map(|runtime| {
                (
                    runtime.history.clone(),
                    unix_seconds().saturating_add(
                        i64::from(runtime.settings.schedule_utc_offset_minutes) * 60,
                    ),
                )
            });
        if let Some((history, timestamp)) = snapshot {
            history.prune_at(timestamp)?;
            history.checkpoint()?;
        }
        Ok(())
    }
    pub(crate) fn history_retention_days(&self) -> Option<u16> {
        self.runtime
            .lock()
            .ok()?
            .as_ref()
            .map(|runtime| runtime.history.retention_days())
    }
    pub fn history_report(&self) -> Option<crate::usage_history::HistoryReport> {
        self.runtime
            .lock()
            .ok()?
            .as_ref()
            .map(|runtime| runtime.history.report())
    }
    pub fn history_json(&self) -> Result<String, crate::usage_history::HistoryError> {
        let runtime = self.runtime.lock().map_err(|_| {
            crate::usage_history::HistoryError::Unavailable("Zámek historie byl poškozen.".into())
        })?;
        runtime
            .as_ref()
            .ok_or_else(|| {
                crate::usage_history::HistoryError::Unavailable("Historie není spuštěna.".into())
            })?
            .history
            .json_report()
    }
    pub fn history_csv(&self) -> Result<String, crate::usage_history::HistoryError> {
        let runtime = self.runtime.lock().map_err(|_| {
            crate::usage_history::HistoryError::Unavailable("Zámek historie byl poškozen.".into())
        })?;
        runtime
            .as_ref()
            .ok_or_else(|| {
                crate::usage_history::HistoryError::Unavailable("Historie není spuštěna.".into())
            })?
            .history
            .csv()
    }
    /// Check transfer restrictions before the first authenticated profile admission.
    /// The caller must supply a verified principal. A prior 407 challenge is not an
    /// admission; an anonymous request is. Existing identities/IP aliases retain the
    /// strict transport guard, including its ability to close without an HTTP reply.
    /// This does not reserve quota or attach profile identity to denied diagnostics.
    pub(crate) fn fresh_principal_transfer_decision(
        &self,
        id: u64,
        peer: IpAddr,
        verified_username: &str,
    ) -> Result<Option<crate::policy::PolicyDecision>, String> {
        let guard = self
            .runtime
            .lock()
            .map_err(|_| "Zámek identity byl poškozen.".to_string())?;
        let Some(runtime) = guard.as_ref() else {
            return Ok(None);
        };
        if verified_username != runtime.settings.proxy_username
            && !runtime
                .settings
                .device_profiles
                .iter()
                .any(|profile| profile.username == verified_username)
        {
            return Err("Neznámá ověřená identita.".into());
        }
        let binding = runtime
            .bindings
            .get(&id)
            .ok_or_else(|| "Identita živého spojení není dostupná.".to_string())?;
        if binding.peer != peer {
            return Err("Adresa živého spojení nesouhlasí.".into());
        }
        if binding.admitted || binding.principal.is_some() || binding.profile_id.is_some() {
            return Ok(None);
        }
        let IpAddr::V4(ip) = peer else {
            return Ok(None);
        };
        // Include aliases added after this connection began. Never detach or bypass
        // an IP identity merely because credentials select a different profile.
        if crate::policy::resolve_profile(&runtime.settings, None, ip).is_some() {
            return Ok(None);
        }
        let Some(profile) =
            crate::policy::resolve_profile(&runtime.settings, Some(verified_username), ip)
        else {
            return Ok(None);
        };
        let now = unix_seconds();
        let timestamp =
            now.saturating_add(i64::from(runtime.settings.schedule_utc_offset_minutes) * 60);
        let usage = runtime
            .history
            .usage_at(&format!("profile:{}", profile.id), timestamp)
            .unwrap_or(crate::policy::QuotaUsage {
                healthy: false,
                ..Default::default()
            });
        // Only the restrictions that would prevent writing a local HTTP response
        // need pre-admission handling. Destination ACL/adblock checks keep their
        // existing path and AdblockMode semantics after binding.
        Ok(Some(crate::policy::transfer_decision_at(
            &runtime.settings,
            Some(&profile.id),
            now,
            usage,
        )))
    }
    /// The caller must pass a principal returned by authenticate, never an unverified header.
    pub fn bind_principal(
        &self,
        id: u64,
        peer: IpAddr,
        verified_username: Option<&str>,
    ) -> Result<Option<String>, String> {
        let profile_id = {
            let mut guard = self
                .runtime
                .lock()
                .map_err(|_| "Zámek identity byl poškozen.".to_string())?;
            let Some(runtime) = guard.as_mut() else {
                return Ok(None);
            };
            if runtime.bindings.len() >= 8192 && !runtime.bindings.contains_key(&id) {
                return Err("Příliš mnoho živých identit.".into());
            }
            if let Some(username) = verified_username {
                if username != runtime.settings.proxy_username
                    && !runtime
                        .settings
                        .device_profiles
                        .iter()
                        .any(|p| p.username == username)
                {
                    return Err("Neznámá ověřená identita.".into());
                }
            }
            let profile_id = match peer {
                IpAddr::V4(ip) => {
                    crate::policy::resolve_profile(&runtime.settings, verified_username, ip)
                        .map(|p| p.id.clone())
                }
                _ => None,
            };
            let binding = runtime.bindings.entry(id).or_insert(ActivityBinding {
                peer,
                profile_id: None,
                principal: None,
                admitted: false,
                host: String::new(),
            });
            if let Some(previous) = binding.principal.as_deref() {
                if verified_username != Some(previous) {
                    return Err("Identitu živého spojení nelze změnit.".into());
                }
            }
            binding.peer = peer;
            binding.profile_id = profile_id.clone();
            binding.principal = verified_username.map(str::to_owned);
            binding.admitted = true;
            profile_id
        };
        self.record_history_counters(
            id,
            peer,
            crate::usage_history::UsageCounters {
                requests: 1,
                ..Default::default()
            },
        );
        Ok(profile_id)
    }
    pub fn policy_decision(&self, id: u64, host: &str) -> crate::policy::PolicyDecision {
        let runtime = match self.runtime.lock() {
            Ok(runtime) => runtime,
            Err(_) => return denied_decision(crate::policy::PolicyReason::HistoryUnavailable),
        };
        let Some(runtime) = runtime.as_ref() else {
            return crate::policy::decision_at(
                &crate::config::Settings::default(),
                None,
                host,
                unix_seconds(),
                Default::default(),
            );
        };
        let Some(binding) = runtime.bindings.get(&id) else {
            return denied_decision(crate::policy::PolicyReason::UnknownProfile);
        };
        let now = unix_seconds();
        let timestamp =
            now.saturating_add(i64::from(runtime.settings.schedule_utc_offset_minutes) * 60);
        let identity = binding_identity(binding);
        let usage =
            runtime
                .history
                .usage_at(&identity, timestamp)
                .unwrap_or(crate::policy::QuotaUsage {
                    healthy: false,
                    ..Default::default()
                });
        crate::policy::decision_at(
            &runtime.settings,
            binding.profile_id.as_deref(),
            host,
            now,
            usage,
        )
    }
    pub(crate) fn transfer_context(
        &self,
        id: u64,
        peer: IpAddr,
    ) -> Result<Option<TransferContext>, std::io::Error> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| std::io::Error::other("history-unavailable"))?;
        let Some(runtime) = runtime.as_ref() else {
            return Ok(None);
        };
        let binding = runtime.bindings.get(&id).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "identity-unavailable")
        })?;
        if binding.peer != peer {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "identity-peer-mismatch",
            ));
        }
        let now = unix_seconds();
        let timestamp =
            now.saturating_add(i64::from(runtime.settings.schedule_utc_offset_minutes) * 60);
        let identity = binding_identity(binding);
        let usage =
            runtime
                .history
                .usage_at(&identity, timestamp)
                .unwrap_or(crate::policy::QuotaUsage {
                    healthy: false,
                    ..Default::default()
                });
        let decision = crate::policy::transfer_decision_at(
            &runtime.settings,
            binding.profile_id.as_deref(),
            now,
            usage,
        );
        if !decision.allowed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("policy-{:?}", decision.reason),
            ));
        }
        let profile = binding.profile_id.as_ref().and_then(|id| {
            runtime
                .settings
                .device_profiles
                .iter()
                .find(|p| &p.id == id)
        });
        Ok(Some(TransferContext {
            identity,
            profile_id: binding.profile_id.clone(),
            history: runtime.history.clone(),
            timestamp,
            daily_quota_mib: profile.map_or(0, |p| p.daily_quota_mib),
            monthly_quota_mib: profile.map_or(0, |p| p.monthly_quota_mib),
            decision,
        }))
    }
    pub(crate) fn reserve_transfer(
        &self,
        id: u64,
        peer: IpAddr,
        bytes: u64,
    ) -> Result<Option<crate::usage_history::QuotaReservation>, std::io::Error> {
        let Some(context) = self.transfer_context(id, peer)? else {
            return Ok(None);
        };
        // History loss must not turn an unlimited connection into a configured quota bypass.
        match context.history.reserve(
            &context.identity,
            context.timestamp,
            bytes,
            context.daily_quota_mib,
            context.monthly_quota_mib,
        ) {
            Ok(reservation) => Ok(Some(reservation)),
            Err(crate::usage_history::HistoryError::CreditBusy) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "quota-credit-busy",
            )),
            Err(_) if context.daily_quota_mib == 0 && context.monthly_quota_mib == 0 => Ok(None),
            Err(error) => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                error.to_string(),
            )),
        }
    }
    pub(crate) fn profile_bandwidth(
        &self,
        id: &str,
        up: u64,
        down: u64,
    ) -> Result<crate::traffic::Buckets, std::io::Error> {
        let mut map = self
            .profile_buckets
            .lock()
            .map_err(|_| std::io::Error::other("bandwidth-state-unavailable"))?;
        if map.len() >= 256 && !map.contains_key(id) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "profile-bandwidth-capacity",
            ));
        }
        Ok(map
            .entry(id.to_string())
            .or_insert_with(|| {
                Arc::new(Mutex::new((
                    crate::traffic::Bucket::new(up),
                    crate::traffic::Bucket::new(down),
                )))
            })
            .clone())
    }
    fn record_history_counters(
        &self,
        id: u64,
        peer: IpAddr,
        counters: crate::usage_history::UsageCounters,
    ) {
        let Ok(runtime) = self.runtime.lock() else {
            return;
        };
        let Some(runtime) = runtime.as_ref() else {
            return;
        };
        let Some(binding) = runtime.bindings.get(&id) else {
            return;
        };
        if binding.peer != peer {
            return;
        }
        let timestamp = unix_seconds()
            .saturating_add(i64::from(runtime.settings.schedule_utc_offset_minutes) * 60);
        let _ = runtime
            .history
            .record(&binding_identity(binding), timestamp, counters);
    }
    pub fn history_saved(&self, id: u64, bytes: u64) {
        let peer = self
            .runtime
            .lock()
            .ok()
            .and_then(|r| r.as_ref().and_then(|r| r.bindings.get(&id).map(|b| b.peer)));
        if let Some(peer) = peer {
            self.record_history_counters(
                id,
                peer,
                crate::usage_history::UsageCounters {
                    saved_bytes: bytes,
                    ..Default::default()
                },
            );
        }
    }
}
fn binding_identity(binding: &ActivityBinding) -> String {
    binding.profile_id.as_ref().map_or_else(
        || format!("ip:{}", binding.peer),
        |id| format!("profile:{id}"),
    )
}

impl Stats {
    /// Atomic whole-datagram quota admission after shared profile rate/schedule checks.
    /// Settle only bytes sent/delivered, and let Drop refund a cancelled/failed datagram.
    pub(crate) async fn reserve_datagram(
        &self,
        id: u64,
        peer: IpAddr,
        upload: bool,
        bytes: usize,
    ) -> std::io::Result<Option<crate::usage_history::QuotaReservation>> {
        crate::traffic::reserve_profile_datagram(self, id, peer, upload, bytes).await
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaStatus {
    pub profile_id: String,
    pub daily_bytes: u64,
    pub monthly_bytes: u64,
    pub daily_quota_mib: u64,
    pub monthly_quota_mib: u64,
    pub warning_percent: u8,
    pub warning: bool,
    pub blocked: bool,
    pub history_healthy: bool,
}
impl Stats {
    pub fn quota_statuses(&self) -> Vec<QuotaStatus> {
        let Ok(runtime) = self.runtime.lock() else {
            return Vec::new();
        };
        let Some(runtime) = runtime.as_ref() else {
            return Vec::new();
        };
        let timestamp = unix_seconds()
            .saturating_add(i64::from(runtime.settings.schedule_utc_offset_minutes) * 60);
        runtime
            .settings
            .device_profiles
            .iter()
            .take(256)
            .map(|profile| {
                let usage = runtime
                    .history
                    .usage_status_at(&format!("profile:{}", profile.id), timestamp);
                let mut warning = false;
                let mut blocked = !usage.healthy
                    && (profile.daily_quota_mib > 0 || profile.monthly_quota_mib > 0);
                for (limit, used) in [
                    (profile.daily_quota_mib, usage.daily_bytes),
                    (profile.monthly_quota_mib, usage.monthly_bytes),
                ] {
                    if limit > 0 {
                        let bytes = limit.saturating_mul(1024 * 1024);
                        warning |= u128::from(used) * 100
                            >= u128::from(bytes) * u128::from(profile.warning_percent);
                        blocked |= used >= bytes;
                    }
                }
                QuotaStatus {
                    profile_id: profile.id.clone(),
                    daily_bytes: usage.daily_bytes,
                    monthly_bytes: usage.monthly_bytes,
                    daily_quota_mib: profile.daily_quota_mib,
                    monthly_quota_mib: profile.monthly_quota_mib,
                    warning_percent: profile.warning_percent,
                    warning,
                    blocked,
                    history_healthy: usage.healthy,
                }
            })
            .collect()
    }
}

impl Stats {
    /// Post-commit path for validated settings. All fallible I/O belongs before
    /// saving configuration; this preserves the active accounting Arc and pools.
    pub fn commit_history_settings(&self, settings: &crate::config::Settings) {
        let mut guard = self
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(runtime) = guard.as_mut() {
            runtime
                .history
                .commit_retention_days(settings.history_retention_days);
            runtime.settings = settings.clone();
        }
        self.profile_buckets
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .retain(|id, _| {
                settings
                    .device_profiles
                    .iter()
                    .any(|profile| &profile.id == id)
            });
    }
}

#[cfg(test)]
mod quota_status_tests {
    use super::*;
    fn settings() -> crate::config::Settings {
        crate::config::Settings { device_profiles: vec![serde_json::from_value(serde_json::json!({"id":"tv","name":"TV","username":"television","password":"0123456789abcdef","dailyQuotaMib":1,"monthlyQuotaMib":2,"warningPercent":80})).unwrap()], ..Default::default() }
    }
    #[test]
    fn transfer_reset_preserves_history_quota_and_in_flight_reservation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage.json");
        let stats = Stats::default();
        stats.configure_history(path.clone(), &settings()).unwrap();
        let peer = "192.168.1.20".parse().unwrap();
        let id = stats.begin_activity(peer, peer);
        stats.bind_principal(id, peer, Some("television")).unwrap();
        stats.traffic(peer, id, 100, 200);
        stats.history_saved(id, 80);
        let reservation = stats.reserve_transfer(id, peer, 500).unwrap().unwrap();
        stats.checkpoint_history().unwrap();
        let file = std::fs::read(&path).unwrap();
        let history = stats.history_json().unwrap();
        let quotas = serde_json::to_value(stats.quota_statuses()).unwrap();
        stats.reset_transfer_stats();
        assert_eq!(stats.history_json().unwrap(), history);
        assert_eq!(
            serde_json::to_value(stats.quota_statuses()).unwrap(),
            quotas
        );
        assert_eq!(std::fs::read(path).unwrap(), file);
        reservation.settle(0, 500).unwrap();
        stats.traffic_accounted(peer, id, 0, 500);
        assert_eq!(stats.quota_statuses()[0].daily_bytes, 800);
        let snapshot = stats.snapshot();
        assert_eq!((snapshot.upload_bytes, snapshot.download_bytes), (0, 500));
        assert_eq!(snapshot.activity[0].download_bytes, 700);
        assert_eq!(
            stats.history_report().unwrap().rows[0].counters.saved_bytes,
            80
        );
    }

    #[test]
    fn statuses_expose_warning_crash_debt_and_known_counters_when_history_fails() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage.json");
        let settings = settings();
        let stats = Stats::default();
        stats.configure_history(path.clone(), &settings).unwrap();
        let peer = "192.168.1.20".parse().unwrap();
        let id = stats.begin_activity(peer, peer);
        stats.bind_principal(id, peer, Some("television")).unwrap();
        stats
            .reserve_transfer(id, peer, 900_000)
            .unwrap()
            .unwrap()
            .settle(0, 900_000)
            .unwrap();
        let status = &stats.quota_statuses()[0];
        assert!(status.warning && !status.blocked && status.history_healthy);
        assert_eq!(status.daily_bytes, 900_000);
        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json["profileId"], "tv");
        assert!(json.get("password").is_none());
        let restarted = Stats::default();
        restarted
            .configure_history(path.clone(), &settings)
            .unwrap();
        let status = &restarted.quota_statuses()[0];
        assert!(status.warning && status.blocked && status.history_healthy);
        assert_eq!(status.daily_bytes, 1024 * 1024);
        fs_remove_then_directory(&path);
        assert!(stats.checkpoint_history().is_err());
        let status = &stats.quota_statuses()[0];
        assert!(!status.history_healthy && status.blocked);
        assert_eq!(status.daily_bytes, 900_000);
    }
    fn fs_remove_then_directory(path: &std::path::Path) {
        std::fs::remove_file(path).unwrap();
        std::fs::create_dir(path).unwrap();
    }
    #[test]
    fn infallible_settings_commit_preserves_reservation_without_more_durable_io() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage.json");
        let mut settings = settings();
        let stats = Stats::default();
        stats.configure_history(path, &settings).unwrap();
        let peer = "192.168.1.20".parse().unwrap();
        let id = stats.begin_activity(peer, peer);
        stats.bind_principal(id, peer, Some("television")).unwrap();
        let reservation = stats.reserve_transfer(id, peer, 500).unwrap().unwrap();
        let history = stats
            .runtime
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .history
            .clone();
        let writes = history.durable_write_count();
        settings.history_retention_days = 1;
        stats.commit_history_settings(&settings);
        assert_eq!(history.durable_write_count(), writes);
        assert_eq!(history.retention_days(), 1);
        reservation.settle(0, 500).unwrap();
        assert_eq!(stats.quota_statuses()[0].daily_bytes, 500);
        stats.checkpoint_history().unwrap();
        assert!(history.report().quota_debts.is_empty());
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    fn settings() -> crate::config::Settings {
        crate::config::Settings {
            device_profiles: vec![serde_json::from_value(serde_json::json!({
                "id":"tv", "name":"TV", "username":"television", "password":"fixture-only-password",
                "schedules":[
                    {"days":[1,2,3,4,5,6,7],"startMinute":0,"endMinute":1439,"action":"deny"},
                    {"days":[1,2,3,4,5,6,7],"startMinute":1439,"endMinute":0,"action":"deny"}
                ]
            }))
            .unwrap()],
            ..Default::default()
        }
    }

    #[test]
    fn fresh_check_does_not_bind_identity_or_admit_and_guard_still_denies_after_binding() {
        let directory = tempfile::tempdir().unwrap();
        let stats = Stats::default();
        let settings = settings();
        stats
            .configure_history(directory.path().join("usage.json"), &settings)
            .unwrap();
        let peer = "192.168.1.20".parse().unwrap();
        let id = stats.begin_activity(peer, peer);
        // A challenge can be retried on this same, still-unadmitted connection.
        stats.activity_authentication(id, false);
        let decision = stats
            .fresh_principal_transfer_decision(id, peer, "television")
            .unwrap()
            .unwrap();
        assert!(!decision.allowed);
        assert_eq!(decision.reason, crate::policy::PolicyReason::Schedule);
        {
            let runtime = stats.runtime.lock().unwrap();
            let binding = &runtime.as_ref().unwrap().bindings[&id];
            assert!(!binding.admitted);
            assert!(binding.profile_id.is_none() && binding.principal.is_none());
        }
        stats.bind_principal(id, peer, Some("television")).unwrap();
        assert!(stats
            .fresh_principal_transfer_decision(id, peer, "television")
            .unwrap()
            .is_none());
        assert!(stats.transfer_context(id, peer).is_err());
        assert!(stats.reserve_transfer(id, peer, 1).is_err());
        // Skip does not conceal or alter the original identity-conflict check.
        assert!(stats
            .fresh_principal_transfer_decision(id, peer, &settings.proxy_username)
            .unwrap()
            .is_none());
        assert!(stats
            .bind_principal(id, peer, Some(&settings.proxy_username))
            .is_err());
    }

    #[test]
    fn anonymous_admission_and_ip_alias_skip_first_admission_diagnostic() {
        let directory = tempfile::tempdir().unwrap();
        let stats = Stats::default();
        let mut settings = settings();
        let peer = "192.168.1.20".parse().unwrap();
        let path = directory.path().join("usage.json");
        stats.configure_history(path.clone(), &settings).unwrap();
        let id = stats.begin_activity(peer, peer);
        stats.bind_principal(id, peer, None).unwrap();
        assert!(stats
            .fresh_principal_transfer_decision(id, peer, "television")
            .unwrap()
            .is_none());
        // Upgrading an already used anonymous socket takes the original strict path.
        stats.bind_principal(id, peer, Some("television")).unwrap();
        assert!(stats.transfer_context(id, peer).is_err());
        settings.device_profiles[0].ips = vec!["192.168.1.20".parse().unwrap()];
        // An alias added after begin_activity also excludes pre-admission handling.
        let before_alias = stats.begin_activity(peer, peer);
        stats.configure_history(path, &settings).unwrap();
        assert!(stats
            .fresh_principal_transfer_decision(before_alias, peer, "television")
            .unwrap()
            .is_none());
        let with_alias = stats.begin_activity(peer, peer);
        assert!(stats
            .fresh_principal_transfer_decision(with_alias, peer, "television")
            .unwrap()
            .is_none());
        assert!(stats.transfer_context(with_alias, peer).is_err());
    }

    #[test]
    fn current_settings_and_peer_are_required_and_poisoned_runtime_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let stats = Stats::default();
        let mut settings = settings();
        let peer = "192.168.1.20".parse().unwrap();
        let path = directory.path().join("usage.json");
        stats.configure_history(path.clone(), &settings).unwrap();
        let id = stats.begin_activity(peer, peer);
        assert!(stats
            .fresh_principal_transfer_decision(id, peer, "unverified")
            .is_err());
        assert!(stats
            .fresh_principal_transfer_decision(id, "192.168.1.21".parse().unwrap(), "television")
            .is_err());
        settings.device_profiles.clear();
        stats.configure_history(path, &settings).unwrap();
        // A principal verified against an older request settings snapshot is rejected.
        assert!(stats
            .fresh_principal_transfer_decision(id, peer, "television")
            .is_err());
        assert!(stats.bind_principal(id, peer, Some("television")).is_err());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = stats.runtime.lock().unwrap();
            panic!("poison runtime for fail-closed regression");
        }));
        assert!(stats
            .fresh_principal_transfer_decision(id, peer, &settings.proxy_username)
            .is_err());
        assert!(stats.transfer_context(id, peer).is_err());
    }
}

#[cfg(test)]
mod diagnostic_observer_tests {
    use super::*;
    #[test]
    fn diagnostics_never_wait_for_history_live_or_traffic_locks() {
        let stats = Stats::default();
        let _history = stats.runtime.lock().unwrap();
        let live = stats.live.lock().unwrap();
        let traffic = stats.traffic.lock().unwrap();
        let observed = stats.diagnostic_metrics(60, true);
        assert!(!observed.live_available && !observed.traffic_available);
        drop(live);
        drop(traffic);
        let observed = stats.diagnostic_metrics(60, true);
        assert!(observed.live_available && observed.traffic_available);
        assert!(!observed.accounting_available);
    }
    #[tokio::test(start_paused = true)]
    async fn diagnostics_counts_only_proven_idle_and_excludes_datagram_lifetime() {
        let stats = Arc::new(Stats::default());
        stats.connection_limits(256, 128);
        let guards = (1..=256)
            .map(|id| stats.track_connection(id, "192.168.1.2".parse().unwrap()))
            .collect::<Vec<_>>();
        stats.connection_protocol(1, "socks5-udp");
        tokio::time::advance(std::time::Duration::from_secs(91)).await;
        stats.connection_progress(2);
        let metrics = stats.diagnostic_metrics(60, false);
        assert_eq!(metrics.active_connections, 256);
        assert_eq!(metrics.over_age_idle_connections, 254);
        assert!(!metrics.over_age_ids.contains(&1));
        assert!(!metrics.over_age_ids.contains(&2));
        assert!(metrics.live_connections.is_none());
        assert_eq!(
            stats
                .diagnostic_metrics(60, true)
                .live_connections
                .unwrap()
                .len(),
            256
        );
        drop(guards);
        assert_eq!(stats.diagnostic_metrics(60, true).active_connections, 0);
    }
}
