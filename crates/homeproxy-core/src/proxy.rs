use crate::https_policy::{
    host_matches_inspection_bypass, host_matches_pinned_update_service, host_matches_video_tunnel,
    normalized_host,
};
#[cfg(test)]
use crate::HttpsMode;
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

use bytes::Bytes;
use http::{
    header::{
        HeaderName, HeaderValue, ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, AGE, AUTHORIZATION,
        CACHE_CONTROL, CONNECTION, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LENGTH,
        CONTENT_TYPE, COOKIE, DATE, HOST, ORIGIN, PRAGMA, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
        RANGE, SET_COOKIE, TRANSFER_ENCODING, USER_AGENT, VARY,
    },
    uri::Authority,
    HeaderMap, Method, Request, Response, StatusCode, Uri,
};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full, Limited};
use hyper::{
    body::Incoming, client::conn::http1 as client_http1, server::conn::http1 as server_http1,
    service::service_fn, upgrade,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use sha2::{Digest, Sha256};
#[cfg(test)]
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    auth::DigestAuth,
    cache::{CacheStore, CachedEntry, FillClaim, TeeBody},
    config::{AdblockMode, CacheMode, Settings},
    dns::Resolver,
    filter::{destination_is_public, host_is_intrinsically_private, is_blocked_host},
    image_transform::transform_image,
    stats::{ConnectionRejectionReason, Stats},
    tls_inspection::{TlsInspection, TlsInspectionError},
    traffic::{BandwidthLimits, MeteredStream},
    ListenerBindFailure, ListenerBindReason, ListenerService,
};

#[cfg(test)]
use crate::cache::MAX_CACHE_ITEM_BYTES;
#[cfg(test)]
const MAX_BUFFERED_BODY: usize = 8 * 1024 * 1024;
#[cfg(test)]
const MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEADER_BUFFER: usize = 32 * 1024;
const MAX_CONNECTIONS: usize = 256;
const MAX_CONNECTIONS_PER_PEER: usize = 128;
const MAX_SOCKS5_METHODS: usize = 16;
const MAX_INSPECTION_FAIL_OPEN_HOSTS: usize = 256;
// A client that rejected (or never finished) our TLS for a host keeps doing so; a short
// window made such apps fail again on every expiry. Tunnels keep origin TLS intact.
const INSPECTION_FAIL_OPEN_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const VIA_VALUE: &str = "1.1 homeproxy";
const CA_DOWNLOAD_HOST: &str = "homeproxy.test";
const CA_DOWNLOAD_PATH: &str = "/ca.cer";

#[path = "proxy/accept.rs"]
mod accept;
#[path = "cache/proxy_policy.rs"]
mod cache_policy;
#[cfg(test)]
#[path = "proxy/cache_upgrade_tests.rs"]
mod cache_upgrade_tests;
#[path = "proxy/device_setup.rs"]
mod device_setup;
#[path = "proxy/health.rs"]
mod health;
#[path = "proxy/prefetch.rs"]
pub(crate) mod prefetch;
#[path = "proxy/transport.rs"]
mod transport;
#[path = "proxy/upstream.rs"]
mod upstream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type ConnectionActivity = transport::Activity<Box<dyn Fn() + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerProtocol {
    HttpMultiplexed,
    Socks5Dedicated,
}

struct BoundListener {
    listener: TcpListener,
    protocol: ListenerProtocol,
}

#[derive(Clone)]
struct ProxyContext {
    settings: Settings,
    cache_enabled: Arc<AtomicBool>,
    bandwidth: BandwidthLimits,
    activity_id: u64,
    // The accepted HTTP stream endpoint, never an address from another listener.
    listener_address: Option<SocketAddr>,
    connection_permit: Option<Arc<ConnectionPermit>>,
    resolver: Resolver,
    cache: CacheStore,
    stats: Arc<Stats>,
    auth: Arc<DigestAuth>,
    allow_private_destinations: bool,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    connections: ConnectionLimiter,
    udp_associations: ConnectionLimiter,
    transform_slots: Arc<Semaphore>,
    buffer_budget: Arc<Semaphore>,
    host_addresses: Arc<HashSet<IpAddr>>,
    tls_inspection: TlsInspection,
    inspection_bypass: InspectionBypass,
}

#[derive(Clone, Default)]
struct InspectionBypass {
    retries: Arc<StdMutex<HashMap<(IpAddr, String), Instant>>>,
}

impl InspectionBypass {
    fn should_bypass(&self, peer: IpAddr, host: &str) -> bool {
        if host_matches_inspection_bypass(host)
            || host_matches_video_tunnel(host)
            || host_matches_pinned_update_service(host)
        {
            return true;
        }
        let key = (peer, normalized_host(host));
        let now = Instant::now();
        let Ok(mut retries) = self.retries.lock() else {
            return false;
        };
        retries.retain(|_, expires_at| *expires_at > now);
        retries
            .get(&key)
            .is_some_and(|expires_at| *expires_at > now)
    }

    fn remember_rejected_inspection(&self, peer: IpAddr, host: &str) {
        let Ok(mut retries) = self.retries.lock() else {
            return;
        };
        let now = Instant::now();
        retries.retain(|_, expires_at| *expires_at > now);
        let key = (peer, normalized_host(host));
        if !retries.contains_key(&key) && retries.len() >= MAX_INSPECTION_FAIL_OPEN_HOSTS {
            if let Some(oldest) = retries
                .iter()
                .min_by_key(|(_, expires_at)| **expires_at)
                .map(|(key, _)| key.clone())
            {
                retries.remove(&oldest);
            }
        }
        retries.insert(key, now + INSPECTION_FAIL_OPEN_TTL);
    }
}

struct PrefixedStream {
    first_byte: Option<u8>,
    stream: MeteredStream,
}

impl PrefixedStream {
    fn new(first_byte: u8, stream: MeteredStream) -> Self {
        Self {
            first_byte: Some(first_byte),
            stream,
        }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buffer.remaining() > 0 {
            if let Some(first_byte) = self.first_byte.take() {
                buffer.put_slice(&[first_byte]);
                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[derive(Clone)]
struct InspectedOrigin {
    host: Arc<str>,
    resolver: Resolver,
    port: u16,
    allow_private_destinations: bool,
    tls_inspection: TlsInspection,
    tasks: TaskTracker,
    sender: Arc<AsyncMutex<Option<client_http1::SendRequest<ProxyBody>>>>,
    offline: bool,
    settings: Settings,
    host_addresses: Arc<HashSet<IpAddr>>,
    cancellation: CancellationToken,
    stats: Arc<Stats>,
    io_activity: Arc<ConnectionActivity>,
}

impl InspectedOrigin {
    fn new(host: &str, port: u16, context: &ProxyContext) -> Self {
        Self {
            host: Arc::from(host),
            offline: context.settings.cache_mode == CacheMode::Offline,
            settings: context.settings.clone(),
            host_addresses: context.host_addresses.clone(),
            resolver: context.resolver.clone(),
            port,
            allow_private_destinations: context.allow_private_destinations,
            tls_inspection: context.tls_inspection.clone(),
            tasks: context.tasks.clone(),
            sender: Arc::new(AsyncMutex::new(None)),
            cancellation: context.cancellation.clone(),
            stats: context.stats.clone(),
            io_activity: connection_activity(context),
        }
    }

    async fn send_boxed(
        &self,
        request: Request<ProxyBody>,
    ) -> Result<Response<Incoming>, ProxyError> {
        if self.offline {
            return Err(ProxyError::Offline);
        }
        let mut sender = self.sender.lock().await;
        if !sender_is_ready(&mut sender).await {
            *sender = Some(self.open_sender().await?);
        }
        let origin_sender = sender.as_mut().ok_or(ProxyError::Upstream(
            "HTTPS spojení nebylo možné připravit.",
        ))?;
        let result = timeout(
            UPSTREAM_RESPONSE_TIMEOUT,
            origin_sender.send_request(request),
        )
        .await;
        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                *sender = None;
                Err(ProxyError::Upstream("HTTPS web nevrátil platnou odpověď."))
            }
            Err(_) => {
                *sender = None;
                Err(ProxyError::Network("HTTPS web neodpověděl včas."))
            }
        }
    }

    async fn open_sender(&self) -> Result<client_http1::SendRequest<ProxyBody>, ProxyError> {
        let upstream = upstream::connect(
            &self.host,
            self.port,
            self.allow_private_destinations,
            &self.resolver,
            &self.settings,
            &self.host_addresses,
        )
        .await?;
        if transport::configure_keepalive(&upstream).is_err() {
            self.stats.keepalive_configuration_failed();
        }
        let upstream = timeout(
            CONNECT_TIMEOUT,
            self.tls_inspection.connect_upstream(&self.host, upstream),
        )
        .await
        .map_err(|_| ProxyError::Upstream("HTTPS web neodpověděl včas."))??;
        let (sender, connection) = timeout(
            UPSTREAM_RESPONSE_TIMEOUT,
            client_http1::handshake(TokioIo::new(transport::ProgressIo::new(
                upstream,
                self.io_activity.clone(),
            ))),
        )
        .await
        .map_err(|_| ProxyError::Upstream("HTTPS web neodpověděl včas."))?
        .map_err(|_| ProxyError::Upstream("HTTPS web nepřijal HTTP spojení."))?;
        let cancellation = self.cancellation.clone();
        self.tasks.spawn(async move {
            tokio::select! { _ = cancellation.cancelled() => {}, _ = connection.with_upgrades() => {} }
        });
        Ok(sender)
    }
}

async fn sender_is_ready(sender: &mut Option<client_http1::SendRequest<ProxyBody>>) -> bool {
    let Some(sender) = sender.as_mut() else {
        return false;
    };
    matches!(
        timeout(UPSTREAM_RESPONSE_TIMEOUT, sender.ready()).await,
        Ok(Ok(_))
    )
}

#[derive(Clone)]
struct ConnectionLimiter {
    global: Arc<Semaphore>,
    max_per_peer: usize,
    per_peer: Arc<StdMutex<HashMap<IpAddr, usize>>>,
}

impl Default for ConnectionLimiter {
    fn default() -> Self {
        Self {
            global: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            max_per_peer: MAX_CONNECTIONS_PER_PEER,
            per_peer: Arc::new(StdMutex::new(HashMap::new())),
        }
    }
}

impl ConnectionLimiter {
    fn try_acquire(&self, peer: IpAddr) -> Result<ConnectionPermit, ConnectionRejectionReason> {
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| ConnectionRejectionReason::GlobalLimit)?;
        let mut per_peer = self.per_peer.lock().unwrap_or_else(|e| e.into_inner());
        let count = per_peer.entry(peer).or_default();
        if *count >= self.max_per_peer {
            return Err(ConnectionRejectionReason::PeerLimit);
        }
        *count += 1;
        drop(per_peer);
        Ok(ConnectionPermit {
            _global: global,
            peer,
            per_peer: self.per_peer.clone(),
            diagnostics: None,
            io_activity: Arc::new(transport::Activity::new(Box::new(|| {}))),
            cancellation: None,
        })
    }
}

struct ConnectionPermit {
    _global: OwnedSemaphorePermit,
    peer: IpAddr,
    per_peer: Arc<StdMutex<HashMap<IpAddr, usize>>>,
    diagnostics: Option<crate::stats::ConnectionGuard>,
    io_activity: Arc<ConnectionActivity>,
    // Cancel origin drivers only when the last HTTP/upgrade owner releases the
    // socket. Origin drivers deliberately never retain this permit.
    cancellation: Option<CancellationToken>,
}

impl ConnectionPermit {
    fn track(&mut self, stats: &Arc<Stats>, id: u64) {
        self.diagnostics = Some(stats.track_connection(id, self.peer));
        // Install before sharing the permit. HTTP/Inspect client and origin I/O
        // then publish the same positive progress that renews their idle timer,
        // including origin control bytes that never reach MeteredStream.
        // Activity releases its clock lock before calling Stats. Capturing only
        // Stats and the ID keeps origin drivers from retaining this permit.
        let stats = stats.clone();
        self.io_activity = Arc::new(transport::Activity::new(Box::new(move || {
            stats.connection_progress(id);
        })));
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Some(cancellation) = self.cancellation.take() {
            cancellation.cancel();
        }
        // Remove telemetry before releasing either limit. Otherwise a newly
        // admitted socket could encounter a still-full diagnostic registry.
        drop(self.diagnostics.take());
        let Ok(mut per_peer) = self.per_peer.lock() else {
            return;
        };
        let Some(count) = per_peer.get_mut(&self.peer) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            per_peer.remove(&self.peer);
        }
    }
}

pub struct ProxyHandle {
    context: ProxyContext,
    cache: CacheStore,
    cache_enabled: Arc<AtomicBool>,
    cancellation: CancellationToken,
    join: JoinHandle<Result<(), ProxyError>>,
}

impl ProxyHandle {
    pub(crate) fn prefetch_executor(&self) -> prefetch::PrefetchExecutor {
        prefetch::PrefetchExecutor::new(self.context.clone())
    }
    pub fn set_cache_enabled(&self, enabled: bool) {
        self.cache_enabled.store(enabled, Ordering::Release);
        if !enabled {
            self.cache.invalidate();
        }
    }
    pub fn is_running(&self) -> bool {
        !self.join.is_finished()
    }

    pub(crate) fn runtime_error(&self) -> Option<String> {
        self.context.stats.listener_error()
    }

    pub async fn stop(mut self) {
        self.cache.invalidate();
        self.cancellation.cancel();
        if timeout(Duration::from_secs(2), &mut self.join)
            .await
            .is_err()
        {
            self.join.abort();
        }
    }
}

pub(crate) async fn start_proxy(
    settings: Settings,
    cache: CacheStore,
    stats: Arc<Stats>,
    tls_inspection: TlsInspection,
) -> Result<ProxyHandle, ProxyError> {
    let mut listeners = vec![
        bind_listener(
            SocketAddr::from((Ipv4Addr::LOCALHOST, settings.proxy_port)),
            ListenerProtocol::HttpMultiplexed,
        )
        .await?,
    ];
    if settings.lan_enabled {
        for listen_ip in settings
            .selected_listen_ips()
            .map_err(|_| ProxyError::InvalidTarget("Chybí adresa domácí sítě."))?
        {
            listeners.push(
                bind_listener(
                    SocketAddr::from((listen_ip, settings.proxy_port)),
                    ListenerProtocol::HttpMultiplexed,
                )
                .await?,
            );
        }
    }
    if settings.socks5_enabled {
        listeners.push(
            bind_listener(
                SocketAddr::from((Ipv4Addr::LOCALHOST, settings.socks5_port)),
                ListenerProtocol::Socks5Dedicated,
            )
            .await?,
        );
        if settings.lan_enabled {
            for listen_ip in settings
                .selected_listen_ips()
                .map_err(|_| ProxyError::InvalidTarget("Chybí adresa domácí sítě."))?
            {
                listeners.push(
                    bind_listener(
                        SocketAddr::from((listen_ip, settings.socks5_port)),
                        ListenerProtocol::Socks5Dedicated,
                    )
                    .await?,
                );
            }
        }
    }

    let cancellation = CancellationToken::new();
    let dns_endpoint = format!(
        "{}:{}",
        if settings.lan_enabled {
            settings.listen_ip().unwrap_or(Ipv4Addr::LOCALHOST)
        } else {
            Ipv4Addr::LOCALHOST
        },
        settings.lan_dns_port
    );
    let dns = crate::lan_dns::start(settings.clone(), &cancellation, cache.dns_answers())
        .await
        .map_err(|source| ProxyError::Bind {
            failure: ListenerBindFailure {
                service: ListenerService::Dns,
                endpoint: dns_endpoint,
                reason: listener_bind_reason(source.kind()),
            },
            source,
        })?;
    match spawn_proxy_with_cancellation(
        settings,
        cache,
        stats,
        tls_inspection,
        listeners,
        false,
        cancellation.clone(),
    ) {
        Ok(mut handle) => {
            let original = handle.join;
            handle.join = tokio::spawn(async move {
                let result = original.await.unwrap_or_else(|_| {
                    Err(ProxyError::Upstream("Úloha proxy neočekávaně skončila."))
                });
                if let Some(dns) = dns {
                    dns.stop().await;
                }
                result
            });
            Ok(handle)
        }
        Err(error) => {
            cancellation.cancel();
            if let Some(dns) = dns {
                dns.stop().await;
            }
            Err(error)
        }
    }
}

async fn bind_listener(
    endpoint: SocketAddr,
    protocol: ListenerProtocol,
) -> Result<BoundListener, ProxyError> {
    let listener = TcpListener::bind(endpoint)
        .await
        .map_err(|source| ProxyError::Bind {
            failure: ListenerBindFailure {
                service: match protocol {
                    ListenerProtocol::HttpMultiplexed => ListenerService::Http,
                    ListenerProtocol::Socks5Dedicated => ListenerService::Socks5,
                },
                endpoint: endpoint.to_string(),
                reason: listener_bind_reason(source.kind()),
            },
            source,
        })?;
    Ok(BoundListener { listener, protocol })
}

fn listener_bind_reason(kind: std::io::ErrorKind) -> ListenerBindReason {
    match kind {
        std::io::ErrorKind::AddrInUse => ListenerBindReason::InUse,
        std::io::ErrorKind::PermissionDenied => ListenerBindReason::AccessDenied,
        std::io::ErrorKind::AddrNotAvailable => ListenerBindReason::AddressUnavailable,
        _ => ListenerBindReason::Other,
    }
}

#[cfg(test)]
fn spawn_proxy_with_listeners(
    settings: Settings,
    cache: CacheStore,
    stats: Arc<Stats>,
    tls_inspection: TlsInspection,
    listeners: Vec<TcpListener>,
    allow_private_destinations: bool,
) -> Result<ProxyHandle, ProxyError> {
    cache.configure_limits(
        settings.cache_limit_bytes(),
        settings.cache_max_object_bytes(),
    );
    let listeners = listeners
        .into_iter()
        .map(|listener| BoundListener {
            listener,
            protocol: ListenerProtocol::HttpMultiplexed,
        })
        .collect();
    spawn_proxy_with_bound_listeners(
        settings,
        cache,
        stats,
        tls_inspection,
        listeners,
        allow_private_destinations,
    )
}

#[cfg(test)]
fn spawn_proxy_with_bound_listeners(
    settings: Settings,
    cache: CacheStore,
    stats: Arc<Stats>,
    tls_inspection: TlsInspection,
    listeners: Vec<BoundListener>,
    allow_private_destinations: bool,
) -> Result<ProxyHandle, ProxyError> {
    spawn_proxy_with_cancellation(
        settings,
        cache,
        stats,
        tls_inspection,
        listeners,
        allow_private_destinations,
        CancellationToken::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn spawn_proxy_with_cancellation(
    settings: Settings,
    cache: CacheStore,
    stats: Arc<Stats>,
    tls_inspection: TlsInspection,
    listeners: Vec<BoundListener>,
    allow_private_destinations: bool,
    cancellation: CancellationToken,
) -> Result<ProxyHandle, ProxyError> {
    let host_addresses = listeners
        .iter()
        .filter_map(|listener| listener.listener.local_addr().ok())
        .map(|address| address.ip())
        .collect::<HashSet<_>>();
    let cache_enabled = Arc::new(AtomicBool::new(settings.cache_enabled));
    let buffer_budget = Arc::new(Semaphore::new(settings.response_buffer_budget_bytes()));
    stats.connection_limits(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_PEER);
    stats.listener_recovered();
    let context = ProxyContext {
        bandwidth: BandwidthLimits::new(&settings.device_limits),
        cache_enabled: cache_enabled.clone(),
        activity_id: 0,
        listener_address: None,
        connection_permit: None,
        resolver: Resolver::new(if settings.cache_mode == CacheMode::Offline {
            crate::config::DnsMode::System
        } else {
            settings.dns_mode
        })
        .map_err(ProxyError::Upstream)?,
        settings,
        cache: cache.clone(),
        stats,
        auth: Arc::new(DigestAuth::default()),
        allow_private_destinations,
        cancellation: cancellation.clone(),
        tasks: TaskTracker::new(),
        connections: ConnectionLimiter::default(),
        udp_associations: udp::association_limiter(),
        transform_slots: Arc::new(Semaphore::new(1)),
        buffer_budget,
        host_addresses: Arc::new(host_addresses),
        tls_inspection,
        inspection_bypass: InspectionBypass::default(),
    };
    let join = tokio::spawn(run_listeners(listeners, context.clone()));
    Ok(ProxyHandle {
        context,
        cache,
        cancellation,
        join,
        cache_enabled,
    })
}

async fn run_listeners(
    listeners: Vec<BoundListener>,
    context: ProxyContext,
) -> Result<(), ProxyError> {
    let mut tasks = JoinSet::new();
    let mut failure = None;
    for listener in listeners {
        tasks.spawn(accept_loop(listener, context.clone()));
    }
    loop {
        tokio::select! {
            _ = context.cancellation.cancelled() => break,
            result = tasks.join_next() => {
                match result {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => {
                        context.cancellation.cancel();
                        failure = Some(error);
                        break;
                    }
                    Some(Err(_)) => {
                        context.cancellation.cancel();
                        failure = Some(ProxyError::Upstream("Úloha listeneru neočekávaně skončila."));
                        break;
                    }
                    None => break,
                }
            }
        }
    }
    context.cancellation.cancel();
    while let Some(result) = tasks.join_next().await {
        if failure.is_none() {
            match result {
                Ok(Err(error)) => failure = Some(error),
                Err(_) => {
                    failure = Some(ProxyError::Upstream(
                        "Úloha listeneru neočekávaně skončila.",
                    ));
                }
                Ok(Ok(())) => {}
            }
        }
    }
    context.tasks.close();
    context.tasks.wait().await;
    if let Some(error) = failure.as_ref() {
        context.stats.listener_runtime_error(error.to_string());
    }
    failure.map_or(Ok(()), Err)
}

async fn accept_loop(bound: BoundListener, context: ProxyContext) -> Result<(), ProxyError> {
    let BoundListener { listener, protocol } = bound;
    let endpoint = listener.local_addr()?;
    loop {
        let Some(accepted) = accept::next(
            || listener.accept(),
            &context.cancellation,
            |error| {
                context
                    .stats
                    .listener_accept_error(endpoint, error.to_string())
            },
        )
        .await?
        else {
            return Ok(());
        };
        let (stream, peer) = accepted;
        context.stats.listener_accept_recovered(endpoint);
        if !peer_is_allowed(peer.ip()) {
            continue;
        }
        let listener_address = match stream.local_addr() {
            Ok(address) => address,
            Err(error) => {
                context
                    .stats
                    .listener_accept_error(endpoint, error.to_string());
                continue;
            }
        };
        if transport::configure_keepalive(&stream).is_err() {
            context.stats.keepalive_configuration_failed();
        }
        let listener_ip = listener_address.ip();
        let connection_permit = match context.connections.try_acquire(peer.ip()) {
            Ok(permit) => permit,
            Err(reason) => {
                let limit = match reason {
                    ConnectionRejectionReason::PeerLimit => MAX_CONNECTIONS_PER_PEER,
                    ConnectionRejectionReason::GlobalLimit => MAX_CONNECTIONS,
                };
                context
                    .stats
                    .connection_rejected(peer.ip(), listener_ip, reason, limit);
                continue;
            }
        };
        let mut connection_context = context.clone();
        connection_context.cancellation = context.cancellation.child_token();
        let id = context.stats.begin_activity(peer.ip(), listener_ip);
        let mut connection_permit = connection_permit;
        connection_permit.track(&context.stats, id);
        connection_permit.cancellation = Some(connection_context.cancellation.clone());
        let connection_permit = Arc::new(connection_permit);
        connection_context.activity_id = id;
        connection_context.listener_address = Some(listener_address);
        if protocol == ListenerProtocol::HttpMultiplexed {
            connection_context.settings.proxy_port = listener_address.port();
        }
        connection_context.connection_permit = Some(connection_permit.clone());
        let stream = MeteredStream::new(
            stream,
            context.stats.clone(),
            peer.ip(),
            id,
            &context.bandwidth,
        );
        let connection_cancellation = connection_context.cancellation.clone();
        context.tasks.spawn(async move {
            let _connection_permit = connection_permit;
            let mut stream = stream;
            let first_byte = tokio::select! {
                _ = connection_cancellation.cancelled() => return,
                result = timeout(HEADER_READ_TIMEOUT, stream.read_u8()) => {
                    let Ok(Ok(first_byte)) = result else {
                        return;
                    };
                    first_byte
                }
            };
            match protocol {
                ListenerProtocol::HttpMultiplexed if first_byte == 5 => {
                    let result = handle_socks5(
                        stream,
                        peer,
                        &connection_context,
                        ListenerProtocol::HttpMultiplexed,
                    )
                    ;
                    tokio::select! { _ = connection_cancellation.cancelled() => {}, result = result => { if let Err(error) = result { connection_context.stats.activity_error(id, error.user_message()); } } }
                    return;
                }
                ListenerProtocol::Socks5Dedicated => {
                    if first_byte == 5 {
                        let result = handle_socks5(
                            stream,
                            peer,
                            &connection_context,
                            ListenerProtocol::Socks5Dedicated,
                        )
                        ;
                        tokio::select! { _ = connection_cancellation.cancelled() => {}, result = result => { if let Err(error) = result { connection_context.stats.activity_error(id, error.user_message()); } } }
                    }
                    return;
                }
                ListenerProtocol::HttpMultiplexed => {}
            }
            connection_context.stats.connection_protocol(id, "http");
            let io_activity = connection_activity(&connection_context);
            let idle_timeout = Duration::from_secs(u64::from(connection_context.settings.tunnel_idle_timeout_seconds));
            let stream = transport::ProgressIo::new(PrefixedStream::new(first_byte, stream), io_activity.clone());
            let connection_stats = connection_context.stats.clone();
            let service = service_fn(move |request| {
                let context = connection_context.clone();
                async move { Ok::<_, Infallible>(handle_request(request, peer, context).await) }
            });
            let mut builder = server_http1::Builder::new();
            builder
                .keep_alive(true)
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .max_buf_size(MAX_HEADER_BUFFER);
            let connection = builder
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            match transport::bounded(connection, &connection_cancellation, idle_timeout, &io_activity).await {
                transport::BoundOutcome::Finished(result) => { record_connection_result(&connection_stats, id, &result, "HTTP-connection-failed"); },
                transport::BoundOutcome::Idle => {
                    connection_cancellation.cancel();
                    connection_stats.connection_idle_closed(id);
                    connection_stats.activity_error(id, "HTTP-idle-timeout");
                }
                transport::BoundOutcome::Cancelled => {}
            }
        });
    }
}

async fn handle_socks5(
    mut client: MeteredStream,
    peer: SocketAddr,
    context: &ProxyContext,
    protocol: ListenerProtocol,
) -> Result<(), ProxyError> {
    context
        .stats
        .connection_protocol(context.activity_id, "socks5");
    context.stats.request(peer.ip());
    if protocol == ListenerProtocol::HttpMultiplexed && !peer.ip().is_loopback() {
        let _ = client.write_all(&[5, 0xff]).await;
        return Err(ProxyError::Forbidden(
            "SOCKS5 je dostupný jen z tohoto počítače.",
        ));
    }
    let external_device = peer_is_external_device(peer.ip(), &context.host_addresses);
    if external_device && device_is_denied(peer.ip(), &context.settings) {
        let _ = client.write_all(&[5, 0xff]).await;
        return Err(ProxyError::Forbidden("Zařízení je v HomeProxy zakázané."));
    }

    let method_count = read_socks5_u8(&mut client).await? as usize;
    if method_count == 0 || method_count > MAX_SOCKS5_METHODS {
        let _ = client.write_all(&[5, 0xff]).await;
        return Err(ProxyError::InvalidTarget(
            "SOCKS5 nabízí neplatný počet způsobů přihlášení.",
        ));
    }
    let mut methods = vec![0u8; method_count];
    read_socks5_exact(&mut client, &mut methods).await?;
    let required_method = socks5_auth_method(peer.ip(), &context.settings);
    let method = if required_method == 2
        || (methods.contains(&2)
            && (!methods.contains(&0) || !context.settings.device_profiles.is_empty()))
    {
        2
    } else {
        0
    };
    if !methods.contains(&method) {
        client.write_all(&[5, 0xff]).await?;
        return Ok(());
    }
    client.write_all(&[5, method]).await?;
    let principal = if method == 2 {
        authenticate_socks5(&mut client, &context.settings).await?
    } else {
        None
    };
    context
        .stats
        .bind_principal(context.activity_id, peer.ip(), principal.as_deref())
        .map_err(|_| ProxyError::Forbidden("SOCKS5 identita není platná."))?;
    if external_device {
        context.stats.authenticated_external_request();
        context.stats.client_seen(peer.ip());
    }

    let mut request = [0u8; 4];
    read_socks5_exact(&mut client, &mut request).await?;
    if request[0] != 5 || request[2] != 0 {
        write_socks5_reply(&mut client, 1, None).await?;
        return Err(ProxyError::InvalidTarget(
            "SOCKS5 požadavek nemá platný formát.",
        ));
    }

    let host = match request[3] {
        1 => {
            let mut address = [0u8; 4];
            read_socks5_exact(&mut client, &mut address).await?;
            IpAddr::V4(address.into()).to_string()
        }
        3 => {
            let length = read_socks5_u8(&mut client).await? as usize;
            let mut domain = vec![0u8; length];
            read_socks5_exact(&mut client, &mut domain).await?;
            // Consume the fixed port field below before rejecting a malformed name.
            // Closing with unread request bytes can reset Windows TCP before REP=08 arrives.
            std::str::from_utf8(&domain)
                .ok()
                .filter(|domain| crate::dns::valid_host(domain))
                .unwrap_or_default()
                .to_owned()
        }
        4 => {
            let mut address = [0u8; 16];
            read_socks5_exact(&mut client, &mut address).await?;
            IpAddr::V6(address.into()).to_string()
        }
        _ => {
            write_socks5_reply(&mut client, 8, None).await?;
            return Err(ProxyError::InvalidTarget(
                "SOCKS5 používá neznámý typ adresy.",
            ));
        }
    };
    let mut port_bytes = [0u8; 2];
    read_socks5_exact(&mut client, &mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);
    if context.settings.cache_mode == CacheMode::Offline {
        write_socks5_reply(&mut client, 2, None).await?;
        return Err(ProxyError::Offline);
    }
    if request[1] == 3 && context.settings.socks5_enabled && context.settings.socks5_udp_enabled {
        context
            .stats
            .connection_protocol(context.activity_id, "socks5-udp");
        return udp::associate(client, peer, context, &host, port, external_device).await;
    }
    if request[1] != 1 {
        let reason = match request[1] {
            3 => "socks5-udp-disabled",
            2 => "socks5-bind-unsupported",
            _ => "socks5-command-unsupported",
        };
        write_socks5_reply(&mut client, 7, None).await?;
        client.shutdown().await?;
        return Err(ProxyError::InvalidTarget(reason));
    }

    if request[3] == 3 && host.is_empty() {
        write_socks5_reply(&mut client, 8, None).await?;
        client.shutdown().await?;
        return Err(ProxyError::InvalidTarget(
            "SOCKS5 hostitel není platný název.",
        ));
    }
    context.stats.describe_activity(
        context.activity_id,
        &host,
        if request[3] == 3 {
            "SOCKS5 remote DNS"
        } else {
            "SOCKS5 IP"
        },
    );

    if port == 0 {
        write_socks5_reply(&mut client, 8, None).await?;
        return Err(ProxyError::InvalidTarget("SOCKS5 port nesmí být nula."));
    }

    if let Err(error) = enforce_runtime_policy(context, &host, context.settings.adblock_mode) {
        write_socks5_reply(&mut client, socks5_reply_for_error(&error), None).await?;
        return Err(error);
    }
    let mut upstream = match connect_for_context(&host, port, context).await {
        Ok(upstream) => upstream,
        Err(error) => {
            write_socks5_reply(&mut client, socks5_reply_for_error(&error), None).await?;
            return Err(error);
        }
    };
    let bound_address = upstream.local_addr().ok();
    write_socks5_reply(&mut client, 0, bound_address).await?;
    client.verify_external_on_payload(external_device);
    if external_device {
        context.stats.client_seen(peer.ip());
    }
    context.stats.tunnel();
    context.stats.socks5_connection();

    match transport::relay(
        &mut client,
        &mut upstream,
        &context.cancellation,
        Duration::from_secs(u64::from(context.settings.tunnel_idle_timeout_seconds)),
        || context.stats.connection_progress(context.activity_id),
    )
    .await
    {
        transport::RelayOutcome::Finished(result) => result.map(|_| ()).map_err(ProxyError::Io),
        transport::RelayOutcome::Idle => {
            context.stats.connection_idle_closed(context.activity_id);
            Ok(())
        }
        transport::RelayOutcome::Cancelled => Ok(()),
    }
}

async fn authenticate_socks5<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    settings: &Settings,
) -> Result<Option<String>, ProxyError> {
    let version = read_socks5_u8(client).await?;
    let username_length = read_socks5_u8(client).await? as usize;
    if version != 1 || username_length == 0 {
        let _ = client.write_all(&[1, 1]).await;
        return Err(ProxyError::Forbidden("SOCKS5 přihlášení nebylo přijato."));
    }
    let mut username = vec![0; username_length];
    read_socks5_exact(client, &mut username).await?;
    let password_length = read_socks5_u8(client).await? as usize;
    if password_length == 0 {
        let _ = client.write_all(&[1, 1]).await;
        return Err(ProxyError::Forbidden("SOCKS5 přihlášení nebylo přijato."));
    }
    let mut password = vec![0; password_length];
    read_socks5_exact(client, &mut password).await?;

    let principal = crate::auth::authenticate_credentials(&username, &password, settings);
    if principal.is_none() {
        client.write_all(&[1, 1]).await?;
        return Err(ProxyError::Forbidden("SOCKS5 přihlášení nebylo přijato."));
    }
    client.write_all(&[1, 0]).await?;
    Ok(principal)
}

#[cfg(test)]
fn constant_time_bytes_equal(left: &[u8], right: &[u8]) -> bool {
    let left_digest = Sha256::digest(left);
    let right_digest = Sha256::digest(right);
    bool::from(left_digest.ct_eq(&right_digest))
}

#[cfg(test)]
fn socks5_credentials_match(username: &[u8], password: &[u8], settings: &Settings) -> bool {
    constant_time_bytes_equal(username, settings.proxy_username.as_bytes())
        && constant_time_bytes_equal(password, settings.proxy_password.as_bytes())
}

fn socks5_auth_method(peer: IpAddr, settings: &Settings) -> u8 {
    if request_requires_lan_auth(peer, settings) {
        2
    } else {
        0
    }
}

async fn read_socks5_u8<S: AsyncRead + Unpin>(stream: &mut S) -> Result<u8, ProxyError> {
    let mut byte = [0u8; 1];
    read_socks5_exact(stream, &mut byte).await?;
    Ok(byte[0])
}

async fn read_socks5_exact<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &mut [u8],
) -> Result<(), ProxyError> {
    timeout(HEADER_READ_TIMEOUT, stream.read_exact(buffer))
        .await
        .map_err(|_| ProxyError::InvalidTarget("SOCKS5 požadavek nebyl dokončen včas."))??;
    Ok(())
}

async fn write_socks5_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u8,
    bound_address: Option<SocketAddr>,
) -> Result<(), ProxyError> {
    let mut response = vec![5, code, 0];
    match bound_address {
        Some(SocketAddr::V4(address)) => {
            response.push(1);
            response.extend_from_slice(&address.ip().octets());
            response.extend_from_slice(&address.port().to_be_bytes());
        }
        Some(SocketAddr::V6(address)) => {
            response.push(4);
            response.extend_from_slice(&address.ip().octets());
            response.extend_from_slice(&address.port().to_be_bytes());
        }
        None => response.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0]),
    }
    stream.write_all(&response).await?;
    Ok(())
}

fn socks5_reply_for_error(error: &ProxyError) -> u8 {
    match error {
        ProxyError::Offline | ProxyError::Forbidden(_) | ProxyError::Blocked => 2,
        ProxyError::InvalidTarget(_) => 8,
        ProxyError::Network(_) | ProxyError::Upstream(_) => 4,
        ProxyError::Busy(_) => 1,
        ProxyError::Bind { .. }
        | ProxyError::Io(_)
        | ProxyError::BuildResponse(_)
        | ProxyError::Tls(_) => 1,
    }
}

async fn handle_request(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    context: ProxyContext,
) -> Response<ProxyBody> {
    if let Some(response) = health::response(&request, peer) {
        return response;
    }
    context.stats.request(peer.ip());
    context.stats.describe_activity(
        context.activity_id,
        request.uri().host().unwrap_or(""),
        if request.method() == Method::CONNECT {
            "CONNECT"
        } else {
            "HTTP"
        },
    );
    let external_device = peer_is_external_device(peer.ip(), &context.host_addresses);

    if external_device && device_is_denied(peer.ip(), &context.settings) {
        context
            .stats
            .activity_error(context.activity_id, "device-denied");
        return denied_device_response();
    }

    if let Some(response) = device_setup::response(&request, &context) {
        return response;
    }

    if context.settings.pac_enabled && is_pac_request(&request, &context) {
        return pac_response(&context)
            .unwrap_or_else(|error| error_response(error.status(), error.user_message()));
    }
    let requires_auth = request_requires_lan_auth(peer.ip(), &context.settings);
    let provided_auth = request.headers().contains_key(PROXY_AUTHORIZATION);
    let principal = context.auth.authenticate(&request, &context.settings);
    if (requires_auth || (provided_auth && !context.settings.device_profiles.is_empty()))
        && principal.is_none()
    {
        context
            .stats
            .activity_authentication(context.activity_id, false);
        return proxy_auth_required(
            context
                .auth
                .challenge(request.method(), &request.uri().to_string()),
        );
    }
    if let Some(username) = principal.as_deref() {
        match context.stats.fresh_principal_transfer_decision(
            context.activity_id,
            peer.ip(),
            username,
        ) {
            Ok(Some(decision)) if !decision.allowed => {
                context.stats.blocked();
                context
                    .stats
                    .activity_authentication(context.activity_id, true);
                context.stats.activity_error(
                    context.activity_id,
                    &format!("policy-{:?}", decision.reason),
                );
                // A fixed first-admission diagnostic uses the still-unbound stream.
                // It never grants profile quota, DNS/cache access or an upgrade.
                const MESSAGE: &str = "Přístup zakazuje profil, doménové pravidlo, čas nebo kvóta.";
                let mut response = error_response(StatusCode::FORBIDDEN, MESSAGE);
                response.headers_mut().insert(
                    CONTENT_LENGTH,
                    HeaderValue::from_str(&MESSAGE.len().to_string()).unwrap(),
                );
                response
                    .headers_mut()
                    .insert(CONNECTION, HeaderValue::from_static("close"));
                return response;
            }
            Err(_) => {
                context
                    .stats
                    .activity_error(context.activity_id, "identity-conflict");
                return error_response(
                    StatusCode::FORBIDDEN,
                    "Identitu živého spojení nelze změnit.",
                );
            }
            _ => {}
        }
    }
    // Preflight is advisory: binding conflicts, current destination policy and
    // every transport reservation still enforce changes/races fail closed.
    if let Err(_error) =
        context
            .stats
            .bind_principal(context.activity_id, peer.ip(), principal.as_deref())
    {
        context
            .stats
            .activity_error(context.activity_id, "identity-conflict");
        return error_response(
            StatusCode::FORBIDDEN,
            "Identitu živého spojení nelze změnit.",
        );
    }
    if requires_auth || principal.is_some() {
        context
            .stats
            .activity_authentication(context.activity_id, true);
    }
    if external_device {
        context.stats.authenticated_external_request();
        context.stats.client_seen(peer.ip());
    }
    request.headers_mut().remove(PROXY_AUTHORIZATION);

    if request.method() == Method::CONNECT {
        return connect_tunnel(request, peer, external_device, &context)
            .await
            .unwrap_or_else(|error| {
                context
                    .stats
                    .activity_error(context.activity_id, error.user_message());
                error_response(error.status(), error.user_message())
            });
    }

    let result = forward_http(request, &context).await;
    record_successful_external_result(&context.stats, external_device, result.is_ok());
    result.unwrap_or_else(|error| {
        context
            .stats
            .activity_error(context.activity_id, error.user_message());
        error_response(error.status(), error.user_message())
    })
}

fn connect_adblock_mode(host: &str, configured: AdblockMode) -> AdblockMode {
    if host_matches_inspection_bypass(host) {
        AdblockMode::Off
    } else {
        configured
    }
}

fn connect_should_bypass_inspection(
    context: &ProxyContext,
    peer: IpAddr,
    host: &str,
    port: u16,
) -> bool {
    !crate::https_policy::host_is_inspected(&context.settings, host)
        || context.inspection_bypass.should_bypass(peer, host)
        || loopback_nonstandard_connect(peer, port, context.allow_private_destinations)
        // These service ports carry TCP protocols that need not start with TLS.
        || (!context.allow_private_destinations && tcp_service_port(port))
}

fn ensure_online(context: &ProxyContext) -> Result<(), ProxyError> {
    if context.settings.cache_mode == CacheMode::Offline {
        Err(ProxyError::Offline)
    } else {
        Ok(())
    }
}

fn tcp_service_port(port: u16) -> bool {
    matches!(port, 80 | 5060 | 8080)
}

fn loopback_nonstandard_connect(peer: IpAddr, port: u16, allow_private_destinations: bool) -> bool {
    !allow_private_destinations && peer.is_loopback() && port != 443
}

async fn connect_tunnel(
    request: Request<Incoming>,
    peer: SocketAddr,
    external_device: bool,
    context: &ProxyContext,
) -> Result<Response<ProxyBody>, ProxyError> {
    context
        .stats
        .connection_protocol(context.activity_id, "connect");
    let authority = request
        .uri()
        .authority()
        .cloned()
        .ok_or(ProxyError::InvalidTarget("CONNECT nemá platný cíl."))?;
    if authority.as_str().contains('@') {
        return Err(ProxyError::InvalidTarget(
            "Cíl nesmí obsahovat přihlašovací údaje.",
        ));
    }
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);
    if port != 443
        && !tcp_service_port(port)
        && !context.allow_private_destinations
        && !peer.ip().is_loopback()
    {
        return Err(ProxyError::Forbidden(
            "CONNECT ze sítě LAN je povolený jen na porty 80, 443, 5060 a 8080.",
        ));
    }
    enforce_runtime_policy(
        context,
        &host,
        connect_adblock_mode(&host, context.settings.adblock_mode),
    )?;
    let tunnel_permit = context
        .connection_permit
        .clone()
        .ok_or(ProxyError::Busy("Spojení nemá platný limit."))?;
    if connect_should_bypass_inspection(context, peer.ip(), &host, port) {
        return raw_connect_tunnel(request, external_device, context, host, port, tunnel_permit)
            .await;
    }
    let server_config = context.tls_inspection.server_config_for_host(&host)?;
    context
        .stats
        .connection_protocol(context.activity_id, "inspect");
    let origin = InspectedOrigin::new(&host, port, context);
    context.stats.tunnel();

    let cancellation = context.cancellation.clone();
    let inner_context = context.clone();
    let rejected_host = host.clone();
    let rejected_peer = peer.ip();
    context.tasks.spawn(async move {
        let _tunnel_permit = tunnel_permit;
        let upgraded = tokio::select! {
            _ = cancellation.cancelled() => return,
            upgraded = timeout(HEADER_READ_TIMEOUT, upgrade::on(request)) => upgraded,
        };
        let Ok(Ok(upgraded)) = upgraded else {
            inner_context
                .stats
                .activity_error(inner_context.activity_id, "CONNECT-upgrade-failed");
            return;
        };
        // Only a client that actually spoke to us and failed is remembered as not
        // trusting the CA (or not speaking TLS): a rejected certificate, a stalled
        // handshake after our certificate, or bytes that are not a ClientHello.
        // Browser preconnects that close or idle before sending anything are not.
        // A protocol where the server speaks first (e.g. SSH on 443) therefore needs
        // a domain exception.
        let hello = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = timeout(
                HEADER_READ_TIMEOUT,
                tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    TokioIo::new(upgraded),
                ),
            ) => result,
        };
        let start = match hello {
            Ok(Ok(start)) => start,
            Err(_) => {
                inner_context
                    .stats
                    .activity_error(inner_context.activity_id, "TLS-client-hello-timeout");
                return;
            }
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                inner_context
                    .stats
                    .activity_error(inner_context.activity_id, "TLS-client-hello-missing");
                return;
            }
            Ok(Err(_)) => {
                inner_context
                    .stats
                    .activity_error(inner_context.activity_id, "TLS-client-hello-invalid");
                inner_context
                    .inspection_bypass
                    .remember_rejected_inspection(rejected_peer, &rejected_host);
                inner_context.stats.inspection_fail_open_remembered();
                return;
            }
        };
        // The handshake gets its own full window from the received ClientHello.
        let handshake = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = timeout(HEADER_READ_TIMEOUT, start.into_stream(server_config)) => result,
        };
        let client_tls = match handshake {
            Ok(Ok(client_tls)) => client_tls,
            Err(_) => {
                inner_context
                    .stats
                    .activity_error(inner_context.activity_id, "TLS-handshake-timeout");
                inner_context
                    .inspection_bypass
                    .remember_rejected_inspection(rejected_peer, &rejected_host);
                inner_context.stats.inspection_fail_open_remembered();
                return;
            }
            Ok(Err(_)) => {
                inner_context
                    .stats
                    .activity_error(inner_context.activity_id, "TLS-handshake-rejected");
                inner_context
                    .inspection_bypass
                    .remember_rejected_inspection(rejected_peer, &rejected_host);
                inner_context.stats.inspection_fail_open_remembered();
                return;
            }
        };
        let sni = client_tls.get_ref().1.server_name();
        if sni.is_some_and(|name| !name.eq_ignore_ascii_case(authority.host()))
            || (authority.host().parse::<IpAddr>().is_err() && sni.is_none())
        {
            inner_context
                .stats
                .activity_error(inner_context.activity_id, "TLS-SNI-authority-mismatch");
            return;
        }
        // Start the inspected application window after the separate TLS handshake.
        // Observe positive application reads/writes above the inspected TLS stream.
        let io_activity = connection_activity(&inner_context);
        let idle_timeout = Duration::from_secs(u64::from(
            inner_context.settings.tunnel_idle_timeout_seconds,
        ));
        let client_tls = transport::ProgressIo::new(client_tls, io_activity.clone());
        let activity_stats = inner_context.stats.clone();
        let activity_id = inner_context.activity_id;
        let service = service_fn(move |request| {
            let context = inner_context.clone();
            let origin = origin.clone();
            let authority = authority.clone();
            async move {
                let result = handle_inspected_request(request, &authority, origin, &context).await;
                record_successful_external_result(&context.stats, external_device, result.is_ok());
                Ok::<_, Infallible>(result.unwrap_or_else(|error| {
                    context
                        .stats
                        .activity_error(context.activity_id, error.user_message());
                    error_response(error.status(), error.user_message())
                }))
            }
        });
        let mut builder = server_http1::Builder::new();
        builder
            .keep_alive(true)
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .max_buf_size(MAX_HEADER_BUFFER);
        let connection = builder
            .serve_connection(TokioIo::new(client_tls), service)
            .with_upgrades();
        match transport::bounded(connection, &cancellation, idle_timeout, &io_activity).await {
            transport::BoundOutcome::Finished(result) => {
                record_connection_result(
                    &activity_stats,
                    activity_id,
                    &result,
                    "HTTPS-connection-failed",
                );
            }
            transport::BoundOutcome::Idle => {
                cancellation.cancel();
                activity_stats.connection_idle_closed(activity_id);
                activity_stats.activity_error(activity_id, "HTTPS-idle-timeout");
            }
            transport::BoundOutcome::Cancelled => {}
        }
    });

    connect_established_response()
}

async fn raw_connect_tunnel(
    request: Request<Incoming>,
    external_device: bool,
    context: &ProxyContext,
    host: String,
    port: u16,
    tunnel_permit: Arc<ConnectionPermit>,
) -> Result<Response<ProxyBody>, ProxyError> {
    ensure_online(context)?;
    let mut upstream = connect_for_context(&host, port, context).await?;
    context.stats.tunnel();
    let cancellation = context.cancellation.clone();
    let stats = context.stats.clone();
    let activity_id = context.activity_id;
    let idle_timeout = Duration::from_secs(u64::from(context.settings.tunnel_idle_timeout_seconds));
    context.tasks.spawn(async move {
        let _tunnel_permit = tunnel_permit;
        let upgraded = tokio::select! {
            _ = cancellation.cancelled() => return,
            upgraded = timeout(HEADER_READ_TIMEOUT, upgrade::on(request)) => upgraded,
        };
        let Ok(Ok(upgraded)) = upgraded else {
            stats.activity_error(activity_id, "CONNECT-upgrade-failed");
            return;
        };
        let mut client = TokioIo::new(upgraded);
        let succeeded = match transport::relay(
            &mut client,
            &mut upstream,
            &cancellation,
            idle_timeout,
            || stats.connection_progress(activity_id),
        )
        .await
        {
            transport::RelayOutcome::Finished(result) => {
                record_connection_result(&stats, activity_id, &result, "CONNECT-relay-failed")
            }
            transport::RelayOutcome::Idle => {
                stats.connection_idle_closed(activity_id);
                false
            }
            transport::RelayOutcome::Cancelled => false,
        };
        record_successful_external_result(&stats, external_device, succeeded);
    });
    connect_established_response()
}

fn record_connection_result<T, E>(
    stats: &Stats,
    id: u64,
    result: &Result<T, E>,
    error: &'static str,
) -> bool {
    if result.is_err() {
        stats.activity_error(id, error);
    }
    result.is_ok()
}

fn connect_established_response() -> Result<Response<ProxyBody>, ProxyError> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Proxy-Agent", "HomeProxy/0.4")
        .body(empty_body())
        .map_err(ProxyError::BuildResponse)
}

async fn handle_inspected_request(
    mut request: Request<Incoming>,
    connect_authority: &Authority,
    origin: InspectedOrigin,
    context: &ProxyContext,
) -> Result<Response<ProxyBody>, ProxyError> {
    if request.method() == Method::CONNECT {
        return Err(ProxyError::InvalidTarget(
            "Vnořený HTTPS CONNECT není povolený.",
        ));
    }
    validate_inspected_authority(&request, connect_authority)?;
    context
        .stats
        .describe_activity(context.activity_id, connect_authority.host(), "HTTPS");
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    *request.uri_mut() = Uri::builder()
        .scheme("https")
        .authority(connect_authority.clone())
        .path_and_query(path_and_query)
        .build()
        .map_err(|_| ProxyError::InvalidTarget("HTTPS adresa není platná."))?;
    request.headers_mut().remove(PROXY_AUTHORIZATION);
    forward_web_request(
        box_request(request),
        context,
        WebOrigin::Inspected(Box::new(origin)),
    )
    .await
}

fn validate_inspected_authority<B>(
    request: &Request<B>,
    connect_authority: &Authority,
) -> Result<(), ProxyError> {
    if request
        .uri()
        .scheme_str()
        .is_some_and(|scheme| scheme != "https")
    {
        return Err(ProxyError::Forbidden(
            "HTTPS požadavek neodpovídá otevřenému webu.",
        ));
    }
    let mut hosts = request.headers().get_all(HOST).iter();
    let host = hosts
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(ProxyError::InvalidTarget("HTTPS požadavek nemá hostitele."))?
        .parse::<Authority>()
        .map_err(|_| ProxyError::InvalidTarget("HTTPS hostitel není platný."))?;
    if hosts.next().is_some() {
        return Err(ProxyError::InvalidTarget(
            "HTTPS požadavek má více hostitelů.",
        ));
    }
    for authority in std::iter::once(&host).chain(request.uri().authority()) {
        if authority.as_str().contains('@')
            || !authority
                .host()
                .eq_ignore_ascii_case(connect_authority.host())
            || authority.port_u16().unwrap_or(443) != connect_authority.port_u16().unwrap_or(443)
        {
            return Err(ProxyError::Forbidden(
                "HTTPS požadavek neodpovídá otevřenému webu.",
            ));
        }
    }
    Ok(())
}

async fn forward_http(
    request: Request<Incoming>,
    context: &ProxyContext,
) -> Result<Response<ProxyBody>, ProxyError> {
    let uri = request.uri().clone();
    if uri.scheme_str() != Some("http") {
        return Err(ProxyError::InvalidTarget(
            "Proxy očekává úplnou adresu http:// nebo HTTPS CONNECT.",
        ));
    }
    if is_ca_download_request(&request) {
        return ca_download_response(context);
    }
    let authority = uri
        .authority()
        .ok_or(ProxyError::InvalidTarget("HTTP adresa nemá hostitele."))?;
    if authority.as_str().contains('@') {
        return Err(ProxyError::InvalidTarget(
            "Adresa nesmí obsahovat přihlašovací údaje.",
        ));
    }
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(80);
    if port != 80 && !tcp_service_port(port) && !context.allow_private_destinations {
        return Err(ProxyError::Forbidden(
            "Nešifrované HTTP je povolené jen na porty 80, 5060 a 8080.",
        ));
    }
    enforce_runtime_policy(context, host, context.settings.adblock_mode)?;

    forward_web_request(
        box_request(request),
        context,
        WebOrigin::Plain {
            host: host.to_string(),
            port,
        },
    )
    .await
}

enum WebOrigin {
    Plain { host: String, port: u16 },
    Inspected(Box<InspectedOrigin>),
}

fn retire_variant_keys(
    cache: &CacheStore,
    epoch: u64,
    keys: &[String],
    guard: Option<&crate::cache::CacheKeyGuard>,
    successor: &mut Option<crate::cache::CacheKeyGuard>,
) -> Option<u64> {
    let (epoch, replacement) = cache.invalidate_keys_and_request_at_epoch(epoch, keys, guard?)?;
    *successor = Some(replacement);
    Some(epoch)
}

async fn retire_known_variant(
    cache: &CacheStore,
    base: &str,
    token: u64,
    epoch: u64,
    key: &str,
    guard: Option<&crate::cache::CacheKeyGuard>,
) -> Option<(u64, u64, crate::cache::CacheKeyGuard)> {
    let mut successor = None;
    let (token, epoch) = cache.variants.retire_writers(base, token, || {
        retire_variant_keys(cache, epoch, &[key.to_owned()], guard, &mut successor)
    })?;
    let successor = successor?;
    if !cache.variants.bind_guard(base, token, successor.clone()) {
        return None;
    }
    // A held reader/pin may retain the body; the durable invalidation already
    // forbids reuse, so cleanup contention does not undo retirement.
    let _ = cache.remove_invalidated(key).await;
    Some((token, epoch, successor))
}

fn finish_variant_recovery(
    context: &ProxyContext,
    checkpoint: &mut Option<crate::cache::CacheRecoveryToken>,
) -> bool {
    let Some(token) = checkpoint.take() else {
        return true;
    };
    if context.cache.finish_recovery_checkpoint(&token).is_err() {
        context.stats.cache_outcome(
            context.activity_id,
            "bypass",
            Some("cache-recovery-checkpoint-failed"),
        );
        // Drop intentionally retains the durable record for restart recovery.
        false
    } else {
        true
    }
}

async fn forward_web_request(
    mut request: Request<ProxyBody>,
    context: &ProxyContext,
    origin: WebOrigin,
) -> Result<Response<ProxyBody>, ProxyError> {
    let policy = enforce_runtime_policy(
        context,
        request.uri().host().unwrap_or(""),
        context.settings.adblock_mode,
    )?;
    if request.headers().contains_key("upgrade")
        || header_contains_token(request.headers(), CONNECTION, "upgrade")
    {
        return forward_websocket(request, context, origin).await;
    }
    if context.settings.cache_mode == CacheMode::Offline
        || cache_policy::only_if_cached(request.headers())
    {
        // No origin is contacted, so privacy signals cannot be honoured or leaked;
        // find the copies prepared or stored without them.
        for name in ["sec-gpc", "dnt"] {
            request.headers_mut().remove(name);
        }
    }
    let mut cache_epoch = context.cache.epoch();
    let cache_enabled = context.cache_enabled.load(Ordering::Acquire);
    let endpoint = cache_policy::public_endpoint(&request, &context.settings);
    let mut cache_eligible_request = !policy.no_cache && cache_policy::eligible(&request, endpoint);
    let base_key = cache_policy::base_key(&request, context, endpoint);
    let mut recovery_blocked = false;
    if cache_enabled && cache_eligible_request && context.cache.recovery_blocks_family(&base_key) {
        context.stats.cache_outcome(
            context.activity_id,
            "bypass",
            Some("cache-recovery-blocked"),
        );
        if context.settings.cache_mode == CacheMode::Offline
            || cache_policy::only_if_cached(request.headers())
        {
            return Err(ProxyError::Offline);
        }
        // Online, a family awaiting storage recovery is served straight from the
        // origin: the cache is neither read nor written for this request.
        cache_eligible_request = false;
        recovery_blocked = true;
    }
    let origin_headers = cache_policy::origin_headers(&request, endpoint).unwrap_or_default();
    let mut variant_candidate = if cache_enabled && cache_eligible_request {
        context.cache.hydrate_variants(&base_key).await;
        let candidate =
            context
                .cache
                .variants
                .lookup(&base_key, &origin_headers, request.headers());
        if candidate.is_none() {
            context.cache.reclaim_unpublished_variants(&base_key);
        }
        candidate
    } else {
        None
    };
    // Index pointers are hints. Verify their metadata on the actual leased HIT
    // instead of hashing the full body once here and again while serving it.
    let mut cache_key = variant_candidate
        .as_ref()
        .map(|candidate| candidate.key.clone())
        .unwrap_or_else(|| cache_policy::key(&request, context, endpoint));
    let mut variant_generation = 0;
    let is_head = request.method() == Method::HEAD;
    let mut request_headers = request.headers().clone();
    if is_head {
        request_headers.remove(RANGE);
        request_headers.remove("if-range");
        request_headers.insert("x-homeproxy-head", HeaderValue::from_static("1"));
    }
    let offline_mode = context.settings.cache_mode == CacheMode::Offline;
    let offline = offline_mode || cache_policy::only_if_cached(&request_headers);
    let mut flight = None;
    if cache_enabled && cache_eligible_request {
        if request_headers.contains_key(RANGE) {
            if let Some(response) = fragment_cache_response(
                &cache_key,
                &request_headers,
                context,
                offline,
                variant_candidate.as_ref(),
            )
            .await
            {
                return Ok(response);
            }
        }
        if offline {
            let (snapshot, entry) =
                context
                    .cache
                    .snapshot_entry(&cache_key)
                    .await
                    .ok_or_else(|| {
                        context.stats.cache_outcome(
                            context.activity_id,
                            "bypass",
                            Some("offline-missing"),
                        );
                        ProxyError::Offline
                    })?;
            if variant_candidate
                .as_ref()
                .is_some_and(|candidate| !candidate.verifies(&snapshot.headers))
            {
                return Err(ProxyError::Offline);
            }
            if (!offline_mode && snapshot.remaining_ttl.is_zero())
                || !cache_policy::offline_allowed(
                    &snapshot,
                    &request_headers,
                    u64::from(context.settings.offline_max_stale_hours) * 3600,
                )
            {
                let validation_required =
                    parse_cache_control(&snapshot.headers).is_some_and(|policy| {
                        policy.requires_validation
                            || policy.max_age == Some(0)
                            || policy.s_maxage == Some(0)
                    });
                context.stats.cache_outcome(
                    context.activity_id,
                    "bypass",
                    Some(if validation_required {
                        "offline-validation-required"
                    } else {
                        "offline-stale-policy"
                    }),
                );
                return Err(ProxyError::Offline);
            }
            return cached_hit(entry, &request_headers, context);
        }
        loop {
            if let Some(response) = fresh_cache_response(
                &cache_key,
                &request_headers,
                context,
                variant_candidate.as_ref(),
            )
            .await
            {
                return Ok(response);
            }
            // The leader may have learned Vary and published a different derived key.
            if let Some(candidate) =
                context
                    .cache
                    .variants
                    .lookup(&base_key, &origin_headers, &request_headers)
            {
                cache_key = candidate.key.clone();
                variant_candidate = Some(candidate);
            }
            if let Some(response) = fresh_cache_response(
                &cache_key,
                &request_headers,
                context,
                variant_candidate.as_ref(),
            )
            .await
            {
                return Ok(response);
            }
            if request_headers.contains_key(RANGE) {
                if let Some(response) = fragment_cache_response(
                    &cache_key,
                    &request_headers,
                    context,
                    false,
                    variant_candidate.as_ref(),
                )
                .await
                {
                    return Ok(response);
                }
            }
            match context.cache.fills.claim(&cache_key) {
                FillClaim::Leader(guard) => {
                    flight = Some(guard);
                    // A previous leader may have committed between the first lookup and claim.
                    // Keep this claim while closing that gap before contacting the origin.
                    if let Some(response) = fresh_cache_response(
                        &cache_key,
                        &request_headers,
                        context,
                        variant_candidate.as_ref(),
                    )
                    .await
                    {
                        return Ok(response);
                    }
                    break;
                }
                FillClaim::Saturated => break,
                FillClaim::Follower(mut done) => {
                    tokio::select! {
                        _ = context.cancellation.cancelled() => return Err(ProxyError::Busy("Proxy se zastavuje.")),
                        _ = done.changed() => {}
                    }
                    // Re-read after the entire leader body has completed or been dropped.
                }
            }
        }
    }
    if offline {
        return Err(ProxyError::Offline);
    }
    let snapshot =
        if cache_enabled && cache_eligible_request && !request_headers.contains_key(RANGE) {
            context.cache.snapshot(&cache_key).await.filter(|snapshot| {
                variant_candidate
                    .as_ref()
                    .is_none_or(|candidate| candidate.verifies(&snapshot.headers))
            })
        } else {
            None
        };
    let mut request_guard = if cache_enabled && cache_eligible_request {
        variant_generation = context.cache.variants.generation(&base_key);
        context.cache.key_guard(&base_key).filter(|guard| {
            context
                .cache
                .variants
                .bind_guard(&base_key, variant_generation, guard.clone())
        })
    } else {
        None
    };
    let mut successor_guard = None;
    // Fence every existing family durably before an origin can change its
    // selection or privacy contract. Cancellation deliberately retains it.
    let mut recovery_checkpoint = if cache_enabled && cache_eligible_request {
        let keys = context.cache.variants.family_keys(&base_key);
        if keys.is_empty() {
            None
        } else {
            let guard = request_guard.as_ref().ok_or(ProxyError::Busy(
                "Úložiště cache není připravené pro revalidaci.",
            ))?;
            Some(
                context
                    .cache
                    .begin_recovery_checkpoint(cache_epoch, &base_key, &keys, guard)
                    .map_err(|_| {
                        ProxyError::Busy("Úložiště cache není připravené pro revalidaci.")
                    })?,
            )
        }
    } else {
        None
    };
    if cache_enabled && cache_eligible_request {
        context.stats.cache_outcome(
            context.activity_id,
            "validation",
            Some(if snapshot.is_some() {
                "expired-or-validation-required"
            } else {
                "cold-miss"
            }),
        );
    }
    let validator = snapshot.as_ref().and_then(|entry| {
        if entry.headers.contains_key("x-homeproxy-transformed") {
            return None;
        }
        entry
            .headers
            .get("etag")
            .map(|value| (HeaderName::from_static("if-none-match"), value.clone()))
            .or_else(|| {
                entry
                    .headers
                    .get("last-modified")
                    .map(|value| (HeaderName::from_static("if-modified-since"), value.clone()))
            })
    });
    if (!cache_enabled || !cache_eligible_request) && !recovery_blocked {
        context.stats.cache_outcome(
            context.activity_id,
            "bypass",
            Some(if !cache_enabled {
                "cache-disabled"
            } else {
                if policy.no_cache {
                    "policy-no-cache"
                } else {
                    cache_policy::request_reason(&request, endpoint)
                }
            }),
        );
    }
    let accepts_webp = header_contains_token(request.headers(), ACCEPT, "image/webp");
    let original_method = request.method().clone();
    prepare_origin_request(
        &mut request,
        cache_enabled && cache_eligible_request && !endpoint,
    )?;
    for name in [RANGE, HeaderName::from_static("if-range")] {
        request.headers_mut().remove(&name);
        for value in request_headers.get_all(&name) {
            request.headers_mut().append(name.clone(), value.clone());
        }
    }
    if is_head {
        request.headers_mut().remove(RANGE);
        request.headers_mut().remove("if-range");
    }
    // Eligible requests are bodyless GETs/HEADs (body framing headers are ineligible).
    // Capture the actual origin headers before adding our conditional validator.
    let mut retry_request = validator.as_ref().map(|_| {
        let mut retry = Request::new(empty_body());
        *retry.method_mut() = request.method().clone();
        *retry.uri_mut() = request.uri().clone();
        *retry.version_mut() = request.version();
        *retry.headers_mut() = request.headers().clone();
        retry
    });
    if let Some((name, value)) = &validator {
        request.headers_mut().insert(name.clone(), value.clone());
    }
    let fetch = async {
        match &origin {
            WebOrigin::Plain { host, port } => {
                let upstream = connect_for_context(host, *port, context).await?;
                send_origin_body_request(
                    upstream,
                    request,
                    &context.tasks,
                    context.cancellation.clone(),
                    connection_activity(context),
                )
                .await
            }
            WebOrigin::Inspected(origin) => origin.send_boxed(request).await,
        }
    };
    let response = match fetch.await {
        Ok(response) => response,
        Err(error) => {
            // No authoritative response headers were received. This completed
            // error path can close its record; a canceled future never gets here.
            let checkpoint_finished = finish_variant_recovery(context, &mut recovery_checkpoint);
            if checkpoint_finished && matches!(&error, ProxyError::Network(_)) {
                if let Some(response) =
                    stale_error_response(snapshot.as_ref(), &cache_key, &request_headers, context)
                        .await
                {
                    return Ok(response);
                }
            }
            return Err(error);
        }
    };
    let mut response_started = Instant::now();
    let (mut parts, mut body) = response.into_parts();
    remove_hop_by_hop_headers(&mut parts.headers);
    if matches!(
        parts.status,
        StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    ) && !parts.headers.contains_key(SET_COOKIE)
        && (!parts.headers.contains_key(CACHE_CONTROL)
            || parse_cache_control(&parts.headers).is_some_and(|policy| !policy.unsafe_to_share))
    {
        if let Some(response) =
            stale_error_response(snapshot.as_ref(), &cache_key, &request_headers, context).await
        {
            if finish_variant_recovery(context, &mut recovery_checkpoint) {
                return Ok(response);
            }
            // Keep the actual origin failure when recovery durability failed.
        }
    }

    if parts.status == StatusCode::NOT_MODIFIED && validator.is_some() {
        let expected = snapshot.as_ref().unwrap();
        if let Some((headers, ttl)) = cache_policy::merge_304(expected, &parts.headers, endpoint) {
            let mut refresh_retired = false;
            if context
                .cache
                .refresh(&cache_key, expected, &headers, ttl)
                .await
            {
                if let Some(entry) = context.cache.get_including_stale(&cache_key).await {
                    // The durable refreshed metadata authorizes this exact body.
                    // A finish failure keeps recovery protection for restart.
                    let _ = finish_variant_recovery(context, &mut recovery_checkpoint);
                    return cached_hit(entry, &request_headers, context);
                }
            } else {
                // Preserve a lease for this already verified 304-authorized
                // body, but deny every subsequent reuse before responding.
                let ephemeral = context.cache.get_if_snapshot(&cache_key, expected).await;
                let (token, epoch) = context
                    .cache
                    .variants
                    .retire_writers(&base_key, variant_generation, || {
                        retire_variant_keys(
                            &context.cache,
                            cache_epoch,
                            &[cache_key.clone()],
                            request_guard.as_ref(),
                            &mut successor_guard,
                        )
                    })
                    .ok_or(ProxyError::Upstream(
                        "Změnu pravidel revalidované cache se nepodařilo bezpečně uložit.",
                    ))?;
                cache_epoch = epoch;
                variant_generation = token;
                request_guard = successor_guard.take().filter(|guard| {
                    context
                        .cache
                        .variants
                        .bind_guard(&base_key, token, guard.clone())
                });
                refresh_retired = true;
                if let Some(mut entry) = ephemeral {
                    entry.headers = headers;
                    entry.age = Duration::ZERO;
                    entry.remaining_ttl = ttl;
                    let _ = context.cache.remove_invalidated(&cache_key).await;
                    let _ = finish_variant_recovery(context, &mut recovery_checkpoint);
                    return cached_hit(entry, &request_headers, context);
                }
            }
            // An unrelated streaming fill can hold the exclusive store lease.
            // One bounded unconditional GET obtains a live representation rather
            // than reporting a valid 304 as an upstream failure or serving a
            // snapshot that cannot currently be checked.
            if context.cache.epoch() != cache_epoch
                || (!refresh_retired
                    && !tokio::fs::try_exists(
                        context.cache.root().join(format!("{cache_key}.json")),
                    )
                    .await
                    .unwrap_or(false))
            {
                return Err(ProxyError::Upstream(
                    "Revalidovaná položka cache byla zrušena.",
                ));
            }
            let retry = retry_request.take().ok_or(ProxyError::Upstream(
                "Revalidace cache nemá opakovatelný požadavek.",
            ))?;
            drop(body);
            let response = match &origin {
                WebOrigin::Plain { host, port } => {
                    let upstream = connect_for_context(host, *port, context).await?;
                    send_origin_body_request(
                        upstream,
                        retry,
                        &context.tasks,
                        context.cancellation.clone(),
                        connection_activity(context),
                    )
                    .await?
                }
                WebOrigin::Inspected(origin) => origin.send_boxed(retry).await?,
            };
            (parts, body) = response.into_parts();
            response_started = Instant::now();
            remove_hop_by_hop_headers(&mut parts.headers);
            if parts.status == StatusCode::NOT_MODIFIED {
                return Err(ProxyError::Upstream(
                    "Web nevrátil tělo na nepodmíněný požadavek.",
                ));
            }
        } else {
            // A rejected 304 can change the selection schema. Retire every old
            // representation before retrying, including when that retry fails or
            // returns an uncacheable/private response.
            let (generation, epoch, invalidated) = context
                .cache
                .variants
                .invalidate_family(&base_key, variant_generation, &cache_key, |keys| {
                    retire_variant_keys(
                        &context.cache,
                        cache_epoch,
                        keys,
                        request_guard.as_ref(),
                        &mut successor_guard,
                    )
                })
                .ok_or(ProxyError::Upstream(
                    "Revalidovaná rodina cache byla změněna nebo zrušena.",
                ))?;
            cache_epoch = epoch;
            variant_generation = generation;
            request_guard = successor_guard.take().filter(|guard| {
                context
                    .cache
                    .variants
                    .bind_guard(&base_key, generation, guard.clone())
            });
            for key in invalidated {
                let _ = context.cache.remove_invalidated(&key).await;
            }
            let retry = retry_request.take().ok_or(ProxyError::Upstream(
                "Revalidace cache nemá opakovatelný požadavek.",
            ))?;
            drop(body);
            let response = match &origin {
                WebOrigin::Plain { host, port } => {
                    let upstream = connect_for_context(host, *port, context).await?;
                    send_origin_body_request(
                        upstream,
                        retry,
                        &context.tasks,
                        context.cancellation.clone(),
                        connection_activity(context),
                    )
                    .await?
                }
                WebOrigin::Inspected(origin) => origin.send_boxed(retry).await?,
            };
            (parts, body) = response.into_parts();
            response_started = Instant::now();
            remove_hop_by_hop_headers(&mut parts.headers);
            if parts.status == StatusCode::NOT_MODIFIED {
                return Err(ProxyError::Upstream(
                    "Web nevrátil tělo na nepodmíněný požadavek.",
                ));
            }
        }
    }
    // A new origin representation changes the selection contract even when
    // HEAD cannot refresh a body or a private GET cannot be stored. In those
    // cases retiring just the selected key would leave sibling variants usable.
    let mut checkpoint_ready = true;
    let mut family_replaced = false;
    if cache_enabled
        && cache_eligible_request
        && matches!(parts.status, StatusCode::OK | StatusCode::PARTIAL_CONTENT)
        && (!is_head || parts.headers.contains_key(VARY))
        && context
            .cache
            .variants
            .schema_changed(&base_key, &parts.headers)
    {
        family_replaced = true;
        if let Some((token, epoch, invalidated)) = context.cache.variants.invalidate_family(
            &base_key,
            variant_generation,
            &cache_key,
            |keys| {
                retire_variant_keys(
                    &context.cache,
                    cache_epoch,
                    keys,
                    request_guard.as_ref(),
                    &mut successor_guard,
                )
            },
        ) {
            cache_epoch = epoch;
            variant_generation = token;
            request_guard = successor_guard.take().filter(|guard| {
                context
                    .cache
                    .variants
                    .bind_guard(&base_key, token, guard.clone())
            });
            for key in invalidated {
                let _ = context.cache.remove_invalidated(&key).await;
            }
        } else {
            request_guard = None;
            checkpoint_ready = false;
        }
    }
    let mut representation_replaced = family_replaced;
    // Explicit privacy restrictions retire known shared data even on an error
    // response. Successful conditional validation was already handled above.
    let explicitly_unsafe_response = parts.headers.contains_key(SET_COOKIE)
        || (parts.headers.contains_key(CACHE_CONTROL)
            && parse_cache_control(&parts.headers).is_none_or(|policy| policy.unsafe_to_share));
    // An authoritative 200 replaces known partial data even without a full
    // snapshot. Retire it before handing off a stream whose fill may be canceled.
    // Range 206 merges still preserve compatible existing fragments.
    if cache_enabled
        && cache_eligible_request
        && !family_replaced
        && variant_candidate.is_some()
        && (explicitly_unsafe_response
            || (matches!(parts.status, StatusCode::OK | StatusCode::PARTIAL_CONTENT)
                && ((parts.status == StatusCode::OK && snapshot.is_none())
                    || (is_head && parts.status == StatusCode::PARTIAL_CONTENT)
                    || cache_policy::ttl(&parts.headers, parts.status, endpoint).is_none()
                    || (parts.status == StatusCode::PARTIAL_CONTENT
                        && !cache_policy::fragment_eligible(&parts.headers)))))
    {
        representation_replaced = true;
        if let Some((token, epoch)) =
            context
                .cache
                .variants
                .retire_writers(&base_key, variant_generation, || {
                    retire_variant_keys(
                        &context.cache,
                        cache_epoch,
                        &[cache_key.clone()],
                        request_guard.as_ref(),
                        &mut successor_guard,
                    )
                })
        {
            cache_epoch = epoch;
            variant_generation = token;
            request_guard = successor_guard.take().filter(|guard| {
                context
                    .cache
                    .variants
                    .bind_guard(&base_key, token, guard.clone())
            });
            let _ = context.cache.remove_invalidated(&cache_key).await;
        } else {
            request_guard = None;
            checkpoint_ready = false;
        }
    }
    if is_head {
        if cache_enabled && cache_eligible_request && !representation_replaced {
            if let Some(expected) = &snapshot {
                if parts.status == StatusCode::OK {
                    if let Some((headers, ttl)) =
                        cache_policy::head_refresh(expected, &parts.headers, endpoint)
                    {
                        checkpoint_ready = context
                            .cache
                            .refresh(&cache_key, expected, &headers, ttl)
                            .await;
                        if !checkpoint_ready {
                            checkpoint_ready = context
                                .cache
                                .variants
                                .retire_writers(&base_key, variant_generation, || {
                                    retire_variant_keys(
                                        &context.cache,
                                        cache_epoch,
                                        &[cache_key.clone()],
                                        request_guard.as_ref(),
                                        &mut successor_guard,
                                    )
                                })
                                .is_some();
                            let _ = context.cache.remove_invalidated(&cache_key).await;
                        }
                    } else {
                        let retired = context.cache.variants.retire_writers(
                            &base_key,
                            variant_generation,
                            || {
                                retire_variant_keys(
                                    &context.cache,
                                    cache_epoch,
                                    &[cache_key.clone()],
                                    request_guard.as_ref(),
                                    &mut successor_guard,
                                )
                            },
                        );
                        checkpoint_ready = retired.is_some();
                        let _ = context.cache.remove_invalidated(&cache_key).await;
                    }
                }
            }
        }
        if checkpoint_ready {
            let _ = finish_variant_recovery(context, &mut recovery_checkpoint);
        }
        strip_variant_headers(&mut parts.headers);
        add_via(&mut parts.headers);
        return Ok(meter_response(
            Response::from_parts(parts, empty_body()),
            context,
            false,
        ));
    }

    let content_length = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    // A Range miss stores only verified 206 fragments. A server ignoring Range
    // does not replace the existing shared full representation through this path.
    let mut public_response_ttl =
        if request_headers.contains_key(RANGE) && parts.status != StatusCode::PARTIAL_CONTENT {
            None
        } else {
            cache_policy::ttl(&parts.headers, parts.status, endpoint)
        };
    if parts.status == StatusCode::PARTIAL_CONTENT
        && !cache_policy::fragment_eligible(&parts.headers)
    {
        public_response_ttl = None;
    }
    // Cache writer fences govern storage/reuse, not the independent image control.
    // With cache off no guard exists, but public response policy still applies.
    if cache_enabled
        && request_guard
            .as_ref()
            .is_none_or(|guard| !guard.is_current())
    {
        public_response_ttl = None;
    }
    if snapshot.is_some() && parts.status != StatusCode::NOT_MODIFIED && !representation_replaced {
        representation_replaced = true;
        if let Some((token, epoch)) =
            context
                .cache
                .variants
                .retire_writers(&base_key, variant_generation, || {
                    retire_variant_keys(
                        &context.cache,
                        cache_epoch,
                        &[cache_key.clone()],
                        request_guard.as_ref(),
                        &mut successor_guard,
                    )
                })
        {
            cache_epoch = epoch;
            variant_generation = token;
            request_guard = successor_guard.take().filter(|guard| {
                context
                    .cache
                    .variants
                    .bind_guard(&base_key, token, guard.clone())
            });
            if request_guard.is_none() {
                public_response_ttl = None;
                checkpoint_ready = false;
            }
        } else {
            public_response_ttl = None;
            checkpoint_ready = false;
        }
        let _ = context.cache.remove_invalidated(&cache_key).await;
    }
    if cache_enabled && cache_eligible_request && public_response_ttl.is_some() {
        if response_can_transform(&parts.headers, parts.status)
            && context.settings.compression_preset.jpeg_quality().is_some()
        {
            merge_vary_accept(&mut parts.headers);
        }
        if let Some((key, old_keys, token)) = context.cache.variants.observe_with_invalidation(
            &base_key,
            variant_generation,
            &origin_headers,
            &mut parts.headers,
            |keys| {
                if let Some(epoch) = retire_variant_keys(
                    &context.cache,
                    cache_epoch,
                    keys,
                    request_guard.as_ref(),
                    &mut successor_guard,
                ) {
                    cache_epoch = epoch;
                    true
                } else {
                    false
                }
            },
        ) {
            let changed_family = token != variant_generation;
            variant_generation = token;
            if changed_family {
                request_guard = successor_guard.take().filter(|guard| {
                    context
                        .cache
                        .variants
                        .bind_guard(&base_key, token, guard.clone())
                });
            }
            if request_guard
                .as_ref()
                .is_none_or(|guard| !guard.is_current())
            {
                public_response_ttl = None;
            }
            for old in old_keys {
                let _ = context.cache.remove_invalidated(&old).await;
            }
            cache_key = key;
        } else {
            public_response_ttl = None;
        }
    }
    // Fills and response buffers need a known length; a cacheable chunked 200
    // passes through and must not be reported as a MISS that will be stored.
    let unknown_length = public_response_ttl.is_some()
        && parts.status == StatusCode::OK
        && original_method == Method::GET
        && content_length.is_none();
    if cache_enabled && cache_eligible_request {
        context.stats.cache_outcome(
            context.activity_id,
            if public_response_ttl.is_some() && !unknown_length {
                "MISS"
            } else {
                "bypass"
            },
            if public_response_ttl.is_none() {
                Some(cache_policy::response_reason(
                    &parts.headers,
                    parts.status,
                    endpoint,
                ))
            } else if unknown_length {
                Some("response-unknown-length")
            } else {
                Some(if snapshot.is_some() {
                    "expired-or-validation-required"
                } else {
                    "cold-miss"
                })
            },
        );
    }
    let image_candidate = original_method == Method::GET
        && cache_eligible_request
        && public_response_ttl.is_some()
        && context.settings.compression_preset.jpeg_quality().is_some()
        && response_can_transform(&parts.headers, parts.status);
    let cache_candidate = cache_enabled && cache_eligible_request && public_response_ttl.is_some();
    if cache_candidate
        && content_length.is_some_and(|n| n as u64 > context.settings.cache_max_object_bytes())
    {
        context
            .stats
            .cache_outcome(context.activity_id, "bypass", Some("response-size-limit"));
    }
    let Some(buffer_permit) = try_reserve_buffer_budget(
        &context.buffer_budget,
        content_length,
        image_candidate || cache_candidate,
        context.settings.response_buffer_limit_bytes(),
    ) else {
        // A passthrough 206 never reaches the fragment merge that reconciles
        // validators and reuse policy. Retire its known old representation
        // before closing recovery protection or handing off the live body.
        if cache_enabled
            && cache_eligible_request
            && parts.status == StatusCode::PARTIAL_CONTENT
            && !representation_replaced
        {
            if let Some(candidate) = &variant_candidate {
                if let Some((_, epoch, guard)) = retire_known_variant(
                    &context.cache,
                    &base_key,
                    variant_generation,
                    cache_epoch,
                    &candidate.key,
                    request_guard.as_ref(),
                )
                .await
                {
                    cache_epoch = epoch;
                    request_guard = Some(guard);
                } else {
                    request_guard = None;
                    checkpoint_ready = false;
                }
            }
        }
        if cache_candidate
            && parts.status == StatusCode::OK
            && content_length
                .is_some_and(|length| length as u64 <= context.settings.cache_max_object_bytes())
        {
            let length = content_length.unwrap() as u64;
            if let Some(fill) = context
                .cache
                .begin_fill_guarded(
                    cache_epoch,
                    &cache_key,
                    parts.status,
                    &parts.headers,
                    length,
                    public_response_ttl.unwrap(),
                    response_started,
                    context.settings.cache_limit_bytes(),
                    request_guard.as_ref().unwrap(),
                )
                .await
            {
                if checkpoint_ready {
                    let _ = finish_variant_recovery(context, &mut recovery_checkpoint);
                }
                parts.headers.insert(
                    HeaderName::from_static("cache-status"),
                    HeaderValue::from_static("HomeProxy; fwd=miss"),
                );
                strip_variant_headers(&mut parts.headers);
                add_via(&mut parts.headers);
                return Ok(meter_response(
                    Response::from_parts(
                        parts,
                        TeeBody::new(body, fill, length, context.cancellation.clone())
                            .with_flight(flight.take())
                            .boxed_unsync(),
                    ),
                    context,
                    true,
                ));
            }
        }
        if checkpoint_ready {
            let _ = finish_variant_recovery(context, &mut recovery_checkpoint);
        }
        strip_variant_headers(&mut parts.headers);
        add_via(&mut parts.headers);
        return Ok(meter_response(
            Response::from_parts(
                parts,
                body.map_err(|error| -> BoxError { Box::new(error) })
                    .boxed_unsync(),
            ),
            context,
            true,
        ));
    };

    let origin_stats = context.stats.clone();
    let activity_id = context.activity_id;
    let body = body.map_frame(move |frame| {
        if let Some(bytes) = frame.data_ref() {
            origin_stats.body_bytes(activity_id, bytes.len() as u64, 0);
        }
        frame
    });
    let io_activity = connection_activity(context);
    let collected = match transport::bounded(
        Limited::new(body, context.settings.response_buffer_limit_bytes()).collect(),
        &context.cancellation,
        Duration::from_secs(u64::from(context.settings.tunnel_idle_timeout_seconds)),
        &io_activity,
    )
    .await
    {
        transport::BoundOutcome::Finished(result) => {
            result.map_err(|_| ProxyError::Upstream("Odpověď překročila bezpečný limit."))?
        }
        transport::BoundOutcome::Idle => {
            return Err(ProxyError::Upstream(
                "Vypršel čas nečinnosti těla odpovědi.",
            ));
        }
        transport::BoundOutcome::Cancelled => {
            return Err(ProxyError::Upstream("Přenos odpovědi byl zrušen."));
        }
    };
    let has_trailers = collected.trailers().is_some();
    let buffer_permit = Arc::new(buffer_permit);
    let mut response_body = Bytes::from_owner(BudgetedBytes {
        bytes: collected.to_bytes(),
        _permit: buffer_permit.clone(),
    });

    let mut compression_saved = None;
    if image_candidate {
        let content_type = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        let transformed = match (
            context.transform_slots.clone().try_acquire_owned(),
            try_reserve_buffer_budget(
                &context.buffer_budget,
                content_length,
                true,
                context.settings.response_buffer_limit_bytes(),
            ),
        ) {
            (Ok(permit), Some(output_permit)) => {
                let source = response_body.clone();
                let preset = context.settings.compression_preset;
                let output_budget = Arc::new(output_permit);
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    transform_image(&source, &content_type, accepts_webp, preset).map(
                        |mut image| {
                            image.body = Bytes::from_owner(BudgetedBytes {
                                bytes: image.body,
                                _permit: output_budget,
                            });
                            image
                        },
                    )
                })
                .await
                .ok()
                .flatten()
            }
            _ => None,
        };
        if let Some(transformed) = transformed {
            compression_saved = Some(transformed.saved_bytes);
            response_body = transformed.body;
            parts.headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static(transformed.content_type),
            );
            parts.headers.insert(
                CONTENT_LENGTH,
                HeaderValue::from_str(&response_body.len().to_string())
                    .map_err(|_| ProxyError::Upstream("Neplatná délka odpovědi."))?,
            );
            for name in [
                CONTENT_ENCODING,
                HeaderName::from_static("last-modified"),
                HeaderName::from_static("etag"),
                HeaderName::from_static("content-md5"),
                HeaderName::from_static("content-digest"),
                HeaderName::from_static("repr-digest"),
                HeaderName::from_static("accept-ranges"),
            ] {
                parts.headers.remove(name);
            }
            parts
                .headers
                .insert("x-homeproxy-transformed", HeaderValue::from_static("1"));
            if transformed.content_type == "image/webp" {
                merge_vary_accept(&mut parts.headers);
            }
        }
    }

    let mut fragment_stored = false;
    if cache_enabled
        && cache_eligible_request
        && !has_trailers
        && response_body.len() as u64 <= context.settings.cache_max_object_bytes()
    {
        if let Some(ttl) =
            public_response_ttl.map(|ttl| ttl.saturating_sub(response_started.elapsed()))
        {
            // Transformation can change coding/Vary: register the final stored representation.
            let registration = context.cache.variants.observe_with_invalidation(
                &base_key,
                variant_generation,
                &origin_headers,
                &mut parts.headers,
                |keys| {
                    if let Some(epoch) = retire_variant_keys(
                        &context.cache,
                        cache_epoch,
                        keys,
                        request_guard.as_ref(),
                        &mut successor_guard,
                    ) {
                        cache_epoch = epoch;
                        true
                    } else {
                        false
                    }
                },
            );
            let stored = if let Some((key, old_keys, token)) = registration {
                if token != variant_generation {
                    request_guard = successor_guard.take().filter(|guard| {
                        context
                            .cache
                            .variants
                            .bind_guard(&base_key, token, guard.clone())
                    });
                }
                variant_generation = token;
                for old in old_keys {
                    let _ = context.cache.remove_invalidated(&old).await;
                }
                cache_key = key;
                let result = if let Some(guard) =
                    request_guard.as_ref().filter(|guard| guard.is_current())
                {
                    if parts.status == StatusCode::PARTIAL_CONTENT {
                        context
                            .cache
                            .put_fragment_at_epoch_guarded(
                                cache_epoch,
                                &cache_key,
                                parts.status,
                                &parts.headers,
                                response_body.clone(),
                                ttl,
                                context.settings.cache_limit_bytes(),
                                guard,
                            )
                            .await
                    } else {
                        context
                            .cache
                            .put_at_epoch_guarded(
                                cache_epoch,
                                &cache_key,
                                parts.status,
                                &parts.headers,
                                response_body.clone(),
                                ttl,
                                context.settings.cache_limit_bytes(),
                                guard,
                            )
                            .await
                    }
                } else {
                    Err(std::io::Error::other("variant admission retired"))
                };
                if parts.status == StatusCode::PARTIAL_CONTENT {
                    fragment_stored = result.is_ok();
                }
                if result.is_err() {
                    checkpoint_ready = false;
                    context.stats.cache_outcome(
                        context.activity_id,
                        "bypass",
                        Some("cache-write-failed"),
                    );
                }
                result.is_ok()
            } else {
                false
            };
            parts.headers.insert(
                HeaderName::from_static("cache-status"),
                if stored {
                    HeaderValue::from_static("HomeProxy; fwd=miss; stored")
                } else {
                    HeaderValue::from_static("HomeProxy; fwd=miss; store=error")
                },
            );
        }
    }

    // Every known 206 must reconcile the old policy durably. Trailers, size
    // limits, admission failures or a failed merge cannot leave old shared data.
    if parts.status == StatusCode::PARTIAL_CONTENT && !representation_replaced && !fragment_stored {
        if let Some(candidate) = &variant_candidate {
            checkpoint_ready = retire_known_variant(
                &context.cache,
                &base_key,
                variant_generation,
                cache_epoch,
                &candidate.key,
                request_guard.as_ref(),
            )
            .await
            .is_some();
        }
    }
    // Fragment merge can invalidate an old generation/overlap after buffering.
    // Close only after that mutation (and its persistence) actually succeeded.
    if checkpoint_ready {
        let _ = finish_variant_recovery(context, &mut recovery_checkpoint);
    }
    parts.headers.remove("x-homeproxy-transformed");
    strip_variant_headers(&mut parts.headers);
    add_via(&mut parts.headers);
    let stats = context.stats.clone();
    let activity_id = context.activity_id;
    let body = full_body(Bytes::from_owner(BudgetedBytes {
        bytes: response_body,
        _permit: buffer_permit,
    }))
    .map_frame(move |frame| {
        // Full emits the buffered representation as one data frame. Credit
        // only when that frame is consumed, never for an unpolled response.
        if frame.data_ref().is_some_and(|bytes| !bytes.is_empty()) {
            if let Some(saved) = compression_saved.take() {
                stats.compressed(saved);
                stats.history_saved(activity_id, saved);
            }
        }
        frame
    })
    .boxed_unsync();
    Ok(meter_response(
        Response::from_parts(parts, body),
        context,
        false,
    ))
}

async fn forward_websocket(
    mut request: Request<ProxyBody>,
    context: &ProxyContext,
    origin: WebOrigin,
) -> Result<Response<ProxyBody>, ProxyError> {
    ensure_online(context)?;
    if request.method() != Method::GET
        || !header_contains_token(request.headers(), CONNECTION, "upgrade")
        || !header_contains_token(
            request.headers(),
            HeaderName::from_static("upgrade"),
            "websocket",
        )
    {
        return Err(ProxyError::InvalidTarget(
            "Proxy podporuje jen platný WebSocket upgrade.",
        ));
    }
    let permit = context
        .connection_permit
        .clone()
        .ok_or(ProxyError::Busy("Spojení nemá platný limit."))?;
    context.stats.describe_activity(
        context.activity_id,
        request.uri().host().unwrap_or(""),
        if matches!(&origin, WebOrigin::Inspected(_)) {
            "WSS"
        } else {
            "WS"
        },
    );
    context
        .stats
        .cache_outcome(context.activity_id, "bypass", Some("websocket"));
    let client_upgrade = upgrade::on(&mut request);
    prepare_origin_request(&mut request, false)?;
    request
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    request.headers_mut().insert(
        HeaderName::from_static("upgrade"),
        HeaderValue::from_static("websocket"),
    );
    let mut response = match origin {
        WebOrigin::Plain { host, port } => {
            let upstream = connect_for_context(&host, port, context).await?;
            send_origin_body_request(
                upstream,
                request,
                &context.tasks,
                context.cancellation.clone(),
                connection_activity(context),
            )
            .await?
        }
        WebOrigin::Inspected(origin) => origin.send_boxed(request).await?,
    };
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        let (mut parts, body) = response.into_parts();
        remove_hop_by_hop_headers(&mut parts.headers);
        return Ok(meter_response(
            Response::from_parts(
                parts,
                body.map_err(|error| -> BoxError { Box::new(error) })
                    .boxed_unsync(),
            ),
            context,
            true,
        ));
    }
    if !header_contains_token(response.headers(), CONNECTION, "upgrade")
        || !header_contains_token(
            response.headers(),
            HeaderName::from_static("upgrade"),
            "websocket",
        )
    {
        return Err(ProxyError::Upstream(
            "WebSocket server nevrátil platný upgrade.",
        ));
    }
    let origin_upgrade = upgrade::on(&mut response);
    let cancellation = context.cancellation.clone();
    let stats = context.stats.clone();
    let id = context.activity_id;
    context.stats.connection_protocol(id, "websocket");
    let idle_timeout = Duration::from_secs(u64::from(context.settings.tunnel_idle_timeout_seconds));
    context.tasks.spawn(async move {
        let _permit = permit;
        let streams = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = timeout(HEADER_READ_TIMEOUT, async { tokio::try_join!(client_upgrade, origin_upgrade) }) => result,
        };
        let (client, origin) = match streams {
            Ok(Ok(streams)) => streams,
            _ => { stats.activity_error(id, "WebSocket-upgrade-failed"); return; }
        };
        let mut client = TokioIo::new(client);
        let mut origin = TokioIo::new(origin);
        match transport::relay(
            &mut client, &mut origin, &cancellation, idle_timeout,
            || stats.connection_progress(id),
        ).await {
            transport::RelayOutcome::Finished(result) => { record_connection_result(&stats, id, &result, "WebSocket-relay-failed"); }
            transport::RelayOutcome::Idle => stats.connection_idle_closed(id),
            transport::RelayOutcome::Cancelled => {},
        }
    });
    let (mut parts, _) = response.into_parts();
    remove_hop_by_hop_headers(&mut parts.headers);
    parts
        .headers
        .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    parts.headers.insert(
        HeaderName::from_static("upgrade"),
        HeaderValue::from_static("websocket"),
    );
    Ok(Response::from_parts(parts, empty_body()))
}

async fn fragment_cache_response(
    key: &str,
    headers: &HeaderMap,
    context: &ProxyContext,
    offline: bool,
    candidate: Option<&crate::cache::variants::Candidate>,
) -> Option<Response<ProxyBody>> {
    if cache_policy::request_requires_validation(headers) {
        return None;
    }
    // A full representation already proves any requested range. Keep its
    // verified leased body instead of hashing it via fragment_total and again
    // via get_fragment before serving a one-byte range.
    if let Some(response) = fresh_cache_response(key, headers, context, candidate).await {
        return Some(response);
    }
    let total = context.cache.fragment_total(key).await?;
    let (start, end) = cache_policy::requested_range(headers, total)?;
    let entry = context.cache.get_fragment(key, start, end, offline).await?;
    if candidate.is_some_and(|candidate| !candidate.verifies(&entry.headers)) {
        return None;
    }
    let policy = parse_cache_control(&entry.headers)?;
    if policy.requires_validation || policy.unsafe_to_share {
        return None;
    }
    if entry.remaining_ttl.is_zero() {
        return None;
    } // Partial stale coverage cannot prove a whole representation's offline policy.
    let age = parse_single_age(&entry.headers)
        .unwrap_or(u64::MAX)
        .saturating_add(entry.age.as_secs())
        .max(parse_single_date_apparent_age(&entry.headers).unwrap_or(u64::MAX));
    if !cache_policy::request_allows_fresh(headers, age, entry.remaining_ttl.as_secs()) {
        return None;
    }
    let mut range_headers = headers.clone();
    range_headers.remove(RANGE);
    cached_hit(entry, &range_headers, context).ok()
}

async fn fresh_cache_response(
    key: &str,
    headers: &HeaderMap,
    context: &ProxyContext,
    candidate: Option<&crate::cache::variants::Candidate>,
) -> Option<Response<ProxyBody>> {
    if cache_policy::request_requires_validation(headers) {
        return None;
    }
    let entry = context.cache.get(key).await?;
    if candidate.is_some_and(|candidate| !candidate.verifies(&entry.headers)) {
        return None;
    }
    let age = parse_single_age(&entry.headers)
        .unwrap_or(u64::MAX)
        .saturating_add(entry.age.as_secs())
        .max(parse_single_date_apparent_age(&entry.headers).unwrap_or(u64::MAX));
    if !cache_policy::request_allows_fresh(headers, age, entry.remaining_ttl.as_secs()) {
        return None;
    }
    if parse_cache_control(&entry.headers)
        .is_some_and(|policy| policy.requires_validation || policy.unsafe_to_share)
    {
        return None;
    }
    if headers.contains_key(RANGE)
        && (entry.headers.contains_key("x-homeproxy-transformed")
            || entry
                .headers
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .is_none())
    {
        return None;
    }
    cached_hit(entry, headers, context).ok()
}

async fn stale_error_response(
    snapshot: Option<&crate::cache::CacheSnapshot>,
    key: &str,
    headers: &HeaderMap,
    context: &ProxyContext,
) -> Option<Response<ProxyBody>> {
    let snapshot = snapshot?;
    if !cache_policy::stale_error_allowed(
        snapshot,
        headers,
        u64::from(context.settings.offline_max_stale_hours) * 3600,
    ) {
        return None;
    }
    let entry = context.cache.get_if_snapshot(key, snapshot).await?;
    cached_hit(entry, headers, context).ok()
}

fn cached_hit(
    entry: CachedEntry,
    request_headers: &HeaderMap,
    context: &ProxyContext,
) -> Result<Response<ProxyBody>, ProxyError> {
    if !crate::cache::variants::coding(&entry.headers)
        .is_some_and(|coding| crate::cache::variants::accepts_coding(request_headers, &coding))
    {
        return Err(ProxyError::Offline);
    }
    let response = if request_headers.contains_key("x-homeproxy-head") {
        let mut response = cached_response(entry)?;
        *response.body_mut() = empty_body();
        response
    } else {
        cache_policy::cached_range(entry, request_headers)?
    };
    let (parts, body) = response.into_parts();
    let stats = context.stats.clone();
    let id = context.activity_id;
    let response = Response::from_parts(
        parts,
        body.map_frame(move |frame| {
            if let Some(bytes) = frame.data_ref() {
                stats.history_saved(id, bytes.len() as u64);
            }
            frame
        })
        .boxed_unsync(),
    );
    context.stats.cache_hit(0);
    context
        .stats
        .cache_outcome(context.activity_id, "HIT", None);
    Ok(meter_response(
        meter_cached_response(response, context.stats.clone()),
        context,
        false,
    ))
}

fn meter_cached_response(response: Response<ProxyBody>, stats: Arc<Stats>) -> Response<ProxyBody> {
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        body.map_frame(move |frame| {
            if let Some(bytes) = frame.data_ref() {
                stats.cache_saved_bytes(bytes.len() as u64);
            }
            frame
        })
        .boxed_unsync(),
    )
}

fn meter_response(
    response: Response<ProxyBody>,
    context: &ProxyContext,
    origin: bool,
) -> Response<ProxyBody> {
    let (parts, body) = response.into_parts();
    let stats = context.stats.clone();
    let id = context.activity_id;
    let body = body
        .map_frame(move |frame| {
            if let Some(bytes) = frame.data_ref() {
                stats.body_bytes(
                    id,
                    if origin { bytes.len() as u64 } else { 0 },
                    bytes.len() as u64,
                );
            }
            frame
        })
        .boxed_unsync();
    Response::from_parts(parts, body)
}

fn is_pac_request<B>(request: &Request<B>, context: &ProxyContext) -> bool {
    if request.method() != Method::GET
        || request.uri().path() != "/proxy.pac"
        || request.uri().query().is_some()
    {
        return false;
    }
    let mut values = request.headers().get_all(HOST).iter();
    let Some(host) = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Authority>().ok())
    else {
        return false;
    };
    if values.next().is_some() || host.as_str().contains('@') {
        return false;
    }
    if request.uri().scheme_str() == Some("http") {
        return request
            .uri()
            .host()
            .is_some_and(|host| host.eq_ignore_ascii_case("homeproxy.local"))
            && request.uri().port_u16().is_none_or(|port| port == 80)
            && host.host().eq_ignore_ascii_case("homeproxy.local")
            && host.port_u16().unwrap_or(80) == 80;
    }
    request.uri().scheme().is_none()
        && request.uri().authority().is_none()
        && host.port_u16().unwrap_or(80) == context.settings.proxy_port
        && host
            .host()
            .parse::<IpAddr>()
            .ok()
            .is_some_and(|ip| context.host_addresses.contains(&ip))
}

fn pac_response(context: &ProxyContext) -> Result<Response<ProxyBody>, ProxyError> {
    let listener = context
        .stats
        .snapshot()
        .activity
        .iter()
        .find(|activity| activity.id == context.activity_id)
        .and_then(|activity| activity.listener_ip.parse::<IpAddr>().ok())
        .filter(|address| context.host_addresses.contains(address))
        .ok_or(ProxyError::InvalidTarget(
            "PAC nemá platnou adresu listeneru.",
        ))?;
    let endpoint = SocketAddr::new(listener, context.settings.proxy_port);
    let fallback = if context.settings.pac_direct_fallback {
        "; DIRECT"
    } else {
        ""
    };
    let body = format!(
        "function FindProxyForURL(url, host) {{ return \"PROXY {endpoint}{fallback}\"; }}\n"
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-ns-proxy-autoconfig")
        .header(CACHE_CONTROL, "no-store")
        .header(CONTENT_LENGTH, body.len())
        .body(full_body(Bytes::from(body)))
        .map_err(ProxyError::BuildResponse)
}

fn is_ca_download_request<B>(request: &Request<B>) -> bool {
    request.method() == Method::GET
        && request.uri().scheme_str() == Some("http")
        && request
            .uri()
            .host()
            .is_some_and(|host| host.eq_ignore_ascii_case(CA_DOWNLOAD_HOST))
        && request.uri().port_u16().is_none_or(|port| port == 80)
        && request.uri().path() == CA_DOWNLOAD_PATH
        && request.uri().query().is_none()
}

fn ca_download_response(context: &ProxyContext) -> Result<Response<ProxyBody>, ProxyError> {
    let certificate = context.tls_inspection.try_root_certificate_der()?;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/pkix-cert")
        .header(CONTENT_DISPOSITION, "attachment; filename=HomeProxy-CA.cer")
        .header(CACHE_CONTROL, "no-store")
        .header(CONTENT_LENGTH, certificate.as_ref().len())
        .body(full_body(Bytes::copy_from_slice(certificate.as_ref())))
        .map_err(ProxyError::BuildResponse)
}

fn box_request(request: Request<Incoming>) -> Request<ProxyBody> {
    request.map(|body| {
        body.map_err(|error| -> BoxError { Box::new(error) })
            .boxed_unsync()
    })
}

fn connection_activity(context: &ProxyContext) -> Arc<ConnectionActivity> {
    context
        .connection_permit
        .as_ref()
        .map(|permit| permit.io_activity.clone())
        .unwrap_or_else(|| Arc::new(transport::Activity::new(Box::new(|| {}))))
}

async fn send_origin_body_request(
    upstream: TcpStream,
    request: Request<ProxyBody>,
    tasks: &TaskTracker,
    cancellation: CancellationToken,
    io_activity: Arc<ConnectionActivity>,
) -> Result<Response<Incoming>, ProxyError> {
    let upstream = transport::ProgressIo::new(upstream, io_activity);
    let (mut sender, connection) = timeout(
        UPSTREAM_RESPONSE_TIMEOUT,
        client_http1::handshake(TokioIo::new(upstream)),
    )
    .await
    .map_err(|_| ProxyError::Network("Origin neodpověděl včas."))?
    .map_err(|_| ProxyError::Upstream("Origin nepřijal HTTP spojení."))?;
    tasks.spawn(async move {
        tokio::select! { _ = cancellation.cancelled() => {}, _ = connection.with_upgrades() => {} }
    });
    timeout(UPSTREAM_RESPONSE_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| ProxyError::Network("Origin neodpověděl včas."))?
        .map_err(|_| ProxyError::Upstream("Origin nevrátil platnou HTTP odpověď."))
}

fn prepare_origin_request<B>(
    request: &mut Request<B>,
    canonical_public_fetch: bool,
) -> Result<(), ProxyError> {
    let authority = request
        .uri()
        .authority()
        .cloned()
        .ok_or(ProxyError::InvalidTarget("HTTP adresa nemá hostitele."))?;
    let default_port = match request.uri().scheme_str() {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    };
    let host_header = if authority.port_u16().is_some() && authority.port_u16() == default_port {
        authority.host()
    } else {
        authority.as_str()
    };
    let origin_form: Uri = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .parse()
        .map_err(|_| ProxyError::InvalidTarget("HTTP cesta není platná."))?;
    *request.uri_mut() = origin_form;

    remove_hop_by_hop_headers(request.headers_mut());
    request.headers_mut().remove(PROXY_AUTHORIZATION);
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(host_header)
            .map_err(|_| ProxyError::InvalidTarget("Hostitel není platný."))?,
    );
    if canonical_public_fetch {
        // Origin is part of the cache family (see cache_policy::base_key), so the
        // canonical fetch keeps it and stores the CORS grant for that site only.
        // Privacy signals (Sec-GPC, DNT) are forwarded and partition the family too.
        let negotiated = [
            ACCEPT,
            ACCEPT_LANGUAGE,
            ACCEPT_ENCODING,
            ORIGIN,
            HeaderName::from_static("sec-gpc"),
            HeaderName::from_static("dnt"),
        ]
        .map(|name| {
            let values = request
                .headers()
                .get_all(&name)
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            (name, values)
        });
        request.headers_mut().clear();
        request.headers_mut().insert(
            HOST,
            HeaderValue::from_str(host_header)
                .map_err(|_| ProxyError::InvalidTarget("Hostitel není platný."))?,
        );
        request
            .headers_mut()
            .insert(USER_AGENT, HeaderValue::from_static("HomeProxy/0.4"));
        request
            .headers_mut()
            .insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        for (name, values) in negotiated {
            if !values.is_empty() {
                request.headers_mut().remove(&name);
            }
            for value in values {
                request.headers_mut().append(name.clone(), value);
            }
        }
    }
    Ok(())
}

/// Browser fetch metadata for static media and fonts. The full URL, including any
/// query, stays in the cache key; navigations, fetch()/XHR and scripts/styles
/// (whose query endpoints often tailor output to the browser) never qualify.
fn browser_static_subresource(headers: &HeaderMap) -> bool {
    let destinations = headers
        .get_all(HeaderName::from_static("sec-fetch-dest"))
        .iter()
        .collect::<Vec<_>>();
    destinations.len() == 1
        && destinations[0].to_str().is_ok_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "image" | "font" | "audio" | "video" | "track"
            )
        })
}

fn request_is_shared_cache_eligible<B>(request: &Request<B>) -> bool {
    // Navigations must retain browser metadata: origins use it for redirects and login.
    // They are never canonicalized or shared, even before an origin sets a cookie.
    if request.headers().get_all(ACCEPT).iter().any(|value| {
        value.to_str().map_or(true, |value| {
            let value = value.to_ascii_lowercase();
            value.contains("text/html") || value.contains("application/xhtml+xml")
        })
    }) || header_contains_token(
        request.headers(),
        HeaderName::from_static("sec-fetch-mode"),
        "navigate",
    ) || header_contains_token(
        request.headers(),
        HeaderName::from_static("sec-fetch-dest"),
        "document",
    ) || request.method() != Method::GET
        || (request.uri().query().is_some() && !browser_static_subresource(request.headers()))
        || request.headers().contains_key(COOKIE)
        || request.headers().contains_key(AUTHORIZATION)
        || request.headers().contains_key(RANGE)
        || request.headers().contains_key("proxy-authorization")
        || request.headers().contains_key(CACHE_CONTROL)
        || request.headers().contains_key(PRAGMA)
    {
        return false;
    }
    const ALLOWED: &[&str] = &[
        "accept",
        "accept-encoding",
        "accept-language",
        "connection",
        "host",
        "proxy-connection",
        "user-agent",
    ];
    request.headers().keys().all(|name| {
        let name = name.as_str();
        ALLOWED.contains(&name)
            || matches!(
                name,
                "referer"
                    | "upgrade-insecure-requests"
                    | "priority"
                    | "purpose"
                    | "sec-purpose"
                    | "sec-gpc"
                    | "dnt"
                    | "origin"
            )
            || name.starts_with("sec-fetch-")
            || name.starts_with("sec-ch-ua")
    })
}

#[cfg(test)]
fn response_cache_ttl(headers: &HeaderMap, status: StatusCode) -> Option<Duration> {
    if status != StatusCode::OK
        || headers.contains_key(SET_COOKIE)
        || header_values_contain(headers, CONTENT_DISPOSITION, "attachment")?
    {
        return None;
    }
    let policy = parse_cache_control(headers)?;
    if policy.unsafe_to_share {
        return None;
    }
    if !policy.explicit_public && policy.s_maxage.is_none() {
        return None;
    }
    if !vary_allows_shared_storage(headers)? {
        return None;
    }
    cache_policy::freshness_ttl(headers, &policy)
}

fn try_reserve_buffer_budget(
    budget: &Arc<Semaphore>,
    content_length: Option<usize>,
    candidate: bool,
    response_limit: usize,
) -> Option<OwnedSemaphorePermit> {
    if !candidate || response_limit == 0 {
        return None;
    }
    let content_length = content_length?;
    if content_length > response_limit {
        return None;
    }
    let permits = u32::try_from(content_length.max(1)).ok()?;
    budget.clone().try_acquire_many_owned(permits).ok()
}

fn response_can_transform(headers: &HeaderMap, status: StatusCode) -> bool {
    let Some(cache_control) = parse_cache_control(headers) else {
        return false;
    };
    status == StatusCode::OK
        && !headers.contains_key(SET_COOKIE)
        && !headers.contains_key(CONTENT_ENCODING)
        && !cache_control.unsafe_to_share
        && !cache_control.no_transform
        && headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                let value = value.to_ascii_lowercase();
                value.starts_with("image/jpeg") || value.starts_with("image/png")
            })
}

#[derive(Default)]
struct CacheControlPolicy {
    explicit_public: bool,
    unsafe_to_share: bool,
    requires_validation: bool,
    no_transform: bool,
    must_revalidate: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
    stale_if_error: Option<u64>,
}

fn parse_cache_control(headers: &HeaderMap) -> Option<CacheControlPolicy> {
    let mut policy = CacheControlPolicy::default();
    let mut saw_value = false;
    for value in headers.get_all(CACHE_CONTROL) {
        saw_value = true;
        let value = value.to_str().ok()?;
        for directive in split_http_list(value)? {
            let directive = directive.trim();
            if directive.is_empty() {
                return None;
            }
            let (name, raw_value) = match directive.split_once('=') {
                Some((name, value)) => (name.trim(), Some(value.trim())),
                None => (directive, None),
            };
            if name.is_empty() || !name.bytes().all(is_http_token_byte) {
                return None;
            }
            match name.to_ascii_lowercase().as_str() {
                "public" => {
                    if raw_value.is_some() {
                        return None;
                    }
                    policy.explicit_public = true;
                }
                "private" | "no-store" => policy.unsafe_to_share = true,
                "no-cache" => policy.requires_validation = true,
                "no-transform" => policy.no_transform = true,
                "must-revalidate" | "proxy-revalidate" => policy.must_revalidate = true,
                "max-age" => set_unique_delta_seconds(&mut policy.max_age, raw_value)?,
                "s-maxage" => set_unique_delta_seconds(&mut policy.s_maxage, raw_value)?,
                "stale-if-error" => {
                    set_unique_delta_seconds(&mut policy.stale_if_error, raw_value)?
                }
                _ => {}
            }
        }
    }
    saw_value.then_some(policy)
}

fn set_unique_delta_seconds(target: &mut Option<u64>, raw: Option<&str>) -> Option<()> {
    if target.is_some() {
        return None;
    }
    let raw = raw?;
    let raw = if raw.starts_with('"') || raw.ends_with('"') {
        raw.strip_prefix('"')?.strip_suffix('"')?
    } else {
        raw
    };
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    *target = Some(raw.parse().ok()?);
    Some(())
}

fn split_http_list(value: &str) -> Option<Vec<&str>> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        match character {
            '\\' if quoted => escaped = !escaped,
            '"' if !escaped => quoted = !quoted,
            ',' if !quoted => {
                fields.push(&value[start..index]);
                start = index + 1;
                escaped = false;
            }
            _ => escaped = false,
        }
    }
    if quoted || escaped {
        return None;
    }
    fields.push(&value[start..]);
    Some(fields)
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn header_values_contain(headers: &HeaderMap, name: HeaderName, needle: &str) -> Option<bool> {
    for value in headers.get_all(name) {
        if value.to_str().ok()?.to_ascii_lowercase().contains(needle) {
            return Some(true);
        }
    }
    Some(false)
}

#[cfg(test)]
fn vary_allows_shared_storage(headers: &HeaderMap) -> Option<bool> {
    for value in headers.get_all(VARY) {
        for name in split_http_list(value.to_str().ok()?)? {
            let name = name.trim();
            if name.is_empty()
                || (!name.eq_ignore_ascii_case("accept")
                    && !name.eq_ignore_ascii_case("accept-language")
                    && !name.eq_ignore_ascii_case("accept-encoding"))
            {
                return Some(false);
            }
        }
    }
    Some(true)
}

fn parse_single_age(headers: &HeaderMap) -> Option<u64> {
    let mut values = headers.get_all(AGE).iter();
    let Some(value) = values.next() else {
        return Some(0);
    };
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()?.parse().ok()
}

fn current_response_age(headers: &HeaderMap) -> Option<u64> {
    Some(parse_single_age(headers)?.max(parse_single_date_apparent_age(headers)?))
}

fn parse_single_date_apparent_age(headers: &HeaderMap) -> Option<u64> {
    let mut values = headers.get_all(DATE).iter();
    let Some(value) = values.next() else {
        return Some(0);
    };
    if values.next().is_some() {
        return None;
    }
    let date = httpdate::parse_http_date(value.to_str().ok()?).ok()?;
    Some(
        SystemTime::now()
            .duration_since(date)
            .unwrap_or_default()
            .as_secs(),
    )
}

fn strip_variant_headers(headers: &mut HeaderMap) {
    headers.remove(crate::cache::variants::BASE);
    headers.remove(crate::cache::variants::GENERATION);
    headers.remove(crate::cache::variants::SCHEMA);
    headers.remove(crate::cache::variants::SELECTOR);
}

fn cached_response(mut entry: CachedEntry) -> Result<Response<ProxyBody>, ProxyError> {
    entry.headers.remove("x-homeproxy-transformed");
    strip_variant_headers(&mut entry.headers);
    let origin_age = parse_single_age(&entry.headers).unwrap_or_default();
    let apparent_age = parse_single_date_apparent_age(&entry.headers).unwrap_or_default();
    entry.headers.insert(
        AGE,
        HeaderValue::from_str(
            &apparent_age
                .max(origin_age.saturating_add(entry.age.as_secs()))
                .to_string(),
        )
        .map_err(|_| ProxyError::Upstream("Neplatné stáří cache."))?,
    );
    entry.headers.insert(
        HeaderName::from_static("cache-status"),
        HeaderValue::from_str(&format!(
            "HomeProxy; hit; ttl={}",
            entry.remaining_ttl.as_secs()
        ))
        .map_err(|_| ProxyError::Upstream("Neplatný stav cache."))?,
    );
    add_via(&mut entry.headers);
    let mut response = Response::new(entry.body.boxed_unsync());
    *response.status_mut() = entry.status;
    *response.headers_mut() = entry.headers;
    Ok(response)
}

fn enforce_runtime_policy(
    context: &ProxyContext,
    host: &str,
    adblock_mode: AdblockMode,
) -> Result<crate::policy::PolicyDecision, ProxyError> {
    let global = crate::policy::decision_at(
        &context.settings,
        None,
        host,
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
        crate::policy::QuotaUsage::default(),
    );
    let mut decision = context.stats.policy_decision(context.activity_id, host);
    for check in [&global, &decision] {
        if !check.allowed && check.reason != crate::policy::PolicyReason::Adblock {
            context.stats.blocked();
            return Err(ProxyError::Forbidden(
                "Přístup zakazuje profil, doménové pravidlo, čas nebo kvóta.",
            ));
        }
    }
    decision.no_cache |= global.no_cache;
    decision.explicit_allow |= global.explicit_allow;
    if adblock_mode != AdblockMode::Off
        && !decision.explicit_allow
        && ((!global.allowed && global.reason == crate::policy::PolicyReason::Adblock)
            || (!decision.allowed && decision.reason == crate::policy::PolicyReason::Adblock))
    {
        context.stats.blocked();
        return Err(ProxyError::Blocked);
    }
    enforce_host_policy(
        host,
        if decision.explicit_allow {
            AdblockMode::Off
        } else {
            adblock_mode
        },
        &context.stats,
        context.allow_private_destinations,
    )?;
    Ok(decision)
}

fn enforce_host_policy(
    host: &str,
    mode: AdblockMode,
    stats: &Stats,
    allow_private_destinations: bool,
) -> Result<(), ProxyError> {
    if !allow_private_destinations && host_is_intrinsically_private(host) {
        return Err(ProxyError::Forbidden(
            "Proxy nepovoluje přístup k interním adresám tohoto počítače ani routeru.",
        ));
    }
    if is_blocked_host(host, mode) {
        stats.blocked();
        return Err(ProxyError::Blocked);
    }
    Ok(())
}

async fn connect_for_context(
    host: &str,
    port: u16,
    context: &ProxyContext,
) -> Result<TcpStream, ProxyError> {
    ensure_online(context)?;
    let stream = upstream::connect(
        host,
        port,
        context.allow_private_destinations,
        &context.resolver,
        &context.settings,
        &context.host_addresses,
    )
    .await?;
    if transport::configure_keepalive(&stream).is_err() {
        context.stats.keepalive_configuration_failed();
    }
    Ok(stream)
}

async fn connect_destination(
    host: &str,
    port: u16,
    allow_private_destinations: bool,
    resolver: &Resolver,
) -> Result<TcpStream, ProxyError> {
    let resolved = resolver
        .resolve(host, port)
        .await
        .map_err(ProxyError::Upstream)?;
    dial_addresses(resolved, allow_private_destinations, resolver).await
}

async fn dial_addresses(
    resolved: Vec<SocketAddr>,
    allow_private_destinations: bool,
    resolver: &Resolver,
) -> Result<TcpStream, ProxyError> {
    #[cfg(not(test))]
    let _ = resolver;
    #[cfg(test)]
    let connect = {
        let resolver = resolver.clone();
        move |address| {
            let resolver = resolver.clone();
            async move { resolver.test_dial(address).await }
        }
    };
    #[cfg(not(test))]
    let connect = TcpStream::connect;
    connect_resolved_with(resolved, allow_private_destinations, connect).await
}

async fn connect_resolved_with<F, Fut>(
    resolved: Vec<SocketAddr>,
    allow_private_destinations: bool,
    connect: F,
) -> Result<TcpStream, ProxyError>
where
    F: Fn(SocketAddr) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = std::io::Result<TcpStream>> + Send + 'static,
{
    if resolved.is_empty() {
        return Err(ProxyError::Upstream("Hostitel nemá žádnou adresu."));
    }
    if !allow_private_destinations
        && resolved
            .iter()
            .any(|address| !destination_is_public(address.ip()))
    {
        return Err(ProxyError::Forbidden(
            "DNS vrátilo neveřejnou adresu. Zkontrolujte DNS nastavení HomeProxy a síťové připojení.",
        ));
    }
    let mut seen = HashSet::new();
    let mut addresses = resolved
        .into_iter()
        .filter(|address| seen.insert(*address))
        .collect::<Vec<_>>();
    // Try the other address family next, even if DNS listed several IPv6 addresses first.
    if let Some(first) = addresses.first() {
        if let Some(index) = addresses
            .iter()
            .position(|address| address.is_ipv6() != first.is_ipv6())
        {
            let alternate = addresses.remove(index);
            addresses.insert(1, alternate);
        }
    }
    let connect = Arc::new(connect);
    let race = async move {
        let mut pending = JoinSet::new();
        let mut addresses = addresses.into_iter();
        let mut next_attempt = tokio::time::Instant::now();
        loop {
            tokio::select! {
                result = pending.join_next(), if !pending.is_empty() => {
                    if let Some(Ok(Ok(stream))) = result {
                        return Ok(stream);
                    }
                    if pending.is_empty() {
                        next_attempt = tokio::time::Instant::now();
                    }
                }
                _ = tokio::time::sleep_until(next_attempt), if addresses.len() > 0 => {
                    if let Some(address) = addresses.next() {
                        let connect = connect.clone();
                        pending.spawn(async move { connect(address).await });
                        next_attempt = tokio::time::Instant::now() + Duration::from_millis(250);
                    }
                }
                else => break,
            }
        }
        Err(ProxyError::Network("K hostiteli se nepodařilo připojit."))
    };
    timeout(CONNECT_TIMEOUT, race)
        .await
        .map_err(|_| ProxyError::Network("K hostiteli se nepodařilo připojit."))?
}

fn peer_is_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

fn peer_is_external_device(peer: IpAddr, host_addresses: &HashSet<IpAddr>) -> bool {
    !peer.is_loopback() && !host_addresses.contains(&peer)
}

fn request_requires_lan_auth(peer: IpAddr, settings: &Settings) -> bool {
    !peer.is_loopback() && settings.lan_auth_enabled
}

fn device_is_denied(peer: IpAddr, settings: &Settings) -> bool {
    match peer {
        IpAddr::V4(ip) => settings.denied_client_ips.contains(&ip),
        IpAddr::V6(_) => false,
    }
}

fn record_successful_external_result(stats: &Stats, external_device: bool, succeeded: bool) {
    if external_device && succeeded {
        stats.successful_external_request();
    }
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    let nominated = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect::<Vec<_>>();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        TRANSFER_ENCODING,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        HeaderName::from_static("te"),
        HeaderName::from_static("trailer"),
        HeaderName::from_static("upgrade"),
    ] {
        headers.remove(name);
    }
}

fn merge_vary_accept(headers: &mut HeaderMap) {
    let mut names = Vec::new();
    for value in headers.get_all(VARY) {
        let Ok(value) = value.to_str() else {
            return;
        };
        names.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty()),
        );
    }
    if names.iter().any(|name| name.eq_ignore_ascii_case("accept")) {
        return;
    }
    names.push("Accept");
    let value = names.join(", ");
    if let Ok(value) = HeaderValue::from_str(&value) {
        headers.insert(VARY, value);
    }
}

fn header_contains_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(',')
                .map(|part| part.split(';').next().unwrap_or("").trim())
                .any(|part| part.eq_ignore_ascii_case(token))
        })
}

fn add_via(headers: &mut HeaderMap) {
    headers.append(
        HeaderName::from_static("via"),
        HeaderValue::from_static(VIA_VALUE),
    );
}

fn proxy_auth_required(challenge: String) -> Response<ProxyBody> {
    let mut response = error_response(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "Toto zařízení potřebuje jméno a přístupový klíč z aplikace HomeProxy.",
    );
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response.headers_mut().insert(PROXY_AUTHENTICATE, value);
    }
    response
}

fn denied_device_response() -> Response<ProxyBody> {
    let mut response = error_response(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "Toto zařízení je v aplikaci HomeProxy zakázané.",
    );
    response.headers_mut().insert(
        PROXY_AUTHENTICATE,
        HeaderValue::from_static("HomeProxy realm=\"device-blocked\""),
    );
    response
}

fn error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .body(full_body(Bytes::copy_from_slice(message.as_bytes())))
        .unwrap_or_else(|_| Response::new(empty_body()))
}

struct BudgetedBytes {
    bytes: Bytes,
    _permit: Arc<OwnedSemaphorePermit>,
}
impl AsRef<[u8]> for BudgetedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn empty_body() -> ProxyBody {
    full_body(Bytes::new())
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("{0}")]
    Network(&'static str),
    #[error("Offline cache does not contain a reusable response.")]
    Offline,
    #[error("{0}")]
    InvalidTarget(&'static str),
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("Blokováno nastavením reklam.")]
    Blocked,
    #[error("{0}")]
    Upstream(&'static str),
    #[error("{0}")]
    Busy(&'static str),
    #[error("Službu nelze otevřít na {failure_endpoint}: {source}", failure_endpoint = .failure.endpoint)]
    Bind {
        failure: ListenerBindFailure,
        #[source]
        source: std::io::Error,
    },
    #[error("Proxy nelze otevřít: {0}")]
    Io(#[from] std::io::Error),
    #[error("Odpověď proxy nelze vytvořit: {0}")]
    BuildResponse(#[from] http::Error),
    #[error("{0}")]
    Tls(#[from] TlsInspectionError),
}

impl ProxyError {
    pub(crate) fn listener_bind_failure(&self) -> Option<ListenerBindFailure> {
        match self {
            Self::Bind { failure, .. } => Some(failure.clone()),
            Self::Network(_)
            | Self::Offline
            | Self::InvalidTarget(_)
            | Self::Forbidden(_)
            | Self::Blocked
            | Self::Upstream(_)
            | Self::Busy(_)
            | Self::Io(_)
            | Self::BuildResponse(_)
            | Self::Tls(_) => None,
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Offline => StatusCode::GATEWAY_TIMEOUT,
            Self::InvalidTarget(_) => StatusCode::BAD_REQUEST,
            Self::Forbidden(_) | Self::Blocked => StatusCode::FORBIDDEN,
            Self::Busy(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Network(_)
            | Self::Upstream(_)
            | Self::Bind { .. }
            | Self::Io(_)
            | Self::BuildResponse(_)
            | Self::Tls(_) => StatusCode::BAD_GATEWAY,
        }
    }

    fn user_message(&self) -> &str {
        match self {
            Self::Offline => "Offline cache neobsahuje použitelnou odpověď.",
            Self::InvalidTarget(message)
            | Self::Forbidden(message)
            | Self::Upstream(message)
            | Self::Network(message)
            | Self::Busy(message) => message,
            Self::Blocked => "Požadavek zablokovalo nastavení reklam.",
            Self::Bind { .. } => "HomeProxy nemůže otevřít zvolený port.",
            Self::Io(_) => "Proxy se nedokázala spojit se sítí.",
            Self::BuildResponse(_) => "Proxy nedokázala vytvořit odpověď.",
            Self::Tls(_) => "HomeProxy nedokázal bezpečně otevřít HTTPS spojení.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(super) fn test_tls_inspection(directory: &std::path::Path) -> TlsInspection {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        TlsInspection::for_tests(
            directory.join("inspection-authority.json"),
            rustls::RootCertStore::empty(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn navigation_preserves_headers_and_cookie_redirect_chain_with_cache_on_and_off() {
        for cache_enabled in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let origin = tokio::spawn(async move {
                for step in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let request = String::from_utf8_lossy(&read_headers(&mut stream).await)
                        .to_ascii_lowercase();
                    assert!(
                        request.contains("user-agent: mozilla/5.0 firefox/142.0"),
                        "browser UA changed: {request}"
                    );
                    assert!(request.contains("upgrade-insecure-requests: 1"));
                    let response = if step == 0 {
                        "HTTP/1.1 302 Found\r\nLocation: /final\r\nSet-Cookie: fixture=1; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    } else {
                        assert!(request.contains("cookie: fixture=1"));
                        "HTTP/1.1 200 OK\r\nCache-Control: private, no-store\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                    };
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            });
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let proxy_port = listener.local_addr().unwrap().port();
            let directory = tempfile::tempdir().unwrap();
            let handle = spawn_proxy_with_listeners(
                Settings {
                    cache_enabled,
                    ..Settings::default()
                },
                CacheStore::new(directory.path().join("cache")),
                Arc::new(Stats::default()),
                test_tls_inspection(directory.path()),
                vec![listener],
                true,
            )
            .unwrap();
            for (path, cookie, status) in
                [("/", "", "302"), ("/final", "Cookie: fixture=1\r\n", "200")]
            {
                let request = format!("GET http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: text/html,application/xhtml+xml\r\nUser-Agent: Mozilla/5.0 Firefox/142.0\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Mode: navigate\r\n{cookie}Connection: close\r\n\r\n");
                let response = raw_http_exchange(proxy_port, &request).await;
                let response = String::from_utf8_lossy(&response);
                assert!(
                    response.starts_with(&format!("HTTP/1.1 {status}")),
                    "{response}"
                );
                assert!(!response.contains("cache-status:"));
                if status == "302" {
                    assert!(response.contains("location: /final"));
                    assert!(response.contains("set-cookie: fixture=1"));
                }
            }
            origin.await.unwrap();
            handle.stop().await;
        }
    }

    #[tokio::test]
    async fn stopping_proxy_cancels_a_client_stalled_before_tls_client_hello() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let handle = spawn_proxy_with_listeners(
            Settings {
                https_mode: HttpsMode::Inspect,
                https_client_trust_acknowledged: true,
                https_inspect_hosts: vec!["127.0.0.1".into(), "example.com".into()],
                ..Settings::default()
            },
            CacheStore::new(directory.path().join("cache")),
            Arc::new(Stats::default()),
            test_tls_inspection(directory.path()),
            vec![listener],
            true,
        )
        .unwrap();
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&read_headers(&mut stream).await).starts_with("HTTP/1.1 200")
        );
        timeout(Duration::from_millis(500), handle.stop())
            .await
            .expect("shutdown must cancel the pending TLS handshake");
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_millis(500), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[test]
    fn relay_errors_use_fixed_diagnostic_and_survive_connection_close() {
        let stats = Stats::default();
        let peer = "127.0.0.1".parse().unwrap();
        let id = stats.begin_activity(peer, peer);
        let result: std::io::Result<()> = Err(std::io::Error::other("sensitive upstream details"));
        assert!(!record_connection_result(
            &stats,
            id,
            &result,
            "CONNECT-relay-failed"
        ));
        stats.finish_activity(id, None);
        assert_eq!(stats.snapshot().activity[0].status, "error");
        assert_eq!(
            stats.snapshot().activity[0].error.as_deref(),
            Some("CONNECT-relay-failed")
        );
    }

    #[tokio::test]
    async fn malformed_socks_domain_is_rejected_without_logging_sensitive_suffix() {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stats = Arc::new(Stats::default());
        let handle = spawn_proxy_with_listeners(
            Settings::default(),
            CacheStore::new(directory.path().join("cache")),
            stats.clone(),
            test_tls_inspection(directory.path()),
            vec![listener],
            true,
        )
        .unwrap();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        client.read_exact(&mut [0; 2]).await.unwrap();
        let domain = b"example.test?private-token";
        let mut request = vec![5, 1, 0, 3, domain.len() as u8];
        request.extend_from_slice(domain);
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut response = [0; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 8);
        handle.stop().await;
        assert_eq!(stats.snapshot().upload_bytes, (3 + request.len()) as u64, "reject only after consuming the complete SOCKS request, including its fixed port field");
        let json = serde_json::to_string(&stats.snapshot()).unwrap();
        assert!(!json.contains("private-token"));
        assert_eq!(stats.snapshot().activity[0].status, "error");
    }

    #[tokio::test]
    async fn malformed_http_and_partial_origin_response_remain_visible_as_errors() {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stats = Arc::new(Stats::default());
        let handle = spawn_proxy_with_listeners(
            Settings {
                cache_enabled: true,
                ..Settings::default()
            },
            CacheStore::new(directory.path().join("cache")),
            stats.clone(),
            test_tls_inspection(directory.path()),
            vec![listener],
            true,
        )
        .unwrap();
        let _ = raw_http_exchange(port, "INVALID HTTP\r\n\r\n").await;
        assert_eq!(stats.snapshot().activity[0].status, "error");
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let _ = read_headers(&mut stream).await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nCache-Control: public, max-age=60\r\nConnection: close\r\n\r\npartial").await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
        });
        let response = raw_http_exchange(port,&format!("GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\nHost:127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n")).await;
        assert!(String::from_utf8_lossy(&response).contains("502"));
        server.await.unwrap();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.activity[1].status, "error");
        assert_eq!(snapshot.origin_bytes, 7);
        handle.stop().await;
    }

    #[tokio::test]
    async fn simultaneous_selected_listeners_bind_and_partial_failure_releases_every_socket() {
        let directory = tempfile::tempdir().unwrap();
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let settings = Settings {
            proxy_port: port,
            lan_enabled: true,
            listen_ips: vec!["127.0.0.2".into(), "127.0.0.3".into()],
            ..Settings::default()
        };
        // The internal listener seam accepts injected loopback addresses; production Settings::validate does not.
        let handle = start_proxy(
            settings.clone(),
            CacheStore::new(directory.path().join("cache")),
            Arc::new(Stats::default()),
            test_tls_inspection(directory.path()),
        )
        .await
        .unwrap();
        for ip in ["127.0.0.1", "127.0.0.2", "127.0.0.3"] {
            assert!(TcpStream::connect((ip, port)).await.is_ok());
        }
        handle.stop().await;
        let occupied = TcpListener::bind(("127.0.0.3", port)).await.unwrap();
        assert!(start_proxy(
            settings,
            CacheStore::new(directory.path().join("cache")),
            Arc::new(Stats::default()),
            test_tls_inspection(directory.path())
        )
        .await
        .is_err());
        let restored_loopback = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let restored_lan = TcpListener::bind(("127.0.0.2", port)).await.unwrap();
        drop((occupied, restored_loopback, restored_lan));
    }

    #[test]
    fn origin_host_omits_default_ports_and_preserves_nondefault_ports() {
        for canonical in [false, true] {
            for (uri, expected) in [
                ("https://www.seznam.cz:443/", "www.seznam.cz"),
                ("http://example.com:80/", "example.com"),
                ("https://example.com:8443/", "example.com:8443"),
                ("https://[2606:4700::1111]:443/", "[2606:4700::1111]"),
            ] {
                let mut request = Request::builder().uri(uri).body(()).unwrap();
                prepare_origin_request(&mut request, canonical).unwrap();
                assert_eq!(request.headers()[HOST], expected);
            }
        }
    }

    #[tokio::test]
    async fn stalled_ipv6_does_not_block_a_working_ipv4_address() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let ipv4 = listener.local_addr().unwrap();
        let ipv6 = "[2001:4860:4860::8888]:443".parse().unwrap();
        let result = timeout(
            Duration::from_secs(1),
            connect_resolved_with(vec![ipv6, ipv4], true, |address| async move {
                if address.is_ipv6() {
                    std::future::pending().await
                } else {
                    TcpStream::connect(address).await
                }
            }),
        )
        .await
        .expect("IPv4 fallback must not wait for the IPv6 connection timeout")
        .unwrap();
        assert!(result.peer_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn mixed_public_private_dns_is_rejected_before_any_connection() {
        let result = connect_resolved_with(
            vec![
                "1.1.1.1:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap(),
            ],
            false,
            |_| async { panic!("must validate every resolved address before connecting") },
        )
        .await;
        assert!(matches!(result, Err(ProxyError::Forbidden(_))));
    }

    #[test]
    fn video_clients_get_a_raw_tls_tunnel_on_the_first_connection() {
        let bypass = InspectionBypass::default();
        let peer = "192.168.1.25".parse().unwrap();
        for host in [
            "youtube.com",
            "www.youtube.com",
            "rr1.googlevideo.com",
            "i.ytimg.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
        ] {
            assert!(
                bypass.should_bypass(peer, host),
                "{host} must not require a failed inspection retry"
            );
        }
        for host in [
            "notyoutube.com",
            "youtube.com.attacker.test",
            "googleapis.com",
            "other.googleapis.com",
        ] {
            assert!(!bypass.should_bypass(peer, host));
        }
        assert_eq!(
            connect_adblock_mode("www.youtube.com", AdblockMode::Mild),
            AdblockMode::Mild
        );
    }

    #[test]
    fn shared_cache_never_accepts_identity_or_query_requests() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/public")
            .header(ACCEPT, "text/html")
            .body(())
            .unwrap();
        assert!(!request_is_shared_cache_eligible(&request));

        let request_with_query = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/public?user=1")
            .body(())
            .unwrap();
        assert!(!request_is_shared_cache_eligible(&request_with_query));

        let request_with_cookie = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/public")
            .header(COOKIE, "session=secret")
            .body(())
            .unwrap();
        assert!(!request_is_shared_cache_eligible(&request_with_cookie));

        let request_with_identity_header = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/public")
            .header("x-user-id", "private-user")
            .body(())
            .unwrap();
        assert!(!request_is_shared_cache_eligible(
            &request_with_identity_header
        ));
    }

    #[test]
    fn shared_cache_accepts_canonicalizable_browser_metadata_only() {
        let browser_request = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/public-image.jpg")
            .header(ACCEPT, "image/avif,image/webp,image/apng,image/*,*/*;q=0.8")
            .header(ACCEPT_ENCODING, "gzip, deflate")
            .header(ACCEPT_LANGUAGE, "cs-CZ,cs;q=0.9,en;q=0.8")
            .header("referer", "https://example.com/gallery")
            .header(
                "sec-ch-ua",
                "\"Chromium\";v=\"140\", \"Microsoft Edge\";v=\"140\"",
            )
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"Windows\"")
            .header("sec-fetch-dest", "image")
            .header("sec-fetch-mode", "no-cors")
            .header("sec-fetch-site", "same-origin")
            .header("upgrade-insecure-requests", "1")
            .header("priority", "i")
            .header("purpose", "prefetch")
            .header("sec-purpose", "prefetch")
            .header(USER_AGENT, "Mozilla/5.0 Chrome/140.0.0.0 Edg/140.0.0.0")
            .body(())
            .unwrap();
        assert!(request_is_shared_cache_eligible(&browser_request));

        let request = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/public-image.jpg")
            .header("x-user-id", "https://private.example")
            .body(())
            .unwrap();
        assert!(!request_is_shared_cache_eligible(&request));
    }

    #[tokio::test]
    async fn canonical_origin_request_strips_browser_metadata() {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let (request_sender, request_receiver) = tokio::sync::oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let request = read_headers(&mut stream).await;
            request_sender
                .send(String::from_utf8_lossy(&request).into_owned())
                .unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nCache-Control: public, max-age=60\r\nContent-Length: 6\r\nConnection: close\r\n\r\npublic",
                )
                .await
                .unwrap();
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let handle = spawn_proxy_with_listeners(
            Settings {
                cache_enabled: true,
                ..Settings::default()
            },
            CacheStore::new(directory.path().to_path_buf()),
            Arc::new(Stats::default()),
            test_tls_inspection(directory.path()),
            vec![proxy_listener],
            true,
        )
        .unwrap();

        let request = format!(
            "GET http://127.0.0.1:{upstream_port}/public-image.jpg HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nAccept: image/avif,image/webp,image/*,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: cs-CZ,cs;q=0.9\r\nReferer: https://example.com/gallery\r\nSec-CH-UA: \"Chromium\";v=\"140\", \"Microsoft Edge\";v=\"140\"\r\nSec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\nSec-Fetch-Dest: image\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Site: same-origin\r\nUpgrade-Insecure-Requests: 1\r\nPriority: i\r\nPurpose: prefetch\r\nSec-Purpose: prefetch\r\nUser-Agent: Mozilla/5.0 Chrome/140.0.0.0 Edg/140.0.0.0\r\nConnection: close\r\n\r\n"
        );
        let response = raw_http_exchange(proxy_port, &request).await;
        let origin_request = request_receiver.await.unwrap().to_ascii_lowercase();

        assert!(String::from_utf8_lossy(&response)
            .contains("cache-status: HomeProxy; fwd=miss; stored"));
        assert!(origin_request.contains("user-agent: homeproxy/0.4\r\n"));
        assert!(origin_request.contains("accept-encoding: gzip, deflate\r\n"));
        assert!(origin_request.contains("accept: image/avif"));
        assert!(origin_request.contains("accept-language: cs-cz,cs;q=0.9\r\n"));
        for stripped in [
            "referer:",
            "sec-ch-ua",
            "sec-fetch-",
            "upgrade-insecure-requests:",
            "priority:",
            "purpose:",
            "sec-purpose:",
        ] {
            assert!(!origin_request.contains(stripped), "retained {stripped}");
        }

        handle.stop().await;
        upstream_task.await.unwrap();
    }

    #[test]
    fn public_cache_requires_explicit_freshness_and_rejects_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=120"),
        );
        assert_eq!(
            response_cache_ttl(&headers, StatusCode::OK),
            Some(Duration::from_secs(120))
        );
        headers.insert(SET_COOKIE, HeaderValue::from_static("session=secret"));
        assert!(response_cache_ttl(&headers, StatusCode::OK).is_none());
    }

    #[test]
    fn public_cache_accounts_for_apparent_age_from_date() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=120"),
        );
        headers.insert(
            DATE,
            HeaderValue::from_str(&httpdate::fmt_http_date(
                std::time::SystemTime::now() - Duration::from_secs(180),
            ))
            .unwrap(),
        );
        assert_eq!(
            response_cache_ttl(&headers, StatusCode::OK),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn delivery_optimization_keeps_pinned_cloud_tls_untouched() {
        let bypass = InspectionBypass::default();
        let peer = "192.168.68.80".parse().unwrap();
        for host in [
            "geo.prod.do.dsp.mp.microsoft.com",
            "array1.prod.do.dsp.mp.microsoft.com",
            "GEO.PROD.DO.DSP.MP.MICROSOFT.COM.",
        ] {
            assert!(bypass.should_bypass(peer, host), "{host}");
        }
        for host in [
            "notdo.dsp.mp.microsoft.com",
            "do.dsp.mp.microsoft.com.example",
            "www.microsoft.com",
            "download.windowsupdate.com",
        ] {
            assert!(!bypass.should_bypass(peer, host), "{host}");
        }
    }

    #[test]
    fn public_cache_rejects_ambiguous_dates_and_reports_corrected_age() {
        let date = HeaderValue::from_str(&httpdate::fmt_http_date(
            SystemTime::now() - Duration::from_secs(180),
        ))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        );
        headers.insert(DATE, date.clone());
        headers.insert(AGE, HeaderValue::from_static("301"));
        assert_eq!(
            response_cache_ttl(&headers, StatusCode::OK),
            Some(Duration::ZERO)
        );

        headers.remove(AGE);
        headers.append(DATE, date);
        assert!(response_cache_ttl(&headers, StatusCode::OK).is_none());

        headers.remove(DATE);
        headers.insert(
            DATE,
            HeaderValue::from_str(&httpdate::fmt_http_date(
                SystemTime::now() - Duration::from_secs(180),
            ))
            .unwrap(),
        );
        let response = cached_response(CachedEntry {
            status: StatusCode::OK,
            headers,
            body: Bytes::new().into(),
            age: Duration::from_secs(2),
            remaining_ttl: Duration::from_secs(100),
        })
        .unwrap();
        assert!(parse_single_age(response.headers()).unwrap() >= 180);
    }

    #[tokio::test]
    async fn partial_cache_hit_only_credits_body_bytes_actually_yielded() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().into());
        let key = "a".repeat(64);
        cache
            .put(
                &key,
                StatusCode::OK,
                &HeaderMap::new(),
                Bytes::from(vec![7; 256 * 1024]),
                Duration::from_secs(60),
                1024 * 1024,
            )
            .await
            .unwrap();
        let entry = cache.get(&key).await.unwrap();
        let stats = Arc::new(Stats::default());
        stats.cache_hit(0);
        let mut body =
            meter_cached_response(cached_response(entry).unwrap(), stats.clone()).into_body();
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert!(bytes.len() <= crate::cache::IO_CHUNK_BYTES);
        drop(body);
        assert_eq!(stats.snapshot().cache_bytes_saved, bytes.len() as u64);
        assert!(stats.snapshot().cache_bytes_saved < 256 * 1024);
    }

    #[tokio::test]
    async fn buffer_permit_lives_until_the_last_emitted_bytes_clone_is_dropped() {
        let budget = Arc::new(Semaphore::new(3));
        let permit = Arc::new(budget.clone().try_acquire_many_owned(3).unwrap());
        let bytes = Bytes::from_owner(BudgetedBytes {
            bytes: Bytes::from_static(b"abc"),
            _permit: permit,
        });
        let mut body = full_body(bytes);
        let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let retained = frame.clone();
        drop(frame);
        drop(body);
        assert_eq!(budget.available_permits(), 0);
        drop(retained);
        assert_eq!(budget.available_permits(), 3);
    }

    #[test]
    fn global_buffer_budget_falls_back_to_streaming_when_exhausted() {
        let budget = Arc::new(Semaphore::new(8));
        let held = budget.clone().try_acquire_many_owned(8).unwrap();
        assert!(try_reserve_buffer_budget(&budget, Some(1), true, MAX_BUFFERED_BODY).is_none());
        drop(held);
        assert!(try_reserve_buffer_budget(&budget, Some(1), true, MAX_BUFFERED_BODY).is_some());
        assert!(try_reserve_buffer_budget(
            &budget,
            Some(MAX_BUFFERED_BODY + 1),
            true,
            MAX_BUFFERED_BODY
        )
        .is_none());
        assert!(try_reserve_buffer_budget(&budget, Some(1), false, MAX_BUFFERED_BODY).is_none());
        assert!(try_reserve_buffer_budget(&budget, Some(0), true, 0).is_none());
        assert!(try_reserve_buffer_budget(&budget, Some(1), true, 0).is_none());
        assert!(
            try_reserve_buffer_budget(&Arc::new(Semaphore::new(0)), Some(1), true, 1).is_none()
        );
        assert!(try_reserve_buffer_budget(&budget, Some(2), true, 1).is_none());
        assert!(try_reserve_buffer_budget(&budget, Some(1), true, 1).is_some());
    }

    #[test]
    fn public_cache_fails_closed_across_repeated_policy_headers() {
        let mut headers = HeaderMap::new();
        headers.append(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=120"),
        );
        headers.append(
            CACHE_CONTROL,
            HeaderValue::from_static("private=\"Set-Cookie, X-User\""),
        );
        assert!(response_cache_ttl(&headers, StatusCode::OK).is_none());

        headers.remove(CACHE_CONTROL);
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=120"),
        );
        headers.append(VARY, HeaderValue::from_static("Accept"));
        headers.append(VARY, HeaderValue::from_static("*"));
        assert!(response_cache_ttl(&headers, StatusCode::OK).is_none());
    }

    #[test]
    fn removes_tokens_from_every_connection_header() {
        let mut headers = HeaderMap::new();
        headers.append(CONNECTION, HeaderValue::from_static("x-first"));
        headers.append(CONNECTION, HeaderValue::from_static("x-second"));
        headers.insert("x-first", HeaderValue::from_static("one"));
        headers.insert("x-second", HeaderValue::from_static("two"));
        remove_hop_by_hop_headers(&mut headers);
        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key("x-first"));
        assert!(!headers.contains_key("x-second"));
    }

    #[test]
    fn limits_connections_per_peer_and_releases_slots() {
        let limiter = ConnectionLimiter::default();
        let peer = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        let mut permits = (0..MAX_CONNECTIONS_PER_PEER)
            .map(|_| limiter.try_acquire(peer).unwrap())
            .collect::<Vec<_>>();
        assert!(limiter.try_acquire(peer).is_err());
        permits.pop();
        assert!(limiter.try_acquire(peer).is_ok());
    }

    #[test]
    fn connection_capacity_preserves_peer_headroom_and_global_ceiling() {
        let limiter = ConnectionLimiter::default();
        let peer_one: IpAddr = "192.168.1.20".parse().unwrap();
        let peer_two: IpAddr = "192.168.1.21".parse().unwrap();
        let peer_three: IpAddr = "192.168.1.22".parse().unwrap();
        let mut first = (0..128)
            .map(|_| limiter.try_acquire(peer_one).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            limiter.try_acquire(peer_one),
            Err(ConnectionRejectionReason::PeerLimit)
        ));
        let second = (0..128)
            .map(|_| limiter.try_acquire(peer_two).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(limiter.global.available_permits(), 0);
        assert!(matches!(
            limiter.try_acquire(peer_three),
            Err(ConnectionRejectionReason::GlobalLimit)
        ));
        first.pop();
        let third = limiter.try_acquire(peer_three).unwrap();
        assert_eq!(limiter.global.available_permits(), 0);
        drop((first, second, third));
        assert_eq!(limiter.global.available_permits(), 256);
        assert!(limiter.per_peer.lock().unwrap().is_empty());
    }

    #[test]
    fn external_device_detection_excludes_loopback_and_host_addresses() {
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 68, 52));
        let remote = IpAddr::V4(Ipv4Addr::new(192, 168, 68, 81));
        let host_addresses = HashSet::from([IpAddr::V4(Ipv4Addr::LOCALHOST), host]);

        assert!(!peer_is_external_device(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &host_addresses,
        ));
        assert!(!peer_is_external_device(host, &host_addresses));
        assert!(peer_is_external_device(remote, &host_addresses));
    }

    #[test]
    fn listener_bind_errors_have_stable_ui_reasons() {
        assert_eq!(
            listener_bind_reason(std::io::ErrorKind::AddrInUse),
            ListenerBindReason::InUse,
        );
        assert_eq!(
            listener_bind_reason(std::io::ErrorKind::PermissionDenied),
            ListenerBindReason::AccessDenied,
        );
        assert_eq!(
            listener_bind_reason(std::io::ErrorKind::AddrNotAvailable),
            ListenerBindReason::AddressUnavailable,
        );
        assert_eq!(
            listener_bind_reason(std::io::ErrorKind::ConnectionReset),
            ListenerBindReason::Other,
        );
    }

    #[test]
    fn lan_authentication_is_optional_but_loopback_never_requires_it() {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let remote = IpAddr::V4(Ipv4Addr::new(192, 168, 68, 81));
        let mut settings = Settings::default();

        assert!(!request_requires_lan_auth(loopback, &settings));
        assert!(request_requires_lan_auth(remote, &settings));

        settings.lan_auth_enabled = false;
        assert!(!request_requires_lan_auth(remote, &settings));
    }

    #[test]
    fn a_denied_device_gets_an_explicit_407_response() {
        let response = denied_device_response();

        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(
            response.headers().get(PROXY_AUTHENTICATE).unwrap(),
            "HomeProxy realm=\"device-blocked\""
        );
    }

    #[test]
    fn chat_service_hosts_bypass_inspection_without_matching_lookalikes() {
        for host in [
            "g.whatsapp.net",
            "mmg.whatsapp.net",
            "media-mxp1-1.cdn.whatsapp.net",
            "static.whatsapp.net",
            "web.whatsapp.com",
            "edge-mqtt.facebook.com",
            "cdn.fbsbx.com",
            "api.telegram.org",
            "updates.tdesktop.com",
            "chat.signal.org",
            "cdn.signal.org.",
        ] {
            assert!(
                host_matches_inspection_bypass(host),
                "did not bypass {host}"
            );
        }
        for host in [
            "example.com",
            "whatsapp.com.attacker.example",
            "nottelegram.org",
            "signal.org.example",
        ] {
            assert!(
                !host_matches_inspection_bypass(host),
                "bypassed lookalike {host}"
            );
        }
        assert_eq!(
            connect_adblock_mode("edge-mqtt.facebook.com", AdblockMode::Strict),
            AdblockMode::Off
        );
        assert_eq!(
            connect_adblock_mode("ads.doubleclick.net", AdblockMode::Strict),
            AdblockMode::Strict
        );
        assert!(loopback_nonstandard_connect(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            5222,
            false
        ));
        assert!(!loopback_nonstandard_connect(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            5222,
            false
        ));

        let dynamic = InspectionBypass::default();
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for index in 0..(MAX_INSPECTION_FAIL_OPEN_HOSTS + 8) {
            dynamic.remember_rejected_inspection(peer, &format!("pinned-{index}.example"));
        }
        assert_eq!(
            dynamic.retries.lock().unwrap().len(),
            MAX_INSPECTION_FAIL_OPEN_HOSTS
        );
        assert!(dynamic.should_bypass(
            peer,
            &format!("pinned-{}.example", MAX_INSPECTION_FAIL_OPEN_HOSTS + 7)
        ));
    }

    #[test]
    fn only_successful_external_results_complete_guided_verification() {
        let stats = Stats::default();

        record_successful_external_result(&stats, true, false);
        record_successful_external_result(&stats, false, true);
        assert_eq!(stats.snapshot().successful_external_requests, 0);

        record_successful_external_result(&stats, true, true);
        assert_eq!(stats.snapshot().successful_external_requests, 1);
    }

    #[tokio::test]
    async fn full_proxy_flow_serves_a_public_cache_hit_and_blocks_an_ad_host() {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let upstream_hits = Arc::new(AtomicUsize::new(0));
        let upstream_counter = upstream_hits.clone();
        let upstream_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = upstream_listener.accept().await.unwrap();
                upstream_counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut request = [0u8; 4096];
                    let read = stream.read(&mut request).await.unwrap_or_default();
                    let private = request[..read]
                        .windows(b"/private".len())
                        .any(|window| window == b"/private");
                    let response: &[u8] = if private {
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: private, max-age=60\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret"
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: public, max-age=60\r\nContent-Length: 6\r\nConnection: close\r\n\r\npublic"
                    };
                    stream.write_all(response).await.unwrap();
                });
            }
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let handle = spawn_proxy_with_listeners(
            Settings {
                cache_enabled: true,
                ..Settings::default()
            },
            CacheStore::new(directory.path().to_path_buf()),
            Arc::new(Stats::default()),
            test_tls_inspection(directory.path()),
            vec![proxy_listener],
            true,
        )
        .unwrap();

        let request = format!(
            "GET http://127.0.0.1:{upstream_port}/public HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
        );
        let first = raw_http_exchange(proxy_port, &request).await;
        let second = raw_http_exchange(proxy_port, &request).await;
        assert!(String::from_utf8_lossy(&first).contains("public"));
        assert!(String::from_utf8_lossy(&second).contains("cache-status: HomeProxy; hit"));
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

        let private_request = format!(
            "GET http://127.0.0.1:{upstream_port}/private HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
        );
        let private_first = raw_http_exchange(proxy_port, &private_request).await;
        let private_second = raw_http_exchange(proxy_port, &private_request).await;
        assert!(String::from_utf8_lossy(&private_first).contains("secret"));
        assert!(!String::from_utf8_lossy(&private_first).contains("cache-status"));
        assert!(!String::from_utf8_lossy(&private_second).contains("cache-status"));
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 3);

        let blocked = raw_http_exchange(
            proxy_port,
            "GET http://ads.doubleclick.net/banner HTTP/1.1\r\nHost: ads.doubleclick.net\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&blocked).starts_with("HTTP/1.1 403"));

        handle.stop().await;
        upstream_task.abort();
    }

    #[tokio::test]
    async fn configurable_object_limit_and_zero_buffers_preserve_http_miss_hit_and_bypass() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let origin = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut request = [0; 4096];
                    let read = stream.read(&mut request).await.unwrap();
                    let over = String::from_utf8_lossy(&request[..read]).contains("/over");
                    let length = 1024 * 1024 + usize::from(over);
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                    for _ in 0..16 {
                        stream.write_all(&[42; 65536]).await.unwrap();
                    }
                    if over {
                        stream.write_all(&[42]).await.unwrap();
                    }
                });
            }
        });
        for buffer_limit in [0, 1, 8] {
            let directory = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let proxy_port = listener.local_addr().unwrap().port();
            let before = hits.load(Ordering::SeqCst);
            let handle = spawn_proxy_with_listeners(
                Settings {
                    cache_enabled: true,
                    cache_max_object_mib: 1,
                    response_buffer_limit_mib: buffer_limit,
                    response_buffer_budget_mib: if buffer_limit == 0 { 0 } else { 64 },
                    compression_preset: crate::CompressionPreset::Off,
                    ..Settings::default()
                },
                CacheStore::new(directory.path().join("cache")),
                Arc::new(Stats::default()),
                test_tls_inspection(directory.path()),
                vec![listener],
                true,
            )
            .unwrap();
            for (path, length) in [("exact", 1024 * 1024), ("over", 1024 * 1024 + 1)] {
                for attempt in 0..2 {
                    let request = format!("GET http://127.0.0.1:{port}/{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
                    let response = raw_http_exchange(proxy_port, &request).await;
                    let end = response
                        .windows(4)
                        .position(|bytes| bytes == b"\r\n\r\n")
                        .unwrap()
                        + 4;
                    assert_eq!(response.len() - end, length);
                    assert!(response[end..].iter().all(|byte| *byte == 42));
                    let hit = String::from_utf8_lossy(&response[..end]).contains("HomeProxy; hit");
                    assert_eq!(
                        hit,
                        path == "exact" && attempt == 1,
                        "{buffer_limit}/{path}/{attempt}"
                    );
                }
            }
            assert_eq!(hits.load(Ordering::SeqCst) - before, 3);
            handle.stop().await;
        }
        origin.abort();
    }

    #[tokio::test]
    async fn large_public_file_streams_to_disk_and_hits_without_refetch() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let origin = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut request = [0; 4096];
                    assert!(stream.read(&mut request).await.unwrap() > 0);
                    stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nContent-Length: 9437184\r\nConnection: close\r\n\r\n").await.unwrap();
                    for _ in 0..144 {
                        if stream.write_all(&[42; 65536]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let handle = spawn_proxy_with_listeners(
            Settings {
                cache_enabled: true,
                ..Settings::default()
            },
            CacheStore::new(directory.path().join("cache")),
            Arc::new(Stats::default()),
            test_tls_inspection(directory.path()),
            vec![listener],
            true,
        )
        .unwrap();
        let request = format!("GET http://127.0.0.1:{port}/package HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        for attempt in 0..2 {
            let response = raw_http_exchange(proxy_port, &request).await;
            let end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            assert_eq!(response.len() - end, 9 * 1024 * 1024);
            assert!(response[end..].iter().all(|byte| *byte == 42));
            if attempt == 1 {
                assert!(String::from_utf8_lossy(&response[..end]).contains("HomeProxy; hit"));
            }
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        handle.stop().await;
        origin.abort();
    }

    #[tokio::test]
    #[ignore = "opt-in isolated 1 GiB loopback transfer; no system proxy or CA installation"]
    async fn one_gib_public_file_streams_with_bounded_memory() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let source = tokio::spawn(async move {
            loop {
                let (mut stream, _) = upstream.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut request = [0; 4096];
                    assert!(stream.read(&mut request).await.unwrap() > 0);
                    stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=3600\r\nContent-Length: 1073741824\r\nConnection: close\r\n\r\n").await.unwrap();
                    let chunk = [0x5a; 64 * 1024];
                    for _ in 0..16384 {
                        stream.write_all(&chunk).await.unwrap();
                    }
                });
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = tempfile::tempdir().unwrap();
        let stats = Arc::new(Stats::default());
        let handle = spawn_proxy_with_listeners(
            Settings {
                cache_enabled: true,
                cache_limit_gib: 2,
                ..Settings::default()
            },
            CacheStore::new(dir.path().join("cache")),
            stats.clone(),
            test_tls_inspection(dir.path()),
            vec![listener],
            true,
        )
        .unwrap();
        let request = format!("GET http://127.0.0.1:{upstream_port}/one-gib HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n");
        let mut digests = Vec::new();
        for pass in 0..2 {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                headers.push_str(&line);
            }
            assert!(headers.starts_with("HTTP/1.1 200"));
            if pass == 0 {
                assert!(headers.contains("HomeProxy; fwd=miss"));
                assert!(!headers.contains("stored"));
            } else {
                assert!(headers.contains("HomeProxy; hit"));
            }
            let mut hasher = Sha256::new();
            let mut count = 0u64;
            let mut chunk = [0; 64 * 1024];
            loop {
                let read = reader.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                count += read as u64;
                hasher.update(&chunk[..read]);
                assert!(chunk[..read].iter().all(|byte| *byte == 0x5a));
            }
            assert_eq!(count, MAX_CACHE_ITEM_BYTES);
            let digest = hex::encode(hasher.finalize());
            println!("1 GiB pass {pass}: bytes={count}, sha256={digest}");
            digests.push(digest);
        }
        assert_eq!(digests[0], digests[1]);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(stats.snapshot().cache_bytes_saved, MAX_CACHE_ITEM_BYTES);
        handle.stop().await;
        source.abort();
    }

    #[tokio::test]
    async fn expanded_ad_hosts_are_rejected_over_http_connect_and_socks() {
        for (mode, host) in [
            (AdblockMode::Mild, "hbopenbid.pubmatic.com"),
            (AdblockMode::Mild, "ssp.seznam.cz"),
            (AdblockMode::Strict, "api2.amplitude.com"),
        ] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let directory = tempfile::tempdir().unwrap();
            let stats = Arc::new(Stats::default());
            let handle = spawn_proxy_with_listeners(
                Settings {
                    adblock_mode: mode,
                    ..Settings::default()
                },
                CacheStore::new(directory.path().join("cache")),
                stats.clone(),
                test_tls_inspection(directory.path()),
                vec![listener],
                true,
            )
            .unwrap();
            for request in [
                format!("GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
                format!(
                    "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nConnection: close\r\n\r\n"
                ),
            ] {
                let response = raw_http_exchange(port, &request).await;
                assert!(response.starts_with(b"HTTP/1.1 403"), "{host}");
            }
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut greeting = [0; 2];
            client.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 0]);
            let mut request = vec![5, 1, 0, 3, host.len() as u8];
            request.extend_from_slice(host.as_bytes());
            request.extend_from_slice(&443u16.to_be_bytes());
            client.write_all(&request).await.unwrap();
            let mut reply = [0; 10];
            timeout(Duration::from_secs(2), client.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply[1], 2, "{host}");
            assert_eq!(stats.snapshot().blocked_requests, 3);
            handle.stop().await;
        }
    }

    #[tokio::test]
    async fn range_downloads_preserve_partial_response_and_bypass_shared_cache() {
        for enabled in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let origin_port = listener.local_addr().unwrap().port();
            let origin = tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let request = String::from_utf8(read_headers(&mut stream).await)
                        .unwrap()
                        .to_lowercase();
                    assert!(request.contains("range: bytes=3-5"));
                    stream.write_all(b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, max-age=300\r\nContent-Length: 3\r\nContent-Range: bytes 3-5/9\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\ndef").await.unwrap();
                }
            });
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let directory = tempfile::tempdir().unwrap();
            let cache_root = directory.path().join("cache");
            let stats = Arc::new(Stats::default());
            let handle = spawn_proxy_with_listeners(
                Settings {
                    cache_enabled: enabled,
                    ..Settings::default()
                },
                CacheStore::new(cache_root.clone()),
                stats.clone(),
                test_tls_inspection(directory.path()),
                vec![listener],
                true,
            )
            .unwrap();
            let request = format!("GET http://127.0.0.1:{origin_port}/update HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nRange: bytes=3-5\r\nConnection: close\r\n\r\n");
            for _ in 0..2 {
                let response = String::from_utf8(raw_http_exchange(port, &request).await).unwrap();
                assert!(response.starts_with("HTTP/1.1 206"));
                assert!(response.contains("content-range: bytes 3-5/9"));
                assert!(response.contains("accept-ranges: bytes"));
                assert!(response.ends_with("\r\n\r\ndef"));
                assert!(!response.contains("cache-status"));
            }
            assert_eq!(stats.snapshot().cache_hits, 0);
            assert!(
                !cache_root.exists() || std::fs::read_dir(cache_root).unwrap().next().is_none()
            );
            timeout(Duration::from_secs(2), origin)
                .await
                .unwrap()
                .unwrap();
            handle.stop().await;
        }
    }

    #[tokio::test]
    async fn ignored_range_gzip_200_never_populates_canonical_identity_cache() {
        const GZIP: &[u8] = &[
            31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 203, 76, 73, 205, 43, 201, 44, 169, 212, 77, 202,
            79, 169, 4, 0, 153, 113, 183, 214, 13, 0, 0, 0,
        ];
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin_port = origin_listener.local_addr().unwrap().port();
        let origin = tokio::spawn(async move {
            for ranged in [true, false] {
                let (mut stream, _) = origin_listener.accept().await.unwrap();
                let request = String::from_utf8(read_headers(&mut stream).await)
                    .unwrap()
                    .to_lowercase();
                let body = if ranged {
                    assert!(request.contains("range: bytes=0-2\r\n"));
                    assert!(request.contains("accept-encoding: gzip\r\n"));
                    GZIP
                } else {
                    assert!(!request.contains("range:"));
                    assert!(request.contains("accept-encoding: identity\r\n"));
                    b"identity-body"
                };
                let encoding = if ranged {
                    "Content-Encoding: gzip\r\n"
                } else {
                    ""
                };
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: public, max-age=300\r\nVary: Accept-Encoding\r\n{encoding}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let cache_root = directory.path().join("cache");
        let stats = Arc::new(Stats::default());
        let handle = spawn_proxy_with_listeners(
            Settings {
                cache_enabled: true,
                ..Settings::default()
            },
            CacheStore::new(cache_root.clone()),
            stats.clone(),
            test_tls_inspection(directory.path()),
            vec![listener],
            true,
        )
        .unwrap();
        let range = format!("GET http://127.0.0.1:{origin_port}/file HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nRange: bytes=0-2\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n");
        let response = raw_http_exchange(port, &range).await;
        let body_start = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
        assert!(String::from_utf8_lossy(&response[..body_start]).contains("content-encoding: gzip"));
        assert_eq!(&response[body_start..], GZIP);
        assert!(!cache_root.exists() || std::fs::read_dir(&cache_root).unwrap().next().is_none());
        let identity = format!("GET http://127.0.0.1:{origin_port}/file HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
        for expected_hits in [0, 1] {
            let response = String::from_utf8(raw_http_exchange(port, &identity).await).unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(response.ends_with("\r\n\r\nidentity-body"), "{response}");
            assert!(!response.contains("content-encoding:"), "{response}");
            assert_eq!(stats.snapshot().cache_hits, expected_hits);
        }
        timeout(Duration::from_secs(2), origin)
            .await
            .unwrap()
            .unwrap();
        handle.stop().await;
    }

    #[tokio::test]
    async fn safe_304_serves_verified_body_during_unrelated_read_lease_unless_invalidated() {
        for invalidation in ["none", "clear", "replace"] {
            let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let origin_port = origin_listener.local_addr().unwrap().port();
            let (validated_tx, validated_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let origin = tokio::spawn(async move {
                let (mut stream, _) = origin_listener.accept().await.unwrap();
                read_headers(&mut stream).await;
                stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\nETag: \"v1\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\nxyz").await.unwrap();
                drop(stream);
                let (mut stream, _) = origin_listener.accept().await.unwrap();
                let request = String::from_utf8(read_headers(&mut stream).await)
                    .unwrap()
                    .to_lowercase();
                assert!(request.contains("if-none-match: \"v1\"\r\n"));
                validated_tx.send(()).unwrap();
                release_rx.await.unwrap();
                stream.write_all(b"HTTP/1.1 304 Not Modified\r\nCache-Control: public, max-age=300\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n").await.unwrap();
            });
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let directory = tempfile::tempdir().unwrap();
            let cache = CacheStore::new(directory.path().join("cache"));
            let handle = spawn_proxy_with_listeners(
                Settings {
                    cache_enabled: true,
                    ..Settings::default()
                },
                cache.clone(),
                Arc::new(Stats::default()),
                test_tls_inspection(directory.path()),
                vec![listener],
                true,
            )
            .unwrap();
            let request = format!("GET http://127.0.0.1:{origin_port}/file HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n");
            assert!(String::from_utf8(raw_http_exchange(port, &request).await)
                .unwrap()
                .ends_with("xyz"));
            let metadata_path = std::fs::read_dir(cache.root())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "json")
                })
                .unwrap();
            let revalidated_key = metadata_path
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let mut metadata: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            metadata["stored_unix_seconds"] = (now - 120).into();
            metadata["expires_unix_seconds"] = (now - 60).into();
            let previous_metadata = serde_json::to_vec(&metadata).unwrap();
            std::fs::write(&metadata_path, &previous_metadata).unwrap();
            let held_key = "a".repeat(64);
            let mut headers = HeaderMap::new();
            headers.insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );
            headers.insert(CONTENT_LENGTH, HeaderValue::from_static("3"));
            cache
                .put(
                    &held_key,
                    StatusCode::OK,
                    &headers,
                    Bytes::from_static(b"abc"),
                    Duration::from_secs(60),
                    1024 * 1024,
                )
                .await
                .unwrap();
            let held_entry = cache.get(&held_key).await.unwrap();
            let request_task = tokio::spawn(async move { raw_http_exchange(port, &request).await });
            timeout(Duration::from_secs(3), validated_rx)
                .await
                .unwrap()
                .unwrap();
            match invalidation {
                "clear" => {
                    assert!(cache.clear().await.is_err());
                }
                "replace" => cache.invalidate_key(&revalidated_key),
                _ => {}
            }
            release_tx.send(()).unwrap();
            let response = String::from_utf8(request_task.await.unwrap()).unwrap();
            if invalidation == "none" {
                assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                assert!(response.ends_with("\r\n\r\nxyz"), "{response}");
                assert!(response.contains("age: 0\r\n"), "{response}");
                let refreshed: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
                let previous: serde_json::Value =
                    serde_json::from_slice(&previous_metadata).unwrap();
                assert_eq!(refreshed["body_sha256"], previous["body_sha256"]);
                assert!(
                    refreshed["expires_unix_seconds"].as_u64().unwrap()
                        > previous["expires_unix_seconds"].as_u64().unwrap()
                );
            } else {
                assert!(
                    response.starts_with("HTTP/1.1 502"),
                    "{invalidation}: {response}"
                );
                assert!(!response.ends_with("\r\n\r\nxyz"));
            }
            drop(held_entry);
            origin.await.unwrap();
            handle.stop().await;
        }
    }

    #[tokio::test]
    async fn unrelated_writer_before_or_during_304_keeps_conditional_validation_and_body() {
        for preexisting in [false, true] {
            let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let origin_port = origin_listener.local_addr().unwrap().port();
            let (validated_tx, validated_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let origin = tokio::spawn(async move {
                let (mut stream, _) = origin_listener.accept().await.unwrap();
                read_headers(&mut stream).await;
                stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\nETag: \"v1\"\r\nContent-Type: text/html\r\nContent-Length: 3\r\nConnection: close\r\n\r\nold").await.unwrap();
                drop(stream);
                let (mut stream, _) = origin_listener.accept().await.unwrap();
                let request = String::from_utf8(read_headers(&mut stream).await)
                    .unwrap()
                    .to_lowercase();
                assert!(request.contains("if-none-match: \"v1\"\r\n"));
                validated_tx.send(()).unwrap();
                release_rx.await.unwrap();
                assert!(request.starts_with("get /file?variant=public http/1.1\r\n"));
                assert!(request.contains(&format!("host: 127.0.0.1:{origin_port}\r\n")));
                assert!(request.contains("user-agent: browser-fixture\r\n"));
                assert!(request.contains("accept-encoding: gzip\r\n"));
                assert!(request.contains("sec-fetch-dest: document\r\n"));
                stream.write_all(b"HTTP/1.1 304 Not Modified\r\nCache-Control: public, max-age=300\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n").await.unwrap();
                drop(stream);
                assert!(timeout(Duration::from_millis(50), origin_listener.accept())
                    .await
                    .is_err());
            });
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let directory = tempfile::tempdir().unwrap();
            let cache = CacheStore::new(directory.path().join("cache"));
            let handle = spawn_proxy_with_listeners(
                Settings {
                    cache_enabled: true,
                    public_cache_endpoints: vec![crate::config::PublicCacheEndpoint {
                        host: "127.0.0.1".into(),
                        path_prefix: "/file".into(),
                    }],
                    ..Settings::default()
                },
                cache.clone(),
                Arc::new(Stats::default()),
                test_tls_inspection(directory.path()),
                vec![listener],
                true,
            )
            .unwrap();
            let request = format!("GET http://127.0.0.1:{origin_port}/file?variant=public HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nUser-Agent: browser-fixture\r\nAccept-Encoding: gzip\r\nSec-Fetch-Dest: document\r\nConnection: close\r\n\r\n");
            assert!(String::from_utf8(raw_http_exchange(port, &request).await)
                .unwrap()
                .ends_with("old"));
            let metadata_path = std::fs::read_dir(cache.root())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "json")
                })
                .unwrap();
            let mut metadata: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            metadata["stored_unix_seconds"] = (now - 120).into();
            metadata["expires_unix_seconds"] = (now - 60).into();
            std::fs::write(metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );
            headers.insert(CONTENT_LENGTH, HeaderValue::from_static("8"));
            let held_key = "a".repeat(64);
            let mut writer = None;
            if preexisting {
                writer = Some(
                    cache
                        .begin_fill(
                            cache.epoch(),
                            &held_key,
                            StatusCode::OK,
                            &headers,
                            8,
                            Duration::from_secs(60),
                            Instant::now(),
                            1024 * 1024,
                        )
                        .await
                        .unwrap()
                        .write(Bytes::from_static(b"a"))
                        .await
                        .unwrap(),
                );
            }
            let request_task = tokio::spawn(async move { raw_http_exchange(port, &request).await });
            timeout(Duration::from_secs(3), validated_rx)
                .await
                .unwrap()
                .unwrap();
            if !preexisting {
                writer = Some(
                    cache
                        .begin_fill(
                            cache.epoch(),
                            &held_key,
                            StatusCode::OK,
                            &headers,
                            8,
                            Duration::from_secs(60),
                            Instant::now(),
                            1024 * 1024,
                        )
                        .await
                        .unwrap()
                        .write(Bytes::from_static(b"a"))
                        .await
                        .unwrap(),
                );
            }
            release_tx.send(()).unwrap();
            let response = String::from_utf8(request_task.await.unwrap()).unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(response.ends_with("\r\n\r\nold"), "{response}");
            assert!(response.contains("HomeProxy; hit"), "{response}");
            drop(writer);
            origin.await.unwrap();
            handle.stop().await;
        }
    }

    #[tokio::test]
    async fn failed_cache_write_never_claims_that_the_response_was_stored() {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: public, max-age=60\r\nContent-Length: 6\r\nConnection: close\r\n\r\npublic",
                )
                .await
                .unwrap();
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let invalid_cache_root = directory.path().join("not-a-directory");
        std::fs::write(&invalid_cache_root, b"file").unwrap();
        let handle = spawn_proxy_with_listeners(
            Settings {
                cache_enabled: true,
                ..Settings::default()
            },
            CacheStore::new_with_recovery(invalid_cache_root, directory.path().join("recovery")),
            Arc::new(Stats::default()),
            test_tls_inspection(directory.path()),
            vec![proxy_listener],
            true,
        )
        .unwrap();

        let request = format!(
            "GET http://127.0.0.1:{upstream_port}/public HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
        );
        let response = raw_http_exchange(proxy_port, &request).await;
        assert!(String::from_utf8_lossy(&response)
            .contains("cache-status: HomeProxy; fwd=miss; store=error"));

        handle.stop().await;
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn inspected_https_uses_the_public_cache_and_rejects_cookie_responses() {
        inspected_https_cache_for_scope(crate::HttpsInspectionScope::SelectedHosts).await;
    }

    #[tokio::test]
    async fn all_supported_unlisted_https_uses_public_cache_and_preserves_privacy() {
        inspected_https_cache_for_scope(crate::HttpsInspectionScope::AllSupportedHosts).await;
    }

    async fn inspected_https_cache_for_scope(scope: crate::HttpsInspectionScope) {
        use rcgen::{CertificateParams, KeyPair};
        use rustls::{
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
            ClientConfig, RootCertStore, ServerConfig,
        };
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let origin_key = KeyPair::generate().unwrap();
        let origin_certificate = CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .self_signed(&origin_key)
            .unwrap();
        let origin_der = origin_certificate.der().clone();
        let origin_acceptor = TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![origin_der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(origin_key.serialize_der())),
                )
                .unwrap(),
        ));
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin_port = origin_listener.local_addr().unwrap().port();
        let origin_hits = Arc::new(AtomicUsize::new(0));
        let origin_counter = origin_hits.clone();
        let origin_requests = Arc::new(AtomicUsize::new(0));
        let request_counter = origin_requests.clone();
        let public_image = Arc::new(transformable_https_jpeg());
        let original_image_len = public_image.len() as u64;
        let origin_task = tokio::spawn(async move {
            loop {
                let (stream, _) = origin_listener.accept().await.unwrap();
                let acceptor = origin_acceptor.clone();
                let counter = origin_counter.clone();
                let request_counter = request_counter.clone();
                let public_image = public_image.clone();
                tokio::spawn(async move {
                    let mut stream = acceptor.accept(stream).await.unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                    loop {
                        let request = read_tls_headers(&mut stream).await;
                        request_counter.fetch_add(1, Ordering::SeqCst);
                        let contains = |needle: &[u8]| {
                            request.windows(needle.len()).any(|window| window == needle)
                        };
                        if contains(b"/reuse-one") {
                            stream
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: private\r\nContent-Length: 3\r\n\r\none",
                                )
                                .await
                                .unwrap();
                            continue;
                        }
                        if contains(b"/reuse-two") {
                            stream
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: private\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo",
                                )
                                .await
                                .unwrap();
                        } else if contains(b"/private") {
                            stream
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: public, max-age=60\r\nSet-Cookie: session=secret\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret",
                                )
                                .await
                                .unwrap();
                        } else {
                            stream
                                .write_all(
                                    format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nCache-Control: public, max-age=60\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                        public_image.len()
                                    )
                                    .as_bytes(),
                                )
                                .await
                                .unwrap();
                            stream.write_all(&public_image).await.unwrap();
                        }
                        break;
                    }
                    stream.shutdown().await.unwrap();
                });
            }
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let mut upstream_roots = RootCertStore::empty();
        upstream_roots.add(origin_der.clone()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let inspection = crate::tls_inspection::TlsInspection::for_tests(
            directory.path().join("inspection-authority.json"),
            upstream_roots,
        )
        .unwrap();
        let mut client_roots = RootCertStore::empty();
        client_roots.add(origin_der).unwrap();
        client_roots.add(inspection.root_certificate_der()).unwrap();
        let client = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(client_roots)
                .with_no_client_auth(),
        ));
        let root_certificate = inspection.root_certificate_der().as_ref().to_vec();
        let stats = Arc::new(Stats::default());
        let handle = spawn_proxy_with_listeners(
            Settings {
                https_mode: HttpsMode::Inspect,
                https_inspection_scope: scope,
                https_client_trust_acknowledged: true,
                https_inspect_hosts: if scope == crate::HttpsInspectionScope::SelectedHosts {
                    vec!["127.0.0.1".into(), "example.com".into()]
                } else {
                    vec!["example.com".into()]
                },
                cache_enabled: true,
                ..Settings::default()
            },
            CacheStore::new(directory.path().to_path_buf()),
            stats.clone(),
            inspection,
            vec![proxy_listener],
            true,
        )
        .unwrap();

        let ca_response = raw_http_exchange(
            proxy_port,
            "GET http://homeproxy.test/ca.cer HTTP/1.1\r\nHost: homeproxy.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            String::from_utf8_lossy(&ca_response).contains("content-type: application/pkix-cert")
        );
        assert!(ca_response.ends_with(&root_certificate));

        let first = https_exchange(&client, proxy_port, origin_port, "/public").await;
        let first_stats = stats.snapshot();
        assert_eq!(first_stats.origin_bytes, original_image_len);
        assert_eq!(first_stats.cache_misses, 1);
        assert_eq!(
            first_stats.compression_bytes_saved,
            original_image_len - first_stats.delivered_bytes
        );
        assert!(first_stats.delivered_bytes < original_image_len);
        let image_delivered = first_stats.delivered_bytes;
        let second = https_exchange(&client, proxy_port, origin_port, "/public").await;
        let hit_stats = stats.snapshot();
        assert_eq!(hit_stats.origin_bytes, original_image_len);
        assert_eq!(hit_stats.delivered_bytes, 2 * image_delivered);
        assert_eq!(hit_stats.cache_bytes_saved, image_delivered);
        assert!(
            String::from_utf8_lossy(&first).contains("cache-status: HomeProxy; fwd=miss; stored")
        );
        assert!(String::from_utf8_lossy(&second).contains("cache-status: HomeProxy; hit"));
        assert_eq!(origin_hits.load(Ordering::SeqCst), 1);

        let private_first = https_exchange(&client, proxy_port, origin_port, "/private").await;
        let private_second = https_exchange(&client, proxy_port, origin_port, "/private").await;
        assert!(String::from_utf8_lossy(&private_first).contains("secret"));
        assert!(!String::from_utf8_lossy(&private_first).contains("cache-status"));
        assert!(!String::from_utf8_lossy(&private_second).contains("cache-status"));
        assert_eq!(origin_hits.load(Ordering::SeqCst), 3);
        assert_eq!(origin_requests.load(Ordering::SeqCst), 3);

        let (reuse_one, reuse_two) =
            https_keepalive_exchange(&client, proxy_port, origin_port).await;
        assert!(String::from_utf8_lossy(&reuse_one).ends_with("one"));
        assert!(String::from_utf8_lossy(&reuse_two).ends_with("two"));
        assert_eq!(origin_hits.load(Ordering::SeqCst), 4);
        assert_eq!(origin_requests.load(Ordering::SeqCst), 5);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.cache_hits, 1);
        assert_eq!(snapshot.compressed_images, 1);
        assert!(snapshot.compression_bytes_saved > 0);
        assert_eq!(snapshot.origin_bytes, original_image_len + 18);
        assert_eq!(snapshot.delivered_bytes, 2 * image_delivered + 18);
        assert_eq!(snapshot.cache_bypasses, 4);
        assert_eq!(snapshot.cache_misses, 1);
        assert!(snapshot
            .activity
            .iter()
            .any(|entry| entry.cache_status == "MISS"));
        assert!(snapshot
            .activity
            .iter()
            .any(|entry| entry.cache_status == "HIT"));
        assert!(snapshot
            .activity
            .iter()
            .any(|entry| entry.cache_bypass_reason.as_deref() == Some("response-set-cookie")));
        assert!(snapshot
            .activity
            .iter()
            .any(|entry| entry.cache_bypass_reason.as_deref() == Some("response-private")));

        // Current Chrome/Firefox subresource requests carry fetch metadata such as
        // Sec-Fetch-Storage-Access and privacy hints; they must still use the cache.
        for browser_headers in [
            "Accept: image/avif,image/webp,image/apng,image/*,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: cs-CZ,cs;q=0.9\r\nUser-Agent: Mozilla/5.0 Chrome/154.0.0.0\r\nReferer: https://news.example/\r\nSec-Ch-Ua: \"Chromium\";v=\"154\"\r\nSec-Ch-Ua-Mobile: ?0\r\nSec-Ch-Ua-Platform: \"Linux\"\r\nSec-Fetch-Dest: image\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-Storage-Access: active\r\nPriority: i\r\n",
            "Accept: image/avif,image/webp,*/*\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: cs,en-US;q=0.7\r\nUser-Agent: Mozilla/5.0 Firefox/157.0\r\nReferer: https://news.example/\r\nDNT: 1\r\nSec-GPC: 1\r\nSec-Fetch-Dest: image\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-Storage-Access: active\r\nPriority: u=5, i\r\n",
        ] {
            let before = stats.snapshot();
            let path = if browser_headers.contains("Firefox") {
                "/firefox-asset"
            } else {
                "/chrome-asset"
            };
            let miss = https_exchange_with_headers(
                &client,
                proxy_port,
                origin_port,
                path,
                browser_headers,
            )
            .await;
            let hit = https_exchange_with_headers(
                &client,
                proxy_port,
                origin_port,
                path,
                browser_headers,
            )
            .await;
            assert!(
                String::from_utf8_lossy(&miss).contains("cache-status: HomeProxy; fwd=miss; stored"),
                "{}",
                String::from_utf8_lossy(&miss[..miss.len().min(600)])
            );
            assert!(String::from_utf8_lossy(&hit).contains("cache-status: HomeProxy; hit"));
            let after = stats.snapshot();
            assert_eq!(after.cache_misses, before.cache_misses + 1);
            assert_eq!(after.cache_hits, before.cache_hits + 1);
        }
        // A cookie still keeps the same request out of the shared cache.
        let cookie = https_exchange_with_headers(
            &client,
            proxy_port,
            origin_port,
            "/chrome-asset",
            "Sec-Fetch-Storage-Access: active\r\nCookie: sid=private\r\n",
        )
        .await;
        assert!(!String::from_utf8_lossy(&cookie).contains("cache-status: HomeProxy; hit"));

        origin_task.abort();
        let _ = origin_task.await;
        // An accepted TCP connection followed by a fatal TLS alert is deterministic
        // on Windows too; a closed port can spend seconds in OS connection retries.
        let rejected_origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let rejected_port = rejected_origin.local_addr().unwrap().port();
        let rejection = tokio::spawn(async move {
            let (mut stream, _) = rejected_origin.accept().await.unwrap();
            let mut header = [0u8; 5];
            stream.read_exact(&mut header).await.unwrap();
            let record_length = u16::from_be_bytes([header[3], header[4]]) as usize;
            assert!(record_length <= 16_384);
            stream
                .read_exact(&mut vec![0u8; record_length])
                .await
                .unwrap();
            stream.write_all(&[21, 3, 3, 0, 2, 2, 40]).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let failed = https_exchange(&client, proxy_port, rejected_port, "/failure").await;
        rejection.await.unwrap();
        assert!(String::from_utf8_lossy(&failed).contains("502"));
        assert_eq!(stats.snapshot().activity.last().unwrap().status, "error");
        handle.stop().await;
    }

    #[tokio::test]
    async fn rejected_inspection_fails_open_as_a_raw_tunnel_on_retry() {
        use rcgen::{CertificateParams, KeyPair};
        use rustls::{
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
            ClientConfig, RootCertStore, ServerConfig,
        };
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let origin_key = KeyPair::generate().unwrap();
        let origin_certificate = CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .self_signed(&origin_key)
            .unwrap();
        let origin_der = origin_certificate.der().clone();
        let origin_acceptor = TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![origin_der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(origin_key.serialize_der())),
                )
                .unwrap(),
        ));
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin_port = origin_listener.local_addr().unwrap().port();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin_listener.accept().await.unwrap();
            let mut stream = origin_acceptor.accept(stream).await.unwrap();
            for _ in 0..3 {
                let request = read_tls_headers(&mut stream).await;
                assert!(request
                    .windows(b"GET /chat".len())
                    .any(|part| part == b"GET /chat"));
                stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: private\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .await
                .unwrap();
            }
            let _ = stream.read_u8().await;
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let stats = Arc::new(Stats::default());
        let handle = spawn_proxy_with_listeners(
            Settings {
                https_mode: HttpsMode::Inspect,
                https_client_trust_acknowledged: true,
                https_inspect_hosts: vec!["127.0.0.1".into(), "example.com".into()],
                ..Settings::default()
            },
            CacheStore::new(directory.path().to_path_buf()),
            stats.clone(),
            test_tls_inspection(directory.path()),
            vec![proxy_listener],
            true,
        )
        .unwrap();

        let mut client_roots = RootCertStore::empty();
        client_roots.add(origin_der).unwrap();
        let pinned_client = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(client_roots)
                .with_no_client_auth(),
        ));

        let mut first = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .unwrap();
        first
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&read_headers(&mut first).await).starts_with("HTTP/1.1 200")
        );
        assert!(pinned_client
            .connect(
                rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                first,
            )
            .await
            .is_err());

        tokio::task::yield_now().await;
        let mut second = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .unwrap();
        second
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&read_headers(&mut second).await).starts_with("HTTP/1.1 200")
        );
        let mut second = pinned_client
            .connect(
                rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                second,
            )
            .await
            .unwrap();
        let mut previous_download = stats.snapshot().download_bytes;
        for cache_enabled in [false, true, false] {
            handle.set_cache_enabled(cache_enabled);
            second
            .write_all(
                format!(
                    "GET /chat HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let response = read_http_response(&mut second).await;
            assert!(response.ends_with(b"ok"));

            let live = stats.snapshot();
            assert!(live.download_bytes > previous_download);
            assert!(live.upload_bytes_per_second > 0 && live.download_bytes_per_second > 0);
            assert!(live.activity.last().unwrap().ended_unix_ms.is_none());
            previous_download = live.download_bytes;
        }

        handle.stop().await;
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn loopback_socks5_shares_the_proxy_port_and_relays_tcp() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let destination_port = destination_listener.local_addr().unwrap().port();
        let destination_task = tokio::spawn(async move {
            let (mut stream, _) = destination_listener.accept().await.unwrap();
            for _ in 0..3 {
                let mut payload = [0u8; 8];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"telegram");
                stream.write_all(b"connected").await.unwrap();
            }
            let mut eof = [0u8; 1];
            assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let stats = Arc::new(Stats::default());
        let handle = spawn_proxy_with_listeners(
            Settings::default(),
            CacheStore::new(directory.path().to_path_buf()),
            stats.clone(),
            test_tls_inspection(directory.path()),
            vec![proxy_listener],
            true,
        )
        .unwrap();

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        timeout(Duration::from_secs(2), client.read_exact(&mut method))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(method, [5, 0]);

        let [port_high, port_low] = destination_port.to_be_bytes();
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, port_high, port_low])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[0..2], [5, 0]);

        for enabled in [false, true, false] {
            handle.set_cache_enabled(enabled);
            client.write_all(b"telegram").await.unwrap();
            let mut response = [0u8; 9];
            timeout(Duration::from_secs(2), client.read_exact(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&response, b"connected");
            let live = stats.snapshot();
            assert!(live.upload_bytes >= 21 && live.download_bytes >= 21);
            assert!(live.upload_bytes_per_second > 0 && live.download_bytes_per_second > 0);
            assert_eq!(live.activity.len(), 1);
            assert!(live.activity[0].ended_unix_ms.is_none());
        }
        let live = stats.snapshot();
        assert_eq!(live.upload_bytes, 3 + 10 + 24);
        assert_eq!(live.download_bytes, 2 + 10 + 27);

        handle.stop().await;
        destination_task.await.unwrap();
    }

    #[tokio::test]
    async fn dedicated_socks5_listener_relays_tcp_and_rejects_udp() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let destination_port = destination_listener.local_addr().unwrap().port();
        let destination_task = tokio::spawn(async move {
            let (mut stream, _) = destination_listener.accept().await.unwrap();
            let mut payload = [0u8; 8];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"whatsapp");
            stream.write_all(b"connected").await.unwrap();
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let stats = Arc::new(Stats::default());
        let handle = spawn_proxy_with_bound_listeners(
            Settings {
                socks5_enabled: true,
                ..Settings::default()
            },
            CacheStore::new(directory.path().to_path_buf()),
            stats.clone(),
            test_tls_inspection(directory.path()),
            vec![BoundListener {
                listener: proxy_listener,
                protocol: ListenerProtocol::Socks5Dedicated,
            }],
            true,
        )
        .unwrap();

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let [port_high, port_low] = destination_port.to_be_bytes();
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, port_high, port_low])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0..2], [5, 0]);
        client.write_all(b"whatsapp").await.unwrap();
        let mut response = [0u8; 9];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"connected");

        for unsupported_command in [2, 3] {
            let mut unsupported_client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
                .await
                .unwrap();
            unsupported_client.write_all(&[5, 1, 0]).await.unwrap();
            unsupported_client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            unsupported_client
                .write_all(&[5, unsupported_command, 0, 1, 127, 0, 0, 1, 0, 53])
                .await
                .unwrap();
            unsupported_client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 7);
            assert_eq!(
                stats.snapshot().activity.last().unwrap().upload_bytes,
                13,
                "unsupported commands must consume the complete IPv4 request before REP=07"
            );
        }

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.socks5_connections, 1);
        assert_eq!(snapshot.cache_hits, 0);
        assert_eq!(snapshot.compressed_images, 0);
        assert_eq!(snapshot.compression_bytes_saved, 0);
        handle.stop().await;
        destination_task.await.unwrap();
    }

    #[test]
    fn dedicated_socks5_uses_lan_auth_and_the_shared_credentials() {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let remote = IpAddr::V4(Ipv4Addr::new(192, 168, 68, 81));
        let mut settings = Settings::default();

        assert_eq!(socks5_auth_method(loopback, &settings), 0);
        assert_eq!(socks5_auth_method(remote, &settings), 2);
        assert!(socks5_credentials_match(
            settings.proxy_username.as_bytes(),
            settings.proxy_password.as_bytes(),
            &settings,
        ));
        assert!(!socks5_credentials_match(
            b"wrong",
            settings.proxy_password.as_bytes(),
            &settings,
        ));
        assert!(!socks5_credentials_match(
            settings.proxy_username.as_bytes(),
            b"wrong",
            &settings,
        ));

        settings.lan_auth_enabled = false;
        assert_eq!(socks5_auth_method(remote, &settings), 0);
    }

    #[tokio::test]
    async fn socks5_username_password_subnegotiation_accepts_and_rejects_credentials() {
        async fn exchange(username: &[u8], password: &[u8]) -> ([u8; 2], bool) {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let settings = Settings {
                proxy_username: "domov".into(),
                proxy_password: "0123456789abcdef".into(),
                ..Settings::default()
            };
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                authenticate_socks5(&mut stream, &settings).await.is_ok()
            });
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            let mut request = vec![1, username.len() as u8];
            request.extend_from_slice(username);
            request.push(password.len() as u8);
            request.extend_from_slice(password);
            client.write_all(&request).await.unwrap();
            let mut response = [0u8; 2];
            client.read_exact(&mut response).await.unwrap();
            (response, server.await.unwrap())
        }

        let (accepted, accepted_result) = exchange(b"domov", b"0123456789abcdef").await;
        assert_eq!(accepted, [1, 0]);
        assert!(accepted_result);

        let (rejected, rejected_result) = exchange(b"domov", b"wrong-password").await;
        assert_eq!(rejected, [1, 1]);
        assert!(!rejected_result);
    }

    pub(super) fn transformable_https_jpeg() -> Vec<u8> {
        use image::{codecs::jpeg::JpegEncoder, DynamicImage, ImageBuffer, Rgb};

        let image = ImageBuffer::from_fn(800, 600, |x, y| {
            Rgb([
                ((x * 31 + y * 7) % 256) as u8,
                ((x * 13 + y * 29) % 256) as u8,
                ((x * 3 + y * 17) % 256) as u8,
            ])
        });
        let mut source = Vec::new();
        JpegEncoder::new_with_quality(&mut source, 100)
            .encode_image(&DynamicImage::ImageRgb8(image))
            .unwrap();
        source
    }

    pub(super) async fn https_exchange(
        connector: &tokio_rustls::TlsConnector,
        proxy_port: u16,
        origin_port: u16,
        path: &str,
    ) -> Vec<u8> {
        https_exchange_with_headers(connector, proxy_port, origin_port, path, "").await
    }

    pub(super) async fn https_exchange_with_headers(
        connector: &tokio_rustls::TlsConnector,
        proxy_port: u16,
        origin_port: u16,
        path: &str,
        extra_headers: &str,
    ) -> Vec<u8> {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let headers = read_headers(&mut stream).await;
        assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));
        let mut stream = connector
            .connect(
                rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                stream,
            )
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n{extra_headers}Connection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "fixture HTTPS response timed out: path={path}, received_bytes={}",
                    response.len()
                )
            })
            .unwrap();
        response
    }

    async fn https_keepalive_exchange(
        connector: &tokio_rustls::TlsConnector,
        proxy_port: u16,
        origin_port: u16,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let headers = read_headers(&mut stream).await;
        assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));
        let mut stream = connector
            .connect(
                rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                stream,
            )
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "GET /reuse-one HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: keep-alive\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let first = read_http_response(&mut stream).await;
        stream
            .write_all(
                format!(
                    "GET /reuse-two HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut second = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut second))
            .await
            .unwrap()
            .unwrap();
        (first, second)
    }

    async fn read_http_response<S>(stream: &mut S) -> Vec<u8>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut response = read_tls_headers(stream).await;
        let headers = String::from_utf8_lossy(&response).to_ascii_lowercase();
        let content_length = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap();
        let mut body = vec![0u8; content_length];
        timeout(Duration::from_secs(2), stream.read_exact(&mut body))
            .await
            .unwrap()
            .unwrap();
        response.extend_from_slice(&body);
        response
    }

    pub(super) async fn read_tls_headers<S>(stream: &mut S) -> Vec<u8>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut response = Vec::new();
        let mut byte = [0u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
                .await
                .unwrap()
                .unwrap();
            response.push(byte[0]);
        }
        response
    }

    pub(super) async fn raw_http_exchange(port: u16, request: &str) -> Vec<u8> {
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        response
    }

    async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
        let mut response = Vec::new();
        let mut byte = [0u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
                .await
                .unwrap()
                .unwrap();
            response.push(byte[0]);
        }
        response
    }
}

#[cfg(test)]
mod feedback_tests;

#[cfg(test)]
#[path = "proxy/image_savings_tests.rs"]
mod image_savings_tests;

#[cfg(test)]
#[path = "proxy/v1_tests.rs"]
mod v1_tests;

#[cfg(test)]
#[path = "proxy/service_port_tests.rs"]
mod service_port_tests;

#[cfg(test)]
#[path = "proxy/udp_tests.rs"]
mod udp_tests;

#[path = "proxy/udp.rs"]
mod udp;

#[cfg(test)]
#[path = "cache/offline_tests.rs"]
mod offline_tests;

#[cfg(test)]
#[path = "cache/profile_tests.rs"]
mod profile_tests;

#[cfg(test)]
#[path = "proxy/admission_tests.rs"]
mod admission_tests;

#[cfg(test)]
#[path = "proxy/resilience_tests.rs"]
mod resilience_tests;
