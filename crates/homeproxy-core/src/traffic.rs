use crate::{config::DeviceLimit, stats::Stats};
use std::{
    collections::HashMap,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::{sleep, Sleep},
};

pub(crate) struct Bucket {
    rate: u64,
    tokens: f64,
    updated: Instant,
}
impl Bucket {
    pub(crate) fn new(rate: u64) -> Self {
        Self {
            rate,
            tokens: Self::capacity(rate),
            updated: Instant::now(),
        }
    }
    fn capacity(rate: u64) -> f64 {
        (rate / 10).clamp(1, 16_384) as f64
    }
    fn set_rate(&mut self, rate: u64) {
        if self.rate != rate {
            self.refill();
            self.rate = rate;
            self.tokens = self.tokens.min(Self::capacity(rate));
        }
    }
    fn refill(&mut self) {
        let now = Instant::now();
        self.tokens = (self.tokens
            + now.duration_since(self.updated).as_secs_f64() * self.rate as f64)
            .min(Self::capacity(self.rate));
        self.updated = now;
    }
}
pub(crate) type Buckets = Arc<Mutex<(Bucket, Bucket)>>;
#[derive(Clone, Default)]
pub(crate) struct BandwidthLimits {
    peers: Arc<HashMap<IpAddr, Buckets>>,
}
impl BandwidthLimits {
    // Reserve a packet progressively: packets may exceed the bucket's 16 KiB burst.
    // The caller owns cancellation and keeps at most one pending packet per direction.
    pub async fn reserve_datagram(&self, peer: IpAddr, upload: bool, mut bytes: usize) {
        let Some(buckets) = self.peers.get(&peer) else {
            return;
        };
        while bytes > 0 {
            let delay = {
                let mut guard = buckets.lock().unwrap_or_else(|e| e.into_inner());
                let bucket = if upload { &mut guard.0 } else { &mut guard.1 };
                if bucket.rate == 0 {
                    return;
                }
                bucket.refill();
                let taken = bytes.min(bucket.tokens as usize);
                bucket.tokens -= taken as f64;
                bytes -= taken;
                Duration::from_secs_f64(((1.0 - bucket.tokens) / bucket.rate as f64).max(0.001))
            };
            if bytes > 0 {
                sleep(delay).await;
            }
        }
    }
    pub fn new(limits: &[DeviceLimit]) -> Self {
        Self {
            peers: Arc::new(
                limits
                    .iter()
                    .map(|limit| {
                        (
                            IpAddr::V4(limit.ip),
                            Arc::new(Mutex::new((
                                Bucket::new(limit.upload_bytes_per_second),
                                Bucket::new(limit.download_bytes_per_second),
                            ))),
                        )
                    })
                    .collect(),
            ),
        }
    }
}
pub(crate) struct MeteredStream {
    stream: TcpStream,
    stats: Arc<Stats>,
    peer: IpAddr,
    id: u64,
    buckets: Option<Buckets>,
    read_wait: Option<Pin<Box<Sleep>>>,
    write_wait: Option<Pin<Box<Sleep>>>,
    external_success_on_write: bool,
    read_credit_wait: Option<Pin<Box<Sleep>>>,
    write_credit_wait: Option<Pin<Box<Sleep>>>,
}
impl MeteredStream {
    pub fn verify_external_on_payload(&mut self, external: bool) {
        self.external_success_on_write = external;
    }
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.stream.local_addr()
    }
    // UDP control lifetime must remain observable when the data bucket is exhausted.
    pub async fn udp_control_closed(&mut self) -> std::io::Result<()> {
        let mut byte = [0; 1];
        let n = tokio::io::AsyncReadExt::read(&mut self.stream, &mut byte).await?;
        if n > 0 {
            self.stats.traffic(self.peer, self.id, n as u64, 0);
        }
        Ok(())
    }
    pub fn new(
        stream: TcpStream,
        stats: Arc<Stats>,
        peer: IpAddr,
        id: u64,
        limits: &BandwidthLimits,
    ) -> Self {
        Self {
            stream,
            stats,
            peer,
            id,
            buckets: limits.peers.get(&peer).cloned(),
            read_wait: None,
            write_wait: None,
            external_success_on_write: false,
            read_credit_wait: None,
            write_credit_wait: None,
        }
    }
}
fn allowance(
    bucket: &mut Bucket,
    wait: &mut Option<Pin<Box<Sleep>>>,
    cx: &mut Context<'_>,
) -> Poll<usize> {
    if bucket.rate == 0 {
        return Poll::Ready(16_384);
    }
    if let Some(timer) = wait.as_mut() {
        if timer.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
    }
    *wait = None;
    bucket.refill();
    if bucket.tokens >= 1.0 {
        return Poll::Ready(bucket.tokens as usize);
    }
    let delay = Duration::from_secs_f64(((1.0 - bucket.tokens) / bucket.rate as f64).max(0.001));
    let mut timer = Box::pin(sleep(delay));
    let _ = timer.as_mut().poll(cx);
    *wait = Some(timer);
    Poll::Pending
}
fn poll_credit_wait(wait: &mut Option<Pin<Box<Sleep>>>, cx: &mut Context<'_>) -> Poll<()> {
    if let Some(timer) = wait.as_mut() {
        if timer.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
    }
    *wait = None;
    Poll::Ready(())
}
fn start_credit_wait(wait: &mut Option<Pin<Box<Sleep>>>, cx: &mut Context<'_>) {
    let mut timer = Box::pin(sleep(Duration::from_millis(2)));
    let _ = timer.as_mut().poll(cx);
    *wait = Some(timer);
}
impl AsyncRead for MeteredStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if poll_credit_wait(&mut this.read_credit_wait, cx).is_pending() {
            return Poll::Pending;
        }
        let context = match this.stats.transfer_context(this.id, this.peer) {
            Ok(context) => context,
            Err(error) => {
                this.stats.activity_error(this.id, "policy-transfer-denied");
                return Poll::Ready(Err(error));
            }
        };
        let profile_buckets = match context
            .as_ref()
            .and_then(|c| c.profile_id.as_deref().map(|id| (id, &c.decision)))
        {
            Some((id, decision)) => match this.stats.profile_bandwidth(
                id,
                decision.upload_bytes_per_second,
                decision.download_bytes_per_second,
            ) {
                Ok(b) => Some(b),
                Err(error) => return Poll::Ready(Err(error)),
            },
            None => None,
        };
        let buckets = this.buckets.clone();
        let mut peer_guard = buckets
            .as_ref()
            .map(|b| b.lock().unwrap_or_else(|e| e.into_inner()));
        let mut profile_guard = profile_buckets
            .as_ref()
            .map(|b| b.lock().unwrap_or_else(|e| e.into_inner()));
        let mut allowed = 16_384usize.min(buffer.remaining());
        if let Some(b) = peer_guard.as_mut() {
            match allowance(&mut b.0, &mut this.read_wait, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(n) => allowed = allowed.min(n),
            }
        }
        if let Some(b) = profile_guard.as_mut() {
            b.0.set_rate(context.as_ref().unwrap().decision.upload_bytes_per_second);
            match allowance(&mut b.0, &mut this.read_wait, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(n) => allowed = allowed.min(n),
            }
        }
        let reservation = match this
            .stats
            .reserve_transfer(this.id, this.peer, allowed as u64)
        {
            Ok(reservation) => reservation,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                start_credit_wait(&mut this.read_credit_wait, cx);
                return Poll::Pending;
            }
            Err(error) => return Poll::Ready(Err(error)),
        };
        if let Some(reservation) = reservation.as_ref() {
            allowed = allowed.min(reservation.bytes() as usize);
        }
        let mut bytes = [0u8; 16_384];
        let mut limited = ReadBuf::new(&mut bytes[..allowed]);
        match Pin::new(&mut this.stream).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let n = limited.filled().len();
                for b in [&mut peer_guard, &mut profile_guard].into_iter().flatten() {
                    if b.0.rate != 0 {
                        b.0.tokens -= n as f64;
                    }
                }
                drop(peer_guard);
                drop(profile_guard);
                buffer.put_slice(limited.filled());
                let accounted = reservation.is_some();
                if let Some(reservation) = reservation {
                    if let Err(error) = reservation.settle(n as u64, 0) {
                        return Poll::Ready(Err(std::io::Error::other(error.to_string())));
                    }
                }
                if n > 0 {
                    if accounted {
                        this.stats
                            .traffic_accounted(this.peer, this.id, n as u64, 0);
                    } else {
                        this.stats.traffic(this.peer, this.id, n as u64, 0);
                    }
                }
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}
impl AsyncWrite for MeteredStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if poll_credit_wait(&mut this.write_credit_wait, cx).is_pending() {
            return Poll::Pending;
        }
        let context = match this.stats.transfer_context(this.id, this.peer) {
            Ok(context) => context,
            Err(error) => {
                this.stats.activity_error(this.id, "policy-transfer-denied");
                return Poll::Ready(Err(error));
            }
        };
        let profile_buckets = match context
            .as_ref()
            .and_then(|c| c.profile_id.as_deref().map(|id| (id, &c.decision)))
        {
            Some((id, decision)) => match this.stats.profile_bandwidth(
                id,
                decision.upload_bytes_per_second,
                decision.download_bytes_per_second,
            ) {
                Ok(b) => Some(b),
                Err(error) => return Poll::Ready(Err(error)),
            },
            None => None,
        };
        let buckets = this.buckets.clone();
        let mut peer_guard = buckets
            .as_ref()
            .map(|b| b.lock().unwrap_or_else(|e| e.into_inner()));
        let mut profile_guard = profile_buckets
            .as_ref()
            .map(|b| b.lock().unwrap_or_else(|e| e.into_inner()));
        let mut allowed = 16_384usize.min(buffer.len());
        if let Some(b) = peer_guard.as_mut() {
            match allowance(&mut b.1, &mut this.write_wait, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(n) => allowed = allowed.min(n),
            }
        }
        if let Some(b) = profile_guard.as_mut() {
            b.1.set_rate(context.as_ref().unwrap().decision.download_bytes_per_second);
            match allowance(&mut b.1, &mut this.write_wait, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(n) => allowed = allowed.min(n),
            }
        }
        let reservation = match this
            .stats
            .reserve_transfer(this.id, this.peer, allowed as u64)
        {
            Ok(reservation) => reservation,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                start_credit_wait(&mut this.write_credit_wait, cx);
                return Poll::Pending;
            }
            Err(error) => return Poll::Ready(Err(error)),
        };
        if let Some(reservation) = reservation.as_ref() {
            allowed = allowed.min(reservation.bytes() as usize);
        }
        match Pin::new(&mut this.stream).poll_write(cx, &buffer[..allowed]) {
            Poll::Ready(Ok(n)) => {
                for b in [&mut peer_guard, &mut profile_guard].into_iter().flatten() {
                    if b.1.rate != 0 {
                        b.1.tokens -= n as f64;
                    }
                }
                drop(peer_guard);
                drop(profile_guard);
                let accounted = reservation.is_some();
                if let Some(reservation) = reservation {
                    if let Err(error) = reservation.settle(0, n as u64) {
                        return Poll::Ready(Err(std::io::Error::other(error.to_string())));
                    }
                }
                if n > 0 {
                    if accounted {
                        this.stats
                            .traffic_accounted(this.peer, this.id, 0, n as u64);
                    } else {
                        this.stats.traffic(this.peer, this.id, 0, n as u64);
                    }
                    if this.external_success_on_write {
                        this.stats.successful_external_request();
                        this.external_success_on_write = false;
                    }
                }
                Poll::Ready(Ok(n))
            }
            result => result,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
impl Drop for MeteredStream {
    fn drop(&mut self) {
        self.stats.finish_activity(self.id, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };
    async fn pair(
        stats: Arc<Stats>,
        limits: &BandwidthLimits,
        peer: IpAddr,
    ) -> (MeteredStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let id = stats.begin_activity(peer, "127.0.0.1".parse().unwrap());
        (MeteredStream::new(stream, stats, peer, id, limits), remote)
    }
    #[tokio::test]
    async fn simultaneous_flows_share_peer_budget_in_both_directions_and_other_peer_is_independent()
    {
        let stats = Arc::new(Stats::default());
        let limits = BandwidthLimits::new(&[DeviceLimit {
            ip: "192.168.1.2".parse().unwrap(),
            upload_bytes_per_second: 1000,
            download_bytes_per_second: 1000,
        }]);
        let peer = "192.168.1.2".parse().unwrap();
        let (mut a, mut ar) = pair(stats.clone(), &limits, peer).await;
        let (mut b, mut br) = pair(stats.clone(), &limits, peer).await;
        let (mut independent, mut ir) =
            pair(stats.clone(), &limits, "192.168.1.3".parse().unwrap()).await;
        let started = Instant::now();
        let first = tokio::spawn(async move {
            a.write_all(&[0; 1000]).await.unwrap();
            ar.write_all(&[0; 1000]).await.unwrap();
            let mut bytes = [0; 1000];
            a.read_exact(&mut bytes).await.unwrap();
            (a, ar)
        });
        let second = tokio::spawn(async move {
            b.write_all(&[0; 1000]).await.unwrap();
            br.write_all(&[0; 1000]).await.unwrap();
            let mut bytes = [0; 1000];
            b.read_exact(&mut bytes).await.unwrap();
            (b, br)
        });
        timeout(Duration::from_millis(200), async {
            independent.write_all(&[0; 2000]).await.unwrap();
            ir.write_all(&[0; 2000]).await.unwrap();
            independent.read_exact(&mut [0; 2000]).await.unwrap();
        })
        .await
        .expect("unlimited peer must not wait for limited peer");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let live = stats.snapshot();
        assert!(live.download_bytes > 2000);
        assert!(live.download_bytes_per_second > 0);
        assert!(live.activity.iter().all(|a| a.ended_unix_ms.is_none()));
        let (_a, _b) = timeout(Duration::from_secs(8), async {
            (first.await.unwrap(), second.await.unwrap())
        })
        .await
        .unwrap();
        assert!(
            started.elapsed() >= Duration::from_millis(1800),
            "two streams must not each get full peer quota"
        );
        let snapshot = stats.snapshot();
        assert_eq!(
            (snapshot.upload_bytes, snapshot.download_bytes),
            (4000, 4000)
        );
    }
}

/// UDP shares the same authenticated profile buckets as TCP. Recheck schedules
/// on every refill; the caller must still reserve the legacy per-IP datagram rate.
pub(crate) async fn reserve_profile_datagram(
    stats: &Stats,
    id: u64,
    peer: IpAddr,
    upload: bool,
    bytes: usize,
) -> std::io::Result<Option<crate::usage_history::QuotaReservation>> {
    let mut remaining = bytes;
    while remaining > 0 {
        let Some(context) = stats.transfer_context(id, peer)? else {
            break;
        };
        let Some(profile_id) = context.profile_id.as_deref() else {
            break;
        };
        let rate = if upload {
            context.decision.upload_bytes_per_second
        } else {
            context.decision.download_bytes_per_second
        };
        if rate == 0 {
            break;
        }
        let buckets = stats.profile_bandwidth(
            profile_id,
            context.decision.upload_bytes_per_second,
            context.decision.download_bytes_per_second,
        )?;
        let delay = {
            let mut guard = buckets
                .lock()
                .map_err(|_| std::io::Error::other("bandwidth-state-unavailable"))?;
            let bucket = if upload { &mut guard.0 } else { &mut guard.1 };
            bucket.set_rate(rate);
            bucket.refill();
            let taken = remaining.min(bucket.tokens as usize);
            bucket.tokens -= taken as f64;
            remaining -= taken;
            Duration::from_secs_f64(((1.0 - bucket.tokens) / rate as f64).max(0.001))
        };
        if remaining > 0 {
            sleep(delay).await;
        }
    }
    let reservation = loop {
        match stats.reserve_transfer(id, peer, bytes as u64) {
            Ok(reservation) => break reservation,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                sleep(Duration::from_millis(2)).await
            }
            Err(error) => return Err(error),
        }
    };
    if reservation
        .as_ref()
        .is_some_and(|reservation| reservation.bytes() < bytes as u64)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "quota-datagram-too-large",
        ));
    }
    Ok(reservation)
}

#[cfg(test)]
mod profile_runtime_tests {
    use super::*;
    use crate::{
        config::Settings,
        policy::{DeviceProfile, ScheduleAction, ScheduleWindow},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };
    fn settings() -> Settings {
        Settings { device_profiles: vec![serde_json::from_value::<DeviceProfile>(serde_json::json!({"id":"tv","name":"TV","username":"television","password":"0123456789abcdef","ips":["192.168.1.20"],"dailyQuotaMib":1})).unwrap()], ..Default::default() }
    }
    async fn pair(stats: Arc<Stats>, peer: IpAddr) -> (MeteredStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let id = stats.begin_activity(peer, "127.0.0.1".parse().unwrap());
        stats.bind_principal(id, peer, Some("television")).unwrap();
        (
            MeteredStream::new(stream, stats, peer, id, &BandwidthLimits::default()),
            remote,
        )
    }
    fn total(stats: &Stats) -> u64 {
        stats
            .history_report()
            .unwrap()
            .months
            .iter()
            .map(|r| r.counters.upload_bytes + r.counters.download_bytes)
            .sum()
    }
    #[tokio::test]
    async fn actual_socket_quota_never_sends_extra_byte_and_restart_keeps_usage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        let stats = Arc::new(Stats::default());
        stats.configure_history(path.clone(), &settings()).unwrap();
        let (mut stream, mut remote) = pair(stats.clone(), "192.168.1.99".parse().unwrap()).await;
        let drain = tokio::spawn(async move {
            let mut data = Vec::new();
            remote.read_to_end(&mut data).await.unwrap();
            data.len()
        });
        let error = stream
            .write_all(&vec![0; 1024 * 1024 + 1])
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        drop(stream);
        assert_eq!(drain.await.unwrap(), 1024 * 1024);
        assert_eq!(total(&stats), 1024 * 1024);
        stats.checkpoint_history().unwrap();
        let history = crate::usage_history::UsageHistory::open(path, 90);
        assert_eq!(history.report().months[0].identity, "profile:tv");
        assert_eq!(
            history.report().months[0].counters.download_bytes,
            1024 * 1024
        );
    }
    #[tokio::test]
    async fn pending_reads_refund_and_changed_schedule_stops_existing_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        let stats = Arc::new(Stats::default());
        let mut settings = settings();
        stats.configure_history(path.clone(), &settings).unwrap();
        let (mut stream, _remote) = pair(stats.clone(), "192.168.1.20".parse().unwrap()).await;
        assert!(timeout(Duration::from_millis(30), stream.read_u8())
            .await
            .is_err());
        assert_eq!(total(&stats), 0);
        let now = time::OffsetDateTime::now_utc();
        let minute = u16::from(now.hour()) * 60 + u16::from(now.minute());
        settings.device_profiles[0].schedules = vec![ScheduleWindow {
            days: vec![now.weekday().number_from_monday()],
            start_minute: minute,
            end_minute: (minute + 60) % 1440,
            action: ScheduleAction::Deny,
            upload_bytes_per_second: 0,
            download_bytes_per_second: 0,
        }];
        stats.configure_history(path, &settings).unwrap();
        assert_eq!(
            stream.write_all(b"blocked").await.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(total(&stats), 0);
    }
    #[tokio::test]
    async fn authenticated_flows_on_different_ips_share_rate_bucket_and_retention_preserves_connection(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        let stats = Arc::new(Stats::default());
        let mut settings = settings();
        settings.device_profiles[0].download_bytes_per_second = 1000;
        stats.configure_history(path.clone(), &settings).unwrap();
        let (mut a, _ar) = pair(stats.clone(), "192.168.1.20".parse().unwrap()).await;
        let (mut b, _br) = pair(stats.clone(), "192.168.1.21".parse().unwrap()).await;
        let started = Instant::now();
        let first = tokio::spawn(async move {
            a.write_all(&vec![0; 500]).await.unwrap();
            a
        });
        let second = tokio::spawn(async move {
            b.write_all(&vec![0; 500]).await.unwrap();
            b
        });
        settings.history_retention_days = 1;
        stats.configure_history(path, &settings).unwrap();
        let (_a, _b) = timeout(Duration::from_secs(3), async {
            (first.await.unwrap(), second.await.unwrap())
        })
        .await
        .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(800));
        assert_eq!(total(&stats), 1000);
        assert_eq!(stats.history_report().unwrap().retention_days, 1);
    }
    #[tokio::test]
    async fn deny_destination_still_allows_local_response_but_udp_partial_quota_is_refunded() {
        let dir = tempfile::tempdir().unwrap();
        let stats = Arc::new(Stats::default());
        let mut settings = settings();
        settings.block_domains = vec!["blocked.test".into()];
        stats
            .configure_history(dir.path().join("history.json"), &settings)
            .unwrap();
        let (mut stream, mut remote) = pair(stats.clone(), "192.168.1.20".parse().unwrap()).await;
        stats.describe_activity(stream.id, "blocked.test", "HTTP");
        assert!(!stats.policy_decision(stream.id, "blocked.test").allowed);
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await
            .unwrap();
        let mut bytes = vec![0; 26];
        remote.read_exact(&mut bytes).await.unwrap();
        let context = stats
            .transfer_context(stream.id, stream.peer)
            .unwrap()
            .unwrap();
        context
            .history
            .record(
                "profile:tv",
                context.timestamp,
                crate::usage_history::UsageCounters {
                    download_bytes: 1024 * 1024 - 26 - 5,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(stats
            .reserve_datagram(stream.id, stream.peer, false, 10)
            .await
            .is_err());
        let reservation = stats
            .reserve_transfer(stream.id, stream.peer, 5)
            .unwrap()
            .unwrap();
        assert_eq!(reservation.bytes(), 5);
    }
}
