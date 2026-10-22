//! A bounded RFC 1928 association. Payloads are opaque and never cached or inspected.
use super::*;
use std::net::{Ipv6Addr, SocketAddrV6};
use tokio::net::UdpSocket;

// Retained tun2socks DNS flows share this finite budget. Keep headroom below
// the general TCP limits (256 total / 128 per peer) for ordinary connections.
pub(super) const MAX_ASSOCIATIONS: usize = 128;
pub(super) const MAX_PER_PEER: usize = 64;
const MAX_ENDPOINTS: usize = 32;
const ENDPOINT_TTL: Duration = Duration::from_secs(60);
const MAX_PAYLOAD: usize = 65_000; // Leaves room for the largest SOCKS domain header.
const MAX_FRAME: usize = MAX_PAYLOAD + 262;

pub(super) fn association_limiter() -> ConnectionLimiter {
    ConnectionLimiter {
        global: Arc::new(Semaphore::new(MAX_ASSOCIATIONS)),
        max_per_peer: MAX_PER_PEER,
        per_peer: Arc::default(),
    }
}

struct Datagram<'a> {
    host: String,
    port: u16,
    payload: &'a [u8],
}
fn parse(bytes: &[u8]) -> Option<Datagram<'_>> {
    if bytes.len() > MAX_FRAME || bytes.get(..3)? != [0, 0, 0] {
        return None;
    }
    let (host, end) = match *bytes.get(3)? {
        1 => (
            Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(4..8)?).ok()?).to_string(),
            8,
        ),
        4 => (
            Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(4..20)?).ok()?).to_string(),
            20,
        ),
        3 => {
            let end = 5 + *bytes.get(4)? as usize;
            let host = std::str::from_utf8(bytes.get(5..end)?).ok()?;
            if !crate::dns::valid_host(host) {
                return None;
            }
            (host.to_owned(), end)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(bytes.get(end..end + 2)?.try_into().ok()?);
    let payload = bytes.get(end + 2..)?;
    if port == 0 || payload.len() > MAX_PAYLOAD {
        return None;
    }
    Some(Datagram {
        host,
        port,
        payload,
    })
}
fn header(address: SocketAddr) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0];
    match address.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    bytes.extend_from_slice(&address.port().to_be_bytes());
    bytes
}
#[derive(Default)]
struct Endpoints(Vec<(SocketAddr, SocketAddr, Instant)>);
impl Endpoints {
    fn expire(&mut self, now: Instant) {
        self.0
            .retain(|entry| now.duration_since(entry.2) < ENDPOINT_TTL);
    }
    fn has_capacity(&mut self, actual: SocketAddr, now: Instant) -> bool {
        self.expire(now);
        self.0.len() < MAX_ENDPOINTS || self.0.iter().any(|entry| entry.0 == actual)
    }
    fn contact(&mut self, actual: SocketAddr, public: SocketAddr, now: Instant) {
        if !self.has_capacity(actual, now) {
            return;
        }
        self.0.retain(|entry| entry.0 != actual);
        self.0.push((actual, public, now));
    }
    fn source(&mut self, actual: SocketAddr, now: Instant) -> Option<SocketAddr> {
        self.expire(now);
        self.0
            .iter()
            .find(|entry| entry.0 == actual)
            .map(|entry| entry.1)
    }
}

async fn send_datagram(
    v4: &UdpSocket,
    v6: Option<&UdpSocket>,
    addresses: &[SocketAddr],
    resolver: &Resolver,
    payload: &[u8],
    endpoints: &StdMutex<Endpoints>,
) -> Result<(), &'static str> {
    if addresses.is_empty() || addresses.iter().any(|a| !destination_is_public(a.ip())) {
        return Err("socks5-udp-destination-denied");
    }
    let mut failure = "socks5-udp-send-failed";
    for &target in addresses {
        #[cfg(test)]
        let actual = resolver.test_datagram_target(target);
        #[cfg(not(test))]
        let actual = {
            let _ = resolver;
            target
        };
        let socket = if actual.is_ipv4() {
            v4
        } else if let Some(socket) = v6 {
            socket
        } else {
            continue;
        };
        if !endpoints
            .lock()
            .unwrap()
            .has_capacity(actual, Instant::now())
        {
            failure = "socks5-udp-endpoint-limit";
            continue;
        }
        // Only a definite local send error allows another candidate. A successful
        // UDP send is final even if the remote endpoint never answers.
        if socket.send_to(payload, actual).await.is_ok() {
            endpoints
                .lock()
                .unwrap()
                .contact(actual, target, Instant::now());
            return Ok(());
        }
    }
    Err(failure)
}

async fn receive_datagram(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    #[cfg(not(windows))]
    {
        socket.recv_from(buffer).await
    }
    #[cfg(windows)]
    loop {
        match socket.recv_from(buffer).await {
            Err(error) if error.raw_os_error() == Some(10054) => {
                // Winsock reports an ICMP port-unreachable from a prior UDP send
                // as WSAECONNRESET. The unconnected socket remains usable. Bound
                // repeated errors without starving the enclosing EOF/Stop select.
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            result => return result,
        }
    }
}

pub(super) async fn associate(
    mut control: MeteredStream,
    peer: SocketAddr,
    context: &ProxyContext,
    hint: &str,
    port: u16,
    external: bool,
) -> Result<(), ProxyError> {
    ensure_online(context)?;
    if !context.settings.upstream_proxies.is_empty() {
        write_socks5_reply(&mut control, 7, None).await?;
        return Err(ProxyError::Forbidden("socks5-udp-upstream-unsupported"));
    }
    // Do not resolve a client-supplied association hint: it must identify this TCP peer.
    let valid_hint = hint
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_unspecified() || ip == peer.ip());
    if !valid_hint {
        write_socks5_reply(&mut control, 2, None).await?;
        return Err(ProxyError::Forbidden("socks5-udp-client-mismatch"));
    }
    let _permit = match context.udp_associations.try_acquire(peer.ip()) {
        Ok(permit) => permit,
        Err(_) => {
            write_socks5_reply(&mut control, 1, None).await?;
            return Err(ProxyError::Forbidden("socks5-udp-association-limit"));
        }
    };
    let client = UdpSocket::bind(SocketAddr::new(control.local_addr()?.ip(), 0)).await?;
    let v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    // IPv6 can be unavailable on the host. IPv4 associations still work in that case.
    let v6 = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        .await
        .ok();
    write_socks5_reply(&mut control, 0, Some(client.local_addr()?)).await?;
    context
        .stats
        .describe_activity(context.activity_id, "", "SOCKS5 UDP");
    context.stats.socks5_connection();
    if external {
        context.stats.client_seen(peer.ip());
    }
    let pinned = StdMutex::new((port != 0).then_some(SocketAddr::new(peer.ip(), port)));
    let endpoints = StdMutex::new(Endpoints::default());
    let upload = async {
        let mut buffer = vec![0; 65_536];
        loop {
            let (n, source) = receive_datagram(&client, &mut buffer).await?;
            if source.ip() != peer.ip() || pinned.lock().unwrap().is_some_and(|p| p != source) {
                continue;
            }
            let Some(packet) = parse(&buffer[..n]) else {
                context
                    .stats
                    .traffic(peer.ip(), context.activity_id, n as u64, 0);
                continue;
            };
            // Pin only after a complete, well-formed frame, never on malformed noise.
            *pinned.lock().unwrap() = Some(source);
            context.bandwidth.reserve_datagram(peer.ip(), true, n).await;
            if let Err(error) =
                enforce_runtime_policy(context, &packet.host, context.settings.adblock_mode)
                    .and_then(|_| {
                        enforce_host_policy(&packet.host, AdblockMode::Off, &context.stats, false)
                    })
            {
                context
                    .stats
                    .traffic(peer.ip(), context.activity_id, n as u64, 0);
                context
                    .stats
                    .activity_error(context.activity_id, error.user_message());
                continue;
            }
            let reservation = match context
                .stats
                .reserve_datagram(context.activity_id, peer.ip(), true, n)
                .await
            {
                Ok(reservation) => reservation,
                Err(error) => {
                    context
                        .stats
                        .activity_error(context.activity_id, "socks5-udp-quota-or-schedule");
                    return Err(error);
                }
            };
            // Admission accounts bytes actually accepted from the client, even if origin send fails.
            if let Some(reservation) = reservation {
                reservation
                    .settle(n as u64, 0)
                    .map_err(std::io::Error::other)?;
                context
                    .stats
                    .traffic_accounted(peer.ip(), context.activity_id, n as u64, 0);
            } else {
                context
                    .stats
                    .traffic(peer.ip(), context.activity_id, n as u64, 0);
            }
            let addresses = match context.resolver.resolve(&packet.host, packet.port).await {
                Ok(addresses)
                    if !addresses.is_empty()
                        && addresses.iter().all(|a| destination_is_public(a.ip())) =>
                {
                    addresses
                }
                _ => {
                    context
                        .stats
                        .activity_error(context.activity_id, "socks5-udp-destination-denied");
                    continue;
                }
            };
            context
                .stats
                .describe_activity(context.activity_id, &packet.host, "SOCKS5 UDP");
            if let Err(reason) = send_datagram(
                &v4,
                v6.as_ref(),
                &addresses,
                &context.resolver,
                packet.payload,
                &endpoints,
            )
            .await
            {
                context.stats.activity_error(context.activity_id, reason);
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };
    let download = async {
        let mut verified = false;
        let mut buffer4 = vec![0; 65_536];
        let mut buffer6 = vec![0; 65_536];
        loop {
            let (n, source, ipv6) = tokio::select! {
                result = receive_datagram(&v4, &mut buffer4) => { let (n, a) = result?; (n, a, false) },
                result = async { match &v6 { Some(s) => receive_datagram(s, &mut buffer6).await, None => std::future::pending().await } } => { let (n,a) = result?; (n,a,true) },
            };
            if n > MAX_PAYLOAD {
                continue;
            }
            let Some(public) = endpoints.lock().unwrap().source(source, Instant::now()) else {
                continue;
            };
            let Some(destination) = *pinned.lock().unwrap() else {
                continue;
            };
            let mut frame = header(public);
            frame.extend_from_slice(if ipv6 { &buffer6[..n] } else { &buffer4[..n] });
            context
                .bandwidth
                .reserve_datagram(peer.ip(), false, frame.len())
                .await;
            let reservation = context
                .stats
                .reserve_datagram(context.activity_id, peer.ip(), false, frame.len())
                .await?;
            // Expired endpoints may not be revived by a long limiter wait.
            if endpoints
                .lock()
                .unwrap()
                .source(source, Instant::now())
                .is_none()
            {
                continue;
            }
            if let Ok(sent) = client.send_to(&frame, destination).await {
                if let Some(reservation) = reservation {
                    reservation
                        .settle(0, sent as u64)
                        .map_err(std::io::Error::other)?;
                    context
                        .stats
                        .traffic_accounted(peer.ip(), context.activity_id, 0, sent as u64);
                } else {
                    context
                        .stats
                        .traffic(peer.ip(), context.activity_id, 0, sent as u64);
                }
                if external && n > 0 && !verified {
                    context.stats.successful_external_request();
                    verified = true;
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };
    tokio::select! {
        biased;
        _ = context.cancellation.cancelled() => Ok(()),
        result = control.udp_control_closed() => result.map_err(ProxyError::Io),
        result = upload => result.map_err(ProxyError::Io),
        result = download => result.map_err(ProxyError::Io),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_cap_ttl_and_reclaim() {
        let now = Instant::now();
        let mut endpoints = Endpoints::default();
        for port in 1..=33 {
            let a = SocketAddr::from(([1, 1, 1, 1], port));
            endpoints.contact(a, a, now);
        }
        assert_eq!(endpoints.0.len(), 32);
        assert!(endpoints
            .source("1.1.1.1:33".parse().unwrap(), now)
            .is_none());
        assert!(endpoints
            .source("1.1.1.1:1".parse().unwrap(), now)
            .is_some());
        assert!(!endpoints.has_capacity("1.1.1.1:33".parse().unwrap(), now));
        endpoints.expire(now + ENDPOINT_TTL);
        assert!(endpoints.0.is_empty());
    }
}

#[cfg(test)]
mod fallback_tests {
    use super::*;
    async fn check(first: SocketAddr, available_v6: bool, first_succeeds: bool) {
        let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let v6 = if available_v6 {
            Some(UdpSocket::bind("[::1]:0").await.unwrap())
        } else {
            None
        };
        let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let alternate = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = Resolver::default();
        let second = "1.1.1.1:53".parse().unwrap();
        let endpoints = StdMutex::new(Endpoints::default());
        resolver.map_test_dial(
            first,
            if first_succeeds {
                primary.local_addr().unwrap()
            } else if available_v6 {
                "127.0.0.1:0".parse().unwrap()
            } else {
                "[::1]:1".parse().unwrap()
            },
        );
        resolver.map_test_dial(second, alternate.local_addr().unwrap());
        send_datagram(
            &v4,
            v6.as_ref(),
            &[first, second],
            &resolver,
            b"once",
            &endpoints,
        )
        .await
        .expect("a usable validated IPv4 alternative must be tried");
        let (receiver, unused) = if first_succeeds {
            (&primary, &alternate)
        } else {
            (&alternate, &primary)
        };
        let mut buffer = [0; 16];
        let (n, _) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], b"once");
        assert!(
            timeout(Duration::from_millis(60), unused.recv_from(&mut buffer))
                .await
                .is_err(),
            "successful UDP must not be duplicated to another candidate"
        );
        assert_eq!(endpoints.lock().unwrap().0.len(), 1);
    }
    #[tokio::test]
    async fn udp_missing_ipv6_socket_uses_ipv4_candidate_once() {
        check("[2606:4700:4700::1111]:53".parse().unwrap(), false, false).await;
    }
    #[tokio::test]
    async fn udp_definite_send_failure_uses_next_candidate_once() {
        check("[2606:4700:4700::1111]:53".parse().unwrap(), true, false).await;
    }
    #[tokio::test]
    async fn udp_first_success_never_duplicates_to_alternate() {
        check("8.8.8.8:53".parse().unwrap(), false, true).await;
    }
    #[tokio::test]
    async fn udp_mixed_private_answers_fail_before_any_candidate_send() {
        let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = Resolver::default();
        let public = "1.1.1.1:53".parse().unwrap();
        resolver.map_test_dial(public, receiver.local_addr().unwrap());
        let result = send_datagram(
            &v4,
            None,
            &[public, "127.0.0.1:53".parse().unwrap()],
            &resolver,
            b"denied",
            &StdMutex::new(Endpoints::default()),
        )
        .await;
        assert_eq!(result, Err("socks5-udp-destination-denied"));
        assert!(
            timeout(Duration::from_millis(60), receiver.recv_from(&mut [0; 20]))
                .await
                .is_err()
        );
    }
}
