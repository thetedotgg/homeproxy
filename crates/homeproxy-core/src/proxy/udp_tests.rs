use super::*;
use tokio::net::UdpSocket;

async fn start(
    settings: Settings,
) -> (ProxyContext, SocketAddr, JoinHandle<()>, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let mut context = service_port_tests::context(directory.path(), settings).await;
    context.bandwidth = BandwidthLimits::new(&context.settings.device_limits);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cloned = context.clone();
    let task = tokio::spawn(async move {
        accept_loop(
            BoundListener {
                listener,
                protocol: ListenerProtocol::Socks5Dedicated,
            },
            cloned,
        )
        .await
        .unwrap();
    });
    (context, address, task, directory)
}
async fn associate(address: SocketAddr) -> (TcpStream, Vec<u8>) {
    let mut control = TcpStream::connect(address).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    control.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = vec![0; 10];
    control.read_exact(&mut reply).await.unwrap();
    (control, reply)
}
#[tokio::test]
async fn opted_in_udp_associate_returns_real_endpoint_and_relays() {
    // serde allows this same socket regression to run against the pre-feature baseline.
    let mut value = serde_json::to_value(Settings {
        socks5_enabled: true,
        ..Settings::default()
    })
    .unwrap();
    value["socks5UdpEnabled"] = true.into();
    let settings = serde_json::from_value(value).unwrap_or_else(|_| Settings {
        socks5_enabled: true,
        ..Settings::default()
    });
    let (context, address, task, _directory) = start(settings).await;
    let (_control, reply) = associate(address).await;
    assert_eq!(
        context.stats.snapshot().activity[0].host,
        "",
        "idle UDP association has no target yet"
    );
    assert_eq!(
        reply[1], 0,
        "opt-in UDP ASSOCIATE must return success, baseline REP=07"
    );
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    assert_eq!(relay.ip(), address.ip());
    assert_ne!(relay.port(), 0);
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    context
        .resolver
        .map_test_dial("1.1.1.1:53".parse().unwrap(), echo.local_addr().unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let frame = [0, 0, 0, 1, 1, 1, 1, 1, 0, 53, 0xde, 0xad];
    client.send_to(&frame, relay).await.unwrap();
    let mut bytes = [0; 100];
    let (n, upstream) = timeout(Duration::from_secs(2), echo.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], &[0xde, 0xad]);
    echo.send_to(&bytes[..n], upstream).await.unwrap();
    let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], &frame);
    context.cancellation.cancel();
    task.await.unwrap();
    context.tasks.close();
    context.tasks.wait().await;
}

fn enabled() -> Settings {
    Settings {
        socks5_enabled: true,
        socks5_udp_enabled: true,
        ..Settings::default()
    }
}
fn endpoint(reply: &[u8]) -> SocketAddr {
    SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ))
}
fn frame(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0];
    match target.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
fn domain_frame(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, 3, host.len() as u8];
    bytes.extend_from_slice(host.as_bytes());
    bytes.extend_from_slice(&port.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
async fn stop(context: ProxyContext, task: JoinHandle<()>) {
    context.cancellation.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    context.tasks.close();
    timeout(Duration::from_secs(1), context.tasks.wait())
        .await
        .unwrap();
    assert_eq!(
        context.udp_associations.global.available_permits(),
        udp::MAX_ASSOCIATIONS
    );
    assert_eq!(
        context.connections.global.available_permits(),
        MAX_CONNECTIONS
    );
}
async fn exchange(
    client: &UdpSocket,
    relay: SocketAddr,
    origin: &UdpSocket,
    request: &[u8],
    expected: &[u8],
    response: &[u8],
) -> SocketAddr {
    client.send_to(request, relay).await.unwrap();
    let mut bytes = vec![0; 65536];
    let (n, upstream) = timeout(Duration::from_secs(4), origin.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], expected);
    origin.send_to(expected, upstream).await.unwrap();
    let (n, from) = timeout(Duration::from_secs(4), client.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, relay);
    assert_eq!(&bytes[..n], response);
    upstream
}
#[tokio::test]
async fn udp_dns_bursts_keep_control_connections_with_bounded_capacity_and_reclamation() {
    async fn associate_from(address: SocketAddr, peer: Ipv4Addr) -> (TcpStream, Vec<u8>) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::from((peer, 0))).unwrap();
        let mut control = socket.connect(address).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = vec![0; 10];
        control.read_exact(&mut reply).await.unwrap();
        (control, reply)
    }
    async fn dns_exchange(client: &UdpSocket, relay: SocketAddr, origin: &UdpSocket, id: u16) {
        // A complete DNS question and NXDOMAIN response; HomeProxy must relay
        // these as opaque datagrams, not close the association after a reply.
        let mut query = vec![
            0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
            b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        query[..2].copy_from_slice(&id.to_be_bytes());
        let target = "8.8.8.8:53".parse().unwrap();
        client.send_to(&frame(target, &query), relay).await.unwrap();
        let mut bytes = [0; 100];
        let (n, upstream) = timeout(Duration::from_secs(2), origin.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..n], &query);
        let mut answer = query;
        answer[2] = 0x81;
        answer[3] = 0x83;
        origin.send_to(&answer, upstream).await.unwrap();
        let (n, source) = timeout(Duration::from_secs(2), client.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, relay);
        assert_eq!(&bytes[..n], frame(target, &answer));
    }
    async fn refused(address: SocketAddr, peer: Ipv4Addr) {
        let (mut control, reply) = associate_from(address, peer).await;
        assert_eq!(reply[1], 1, "exhausted association budget must refuse");
        assert_eq!(
            timeout(Duration::from_secs(2), control.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0,
            "refused association must close its TCP control"
        );
    }

    let (ctx, address, task, _dir) = start(enabled()).await;
    let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    ctx.resolver
        .map_test_dial("8.8.8.8:53".parse().unwrap(), origin.local_addr().unwrap());
    let peer1 = Ipv4Addr::LOCALHOST;
    let peer2 = Ipv4Addr::new(127, 0, 0, 2);
    let peer3 = Ipv4Addr::new(127, 0, 0, 3);
    let mut flows = Vec::new();
    // Like a tun2socks client, retain each completed DNS flow's TCP control
    // while later questions open fresh flows. Do not sleep for a client TTL.
    for peer in [peer1, peer2] {
        for index in 0..64 {
            let (control, reply) = associate_from(address, peer).await;
            assert_eq!(reply[1], 0, "DNS flow {} for {peer} was refused", index + 1);
            let client = UdpSocket::bind(SocketAddr::from((peer, 0))).await.unwrap();
            let relay = endpoint(&reply);
            dns_exchange(&client, relay, &origin, flows.len() as u16).await;
            flows.push((control, client, relay));
        }
        if peer == peer1 {
            refused(address, peer1).await;
            assert_eq!(ctx.udp_associations.global.available_permits(), 64);
        }
    }
    assert_eq!(udp::MAX_PER_PEER, 64);
    assert_eq!(udp::MAX_ASSOCIATIONS, 128);
    assert_eq!(ctx.udp_associations.global.available_permits(), 0);
    refused(address, peer3).await;
    // The separate ordinary TCP budget still permits a real CONNECT relay
    // from the same peer even with both UDP budgets saturated.
    let tcp_origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    ctx.resolver.map_test_dial(
        "1.1.1.1:443".parse().unwrap(),
        tcp_origin.local_addr().unwrap(),
    );
    let mut tcp = TcpStream::connect(address).await.unwrap();
    tcp.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    tcp.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    tcp.write_all(&[5, 1, 0, 1, 1, 1, 1, 1, 1, 187])
        .await
        .unwrap();
    let mut reply = [0; 10];
    tcp.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    let (mut remote, _) = timeout(Duration::from_secs(2), tcp_origin.accept())
        .await
        .unwrap()
        .unwrap();
    tcp.write_all(b"tcp").await.unwrap();
    let mut payload = [0; 3];
    remote.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"tcp");
    remote.write_all(b"ack").await.unwrap();
    tcp.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"ack");

    // Release half of peer1's idle controls. The surviving original flow must
    // remain usable, and all reclaimed slots must admit a second DNS burst.
    let released_relays = flows[32..64].iter().map(|flow| flow.2).collect::<Vec<_>>();
    drop(flows.drain(32..64));
    timeout(Duration::from_secs(2), async {
        while ctx.udp_associations.global.available_permits() != 32 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("control EOF must reclaim every released association");
    for relay in released_relays {
        drop(
            UdpSocket::bind(relay)
                .await
                .expect("EOF releases relay socket"),
        );
    }
    dns_exchange(&flows[0].1, flows[0].2, &origin, 200).await;
    for index in 0..32 {
        let (control, reply) = associate_from(address, peer1).await;
        assert_eq!(reply[1], 0, "reclaimed DNS slot {index}");
        let client = UdpSocket::bind(SocketAddr::from((peer1, 0))).await.unwrap();
        let relay = endpoint(&reply);
        dns_exchange(&client, relay, &origin, 201 + index).await;
        flows.push((control, client, relay));
    }
    assert_eq!(ctx.udp_associations.global.available_permits(), 0);
    refused(address, peer1).await;
    refused(address, peer3).await;
    dns_exchange(&flows[0].1, flows[0].2, &origin, 250).await;
    assert!(ctx
        .stats
        .snapshot()
        .activity
        .iter()
        .any(|activity| { activity.error.as_deref() == Some("socks5-udp-association-limit") }));
    stop(ctx.clone(), task).await;
    assert!(ctx.udp_associations.per_peer.lock().unwrap().is_empty());
    assert!(ctx.connections.per_peer.lock().unwrap().is_empty());
    for (mut control, _, relay) in flows {
        assert_eq!(
            timeout(Duration::from_secs(2), control.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        drop(
            UdpSocket::bind(relay)
                .await
                .expect("Stop releases relay socket"),
        );
    }
}

#[tokio::test]
async fn udp_default_and_effective_flag_and_bind_remain_unsupported() {
    let mut legacy = serde_json::to_value(Settings::default()).unwrap();
    legacy.as_object_mut().unwrap().remove("socks5UdpEnabled");
    assert!(
        !serde_json::from_value::<Settings>(legacy)
            .unwrap()
            .socks5_udp_enabled
    );
    for settings in [
        Settings::default(),
        Settings {
            socks5_udp_enabled: true,
            ..Settings::default()
        },
        Settings {
            socks5_enabled: true,
            ..Settings::default()
        },
    ] {
        let (ctx, address, task, _dir) = start(settings).await;
        let (_control, reply) = associate(address).await;
        assert_eq!(reply[1], 7);
        assert_eq!(
            ctx.udp_associations.global.available_permits(),
            udp::MAX_ASSOCIATIONS
        );
        stop(ctx, task).await;
    }
    let (ctx, address, task, _dir) = start(enabled()).await;
    let mut control = TcpStream::connect(address).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    control.read_exact(&mut [0; 2]).await.unwrap();
    control
        .write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 7);
    stop(ctx, task).await;
}
#[tokio::test]
async fn udp_ipv4_domain_ipv6_multidestination_and_exact_counters_without_payload_logging() {
    let (ctx, address, task, _dir) = start(enabled()).await;
    let (_control, reply) = associate(address).await;
    let relay = endpoint(&reply);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut uploaded = 13u64;
    let mut downloaded = 12u64;
    for (target, domain, fixture) in [
        ("1.1.1.1:53", false, "127.0.0.1:0"),
        ("8.8.8.8:443", true, "127.0.0.1:0"),
        ("[2606:4700:4700::1111]:443", false, "[::1]:0"),
    ] {
        let target: SocketAddr = target.parse().unwrap();
        let origin = UdpSocket::bind(fixture).await.unwrap();
        ctx.resolver
            .map_test_dial(target, origin.local_addr().unwrap());
        ctx.resolver
            .set_test_answer("opaque.test", vec![target.ip()], Duration::ZERO);
        let payload = b"DNS-QUERY-PRIVATE-PAYLOAD-NEVER-LOG";
        let response = frame(target, payload);
        let request = if domain {
            domain_frame("opaque.test", target.port(), payload)
        } else {
            response.clone()
        };
        exchange(&client, relay, &origin, &request, payload, &response).await;
        uploaded += request.len() as u64;
        downloaded += response.len() as u64;
    }
    let snap = ctx.stats.snapshot();
    assert_eq!(
        (snap.upload_bytes, snap.download_bytes),
        (uploaded, downloaded)
    );
    assert_eq!(snap.activity.len(), 1);
    assert_eq!(snap.socks5_connections, 1);
    assert_eq!(snap.cache_hits, 0);
    assert_eq!(snap.compressed_images, 0);
    assert!(!serde_json::to_string(&snap)
        .unwrap()
        .contains("PRIVATE-PAYLOAD"));
    stop(ctx, task).await;
}
#[tokio::test]
async fn udp_rejects_foreign_sources_uncontacted_responses_malformed_and_private_destinations() {
    let (ctx, address, task, _dir) = start(enabled()).await;
    let (_control, reply) = associate(address).await;
    let relay = endpoint(&reply);
    let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = "1.1.1.1:53".parse().unwrap();
    ctx.resolver
        .map_test_dial(target, origin.local_addr().unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let good = frame(target, b"opaque");
    let mut fragmented = good.clone();
    fragmented[2] = 1;
    let mut reserved = good.clone();
    reserved[1] = 1;
    let mut zeroport = good.clone();
    zeroport[8] = 0;
    zeroport[9] = 0;
    let mut atyp = good.clone();
    atyp[3] = 7;
    let mut malformed = vec![
        fragmented,
        reserved,
        zeroport,
        atyp,
        vec![0, 0, 0, 3, 255, 65],
        frame(target, &vec![0; 65001]),
    ];
    for n in 0..10 {
        malformed.push(good[..n].to_vec());
    }
    for packet in malformed {
        client.send_to(&packet, relay).await.unwrap();
    }
    // Malformed frames must not pin the first source port.
    let pinned = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = exchange(&pinned, relay, &origin, &good, b"opaque", &good).await;
    client.send_to(&good, relay).await.unwrap(); // wrong port
    let foreign = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    foreign.send_to(&good, relay).await.unwrap();
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    attacker.send_to(b"unsolicited", upstream).await.unwrap();
    for host in ["127.0.0.1", "10.0.0.1", "::ffff:127.0.0.1", "::1"] {
        let forbidden = SocketAddr::new(host.parse().unwrap(), 53);
        ctx.resolver
            .map_test_dial(forbidden, origin.local_addr().unwrap());
        pinned
            .send_to(&frame(forbidden, b"private"), relay)
            .await
            .unwrap();
    }
    ctx.resolver.set_test_answer(
        "mixed.test",
        vec!["1.1.1.1".parse().unwrap(), "192.168.1.1".parse().unwrap()],
        Duration::ZERO,
    );
    pinned
        .send_to(&domain_frame("mixed.test", 53, b"mixed"), relay)
        .await
        .unwrap();
    pinned
        .send_to(&domain_frame("secret/bad?token=PRIVATE", 53, b"bad"), relay)
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(120), origin.recv_from(&mut [0; 100]))
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(120), pinned.recv_from(&mut [0; 100]))
            .await
            .is_err()
    );
    assert!(!serde_json::to_string(&ctx.stats.snapshot())
        .unwrap()
        .contains("token="));
    exchange(&pinned, relay, &origin, &good, b"opaque", &good).await;
    stop(ctx, task).await;
}
#[tokio::test]
async fn udp_association_hint_must_match_tcp_peer_and_requested_port_is_enforced() {
    let (ctx, address, task, _dir) = start(enabled()).await;
    for hint in [
        vec![5, 3, 0, 1, 127, 0, 0, 2, 0, 0],
        vec![5, 3, 0, 3, 1, b'x', 0, 0],
    ] {
        let mut control = TcpStream::connect(address).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        control.read_exact(&mut [0; 2]).await.unwrap();
        control.write_all(&hint).await.unwrap();
        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 2);
        assert_eq!(
            ctx.udp_associations.global.available_permits(),
            udp::MAX_ASSOCIATIONS
        );
    }
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut control = TcpStream::connect(address).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    control.read_exact(&mut [0; 2]).await.unwrap();
    let mut request = vec![5, 3, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&client.local_addr().unwrap().port().to_be_bytes());
    control.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = "1.1.1.1:53".parse().unwrap();
    ctx.resolver
        .map_test_dial(target, origin.local_addr().unwrap());
    let packet = frame(target, b"port");
    let foreign = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    foreign.send_to(&packet, endpoint(&reply)).await.unwrap();
    assert!(
        timeout(Duration::from_millis(80), origin.recv_from(&mut [0; 100]))
            .await
            .is_err()
    );
    exchange(
        &client,
        endpoint(&reply),
        &origin,
        &packet,
        b"port",
        &packet,
    )
    .await;
    stop(ctx, task).await;
}
#[tokio::test]
async fn udp_eof_and_stop_cancel_receive_dns_and_limiter_and_release_bound_endpoint() {
    for stage in ["receive", "dns", "upload-limit", "download-limit"] {
        for eof in [true, false] {
            let mut settings = enabled();
            if stage.ends_with("limit") {
                settings.device_limits.push(crate::config::DeviceLimit {
                    ip: Ipv4Addr::LOCALHOST,
                    upload_bytes_per_second: if stage == "upload-limit" { 1000 } else { 0 },
                    download_bytes_per_second: if stage == "download-limit" { 1000 } else { 0 },
                });
            }
            let (ctx, address, task, _dir) = start(settings).await;
            // start() must construct the very same shared buckets as production.
            let (control, reply) = associate(address).await;
            let relay = endpoint(&reply);
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            ctx.resolver
                .map_test_dial("1.1.1.1:53".parse().unwrap(), origin.local_addr().unwrap());
            if stage == "dns" {
                ctx.resolver.set_test_answer(
                    "slow.test",
                    vec!["1.1.1.1".parse().unwrap()],
                    Duration::from_secs(30),
                );
                client
                    .send_to(&domain_frame("slow.test", 53, b"wait"), relay)
                    .await
                    .unwrap();
            } else if stage.ends_with("limit") {
                let payload = if stage == "upload-limit" {
                    vec![0; 60000]
                } else {
                    vec![0; 1]
                };
                client
                    .send_to(&frame("1.1.1.1:53".parse().unwrap(), &payload), relay)
                    .await
                    .unwrap();
                if stage == "download-limit" {
                    let (_, up) = timeout(Duration::from_secs(1), origin.recv_from(&mut [0; 100]))
                        .await
                        .unwrap()
                        .unwrap();
                    origin.send_to(&vec![0; 60000], up).await.unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
            if eof {
                drop(control);
                timeout(Duration::from_millis(300), async {
                    while ctx.udp_associations.global.available_permits() != udp::MAX_ASSOCIATIONS {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("EOF must cancel pending association work");
            } else {
                ctx.cancellation.cancel();
            }
            stop(ctx.clone(), task).await;
            let rebound = UdpSocket::bind(relay)
                .await
                .expect("all association sockets must close");
            drop(rebound);
        }
    }
}
#[tokio::test]
async fn udp_larger_than_bucket_datagram_completes_with_shared_limiter() {
    let mut settings = enabled();
    settings.device_limits.push(crate::config::DeviceLimit {
        ip: Ipv4Addr::LOCALHOST,
        upload_bytes_per_second: 100_000,
        download_bytes_per_second: 100_000,
    });
    let (ctx, address, task, _dir) = start(settings).await;
    let (_control, reply) = associate(address).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = "1.1.1.1:443".parse().unwrap();
    ctx.resolver
        .map_test_dial(target, origin.local_addr().unwrap());
    let payload = vec![0xa5; 40_000];
    let packet = frame(target, &payload);
    let now = Instant::now();
    exchange(
        &client,
        endpoint(&reply),
        &origin,
        &packet,
        &payload,
        &packet,
    )
    .await;
    assert!(
        now.elapsed() >= Duration::from_millis(500),
        "upload and download must each reserve full packet"
    );
    stop(ctx, task).await;
}
#[test]
fn udp_global_and_per_peer_caps_reclaim_without_growing_registry() {
    let limiter = udp::association_limiter();
    let peer = "192.168.1.1".parse().unwrap();
    let mut permits = (0..udp::MAX_PER_PEER)
        .map(|_| limiter.try_acquire(peer).unwrap())
        .collect::<Vec<_>>();
    assert!(matches!(
        limiter.try_acquire(peer),
        Err(ConnectionRejectionReason::PeerLimit)
    ));
    for n in 2..=udp::MAX_ASSOCIATIONS / udp::MAX_PER_PEER {
        for _ in 0..udp::MAX_PER_PEER {
            permits.push(
                limiter
                    .try_acquire(IpAddr::V4(Ipv4Addr::new(192, 168, 1, n as u8)))
                    .unwrap(),
            );
        }
    }
    assert!(matches!(
        limiter.try_acquire("192.168.1.9".parse().unwrap()),
        Err(ConnectionRejectionReason::GlobalLimit)
    ));
    drop(permits);
    assert_eq!(limiter.global.available_permits(), udp::MAX_ASSOCIATIONS);
    assert!(limiter.per_peer.lock().unwrap().is_empty());
    assert!(limiter.try_acquire(peer).is_ok());
}

// Exercises the SOCKS path with a real socket and explicit LAN peer identity.
async fn external_control(ctx: ProxyContext, peer: SocketAddr) -> (TcpStream, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut context = ctx;
        let permit = Arc::new(context.connections.try_acquire(peer.ip()).unwrap());
        context.connection_permit = Some(permit.clone());
        let id = context
            .stats
            .begin_activity(peer.ip(), stream.local_addr().unwrap().ip());
        context.activity_id = id;
        let mut stream = MeteredStream::new(
            stream,
            context.stats.clone(),
            peer.ip(),
            id,
            &context.bandwidth,
        );
        assert_eq!(stream.read_u8().await.unwrap(), 5);
        let result = handle_socks5(stream, peer, &context, ListenerProtocol::Socks5Dedicated).await;
        if device_is_denied(peer.ip(), &context.settings) {
            assert!(
                matches!(
                    result,
                    Err(ProxyError::Forbidden("Zařízení je v HomeProxy zakázané."))
                ),
                "configured device must take the exact denial path: {result:?}"
            );
        }
    });
    (TcpStream::connect(address).await.unwrap(), task)
}
#[tokio::test]
async fn socks_external_success_requires_actual_return_payload_and_counts_once() {
    let directory = tempfile::tempdir().unwrap();
    for external in [true, false] {
        let ctx = service_port_tests::context(
            directory.path(),
            Settings {
                lan_auth_enabled: false,
                ..enabled()
            },
        )
        .await;
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        ctx.resolver
            .map_test_dial("1.1.1.1:443".parse().unwrap(), origin.local_addr().unwrap());
        let peer = if external {
            "192.168.1.123:49152"
        } else {
            "127.0.0.1:49152"
        }
        .parse()
        .unwrap();
        let (mut client, task) = external_control(ctx.clone(), peer).await;
        client.write_all(&[5, 1, 0]).await.unwrap();
        client.read_exact(&mut [0; 2]).await.unwrap();
        client
            .write_all(&[5, 1, 0, 1, 1, 1, 1, 1, 1, 187])
            .await
            .unwrap();
        client.read_exact(&mut [0; 10]).await.unwrap();
        let (mut remote, _) = origin.accept().await.unwrap();
        assert_eq!(ctx.stats.snapshot().successful_external_requests, 0);
        for payload in [b"first", b"again"] {
            remote.write_all(payload).await.unwrap();
            client.read_exact(&mut [0; 5]).await.unwrap();
        }
        let snapshot = ctx.stats.snapshot();
        assert_eq!(snapshot.successful_external_requests, u64::from(external));
        assert_eq!(
            snapshot.authenticated_external_requests,
            u64::from(external)
        );
        drop(client);
        drop(remote);
        task.await.unwrap();
    }
}
#[tokio::test]
async fn socks_auth_device_denial_and_private_target_never_allocate_udp_or_complete_guide() {
    let directory = tempfile::tempdir().unwrap();
    for stage in ["device", "auth", "private"] {
        let mut settings = enabled();
        if stage == "device" {
            settings
                .denied_client_ips
                .push("192.168.1.123".parse().unwrap());
        }
        if stage == "private" {
            settings.lan_auth_enabled = false;
        }
        let ctx = service_port_tests::context(directory.path(), settings).await;
        let (mut client, task) =
            external_control(ctx.clone(), "192.168.1.123:49152".parse().unwrap()).await;
        client
            .write_all(&[5, 1, if stage == "auth" { 2 } else { 0 }])
            .await
            .unwrap();
        let mut method = [0; 2];
        let method_result = client.read_exact(&mut method).await;
        if stage == "device" {
            match method_result {
                Ok(_) => assert_eq!(method, [5, 255]),
                // Denial precedes NMETHODS/METHODS consumption. Windows may reset
                // this TCP socket with unread greeting bytes instead of delivering
                // the attempted rejection reply. The server task independently
                // asserts the exact Forbidden result; all counters remain checked.
                Err(error) if cfg!(windows) && error.raw_os_error() == Some(10054) => {}
                Err(error) => panic!("unexpected device-denial response: {error}"),
            }
        } else {
            method_result.unwrap();
        }
        if stage == "auth" {
            assert_eq!(method, [5, 2]);
            client.write_all(&[1, 1, b'x', 1, b'x']).await.unwrap();
            let mut status = [0; 2];
            client.read_exact(&mut status).await.unwrap();
            assert_eq!(status, [1, 1]);
        } else if stage == "private" {
            assert_eq!(method, [5, 0]);
            client
                .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 2);
        }
        drop(client);
        task.await.unwrap();
        let snap = ctx.stats.snapshot();
        assert_eq!(snap.socks5_connections, 0);
        assert_eq!(snap.successful_external_requests, 0);
        if stage != "private" {
            assert_eq!(snap.authenticated_external_requests, 0);
        }
        assert_eq!(
            ctx.udp_associations.global.available_permits(),
            udp::MAX_ASSOCIATIONS
        );
    }
}

#[tokio::test]
async fn udp_two_associations_and_tcp_share_upload_download_budgets_and_other_peer_is_independent()
{
    let mut settings = enabled();
    settings.device_limits.push(crate::config::DeviceLimit {
        ip: Ipv4Addr::LOCALHOST,
        upload_bytes_per_second: 20_000,
        download_bytes_per_second: 20_000,
    });
    let (ctx, address, task, _dir) = start(settings).await;
    let origin = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let target = "1.1.1.1:443".parse().unwrap();
    ctx.resolver
        .map_test_dial(target, origin.local_addr().unwrap());
    let tcp_origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    ctx.resolver.map_test_dial(
        "8.8.8.8:443".parse().unwrap(),
        tcp_origin.local_addr().unwrap(),
    );
    let mut tcp = TcpStream::connect(address).await.unwrap();
    tcp.write_all(&[5, 1, 0]).await.unwrap();
    tcp.read_exact(&mut [0; 2]).await.unwrap();
    tcp.write_all(&[5, 1, 0, 1, 8, 8, 8, 8, 1, 187])
        .await
        .unwrap();
    tcp.read_exact(&mut [0; 10]).await.unwrap();
    let (mut tcp_remote, _) = tcp_origin.accept().await.unwrap();
    let (control1, reply1) = associate(address).await;
    let (control2, reply2) = associate(address).await;
    let echo = origin.clone();
    let echo_task = tokio::spawn(async move {
        for _ in 0..2 {
            let mut b = vec![0; 65536];
            let (n, a) = echo.recv_from(&mut b).await.unwrap();
            echo.send_to(&b[..n], a).await.unwrap();
        }
    });
    let mut jobs = JoinSet::new();
    let started = Instant::now();
    for (control, reply) in [(control1, reply1), (control2, reply2)] {
        jobs.spawn(async move {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let packet = frame(target, &vec![0x41; 20_000]);
            client.send_to(&packet, endpoint(&reply)).await.unwrap();
            let mut b = vec![0; 65536];
            let (n, _) = client.recv_from(&mut b).await.unwrap();
            assert_eq!(&b[..n], &packet);
            drop(control);
        });
    }
    jobs.spawn(async move {
        let remote = tokio::spawn(async move {
            let mut b = vec![0; 20_000];
            tcp_remote.read_exact(&mut b).await.unwrap();
            tcp_remote.write_all(&b).await.unwrap();
        });
        tcp.write_all(&vec![0x42; 20_000]).await.unwrap();
        tcp.read_exact(&mut vec![0; 20_000]).await.unwrap();
        remote.await.unwrap();
    });
    // A distinct source IP establishes an unlimited association while the first IP is busy.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let mut other = socket.connect(address).await.unwrap();
    other.write_all(&[5, 1, 0]).await.unwrap();
    other.read_exact(&mut [0; 2]).await.unwrap();
    other
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0; 10];
    other.read_exact(&mut reply).await.unwrap();
    let separate_origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let separate_target = "9.9.9.9:53".parse().unwrap();
    ctx.resolver
        .map_test_dial(separate_target, separate_origin.local_addr().unwrap());
    let independent = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    let packet = frame(separate_target, b"other-peer");
    timeout(
        Duration::from_millis(250),
        exchange(
            &independent,
            endpoint(&reply),
            &separate_origin,
            &packet,
            b"other-peer",
            &packet,
        ),
    )
    .await
    .expect("other IP must not wait behind limited flows");
    timeout(Duration::from_secs(9), async {
        while let Some(result) = jobs.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
    echo_task.await.unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(2800),
        "TCP plus two UDP flows must consume one 20 kB/s peer budget"
    );
    let snap = ctx.stats.snapshot();
    assert_eq!(
        snap.upload_bytes,
        60_020 + 3 * 13 + 13 + packet.len() as u64
    );
    assert_eq!(
        snap.download_bytes,
        60_020 + 3 * 12 + 12 + packet.len() as u64
    );
    stop(ctx, task).await;
}

async fn native_udp_relay(ip: Ipv4Addr) {
    let directory = tempfile::tempdir().unwrap();
    let ctx = service_port_tests::context(
        directory.path(),
        Settings {
            lan_auth_enabled: false,
            ..enabled()
        },
    )
    .await;
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let cloned = ctx.clone();
    let task = tokio::spawn(async move {
        accept_loop(
            BoundListener {
                listener,
                protocol: ListenerProtocol::Socks5Dedicated,
            },
            cloned,
        )
        .await
        .unwrap();
    });
    let (control, reply) = associate(address).await;
    assert_eq!(reply[1], 0);
    let relay = endpoint(&reply);
    assert_eq!(relay.ip(), IpAddr::V4(ip));
    assert!(!control.local_addr().unwrap().ip().is_loopback());
    let client = UdpSocket::bind((ip, 0)).await.unwrap();
    let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = "1.1.1.1:53".parse().unwrap();
    ctx.resolver
        .map_test_dial(target, origin.local_addr().unwrap());
    assert_eq!(ctx.stats.snapshot().successful_external_requests, 0);
    let packet = frame(target, b"native-opaque-fixture");
    for _ in 0..2 {
        exchange(
            &client,
            relay,
            &origin,
            &packet,
            b"native-opaque-fixture",
            &packet,
        )
        .await;
    }
    assert_eq!(ctx.stats.snapshot().successful_external_requests, 1);
    assert_eq!(ctx.stats.snapshot().authenticated_external_requests, 1);
    drop(control);
    timeout(Duration::from_secs(1), async {
        while ctx.udp_associations.global.available_permits() != udp::MAX_ASSOCIATIONS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    UdpSocket::bind(relay).await.unwrap();
    stop(ctx, task).await;
    println!("NATIVE UDP PASS ip={ip}; actual TCP and UDP LAN endpoints; production public-target policy; local final-dial fixture; opaque datagrams; one successful external association; EOF released relay endpoint");
}
#[tokio::test]
#[ignore = "explicit native adapter test; set HOMEPROXY_NATIVE_TEST_IP"]
async fn native_lan_udp_relay_with_production_destination_policy() {
    let ip: Ipv4Addr = std::env::var("HOMEPROXY_NATIVE_TEST_IP")
        .unwrap()
        .parse()
        .unwrap();
    assert!(ip.is_private());
    assert!(crate::available_lan_addresses().iter().any(|a| a.ip == ip));
    native_udp_relay(ip).await;
}

#[tokio::test]
async fn udp_password_authentication_precedes_association_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let ctx = service_port_tests::context(directory.path(), enabled()).await;
    let (mut client, task) =
        external_control(ctx.clone(), "192.168.1.123:49152".parse().unwrap()).await;
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    assert_eq!(
        ctx.udp_associations.global.available_permits(),
        udp::MAX_ASSOCIATIONS
    );
    let mut auth = vec![1, ctx.settings.proxy_username.len() as u8];
    auth.extend_from_slice(ctx.settings.proxy_username.as_bytes());
    auth.push(ctx.settings.proxy_password.len() as u8);
    auth.extend_from_slice(ctx.settings.proxy_password.as_bytes());
    client.write_all(&auth).await.unwrap();
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [1, 0]);
    assert_eq!(
        ctx.udp_associations.global.available_permits(),
        udp::MAX_ASSOCIATIONS
    );
    client
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    assert_eq!(
        ctx.udp_associations.global.available_permits(),
        udp::MAX_ASSOCIATIONS - 1
    );
    assert_eq!(ctx.stats.snapshot().successful_external_requests, 0);
    drop(client);
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ctx.udp_associations.global.available_permits(),
        udp::MAX_ASSOCIATIONS
    );
}

#[cfg(windows)]
#[tokio::test]
async fn windows_udp_icmp_reset_preserves_same_association_for_next_destination() {
    let (ctx, address, task, _directory) = start(enabled()).await;
    let (control, reply) = associate(address).await;
    let relay = endpoint(&reply);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Close only our own ephemeral socket. No public packets or external port probes.
    let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let closed_address = closed.local_addr().unwrap();
    let unreachable = "1.1.1.1:53".parse().unwrap();
    ctx.resolver.map_test_dial(unreachable, closed_address);
    drop(closed);
    client
        .send_to(&frame(unreachable, b"closed-owned-fixture"), relay)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    println!(
        "After own closed UDP port: available association permits={}, activity={:?}",
        ctx.udp_associations.global.available_permits(),
        ctx.stats
            .snapshot()
            .activity
            .iter()
            .map(|entry| (&entry.error, entry.ended_unix_ms))
            .collect::<Vec<_>>()
    );
    let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = "8.8.8.8:53".parse().unwrap();
    ctx.resolver
        .map_test_dial(target, origin.local_addr().unwrap());
    let packet = frame(target, b"same-association-survives");
    exchange(
        &client,
        relay,
        &origin,
        &packet,
        b"same-association-survives",
        &packet,
    )
    .await;
    assert_eq!(
        ctx.udp_associations.global.available_permits(),
        udp::MAX_ASSOCIATIONS - 1
    );
    println!("Windows actual-core UDP ICMP recovery: same TCP control and client UDP socket reached next owned endpoint; public packets=0");
    drop(control);
    stop(ctx, task).await;
}

#[tokio::test]
async fn udp_zero_length_response_counts_frame_but_requires_later_payload_for_guide_success() {
    let directory = tempfile::tempdir().unwrap();
    let mut ctx = service_port_tests::context(directory.path(), enabled()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut control = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, peer) = listener.accept().await.unwrap();
    ctx.activity_id = ctx
        .stats
        .begin_activity(peer.ip(), stream.local_addr().unwrap().ip());
    let server_ctx = ctx.clone();
    let server = tokio::spawn(async move {
        let control = MeteredStream::new(
            stream,
            server_ctx.stats.clone(),
            peer.ip(),
            server_ctx.activity_id,
            &server_ctx.bandwidth,
        );
        // Isolated UDP response attribution boundary: production passes this after peer classification.
        udp::associate(control, peer, &server_ctx, "0.0.0.0", 0, true)
            .await
            .unwrap();
    });
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = "1.1.1.1:53".parse().unwrap();
    ctx.resolver
        .map_test_dial(target, origin.local_addr().unwrap());
    let empty = frame(target, b"");
    exchange(&client, endpoint(&reply), &origin, &empty, b"", &empty).await;
    assert_eq!(
        ctx.stats.snapshot().download_bytes,
        20,
        "association reply plus empty SOCKS UDP frame still count"
    );
    assert_eq!(
        ctx.stats.snapshot().successful_external_requests,
        0,
        "empty upstream data is not successful guide payload"
    );
    for _ in 0..2 {
        let packet = frame(target, b"actual-payload");
        exchange(
            &client,
            endpoint(&reply),
            &origin,
            &packet,
            b"actual-payload",
            &packet,
        )
        .await;
    }
    assert_eq!(ctx.stats.snapshot().successful_external_requests, 1);
    drop(control);
    timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
}
