use super::*;

#[tokio::test]
async fn digest_retry_activity_tracks_recovery_and_preserves_rejections() {
    use md5::{Digest, Md5};

    for scenario in [
        "valid",
        "missing",
        "invalid",
        "denied",
        "prior-error",
        "upstream-error",
    ] {
        let directory = tempfile::tempdir().unwrap();
        super::offline_tests::secure_directory(directory.path());
        let stats = Arc::new(Stats::default());
        // Exercise LAN authentication over an isolated loopback transport, without
        // relying on a host's interfaces or changing production auth exemptions.
        let peer: SocketAddr = "192.168.68.81:12345".parse().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let authority = upstream.local_addr().unwrap().to_string();
        let mut settings = Settings {
            https_mode: HttpsMode::Tunnel,
            proxy_username: "activity-fixture".into(),
            proxy_password: "fixture-only-password".into(),
            ..Settings::default()
        };
        if scenario == "denied" {
            settings
                .denied_client_ips
                .push("192.168.68.81".parse().unwrap());
        }
        let connections = ConnectionLimiter::default();
        let id = stats.begin_activity(peer.ip(), endpoint.ip());
        if scenario == "prior-error" {
            stats.activity_error(id, "HTTP-connection-failed");
        }
        let context = ProxyContext {
            bandwidth: BandwidthLimits::default(),
            cache_enabled: Arc::new(AtomicBool::new(false)),
            activity_id: id,
            listener_address: None,
            connection_permit: Some(Arc::new(connections.try_acquire(peer.ip()).unwrap())),
            resolver: Resolver::new(settings.dns_mode).unwrap(),
            settings,
            cache: CacheStore::new(directory.path().join("cache")),
            stats: stats.clone(),
            auth: Arc::new(DigestAuth::default()),
            allow_private_destinations: true,
            cancellation: CancellationToken::new(),
            tasks: TaskTracker::new(),
            connections,
            udp_associations: udp::association_limiter(),
            transform_slots: Arc::new(Semaphore::new(1)),
            buffer_budget: Arc::new(Semaphore::new(MAX_BUFFERED_BYTES)),
            host_addresses: Arc::new(HashSet::new()),
            tls_inspection: TlsInspection::for_tests(
                directory.path().join("ca.json"),
                rustls::RootCertStore::empty(),
            )
            .unwrap(),
            inspection_bypass: InspectionBypass::default(),
        };
        let denied_challenge = context.auth.challenge(&Method::CONNECT, &authority);
        let tasks = context.tasks.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = MeteredStream::new(
                stream,
                context.stats.clone(),
                peer.ip(),
                id,
                &context.bandwidth,
            );
            let service = service_fn(move |request| {
                let context = context.clone();
                async move { Ok::<_, Infallible>(handle_request(request, peer, context).await) }
            });
            server_http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await
                .unwrap();
        });
        let mut client = TcpStream::connect(endpoint).await.unwrap();
        client
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let challenge_headers = String::from_utf8(headers(&mut client).await).unwrap();
        assert!(
            challenge_headers.starts_with("HTTP/1.1 407"),
            "{scenario}: {challenge_headers}"
        );
        let body_len: usize = challenge_headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        client.read_exact(&mut vec![0; body_len]).await.unwrap();
        assert!(
            timeout(Duration::from_millis(20), upstream.accept())
                .await
                .is_err(),
            "challenge contacted upstream"
        );

        if scenario != "missing" {
            let challenge = if scenario == "denied" {
                &denied_challenge
            } else {
                &challenge_headers
            };
            let nonce = challenge
                .split("nonce=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            let password = if scenario == "invalid" {
                "wrong-password"
            } else {
                "fixture-only-password"
            };
            let digest = |value: &str| hex::encode(Md5::digest(value.as_bytes()));
            let ha1 = digest(&format!("activity-fixture:HomeProxy:{password}"));
            let ha2 = digest(&format!("CONNECT:{authority}"));
            let response = digest(&format!("{ha1}:{nonce}:00000001:fixture:auth:{ha2}"));
            let authorization = format!("Digest username=\"activity-fixture\", realm=\"HomeProxy\", nonce=\"{nonce}\", uri=\"{authority}\", response=\"{response}\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"fixture\"");
            let upstream = if scenario == "upstream-error" {
                drop(upstream);
                None
            } else {
                Some(upstream)
            };
            client.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {authorization}\r\n\r\n").as_bytes()).await.unwrap();
            // Windows can take over two seconds to report a refused connection.
            let response_timeout = if scenario == "upstream-error" {
                CONNECT_TIMEOUT + Duration::from_secs(2)
            } else {
                Duration::from_secs(2)
            };
            let response =
                String::from_utf8(headers_with_timeout(&mut client, response_timeout).await)
                    .unwrap();
            if matches!(scenario, "invalid" | "denied") {
                assert!(
                    response.starts_with("HTTP/1.1 407"),
                    "{scenario}: {response}"
                );
                assert!(
                    timeout(
                        Duration::from_millis(20),
                        upstream.as_ref().unwrap().accept()
                    )
                    .await
                    .is_err(),
                    "rejection contacted upstream"
                );
                // Drain the rejected response before closing the connection.
                let body_len: usize = response
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                client.read_exact(&mut vec![0; body_len]).await.unwrap();
            } else if scenario == "upstream-error" {
                assert!(response.starts_with("HTTP/1.1 502"), "{response}");
                let body_len: usize = response
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                client.read_exact(&mut vec![0; body_len]).await.unwrap();
            } else {
                assert!(
                    response.starts_with("HTTP/1.1 200"),
                    "{scenario}: {response}"
                );
                let (mut origin, _) =
                    timeout(Duration::from_secs(2), upstream.as_ref().unwrap().accept())
                        .await
                        .unwrap()
                        .unwrap();
                client.write_all(b"ping").await.unwrap();
                let mut payload = [0; 4];
                timeout(Duration::from_secs(2), origin.read_exact(&mut payload))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&payload, b"ping");
                origin.write_all(b"pong").await.unwrap();
                timeout(Duration::from_secs(2), client.read_exact(&mut payload))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&payload, b"pong");
                if scenario == "valid" {
                    let live = stats.snapshot();
                    assert_eq!(live.activity[0].status, "active");
                    assert!(live.activity[0].error.is_none());
                    assert!(live.activity[0].ended_unix_ms.is_none());
                }
                origin.shutdown().await.unwrap();
                client.shutdown().await.unwrap();
            }
        }
        drop(client);
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        tasks.close();
        timeout(Duration::from_secs(2), tasks.wait()).await.unwrap();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.activity.len(), 1, "{scenario}: one TCP activity");
        let activity = &snapshot.activity[0];
        assert!(activity.ended_unix_ms.is_some(), "{scenario}");
        assert!(activity.upload_bytes > 0 && activity.download_bytes > 0);
        let expected = match scenario {
            "valid" => None,
            "missing" | "invalid" => Some("authentication-required"),
            "denied" => Some("device-denied"),
            "prior-error" => Some("HTTP-connection-failed"),
            "upstream-error" => Some("K hostiteli se nepodařilo připojit."),
            _ => unreachable!(),
        };
        assert_eq!(activity.error.as_deref(), expected, "{scenario}");
        assert_eq!(
            activity.status,
            if expected.is_some() {
                "error"
            } else {
                "completed"
            },
            "{scenario}"
        );
        if matches!(scenario, "missing" | "invalid" | "denied") {
            assert_eq!(snapshot.authenticated_external_requests, 0, "{scenario}");
            assert_eq!(snapshot.connect_tunnels, 0, "{scenario}");
        }
    }
}

async fn headers<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    headers_with_timeout(stream, Duration::from_secs(2)).await
}
async fn headers_with_timeout<S: AsyncRead + Unpin>(stream: &mut S, budget: Duration) -> Vec<u8> {
    let mut result = Vec::new();
    timeout(budget, async {
        while !result.ends_with(b"\r\n\r\n") {
            result.push(stream.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    result
}
async fn websocket_origin<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    let request = headers(&mut stream).await;
    assert!(String::from_utf8_lossy(&request)
        .to_ascii_lowercase()
        .contains("upgrade: websocket"));
    assert!(!String::from_utf8_lossy(&request)
        .to_ascii_lowercase()
        .contains("proxy-authorization:"));
    stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
    for _ in 0..3 {
        let mut frame = [0; 10];
        stream.read_exact(&mut frame).await.unwrap();
        assert_eq!(frame, [0x81, 0x84, 1, 2, 3, 4, 0x71, 0x6b, 0x6d, 0x63]);
        stream
            .write_all(&[0x81, 4, b'p', b'o', b'n', b'g'])
            .await
            .unwrap();
    }
    let _ = stream.read_u8().await;
}
async fn websocket_client<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: String,
    handle: ProxyHandle,
    stats: Arc<Stats>,
    expect_visible_upgrade: bool,
    plain_wire: bool,
) {
    let mut initial = request.as_bytes().to_vec();
    initial.extend_from_slice(&[0x81, 0x84, 1, 2, 3, 4, 0x71, 0x6b, 0x6d, 0x63]);
    stream.write_all(&initial).await.unwrap();
    let response = headers(&mut stream).await;
    assert!(
        response.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    for (index, enabled) in [false, true, false].into_iter().enumerate() {
        handle.set_cache_enabled(enabled);
        if index > 0 {
            stream
                .write_all(&[0x81, 0x84, 1, 2, 3, 4, 0x71, 0x6b, 0x6d, 0x63])
                .await
                .unwrap();
        }
        let mut reply = [0; 6];
        timeout(Duration::from_secs(2), stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, [0x81, 4, b'p', b'o', b'n', b'g']);
        let live = stats.snapshot();
        assert!(live.upload_bytes > 0 && live.download_bytes > 0);
        assert!(live.activity.last().unwrap().ended_unix_ms.is_none());
    }
    if plain_wire {
        assert_eq!(
            stats.snapshot().upload_bytes,
            request.len() as u64 + 30,
            "buffered upgrade bytes counted exactly once"
        );
        assert_eq!(stats.snapshot().download_bytes, response.len() as u64 + 18);
    }
    assert_eq!(stats.snapshot().cache_hits, 0);
    assert_eq!(stats.snapshot().compressed_images, 0);
    if expect_visible_upgrade {
        assert!(stats
            .snapshot()
            .activity
            .iter()
            .any(|entry| entry.cache_bypass_reason.as_deref() == Some("websocket")));
    }
    timeout(Duration::from_secs(1), handle.stop())
        .await
        .unwrap();
    let mut byte = [0];
    let closed = timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(!matches!(closed,Ok(n) if n>0));
}

#[tokio::test]
async fn plain_ws_and_inspected_wss_upgrade_relay_frames_and_cancel() {
    use rcgen::{CertificateParams, KeyPair};
    use rustls::{
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        ClientConfig, RootCertStore, ServerConfig,
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    for (secure, inspect) in [(false, false), (true, true), (true, false)] {
        let directory = tempfile::tempdir().unwrap();
        super::offline_tests::secure_directory(directory.path());
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap(),
        ));
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let inspection = TlsInspection::for_tests(directory.path().join("ca.json"), roots).unwrap();
        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(if inspect {
                inspection.root_certificate_der()
            } else {
                cert.der().clone()
            })
            .unwrap();
        let connector = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(client_roots)
                .with_no_client_auth(),
        ));
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            if secure {
                websocket_origin(acceptor.accept(stream).await.unwrap()).await;
            } else {
                websocket_origin(stream).await;
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let stats = Arc::new(Stats::default());
        let handle = spawn_proxy_with_listeners(
            Settings {
                https_mode: if inspect {
                    HttpsMode::Inspect
                } else {
                    HttpsMode::Tunnel
                },
                cache_enabled: true,
                https_client_trust_acknowledged: true,
                https_inspect_hosts: vec!["127.0.0.1".into()],
                ..Settings::default()
            },
            CacheStore::new(directory.path().join("cache")),
            stats.clone(),
            inspection,
            vec![listener],
            true,
        )
        .unwrap();
        let mut occupied = Vec::new();
        if !secure {
            for _ in 0..(MAX_CONNECTIONS_PER_PEER - 1) {
                occupied.push(
                    TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
                        .await
                        .unwrap(),
                );
            }
        }
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .unwrap();
        let path = if secure {
            "/socket?private-token".into()
        } else {
            format!("http://127.0.0.1:{origin_port}/socket?private-token")
        };
        let proxy_auth = if !secure || inspect {
            "Proxy-Authorization: Basic privatecredential\r\n"
        } else {
            ""
        };
        let request=format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCookie: session=private\r\n{proxy_auth}\r\n");
        if secure {
            stream.write_all(format!("CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost:127.0.0.1:{origin_port}\r\n\r\n").as_bytes()).await.unwrap();
            assert!(headers(&mut stream).await.starts_with(b"HTTP/1.1 200"));
            let tls = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                    stream,
                )
                .await
                .unwrap();
            websocket_client(tls, request, handle, stats.clone(), inspect, false).await;
        } else {
            websocket_client(stream, request, handle, stats.clone(), true, true).await;
        }
        server.await.unwrap();
        let snapshot = serde_json::to_string(&stats.snapshot()).unwrap();
        assert!(!snapshot.contains("private-token") && !snapshot.contains("session="));
    }
}

#[tokio::test]
async fn reserved_dns_and_literal_socks_addresses_never_reach_connector() {
    let resolver = Resolver::new(crate::config::DnsMode::Cloudflare).unwrap();
    let literal = resolver.resolve("192.0.0.88", 443).await.unwrap();
    for addresses in [
        literal,
        vec![
            "93.184.216.34:443".parse().unwrap(),
            "192.0.0.88:443".parse().unwrap(),
        ],
        vec![
            "[2606:4700::1111]:443".parse().unwrap(),
            "[::1]:443".parse().unwrap(),
        ],
    ] {
        let result = connect_resolved_with(addresses, false, |_| async {
            panic!("reserved/mixed DNS must fail before any TCP attempt")
        })
        .await;
        assert!(matches!(result, Err(ProxyError::Forbidden(_))));
    }
}

#[tokio::test]
async fn upgraded_websocket_keeps_upload_and_download_limits() {
    let directory = tempfile::tempdir().unwrap();
    super::offline_tests::secure_directory(directory.path());
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        headers(&mut stream).await;
        stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
        let started = std::time::Instant::now();
        let mut frame = vec![0; 16_392];
        stream.read_exact(&mut frame).await.unwrap();
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "upgraded upload escaped limiter"
        );
        assert_eq!(&frame[..8], &[0x82, 0xfe, 0x40, 0, 0, 0, 0, 0]);
        stream.write_all(&[0x82, 126, 0x40, 0]).await.unwrap();
        stream.write_all(&frame[8..]).await.unwrap();
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stats = Arc::new(Stats::default());
    let inspection = TlsInspection::for_tests(
        directory.path().join("ca.json"),
        rustls::RootCertStore::empty(),
    )
    .unwrap();
    let handle = spawn_proxy_with_listeners(
        Settings {
            device_limits: vec![crate::config::DeviceLimit {
                ip: Ipv4Addr::LOCALHOST,
                upload_bytes_per_second: 32_768,
                download_bytes_per_second: 32_768,
            }],
            ..Settings::default()
        },
        CacheStore::new(directory.path().join("cache")),
        stats,
        inspection,
        vec![listener],
        true,
    )
    .unwrap();
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    stream.write_all(format!("GET http://127.0.0.1:{origin_port}/ws HTTP/1.1\r\nHost:127.0.0.1:{origin_port}\r\nConnection:Upgrade\r\nUpgrade:websocket\r\n\r\n").as_bytes()).await.unwrap();
    assert!(headers(&mut stream).await.starts_with(b"HTTP/1.1 101"));
    let mut frame = vec![b'x'; 16_392];
    frame[..8].copy_from_slice(&[0x82, 0xfe, 0x40, 0, 0, 0, 0, 0]);
    let started = std::time::Instant::now();
    stream.write_all(&frame).await.unwrap();
    let mut reply = vec![0; 16_388];
    timeout(Duration::from_secs(3), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(650),
        "upgraded download escaped limiter"
    );
    assert_eq!(&reply[..4], &[0x82, 126, 0x40, 0]);
    assert_eq!(&reply[4..], &frame[8..]);
    handle.stop().await;
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Explicit 60-second isolated loopback CONNECT/SOCKS/WebSocket soak"]
async fn sustained_connect_socks_websocket_cache_toggle_and_stop() {
    let directory = tempfile::tempdir().unwrap();
    super::offline_tests::secure_directory(directory.path());
    let mut origins = Vec::new();
    let mut servers = Vec::new();
    for websocket in [false, false, true] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        origins.push(listener.local_addr().unwrap().port());
        servers.push(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if websocket {
                headers(&mut stream).await;
                stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
            }
            loop {
                let mut buffer = vec![0; if websocket { 10 } else { 4 }];
                match stream.read_exact(&mut buffer).await {
                    Ok(_) => {
                        let reply: &[u8] = if websocket { &[0x81, 4, b'p', b'o', b'n', b'g'] } else { b"pong" };
                        if stream.write_all(reply).await.is_err() { break; }
                    }
                    Err(error) if matches!(error.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted) => break,
                    Err(error) => panic!("fixture read: {error}"),
                }
            }
        }));
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stats = Arc::new(Stats::default());
    let inspection = TlsInspection::for_tests(
        directory.path().join("ca.json"),
        rustls::RootCertStore::empty(),
    )
    .unwrap();
    let handle = spawn_proxy_with_listeners(
        Settings {
            https_mode: HttpsMode::Tunnel,
            ..Settings::default()
        },
        CacheStore::new(directory.path().join("cache")),
        stats.clone(),
        inspection,
        vec![listener],
        true,
    )
    .unwrap();
    let mut connect = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    connect
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost:127.0.0.1:{}\r\n\r\n",
                origins[0], origins[0]
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert!(headers(&mut connect).await.starts_with(b"HTTP/1.1 200"));
    let mut socks = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    socks.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    socks.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut command = vec![5, 1, 0, 1, 127, 0, 0, 1];
    command.extend_from_slice(&origins[1].to_be_bytes());
    socks.write_all(&command).await.unwrap();
    let mut reply = [0; 10];
    socks.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..2], &[5, 0]);
    let mut ws = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    ws.write_all(format!("GET http://127.0.0.1:{}/socket HTTP/1.1\r\nHost:127.0.0.1:{}\r\nConnection:Upgrade\r\nUpgrade:websocket\r\n\r\n",origins[2],origins[2]).as_bytes()).await.unwrap();
    assert!(headers(&mut ws).await.starts_with(b"HTTP/1.1 101"));
    let started = std::time::Instant::now();
    let mut rounds = 0;
    let mut previous = stats.snapshot();
    while started.elapsed() < Duration::from_secs(60) {
        handle.set_cache_enabled(rounds % 2 == 0);
        for (index, stream) in [&mut connect, &mut socks, &mut ws].into_iter().enumerate() {
            let request: &[u8] = if index == 2 {
                &[0x81, 0x84, 1, 2, 3, 4, 0x71, 0x6b, 0x6d, 0x63]
            } else {
                b"ping"
            };
            stream.write_all(request).await.unwrap();
            let mut reply = vec![0; if index == 2 { 6 } else { 4 }];
            timeout(Duration::from_secs(2), stream.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&reply[reply.len() - 4..], b"pong");
        }
        let current = stats.snapshot();
        assert!(
            current.upload_bytes > previous.upload_bytes
                && current.download_bytes > previous.download_bytes
        );
        assert_eq!(
            current
                .activity
                .iter()
                .filter(|entry| entry.ended_unix_ms.is_none())
                .count(),
            3
        );
        previous = current;
        rounds += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(rounds >= 60);
    timeout(Duration::from_secs(2), handle.stop())
        .await
        .unwrap();
    assert!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await.is_ok(),
        "stopped proxy must release listener"
    );
    for stream in [&mut connect, &mut socks, &mut ws] {
        let mut byte = [0];
        let result = timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .unwrap();
        assert!(!matches!(result, Ok(size) if size > 0));
    }
    for server in servers {
        timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
    assert!(stats
        .snapshot()
        .activity
        .iter()
        .all(|entry| entry.ended_unix_ms.is_some()));
    println!("60-second loopback soak: {rounds} exchanges per protocol, live counters, cache toggles, stopped transports and listener verified");
}

#[tokio::test]
async fn browser_connection_capacity_admits_more_than_32_live_tunnels() {
    let directory = tempfile::tempdir().unwrap();
    super::offline_tests::secure_directory(directory.path());
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut peers = tokio::task::JoinSet::new();
        for _ in 0..40 {
            let (mut stream, _) = origin.accept().await.unwrap();
            peers.spawn(async move {
                let mut byte = [0];
                while matches!(stream.read(&mut byte).await, Ok(1)) {
                    if stream.write_all(&byte).await.is_err() {
                        break;
                    }
                }
            });
        }
        while let Some(result) = peers.join_next().await {
            result.unwrap();
        }
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stats = Arc::new(Stats::default());
    let inspection = TlsInspection::for_tests(
        directory.path().join("ca.json"),
        rustls::RootCertStore::empty(),
    )
    .unwrap();
    let handle = spawn_proxy_with_listeners(
        Settings {
            https_mode: HttpsMode::Tunnel,
            ..Settings::default()
        },
        CacheStore::new(directory.path().join("cache")),
        stats.clone(),
        inspection,
        vec![listener],
        true,
    )
    .unwrap();
    let mut clients = Vec::new();
    for index in 0..40 {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream.write_all(format!("CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost:127.0.0.1:{origin_port}\r\n\r\n").as_bytes()).await.unwrap();
        let response = headers(&mut stream).await;
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "connection {} was not admitted",
            index + 1
        );
        clients.push(stream);
    }
    for stream in &mut clients {
        stream.write_all(b"x").await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), stream.read_u8())
                .await
                .unwrap()
                .unwrap(),
            b'x'
        );
    }
    assert_eq!(
        stats
            .snapshot()
            .activity
            .iter()
            .filter(|entry| entry.ended_unix_ms.is_none())
            .count(),
        40
    );
    handle.stop().await;
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn peer_capacity_rejects_129th_socket_records_metadata_and_recovers() {
    let directory = tempfile::tempdir().unwrap();
    super::offline_tests::secure_directory(directory.path());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stats = Arc::new(Stats::default());
    let inspection = TlsInspection::for_tests(
        directory.path().join("ca.json"),
        rustls::RootCertStore::empty(),
    )
    .unwrap();
    let handle = spawn_proxy_with_listeners(
        Settings::default(),
        CacheStore::new(directory.path().join("cache")),
        stats.clone(),
        inspection,
        vec![listener],
        true,
    )
    .unwrap();
    let mut clients = Vec::new();
    for _ in 0..128 {
        clients.push(
            TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap(),
        );
    }
    timeout(Duration::from_secs(2), async {
        while stats.snapshot().activity.len() < 128 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut rejected = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let result = timeout(Duration::from_secs(2), rejected.read_u8())
        .await
        .unwrap();
    assert!(
        result.is_err(),
        "129th peer socket must close without a payload exchange"
    );
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.rejected_connections, 1);
    assert_eq!(snapshot.total_requests, 0);
    assert_eq!(snapshot.activity.len(), 128);
    let latest = snapshot.latest_connection_rejection.unwrap();
    assert_eq!(latest.reason, ConnectionRejectionReason::PeerLimit);
    assert_eq!(latest.limit, 128);
    assert_eq!(latest.peer_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(latest.listener_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    drop(clients.pop());
    timeout(Duration::from_secs(2), async {
        while stats
            .snapshot()
            .activity
            .iter()
            .all(|entry| entry.ended_unix_ms.is_none())
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut recovered = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    recovered.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    timeout(Duration::from_secs(2), recovered.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, [5, 0]);
    assert_eq!(stats.snapshot().rejected_connections, 1);
    handle.stop().await;
    assert!(stats
        .snapshot()
        .activity
        .iter()
        .all(|entry| entry.ended_unix_ms.is_some()));
}
