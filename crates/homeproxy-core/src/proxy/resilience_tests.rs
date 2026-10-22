use super::tests::test_tls_inspection;
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::test(start_paused = true)]
async fn origin_only_trailer_progress_at_global_capacity_is_not_restart_evidence() {
    let stats = Arc::new(Stats::default());
    stats.connection_limits(MAX_CONNECTIONS, MAX_CONNECTIONS_PER_PEER);
    let limiter = ConnectionLimiter::default();
    let mut origins = Vec::new();
    let mut readers = Vec::new();
    let mut connections = Vec::new();
    let mut drivers = Vec::new();
    let idle = Duration::from_secs(60);
    let started = tokio::time::Instant::now();

    for index in 0..MAX_CONNECTIONS {
        let peer = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2 + (index / 128) as u8));
        let id = stats.begin_activity(peer, Ipv4Addr::LOCALHOST.into());
        let mut permit = limiter.try_acquire(peer).unwrap();
        permit.track(&stats, id);
        let cancellation = CancellationToken::new();
        permit.cancellation = Some(cancellation.clone());
        stats.connection_protocol(id, "http");
        let activity = permit.io_activity.clone();
        let (upstream, mut origin) = tokio::io::duplex(4096);
        // This outer observer proves Hyper consumed positive origin I/O. Its
        // callback never updates Stats or the production inactivity clock.
        let (observed, mut reads) = tokio::sync::mpsc::unbounded_channel();
        let observer = Arc::new(transport::Activity::new(move || {
            let _ = observed.send(());
        }));
        let upstream = transport::ProgressIo::new(upstream, activity.clone());
        let upstream = transport::ProgressIo::new(upstream, observer);
        let (mut sender, driver) = client_http1::handshake(TokioIo::new(upstream))
            .await
            .unwrap();
        let driver_cancellation = cancellation.clone();
        drivers.push(tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = driver_cancellation.cancelled() => {},
                result = driver => result.unwrap(),
            }
        }));
        let response = tokio::spawn(async move {
            sender
                .send_request(
                    Request::builder()
                        .uri("/progress")
                        .body(full_body(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        read_headers(&mut origin).await;
        origin
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nx-origin-progress: ",
            )
            .await
            .unwrap();
        let mut body = response.await.unwrap().into_body();
        let connection_stats = stats.clone();
        connections.push(tokio::spawn(async move {
            // The permit owns both telemetry and capacity until this single
            // body future expires. No client bytes or traffic accounting occur.
            let _permit = permit;
            let result = transport::bounded(
                async {
                    assert!(
                        body.frame().await.is_none(),
                        "an incomplete trailer must not produce a downstream frame"
                    );
                },
                &cancellation,
                idle,
                &activity,
            )
            .await;
            let expired = matches!(result, transport::BoundOutcome::Idle);
            if expired {
                connection_stats.connection_idle_closed(id);
            }
            expired
        }));
        while reads.try_recv().is_ok() {}
        origins.push(origin);
        readers.push(reads);
    }

    for round in 1..=5 {
        tokio::time::advance(Duration::from_secs(40)).await;
        for (origin, observed) in origins.iter_mut().zip(&mut readers) {
            origin.write_all(b"a").await.unwrap();
            observed
                .recv()
                .await
                .expect("Hyper reads the new origin byte");
        }
        assert!(connections
            .iter()
            .all(|connection| !connection.is_finished()));
        if round >= 3 {
            let before = stats.diagnostic_metrics(60, true);
            assert_eq!(before.active_connections, MAX_CONNECTIONS);
            assert!(before.consistent());
            let probe_peer = Ipv4Addr::LOCALHOST.into();
            assert!(matches!(
                limiter.try_acquire(probe_peer),
                Err(ConnectionRejectionReason::GlobalLimit)
            ));
            stats.connection_rejected(
                probe_peer,
                probe_peer,
                ConnectionRejectionReason::GlobalLimit,
                MAX_CONNECTIONS,
            );
            let after = stats.diagnostic_metrics(60, true);
            for metrics in [&before, &after] {
                assert!(metrics.consistent());
                assert_eq!(metrics.active_connections, MAX_CONNECTIONS);
                assert_eq!((metrics.upload_bytes, metrics.download_bytes), (0, 0));
                assert!(
                    metrics.over_age_ids.is_empty(),
                    "origin progress cannot be over-age evidence: {} IDs",
                    metrics.over_age_ids.len()
                );
                assert_eq!(metrics.over_age_idle_connections, 0);
                assert!(metrics
                    .live_connections
                    .as_ref()
                    .unwrap()
                    .iter()
                    .all(|connection| connection.idle_ms == 0));
                // At global capacity, neither free-capacity nor over-age
                // evidence can qualify these three failed admission probes.
                assert!(
                    !(metrics.active_connections < MAX_CONNECTIONS
                        && metrics.loopback_connections < MAX_CONNECTIONS_PER_PEER)
                );
            }
        }
    }
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(200)
    );
    assert_eq!(stats.diagnostic_metrics(60, false).rejected_connections, 3);
    assert_eq!(limiter.global.available_permits(), 0);

    tokio::time::advance(idle - Duration::from_secs(1)).await;
    assert!(connections
        .iter()
        .all(|connection| !connection.is_finished()));
    tokio::time::advance(Duration::from_secs(1)).await;
    for connection in connections {
        assert!(connection.await.unwrap(), "origin stall expires normally");
    }
    for driver in drivers {
        driver.await.unwrap();
    }
    let metrics = stats.diagnostic_metrics(60, true);
    assert_eq!(metrics.active_connections, 0);
    assert_eq!(metrics.idle_connections_closed, MAX_CONNECTIONS as u64);
    assert!(metrics.live_connections.unwrap().is_empty());
    assert_eq!(limiter.global.available_permits(), MAX_CONNECTIONS);
    assert!(limiter.per_peer.lock().unwrap().is_empty());
    assert!(limiter.try_acquire(Ipv4Addr::LOCALHOST.into()).is_ok());
    for mut origin in origins {
        assert_eq!(
            origin.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}

struct Fixture {
    handle: ProxyHandle,
    endpoint: SocketAddr,
    origin: TcpListener,
    stats: Arc<Stats>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    async fn new(protocol: ListenerProtocol) -> Self {
        Self::with_settings(
            protocol,
            Settings {
                https_mode: HttpsMode::Tunnel,
                socks5_enabled: true,
                tunnel_idle_timeout_seconds: 1,
                ..Settings::default()
            },
        )
        .await
    }

    async fn with_settings(protocol: ListenerProtocol, settings: Settings) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let stats = Arc::new(Stats::default());
        // Direct test fixture construction deliberately bypasses Settings::validate;
        // the production minimum of 60 seconds remains unchanged.
        let handle = spawn_proxy_with_bound_listeners(
            settings,
            CacheStore::new(directory.path().join("cache")),
            stats.clone(),
            test_tls_inspection(directory.path()),
            vec![BoundListener { listener, protocol }],
            true,
        )
        .unwrap();
        Self {
            handle,
            endpoint,
            origin,
            stats,
            _directory: directory,
        }
    }

    async fn connect(&self) -> (TcpStream, TcpStream) {
        let authority = self.origin.local_addr().unwrap();
        let mut client = TcpStream::connect(self.endpoint).await.unwrap();
        client
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let headers = read_headers(&mut client).await;
        assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
        let (origin, _) = timeout(IO_TIMEOUT, self.origin.accept())
            .await
            .unwrap()
            .unwrap();
        (client, origin)
    }

    async fn wait_for_active(&self, expected: u64) {
        timeout(IO_TIMEOUT, async {
            loop {
                if self.stats.snapshot().active_connections == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("live connection count must match socket ownership");
    }

    async fn assert_idle_closed(&self, client: &mut TcpStream, origin: &mut TcpStream) {
        assert_eof(client).await;
        assert_eof(origin).await;
        self.wait_for_active(0).await;
        let snapshot = self.stats.snapshot();
        assert_eq!(snapshot.idle_connections_closed, 1);
        assert!(snapshot.live_connections.is_empty());
        assert_eq!(
            snapshot.activity[0].error.as_deref(),
            Some("tunnel-idle-timeout")
        );
    }

    async fn stop(self) {
        timeout(IO_TIMEOUT, self.handle.stop())
            .await
            .expect("proxy stops after idle relay cleanup");
    }

    async fn assert_http_cleanup(&self, diagnostic: &str, idle_closes: u64) {
        self.wait_for_active(0).await;
        timeout(IO_TIMEOUT, async {
            while !self.handle.context.tasks.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("origin drivers release without stopping the listener");
        let snapshot = self.stats.snapshot();
        assert_eq!(snapshot.idle_connections_closed, idle_closes);
        assert!(snapshot.live_connections.is_empty());
        if idle_closes > 0 {
            assert_eq!(snapshot.activity[0].error.as_deref(), Some(diagnostic));
        }
        assert_eq!(
            self.handle.context.connections.global.available_permits(),
            MAX_CONNECTIONS
        );
    }
}

async fn read_headers(stream: &mut (impl AsyncRead + Unpin)) -> String {
    timeout(IO_TIMEOUT, async {
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            assert!(headers.len() < MAX_HEADER_BUFFER);
            headers.push(stream.read_u8().await.unwrap());
        }
        String::from_utf8(headers).unwrap()
    })
    .await
    .expect("complete upgrade response headers")
}

async fn start_http(fixture: &Fixture, upload: bool) -> (TcpStream, TcpStream) {
    let authority = fixture.origin.local_addr().unwrap();
    let mut client = TcpStream::connect(fixture.endpoint).await.unwrap();
    client
        .write_all(
            format!(
                "{} http://{authority}/stall HTTP/1.1\r\nHost: {authority}\r\n{}\r\n",
                if upload { "POST" } else { "GET" },
                if upload {
                    "Content-Length: 1048576\r\n"
                } else {
                    ""
                },
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (mut origin, _) = timeout(IO_TIMEOUT, fixture.origin.accept())
        .await
        .unwrap()
        .unwrap();
    let headers = read_headers(&mut origin).await;
    assert!(headers.contains("/stall HTTP/1.1"), "{headers}");
    (client, origin)
}

#[tokio::test]
async fn http_stalled_origin_body_expires_and_reclaims_real_capacity() {
    let fixture = Fixture::new(ListenerProtocol::HttpMultiplexed).await;
    let limiter = fixture.handle.context.connections.clone();
    let peer = fixture.endpoint.ip();
    let reservations: Vec<_> = (1..MAX_CONNECTIONS_PER_PEER)
        .map(|_| limiter.try_acquire(peer).unwrap())
        .collect();
    let (mut client, mut origin) = start_http(&fixture, false).await;
    origin
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nCache-Control: no-store\r\n\r\nx",
        )
        .await
        .unwrap();
    assert!(read_headers(&mut client).await.starts_with("HTTP/1.1 200"));
    assert_eq!(client.read_u8().await.unwrap(), b'x');
    assert!(matches!(
        limiter.try_acquire(peer),
        Err(ConnectionRejectionReason::PeerLimit)
    ));
    assert_eof(&mut client).await;
    assert_eof(&mut origin).await;
    fixture.wait_for_active(0).await;
    let snapshot = fixture.stats.snapshot();
    assert_eq!(snapshot.idle_connections_closed, 1);
    assert!(snapshot.live_connections.is_empty());
    assert_eq!(
        snapshot.activity[0].error.as_deref(),
        Some("HTTP-idle-timeout")
    );
    assert_eq!(
        limiter.global.available_permits(),
        MAX_CONNECTIONS - reservations.len()
    );
    drop(
        limiter
            .try_acquire(peer)
            .expect("HTTP expiration frees peer capacity"),
    );
    drop(reservations);
    fixture.stop().await;
}

async fn assert_eof(stream: &mut (impl AsyncRead + Unpin)) {
    let mut byte = [0];
    assert_eq!(
        timeout(IO_TIMEOUT, stream.read(&mut byte))
            .await
            .expect("idle relay closes socket")
            .unwrap(),
        0,
        "socket must close without extra payload"
    );
}

#[tokio::test]
async fn http_request_upload_stall_expires_and_client_drop_cancels_origin() {
    for drop_client in [false, true] {
        let fixture = Fixture::new(ListenerProtocol::HttpMultiplexed).await;
        let (mut client, mut origin) = start_http(&fixture, true).await;
        transfer(&mut client, &mut origin, b"partial upload").await;
        if drop_client {
            drop(client);
        } else {
            assert_eof(&mut client).await;
        }
        assert_eof(&mut origin).await;
        fixture
            .assert_http_cleanup("HTTP-idle-timeout", if drop_client { 0 } else { 1 })
            .await;
        fixture.stop().await;
    }
}

#[tokio::test]
async fn http_one_way_upload_and_download_outlive_multiple_idle_windows() {
    for upload in [true, false] {
        let fixture = Fixture::new(ListenerProtocol::HttpMultiplexed).await;
        let (mut client, mut origin) = start_http(&fixture, upload).await;
        if !upload {
            origin.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nCache-Control: no-store\r\n\r\n").await.unwrap();
            assert!(read_headers(&mut client).await.starts_with("HTTP/1.1 200"));
        }
        let started = tokio::time::Instant::now();
        for sequence in 0..12u8 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let payload = [sequence, 0, 0xff, b'\r', b'\n'];
            if upload {
                transfer(&mut client, &mut origin, &payload).await;
            } else {
                transfer(&mut origin, &mut client, &payload).await;
            }
            assert_eq!(fixture.stats.snapshot().active_connections, 1);
            assert_eq!(fixture.stats.snapshot().idle_connections_closed, 0);
        }
        assert!(started.elapsed() >= Duration::from_secs(2));
        let stopped = tokio::time::Instant::now();
        assert_eof(&mut client).await;
        assert!(stopped.elapsed() >= Duration::from_millis(900));
        assert_eof(&mut origin).await;
        fixture.assert_http_cleanup("HTTP-idle-timeout", 1).await;
        fixture.stop().await;
    }
}

#[tokio::test]
async fn http_nonreading_client_download_expires_under_socket_backpressure() {
    let fixture = Fixture::new(ListenerProtocol::HttpMultiplexed).await;
    let (mut client, mut origin) = start_http(&fixture, false).await;
    socket2::SockRef::from(&client)
        .set_recv_buffer_size(4096)
        .unwrap();
    origin
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 67108864\r\nCache-Control: no-store\r\n\r\n",
        )
        .await
        .unwrap();
    assert!(read_headers(&mut client).await.starts_with("HTTP/1.1 200"));
    // More than both TCP buffers and Hyper's bounded read-ahead. The client
    // deliberately never consumes body bytes while the origin keeps writing.
    let writer = tokio::spawn(async move {
        let chunk = [b'x'; 64 * 1024];
        for _ in 0..1024 {
            if origin.write_all(&chunk).await.is_err() {
                return;
            }
        }
        panic!("nonreading client must backpressure this response");
    });
    fixture.wait_for_active(0).await;
    timeout(IO_TIMEOUT, writer)
        .await
        .expect("client idle closure releases backpressured origin writer")
        .unwrap();
    fixture.assert_http_cleanup("HTTP-idle-timeout", 1).await;
    drop(client);
    fixture.stop().await;
}

#[tokio::test]
async fn http_partial_cache_fill_is_removed_on_idle_and_client_disconnect() {
    for drop_client in [false, true] {
        let fixture = Fixture::with_settings(
            ListenerProtocol::HttpMultiplexed,
            Settings {
                tunnel_idle_timeout_seconds: 1,
                cache_enabled: true,
                response_buffer_limit_mib: 0,
                compression_preset: crate::config::CompressionPreset::Off,
                ..Settings::default()
            },
        )
        .await;
        let authority = fixture.origin.local_addr().unwrap();
        let request = Request::builder()
            .uri(format!("http://{authority}/stall"))
            .body(())
            .unwrap();
        let key = cache_policy::key(&request, &fixture.handle.context, false);
        let cache = fixture.handle.context.cache.clone();
        let (mut client, mut origin) = start_http(&fixture, false).await;
        origin.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nContent-Type: application/octet-stream\r\nCache-Control: public, max-age=60\r\n\r\nx").await.unwrap();
        let headers = read_headers(&mut client).await;
        assert!(
            headers.contains("cache-status: HomeProxy; fwd=miss"),
            "{headers}"
        );
        assert_eq!(client.read_u8().await.unwrap(), b'x');
        let mut flight = match cache.fills.claim(&key) {
            FillClaim::Follower(flight) => flight,
            _ => panic!("test must exercise a live TeeBody cache fill"),
        };
        assert!(std::fs::read_dir(cache.root()).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".cache-tmp-")));
        if drop_client {
            drop(client);
        } else {
            assert_eof(&mut client).await;
        }
        assert_eof(&mut origin).await;
        fixture
            .assert_http_cleanup("HTTP-idle-timeout", if drop_client { 0 } else { 1 })
            .await;
        timeout(IO_TIMEOUT, flight.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*flight.borrow(), "partial fill followers are released");
        assert!(matches!(cache.fills.claim(&key), FillClaim::Leader(_)));
        assert!(
            cache_policy::cached_key(&request, &fixture.handle.context, false)
                .await
                .is_none(),
            "partial representation is not discoverable by production cache lookup"
        );
        assert!(
            cache.get(&key).await.is_none(),
            "partial body cannot become a cache HIT"
        );
        assert!(!std::fs::read_dir(cache.root()).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".cache-tmp-")));
        fixture.stop().await;
    }
}

#[tokio::test]
async fn http_buffered_origin_progress_renews_idle_before_downstream_response_exists() {
    let fixture = Fixture::with_settings(
        ListenerProtocol::HttpMultiplexed,
        Settings {
            tunnel_idle_timeout_seconds: 1,
            cache_enabled: true,
            response_buffer_limit_mib: 1,
            compression_preset: crate::config::CompressionPreset::Off,
            ..Settings::default()
        },
    )
    .await;
    let (mut client, mut origin) = start_http(&fixture, false).await;
    origin.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 60\r\nContent-Type: application/octet-stream\r\nCache-Control: public, max-age=60\r\n\r\n").await.unwrap();
    let mut expected = Vec::new();
    for sequence in 0..12u8 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let payload = [sequence, 0, 0xff, b'\r', b'\n'];
        origin.write_all(&payload).await.unwrap();
        expected.extend_from_slice(&payload);
        assert_eq!(fixture.stats.snapshot().idle_connections_closed, 0);
        assert_eq!(fixture.stats.snapshot().active_connections, 1);
    }
    let headers = read_headers(&mut client).await;
    assert!(
        headers.contains("cache-status: HomeProxy; fwd=miss; stored"),
        "{headers}"
    );
    let mut received = [0; 60];
    timeout(IO_TIMEOUT, client.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.as_slice(), expected);
    let request = Request::builder()
        .uri(format!(
            "http://{}/stall",
            fixture.origin.local_addr().unwrap()
        ))
        .body(())
        .unwrap();
    let key = cache_policy::cached_key(&request, &fixture.handle.context, false)
        .await
        .expect("completed representation is discoverable by production cache lookup");
    let entry = fixture
        .handle
        .context
        .cache
        .get(&key)
        .await
        .expect("complete active response is cached");
    assert_eq!(
        entry.body.collect().await.unwrap().to_bytes().as_ref(),
        expected
    );
    assert_eof(&mut client).await;
    assert_eof(&mut origin).await;
    fixture.assert_http_cleanup("HTTP-idle-timeout", 1).await;
    fixture.stop().await;
}

async fn transfer(source: &mut TcpStream, destination: &mut TcpStream, payload: &[u8]) {
    timeout(IO_TIMEOUT, async {
        source.write_all(payload).await.unwrap();
        let mut received = vec![0; payload.len()];
        destination.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload, "relay preserves exact socket bytes");
    })
    .await
    .expect("active relay forwards payload");
}

async fn start_inspected(
    upload: bool,
) -> (
    Fixture,
    tokio_rustls::client::TlsStream<TcpStream>,
    tokio_rustls::server::TlsStream<TcpStream>,
) {
    start_inspected_with_cache(upload, false).await
}

async fn start_inspected_with_cache(
    upload: bool,
    cache_enabled: bool,
) -> (
    Fixture,
    tokio_rustls::client::TlsStream<TcpStream>,
    tokio_rustls::server::TlsStream<TcpStream>,
) {
    use rcgen::{CertificateParams, KeyPair};
    use rustls::{
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
        ClientConfig, RootCertStore, ServerConfig,
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    let origin_key = KeyPair::generate().unwrap();
    let origin_certificate = CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&origin_key)
        .unwrap();
    let origin_acceptor = TlsAcceptor::from(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![origin_certificate.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(origin_key.serialize_der())),
            )
            .unwrap(),
    ));
    let mut upstream_roots = RootCertStore::empty();
    upstream_roots
        .add(origin_certificate.der().clone())
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let inspection =
        TlsInspection::for_tests(directory.path().join("authority.json"), upstream_roots).unwrap();
    let mut client_roots = RootCertStore::empty();
    client_roots.add(inspection.root_certificate_der()).unwrap();
    let client_connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(client_roots)
            .with_no_client_auth(),
    ));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let authority = origin.local_addr().unwrap();
    let stats = Arc::new(Stats::default());
    let handle = spawn_proxy_with_bound_listeners(
        Settings {
            tunnel_idle_timeout_seconds: 1,
            https_mode: HttpsMode::Inspect,
            https_client_trust_acknowledged: true,
            https_inspect_hosts: vec!["127.0.0.1".into()],
            cache_enabled,
            response_buffer_limit_mib: 0,
            compression_preset: crate::config::CompressionPreset::Off,
            ..Settings::default()
        },
        CacheStore::new(directory.path().join("cache")),
        stats.clone(),
        inspection,
        vec![BoundListener {
            listener,
            protocol: ListenerProtocol::HttpMultiplexed,
        }],
        true,
    )
    .unwrap();
    let fixture = Fixture {
        handle,
        endpoint,
        origin,
        stats,
        _directory: directory,
    };
    let mut client = TcpStream::connect(endpoint).await.unwrap();
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(read_headers(&mut client).await.starts_with("HTTP/1.1 200"));
    let mut client = timeout(
        IO_TIMEOUT,
        client_connector.connect(ServerName::try_from("127.0.0.1").unwrap(), client),
    )
    .await
    .unwrap()
    .unwrap();
    client
        .write_all(
            format!(
                "{} /stall HTTP/1.1\r\nHost: {authority}\r\n{}\r\n",
                if upload { "POST" } else { "GET" },
                if upload {
                    "Content-Length: 1048576\r\n"
                } else {
                    ""
                }
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (origin, _) = timeout(IO_TIMEOUT, fixture.origin.accept())
        .await
        .unwrap()
        .unwrap();
    let mut origin = timeout(IO_TIMEOUT, origin_acceptor.accept(origin))
        .await
        .unwrap()
        .unwrap();
    assert!(read_headers(&mut origin).await.contains("/stall HTTP/1.1"));
    assert_eq!(
        fixture.stats.snapshot().live_connections[0].protocol,
        "inspect"
    );
    (fixture, client, origin)
}

// Idle closure drops TLS without close_notify, so a verified TLS client reports
// UnexpectedEof rather than plaintext EOF. Both prove the transport was closed.
async fn assert_tls_closed(stream: &mut (impl AsyncRead + Unpin)) {
    let result = timeout(IO_TIMEOUT, stream.read(&mut [0]))
        .await
        .expect("idle Inspect closes TLS socket");
    assert!(
        matches!(result, Ok(0))
            || matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::UnexpectedEof),
        "{result:?}"
    );
}

#[tokio::test]
async fn inspected_upload_and_origin_body_stalls_release_both_tls_connections() {
    for upload in [false, true] {
        let (fixture, mut client, mut origin) = start_inspected(upload).await;
        if upload {
            client.write_all(b"x").await.unwrap();
            assert_eq!(
                timeout(IO_TIMEOUT, origin.read_u8())
                    .await
                    .unwrap()
                    .unwrap(),
                b'x'
            );
        } else {
            origin.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nCache-Control: no-store\r\n\r\nx").await.unwrap();
            assert!(read_headers(&mut client).await.starts_with("HTTP/1.1 200"));
            assert_eq!(client.read_u8().await.unwrap(), b'x');
        }
        assert_tls_closed(&mut client).await;
        assert_tls_closed(&mut origin).await;
        fixture.assert_http_cleanup("HTTPS-idle-timeout", 1).await;
        fixture.stop().await;
    }
}

#[tokio::test]
async fn inspected_one_way_upload_and_download_outlive_multiple_idle_windows() {
    for upload in [true, false] {
        let (fixture, mut client, mut origin) = start_inspected(upload).await;
        if !upload {
            origin.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nCache-Control: no-store\r\n\r\n").await.unwrap();
            assert!(read_headers(&mut client).await.starts_with("HTTP/1.1 200"));
        }
        let started = tokio::time::Instant::now();
        for sequence in 0..12u8 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let payload = [sequence, 0, 0xff];
            let mut received = [0; 3];
            timeout(IO_TIMEOUT, async {
                if upload {
                    client.write_all(&payload).await.unwrap();
                    origin.read_exact(&mut received).await.unwrap();
                } else {
                    origin.write_all(&payload).await.unwrap();
                    client.read_exact(&mut received).await.unwrap();
                }
            })
            .await
            .unwrap();
            assert_eq!(received, payload);
            assert_eq!(fixture.stats.snapshot().active_connections, 1);
            assert_eq!(fixture.stats.snapshot().idle_connections_closed, 0);
        }
        assert!(started.elapsed() >= Duration::from_secs(2));
        let stopped = tokio::time::Instant::now();
        assert_tls_closed(&mut client).await;
        assert!(stopped.elapsed() >= Duration::from_millis(900));
        assert_tls_closed(&mut origin).await;
        fixture.assert_http_cleanup("HTTPS-idle-timeout", 1).await;
        fixture.stop().await;
    }
}

#[tokio::test]
async fn inspected_nonreading_client_download_expires_under_tls_backpressure() {
    let (fixture, mut client, mut origin) = start_inspected(false).await;
    socket2::SockRef::from(client.get_ref().0)
        .set_recv_buffer_size(4096)
        .unwrap();
    origin
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 67108864\r\nCache-Control: no-store\r\n\r\n",
        )
        .await
        .unwrap();
    assert!(read_headers(&mut client).await.starts_with("HTTP/1.1 200"));
    let writer = tokio::spawn(async move {
        let chunk = [b'x'; 64 * 1024];
        for _ in 0..1024 {
            if origin.write_all(&chunk).await.is_err() {
                return;
            }
        }
        panic!("nonreading TLS client must backpressure this response");
    });
    fixture.wait_for_active(0).await;
    timeout(IO_TIMEOUT, writer)
        .await
        .expect("Inspect idle closure releases origin writer")
        .unwrap();
    fixture.assert_http_cleanup("HTTPS-idle-timeout", 1).await;
    drop(client);
    fixture.stop().await;
}

#[tokio::test]
async fn inspected_partial_cache_fill_is_removed_on_idle_and_client_disconnect() {
    for drop_client in [false, true] {
        let (fixture, mut client, mut origin) = start_inspected_with_cache(false, true).await;
        let request = Request::builder()
            .uri(format!(
                "https://{}/stall",
                fixture.origin.local_addr().unwrap()
            ))
            .body(())
            .unwrap();
        let key = cache_policy::key(&request, &fixture.handle.context, false);
        let cache = fixture.handle.context.cache.clone();
        origin.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nContent-Type: application/octet-stream\r\nCache-Control: public, max-age=60\r\n\r\nx").await.unwrap();
        let headers = read_headers(&mut client).await;
        assert!(
            headers.contains("cache-status: HomeProxy; fwd=miss"),
            "{headers}"
        );
        assert_eq!(client.read_u8().await.unwrap(), b'x');
        let mut flight = match cache.fills.claim(&key) {
            FillClaim::Follower(flight) => flight,
            _ => panic!("test must exercise inspected TeeBody cache fill"),
        };
        assert!(std::fs::read_dir(cache.root()).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".cache-tmp-")));
        if drop_client {
            drop(client);
        } else {
            assert_tls_closed(&mut client).await;
        }
        assert_tls_closed(&mut origin).await;
        fixture
            .assert_http_cleanup("HTTPS-idle-timeout", if drop_client { 0 } else { 1 })
            .await;
        timeout(IO_TIMEOUT, flight.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*flight.borrow());
        assert!(matches!(cache.fills.claim(&key), FillClaim::Leader(_)));
        assert!(
            cache_policy::cached_key(&request, &fixture.handle.context, false)
                .await
                .is_none(),
            "partial representation is not discoverable by production cache lookup"
        );
        assert!(
            cache.get(&key).await.is_none(),
            "partial inspected body cannot become a cache HIT"
        );
        assert!(!std::fs::read_dir(cache.root()).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".cache-tmp-")));
        fixture.stop().await;
    }
}

#[tokio::test]
async fn http_and_inspected_body_cancellation_release_origins_without_idle_count() {
    let fixture = Fixture::new(ListenerProtocol::HttpMultiplexed).await;
    let (mut client, mut origin) = start_http(&fixture, false).await;
    origin
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nCache-Control: no-store\r\n\r\nx",
        )
        .await
        .unwrap();
    read_headers(&mut client).await;
    assert_eq!(client.read_u8().await.unwrap(), b'x');
    let stats = fixture.stats.clone();
    fixture.stop().await;
    assert_eof(&mut client).await;
    assert_eof(&mut origin).await;
    assert_eq!(stats.snapshot().idle_connections_closed, 0);
    assert_eq!(stats.snapshot().active_connections, 0);

    let (fixture, mut client, mut origin) = start_inspected(false).await;
    origin
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nCache-Control: no-store\r\n\r\nx",
        )
        .await
        .unwrap();
    read_headers(&mut client).await;
    assert_eq!(client.read_u8().await.unwrap(), b'x');
    let stats = fixture.stats.clone();
    fixture.stop().await;
    assert_tls_closed(&mut client).await;
    assert_tls_closed(&mut origin).await;
    assert_eq!(stats.snapshot().idle_connections_closed, 0);
    assert_eq!(stats.snapshot().active_connections, 0);
}

#[tokio::test]
async fn connect_idle_expiration_releases_upgraded_permit_and_real_capacity() {
    let fixture = Fixture::new(ListenerProtocol::HttpMultiplexed).await;
    let peer = fixture.endpoint.ip();
    let limiter = fixture.handle.context.connections.clone();
    let reservations: Vec<_> = (1..MAX_CONNECTIONS_PER_PEER)
        .map(|_| limiter.try_acquire(peer).unwrap())
        .collect();
    let (mut client, mut origin) = fixture.connect().await;
    fixture.wait_for_active(1).await;
    assert_eq!(
        fixture.stats.snapshot().live_connections[0].protocol,
        "connect"
    );
    assert!(matches!(
        limiter.try_acquire(peer),
        Err(ConnectionRejectionReason::PeerLimit)
    ));
    // The HTTP connection future completes on upgrade; the live socket and its
    // capacity must still be retained by the relay, including after history ends.
    let id = fixture.stats.snapshot().live_connections[0].id;
    fixture.stats.finish_activity(id, None);
    assert_eq!(fixture.stats.snapshot().active_connections, 1);
    assert!(matches!(
        limiter.try_acquire(peer),
        Err(ConnectionRejectionReason::PeerLimit)
    ));
    fixture.assert_idle_closed(&mut client, &mut origin).await;
    assert_eq!(
        limiter.global.available_permits(),
        MAX_CONNECTIONS - reservations.len()
    );
    let released = limiter
        .try_acquire(peer)
        .expect("idle timeout frees peer slot");
    drop(released);
    // Admission is also proved through a second actual upgraded connection.
    let (mut next_client, mut next_origin) = fixture.connect().await;
    transfer(&mut next_client, &mut next_origin, b"capacity recovered").await;
    fixture.wait_for_active(1).await;
    drop(reservations);
    fixture.stop().await;
    assert_eof(&mut next_client).await;
    assert_eof(&mut next_origin).await;
}

#[tokio::test]
async fn connect_one_way_traffic_outlives_idle_periods_then_expires_without_corruption() {
    // Both directions independently reset inactivity; the opposite direction
    // stays silent throughout each run, so this cannot pass via echo traffic.
    for upload in [true, false] {
        let fixture = Fixture::new(ListenerProtocol::HttpMultiplexed).await;
        let (mut client, mut origin) = fixture.connect().await;
        let started = tokio::time::Instant::now();
        for sequence in 0..12u8 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let payload = [sequence, 0, 0xff, b'\r', b'\n'];
            if upload {
                transfer(&mut client, &mut origin, &payload).await;
            } else {
                transfer(&mut origin, &mut client, &payload).await;
            }
            let snapshot = fixture.stats.snapshot();
            assert_eq!(snapshot.active_connections, 1);
            assert_eq!(snapshot.idle_connections_closed, 0);
            assert!(snapshot.live_connections[0].idle_ms < 1000);
        }
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert!(fixture.stats.snapshot().live_connections[0].age_ms >= 2000);
        let stopped = tokio::time::Instant::now();
        fixture.assert_idle_closed(&mut client, &mut origin).await;
        assert!(
            stopped.elapsed() >= Duration::from_millis(900),
            "expiration must measure inactivity after the final payload"
        );
        assert_eq!(
            fixture
                .handle
                .context
                .connections
                .global
                .available_permits(),
            MAX_CONNECTIONS
        );
        fixture.stop().await;
    }
}

#[tokio::test]
async fn dedicated_socks_tcp_idle_expiration_closes_both_sockets_and_releases_capacity() {
    let fixture = Fixture::new(ListenerProtocol::Socks5Dedicated).await;
    let mut client = TcpStream::connect(fixture.endpoint).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    timeout(IO_TIMEOUT, client.read_exact(&mut method))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(method, [5, 0]);
    let [high, low] = fixture.origin.local_addr().unwrap().port().to_be_bytes();
    client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, high, low])
        .await
        .unwrap();
    let mut reply = [0; 10];
    timeout(IO_TIMEOUT, client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..2], &[5, 0]);
    let (mut origin, _) = timeout(IO_TIMEOUT, fixture.origin.accept())
        .await
        .unwrap()
        .unwrap();
    transfer(&mut client, &mut origin, b"SOCKS\0payload").await;
    transfer(&mut origin, &mut client, b"unchanged\xff").await;
    let live = fixture.stats.snapshot();
    assert_eq!(live.active_connections, 1);
    assert_eq!(live.live_connections[0].protocol, "socks5");
    fixture.assert_idle_closed(&mut client, &mut origin).await;
    assert_eq!(
        fixture
            .handle
            .context
            .connections
            .global
            .available_permits(),
        MAX_CONNECTIONS
    );
    fixture.stop().await;
}

#[tokio::test]
async fn websocket_idle_expiration_preserves_frames_and_releases_upgrade_capacity() {
    let fixture = Fixture::new(ListenerProtocol::HttpMultiplexed).await;
    let authority = fixture.origin.local_addr().unwrap();
    let client_upgrade = async {
        let mut client = TcpStream::connect(fixture.endpoint).await.unwrap();
        client.write_all(format!("GET http://{authority}/socket HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
        let headers = read_headers(&mut client).await;
        assert!(headers.starts_with("HTTP/1.1 101"), "{headers}");
        assert!(headers.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        client
    };
    let origin_upgrade = async {
        let (mut origin, _) = fixture.origin.accept().await.unwrap();
        let headers = read_headers(&mut origin).await;
        assert!(headers.starts_with("GET /socket HTTP/1.1"), "{headers}");
        origin.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
        origin
    };
    let (mut client, mut origin) = timeout(IO_TIMEOUT, async {
        tokio::join!(client_upgrade, origin_upgrade)
    })
    .await
    .expect("both real WebSocket upgrade handshakes complete");
    // Valid masked client frame for "ping", then an unmasked server frame.
    transfer(
        &mut client,
        &mut origin,
        b"\x82\x84\x01\x02\x03\x04\x71\x6b\x6d\x63",
    )
    .await;
    transfer(&mut origin, &mut client, b"\x82\x04pong").await;
    let live = fixture.stats.snapshot();
    assert_eq!(live.active_connections, 1);
    assert_eq!(live.live_connections[0].protocol, "websocket");
    fixture.assert_idle_closed(&mut client, &mut origin).await;
    assert_eq!(
        fixture
            .handle
            .context
            .connections
            .global
            .available_permits(),
        MAX_CONNECTIONS
    );
    fixture.stop().await;
}

fn untrusting_client_config() -> Arc<rustls::ClientConfig> {
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
    )
}

async fn assert_next_connect_tunnels(proxy_port: u16, origin: &TcpListener, origin_port: u16) {
    let mut tunnel = connect_through_host(proxy_port, origin, origin_port).await;
    let (mut upstream, _) = timeout(IO_TIMEOUT, origin.accept()).await.unwrap().unwrap();
    tunnel.write_all(b"opaque-client-bytes").await.unwrap();
    let mut received = [0u8; 19];
    timeout(IO_TIMEOUT, upstream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, b"opaque-client-bytes");
}

async fn connect_through_host(
    proxy_port: u16,
    origin: &TcpListener,
    origin_port: u16,
) -> TcpStream {
    let host = origin.local_addr().unwrap().ip();
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
        .await
        .unwrap();
    stream
        .write_all(
            format!("CONNECT {host}:{origin_port} HTTP/1.1\r\nHost: {host}:{origin_port}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(
            timeout(IO_TIMEOUT, stream.read_u8())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));
    stream
}

async fn wait_for_close(stream: &mut TcpStream) {
    let mut sink = [0u8; 4096];
    loop {
        match timeout(HEADER_READ_TIMEOUT + IO_TIMEOUT, stream.read(&mut sink))
            .await
            .expect("inspected handshake must end within its deadline")
        {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[tokio::test]
async fn only_clients_that_saw_our_certificate_get_the_fail_open_tunnel() {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let rejecting_origin = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .unwrap();
    let rejecting_port = rejecting_origin.local_addr().unwrap().port();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let directory = tempfile::tempdir().unwrap();
    let stats = Arc::new(Stats::default());
    let handle = spawn_proxy_with_listeners(
        Settings {
            cache_enabled: false,
            https_mode: HttpsMode::Inspect,
            https_inspection_scope: crate::HttpsInspectionScope::AllSupportedHosts,
            https_client_trust_acknowledged: true,
            ..Settings::default()
        },
        CacheStore::new(directory.path().join("cache")),
        stats.clone(),
        test_tls_inspection(directory.path()),
        vec![listener],
        true,
    )
    .unwrap();

    // Browser preconnects that close or idle before any ClientHello are not
    // evidence of an untrusted CA and must keep inspection (and the cache).
    drop(connect_through_host(port, &origin, origin_port).await);
    let mut idle = connect_through_host(port, &origin, origin_port).await;
    wait_for_close(&mut idle).await;
    let still_inspected = connect_through_host(port, &origin, origin_port).await;
    assert!(
        timeout(Duration::from_millis(300), origin.accept())
            .await
            .is_err(),
        "an abandoned preconnect must not switch the host to a raw tunnel"
    );
    drop(still_inspected);

    // A client that received our certificate and then went silent is remembered.
    let mut silent = connect_through_host(port, &origin, origin_port).await;
    let mut hello = Vec::new();
    rustls::ClientConnection::new(untrusting_client_config(), "127.0.0.1".try_into().unwrap())
        .unwrap()
        .write_tls(&mut hello)
        .unwrap();
    silent.write_all(&hello).await.unwrap();
    wait_for_close(&mut silent).await;
    assert_next_connect_tunnels(port, &origin, origin_port).await;

    // A client that rejects our certificate with a TLS alert is remembered too.
    let rejecting = connect_through_host(port, &rejecting_origin, rejecting_port).await;
    let connector = tokio_rustls::TlsConnector::from(untrusting_client_config());
    assert!(timeout(
        IO_TIMEOUT,
        connector.connect("127.0.0.2".try_into().unwrap(), rejecting)
    )
    .await
    .unwrap()
    .is_err());
    // The proxy records the rejection after reading the alert.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_next_connect_tunnels(port, &rejecting_origin, rejecting_port).await;

    // A client-first protocol that is not TLS (e.g. obfuscated MTProto on 443)
    // falls back to a raw tunnel on its next CONNECT, as before 1.2.8.
    let other_protocol = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
        .await
        .unwrap();
    let other_port = other_protocol.local_addr().unwrap().port();
    let mut not_tls = connect_through_host(port, &other_protocol, other_port).await;
    not_tls
        .write_all(b"\xef\xef\xef\xef not a client hello")
        .await
        .unwrap();
    wait_for_close(&mut not_tls).await;
    assert_next_connect_tunnels(port, &other_protocol, other_port).await;
    handle.stop().await;
}
