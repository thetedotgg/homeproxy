//! Production destination policy stays enabled; only the final socket dial is mapped.
use super::*;
async fn read_headers(stream: &mut TcpStream) -> String {
    timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
        }
        String::from_utf8(bytes).unwrap()
    })
    .await
    .unwrap()
}

pub(super) async fn context(directory: &std::path::Path, settings: Settings) -> ProxyContext {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    ProxyContext {
        cache_enabled: Arc::new(AtomicBool::new(false)),
        bandwidth: BandwidthLimits::default(),
        activity_id: 0,
        listener_address: None,
        connection_permit: None,
        resolver: Resolver::default(),
        settings,
        cache: CacheStore::new(directory.join("cache")),
        stats: Arc::new(Stats::default()),
        auth: Arc::new(DigestAuth::default()),
        transform_slots: Arc::new(Semaphore::new(1)),
        buffer_budget: Arc::new(Semaphore::new(MAX_BUFFERED_BYTES)),
        host_addresses: Arc::new(HashSet::new()),
        tls_inspection: TlsInspection::for_tests(
            directory.join("ca.json"),
            rustls::RootCertStore::empty(),
        )
        .unwrap(),
        inspection_bypass: InspectionBypass::default(),
        allow_private_destinations: false,
        cancellation: CancellationToken::new(),
        tasks: TaskTracker::new(),
        connections: ConnectionLimiter::default(),
        udp_associations: udp::association_limiter(),
    }
}

// A real HTTP socket with an explicit remote peer exercises production auth and
// admission. Native coverage below additionally uses the real OS peer address.
async fn proxy_client(
    context: ProxyContext,
    native_ip: Option<Ipv4Addr>,
) -> (TcpStream, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((native_ip.unwrap_or(Ipv4Addr::LOCALHOST), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    if native_ip.is_some() {
        let task = tokio::spawn(async move {
            accept_loop(
                BoundListener {
                    listener,
                    protocol: ListenerProtocol::HttpMultiplexed,
                },
                context,
            )
            .await
            .unwrap();
        });
        let client = TcpStream::connect(address).await.unwrap();
        assert!(!client.local_addr().unwrap().ip().is_loopback());
        return (client, task);
    }
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let peer: SocketAddr = "192.168.1.123:49152".parse().unwrap();
        assert!(peer_is_allowed(peer.ip()));
        let mut context = context;
        context.connection_permit = Some(Arc::new(
            context.connections.try_acquire(peer.ip()).unwrap(),
        ));
        let service = service_fn(move |request| {
            let context = context.clone();
            async move { Ok::<_, Infallible>(handle_request(request, peer, context).await) }
        });
        let _ = server_http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await;
    });
    (TcpStream::connect(address).await.unwrap(), task)
}

async fn production_service_ports(native_ip: Option<Ipv4Addr>) {
    let public_ip = "93.184.216.12";
    for port in [80, 5060, 8080] {
        for connect in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let destination: SocketAddr = format!("{public_ip}:{port}").parse().unwrap();
            assert!(destination_is_public(destination.ip()));
            let context = context(
                directory.path(),
                Settings {
                    https_mode: HttpsMode::Inspect,
                    https_client_trust_acknowledged: true,
                    https_inspect_hosts: vec!["example.com".into()],
                    lan_auth_enabled: false,
                    cache_enabled: false,
                    ..Settings::default()
                },
            )
            .await;
            context
                .resolver
                .map_test_dial(destination, origin.local_addr().unwrap());
            let shutdown = context.clone();
            let (mut client, server) = proxy_client(context, native_ip).await;
            let origin_task = tokio::spawn(async move {
                let (mut stream, _) = origin.accept().await.unwrap();
                if connect {
                    let mut bytes = [0; 4];
                    stream.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"PING");
                    stream.write_all(b"PONG").await.unwrap();
                } else {
                    let request = read_headers(&mut stream).await;
                    assert!(request.starts_with("GET /probe HTTP/1.1"));
                    assert!(!request
                        .to_ascii_lowercase()
                        .contains("proxy-authorization:"));
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nPONG").await.unwrap();
                }
            });
            let target = format!("{public_ip}:{port}");
            let request = if connect {
                format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n")
            } else {
                format!("GET http://{target}/probe HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
            };
            client.write_all(request.as_bytes()).await.unwrap();
            let response = read_headers(&mut client).await;
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "port={port} connect={connect} native={native_ip:?}: {response}"
            );
            if connect {
                client.write_all(b"PING").await.unwrap();
            }
            let mut reply = [0; 4];
            timeout(Duration::from_secs(3), client.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&reply, b"PONG", "raw non-TLS TCP must survive Inspect mode");
            drop(client);
            timeout(Duration::from_secs(3), origin_task)
                .await
                .unwrap()
                .unwrap();
            shutdown.cancellation.cancel();
            shutdown.tasks.close();
            timeout(Duration::from_secs(3), shutdown.tasks.wait())
                .await
                .unwrap();
            timeout(Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap();
            println!("SERVICE PORT PASS port={port} connect={connect} native={native_ip:?}; public validation enabled; actual TCP payload PING/PONG");
        }
    }
}

#[tokio::test]
async fn lan_service_ports_relay_with_production_destination_policy() {
    production_service_ports(None).await;
}

#[tokio::test]
#[ignore = "explicit native adapter test; set HOMEPROXY_NATIVE_TEST_IP"]
async fn native_lan_service_ports_relay_with_production_destination_policy() {
    let ip: Ipv4Addr = std::env::var("HOMEPROXY_NATIVE_TEST_IP")
        .unwrap()
        .parse()
        .unwrap();
    assert!(ip.is_private());
    assert!(crate::available_lan_addresses()
        .iter()
        .any(|address| address.ip == ip));
    production_service_ports(Some(ip)).await;
}

#[tokio::test]
async fn service_ports_preserve_auth_private_targets_and_port_denials() {
    for auth in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let context = context(
            directory.path(),
            Settings {
                lan_auth_enabled: auth,
                https_mode: HttpsMode::Inspect,
                https_client_trust_acknowledged: true,
                https_inspect_hosts: vec!["example.com".into()],
                ..Settings::default()
            },
        )
        .await;
        for request in [
            "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\nConnection: close\r\n\r\n",
            "GET http://127.0.0.1:5060/ HTTP/1.1\r\nHost: 127.0.0.1:5060\r\nConnection: close\r\n\r\n",
            "CONNECT 93.184.216.12:22 HTTP/1.1\r\nHost: 93.184.216.12:22\r\nConnection: close\r\n\r\n",
            "GET http://93.184.216.12:22/ HTTP/1.1\r\nHost: 93.184.216.12:22\r\nConnection: close\r\n\r\n",
        ] {
            let (mut client, server) = proxy_client(context.clone(), None).await;
            client.write_all(request.as_bytes()).await.unwrap();
            let response = read_headers(&mut client).await;
            assert!(response.starts_with(if auth { "HTTP/1.1 407" } else { "HTTP/1.1 403" }), "{response}");
            drop(client);
            server.await.unwrap();
        }
    }
    for port in [80, 5060, 8080] {
        let result = connect_resolved_with(
            vec![
                SocketAddr::from(([1, 1, 1, 1], port)),
                SocketAddr::from(([127, 0, 0, 1], port)),
            ],
            false,
            |_| async { panic!("mixed DNS must be rejected before any dial") },
        )
        .await;
        assert!(matches!(result, Err(ProxyError::Forbidden(_))));
    }
}

#[tokio::test]
async fn service_port_inspection_and_device_policy_stay_scoped() {
    let directory = tempfile::tempdir().unwrap();
    let mut context = context(
        directory.path(),
        Settings {
            https_mode: HttpsMode::Inspect,
            https_client_trust_acknowledged: true,
            https_inspect_hosts: vec!["example.com".into()],
            lan_auth_enabled: false,
            ..Settings::default()
        },
    )
    .await;
    let peer: IpAddr = "192.168.1.123".parse().unwrap();
    for port in [80, 5060, 8080] {
        assert!(connect_should_bypass_inspection(
            &context,
            peer,
            "example.com",
            port
        ));
    }
    for port in [443, 22, 5222] {
        assert!(!connect_should_bypass_inspection(
            &context,
            peer,
            "example.com",
            port
        ));
    }
    assert!(connect_should_bypass_inspection(
        &context,
        "127.0.0.1".parse().unwrap(),
        "example.com",
        5222
    ));
    context.settings.lan_auth_enabled = true;
    let (mut client, server) = proxy_client(context.clone(), None).await;
    client.write_all(b"CONNECT 93.184.216.12:8080 HTTP/1.1\r\nHost: 93.184.216.12:8080\r\nConnection: close\r\n\r\n").await.unwrap();
    assert!(read_headers(&mut client).await.starts_with("HTTP/1.1 407"));
    drop(client);
    server.await.unwrap();
    context.settings.lan_auth_enabled = false;
    context
        .settings
        .denied_client_ips
        .push("192.168.1.123".parse().unwrap());
    let (mut client, server) = proxy_client(context, None).await;
    client.write_all(b"CONNECT 93.184.216.12:8080 HTTP/1.1\r\nHost: 93.184.216.12:8080\r\nConnection: close\r\n\r\n").await.unwrap();
    let response = read_headers(&mut client).await;
    assert!(response.starts_with("HTTP/1.1 407") && response.contains("device-blocked"));
    drop(client);
    server.await.unwrap();
}
