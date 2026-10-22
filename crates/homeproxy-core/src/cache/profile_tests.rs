use super::offline_tests::{exchange, headers, req, secure_directory};
use super::*;
fn profile() -> crate::policy::DeviceProfile {
    serde_json::from_value(serde_json::json!({"id":"tv","name":"TV","username":"tv-user","password":"tv-password","noCacheDomains":["127.0.0.1"],"blockDomains":["blocked.test"]})).unwrap()
}
fn md5(value: &str) -> String {
    hex::encode(md5::Md5::digest(value.as_bytes()))
}
fn authorization(challenge: &str, username: &str, password: &str, uri: &str) -> String {
    let nonce = challenge
        .split("nonce=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let response = md5(&format!(
        "{}:{nonce}:00000001:client:auth:{}",
        md5(&format!("{username}:HomeProxy:{password}")),
        md5(&format!("GET:{uri}"))
    ));
    format!("Proxy-Authorization: Digest username=\"{username}\", realm=\"HomeProxy\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"client\"\r\n")
}
async fn start(settings: Settings, dir: &std::path::Path) -> (ProxyHandle, u16, Arc<Stats>) {
    secure_directory(dir);
    let stats = Arc::new(Stats::default());
    stats
        .configure_history(dir.join("history.json"), &settings)
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tls = TlsInspection::for_tests(dir.join("authority.json"), rustls::RootCertStore::empty())
        .unwrap();
    let handle = spawn_proxy_with_listeners(
        settings,
        CacheStore::new(dir.join("cache")),
        stats.clone(),
        tls,
        vec![listener],
        true,
    )
    .unwrap();
    (handle, port, stats)
}
#[tokio::test]
async fn verified_digest_profile_enforces_no_cache_and_deny_before_dns() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = headers(&mut stream).await.to_lowercase();
            assert!(!request.contains("proxy-authorization"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nContent-Length: 3\r\nConnection: close\r\n\r\none").await.unwrap();
        }
    });
    let settings = Settings {
        cache_enabled: true,
        device_profiles: vec![profile()],
        ..Settings::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let (handle, port, stats) = start(settings, dir.path()).await;
    for _ in 0..2 {
        let challenge = exchange(
            port,
            &req(origin, "/file", "Proxy-Authorization: invalid\r\n"),
        )
        .await;
        assert!(challenge.starts_with("HTTP/1.1 407"));
        let uri = format!("http://127.0.0.1:{origin}/file");
        let auth = authorization(&challenge, "tv-user", "tv-password", &uri);
        let response = exchange(port, &req(origin, "/file", &auth)).await;
        assert!(response.ends_with("one"), "{response}");
        assert!(!response.contains("cache-status"));
    }
    task.await.unwrap();
    assert_eq!(stats.snapshot().cache_hits, 0);
    let challenge=exchange(port,"GET http://blocked.test/file HTTP/1.1\r\nHost: blocked.test\r\nProxy-Authorization: invalid\r\nConnection: close\r\n\r\n").await;
    let auth = authorization(
        &challenge,
        "tv-user",
        "tv-password",
        "http://blocked.test/file",
    );
    let response=exchange(port,&format!("GET http://blocked.test/file HTTP/1.1\r\nHost: blocked.test\r\n{auth}Connection: close\r\n\r\n")).await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    let report = stats.history_json().unwrap();
    assert!(report.contains("profile:tv"));
    assert!(!report.contains("tv-password"));
    assert!(!report.contains("blocked.test/file"));
    handle.stop().await;
}
#[tokio::test]
async fn socks_profile_credentials_are_verified_and_block_named_targets() {
    let dir = tempfile::tempdir().unwrap();
    let configuration = Settings {
        device_profiles: vec![profile()],
        socks5_enabled: true,
        ..Settings::default()
    };
    let (handle, port, _) = start(configuration, dir.path()).await;
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut response = [0; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 2]);
    let mut auth = vec![1, 7];
    auth.extend_from_slice(b"tv-user");
    auth.push(11);
    auth.extend_from_slice(b"tv-password");
    client.write_all(&auth).await.unwrap();
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [1, 0]);
    let mut request = vec![5, 1, 0, 3, 12];
    request.extend_from_slice(b"blocked.test");
    request.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 2);
    handle.stop().await;
}
#[tokio::test]
async fn udp_profile_domain_deny_prevents_dns_or_send_and_allowed_packet_is_accounted() {
    use tokio::net::UdpSocket;
    let dir = tempfile::tempdir().unwrap();
    secure_directory(dir.path());
    let mut configured_profile = profile();
    configured_profile.ips = vec![Ipv4Addr::LOCALHOST];
    let configuration = Settings {
        device_profiles: vec![configured_profile],
        socks5_enabled: true,
        socks5_udp_enabled: true,
        ..Settings::default()
    };
    let context = service_port_tests::context(dir.path(), configuration.clone()).await;
    context
        .stats
        .configure_history(dir.path().join("history.json"), &configuration)
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let running = context.clone();
    let task = tokio::spawn(async move {
        accept_loop(
            BoundListener {
                listener,
                protocol: ListenerProtocol::Socks5Dedicated,
            },
            running,
        )
        .await
        .unwrap()
    });
    let mut control = TcpStream::connect(address).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    control.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let origin = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    context
        .resolver
        .map_test_dial("1.1.1.1:53".parse().unwrap(), origin.local_addr().unwrap());
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut denied = vec![0, 0, 0, 3, 12];
    denied.extend_from_slice(b"blocked.test");
    denied.extend_from_slice(&53u16.to_be_bytes());
    denied.push(1);
    client.send_to(&denied, relay).await.unwrap();
    assert!(
        timeout(Duration::from_millis(75), origin.recv_from(&mut [0; 16]))
            .await
            .is_err()
    );
    let allowed = [0, 0, 0, 1, 1, 1, 1, 1, 0, 53, 1, 2];
    client.send_to(&allowed, relay).await.unwrap();
    let mut bytes = [0; 100];
    let (n, from) = timeout(Duration::from_secs(2), origin.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], &[1, 2]);
    origin.send_to(&bytes[..n], from).await.unwrap();
    let (n, _) = timeout(Duration::from_secs(2), client.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..n], &allowed);
    assert!(context.stats.history_json().unwrap().contains("profile:tv"));
    context.cancellation.cancel();
    task.await.unwrap();
    context.tasks.close();
    context.tasks.wait().await;
}

#[tokio::test]
async fn imported_filter_blocks_real_proxy_path_and_explicit_allow_reaches_origin() {
    for explicit_allow in [false, true] {
        let feed =
            crate::filter_feeds::FilterFeed::parse("fixture", "||imported.example^").unwrap();
        let configuration = Settings {
            filter_feeds: vec![feed],
            allow_domains: if explicit_allow {
                vec!["sub.imported.example".into()]
            } else {
                Vec::new()
            },
            ..Settings::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let context = service_port_tests::context(dir.path(), configuration).await;
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = origin.local_addr().unwrap();
        context.resolver.set_test_answer(
            "sub.imported.example",
            vec!["9.9.9.9".parse().unwrap()],
            Duration::ZERO,
        );
        context
            .resolver
            .map_test_dial("9.9.9.9:8080".parse().unwrap(), address);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let run = context.clone();
        let proxy = tokio::spawn(async move {
            accept_loop(
                BoundListener {
                    listener,
                    protocol: ListenerProtocol::HttpMultiplexed,
                },
                run,
            )
            .await
            .unwrap()
        });
        let request="GET http://sub.imported.example:8080/file HTTP/1.1\r\nHost: sub.imported.example:8080\r\nConnection: close\r\n\r\n";
        if explicit_allow {
            let task = tokio::spawn(async move {
                let (mut stream, _) = origin.accept().await.unwrap();
                headers(&mut stream).await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none",
                    )
                    .await
                    .unwrap();
            });
            assert!(exchange(port, request).await.ends_with("one"));
            task.await.unwrap();
        } else {
            let response = exchange(port, request).await;
            assert!(response.starts_with("HTTP/1.1 403"), "{response}");
            assert!(timeout(Duration::from_millis(75), origin.accept())
                .await
                .is_err());
        }
        context.cancellation.cancel();
        proxy.await.unwrap();
        context.tasks.close();
        context.tasks.wait().await;
    }
}
