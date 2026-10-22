use super::*;
use http_body_util::BodyExt;
use std::{path::Path, sync::atomic::AtomicUsize};

pub(super) async fn headers<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(
            timeout(Duration::from_secs(3), stream.read_u8())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    String::from_utf8(bytes).unwrap()
}
pub(super) async fn exchange(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(bytes).unwrap()
}
pub(super) fn req(origin: u16, path: &str, extra: &str) -> String {
    format!("GET http://127.0.0.1:{origin}{path} HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\n{extra}Connection: close\r\n\r\n")
}
pub(super) fn secure_directory(directory: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

async fn proxy(settings: Settings, cache: CacheStore, dir: &Path) -> (ProxyHandle, u16) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    secure_directory(dir);
    let tls = TlsInspection::for_tests(dir.join("authority.json"), rustls::RootCertStore::empty())
        .unwrap();
    (
        spawn_proxy_with_listeners(
            settings,
            cache,
            Arc::new(Stats::default()),
            tls,
            vec![listener],
            true,
        )
        .unwrap(),
        port,
    )
}
fn expire(cache: &CacheStore, seconds: u64) {
    for file in std::fs::read_dir(cache.root()).unwrap() {
        let path = file.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            let mut metadata: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            metadata["stored_unix_seconds"] = (now - 120 - seconds).into();
            metadata["expires_unix_seconds"] = (now - seconds).into();
            std::fs::write(path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        }
    }
}
fn settings(mode: CacheMode) -> Settings {
    Settings {
        cache_enabled: true,
        cache_mode: mode,
        ..Settings::default()
    }
}

#[tokio::test]
async fn snapshot_releases_lease_and_refresh_requires_same_epoch_and_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let cache = CacheStore::new(dir.path().into());
    let key = "a".repeat(64);
    let mut h = HeaderMap::new();
    h.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );
    h.insert(CONTENT_LENGTH, HeaderValue::from_static("3"));
    cache
        .put(
            &key,
            StatusCode::OK,
            &h,
            Bytes::from_static(b"abc"),
            Duration::from_secs(60),
            1024 * 1024,
        )
        .await
        .unwrap();
    expire(&cache, 10);
    assert!(cache.get(&key).await.is_none());
    let snapshot = cache.snapshot(&key).await.unwrap();
    assert!(snapshot.stale_for.as_secs() >= 10);
    assert_eq!(snapshot.body_length, 3);
    assert!(
        cache
            .refresh(&key, &snapshot, &h, Duration::from_secs(60))
            .await
    );
    assert!(
        !cache
            .refresh(&key, &snapshot, &h, Duration::from_secs(60))
            .await
    );
    assert!(cache.get_if_snapshot(&key, &snapshot).await.is_none());
    let entry = cache.get(&key).await.unwrap();
    assert_eq!(entry.body.collect().await.unwrap().to_bytes(), "abc");
    let snapshot = cache.snapshot(&key).await.unwrap();
    cache.clear().await.unwrap();
    assert!(cache.get_if_snapshot(&key, &snapshot).await.is_none());
    assert!(
        !cache
            .refresh(&key, &snapshot, &h, Duration::from_secs(60))
            .await
    );
}

#[tokio::test]
async fn online_etag_304_changed_200_and_restrictive_304() {
    for replacement in [
        "304",
        "lastmodified304",
        "200",
        "private304",
        "cookie304",
        "nostore200",
    ] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let first = headers(&mut stream).await.to_lowercase();
            assert!(!first.contains("if-none-match"));
            let initial = b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\nETag: \"v1\"\r\nLast-Modified: Tue, 01 Sep 2026 00:00:00 GMT\r\nContent-Length: 3\r\nConnection: close\r\n\r\none";
            let initial = String::from_utf8_lossy(initial);
            let initial = if replacement == "lastmodified304" {
                initial.replace("ETag: \"v1\"\r\n", "")
            } else {
                initial.to_string()
            };
            stream.write_all(initial.as_bytes()).await.unwrap();
            drop(stream);
            let (mut stream, _) = listener.accept().await.unwrap();
            let second = headers(&mut stream).await.to_lowercase();
            if replacement == "lastmodified304" {
                assert!(
                    second.contains("if-modified-since: tue, 01 sep 2026"),
                    "{second}"
                );
                assert!(!second.contains("if-none-match"));
            } else {
                assert!(second.contains("if-none-match: \"v1\""), "{second}");
                assert!(!second.contains("if-modified-since"));
            }
            let response = match replacement {
                "304" | "lastmodified304" => "HTTP/1.1 304 Not Modified\r\nCache-Control: public, max-age=120\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                "200" => "HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nETag: \"v2\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo",
                "private304" => "HTTP/1.1 304 Not Modified\r\nCache-Control: private, max-age=120\r\nConnection: close\r\n\r\n",
                "cookie304" => "HTTP/1.1 304 Not Modified\r\nCache-Control: public, max-age=120\r\nSet-Cookie: token=secret\r\nConnection: close\r\n\r\n",
                _ => "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo"
            };
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().join("cache"));
        let (handle, port) = proxy(settings(CacheMode::Online), cache.clone(), dir.path()).await;
        assert!(exchange(port, &req(origin, "/file", ""))
            .await
            .ends_with("one"));
        expire(&cache, 10);
        let response = exchange(port, &req(origin, "/file", "")).await;
        task.await.unwrap();
        handle.stop().await;
        let reopened = CacheStore::new(cache.root().to_owned());
        let (handle, port) = proxy(settings(CacheMode::Offline), reopened, dir.path()).await;
        let offline = exchange(port, &req(origin, "/file", "")).await;
        match replacement {
            "304" | "lastmodified304" => {
                assert!(response.starts_with("HTTP/1.1 200"));
                assert!(offline.ends_with("one"));
            }
            "200" => {
                assert!(response.ends_with("two"));
                assert!(offline.ends_with("two"));
            }
            _ => {
                assert!(offline.starts_with("HTTP/1.1 504"), "{offline}");
            }
        }
        handle.stop().await;
    }
}

#[tokio::test]
async fn offline_stale_directives_range_and_restart() {
    for policy in [
        "public, max-age=60",
        "public, max-age=60, must-revalidate",
        "public, s-maxage=60",
        "public, max-age=60, proxy-revalidate",
    ] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin = listener.local_addr().unwrap().port();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            headers(&mut stream).await;
            stream.write_all(format!("HTTP/1.1 200 OK\r\nCache-Control: {policy}\r\nETag: \"v1\"\r\nContent-Length: 9\r\nConnection: close\r\n\r\nabcdefghi").as_bytes()).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().join("cache"));
        let (online, port) = proxy(settings(CacheMode::Online), cache.clone(), dir.path()).await;
        assert!(exchange(port, &req(origin, "/file", ""))
            .await
            .ends_with("abcdefghi"));
        origin_task.await.unwrap();
        online.stop().await;
        let (offline, port) = proxy(settings(CacheMode::Offline), cache.clone(), dir.path()).await;
        assert!(exchange(port, &req(origin, "/file", ""))
            .await
            .ends_with("abcdefghi"));
        for (extra, expected) in [
            ("Range: bytes=3-5\r\n", "def"),
            ("Range: bytes=-2\r\n", "hi"),
            ("Range: bytes=7-\r\n", "hi"),
        ] {
            let response = exchange(port, &req(origin, "/file", extra)).await;
            assert!(response.starts_with("HTTP/1.1 206"), "{response}");
            assert!(response.ends_with(expected));
        }
        assert!(
            exchange(port, &req(origin, "/file", "Range: bytes=99-\r\n"))
                .await
                .starts_with("HTTP/1.1 416")
        );
        assert!(exchange(
            port,
            &req(
                origin,
                "/file",
                "Range: bytes=3-5\r\nIf-Range: \"other\"\r\n"
            )
        )
        .await
        .ends_with("abcdefghi"));
        assert!(
            exchange(port, &req(origin, "/file", "Cache-Control: no-cache\r\n"))
                .await
                .starts_with("HTTP/1.1 504")
        );
        offline.stop().await;
        expire(&cache, 10);
        let (offline, port) = proxy(
            settings(CacheMode::Offline),
            CacheStore::new(cache.root().into()),
            dir.path(),
        )
        .await;
        let response = exchange(port, &req(origin, "/file", "")).await;
        assert_eq!(
            response.starts_with("HTTP/1.1 200"),
            policy == "public, max-age=60",
            "{policy}: {response}"
        );
        assert!(exchange(port, &req(origin, "/miss", ""))
            .await
            .starts_with("HTTP/1.1 504"));
        offline.stop().await;
    }
}

#[tokio::test]
async fn offline_blocks_http_connect_websocket_socks_and_udp_without_origin_accepts() {
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let mut configuration = settings(CacheMode::Offline);
    configuration.cache_enabled = false;
    configuration.socks5_enabled = true;
    configuration.socks5_udp_enabled = true;
    let (handle, port) = proxy(
        configuration,
        CacheStore::new(dir.path().join("cache")),
        dir.path(),
    )
    .await;
    for request in [req(origin_port,"/", ""),
        format!("CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"),
        req(origin_port,"/ws","Upgrade: websocket\r\nConnection: Upgrade\r\n")] {
        assert!(exchange(port,&request).await.starts_with("HTTP/1.1 504"));
    }
    for command in [1, 3] {
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        let mut request = vec![5, command, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&origin_port.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 2);
    }
    assert!(timeout(Duration::from_millis(100), origin.accept())
        .await
        .is_err());
    handle.stop().await;
}

#[tokio::test]
async fn opt_in_navigation_queries_keep_headers_and_variant_keys() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let origin_hits = hits.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            origin_hits.fetch_add(1, Ordering::SeqCst);
            let request = headers(&mut stream).await;
            assert!(
                request.contains("User-Agent: Browser/1")
                    || request.contains("user-agent: Browser/1"),
                "{request}"
            );
            assert!(request.to_lowercase().contains("sec-fetch-mode: navigate"));
            let body = if request.contains("?q=one") {
                "one"
            } else {
                "two"
            };
            let restrictive = request.to_lowercase().contains("cookie:")
                || request.to_lowercase().contains("authorization:")
                || request.to_lowercase().contains("x-private:");
            let policy = if restrictive {
                "private"
            } else {
                "max-age=120"
            };
            stream.write_all(format!("HTTP/1.1 200 OK\r\nCache-Control: {policy}\r\nVary: Accept-Language, User-Agent\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{body}").as_bytes()).await.unwrap();
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let mut configuration = settings(CacheMode::Online);
    configuration.public_cache_endpoints = vec![crate::config::PublicCacheEndpoint {
        host: "127.0.0.1".into(),
        path_prefix: "/public".into(),
    }];
    let (handle, port) = proxy(
        configuration.clone(),
        CacheStore::new(dir.path().join("cache")),
        dir.path(),
    )
    .await;
    let browser = "Accept: text/html\r\nUser-Agent: Browser/1\r\nSec-Fetch-Mode: navigate\r\nAccept-Language: en\r\n";
    for path in [
        "/public?q=one",
        "/public?q=one",
        "/public?q=two",
        "/public?q=two",
    ] {
        assert!(exchange(port, &req(origin, path, browser))
            .await
            .starts_with("HTTP/1.1 200"));
    }
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let changed = browser.replace("en\r\n", "cs\r\n");
    exchange(port, &req(origin, "/public?q=one", &changed)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    for extra in [
        "Cookie: token=secret\r\n",
        "Authorization: bearer secret\r\n",
        "X-Private: secret\r\n",
    ] {
        for _ in 0..2 {
            exchange(
                port,
                &req(origin, "/public?q=one", &format!("{browser}{extra}")),
            )
            .await;
        }
    }
    assert_eq!(hits.load(Ordering::SeqCst), 9);
    handle.stop().await;
    task.abort();
    let mut boundary = Request::new(());
    *boundary.uri_mut() = format!("http://127.0.0.1:{origin}/publicity")
        .parse()
        .unwrap();
    assert!(!cache_policy::public_endpoint(&boundary, &configuration));
}

#[tokio::test]
async fn streamed_concurrent_misses_share_one_download() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let origin_hits = hits.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            origin_hits.fetch_add(1, Ordering::SeqCst);
            headers(&mut stream).await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabc").await.unwrap();
            tokio::time::sleep(Duration::from_millis(75)).await;
            stream.write_all(b"def").await.unwrap();
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let mut configuration = settings(CacheMode::Online);
    configuration.response_buffer_limit_mib = 0;
    let (handle, port) = proxy(
        configuration,
        CacheStore::new(dir.path().join("cache")),
        dir.path(),
    )
    .await;
    let request = req(origin, "/file", "");
    let mut clients = JoinSet::new();
    for _ in 0..8 {
        let request = request.clone();
        clients.spawn(async move { exchange(port, &request).await });
    }
    while let Some(result) = clients.join_next().await {
        assert!(result.unwrap().ends_with("abcdef"));
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    handle.stop().await;
    task.abort();
}

async fn tls_request(
    connector: &tokio_rustls::TlsConnector,
    proxy_port: u16,
    origin_port: u16,
    host_header: &str,
) -> String {
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
    assert!(headers(&mut stream).await.starts_with("HTTP/1.1 200"));
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_owned()).unwrap();
    let mut stream = connector.connect(name, stream).await.unwrap();
    stream
        .write_all(
            format!("GET /file HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    // TLS peers may close TCP without close_notify after the complete HTTP response.
    let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn real_https_warm_revalidate_restart_offline_and_authority_mismatch() {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap(),
    ));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        for attempt in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let request = headers(&mut stream).await.to_lowercase();
            if attempt == 0 {
                assert!(!request.contains("if-none-match"));
                stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\nETag: \"tls1\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntls").await.unwrap();
            } else {
                assert!(request.contains("if-none-match: \"tls1\""));
                stream.write_all(b"HTTP/1.1 304 Not Modified\r\nCache-Control: public, max-age=120\r\nETag: \"tls1\"\r\nConnection: close\r\n\r\n").await.unwrap();
            }
            stream.shutdown().await.unwrap();
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let cache = CacheStore::new(dir.path().join("cache"));
    let mut origin_roots = rustls::RootCertStore::empty();
    origin_roots.add(cert.der().clone()).unwrap();
    secure_directory(dir.path());
    let inspection =
        TlsInspection::for_tests(dir.path().join("authority.json"), origin_roots).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(inspection.root_certificate_der()).unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let configuration = Settings {
        https_mode: HttpsMode::Inspect,
        https_client_trust_acknowledged: true,
        https_inspect_hosts: vec!["127.0.0.1".into()],
        ..settings(CacheMode::Online)
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let handle = spawn_proxy_with_listeners(
        configuration.clone(),
        cache.clone(),
        Arc::new(Stats::default()),
        inspection.clone(),
        vec![listener],
        true,
    )
    .unwrap();
    let host = format!("127.0.0.1:{origin_port}");
    assert!(tls_request(&connector, proxy_port, origin_port, &host)
        .await
        .ends_with("tls"));
    assert!(tls_request(&connector, proxy_port, origin_port, &host)
        .await
        .contains("HomeProxy; hit"));
    expire(&cache, 5);
    assert!(tls_request(&connector, proxy_port, origin_port, &host)
        .await
        .ends_with("tls"));
    task.await.unwrap();
    handle.stop().await;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let handle = spawn_proxy_with_listeners(
        Settings {
            cache_mode: CacheMode::Offline,
            ..configuration
        },
        CacheStore::new(cache.root().into()),
        Arc::new(Stats::default()),
        inspection,
        vec![listener],
        true,
    )
    .unwrap();
    assert!(tls_request(&connector, proxy_port, origin_port, &host)
        .await
        .contains("HomeProxy; hit"));
    assert!(
        tls_request(&connector, proxy_port, origin_port, "other.test")
            .await
            .starts_with("HTTP/1.1 403")
    );
    let response=exchange(proxy_port,"CONNECT unselected.test:443 HTTP/1.1\r\nHost: unselected.test:443\r\nConnection: close\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 504"));
    handle.stop().await;
}

#[tokio::test]
async fn inspected_https_unrelated_writer_during_304_preserves_verified_hit_and_sni() {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    async fn exchange_https(
        connector: &tokio_rustls::TlsConnector,
        proxy_port: u16,
        origin_port: u16,
    ) -> String {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .unwrap();
        stream.write_all(format!("CONNECT localhost:{origin_port} HTTP/1.1\r\nHost: localhost:{origin_port}\r\n\r\n").as_bytes()).await.unwrap();
        assert!(headers(&mut stream).await.starts_with("HTTP/1.1 200"));
        let name = rustls::pki_types::ServerName::try_from("localhost".to_owned()).unwrap();
        let mut stream = connector.connect(name, stream).await.unwrap();
        stream.write_all(format!("GET /file HTTP/1.1\r\nHost: localhost:{origin_port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        // The complete HTTP body remains valid if the TLS peer omits close_notify.
        let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .unwrap();
        String::from_utf8(response).unwrap()
    }

    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap(),
    ));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_port = listener.local_addr().unwrap().port();
    let (validated_tx, validated_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let requests = Arc::new(AtomicUsize::new(0));
    let origin_requests = requests.clone();
    let origin = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        assert_eq!(stream.get_ref().1.server_name(), Some("localhost"));
        let warm = headers(&mut stream).await.to_lowercase();
        origin_requests.fetch_add(1, Ordering::SeqCst);
        assert!(warm.contains(&format!("host: localhost:{origin_port}\r\n")));
        assert!(!warm.contains("if-none-match:"));
        stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\nETag: \"tls1\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\nold").await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);

        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        assert_eq!(stream.get_ref().1.server_name(), Some("localhost"));
        let conditional = headers(&mut stream).await.to_lowercase();
        origin_requests.fetch_add(1, Ordering::SeqCst);
        assert!(conditional.starts_with("get /file http/1.1\r\n"));
        assert!(conditional.contains(&format!("host: localhost:{origin_port}\r\n")));
        assert!(conditional.contains("if-none-match: \"tls1\"\r\n"));
        validated_tx.send(()).unwrap();
        release_rx.await.unwrap();
        // The unrelated slow fill cannot prevent refreshing this exact snapshot.
        stream.write_all(b"HTTP/1.1 304 Not Modified\r\nCache-Control: public, max-age=300\r\nETag: \"tls1\"\r\nConnection: close\r\n\r\n").await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        assert!(timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err());
    });
    let directory = tempfile::tempdir().unwrap();
    secure_directory(directory.path());
    let cache = CacheStore::new(directory.path().join("cache"));
    let mut origin_roots = rustls::RootCertStore::empty();
    origin_roots.add(cert.der().clone()).unwrap();
    let inspection =
        TlsInspection::for_tests(directory.path().join("authority.json"), origin_roots).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(inspection.root_certificate_der()).unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let handle = spawn_proxy_with_listeners(
        Settings {
            https_mode: HttpsMode::Inspect,
            https_client_trust_acknowledged: true,
            https_inspect_hosts: vec!["localhost".into()],
            ..settings(CacheMode::Online)
        },
        cache.clone(),
        Arc::new(Stats::default()),
        inspection,
        vec![listener],
        true,
    )
    .unwrap();
    assert!(exchange_https(&connector, proxy_port, origin_port)
        .await
        .ends_with("old"));
    expire(&cache, 5);
    let request_task =
        tokio::spawn(async move { exchange_https(&connector, proxy_port, origin_port).await });
    timeout(Duration::from_secs(3), validated_rx)
        .await
        .unwrap()
        .unwrap();
    let mut writer_headers = HeaderMap::new();
    writer_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );
    writer_headers.insert(CONTENT_LENGTH, HeaderValue::from_static("8"));
    let writer = cache
        .begin_fill(
            cache.epoch(),
            &"a".repeat(64),
            StatusCode::OK,
            &writer_headers,
            8,
            Duration::from_secs(60),
            Instant::now(),
            1024 * 1024,
        )
        .await
        .unwrap()
        .write(Bytes::from_static(b"a"))
        .await
        .unwrap();
    release_tx.send(()).unwrap();
    let response = request_task.await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("\r\n\r\nold"), "{response}");
    assert!(response.contains("HomeProxy; hit"), "{response}");
    drop(writer);
    origin.await.unwrap();
    // One conditional request followed the warm request; no full refetch.
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    handle.stop().await;
}

#[tokio::test]
async fn dedup_leader_drop_and_clear_wake_followers_and_do_not_commit_partial_bodies() {
    use crate::cache::{FillClaim, FillRegistry};
    let registry = FillRegistry::default();
    let FillClaim::Leader(leader) = registry.claim("key") else {
        panic!()
    };
    let FillClaim::Follower(mut follower) = registry.claim("key") else {
        panic!()
    };
    drop(leader);
    timeout(Duration::from_millis(100), follower.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(*follower.borrow());
    let dir = tempfile::tempdir().unwrap();
    let cache = CacheStore::new(dir.path().into());
    let key = "b".repeat(64);
    let FillClaim::Leader(leader) = cache.fills.claim(&key) else {
        panic!()
    };
    let FillClaim::Follower(mut follower) = cache.fills.claim(&key) else {
        panic!()
    };
    let fill = cache
        .begin_fill(
            cache.epoch(),
            &key,
            StatusCode::OK,
            &HeaderMap::new(),
            3,
            Duration::from_secs(60),
            Instant::now(),
            1024 * 1024,
        )
        .await
        .unwrap();
    let body = TeeBody::new(
        Full::new(Bytes::from_static(b"abc")),
        fill,
        3,
        CancellationToken::new(),
    )
    .with_flight(Some(leader));
    assert_eq!(
        cache.clear().await.unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    timeout(Duration::from_millis(100), follower.changed())
        .await
        .unwrap()
        .unwrap();
    let FillClaim::Leader(new_leader) = cache.fills.claim(&key) else {
        panic!()
    };
    let FillClaim::Follower(mut new_follower) = cache.fills.claim(&key) else {
        panic!()
    };
    assert_eq!(body.collect().await.unwrap().to_bytes(), "abc");
    assert!(matches!(cache.fills.claim(&key), FillClaim::Follower(_)));
    drop(new_leader);
    timeout(Duration::from_millis(100), new_follower.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(cache.get(&key).await.is_none());
    cache.maintain().await.unwrap();
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    let mut guards = Vec::new();
    for i in 0..256 {
        let FillClaim::Leader(guard) = registry.claim(&format!("other-{i}")) else {
            panic!()
        };
        guards.push(guard);
    }
    assert!(matches!(registry.claim("overflow"), FillClaim::Saturated));
    drop(guards);
    assert!(matches!(registry.claim("overflow"), FillClaim::Leader(_)));
}

#[test]
fn absolute_https_uri_and_host_must_both_match_connect() {
    let authority: Authority = "allowed.test:443".parse().unwrap();
    let request = Request::builder()
        .uri("https://allowed.test/file")
        .header(HOST, "evil.test")
        .body(())
        .unwrap();
    assert!(validate_inspected_authority(&request, &authority).is_err());
    let request = Request::builder()
        .uri("https://evil.test/file")
        .header(HOST, "allowed.test")
        .body(())
        .unwrap();
    assert!(validate_inspected_authority(&request, &authority).is_err());
    let request = Request::builder()
        .uri("https://allowed.test/file")
        .header(HOST, "allowed.test")
        .body(())
        .unwrap();
    assert!(validate_inspected_authority(&request, &authority).is_ok());
}

#[tokio::test]
async fn pac_is_local_opt_in_uses_listener_address_and_explicit_fallback() {
    for direct in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut configuration = settings(CacheMode::Online);
        configuration.pac_enabled = true;
        configuration.pac_direct_fallback = direct;
        let (handle, port) = proxy(
            configuration,
            CacheStore::new(dir.path().join("cache")),
            dir.path(),
        )
        .await;
        let response=exchange(port,"GET http://homeproxy.local/proxy.pac HTTP/1.1\r\nHost: homeproxy.local\r\nConnection: close\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains(&format!("PROXY 127.0.0.1:{port}")));
        assert!(!response.contains("attacker.test"));
        assert_eq!(response.contains("; DIRECT"), direct);
        assert!(response.contains("application/x-ns-proxy-autoconfig"));
        let direct_request = format!(
            "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        );
        let direct_response = exchange(port, &direct_request).await;
        assert!(
            direct_response.starts_with("HTTP/1.1 200"),
            "{direct_response}"
        );
        let forged_response = exchange(
            port,
            "GET /proxy.pac HTTP/1.1\r\nHost: attacker.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            forged_response.starts_with("HTTP/1.1 400"),
            "{forged_response}"
        );
        handle.stop().await;
    }
}

#[derive(Debug)]
struct FixedCertificateNameVerifier(Arc<rustls::client::WebPkiServerVerifier>);
impl rustls::client::danger::ServerCertVerifier for FixedCertificateNameVerifier {
    fn verify_server_cert(
        &self,
        certificate: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _name: &rustls::pki_types::ServerName<'_>,
        ocsp: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Only the test client deliberately separates its SNI from certificate identity;
        // the full CA, validity and handshake signature verification stays enabled.
        self.0.verify_server_cert(
            certificate,
            intermediates,
            &rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
            ocsp,
            now,
        )
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0
            .verify_tls12_signature(message, certificate, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0
            .verify_tls13_signature(message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

#[tokio::test]
async fn real_tls_sni_mismatch_is_rejected_before_any_origin_accept() {
    let dir = tempfile::tempdir().unwrap();
    secure_directory(dir.path());
    let inspection = TlsInspection::for_tests(
        dir.path().join("authority.json"),
        rustls::RootCertStore::empty(),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(inspection.root_certificate_der()).unwrap();
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FixedCertificateNameVerifier(verifier)))
            .with_no_client_auth(),
    ));
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let stats = Arc::new(Stats::default());
    let configuration = Settings {
        https_mode: HttpsMode::Inspect,
        https_client_trust_acknowledged: true,
        https_inspect_hosts: vec!["127.0.0.1".into()],
        ..Settings::default()
    };
    let handle = spawn_proxy_with_listeners(
        configuration,
        CacheStore::new(dir.path().join("cache")),
        stats.clone(),
        inspection,
        vec![listener],
        true,
    )
    .unwrap();
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
    assert!(headers(&mut stream).await.starts_with("HTTP/1.1 200"));
    let _ = connector
        .connect(
            rustls::pki_types::ServerName::try_from("other.test").unwrap(),
            stream,
        )
        .await;
    timeout(Duration::from_secs(2), async {
        loop {
            if stats
                .snapshot()
                .activity
                .iter()
                .any(|a| a.error.as_deref() == Some("TLS-SNI-authority-mismatch"))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(timeout(Duration::from_millis(75), origin.accept())
        .await
        .is_err());
    handle.stop().await;
}

#[tokio::test]
async fn explicit_stale_if_error_only_reuses_allowed_500_and_connect_failure() {
    for (policy, status, reuse) in [
        ("public, max-age=60, stale-if-error=120", 500, true),
        (
            "public, max-age=60, stale-if-error=120, must-revalidate",
            500,
            false,
        ),
        ("public, s-maxage=60, stale-if-error=120", 500, false),
        ("public, max-age=60", 500, false),
        ("public, max-age=60, stale-if-error=5", 500, false),
        ("public, max-age=60, stale-if-error=120", 403, false),
        ("public, max-age=60, stale-if-error=120", 0, true),
    ] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            headers(&mut stream).await;
            stream.write_all(format!("HTTP/1.1 200 OK\r\nCache-Control: {policy}\r\nETag: \"one\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\none").as_bytes()).await.unwrap();
            drop(stream);
            if status != 0 {
                let (mut stream, _) = listener.accept().await.unwrap();
                headers(&mut stream).await;
                stream.write_all(format!("HTTP/1.1 {status} Origin Failure\r\nContent-Length: 3\r\nConnection: close\r\n\r\nerr").as_bytes()).await.unwrap();
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(dir.path().join("cache"));
        let (handle, port) = proxy(settings(CacheMode::Online), cache.clone(), dir.path()).await;
        assert!(exchange(port, &req(origin, "/file", ""))
            .await
            .ends_with("one"));
        if status == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        expire(&cache, 10);
        let response = exchange(port, &req(origin, "/file", "")).await;
        assert_eq!(response.ends_with("one"), reuse, "{policy}: {response}");
        if reuse {
            assert!(response.contains("HomeProxy; hit"));
        }
        task.await.unwrap();
        handle.stop().await;
    }
}

#[tokio::test]
async fn explicit_stale_if_error_never_masks_origin_tls_failure() {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap(),
    ));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        headers(&mut stream).await;
        stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60, stale-if-error=600\r\nETag: \"tls\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntls").await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut record = [0; 5];
        stream.read_exact(&mut record).await.unwrap();
        let size = u16::from_be_bytes([record[3], record[4]]) as usize;
        stream.read_exact(&mut vec![0; size]).await.unwrap();
        stream.write_all(&[21, 3, 3, 0, 2, 2, 40]).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    secure_directory(dir.path());
    let cache = CacheStore::new(dir.path().join("cache"));
    let mut origin_roots = rustls::RootCertStore::empty();
    origin_roots.add(cert.der().clone()).unwrap();
    let inspection =
        TlsInspection::for_tests(dir.path().join("authority.json"), origin_roots).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(inspection.root_certificate_der()).unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let configuration = Settings {
        cache_enabled: true,
        https_mode: HttpsMode::Inspect,
        https_client_trust_acknowledged: true,
        https_inspect_hosts: vec!["127.0.0.1".into()],
        ..Settings::default()
    };
    let handle = spawn_proxy_with_listeners(
        configuration,
        cache.clone(),
        Arc::new(Stats::default()),
        inspection,
        vec![listener],
        true,
    )
    .unwrap();
    let host = format!("127.0.0.1:{origin}");
    assert!(tls_request(&connector, port, origin, &host)
        .await
        .ends_with("tls"));
    expire(&cache, 10);
    let response = tls_request(&connector, port, origin, &host).await;
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert!(!response.contains("HomeProxy; hit"));
    task.await.unwrap();
    handle.stop().await;
}

#[tokio::test]
async fn lru_recency_retains_hot_object_and_is_persisted_at_most_once_per_minute() {
    let dir = tempfile::tempdir().unwrap();
    let cache = CacheStore::new(dir.path().into());
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    let c = "c".repeat(64);
    let h = HeaderMap::new();
    for key in [&a, &b] {
        cache
            .put(
                key,
                StatusCode::OK,
                &h,
                Bytes::from_static(b"object"),
                Duration::from_secs(3600),
                1024 * 1024,
            )
            .await
            .unwrap();
    }
    let now = SystemTime::now();
    for (key, age) in [(&a, 300), (&b, 200)] {
        for extension in ["body", "json"] {
            let file = std::fs::File::open(dir.path().join(format!("{key}.{extension}"))).unwrap();
            file.set_times(std::fs::FileTimes::new().set_modified(now - Duration::from_secs(age)))
                .unwrap();
        }
    }
    let body_path = dir.path().join(format!("{a}.body"));
    assert_eq!(
        cache
            .get(&a)
            .await
            .unwrap()
            .body
            .collect()
            .await
            .unwrap()
            .to_bytes(),
        "object"
    );
    let touched = std::fs::metadata(&body_path).unwrap().modified().unwrap();
    assert!(touched >= now);
    drop(cache.get(&a).await.unwrap());
    assert_eq!(
        std::fs::metadata(&body_path).unwrap().modified().unwrap(),
        touched
    );
    let entry_bytes = std::fs::metadata(dir.path().join(format!("{a}.json")))
        .unwrap()
        .len()
        + 6;
    cache
        .put(
            &c,
            StatusCode::OK,
            &h,
            Bytes::from_static(b"object"),
            Duration::from_secs(3600),
            entry_bytes * 2 + 16,
        )
        .await
        .unwrap();
    assert!(cache.get(&b).await.is_none());
    assert!(cache.get(&a).await.is_some());
    assert!(cache.get(&c).await.is_some());
}

#[tokio::test]
async fn dns_listener_start_failure_rolls_back_proxy_and_stop_releases_all_sockets() {
    use tokio::net::UdpSocket;
    let occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let dns_port = occupied.local_addr().unwrap().port();
    let free = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_port = free.local_addr().unwrap().port();
    drop(free);
    let dir = tempfile::tempdir().unwrap();
    let configuration = Settings {
        proxy_port,
        lan_dns_enabled: true,
        lan_dns_port: dns_port,
        ..Settings::default()
    };
    let error = start_proxy(
        configuration.clone(),
        CacheStore::new(dir.path().join("cache")),
        Arc::new(Stats::default()),
        TlsInspection::lazy(dir.path().join("authority.json")),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(
        error.listener_bind_failure().unwrap().service,
        ListenerService::Dns
    );
    drop(
        TcpListener::bind((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .unwrap(),
    );
    drop(occupied);
    let handle = start_proxy(
        configuration,
        CacheStore::new(dir.path().join("cache")),
        Arc::new(Stats::default()),
        TlsInspection::lazy(dir.path().join("authority.json")),
    )
    .await
    .unwrap();
    handle.stop().await;
    drop(
        TcpListener::bind((Ipv4Addr::LOCALHOST, proxy_port))
            .await
            .unwrap(),
    );
    drop(
        TcpListener::bind((Ipv4Addr::LOCALHOST, dns_port))
            .await
            .unwrap(),
    );
    drop(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, dns_port))
            .await
            .unwrap(),
    );
}
