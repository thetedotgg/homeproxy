use super::*;

const LAN: &str = "192.168.68.2:8181";
const PEER: &str = "192.168.68.81:49152";

async fn fixture(directory: &std::path::Path) -> ProxyContext {
    let mut context = crate::proxy::service_port_tests::context(
        directory,
        Settings {
            lan_enabled: true,
            listen_ips: vec!["192.168.68.2".into()],
            proxy_username: "fixture-user-not-public".into(),
            proxy_password: "fixture-secret-never-public".into(),
            ..Settings::default()
        },
    )
    .await;
    context.listener_address = Some(LAN.parse().unwrap());
    context
}

fn fingerprint(context: &ProxyContext) -> String {
    hex::encode(Sha256::digest(
        context.tls_inspection.root_certificate_der().as_ref(),
    ))
}

fn request(method: Method, path: &str, host: &str) -> Request<()> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, host)
        .body(())
        .unwrap()
}

#[tokio::test]
async fn public_setup_exact_der_head_and_hardened_local_responses() {
    let directory = tempfile::tempdir().unwrap();
    let context = fixture(directory.path()).await;
    let fp = fingerprint(&context);
    for path in [SETUP_PATH, CERT_PATH, PROFILE_PATH] {
        let uri = format!("{path}?lang=en&fp={fp}");
        let get = response(&request(Method::GET, &uri, LAN), &context).unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(get.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(get.headers()["x-content-type-options"], "nosniff");
        assert_eq!(get.headers()["referrer-policy"], "no-referrer");
        assert_eq!(get.headers()["x-frame-options"], "DENY");
        assert!(!get.headers().contains_key("access-control-allow-origin"));
        assert!(get.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
        let length = get.headers()[CONTENT_LENGTH]
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let bytes = get.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), length);
        assert!(length <= MAX_SETUP_BODY);
        let head = response(&request(Method::HEAD, &uri, LAN), &context).unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers()[CONTENT_LENGTH].to_str().unwrap(),
            length.to_string()
        );
        assert!(head
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());
        if path == CERT_PATH {
            assert_eq!(
                &bytes[..],
                context.tls_inspection.root_certificate_der().as_ref()
            );
        } else {
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(!text.contains(&context.settings.proxy_username));
            assert!(!text.contains(&context.settings.proxy_password));
            assert!(!text.contains("PRIVATE KEY"));
            assert!(!text.contains("protected_private_key"));
            if path == SETUP_PATH {
                assert!(text.contains(&format!("{CERT_PATH}?lang=en&amp;fp={fp}")));
                assert!(text.contains(&format!("{PROFILE_PATH}?lang=en&amp;fp={fp}")));
                assert!(text.contains("192.168.68.2"));
                assert!(text.contains("8181"));
                assert!(text.contains("does not prove authenticity"));
                assert!(text.contains("certutil -hashfile HomeProxy-CA.cer SHA256"));
                assert!(!text.contains("<script"));
                assert!(!text.contains("<form"));
            }
        }
    }
    assert!(!context.settings.https_client_trust_acknowledged);
    assert_eq!(context.stats.snapshot().authenticated_external_requests, 0);
    assert_eq!(context.stats.snapshot().successful_external_requests, 0);
}

#[tokio::test]
async fn public_setup_rejects_host_methods_escaped_paths_and_queries() {
    let directory = tempfile::tempdir().unwrap();
    let context = fixture(directory.path()).await;
    let fp = fingerprint(&context);
    let valid = format!("{CERT_PATH}?fp={fp}");
    for host in [
        "homeproxy.test",
        "evil.example:8181",
        "192.168.68.3:8181",
        "192.168.68.2:8182",
        "192.168.68.2",
        "user@192.168.68.2:8181",
        "192.168.068.2:8181",
        "192.168.68.2:8181.",
    ] {
        assert_eq!(
            response(&request(Method::GET, &valid, host), &context)
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST,
            "{host}"
        );
    }
    let mut duplicate_host = request(Method::GET, &valid, LAN);
    duplicate_host
        .headers_mut()
        .append(HOST, HeaderValue::from_static(LAN));
    assert_eq!(
        response(&duplicate_host, &context).unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let mut missing_host = request(Method::GET, &valid, LAN);
    missing_host.headers_mut().remove(HOST);
    assert_eq!(
        response(&missing_host, &context).unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    for method in [
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::OPTIONS,
        Method::CONNECT,
    ] {
        let denied = response(&request(method.clone(), &valid, LAN), &context).unwrap();
        assert_eq!(denied.status(), StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(denied.headers()["allow"], "GET, HEAD");
    }
    for header in ["upgrade", "connection"] {
        let mut upgrade = request(Method::GET, &valid, LAN);
        upgrade.headers_mut().insert(
            HeaderName::from_static(header),
            HeaderValue::from_static("Upgrade"),
        );
        assert_eq!(
            response(&upgrade, &context).unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    for path in [
        "/homeproxy",
        "/homeproxy/",
        "/homeproxy/settings",
        "/homeproxy/ca.cer/../setup",
        "/homeproxy/%63a.cer",
        "/%68omeproxy/ca.cer",
        "/other/../homeproxy/ca.cer",
        "/homeproxy%2fca.cer",
    ] {
        let uri = format!("{path}?fp={fp}");
        assert_eq!(
            response(&request(Method::GET, &uri, LAN), &context)
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    for uri in [
        format!("http://{LAN}{valid}"),
        format!("http://user@{LAN}{valid}"),
    ] {
        assert_eq!(
            response(&request(Method::GET, &uri, LAN), &context)
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for uri in [
        format!("http://evil.example{valid}"),
        "http://example.com/a/homeproxy/b".into(),
        "http://example.com/a/%68omeproxy/b".into(),
        format!("http://192.168.68.3:8181{valid}"),
        format!("http://192.168.68.2:8182{valid}"),
    ] {
        assert!(
            response(&request(Method::GET, &uri, LAN), &context).is_none(),
            "{uri}"
        );
    }
    let connect = request(Method::CONNECT, LAN, LAN);
    assert_eq!(
        response(&connect, &context).unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    for query in [
        String::new(),
        "lang=cs".into(),
        format!("fp={fp}&fp={fp}"),
        format!("fp={fp}&lang=cs&lang=en"),
        format!("fp={fp}&lang=de"),
        format!("fp={fp}&token=secret"),
        format!("fp={fp}&"),
        format!("fp={fp}&lang=%65n"),
        format!("fp={}", fp.to_uppercase()),
        "fp=1234".into(),
        format!("fp={}g", "0".repeat(63)),
        format!("fp={fp}%23x"),
        format!("fp={fp}{}", "x".repeat(100)),
    ] {
        let req = request(Method::GET, &format!("{SETUP_PATH}?{query}"), LAN);
        assert_eq!(
            response(&req, &context).unwrap().status(),
            StatusCode::BAD_REQUEST,
            "{query}"
        );
    }
    let oversized = format!("/{}/%68omeproxy/ca.cer?fp={fp}", "x".repeat(2048));
    assert_eq!(
        response(&request(Method::GET, &oversized, LAN), &context)
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let wrong = format!("{CERT_PATH}?fp={}", "0".repeat(64));
    assert_eq!(
        response(&request(Method::GET, &wrong, LAN), &context)
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let default_cs = response(
        &request(Method::GET, &format!("{SETUP_PATH}?fp={fp}"), LAN),
        &context,
    )
    .unwrap();
    assert!(
        std::str::from_utf8(&default_cs.into_body().collect().await.unwrap().to_bytes())
            .unwrap()
            .contains("<html lang=\"cs\">")
    );
}

#[tokio::test]
async fn public_setup_requires_selected_private_lan_and_never_generates_ca() {
    let directory = tempfile::tempdir().unwrap();
    let context = fixture(directory.path()).await;
    let uri = format!("{CERT_PATH}?fp={}", fingerprint(&context));
    for scenario in [
        "disabled",
        "other-listener",
        "loopback",
        "public",
        "unspecified",
        "unprepared",
        "corrupt",
    ] {
        let mut candidate = context.clone();
        match scenario {
            "disabled" => candidate.settings.lan_enabled = false,
            "other-listener" => candidate.settings.listen_ips = vec!["192.168.68.3".into()],
            "loopback" => candidate.listener_address = Some("127.0.0.1:8181".parse().unwrap()),
            "public" => candidate.listener_address = Some("93.184.216.34:8181".parse().unwrap()),
            "unspecified" => candidate.listener_address = None,
            "unprepared" | "corrupt" => {
                let path = directory.path().join(format!("{scenario}.json"));
                if scenario == "corrupt" {
                    std::fs::write(&path, b"corrupt").unwrap();
                }
                candidate.tls_inspection = TlsInspection::lazy(path);
            }
            _ => unreachable!(),
        }
        let host = candidate
            .listener_address
            .map_or_else(|| LAN.into(), |address| address.to_string());
        assert_eq!(
            response(&request(Method::GET, &uri, &host), &candidate)
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{scenario}"
        );
    }
    assert!(!directory.path().join("unprepared.json").exists());
    assert_eq!(
        std::fs::read(directory.path().join("corrupt.json")).unwrap(),
        b"corrupt"
    );
}

#[tokio::test]
async fn public_setup_mobileconfig_has_single_matching_root_and_stable_distinct_uuids() {
    let directory = tempfile::tempdir().unwrap();
    let context = fixture(directory.path()).await;
    let certificate = context.tls_inspection.root_certificate_der();
    let uri = format!("{PROFILE_PATH}?lang=en&fp={}", fingerprint(&context));
    let res = response(&request(Method::GET, &uri, LAN), &context).unwrap();
    assert_eq!(
        res.headers()[CONTENT_TYPE],
        "application/x-apple-aspen-config"
    );
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let xml = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(
        xml.matches("<string>com.apple.security.root</string>")
            .count(),
        1
    );
    assert_eq!(xml.matches("<array>").count(), 1);
    assert_eq!(xml.matches("<data>").count(), 1);
    let pem = context
        .tls_inspection
        .export_certificate(CertificateFormat::Pem)
        .unwrap();
    let encoded = pem
        .certificate
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    assert!(xml.contains(&format!("<data>{encoded}</data>")));
    for forbidden in [
        "com.apple.wifi",
        "com.apple.vpn",
        "com.apple.mdm",
        "ProxyServer",
        "ProxyPACURL",
        "Password",
        "UserName",
        "PRIVATE KEY",
    ] {
        assert!(!xml.contains(forbidden), "{forbidden}");
    }
    let top = profile_uuid(certificate.as_ref(), b"homeproxy.profile.root-only.v1");
    let root = profile_uuid(certificate.as_ref(), b"homeproxy.payload.root-only.v1");
    assert_ne!(top, root);
    assert_eq!(
        top,
        profile_uuid(certificate.as_ref(), b"homeproxy.profile.root-only.v1")
    );
    for uuid in [top, root] {
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.as_bytes()[14], b'8');
        assert!(matches!(uuid.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        assert!(xml.contains(&format!("<key>PayloadUUID</key><string>{uuid}</string>")));
    }
    assert_ne!(
        profile_uuid(certificate.as_ref(), b"homeproxy.profile.root-only.v1"),
        profile_uuid(b"different CA", b"homeproxy.profile.root-only.v1")
    );
}

// A real HTTP connection with the same isolated explicit-LAN-peer seam used by
// service-port tests; production accept_loop separately supplies local_addr().
async fn exchange(context: ProxyContext, target: &str) -> Vec<u8> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer: SocketAddr = PEER.parse().unwrap();
    let mut context = context;
    context.activity_id = context
        .stats
        .begin_activity(peer.ip(), "192.168.68.2".parse().unwrap());
    context.connection_permit = Some(Arc::new(
        context.connections.try_acquire(peer.ip()).unwrap(),
    ));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let stream = MeteredStream::new(
            stream,
            context.stats.clone(),
            peer.ip(),
            context.activity_id,
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
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(target.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    task.await.unwrap();
    bytes
}

#[tokio::test]
async fn public_setup_http_bypasses_auth_only_for_public_resources_and_preserves_device_deny() {
    let directory = tempfile::tempdir().unwrap();
    let context = fixture(directory.path()).await;
    let fp = fingerprint(&context);
    for (method, path) in [
        ("GET", SETUP_PATH),
        ("GET", CERT_PATH),
        ("GET", PROFILE_PATH),
        ("HEAD", CERT_PATH),
    ] {
        let raw = format!("{method} {path}?fp={fp} HTTP/1.1\r\nHost: {LAN}\r\nProxy-Authorization: Basic invalid\r\nConnection: close\r\n\r\n");
        let bytes = exchange(context.clone(), &raw).await;
        assert!(bytes.starts_with(b"HTTP/1.1 200"));
        assert!(!String::from_utf8_lossy(&bytes)
            .to_ascii_lowercase()
            .contains("proxy-authenticate:"));
        if method == "HEAD" {
            assert!(bytes.ends_with(b"\r\n\r\n"));
        }
    }
    let snapshot = context.stats.snapshot();
    assert_eq!(snapshot.total_requests, 4);
    assert_eq!(snapshot.authenticated_external_requests, 0);
    assert_eq!(snapshot.successful_external_requests, 0);
    // unique_clients means observed TCP peers, not authenticated/verified devices.
    // MeteredStream -> Stats::traffic_accounted records this peer before auth;
    // preserving wire metering necessarily preserves that transport inventory.
    assert_eq!(snapshot.unique_clients, 1);
    assert_eq!(snapshot.clients.len(), 1);
    let client = &snapshot.clients[0];
    assert_eq!(client.ip, PEER.parse::<SocketAddr>().unwrap().ip());
    assert!(client.last_seen_unix_ms > 0);
    assert_eq!(client.upload_bytes, snapshot.upload_bytes);
    assert_eq!(client.download_bytes, snapshot.download_bytes);
    assert!(snapshot
        .activity
        .iter()
        .all(|activity| activity.origin_bytes == 0 && activity.delivered_bytes == 0));
    assert_eq!(snapshot.origin_bytes, 0);
    assert_eq!(snapshot.cache_misses, 0);
    assert_eq!(snapshot.connect_tunnels, 0);
    assert!(
        snapshot.download_bytes > 0,
        "existing wire metering must remain active"
    );
    assert!(!context.settings.https_client_trust_acknowledged);
    for target in [
        "http://example.com/",
        "http://example.com/homeproxyish",
        "http://example.com/homeproxy/setup",
        "http://example.com/a/homeproxy/b",
        "http://example.com/a/%68omeproxy/b",
        "http://homeproxy.test/ca.cer",
    ] {
        let raw =
            format!("GET {target} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
        let bytes = exchange(context.clone(), &raw).await;
        assert!(bytes.starts_with(b"HTTP/1.1 407"), "{target}");
        assert!(String::from_utf8_lossy(&bytes).contains("Digest "));
    }
    let mut denied = context.clone();
    denied
        .settings
        .denied_client_ips
        .push("192.168.68.81".parse().unwrap());
    let raw =
        format!("GET {CERT_PATH}?fp={fp} HTTP/1.1\r\nHost: {LAN}\r\nConnection: close\r\n\r\n");
    let bytes = exchange(denied, &raw).await;
    assert!(bytes.starts_with(b"HTTP/1.1 407"));
    assert!(String::from_utf8_lossy(&bytes).contains("device-blocked"));
    let malformed = format!(
        "GET /homeproxy/settings?fp={fp} HTTP/1.1\r\nHost: {LAN}\r\nConnection: close\r\n\r\n"
    );
    assert!(exchange(context.clone(), &malformed)
        .await
        .starts_with(b"HTTP/1.1 404"));
    assert_eq!(context.stats.snapshot().authenticated_external_requests, 0);
    assert_eq!(context.stats.snapshot().successful_external_requests, 0);
    assert_eq!(context.stats.snapshot().origin_bytes, 0);
}

#[tokio::test]
async fn public_setup_does_not_intercept_authenticated_third_party_namespace_forwarding() {
    use md5::Md5;

    let directory = tempfile::tempdir().unwrap();
    let context = fixture(directory.path()).await;
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let destination: SocketAddr = "93.184.216.12:80".parse().unwrap();
    assert!(destination_is_public(destination.ip()));
    context
        .resolver
        .map_test_dial(destination, origin.local_addr().unwrap());
    let uri = "http://93.184.216.12/homeproxy/setup";
    let challenge = context.auth.challenge(&Method::GET, uri);
    let nonce = challenge
        .split("nonce=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let digest = |value: &str| hex::encode(Md5::digest(value.as_bytes()));
    let username = &context.settings.proxy_username;
    let ha1 = digest(&format!(
        "{username}:HomeProxy:{}",
        context.settings.proxy_password
    ));
    let ha2 = digest(&format!("GET:{uri}"));
    let answer = digest(&format!("{ha1}:{nonce}:00000001:fixture:auth:{ha2}"));
    let authorization = format!("Digest username=\"{username}\", realm=\"HomeProxy\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{answer}\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"fixture\"");
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = timeout(Duration::from_secs(3), origin.accept())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(
                timeout(Duration::from_secs(3), stream.read_u8())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        let headers = String::from_utf8(bytes).unwrap();
        assert!(headers.starts_with("GET /homeproxy/setup HTTP/1.1\r\n"));
        assert!(!headers
            .to_ascii_lowercase()
            .contains("proxy-authorization:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nPONG")
            .await
            .unwrap();
    });
    let raw = format!("GET {uri} HTTP/1.1\r\nHost: 93.184.216.12\r\nProxy-Authorization: {authorization}\r\nConnection: close\r\n\r\n");
    let bytes = exchange(context.clone(), &raw).await;
    assert!(bytes.starts_with(b"HTTP/1.1 200"));
    assert!(bytes.ends_with(b"PONG"));
    origin_task.await.unwrap();
    let stats = context.stats.snapshot();
    assert_eq!(stats.authenticated_external_requests, 1);
    assert_eq!(stats.successful_external_requests, 1);
    assert_eq!(stats.origin_bytes, 4);
    assert!(!context.settings.https_client_trust_acknowledged);
    context.cancellation.cancel();
    context.tasks.close();
    context.tasks.wait().await;
}

#[tokio::test]
async fn public_setup_default_http_port_accepts_only_canonical_omitted_or_explicit_host() {
    let directory = tempfile::tempdir().unwrap();
    let mut context = fixture(directory.path()).await;
    context.listener_address = Some("192.168.68.2:80".parse().unwrap());
    let fp = fingerprint(&context);
    for path in [SETUP_PATH, CERT_PATH, PROFILE_PATH] {
        let uri = format!("{path}?lang=en&fp={fp}");
        let mut canonical_length = None;
        for host in ["192.168.68.2", "192.168.68.2:80"] {
            let get = response(&request(Method::GET, &uri, host), &context).unwrap();
            assert_eq!(get.status(), StatusCode::OK, "{path} {host}");
            let length = get.headers()[CONTENT_LENGTH]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let body = get.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.len(), length);
            if let Some(expected) = canonical_length {
                assert_eq!(length, expected);
            }
            canonical_length = Some(length);
            let head = response(&request(Method::HEAD, &uri, host), &context).unwrap();
            assert_eq!(head.status(), StatusCode::OK, "{path} {host}");
            assert_eq!(
                head.headers()[CONTENT_LENGTH].to_str().unwrap(),
                length.to_string()
            );
            assert!(head
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty());

            // Real HTTP parsing over the isolated explicit-listener seam, including
            // the Host spelling sent by browsers for HTTP's default port.
            for method in ["GET", "HEAD"] {
                let raw =
                    format!("{method} {uri} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
                let bytes = exchange(context.clone(), &raw).await;
                assert!(bytes.starts_with(b"HTTP/1.1 200"), "{method} {path} {host}");
                let boundary = bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                assert!(String::from_utf8_lossy(&bytes[..boundary])
                    .contains(&format!("content-length: {length}\r\n")));
                if method == "HEAD" {
                    assert_eq!(bytes.len(), boundary);
                } else {
                    assert_eq!(bytes.len() - boundary, length);
                }
            }
        }
        for host in [
            "192.168.68.2:81",
            "192.168.68.2:080",
            "192.168.068.2",
            "192.168.68.2.",
            "user@192.168.68.2",
            "user@192.168.68.2:80",
            "192.168.68.3",
        ] {
            assert_eq!(
                response(&request(Method::GET, &uri, host), &context)
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST,
                "{host}"
            );
        }
        let mut duplicate = request(Method::GET, &uri, "192.168.68.2");
        duplicate
            .headers_mut()
            .append(HOST, HeaderValue::from_static("192.168.68.2:80"));
        assert_eq!(
            response(&duplicate, &context).unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        for authority in [
            "192.168.68.2",
            "192.168.68.2:80",
            "user@192.168.68.2",
            "user@192.168.68.2:80",
        ] {
            let absolute = format!("http://{authority}{uri}");
            assert_eq!(
                response(&request(Method::GET, &absolute, "192.168.68.2"), &context)
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST,
                "{absolute}"
            );
        }
        let foreign = format!("http://example.com{uri}");
        assert!(response(&request(Method::GET, &foreign, "example.com"), &context).is_none());
    }
    let stats = context.stats.snapshot();
    assert_eq!(stats.authenticated_external_requests, 0);
    assert_eq!(stats.successful_external_requests, 0);
    assert_eq!(stats.origin_bytes, 0);
    assert!(!context.settings.https_client_trust_acknowledged);
}
