use super::tests::{raw_http_exchange, test_tls_inspection};
use super::*;
use std::sync::atomic::AtomicUsize;

struct Fixture {
    handle: ProxyHandle,
    port: u16,
    hits: Arc<AtomicUsize>,
    origin: JoinHandle<()>,
    directory: tempfile::TempDir,
}
impl Fixture {
    async fn new(response: fn(&str, usize) -> Vec<u8>, endpoint: bool) -> Self {
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = origin_listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let origin = tokio::spawn(async move {
            loop {
                let (mut stream, _) = origin_listener.accept().await.unwrap();
                let number = counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut byte = [0];
                    while !request.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte).await.unwrap() == 0 {
                            return;
                        }
                        request.push(byte[0]);
                    }
                    let bytes = response(&String::from_utf8(request).unwrap(), number);
                    stream.write_all(&bytes).await.unwrap();
                });
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let mut settings = Settings {
            cache_enabled: true,
            ..Settings::default()
        };
        if endpoint {
            settings
                .public_cache_endpoints
                .push(crate::config::PublicCacheEndpoint {
                    host: "cache.example".into(),
                    path_prefix: "/".into(),
                });
        }
        let handle = spawn_proxy_with_listeners(
            settings,
            CacheStore::new(directory.path().join("cache")),
            Arc::new(Stats::default()),
            test_tls_inspection(directory.path()),
            vec![listener],
            false,
        )
        .unwrap();
        let public = "93.184.216.34".parse().unwrap();
        handle
            .context
            .resolver
            .set_test_answer("cache.example", vec![public], Duration::ZERO);
        handle
            .context
            .resolver
            .map_test_dial(SocketAddr::new(public, 80), address);
        Self {
            handle,
            port,
            hits,
            origin,
            directory,
        }
    }
    async fn request(&self, method: &str, headers: &str) -> Vec<u8> {
        raw_http_exchange(self.port,&format!("{method} http://cache.example/file HTTP/1.1\r\nHost: cache.example\r\nConnection: close\r\n{headers}\r\n")).await
    }
    fn expire(&self) {
        for entry in std::fs::read_dir(self.directory.path().join("cache")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|v| v == "json") {
                let mut metadata: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                metadata["expires_unix_seconds"] = 0.into();
                std::fs::write(path, serde_json::to_vec(&metadata).unwrap()).unwrap();
            }
        }
    }
    async fn stop(self) {
        self.handle.stop().await;
        self.origin.abort();
    }
}
fn header(bytes: &[u8]) -> String {
    let end = bytes.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
    String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase()
}
fn body(bytes: &[u8]) -> &[u8] {
    let end = bytes.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
    &bytes[end..]
}

#[tokio::test]
async fn stored_no_cache_revalidates_every_request_and_refuses_offline() {
    let f=Fixture::new(|request,_| {
        if request.to_ascii_lowercase().contains("if-none-match: \"same\"") { b"HTTP/1.1 304 Not Modified\r\nCache-Control: public, no-cache, max-age=120\r\nETag: \"same\"\r\nConnection: close\r\n\r\n".to_vec() }
        else { b"HTTP/1.1 200 OK\r\nCache-Control: public, no-cache, max-age=120\r\nETag: \"same\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc".to_vec() }
    },false).await;
    for _ in 0..3 {
        let r = f.request("GET", "").await;
        assert_eq!(body(&r), b"abc");
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 3);
    let mut offline = f.handle.context.clone();
    offline.settings.cache_mode = CacheMode::Offline;
    let request = Request::builder()
        .uri("http://cache.example/file")
        .body(empty_body())
        .unwrap();
    assert!(matches!(
        forward_web_request(
            request,
            &offline,
            WebOrigin::Plain {
                host: "cache.example".into(),
                port: 80
            }
        )
        .await,
        Err(ProxyError::Offline)
    ));
    assert_eq!(f.hits.load(Ordering::SeqCst), 3);
    f.stop().await;
}
#[tokio::test]
async fn head_reuses_get_without_range_or_savings_and_strong_refresh_keeps_body() {
    let f=Fixture::new(|request,_| { let headers=b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nETag: \"same\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\n"; let mut result=headers.to_vec(); if !request.starts_with("HEAD ") { result.extend_from_slice(b"abc"); } result },false).await;
    assert_eq!(body(&f.request("GET", "").await), b"abc");
    let savings = f.handle.context.stats.snapshot().cache_bytes_saved;
    let head = f.request("HEAD", "Range: bytes=1-2\r\n").await;
    assert!(header(&head).starts_with("http/1.1 200"));
    assert!(header(&head).contains("content-length: 3"));
    assert!(body(&head).is_empty());
    assert_eq!(f.handle.context.stats.snapshot().cache_bytes_saved, savings);
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
    f.expire();
    assert!(body(&f.request("HEAD", "").await).is_empty());
    assert_eq!(body(&f.request("GET", "").await), b"abc");
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}
#[tokio::test]
async fn head_validator_mismatch_invalidates_the_get_body() {
    let f=Fixture::new(|request,n| { let mut response=format!("HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nETag: \"v{n}\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\n").into_bytes(); if !request.starts_with("HEAD "){response.extend_from_slice(b"abc");} response },false).await;
    f.request("GET", "").await;
    f.expire();
    f.request("HEAD", "").await;
    assert_eq!(body(&f.request("GET", "").await), b"abc");
    assert_eq!(f.hits.load(Ordering::SeqCst), 3);
    f.stop().await;
}
#[tokio::test]
async fn expires_endpoint_and_verified_vary_share_only_matching_values() {
    let f=Fixture::new(|request,_| { let date=SystemTime::now(); let expires=date+Duration::from_secs(120); let ua=request.lines().find(|v|v.to_ascii_lowercase().starts_with("user-agent:")).unwrap_or("absent"); let payload=if ua.ends_with("one"){b"one"}else{b"two"}; let mut r=format!("HTTP/1.1 200 OK\r\nDate: {}\r\nExpires: {}\r\nVary: User-Agent\r\nContent-Length: 3\r\nConnection: close\r\n\r\n",httpdate::fmt_http_date(date),httpdate::fmt_http_date(expires)).into_bytes(); r.extend_from_slice(payload);r },true).await;
    assert_eq!(
        body(
            &f.request("GET", "User-Agent: one\r\nAccept-Language: en\r\n")
                .await
        ),
        b"one"
    );
    let hit = f
        .request("GET", "User-Agent: one\r\nAccept-Language: cs\r\n")
        .await;
    assert!(header(&hit).contains("homeproxy; hit"));
    assert_eq!(body(&f.request("GET", "User-Agent: two\r\n").await), b"two");
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}
#[tokio::test]
async fn encoded_representation_obeys_q_zero_even_without_vary_and_ranges_encoded_bytes() {
    let f=Fixture::new(|request,_| { if request.contains("gzip;q=0") { return b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nContent-Length: 3\r\nConnection: close\r\n\r\nraw".to_vec(); }
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nContent-Encoding: gzip\r\nETag: \"coded\"\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\x1f\x8b\x01\x02".to_vec() },false).await;
    assert_eq!(
        body(&f.request("GET", "Accept-Encoding: gzip\r\n").await),
        b"\x1f\x8b\x01\x02"
    );
    let range = f
        .request("GET", "Accept-Encoding: gzip\r\nRange: bytes=1-2\r\n")
        .await;
    assert!(header(&range).contains("206"));
    assert_eq!(body(&range), b"\x8b\x01");
    assert_eq!(
        body(
            &f.request("GET", "Accept-Encoding: gzip;q=0, identity\r\n")
                .await
        ),
        b"raw"
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}
#[tokio::test]
async fn range_miss_stores_verified_fragment_and_reuses_covered_range() {
    let f=Fixture::new(|_,_|b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, max-age=120\r\nETag: \"fragment\"\r\nContent-Range: bytes 1-3/6\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbcd".to_vec(),false).await;
    assert_eq!(
        body(&f.request("GET", "Range: bytes=1-3\r\n").await),
        b"bcd"
    );
    let hit = f.request("GET", "Range: bytes=2-3\r\n").await;
    assert_eq!(body(&hit), b"cd");
    assert!(header(&hit).contains("homeproxy; hit"));
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
    f.stop().await;
}

#[test]
fn expires_precedence_no_cache_field_form_and_invalid_directives() {
    let mut h = HeaderMap::new();
    h.insert(
        CACHE_CONTROL,
        "public, max-age=10, s-maxage=20".parse().unwrap(),
    );
    h.insert("expires", "bad".parse().unwrap());
    assert_eq!(
        cache_policy::ttl(&h, StatusCode::OK, false),
        Some(Duration::from_secs(20))
    );
    h.insert(
        CACHE_CONTROL,
        "public, no-cache=\"set-cookie\", max-age=100"
            .parse()
            .unwrap(),
    );
    assert_eq!(
        cache_policy::ttl(&h, StatusCode::OK, false),
        Some(Duration::ZERO)
    );
    h.insert(CACHE_CONTROL, "public, max-age=0".parse().unwrap());
    assert_eq!(
        cache_policy::ttl(&h, StatusCode::OK, false),
        Some(Duration::ZERO)
    );
    h.insert(CACHE_CONTROL, "broken==\"".parse().unwrap());
    assert!(cache_policy::ttl(&h, StatusCode::OK, true).is_none());
}

#[tokio::test]
async fn variant_index_restores_verified_disk_entries_for_offline_restart() {
    let f=Fixture::new(|_,_|b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nVary: Accept-Language\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc".to_vec(),false).await;
    assert_eq!(
        body(&f.request("GET", "Accept-Language: en\r\n").await),
        b"abc"
    );
    let mut context = f.handle.context.clone();
    context.cache = CacheStore::new(f.directory.path().join("cache"));
    context.settings.cache_mode = CacheMode::Offline;
    let request = Request::builder()
        .uri("http://cache.example/file")
        .header(ACCEPT_LANGUAGE, "en")
        .body(empty_body())
        .unwrap();
    let response = forward_web_request(
        request,
        &context,
        WebOrigin::Plain {
            host: "cache.example".into(),
            port: 80,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"abc")
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
    let wrong = Request::builder()
        .uri("http://cache.example/file")
        .header(ACCEPT_LANGUAGE, "cs")
        .body(empty_body())
        .unwrap();
    assert!(matches!(
        forward_web_request(
            wrong,
            &context,
            WebOrigin::Plain {
                host: "cache.example".into(),
                port: 80
            }
        )
        .await,
        Err(ProxyError::Offline)
    ));
    f.stop().await;
}
#[tokio::test]
async fn brotli_raw_bytes_are_reused_only_for_accepted_coding() {
    let f=Fixture::new(|request,_| { if request.contains("br;q=0") { b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nContent-Length: 3\r\nConnection: close\r\n\r\nraw".to_vec() } else { b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nContent-Encoding: br\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\x8b\x01\x80\xff".to_vec() } },false).await;
    let offered = "Accept-Encoding: br, identity;q=0\r\n";
    assert_eq!(body(&f.request("GET", offered).await), b"\x8b\x01\x80\xff");
    let hit = f.request("GET", offered).await;
    assert_eq!(body(&hit), b"\x8b\x01\x80\xff");
    assert!(header(&hit).contains("homeproxy; hit"));
    assert_eq!(
        body(
            &f.request("GET", "Accept-Encoding: br;q=0, identity\r\n")
                .await
        ),
        b"raw"
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}
#[tokio::test]
async fn complete_fragment_coverage_promotes_to_full_get() {
    let f=Fixture::new(|request,_| { assert!(request.to_ascii_lowercase().contains("range: bytes="));
        if request.contains("bytes=0-2") { b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, max-age=120\r\nETag: \"same\"\r\nContent-Range: bytes 0-2/6\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc".to_vec() }
        else { b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, max-age=120\r\nETag: \"same\"\r\nContent-Range: bytes 3-5/6\r\nContent-Length: 3\r\nConnection: close\r\n\r\ndef".to_vec() }
    },false).await;
    assert_eq!(
        body(&f.request("GET", "Range: bytes=0-2\r\n").await),
        b"abc"
    );
    assert_eq!(
        body(&f.request("GET", "Range: bytes=3-5\r\n").await),
        b"def"
    );
    let full = f.request("GET", "").await;
    assert!(header(&full).starts_with("http/1.1 200"));
    assert_eq!(body(&full), b"abcdef");
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}

#[tokio::test]
async fn changed_vary_on_304_refetches_once_and_rekeys_the_live_body() {
    let f=Fixture::new(|request,n| match n {
        0=>b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nVary: Accept-Language\r\nETag: \"same\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\none".to_vec(),
        1=>{assert!(request.to_ascii_lowercase().contains("if-none-match:"));b"HTTP/1.1 304 Not Modified\r\nCache-Control: public, max-age=120\r\nVary: Accept\r\nETag: \"same\"\r\nConnection: close\r\n\r\n".to_vec()},
        2=>{assert!(!request.to_ascii_lowercase().contains("if-none-match:"));b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nVary: Accept\r\nETag: \"new\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo".to_vec()},
        _=>panic!("unexpected additional origin request"),
    },false).await;
    assert_eq!(
        body(&f.request("GET", "Accept-Language: en\r\n").await),
        b"one"
    );
    f.expire();
    assert_eq!(
        body(&f.request("GET", "Accept-Language: en\r\n").await),
        b"two"
    );
    let hit = f.request("GET", "Accept-Language: cs\r\n").await;
    assert_eq!(body(&hit), b"two");
    assert!(header(&hit).contains("homeproxy; hit"));
    assert_eq!(f.hits.load(Ordering::SeqCst), 3);
    f.stop().await;
}

async fn rejected_304_retires_other_language_variants(
    response: fn(&str, usize) -> Vec<u8>,
    retry_succeeds: bool,
) {
    let f = Fixture::new(response, false).await;
    let mut keys = Vec::new();
    for (language, expected_body) in [("en", b"one"), ("cs", b"dva")] {
        let response = f
            .request("GET", &format!("Accept-Language: {language}\r\n"))
            .await;
        assert!(header(&response).starts_with("http/1.1 200"));
        assert_eq!(body(&response), expected_body);
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(ACCEPT_LANGUAGE, language)
            .body(())
            .unwrap();
        let key = cache_policy::cached_key(&request, &f.handle.context, false)
            .await
            .unwrap();
        keys.push(key);
    }
    assert_ne!(keys[0], keys[1]);
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    // Only English requires validation; Czech would otherwise remain a fresh HIT.
    let path = f
        .directory
        .path()
        .join("cache")
        .join(format!("{}.json", keys[0]));
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    metadata["expires_unix_seconds"] = 0.into();
    std::fs::write(path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    assert!(f
        .handle
        .context
        .cache
        .snapshot(&keys[0])
        .await
        .unwrap()
        .remaining_ttl
        .is_zero());
    assert!(!f
        .handle
        .context
        .cache
        .snapshot(&keys[1])
        .await
        .unwrap()
        .remaining_ttl
        .is_zero());

    let retried = f.request("GET", "Accept-Language: en\r\n").await;
    if retry_succeeds {
        assert!(header(&retried).starts_with("http/1.1 200"));
        assert_eq!(body(&retried), b"secret");
    } else {
        assert!(header(&retried).starts_with("http/1.1 502"));
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 4);
    for key in &keys {
        assert!(f.handle.context.cache.snapshot(key).await.is_none());
        assert!(!f
            .directory
            .path()
            .join("cache")
            .join(format!("{key}.json"))
            .exists());
    }
    // Check both the current index and a fresh store hydrating the same disk.
    for restarted in [false, true] {
        let mut context = f.handle.context.clone();
        context.settings.cache_mode = CacheMode::Offline;
        if restarted {
            context.cache = CacheStore::new(f.directory.path().join("cache"));
        }
        for language in ["en", "cs"] {
            let request = Request::builder()
                .uri("http://cache.example/file")
                .header(ACCEPT_LANGUAGE, language)
                .body(empty_body())
                .unwrap();
            assert!(
                matches!(
                    forward_web_request(
                        request,
                        &context,
                        WebOrigin::Plain {
                            host: "cache.example".into(),
                            port: 80,
                        }
                    )
                    .await,
                    Err(ProxyError::Offline)
                ),
                "retired {language} representation survived (restarted={restarted})"
            );
        }
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 4);
    let czech = f.request("GET", "Accept-Language: cs\r\n").await;
    assert!(header(&czech).starts_with("http/1.1 503"));
    if retry_succeeds {
        assert_eq!(body(&czech), b"unavailable");
        assert_eq!(f.hits.load(Ordering::SeqCst), 5);
    } else {
        let request = Request::builder()
            .uri("http://cache.example/file")
            .body(())
            .unwrap();
        let base = cache_policy::base_key(&request, &f.handle.context, false);
        assert!(f.handle.context.cache.recovery_blocks_family(&base));
        let journal: serde_json::Value = serde_json::from_slice(
            &std::fs::read(f.directory.path().join("cache").join(".cache-recovery-v1")).unwrap(),
        )
        .unwrap();
        assert_eq!(journal["records"].as_array().unwrap().len(), 1);
        assert_eq!(journal["records"][0]["base"], base);
        // Online, the retained recovery record still forbids any cache reuse, but
        // the request is served uncached from the origin instead of a local 503.
        assert_eq!(body(&czech), b"unavailable");
        assert_eq!(f.hits.load(Ordering::SeqCst), 5);
        assert!(f.handle.context.cache.recovery_blocks_family(&base));
        for key in &keys {
            assert!(f.handle.context.cache.snapshot(key).await.is_none());
        }
        let mut offline = f.handle.context.clone();
        offline.settings.cache_mode = CacheMode::Offline;
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(ACCEPT_LANGUAGE, "cs")
            .body(empty_body())
            .unwrap();
        assert!(matches!(
            forward_web_request(
                request,
                &offline,
                WebOrigin::Plain {
                    host: "cache.example".into(),
                    port: 80,
                }
            )
            .await,
            Err(ProxyError::Offline)
        ));
        assert_eq!(f.hits.load(Ordering::SeqCst), 5);
    }
    f.stop().await;
}

fn changed_vary_language_response(request: &str, number: usize, private_retry: bool) -> Vec<u8> {
    let request = request.to_ascii_lowercase();
    match number {
        0 | 1 => {
            let (language, payload) = if number == 0 {
                ("en", "one")
            } else {
                ("cs", "dva")
            };
            assert!(request.contains(&format!("accept-language: {language}\r\n")));
            assert!(!request.contains("if-none-match:"));
            format!("HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nVary: Accept-Language\r\nETag: \"same\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{payload}").into_bytes()
        }
        2 => {
            assert!(request.contains("accept-language: en\r\n"));
            assert!(request.contains("if-none-match: \"same\"\r\n"));
            b"HTTP/1.1 304 Not Modified\r\nCache-Control: public, max-age=120\r\nVary: Accept\r\nETag: \"same\"\r\nConnection: close\r\n\r\n".to_vec()
        }
        3 => {
            assert!(request.contains("accept-language: en\r\n"));
            assert!(!request.contains("if-none-match:"));
            if private_retry {
                b"HTTP/1.1 200 OK\r\nCache-Control: private, max-age=120\r\nVary: Accept\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret".to_vec()
            } else {
                // EOF before response headers deterministically fails the retry.
                Vec::new()
            }
        }
        4 => {
            assert!(request.contains("accept-language: cs\r\n"));
            assert!(!request.contains("if-none-match:"));
            b"HTTP/1.1 503 Service Unavailable\r\nCache-Control: no-store\r\nContent-Length: 11\r\nConnection: close\r\n\r\nunavailable".to_vec()
        }
        _ => panic!("unexpected additional origin request"),
    }
}

#[tokio::test]
async fn changed_vary_on_304_failed_retry_retires_whole_family_including_after_restart() {
    rejected_304_retires_other_language_variants(
        |request, number| changed_vary_language_response(request, number, false),
        false,
    )
    .await;
}

#[tokio::test]
async fn changed_vary_on_304_private_retry_retires_whole_family_including_after_restart() {
    rejected_304_retires_other_language_variants(
        |request, number| changed_vary_language_response(request, number, true),
        true,
    )
    .await;
}

#[tokio::test]
async fn variant_index_pressure_keeps_new_public_responses_cacheable_with_one_disk_scan() {
    let f = Fixture::new(|_, _| {
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nVary: Accept-Language\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc".to_vec()
    }, false).await;
    assert_eq!(
        body(&f.request("GET", "Accept-Language: en\r\n").await),
        b"abc"
    );
    let mut context = f.handle.context.clone();
    context.cache = CacheStore::new(f.directory.path().join("cache"));
    for number in 0..8193 {
        let request = Request::builder()
            .uri(format!("http://cache.example/missing/{number}"))
            .body(())
            .unwrap();
        let base = cache_policy::base_key(&request, &context, false);
        context.cache.hydrate_variants(&base).await;
        context.cache.variants.generation(&base);
    }
    assert_eq!(context.cache.variants.scan_counts(), (1, 1));
    for attempt in 0..2 {
        let request = Request::builder()
            .uri("http://cache.example/new-public")
            .header(ACCEPT_LANGUAGE, "en")
            .body(empty_body())
            .unwrap();
        let response = forward_web_request(
            request,
            &context,
            WebOrigin::Plain {
                host: "cache.example".into(),
                port: 80,
            },
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cache_status = response
            .headers()
            .get("cache-status")
            .unwrap()
            .to_str()
            .unwrap();
        if attempt == 0 {
            assert_eq!(cache_status, "HomeProxy; fwd=miss; stored");
        } else {
            assert!(cache_status.starts_with("HomeProxy; hit; ttl="));
        }
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"abc")
        );
    }
    assert_eq!(context.cache.variants.scan_counts(), (1, 1));
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    // The original persisted selector remains reachable after empty-family pressure.
    context.settings.cache_mode = CacheMode::Offline;
    let request = Request::builder()
        .uri("http://cache.example/file")
        .header(ACCEPT_LANGUAGE, "en")
        .body(empty_body())
        .unwrap();
    let response = forward_web_request(
        request,
        &context,
        WebOrigin::Plain {
            host: "cache.example".into(),
            port: 80,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"abc")
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}

async fn changed_vary_200_retires_other_languages(
    method: &str,
    response: fn(&str, usize) -> Vec<u8>,
) {
    let f = Fixture::new(response, false).await;
    let mut keys = Vec::new();
    for (language, expected) in [("en", b"one"), ("cs", b"dva")] {
        assert_eq!(
            body(
                &f.request("GET", &format!("Accept-Language: {language}\r\n"))
                    .await
            ),
            expected
        );
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(ACCEPT_LANGUAGE, language)
            .body(())
            .unwrap();
        keys.push(
            cache_policy::cached_key(&request, &f.handle.context, false)
                .await
                .unwrap(),
        );
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    let path = f
        .directory
        .path()
        .join("cache")
        .join(format!("{}.json", keys[0]));
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    metadata["expires_unix_seconds"] = 0.into();
    std::fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    assert!(!f
        .handle
        .context
        .cache
        .snapshot(&keys[1])
        .await
        .unwrap()
        .remaining_ttl
        .is_zero());
    let replacement = f.request(method, "Accept-Language: en\r\n").await;
    assert!(header(&replacement).starts_with("http/1.1 200"));
    assert_eq!(
        body(&replacement),
        if method == "HEAD" {
            b"".as_slice()
        } else {
            b"secret".as_slice()
        }
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 3);
    for key in &keys {
        assert!(f.handle.context.cache.snapshot(key).await.is_none());
    }
    for restarted in [false, true] {
        let mut context = f.handle.context.clone();
        context.settings.cache_mode = CacheMode::Offline;
        if restarted {
            context.cache = CacheStore::new(f.directory.path().join("cache"));
        }
        for language in ["en", "cs"] {
            let request = Request::builder()
                .uri("http://cache.example/file")
                .header(ACCEPT_LANGUAGE, language)
                .body(empty_body())
                .unwrap();
            assert!(
                matches!(
                    forward_web_request(
                        request,
                        &context,
                        WebOrigin::Plain {
                            host: "cache.example".into(),
                            port: 80,
                        }
                    )
                    .await,
                    Err(ProxyError::Offline)
                ),
                "old {language} survived {method} changed Vary (restart={restarted})"
            );
        }
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 3);
    let response = f.request("GET", "Accept-Language: cs\r\n").await;
    assert!(header(&response).starts_with("http/1.1 503"));
    assert_eq!(body(&response), b"unavailable");
    assert_eq!(f.hits.load(Ordering::SeqCst), 4);
    f.stop().await;
}

fn changed_vary_200_origin(request: &str, number: usize, head: bool) -> Vec<u8> {
    let request = request.to_ascii_lowercase();
    match number {
        0 | 1 => {
            let (language, payload) = if number == 0 {
                ("en", "one")
            } else {
                ("cs", "dva")
            };
            assert!(request.starts_with("get "));
            assert!(request.contains(&format!("accept-language: {language}\r\n")));
            format!("HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nVary: Accept-Language\r\nETag: \"same\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{payload}").into_bytes()
        }
        2 => {
            assert!(request.contains("if-none-match: \"same\"\r\n"));
            assert!(request.contains("accept-language: en\r\n"));
            if head {
                assert!(request.starts_with("head "));
                b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nVary: Accept\r\nETag: \"same\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\n".to_vec()
            } else {
                assert!(request.starts_with("get "));
                b"HTTP/1.1 200 OK\r\nCache-Control: private, max-age=120\r\nVary: Accept\r\nETag: \"new\"\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret".to_vec()
            }
        }
        3 => {
            assert!(request.starts_with("get "));
            assert!(request.contains("accept-language: cs\r\n"));
            assert!(!request.contains("if-none-match:"));
            b"HTTP/1.1 503 Service Unavailable\r\nCache-Control: no-store\r\nContent-Length: 11\r\nConnection: close\r\n\r\nunavailable".to_vec()
        }
        _ => panic!("unexpected additional origin request"),
    }
}

#[tokio::test]
async fn head_200_changed_vary_retires_whole_family_including_after_restart() {
    changed_vary_200_retires_other_languages("HEAD", |request, number| {
        changed_vary_200_origin(request, number, true)
    })
    .await;
}

#[tokio::test]
async fn private_get_200_changed_vary_retires_whole_family_including_after_restart() {
    changed_vary_200_retires_other_languages("GET", |request, number| {
        changed_vary_200_origin(request, number, false)
    })
    .await;
}

#[tokio::test]
async fn recovery_checkpoint_failure_refuses_revalidation_before_origin_egress() {
    let f = Fixture::new(|_, number| {
        assert_eq!(number, 0, "failed recovery checkpoint reached origin");
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nVary: Accept-Language\r\nETag: \"same\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc".to_vec()
    }, false).await;
    assert_eq!(
        body(&f.request("GET", "Accept-Language: en\r\n").await),
        b"abc"
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
    f.expire();
    // A non-regular recovery path produces a deterministic persistence failure,
    // independent of the account's filesystem permissions.
    std::fs::create_dir(f.directory.path().join("cache").join(".cache-recovery-v1")).unwrap();
    let response = f.request("GET", "Accept-Language: en\r\n").await;
    assert!(header(&response).starts_with("http/1.1 503"));
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
    f.stop().await;
}

async fn failed_fragment_merge_retains_recovery(
    response: fn(&str, usize) -> Vec<u8>,
    expected: &[u8],
) {
    let f = Fixture::new(response, false).await;
    assert_eq!(
        body(&f.request("GET", "Range: bytes=1-3\r\n").await),
        b"bcd"
    );
    let hit = f.request("GET", "Range: bytes=1-3\r\n").await;
    assert!(header(&hit).contains("homeproxy; hit"));
    assert_eq!(body(&hit), b"bcd");
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
    let lookup = Request::builder()
        .uri("http://cache.example/file")
        .header(RANGE, "bytes=1-3")
        .body(())
        .unwrap();
    let key = cache_policy::cached_key(&lookup, &f.handle.context, false)
        .await
        .unwrap();
    f.handle
        .context
        .cache
        .set_invalidation_persist_failure(true);
    let changed = f.request("GET", "Range: bytes=3-5\r\n").await;
    assert!(header(&changed).starts_with("http/1.1 206"));
    assert!(header(&changed).contains("store=error"));
    assert_eq!(body(&changed), expected);
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    let path = f.directory.path().join("cache").join(format!("{key}.json"));
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        metadata["invalidated"], false,
        "fixture must leave old valid disk metadata after persistence failure"
    );
    let journal: serde_json::Value = serde_json::from_slice(
        &std::fs::read(f.directory.path().join("cache").join(".cache-recovery-v1")).unwrap(),
    )
    .unwrap();
    assert_eq!(journal["records"].as_array().unwrap().len(), 1);
    for restarted in [false, true] {
        let mut context = f.handle.context.clone();
        context.settings.cache_mode = CacheMode::Offline;
        if restarted {
            context.cache = CacheStore::new(f.directory.path().join("cache"));
        }
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(RANGE, "bytes=1-3")
            .body(empty_body())
            .unwrap();
        assert!(
            matches!(
                forward_web_request(
                    request,
                    &context,
                    WebOrigin::Plain {
                        host: "cache.example".into(),
                        port: 80,
                    }
                )
                .await,
                Err(ProxyError::Offline)
            ),
            "old fragments survived failed late invalidation (restart={restarted})"
        );
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}

fn conflicting_fragment_origin(request: &str, number: usize, changed_etag: bool) -> Vec<u8> {
    let request = request.to_ascii_lowercase();
    match number {
        0 => {
            assert!(request.contains("range: bytes=1-3\r\n"));
            b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, max-age=120\r\nETag: \"old\"\r\nContent-Range: bytes 1-3/6\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbcd".to_vec()
        }
        1 => {
            assert!(request.contains("range: bytes=3-5\r\n"));
            let (etag, payload) = if changed_etag {
                ("new", "def")
            } else {
                ("old", "Xef")
            };
            format!("HTTP/1.1 206 Partial Content\r\nCache-Control: public, max-age=120\r\nETag: \"{etag}\"\r\nContent-Range: bytes 3-5/6\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{payload}").into_bytes()
        }
        _ => panic!("unexpected origin request"),
    }
}

#[tokio::test]
async fn fragment_etag_change_persistence_failure_retains_checkpoint_and_blocks_restart_reuse() {
    failed_fragment_merge_retains_recovery(
        |request, number| conflicting_fragment_origin(request, number, true),
        b"def",
    )
    .await;
}

#[tokio::test]
async fn fragment_overlap_persistence_failure_retains_checkpoint_and_blocks_restart_reuse() {
    failed_fragment_merge_retains_recovery(
        |request, number| conflicting_fragment_origin(request, number, false),
        b"Xef",
    )
    .await;
}

async fn refresh_failure_retires_current_and_restarted_representation(
    method: &str,
    response: fn(&str, usize) -> Vec<u8>,
) {
    let f = Fixture::new(response, false).await;
    assert_eq!(
        body(&f.request("GET", "Accept-Language: en\r\n").await),
        b"abc"
    );
    let lookup = Request::builder()
        .uri("http://cache.example/file")
        .header(ACCEPT_LANGUAGE, "en")
        .body(())
        .unwrap();
    let key = cache_policy::cached_key(&lookup, &f.handle.context, false)
        .await
        .unwrap();
    f.handle.context.cache.set_refresh_failure(true);
    let refreshed = f
        .request(method, "Accept-Language: en\r\nCache-Control: no-cache\r\n")
        .await;
    assert!(header(&refreshed).starts_with("http/1.1 200"));
    assert_eq!(
        body(&refreshed),
        if method == "HEAD" {
            b"".as_slice()
        } else {
            b"abc".as_slice()
        }
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    assert!(f.handle.context.cache.status_snapshot(&key).await.is_none());
    let journal: serde_json::Value = serde_json::from_slice(
        &std::fs::read(f.directory.path().join("cache").join(".cache-recovery-v1")).unwrap(),
    )
    .unwrap();
    assert!(journal["records"].as_array().unwrap().is_empty());
    for restarted in [false, true] {
        let mut context = f.handle.context.clone();
        context.settings.cache_mode = CacheMode::Offline;
        if restarted {
            context.cache = CacheStore::new(f.directory.path().join("cache"));
        }
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(ACCEPT_LANGUAGE, "en")
            .body(empty_body())
            .unwrap();
        assert!(
            matches!(
                forward_web_request(
                    request,
                    &context,
                    WebOrigin::Plain {
                        host: "cache.example".into(),
                        port: 80,
                    }
                )
                .await,
                Err(ProxyError::Offline)
            ),
            "old policy survived {method} refresh failure (restart={restarted})"
        );
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}

fn restrictive_refresh_origin(request: &str, number: usize, head: bool) -> Vec<u8> {
    let request = request.to_ascii_lowercase();
    match number {
        0 => b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nVary: Accept-Language\r\nETag: \"same\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc".to_vec(),
        1 => {
            assert!(request.contains("if-none-match: \"same\"\r\n"));
            if head {
                assert!(request.starts_with("head "));
                b"HTTP/1.1 200 OK\r\nCache-Control: public, no-cache, max-age=120\r\nVary: Accept-Language\r\nETag: \"same\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\n".to_vec()
            } else {
                b"HTTP/1.1 304 Not Modified\r\nCache-Control: public, no-cache, max-age=120\r\nVary: Accept-Language\r\nETag: \"same\"\r\nConnection: close\r\n\r\n".to_vec()
            }
        }
        _ => panic!("unexpected origin request"),
    }
}

#[tokio::test]
async fn restrictive_304_refresh_failure_retires_cache_before_ephemeral_authorized_body() {
    refresh_failure_retires_current_and_restarted_representation("GET", |request, number| {
        restrictive_refresh_origin(request, number, false)
    })
    .await;
}

#[tokio::test]
async fn restrictive_head_refresh_failure_retires_cache_before_live_head_response() {
    refresh_failure_retires_current_and_restarted_representation("HEAD", |request, number| {
        restrictive_refresh_origin(request, number, true)
    })
    .await;
}

#[tokio::test]
async fn repeated_no_cache_304_with_body_reader_closes_more_than_128_checkpoints() {
    let f = Fixture::new(|request, number| {
        if number == 0 {
            b"HTTP/1.1 200 OK\r\nCache-Control: public, no-cache, max-age=120\r\nETag: \"same\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc".to_vec()
        } else {
            assert!(request.to_ascii_lowercase().contains("if-none-match: \"same\"\r\n"));
            b"HTTP/1.1 304 Not Modified\r\nCache-Control: public, no-cache, max-age=120\r\nETag: \"same\"\r\nConnection: close\r\n\r\n".to_vec()
        }
    }, false).await;
    assert_eq!(body(&f.request("GET", "").await), b"abc");
    let lookup = Request::builder()
        .uri("http://cache.example/file")
        .body(())
        .unwrap();
    let key = cache_policy::cached_key(&lookup, &f.handle.context, false)
        .await
        .unwrap();
    let reader = f
        .handle
        .context
        .cache
        .get_including_stale(&key)
        .await
        .unwrap();
    for _ in 0..130 {
        let response = f.request("GET", "").await;
        assert!(header(&response).starts_with("http/1.1 200"));
        assert_eq!(body(&response), b"abc");
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 131);
    let journal: serde_json::Value = serde_json::from_slice(
        &std::fs::read(f.directory.path().join("cache").join(".cache-recovery-v1")).unwrap(),
    )
    .unwrap();
    assert!(journal["records"].as_array().unwrap().is_empty());
    drop(reader);
    f.stop().await;
}

async fn restrictive_206_changed_vary_retires_languages(response: fn(&str, usize) -> Vec<u8>) {
    let f = Fixture::new(response, false).await;
    let mut keys = Vec::new();
    for (language, payload) in [("en", b"one"), ("cs", b"dva")] {
        assert_eq!(
            body(
                &f.request("GET", &format!("Accept-Language: {language}\r\n"))
                    .await
            ),
            payload
        );
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(ACCEPT_LANGUAGE, language)
            .body(())
            .unwrap();
        keys.push(
            cache_policy::cached_key(&request, &f.handle.context, false)
                .await
                .unwrap(),
        );
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    let partial = f
        .request(
            "GET",
            "Accept-Language: en\r\nRange: bytes=0-1\r\nCache-Control: no-cache\r\n",
        )
        .await;
    assert!(header(&partial).starts_with("http/1.1 206"));
    assert_eq!(body(&partial), b"ne");
    assert_eq!(f.hits.load(Ordering::SeqCst), 3);
    for key in &keys {
        assert!(f.handle.context.cache.status_snapshot(key).await.is_none());
    }
    for restarted in [false, true] {
        let mut context = f.handle.context.clone();
        context.settings.cache_mode = CacheMode::Offline;
        if restarted {
            context.cache = CacheStore::new(f.directory.path().join("cache"));
        }
        for language in ["en", "cs"] {
            let request = Request::builder()
                .uri("http://cache.example/file")
                .header(ACCEPT_LANGUAGE, language)
                .body(empty_body())
                .unwrap();
            assert!(
                matches!(
                    forward_web_request(
                        request,
                        &context,
                        WebOrigin::Plain {
                            host: "cache.example".into(),
                            port: 80,
                        }
                    )
                    .await,
                    Err(ProxyError::Offline)
                ),
                "old {language} survived restrictive 206 changed Vary (restart={restarted})"
            );
        }
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 3);
    let response = f.request("GET", "Accept-Language: cs\r\n").await;
    assert!(header(&response).starts_with("http/1.1 503"));
    assert_eq!(body(&response), b"unavailable");
    assert_eq!(f.hits.load(Ordering::SeqCst), 4);
    f.stop().await;
}

fn restrictive_206_changed_vary_origin(request: &str, number: usize, policy: &str) -> Vec<u8> {
    if number < 2 || number == 3 {
        return changed_vary_200_origin(request, number, false);
    }
    assert_eq!(number, 2);
    let request = request.to_ascii_lowercase();
    assert!(request.starts_with("get "));
    assert!(request.contains("accept-language: en\r\n"));
    assert!(request.contains("range: bytes=0-1\r\n"));
    format!("HTTP/1.1 206 Partial Content\r\n{policy}\r\nVary: Accept\r\nETag: \"new\"\r\nContent-Range: bytes 0-1/3\r\nContent-Length: 2\r\nConnection: close\r\n\r\nne").into_bytes()
}

#[tokio::test]
async fn private_range_206_changed_vary_retires_whole_family_including_after_restart() {
    restrictive_206_changed_vary_retires_languages(|request, number| {
        restrictive_206_changed_vary_origin(request, number, "Cache-Control: private, max-age=120")
    })
    .await;
}

#[tokio::test]
async fn no_store_range_206_changed_vary_retires_whole_family_including_after_restart() {
    restrictive_206_changed_vary_retires_languages(|request, number| {
        restrictive_206_changed_vary_origin(request, number, "Cache-Control: no-store")
    })
    .await;
}

#[tokio::test]
async fn set_cookie_range_206_changed_vary_retires_whole_family_including_after_restart() {
    restrictive_206_changed_vary_retires_languages(|request, number| {
        restrictive_206_changed_vary_origin(
            request,
            number,
            "Cache-Control: public, max-age=120\r\nSet-Cookie: session=secret",
        )
    })
    .await;
}

#[tokio::test]
async fn private_same_schema_206_retires_known_fragments_without_snapshot_including_restart() {
    let f = Fixture::new(|request, number| {
        let request = request.to_ascii_lowercase();
        match number {
            0 => {
                assert!(request.contains("range: bytes=1-3\r\n"));
                b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, max-age=120\r\nETag: \"same\"\r\nContent-Range: bytes 1-3/6\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbcd".to_vec()
            }
            1 => {
                assert!(request.contains("range: bytes=3-5\r\n"));
                b"HTTP/1.1 206 Partial Content\r\nCache-Control: private, max-age=120\r\nETag: \"same\"\r\nContent-Range: bytes 3-5/6\r\nContent-Length: 3\r\nConnection: close\r\n\r\ndef".to_vec()
            }
            _ => panic!("unexpected origin request"),
        }
    }, false).await;
    assert_eq!(
        body(&f.request("GET", "Range: bytes=1-3\r\n").await),
        b"bcd"
    );
    let hit = f.request("GET", "Range: bytes=1-3\r\n").await;
    assert!(header(&hit).contains("homeproxy; hit"));
    assert_eq!(body(&hit), b"bcd");
    let lookup = Request::builder()
        .uri("http://cache.example/file")
        .header(RANGE, "bytes=1-3")
        .body(())
        .unwrap();
    let key = cache_policy::cached_key(&lookup, &f.handle.context, false)
        .await
        .unwrap();
    let private = f.request("GET", "Range: bytes=3-5\r\n").await;
    assert!(header(&private).starts_with("http/1.1 206"));
    assert_eq!(body(&private), b"def");
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    assert!(f.handle.context.cache.status_snapshot(&key).await.is_none());
    for restarted in [false, true] {
        let mut context = f.handle.context.clone();
        context.settings.cache_mode = CacheMode::Offline;
        if restarted {
            context.cache = CacheStore::new(f.directory.path().join("cache"));
        }
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(RANGE, "bytes=1-3")
            .body(empty_body())
            .unwrap();
        assert!(
            matches!(
                forward_web_request(
                    request,
                    &context,
                    WebOrigin::Plain {
                        host: "cache.example".into(),
                        port: 80,
                    }
                )
                .await,
                Err(ProxyError::Offline)
            ),
            "private old fragments survived (restart={restarted})"
        );
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}

async fn full_no_cache_response_retires_fragments_before_handoff(method: &str, failed: bool) {
    let f = Fixture::new(|request, number| {
        let request = request.to_ascii_lowercase();
        match number {
            0 => {
                assert!(request.starts_with("get "));
                assert!(request.contains("range: bytes=0-1\r\n"));
                b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, max-age=120\r\nETag: \"same\"\r\nContent-Range: bytes 0-1/8\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab".to_vec()
            }
            1 => {
                assert!(!request.contains("range:"));
                assert!(!request.contains("if-none-match:"));
                let mut response = b"HTTP/1.1 200 OK\r\nCache-Control: public, no-cache, max-age=120\r\nETag: \"same\"\r\nContent-Length: 8\r\nConnection: close\r\n\r\n".to_vec();
                if request.starts_with("get ") {
                    response.extend_from_slice(b"abcdefgh");
                } else {
                    assert!(request.starts_with("head "));
                }
                response
            }
            _ => panic!("unexpected origin request"),
        }
    }, false).await;
    assert_eq!(body(&f.request("GET", "Range: bytes=0-1\r\n").await), b"ab");
    let hit = f.request("GET", "Range: bytes=0-1\r\n").await;
    assert!(header(&hit).contains("homeproxy; hit"));
    assert_eq!(body(&hit), b"ab");
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
    let lookup = Request::builder()
        .uri("http://cache.example/file")
        .header(RANGE, "bytes=0-1")
        .body(())
        .unwrap();
    let key = cache_policy::cached_key(&lookup, &f.handle.context, false)
        .await
        .unwrap();
    assert!(
        f.handle.context.cache.snapshot(&key).await.is_none(),
        "partial representation must not yield a full snapshot"
    );
    f.handle
        .context
        .cache
        .set_invalidation_persist_failure(failed);
    let mut context = f.handle.context.clone();
    context.settings.response_buffer_limit_mib = 0;
    let request = Request::builder()
        .method(method)
        .uri("http://cache.example/file")
        .body(empty_body())
        .unwrap();
    let response = forward_web_request(
        request,
        &context,
        WebOrigin::Plain {
            host: "cache.example".into(),
            port: 80,
        },
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CACHE_CONTROL).unwrap(),
        "public, no-cache, max-age=120"
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    let path = f.directory.path().join("cache").join(format!("{key}.json"));
    let journal: serde_json::Value = serde_json::from_slice(
        &std::fs::read(f.directory.path().join("cache").join(".cache-recovery-v1")).unwrap(),
    )
    .unwrap();
    if failed {
        let old: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            old["invalidated"], false,
            "failed retirement must leave actual old disk metadata for restart regression"
        );
        assert_eq!(journal["records"].as_array().unwrap().len(), 1);
    } else {
        // Retirement persisted before cleanup. Neither old file remains when
        // the authorized origin response is handed to the caller unread.
        assert!(!path.exists());
        assert!(!f
            .directory
            .path()
            .join("cache")
            .join(format!("{key}.body"))
            .exists());
        assert!(journal["records"].as_array().unwrap().is_empty());
        if method == "GET" {
            assert_eq!(
                response.headers().get("cache-status").unwrap(),
                "HomeProxy; fwd=miss",
                "zero-buffer GET must take the TeeBody streaming path"
            );
        }
    }
    // Do not read any frame: cancellation cannot publish the full no-cache fill.
    drop(response);
    assert!(context.cache.status_snapshot(&key).await.is_none());
    for restarted in [false, true] {
        let mut offline = context.clone();
        offline.settings.cache_mode = CacheMode::Offline;
        if restarted {
            offline.cache = CacheStore::new(f.directory.path().join("cache"));
        }
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(RANGE, "bytes=0-1")
            .body(empty_body())
            .unwrap();
        assert!(matches!(forward_web_request(request, &offline, WebOrigin::Plain {
            host: "cache.example".into(), port: 80,
        }).await, Err(ProxyError::Offline)), "old fresh fragments survived {method} handoff/cancel (failed={failed}, restart={restarted})");
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}

#[tokio::test]
async fn canceled_full_no_cache_stream_retires_old_fragments_before_handoff_and_restart() {
    full_no_cache_response_retires_fragments_before_handoff("GET", false).await;
}

#[tokio::test]
async fn failed_retirement_before_canceled_full_no_cache_stream_retains_checkpoint_for_restart() {
    full_no_cache_response_retires_fragments_before_handoff("GET", true).await;
}

#[tokio::test]
async fn no_cache_head_retires_known_partial_representation_without_full_snapshot() {
    full_no_cache_response_retires_fragments_before_handoff("HEAD", false).await;
}

async fn unbuffered_206_retires_known_fragments(changed_etag: bool, failed: bool, consume: bool) {
    let origin = if changed_etag {
        unbuffered_changed_etag_206_origin
    } else {
        unbuffered_no_cache_206_origin
    };
    let f = Fixture::new(origin, false).await;
    assert_eq!(body(&f.request("GET", "Range: bytes=0-1\r\n").await), b"ab");
    let hit = f.request("GET", "Range: bytes=0-1\r\n").await;
    assert!(header(&hit).contains("homeproxy; hit"));
    assert_eq!(body(&hit), b"ab");
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
    let lookup = Request::builder()
        .uri("http://cache.example/file")
        .header(RANGE, "bytes=0-1")
        .body(())
        .unwrap();
    let key = cache_policy::cached_key(&lookup, &f.handle.context, false)
        .await
        .unwrap();
    f.handle
        .context
        .cache
        .set_invalidation_persist_failure(failed);
    let mut context = f.handle.context.clone();
    context.settings.response_buffer_limit_mib = 0;
    let request = Request::builder()
        .uri("http://cache.example/file")
        .header(RANGE, "bytes=4-5")
        .body(empty_body())
        .unwrap();
    let response = forward_web_request(
        request,
        &context,
        WebOrigin::Plain {
            host: "cache.example".into(),
            port: 80,
        },
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.headers().get("content-range").unwrap(),
        "bytes 4-5/8"
    );
    assert_eq!(
        response.headers().get("etag").unwrap(),
        if changed_etag { "\"new\"" } else { "\"same\"" }
    );
    assert_eq!(
        response.headers().get(CACHE_CONTROL).unwrap(),
        if changed_etag {
            "public, max-age=120"
        } else {
            "public, no-cache, max-age=120"
        }
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    // Inspect persistence before either consuming or canceling this live body.
    let root = f.directory.path().join("cache");
    let path = root.join(format!("{key}.json"));
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(".cache-recovery-v1")).unwrap()).unwrap();
    if failed {
        let metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            metadata["invalidated"], false,
            "fixture must preserve old valid metadata after forced persistence failure"
        );
        assert_eq!(journal["records"].as_array().unwrap().len(), 1);
    } else {
        assert!(
            !path.exists(),
            "old fragment metadata must be retired before body handoff"
        );
        assert!(!root.join(format!("{key}.body")).exists());
        assert!(journal["records"].as_array().unwrap().is_empty());
    }
    if consume {
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"ef")
        );
    } else {
        drop(response);
    }
    assert!(context.cache.status_snapshot(&key).await.is_none());
    for restarted in [false, true] {
        let mut offline = context.clone();
        offline.settings.cache_mode = CacheMode::Offline;
        if restarted {
            offline.cache = CacheStore::new(root.clone());
        }
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(RANGE, "bytes=0-1")
            .body(empty_body())
            .unwrap();
        assert!(matches!(forward_web_request(request, &offline, WebOrigin::Plain {
            host: "cache.example".into(), port: 80,
        }).await, Err(ProxyError::Offline)), "old fragment survived unbuffered206 (changed_etag={changed_etag}, failed={failed}, consume={consume}, restart={restarted})");
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}

fn unbuffered_206_origin(request: &str, number: usize, changed_etag: bool) -> Vec<u8> {
    let request = request.to_ascii_lowercase();
    match number {
        0 => {
            assert!(request.contains("range: bytes=0-1\r\n"));
            b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, max-age=120\r\nETag: \"same\"\r\nContent-Range: bytes 0-1/8\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab".to_vec()
        }
        1 => {
            assert!(request.contains("range: bytes=4-5\r\n"));
            let (etag, policy) = if changed_etag {
                ("new", "public, max-age=120")
            } else {
                ("same", "public, no-cache, max-age=120")
            };
            format!("HTTP/1.1 206 Partial Content\r\nCache-Control: {policy}\r\nETag: \"{etag}\"\r\nContent-Range: bytes 4-5/8\r\nContent-Length: 2\r\nConnection: close\r\n\r\nef").into_bytes()
        }
        _ => panic!("unexpected origin request"),
    }
}

fn unbuffered_no_cache_206_origin(request: &str, number: usize) -> Vec<u8> {
    unbuffered_206_origin(request, number, false)
}

fn unbuffered_changed_etag_206_origin(request: &str, number: usize) -> Vec<u8> {
    unbuffered_206_origin(request, number, true)
}

#[tokio::test]
async fn unbuffered_same_etag_no_cache_206_retires_old_fragments_before_cancel_or_complete() {
    for consume in [false, true] {
        unbuffered_206_retires_known_fragments(false, false, consume).await;
    }
}

#[tokio::test]
async fn unbuffered_changed_etag_public_206_retires_old_fragments_before_cancel_or_complete() {
    for consume in [false, true] {
        unbuffered_206_retires_known_fragments(true, false, consume).await;
    }
}

#[tokio::test]
async fn unbuffered_206_failed_retirement_retains_checkpoint_before_cancel_or_complete() {
    for changed_etag in [false, true] {
        for consume in [false, true] {
            unbuffered_206_retires_known_fragments(changed_etag, true, consume).await;
        }
    }
}

#[tokio::test]
async fn private_head_403_retires_known_partial_and_full_policy_before_handoff_and_restart() {
    for partial in [true, false] {
        let f = Fixture::new(|request, number| {
            let request = request.to_ascii_lowercase();
            match number {
                0 => {
                    assert!(request.starts_with("get "));
                    if request.contains("range: bytes=0-1\r\n") {
                        b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, max-age=120\r\nETag: \"same\"\r\nContent-Range: bytes 0-1/8\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab".to_vec()
                    } else {
                        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nETag: \"same\"\r\nContent-Length: 8\r\nConnection: close\r\n\r\nabcdefgh".to_vec()
                    }
                }
                1 => {
                    assert!(request.starts_with("head "));
                    assert!(!request.contains("range:"));
                    b"HTTP/1.1 403 Forbidden\r\nCache-Control: private, no-store\r\nContent-Length: 8\r\nConnection: close\r\n\r\n".to_vec()
                }
                _ => panic!("unexpected origin request"),
            }
        }, false).await;
        let seed = f
            .request("GET", if partial { "Range: bytes=0-1\r\n" } else { "" })
            .await;
        assert_eq!(
            body(&seed),
            if partial {
                b"ab".as_slice()
            } else {
                b"abcdefgh".as_slice()
            }
        );
        let hit = f.request("GET", "Range: bytes=0-1\r\n").await;
        assert!(header(&hit).contains("homeproxy; hit"));
        assert_eq!(body(&hit), b"ab");
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(RANGE, "bytes=0-1")
            .body(())
            .unwrap();
        let key = cache_policy::cached_key(&request, &f.handle.context, false)
            .await
            .unwrap();
        assert_eq!(
            f.handle.context.cache.snapshot(&key).await.is_none(),
            partial
        );
        let response = forward_web_request(
            Request::builder()
                .method("HEAD")
                .uri("http://cache.example/file")
                .header(CACHE_CONTROL, "no-cache")
                .body(empty_body())
                .unwrap(),
            &f.handle.context,
            WebOrigin::Plain {
                host: "cache.example".into(),
                port: 80,
            },
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            f.hits.load(Ordering::SeqCst),
            2,
            "no-cache HEAD must reach the actual restrictive origin response"
        );
        let root = f.directory.path().join("cache");
        assert!(!root.join(format!("{key}.json")).exists());
        assert!(!root.join(format!("{key}.body")).exists());
        let journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(".cache-recovery-v1")).unwrap())
                .unwrap();
        assert!(journal["records"].as_array().unwrap().is_empty());
        assert!(response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());
        for restarted in [false, true] {
            let mut context = f.handle.context.clone();
            context.settings.cache_mode = CacheMode::Offline;
            if restarted {
                context.cache = CacheStore::new(root.clone());
            }
            let request = Request::builder()
                .uri("http://cache.example/file")
                .header(RANGE, "bytes=0-1")
                .body(empty_body())
                .unwrap();
            assert!(matches!(forward_web_request(request, &context, WebOrigin::Plain {
                host: "cache.example".into(), port: 80,
            }).await, Err(ProxyError::Offline)), "old public policy survived private HEAD403 (partial={partial}, restart={restarted})");
        }
        assert_eq!(f.hits.load(Ordering::SeqCst), 2);
        f.stop().await;
    }
}

#[derive(Clone, Copy, Debug)]
enum SkippedFragmentMerge {
    Trailers,
    Oversize,
    BodyReader,
}

fn buffered_no_cache_206_origin(request: &str, number: usize) -> Vec<u8> {
    unbuffered_no_cache_206_origin(request, number)
}

fn buffered_trailer_206_origin(request: &str, number: usize) -> Vec<u8> {
    if number == 0 {
        return unbuffered_no_cache_206_origin(request, number);
    }
    assert_eq!(number, 1);
    assert!(request
        .to_ascii_lowercase()
        .contains("range: bytes=4-5\r\n"));
    b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, no-cache, max-age=120\r\nETag: \"same\"\r\nContent-Range: bytes 4-5/8\r\nTransfer-Encoding: chunked\r\nTrailer: Cache-Control\r\nConnection: close\r\n\r\n2\r\nef\r\n0\r\nCache-Control: private\r\n\r\n".to_vec()
}

async fn buffered_206_requires_merge_or_retirement(
    mode: SkippedFragmentMerge,
    failed: bool,
    consume: bool,
) {
    let origin = if matches!(mode, SkippedFragmentMerge::Trailers) {
        buffered_trailer_206_origin
    } else {
        buffered_no_cache_206_origin
    };
    let f = Fixture::new(origin, false).await;
    assert_eq!(body(&f.request("GET", "Range: bytes=0-1\r\n").await), b"ab");
    let hit = f.request("GET", "Range: bytes=0-1\r\n").await;
    assert!(header(&hit).contains("homeproxy; hit"));
    assert_eq!(body(&hit), b"ab");
    let lookup = Request::builder()
        .uri("http://cache.example/file")
        .header(RANGE, "bytes=0-1")
        .body(())
        .unwrap();
    let key = cache_policy::cached_key(&lookup, &f.handle.context, false)
        .await
        .unwrap();
    let reader = if matches!(mode, SkippedFragmentMerge::BodyReader) {
        Some(
            f.handle
                .context
                .cache
                .get_fragment(&key, 0, 1, true)
                .await
                .unwrap(),
        )
    } else {
        None
    };
    f.handle
        .context
        .cache
        .set_invalidation_persist_failure(failed);
    let mut context = f.handle.context.clone();
    if matches!(mode, SkippedFragmentMerge::Oversize) {
        // Change only this request's admission limit; keep the seeded store's
        // limits intact so the fixture does not prune old data before origin.
        context.settings.cache_max_object_mib = 0;
    }
    let request = Request::builder()
        .uri("http://cache.example/file")
        .header(RANGE, "bytes=4-5")
        .body(empty_body())
        .unwrap();
    let response = forward_web_request(
        request,
        &context,
        WebOrigin::Plain {
            host: "cache.example".into(),
            port: 80,
        },
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.headers().get(CACHE_CONTROL).unwrap(),
        "public, no-cache, max-age=120"
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    let root = f.directory.path().join("cache");
    let path = root.join(format!("{key}.json"));
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(".cache-recovery-v1")).unwrap()).unwrap();
    if failed {
        let metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(metadata["invalidated"], false);
        assert_eq!(journal["records"].as_array().unwrap().len(), 1);
    } else {
        assert!(journal["records"].as_array().unwrap().is_empty());
        if reader.is_some() {
            let metadata: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(
                metadata["invalidated"], true,
                "a leased body may remain only with a durable tombstone"
            );
        } else {
            assert!(
                !path.exists(),
                "skipped merge must retire old metadata before handoff ({mode:?})"
            );
            assert!(!root.join(format!("{key}.body")).exists());
        }
    }
    if consume {
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"ef")
        );
    } else {
        drop(response);
    }
    drop(reader);
    assert!(context.cache.status_snapshot(&key).await.is_none());
    for restarted in [false, true] {
        let mut offline = context.clone();
        offline.settings.cache_mode = CacheMode::Offline;
        if restarted {
            offline.cache = CacheStore::new(root.clone());
        }
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(RANGE, "bytes=0-1")
            .body(empty_body())
            .unwrap();
        assert!(matches!(forward_web_request(request, &offline, WebOrigin::Plain {
            host: "cache.example".into(), port: 80,
        }).await, Err(ProxyError::Offline)), "old policy survived unreconciled buffered206 (mode={mode:?}, failed={failed}, consume={consume}, restart={restarted})");
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}

#[tokio::test]
async fn buffered_206_skipped_or_rejected_merge_retires_old_policy_before_handoff_and_restart() {
    for mode in [
        SkippedFragmentMerge::Trailers,
        SkippedFragmentMerge::Oversize,
        SkippedFragmentMerge::BodyReader,
    ] {
        for consume in [false, true] {
            buffered_206_requires_merge_or_retirement(mode, false, consume).await;
        }
    }
}

#[tokio::test]
async fn buffered_206_failed_retirement_blocks_old_policy_in_ram_and_after_restart() {
    for mode in [
        SkippedFragmentMerge::Trailers,
        SkippedFragmentMerge::Oversize,
        SkippedFragmentMerge::BodyReader,
    ] {
        for consume in [false, true] {
            buffered_206_requires_merge_or_retirement(mode, true, consume).await;
        }
    }
}

#[tokio::test]
async fn truncated_buffered_206_retains_checkpoint_and_blocks_old_fragments_in_ram_and_restart() {
    let f = Fixture::new(|request, number| {
        if number == 0 { return unbuffered_no_cache_206_origin(request, number); }
        assert_eq!(number, 1);
        assert!(request.to_ascii_lowercase().contains("range: bytes=4-5\r\n"));
        b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, no-cache, max-age=120\r\nETag: \"same\"\r\nContent-Range: bytes 4-5/8\r\nContent-Length: 2\r\nConnection: close\r\n\r\ne".to_vec()
    }, false).await;
    assert_eq!(body(&f.request("GET", "Range: bytes=0-1\r\n").await), b"ab");
    let lookup = Request::builder()
        .uri("http://cache.example/file")
        .header(RANGE, "bytes=0-1")
        .body(())
        .unwrap();
    let key = cache_policy::cached_key(&lookup, &f.handle.context, false)
        .await
        .unwrap();
    let request = Request::builder()
        .uri("http://cache.example/file")
        .header(RANGE, "bytes=4-5")
        .body(empty_body())
        .unwrap();
    assert!(forward_web_request(
        request,
        &f.handle.context,
        WebOrigin::Plain {
            host: "cache.example".into(),
            port: 80,
        }
    )
    .await
    .is_err());
    let root = f.directory.path().join("cache");
    let old: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(format!("{key}.json"))).unwrap()).unwrap();
    assert_eq!(
        old["invalidated"], false,
        "body collection failed before durable reconciliation"
    );
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(".cache-recovery-v1")).unwrap()).unwrap();
    assert_eq!(journal["records"].as_array().unwrap().len(), 1);
    for restarted in [false, true] {
        let mut offline = f.handle.context.clone();
        offline.settings.cache_mode = CacheMode::Offline;
        if restarted {
            offline.cache = CacheStore::new(root.clone());
        }
        let request = Request::builder()
            .uri("http://cache.example/file")
            .header(RANGE, "bytes=0-1")
            .body(empty_body())
            .unwrap();
        assert!(
            matches!(
                forward_web_request(
                    request,
                    &offline,
                    WebOrigin::Plain {
                        host: "cache.example".into(),
                        port: 80,
                    }
                )
                .await,
                Err(ProxyError::Offline)
            ),
            "truncated206 checkpoint failed to block old public fragments (restart={restarted})"
        );
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}

fn unsolicited_unsafe_range_304_origin(
    request: &str,
    number: usize,
    unsafe_header: &str,
) -> Vec<u8> {
    let request = request.to_ascii_lowercase();
    match number {
        0 => {
            assert!(request.starts_with("get "));
            assert!(request.contains("range: bytes=0-1\r\n"));
            b"HTTP/1.1 206 Partial Content\r\nCache-Control: public, max-age=120\r\nETag: \"same\"\r\nContent-Range: bytes 0-1/8\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab".to_vec()
        }
        1 => {
            assert!(request.starts_with("get "));
            assert!(request.contains("range: bytes=4-5\r\n"));
            assert!(!request.contains("if-none-match:"));
            let received_if_range = if request.contains("if-range:") {
                assert!(request.contains("if-range: \"same\"\r\n"));
                "yes"
            } else {
                "no"
            };
            format!("HTTP/1.1 304 Not Modified\r\n{unsafe_header}\r\nX-Fixture-Received-If-Range: {received_if_range}\r\nETag: \"same\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
        }
        _ => panic!("unexpected origin request"),
    }
}

#[tokio::test]
async fn unsolicited_unsafe_304_for_range_miss_retires_old_fragments_with_or_without_if_range() {
    let origins: [fn(&str, usize) -> Vec<u8>; 3] = [
        |request, number| {
            unsolicited_unsafe_range_304_origin(
                request,
                number,
                "Cache-Control: private, max-age=120",
            )
        },
        |request, number| {
            unsolicited_unsafe_range_304_origin(request, number, "Cache-Control: no-store")
        },
        |request, number| {
            unsolicited_unsafe_range_304_origin(
                request,
                number,
                "Cache-Control: public, max-age=120\r\nSet-Cookie: session=private",
            )
        },
    ];
    for origin in origins {
        for if_range in [false, true] {
            let f = Fixture::new(origin, false).await;
            assert_eq!(body(&f.request("GET", "Range: bytes=0-1\r\n").await), b"ab");
            let hit = f.request("GET", "Range: bytes=0-1\r\n").await;
            assert!(header(&hit).contains("homeproxy; hit"));
            assert_eq!(body(&hit), b"ab");
            assert_eq!(f.hits.load(Ordering::SeqCst), 1);
            let lookup = Request::builder()
                .uri("http://cache.example/file")
                .header(RANGE, "bytes=0-1")
                .body(())
                .unwrap();
            let key = cache_policy::cached_key(&lookup, &f.handle.context, false)
                .await
                .unwrap();
            let mut request = Request::builder()
                .uri("http://cache.example/file")
                .header(RANGE, "bytes=4-5");
            if if_range {
                request = request.header("if-range", "\"same\"");
            }
            let request = request.body(empty_body()).unwrap();
            assert!(
                cache_policy::eligible(&request, false),
                "the Range/If-Range regression must exercise an eligible shared-cache request"
            );
            let response = forward_web_request(
                request,
                &f.handle.context,
                WebOrigin::Plain {
                    host: "cache.example".into(),
                    port: 80,
                },
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
            assert_eq!(
                response
                    .headers()
                    .get("x-fixture-received-if-range")
                    .unwrap(),
                if if_range { "yes" } else { "no" },
                "the actual origin must verify If-Range independently of request eligibility"
            );
            assert_eq!(f.hits.load(Ordering::SeqCst), 2);
            let root = f.directory.path().join("cache");
            assert!(!root.join(format!("{key}.json")).exists(), "unsafe unsolicited304 must retire old fragments before handoff (IfRange={if_range})");
            assert!(!root.join(format!("{key}.body")).exists());
            let journal: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join(".cache-recovery-v1")).unwrap())
                    .unwrap();
            assert!(journal["records"].as_array().unwrap().is_empty());
            assert!(response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty());
            assert!(f.handle.context.cache.status_snapshot(&key).await.is_none());
            for restarted in [false, true] {
                let mut offline = f.handle.context.clone();
                offline.settings.cache_mode = CacheMode::Offline;
                if restarted {
                    offline.cache = CacheStore::new(root.clone());
                }
                let request = Request::builder()
                    .uri("http://cache.example/file")
                    .header(RANGE, "bytes=0-1")
                    .body(empty_body())
                    .unwrap();
                assert!(matches!(forward_web_request(request, &offline, WebOrigin::Plain {
                    host: "cache.example".into(), port: 80,
                }).await, Err(ProxyError::Offline)), "old public fragments survived unsafe304 (IfRange={if_range}, restart={restarted})");
            }
            assert_eq!(f.hits.load(Ordering::SeqCst), 2);
            f.stop().await;
        }
    }
}

#[tokio::test]
async fn cache_base_identity_coalesces_only_dns_case_and_scheme_default_ports() {
    let f = Fixture::new(
        |_, _| panic!("cache identity test must not contact origin"),
        false,
    )
    .await;
    let key = |uri: &str| {
        cache_policy::base_key(
            &Request::builder().uri(uri).body(()).unwrap(),
            &f.handle.context,
            false,
        )
    };
    for (left, right) in [
        (
            "http://cache.example/public.jpg",
            "http://CACHE.EXAMPLE:80/public.jpg",
        ),
        (
            "https://cache.example/public.jpg?b=2&a=1",
            "https://Cache.Example:443/public.jpg?b=2&a=1",
        ),
        (
            "https://[2001:DB8::1]/public.jpg",
            "https://[2001:DB8::1]:443/public.jpg",
        ),
    ] {
        assert_eq!(
            key(left),
            key(right),
            "equivalent transport identity: {left}, {right}"
        );
    }
    for (left, right) in [
        (
            "https://cache.example/public.jpg?a=1&b=2",
            "https://cache.example/public.jpg?b=2&a=1",
        ),
        (
            "https://cache.example/a%2Fb.jpg",
            "https://cache.example/a%2fb.jpg",
        ),
        (
            "https://cache.example/a%2Fb.jpg",
            "https://cache.example/a/b.jpg",
        ),
        (
            "https://cache.example/a/../b.jpg",
            "https://cache.example/b.jpg",
        ),
        ("https://cache.example/A.jpg", "https://cache.example/a.jpg"),
        (
            "https://cache.example/a//b.jpg",
            "https://cache.example/a/b.jpg",
        ),
        (
            "https://cache.example/public.jpg",
            "https://cache.example:8443/public.jpg",
        ),
        (
            "https://cache.example:08443/public.jpg",
            "https://cache.example:8443/public.jpg",
        ),
        (
            "http://cache.example/public.jpg",
            "https://cache.example/public.jpg",
        ),
        (
            "http://cache.example:443/public.jpg",
            "http://cache.example:80/public.jpg",
        ),
        (
            "https://cache.example:80/public.jpg",
            "https://cache.example:443/public.jpg",
        ),
        (
            "https://cache.example./public.jpg",
            "https://cache.example/public.jpg",
        ),
        (
            "https://[2001:DB8::1]/public.jpg",
            "https://[2001:db8::1]/public.jpg",
        ),
    ] {
        assert_ne!(
            key(left),
            key(right),
            "distinct cache identity: {left}, {right}"
        );
    }
    let request = Request::builder()
        .uri("https://cache.example/public.jpg")
        .body(())
        .unwrap();
    assert_ne!(
        cache_policy::base_key(&request, &f.handle.context, false),
        cache_policy::base_key(&request, &f.handle.context, true)
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
    f.stop().await;
}

#[tokio::test]
async fn https_prefetch_without_port_is_offline_hit_through_connect_443_and_cache_restart() {
    use rcgen::{CertificateParams, KeyPair};
    use rustls::{
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
        ClientConfig, RootCertStore, ServerConfig,
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let origin_key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec!["cache.example".into()])
        .unwrap()
        .self_signed(&origin_key)
        .unwrap();
    let certificate_der = certificate.der().clone();
    let acceptor = TlsAcceptor::from(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate_der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(origin_key.serialize_der())),
            )
            .unwrap(),
    ));
    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_address = origin_listener.local_addr().unwrap();
    let origin_connections = Arc::new(AtomicUsize::new(0));
    let counter = origin_connections.clone();
    let origin = tokio::spawn(async move {
        loop {
            let (stream, _) = origin_listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut stream = acceptor.accept(stream).await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.starts_with("get /public.jpg http/1.1\r\n"));
                assert!(request.contains("host: cache.example\r\n"));
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nCache-Control: public, max-age=120\r\nETag: \"prepared\"\r\nContent-Length: 14\r\nConnection: close\r\n\r\nprepared-https").await.unwrap();
                stream.shutdown().await.unwrap();
            });
        }
    });
    let mut upstream_roots = RootCertStore::empty();
    upstream_roots.add(certificate_der).unwrap();
    let inspection = crate::tls_inspection::TlsInspection::for_tests(
        directory.path().join("inspection-authority.json"),
        upstream_roots,
    )
    .unwrap();
    let mut client_roots = RootCertStore::empty();
    client_roots.add(inspection.root_certificate_der()).unwrap();
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(client_roots)
            .with_no_client_auth(),
    ));
    let settings = Settings {
        cache_enabled: true,
        compression_preset: crate::CompressionPreset::Off,
        adblock_mode: AdblockMode::Off,
        https_mode: HttpsMode::Inspect,
        https_client_trust_acknowledged: true,
        https_inspect_hosts: vec!["cache.example".into()],
        ..Settings::default()
    };
    let cache_path = directory.path().join("cache");
    let cache = CacheStore::new(cache_path.clone());
    let handle = spawn_proxy_with_listeners(
        settings.clone(),
        cache.clone(),
        Arc::new(Stats::default()),
        inspection.clone(),
        vec![TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap()],
        false,
    )
    .unwrap();
    let public: IpAddr = "93.184.216.34".parse().unwrap();
    handle
        .context
        .resolver
        .set_test_answer("cache.example", vec![public], Duration::ZERO);
    handle
        .context
        .resolver
        .map_test_dial(SocketAddr::new(public, 443), origin_address);
    let prepared = handle
        .prefetch_executor()
        .fetch(
            "https://cache.example/public.jpg",
            1024,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(prepared.received_bytes, 14);
    assert!(prefetch::offline_ready(
        &prepared.snapshot,
        &settings,
        "cache.example"
    ));
    cache.pin(&prepared.key, &prepared.snapshot).await.unwrap();
    assert_eq!(origin_connections.load(Ordering::SeqCst), 1);
    handle.stop().await;

    for restarted in [false, true] {
        let mut offline_settings = settings.clone();
        offline_settings.cache_mode = CacheMode::Offline;
        let offline_cache = if restarted {
            CacheStore::new(cache_path.clone())
        } else {
            cache.clone()
        };
        let stats = Arc::new(Stats::default());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let offline = spawn_proxy_with_listeners(
            offline_settings,
            offline_cache,
            stats.clone(),
            inspection.clone(),
            vec![listener],
            false,
        )
        .unwrap();
        let response = timeout(Duration::from_secs(5), async {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port)).await.unwrap();
            stream.write_all(b"CONNECT CACHE.EXAMPLE:443 HTTP/1.1\r\nHost: CACHE.EXAMPLE:443\r\n\r\n").await.unwrap();
            let mut established = Vec::new();
            while !established.ends_with(b"\r\n\r\n") {
                established.push(stream.read_u8().await.unwrap());
            }
            assert!(header(&established).starts_with("http/1.1 200"));
            let mut tls = connector.connect(ServerName::try_from("cache.example").unwrap(), stream).await.unwrap();
            tls.write_all(b"GET /public.jpg HTTP/1.1\r\nHost: cache.example\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").await.unwrap();
            let mut response = Vec::new();
            tls.read_to_end(&mut response).await.unwrap();
            response
        }).await.unwrap();
        assert!(
            header(&response).starts_with("http/1.1 200"),
            "prepared HTTPS failed via CONNECT (restart={restarted}): {}",
            header(&response)
        );
        assert!(header(&response).contains("cache-status: homeproxy; hit"));
        assert_eq!(body(&response), b"prepared-https");
        assert_eq!(
            origin_connections.load(Ordering::SeqCst),
            1,
            "offline TLS cache hit must open no origin connection"
        );
        assert_eq!(stats.snapshot().origin_bytes, 0);
        assert_eq!(stats.snapshot().cache_hits, 1);
        let pins = offline.context.cache.list_pins().await.unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].key, prepared.key);
        offline.stop().await;
    }
    origin.abort();
    let _ = origin.await;
}

#[tokio::test]
async fn cacheable_chunked_response_is_reported_as_unknown_length_bypass() {
    let f = Fixture::new(
        |_, _| {
            b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n".to_vec()
        },
        false,
    )
    .await;
    for _ in 0..2 {
        let response = f.request("GET", "").await;
        assert!(header(&response).starts_with("http/1.1 200"));
        assert!(body(&response).windows(3).any(|window| window == b"abc"));
    }
    let snapshot = f.handle.context.stats.snapshot();
    assert_eq!(snapshot.cache_misses, 0);
    assert_eq!(snapshot.cache_hits, 0);
    assert_eq!(
        snapshot.cache_bypass_reasons.get("response-unknown-length"),
        Some(&2)
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    f.stop().await;
}

// Many origins echo the CORS grant without `Vary: Origin`; isolation must not
// depend on the origin declaring it.
fn cors_echo_response(request: &str, _: usize) -> Vec<u8> {
    let origin = request.lines().find_map(|line| {
        line.to_ascii_lowercase()
            .starts_with("origin:")
            .then(|| line[7..].trim().to_owned())
    });
    let grant = origin
        .as_deref()
        .map(|origin| format!("Access-Control-Allow-Origin: {origin}\r\n"))
        .unwrap_or_default();
    format!("HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\n{grant}Content-Length: 4\r\nConnection: close\r\n\r\nfont").into_bytes()
}

#[tokio::test]
async fn cors_requests_are_cached_per_origin_and_never_cross_sites() {
    let f = Fixture::new(cors_echo_response, false).await;
    let fetch = |origin: Option<&'static str>| {
        let headers = origin
            .map(|origin| {
                format!("Origin: {origin}\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: font\r\n")
            })
            .unwrap_or_default();
        let f = &f;
        async move { f.request("GET", &headers).await }
    };
    let first_a = fetch(Some("https://a.example")).await;
    assert!(header(&first_a).contains("access-control-allow-origin: https://a.example"));
    assert!(header(&first_a).contains("homeproxy; fwd=miss; stored"));
    let second_a = fetch(Some("https://a.example")).await;
    assert!(header(&second_a).contains("homeproxy; hit"));
    assert!(header(&second_a).contains("access-control-allow-origin: https://a.example"));
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);

    // Another site never receives the first site's grant from the cache.
    let first_b = fetch(Some("https://b.example")).await;
    assert!(header(&first_b).contains("homeproxy; fwd=miss; stored"));
    assert!(header(&first_b).contains("access-control-allow-origin: https://b.example"));
    assert!(!header(&first_b).contains("https://a.example"));
    // A no-cors request keeps its own family without any grant.
    let plain = fetch(None).await;
    assert!(header(&plain).contains("homeproxy; fwd=miss; stored"));
    assert!(!header(&plain).contains("access-control-allow-origin"));
    let plain_hit = fetch(None).await;
    assert!(header(&plain_hit).contains("homeproxy; hit"));
    assert!(!header(&plain_hit).contains("access-control-allow-origin"));
    assert_eq!(f.hits.load(Ordering::SeqCst), 3);
    // A cookie still bypasses the shared cache even with Origin.
    let cookie = f
        .request("GET", "Origin: https://a.example\r\nCookie: sid=1\r\n")
        .await;
    assert!(!header(&cookie).contains("homeproxy; hit"));
    assert_eq!(f.hits.load(Ordering::SeqCst), 4);
    f.stop().await;
}

fn max_age_by_path(request: &str, _: usize) -> Vec<u8> {
    let control = if request.contains("/zero") {
        "max-age=0"
    } else if request.contains("/private") {
        "private, max-age=600"
    } else {
        "max-age=600"
    };
    // Echo whether the privacy signal reached the origin.
    let body = if request.to_ascii_lowercase().contains("sec-gpc: 1") {
        "gpc1"
    } else {
        "body"
    };
    format!("HTTP/1.1 200 OK\r\nCache-Control: {control}\r\nContent-Length: 4\r\nConnection: close\r\n\r\n{body}").into_bytes()
}

#[tokio::test]
async fn explicit_max_age_and_static_subresource_queries_use_the_shared_cache() {
    let f = Fixture::new(max_age_by_path, false).await;
    let get = |target: &'static str, headers: &'static str| {
        let port = f.port;
        async move {
            raw_http_exchange(
                port,
                &format!("GET http://cache.example{target} HTTP/1.1\r\nHost: cache.example\r\nConnection: close\r\n{headers}\r\n"),
            )
            .await
        }
    };
    const IMAGE: &str = "Accept: image/*\r\nSec-Fetch-Dest: image\r\nSec-Fetch-Mode: no-cors\r\n";
    // `max-age` without `public` is shareable for a credential-free request.
    for (target, headers) in [("/file", ""), ("/thumb.jpg?w=320&v=7", IMAGE)] {
        assert!(header(&get(target, headers).await).contains("homeproxy; fwd=miss; stored"));
        assert!(header(&get(target, headers).await).contains("homeproxy; hit"));
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 2);
    // A different query is a different representation.
    assert!(header(&get("/thumb.jpg?w=640&v=7", IMAGE).await).contains("fwd=miss; stored"));
    assert_eq!(f.hits.load(Ordering::SeqCst), 3);
    // No explicit freshness, private, a query without browser static metadata and
    // a navigation with a query stay out of the shared cache.
    for (target, headers) in [
        ("/zero", ""),
        ("/private", ""),
        ("/api?id=1", "Accept: application/json\r\n"),
        (
            "/page?id=1",
            "Accept: text/html\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n",
        ),
        (
            "/thumb.jpg?w=320&v=7",
            "Sec-Fetch-Dest: image\r\nCookie: sid=1\r\n",
        ),
        ("/app.js?v=1", "Accept: */*\r\nSec-Fetch-Dest: script\r\n"),
    ] {
        for _ in 0..2 {
            assert!(
                !header(&get(target, headers).await).contains("homeproxy; hit"),
                "{target}"
            );
        }
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 15);
    // A Sec-GPC request reaches the origin with the signal and never reuses the
    // copy fetched without it.
    let gpc = get("/file", "Sec-GPC: 1\r\n").await;
    assert!(header(&gpc).contains("homeproxy; fwd=miss; stored"));
    assert_eq!(body(&gpc), b"gpc1");
    let gpc_hit = get("/file", "Sec-GPC: 1\r\n").await;
    assert!(header(&gpc_hit).contains("homeproxy; hit"));
    assert_eq!(body(&gpc_hit), b"gpc1");
    assert_eq!(body(&get("/file", "").await), b"body");
    assert_eq!(f.hits.load(Ordering::SeqCst), 16);
    // Offline, a privacy-signalling browser still finds the copy stored without it.
    let mut offline = f.handle.context.clone();
    offline.settings.cache_mode = CacheMode::Offline;
    let request = Request::builder()
        .uri("http://cache.example/thumb.jpg?w=320&v=7")
        .header(ACCEPT, "image/*")
        .header("sec-fetch-dest", "image")
        .header("sec-fetch-mode", "no-cors")
        .header("sec-gpc", "1")
        .header("dnt", "1")
        .body(empty_body())
        .unwrap();
    let response = forward_web_request(
        request,
        &offline,
        WebOrigin::Plain {
            host: "cache.example".into(),
            port: 80,
        },
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        &b"body"[..]
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 16);
    // The JSON API, the navigation and the script (all with a query) report
    // request-query.
    let reasons = f.handle.context.stats.snapshot().cache_bypass_reasons;
    assert_eq!(reasons.get("request-query"), Some(&6));
    assert_eq!(reasons.get("response-not-public"), Some(&2));
    f.stop().await;
}
