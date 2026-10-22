use super::*;
use md5::{Digest, Md5};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn response(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
            .await
            .unwrap()
            .expect("complete HTTP response headers");
        header.push(byte[0]);
    }
    let header = String::from_utf8(header).unwrap();
    let length = header
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .expect("explicit response length");
    let mut body = vec![0; length];
    timeout(Duration::from_secs(2), stream.read_exact(&mut body))
        .await
        .unwrap()
        .expect("complete HTTP response body");
    (header, body)
}

#[tokio::test]
async fn fresh_digest_profile_policy_denial_is_complete_http_and_never_contacts_origin() {
    for method in ["GET", "CONNECT"] {
        for scenario in [
            "schedule",
            "daily-quota",
            "monthly-quota",
            "history-unavailable",
            "wrong-password",
        ] {
            let directory = tempfile::tempdir().unwrap();
            super::offline_tests::secure_directory(directory.path());
            let peer: SocketAddr = "192.168.68.81:12345".parse().unwrap();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let endpoint = listener.local_addr().unwrap();
            let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let authority = origin.local_addr().unwrap().to_string();
            let uri = if method == "CONNECT" {
                authority.clone()
            } else {
                format!("http://{authority}/fixture")
            };
            let profile = serde_json::from_value(serde_json::json!({
                "id":"tv", "name":"TV", "username":"television", "password":"fixture-only-password",
                "dailyQuotaMib": if scenario == "daily-quota" || scenario == "history-unavailable" { 1 } else { 0 },
                "monthlyQuotaMib": if scenario == "monthly-quota" { 1 } else { 0 },
                "schedules": if scenario == "schedule" || scenario == "wrong-password" {
                    vec![serde_json::json!({"days":[1,2,3,4,5,6,7],"startMinute":0,"endMinute":1439,"action":"deny"}),
                         serde_json::json!({"days":[1,2,3,4,5,6,7],"startMinute":1439,"endMinute":0,"action":"deny"})]
                } else { vec![] }
            })).unwrap();
            let settings = Settings {
                https_mode: HttpsMode::Tunnel,
                device_profiles: vec![profile],
                schedule_utc_offset_minutes: 330,
                ..Settings::default()
            };
            let history_path = directory.path().join("usage.json");
            if scenario.ends_with("quota") {
                let history = crate::usage_history::UsageHistory::open(
                    &history_path,
                    settings.history_retention_days,
                );
                let now = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                history
                    .record(
                        "profile:tv",
                        now + 330 * 60,
                        crate::usage_history::UsageCounters {
                            download_bytes: 1024 * 1024,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                history.checkpoint().unwrap();
            } else if scenario == "history-unavailable" {
                std::fs::write(&history_path, b"corrupted history").unwrap();
            }
            let stats = Arc::new(Stats::default());
            stats.configure_history(history_path, &settings).unwrap();
            let id = stats.begin_activity(peer.ip(), endpoint.ip());
            let connections = ConnectionLimiter::default();
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
            let server_stats = stats.clone();
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
                let result = server_http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
                server_stats.finish_activity(id, None);
                result
            });
            let mut client = TcpStream::connect(endpoint).await.unwrap();
            client
                .write_all(
                    format!("{method} {uri} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let (challenge, _) = response(&mut client).await;
            assert!(challenge.starts_with("HTTP/1.1 407"), "{challenge}");
            let nonce = challenge
                .split("nonce=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            let digest = |value: &str| hex::encode(Md5::digest(value.as_bytes()));
            let password = if scenario == "wrong-password" {
                "incorrect"
            } else {
                "fixture-only-password"
            };
            let ha1 = digest(&format!("television:HomeProxy:{password}"));
            let ha2 = digest(&format!("{method}:{uri}"));
            let answer = digest(&format!("{ha1}:{nonce}:00000001:fixture:auth:{ha2}"));
            let authorization = format!("Digest username=\"television\", realm=\"HomeProxy\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{answer}\", algorithm=MD5, qop=auth, nc=00000001, cnonce=\"fixture\"");
            client.write_all(format!("{method} {uri} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {authorization}\r\n\r\n").as_bytes()).await.unwrap();
            let (header, body) = response(&mut client).await;
            if scenario == "wrong-password" {
                assert!(header.starts_with("HTTP/1.1 407"), "{header}");
                drop(client);
            } else {
                assert!(
                    header.starts_with("HTTP/1.1 403"),
                    "{method}/{scenario}: {header}"
                );
                assert!(header
                    .to_ascii_lowercase()
                    .contains("connection: close\r\n"));
                assert_eq!(
                    String::from_utf8(body).unwrap(),
                    "Přístup zakazuje profil, doménové pravidlo, čas nebo kvóta."
                );
                let mut byte = [0];
                assert_eq!(
                    timeout(Duration::from_secs(2), client.read(&mut byte))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
                let reason = match scenario {
                    "schedule" => "Schedule",
                    "daily-quota" => "DailyQuota",
                    "monthly-quota" => "MonthlyQuota",
                    _ => "HistoryUnavailable",
                };
                assert_eq!(
                    stats.snapshot().activity[0].error.as_deref(),
                    Some(format!("policy-{reason}").as_str())
                );
                // Denied credentials are verified, but never become a live profile identity.
                if let Some(report) = stats.history_report().filter(|report| report.healthy) {
                    assert!(!report
                        .rows
                        .iter()
                        .any(|row| row.identity == "profile:tv" && row.counters.requests > 0));
                }
            }
            assert!(
                timeout(Duration::from_millis(20), origin.accept())
                    .await
                    .is_err(),
                "denial contacted origin"
            );
            timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }
}
