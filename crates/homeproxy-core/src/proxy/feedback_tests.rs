//! Opt-in public website probes. No user profile, credentials, system proxy or trust-store writes.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit public-network probe; run with HOMEPROXY_PROBE_LOG set"]
async fn public_feedback_matrix() {
    let log = std::env::var("HOMEPROXY_PROBE_LOG").expect("set an explicit probe log path");
    let dns_mode = match std::env::var("HOMEPROXY_PROBE_DNS").as_deref() {
        Err(_) | Ok("system") => crate::config::DnsMode::System,
        Ok("cloudflare") => crate::config::DnsMode::Cloudflare,
        _ => panic!("HOMEPROXY_PROBE_DNS must be system or cloudflare"),
    };
    let directory = tempfile::tempdir().unwrap();
    let tls = TlsInspection::load_or_create(directory.path().join("ca.json")).unwrap();
    let der = directory.path().join("ca.der");
    let pem = directory.path().join("ca.pem");
    std::fs::write(&der, tls.root_certificate_der()).unwrap();
    assert!(std::process::Command::new("openssl")
        .args(["x509", "-inform", "DER", "-in"])
        .arg(&der)
        .arg("-out")
        .arg(&pem)
        .status()
        .unwrap()
        .success());
    let mut results = Vec::new();
    let mut failures = 0;
    for cache_enabled in [false, true] {
        for inspect in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let cancellation = CancellationToken::new();
            let bypass = InspectionBypass::default();
            let hot_cache = Arc::new(AtomicBool::new(cache_enabled));
            let context = ProxyContext {
                cache_enabled: hot_cache.clone(),
                bandwidth: BandwidthLimits::default(),
                activity_id: 0,
                listener_address: None,
                connection_permit: None,
                resolver: Resolver::new(dns_mode).unwrap(),
                settings: Settings {
                    https_mode: if inspect {
                        HttpsMode::Inspect
                    } else {
                        HttpsMode::Tunnel
                    },
                    dns_mode,
                    cache_enabled,
                    ..Settings::default()
                },
                cache: CacheStore::new(
                    directory
                        .path()
                        .join(format!("cache-{cache_enabled}-{inspect}")),
                ),
                stats: Arc::new(Stats::default()),
                auth: Arc::new(DigestAuth::default()),
                transform_slots: Arc::new(Semaphore::new(1)),
                buffer_budget: Arc::new(Semaphore::new(MAX_BUFFERED_BYTES)),
                host_addresses: Arc::new(HashSet::new()),
                tls_inspection: tls.clone(),
                inspection_bypass: bypass,
                allow_private_destinations: false,
                cancellation: cancellation.clone(),
                tasks: TaskTracker::new(),
                connections: ConnectionLimiter::default(),
                udp_associations: udp::association_limiter(),
            };
            let handle_cache = context.cache.clone();
            let join = tokio::spawn(run_listeners(
                vec![BoundListener {
                    listener,
                    protocol: ListenerProtocol::HttpMultiplexed,
                }],
                context.clone(),
            ));
            let handle = ProxyHandle {
                context,
                cache: handle_cache,
                cancellation,
                join,
                cache_enabled: hot_cache,
            };
            for protocol in ["http", "socks5h"] {
                for repeat in 1..=2 {
                    for url in [
                        "http://gmail.com/",
                        "http://seznam.cz/",
                        "http://www.seznam.cz/",
                        "http://netflyx.cz/",
                        "https://gmail.com/",
                        "https://seznam.cz/",
                        "https://www.seznam.cz/",
                        "https://netflyx.cz/",
                        "https://www.youtube.com/",
                        "https://smarttubeapp.github.io/",
                    ] {
                        let pem = pem.clone();
                        let output = tokio::task::spawn_blocking(move || std::process::Command::new("curl")
                            .args(["--silent", "--show-error", "--location", "--max-redirs", "10", "--max-time", "40", "--connect-timeout", "15", "--noproxy", "", "--proxy"])
                            .arg(format!("{protocol}://127.0.0.1:{port}"))
                            .arg("--cacert").arg(pem).args(["--user-agent", "Mozilla/5.0 Firefox/142.0", "--header", "Accept: text/html,application/xhtml+xml", "--header", "Upgrade-Insecure-Requests: 1", "--dump-header", "-", "--output", "/dev/null", "--write-out", "RESULT status=%{http_code} redirects=%{num_redirects} time=%{time_total}\n", url]).output().unwrap()).await.unwrap();
                        let headers = String::from_utf8_lossy(&output.stdout);
                        let chain = headers
                            .lines()
                            .filter(|line| {
                                line.starts_with("HTTP/")
                                    || line.to_ascii_lowercase().starts_with("location:")
                                    || line.starts_with("RESULT ")
                            })
                            .map(|line| line.split('?').next().unwrap().trim())
                            .collect::<Vec<_>>()
                            .join(" | ");
                        if !output.status.success() || !chain.contains("RESULT status=200 ") {
                            failures += 1;
                        }
                        let result = format!("dns={dns_mode:?} cache={cache_enabled} inspect={inspect} protocol={protocol} repeat={repeat} url={url} exit={:?} {chain} error={}\n", output.status.code(), String::from_utf8_lossy(&output.stderr).trim());
                        eprint!("{result}");
                        results.push(result);
                        std::fs::write(&log, results.concat()).unwrap();
                    }
                }
            }
            handle.stop().await;
        }
    }
    assert_eq!(failures, 0, "public matrix failures; see {log}");
}
