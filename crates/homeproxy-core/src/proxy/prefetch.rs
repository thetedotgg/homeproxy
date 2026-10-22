//! The privileged offline preparation client. It uses the normal forwarding path,
//! never accepts credentials/headers, and never installs a trust authority.
use super::*;

#[derive(Clone)]
pub(crate) struct PrefetchExecutor {
    context: ProxyContext,
}

pub(crate) struct PreparedFile {
    pub key: String,
    pub snapshot: crate::cache::CacheSnapshot,
    pub received_bytes: u64,
}
impl std::fmt::Debug for PreparedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedFile")
            .field("key", &self.key)
            .field("received_bytes", &self.received_bytes)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PrefetchError {
    pub code: &'static str,
    pub received_bytes: u64,
    pub budget_used_bytes: u64,
}

impl PrefetchError {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            received_bytes: 0,
            budget_used_bytes: 0,
        }
    }
}

struct ActivityGuard {
    stats: Arc<Stats>,
    id: u64,
}
impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.stats.finish_activity(self.id, None);
    }
}

impl PrefetchExecutor {
    pub(super) fn new(context: ProxyContext) -> Self {
        Self { context }
    }

    pub(crate) fn check_url(&self, value: &str) -> Result<Uri, PrefetchError> {
        let uri = validate_url(value)?;
        if self.context.cancellation.is_cancelled() {
            return Err(PrefetchError::new("proxy-stopped"));
        }
        if self.context.settings.cache_mode == CacheMode::Offline {
            return Err(PrefetchError::new("offline-mode"));
        }
        if !self.context.cache_enabled.load(Ordering::Acquire) {
            return Err(PrefetchError::new("cache-disabled"));
        }
        let host = uri.host().unwrap_or_default();
        if host_is_intrinsically_private(host.trim_start_matches('[').trim_end_matches(']')) {
            return Err(PrefetchError::new("private-target"));
        }
        if uri.scheme_str() == Some("https")
            && (connect_should_bypass_inspection(
                &self.context,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                host,
                443,
            ) || !self.context.tls_inspection.is_active())
        {
            return Err(PrefetchError::new("https-not-inspected"));
        }
        let mut probe = Request::new(());
        *probe.uri_mut() = uri.clone();
        probe
            .headers_mut()
            .insert(ACCEPT, HeaderValue::from_static("*/*"));
        probe
            .headers_mut()
            .insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        if !cache_policy::eligible(
            &probe,
            cache_policy::public_endpoint(&probe, &self.context.settings),
        ) {
            return Err(PrefetchError::new("request-ineligible"));
        }
        Ok(uri)
    }

    pub(crate) async fn fetch(
        &self,
        value: &str,
        byte_budget: u64,
        cancellation: CancellationToken,
    ) -> Result<PreparedFile, PrefetchError> {
        if byte_budget == 0 {
            return Err(PrefetchError::new("byte-budget"));
        }
        let uri = self.check_url(value)?;
        let mut context = self.context.clone();
        // Streaming keeps the job's byte budget enforceable before an origin body
        // is consumed. It also avoids a separate background response buffer pool.
        context.settings.response_buffer_limit_mib = 0;
        let runtime_cancel = context.cancellation.clone();
        // A job cancellation is visible at the cache publication fence, even
        // when an already-started blocking commit outlives this future.
        context.cancellation = cancellation.child_token();
        let child_cancel = context.cancellation.clone();
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        context.connection_permit = Some(Arc::new(
            context
                .connections
                .try_acquire(peer)
                .map_err(|_| PrefetchError::new("connection-limit"))?,
        ));
        let id = context.stats.begin_activity(peer, peer);
        context.activity_id = id;
        let _activity = ActivityGuard {
            stats: context.stats.clone(),
            id,
        };
        context.stats.request(peer);
        context
            .stats
            .describe_activity(id, uri.host().unwrap_or_default(), "prefetch");
        context
            .stats
            .bind_principal(id, peer, None)
            .map_err(|_| PrefetchError::new("policy-denied"))?;
        let mut consumed = 0u64;
        let mut reserved = 0u64;
        let work = async {
            let mut request = Request::new(empty_body());
            *request.uri_mut() = uri.clone();
            request
                .headers_mut()
                .insert(ACCEPT, HeaderValue::from_static("*/*"));
            request
                .headers_mut()
                .insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
            let endpoint = cache_policy::public_endpoint(&request, &context.settings);
            if !cache_policy::eligible(&request, endpoint) {
                return Err(PrefetchError::new("request-ineligible"));
            }
            let policy = enforce_runtime_policy(
                &context,
                uri.host().unwrap_or_default(),
                context.settings.adblock_mode,
            )
            .map_err(|_| PrefetchError::new("policy-denied"))?;
            if policy.no_cache {
                return Err(PrefetchError::new("request-ineligible"));
            }
            let origin = if uri.scheme_str() == Some("https") {
                WebOrigin::Inspected(Box::new(InspectedOrigin::new(
                    uri.host().unwrap(),
                    443,
                    &context,
                )))
            } else {
                WebOrigin::Plain {
                    host: uri.host().unwrap().into(),
                    port: uri.port_u16().unwrap_or(80),
                }
            };
            let lookup = request.headers().clone();
            let response = forward_web_request(request, &context, origin)
                .await
                .map_err(|error| {
                    PrefetchError::new(match error {
                        ProxyError::Offline => "offline-mode",
                        ProxyError::Forbidden(_) | ProxyError::Blocked => "policy-denied",
                        _ => "origin-failed",
                    })
                })?;
            if response.status().is_redirection() {
                // Following a redirect would need a new admission and explicit host
                // choice. The caller can add its public destination to the list.
                return Err(PrefetchError::new("redirect-not-prepared"));
            }
            if response.status() != StatusCode::OK {
                return Err(PrefetchError::new("origin-status"));
            }
            let length = response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or(PrefetchError::new("unknown-length"))?;
            if length > byte_budget {
                return Err(PrefetchError::new("byte-budget"));
            }
            if cache_policy::ttl(response.headers(), response.status(), endpoint).is_none() {
                return Err(PrefetchError::new("response-not-cacheable"));
            }
            // Charge an incomplete attempt conservatively. Otherwise repeatedly
            // dropping a final chunk could evade the job's aggregate body budget.
            reserved = length;
            let mut body = response.into_body();
            let mut received = 0u64;
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| PrefetchError::new("body-failed"))?;
                if let Some(bytes) = frame.data_ref() {
                    received = received
                        .checked_add(bytes.len() as u64)
                        .ok_or(PrefetchError::new("byte-budget"))?;
                    consumed = received;
                    if received > byte_budget {
                        return Err(PrefetchError::new("byte-budget"));
                    }
                }
            }
            if received != length {
                return Err(PrefetchError::new("body-failed"));
            }
            let mut probe = Request::new(());
            *probe.uri_mut() = uri;
            *probe.headers_mut() = lookup;
            let key = cache_policy::cached_key(&probe, &context, endpoint)
                .await
                .ok_or(PrefetchError::new("storage-failed"))?;
            let snapshot = context
                .cache
                .snapshot(&key)
                .await
                .ok_or(PrefetchError::new("storage-failed"))?;
            Ok(PreparedFile {
                key,
                snapshot,
                received_bytes: received,
            })
        };
        let result = tokio::select! {
            biased;
            _ = runtime_cancel.cancelled() => Err(PrefetchError::new("proxy-stopped")),
            _ = cancellation.cancelled() => Err(PrefetchError::new("cancelled")),
            result = timeout(Duration::from_secs(120), work) =>
                result.unwrap_or(Err(PrefetchError::new("timeout"))),
        };
        context.cache.cancel_fill(&child_cancel);
        result.map_err(|mut error| {
            error.received_bytes = consumed;
            error.budget_used_bytes = reserved;
            error
        })
    }
}

pub(crate) fn validate_url(value: &str) -> Result<Uri, PrefetchError> {
    if value.len() > 4096 || value.contains('#') || value.trim() != value {
        return Err(PrefetchError::new("invalid-url"));
    }
    let uri: Uri = value
        .parse()
        .map_err(|_| PrefetchError::new("invalid-url"))?;
    let authority = uri.authority().ok_or(PrefetchError::new("invalid-url"))?;
    let default_port = match uri.scheme_str() {
        Some("http") => 80,
        Some("https") => 443,
        _ => return Err(PrefetchError::new("invalid-url")),
    };
    if authority.as_str().contains('@')
        || authority.host().is_empty()
        || authority.host().len() > 253
        || (default_port == 80 && !matches!(uri.port_u16().unwrap_or(80), 80 | 8080))
        || (default_port == 443 && uri.port_u16().unwrap_or(443) != 443)
    {
        return Err(PrefetchError::new("invalid-url"));
    }
    Ok(uri)
}

pub(crate) fn offline_ready(
    snapshot: &crate::cache::CacheSnapshot,
    settings: &Settings,
    host: &str,
) -> bool {
    let policy = crate::policy::decision_at(
        settings,
        None,
        host,
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
        crate::policy::QuotaUsage::default(),
    );
    settings.cache_enabled
        && snapshot.status == StatusCode::OK
        // A generic preparation request cannot promise a browser's header-selected
        // representation. Mark these stored files conservatively as not ready.
        && crate::cache::variants::schema(&snapshot.headers).is_some_and(|schema| schema.is_empty())
        && policy.allowed
        && !policy.no_cache
        && !host_is_intrinsically_private(host.trim_start_matches('[').trim_end_matches(']'))
        && cache_policy::offline_allowed(
            snapshot,
            &HeaderMap::new(),
            u64::from(settings.offline_max_stale_hours) * 3600,
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[test]
    fn offline_urls_reject_credentials_fragments_protocols_and_ports() {
        for value in [
            "https://user:password@public.example/a",
            "file:///etc/passwd",
            "https://public.example:8443/a",
            "http://public.example:443/a",
            "http://public.example/a#x",
            " https://public.example/a",
            "//public.example/a",
        ] {
            assert_eq!(validate_url(value).unwrap_err().code, "invalid-url");
        }
        for value in [
            "https://public.example/a",
            "http://public.example:8080/a",
            "https://public.example/a?public=1",
        ] {
            assert!(validate_url(value).is_ok());
        }
    }

    async fn fixture(
        headers: &'static str,
        payload: &'static [u8],
    ) -> (
        tempfile::TempDir,
        PrefetchExecutor,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings {
            cache_enabled: true,
            compression_preset: crate::CompressionPreset::Off,
            adblock_mode: AdblockMode::Off,
            ..Default::default()
        };
        let context = super::super::service_port_tests::context(directory.path(), settings).await;
        context.cache_enabled.store(true, Ordering::Release);
        context.cache.configure_limits(
            context.settings.cache_limit_bytes(),
            context.settings.cache_max_object_bytes(),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let public = SocketAddr::from(([9, 9, 9, 9], 80));
        context
            .resolver
            .set_test_answer("prepare.example", vec![public.ip()], Duration::ZERO);
        context
            .resolver
            .map_test_dial(public, listener.local_addr().unwrap());
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let origin_count = count.clone();
        let origin = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                origin_count.fetch_add(1, Ordering::SeqCst);
                stream.write_all(format!("HTTP/1.1 200 OK\r\n{headers}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",payload.len()).as_bytes()).await.unwrap();
                stream.write_all(payload).await.unwrap();
            }
        });
        (directory, PrefetchExecutor::new(context), count, origin)
    }

    #[tokio::test]
    async fn privileged_fetch_populates_same_public_cache_without_second_origin_download() {
        let (_directory, executor, count, origin) = fixture(
            "Cache-Control: public, max-age=60\r\nETag: \"prepared\"",
            b"public-file",
        )
        .await;
        let first = executor
            .fetch(
                "http://prepare.example/file",
                1024,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(first.snapshot.body_length, 11);
        let second = executor
            .fetch(
                "http://prepare.example/file",
                1024,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(first.key, second.key);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(offline_ready(
            &second.snapshot,
            &executor.context.settings,
            "prepare.example"
        ));
        origin.abort();
        executor.context.cancellation.cancel();
    }

    #[tokio::test]
    async fn byte_budget_private_response_and_mixed_dns_never_publish_prepared_content() {
        let (_dir, executor, count, origin) =
            fixture("Cache-Control: public, max-age=60", b"public-file").await;
        assert_eq!(
            executor
                .fetch("http://prepare.example/large", 3, CancellationToken::new())
                .await
                .unwrap_err()
                .code,
            "byte-budget"
        );
        assert_eq!(executor.context.cache.usage().await.entry_count, 0);
        executor.context.resolver.set_test_answer(
            "mixed.example",
            vec!["9.9.9.9".parse().unwrap(), "127.0.0.1".parse().unwrap()],
            Duration::ZERO,
        );
        assert!(executor
            .fetch("http://mixed.example/file", 1024, CancellationToken::new())
            .await
            .is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        origin.abort();
        let (_dir, executor, _count, origin) =
            fixture("Cache-Control: private, max-age=60", b"private-file").await;
        assert_eq!(
            executor
                .fetch(
                    "http://prepare.example/private",
                    1024,
                    CancellationToken::new()
                )
                .await
                .unwrap_err()
                .code,
            "response-not-cacheable"
        );
        assert_eq!(executor.context.cache.usage().await.entry_count, 0);
        origin.abort();
    }

    #[tokio::test]
    async fn offline_and_bypassed_https_queue_admission_open_no_origin_connection() {
        let (_dir, mut executor, count, origin) =
            fixture("Cache-Control: public, max-age=60", b"public-file").await;
        executor.context.settings.https_inspect_hosts =
            vec!["play.google.com".into(), "youtube.com".into()];
        executor.context.settings.https_bypass_hosts = vec!["play.google.com".into()];
        executor.context.settings.https_mode = crate::HttpsMode::Inspect;
        executor.context.settings.https_client_trust_acknowledged = true;
        for url in [
            "https://play.google.com/file",
            "https://youtube.com/file",
            "https://unselected.example/file",
        ] {
            assert_eq!(
                executor.check_url(url).unwrap_err().code,
                "https-not-inspected"
            );
        }
        for value in [
            "http://127.0.0.1/file",
            "http://[::1]/file",
            "http://[fd00::1]/file",
        ] {
            assert_eq!(
                executor.check_url(value).unwrap_err().code,
                "private-target"
            );
        }
        executor.context.settings.cache_mode = CacheMode::Offline;
        assert_eq!(
            executor
                .fetch(
                    "http://prepare.example/file",
                    1024,
                    CancellationToken::new()
                )
                .await
                .unwrap_err()
                .code,
            "offline-mode"
        );
        for host in ["play.google.com", "youtube.com"] {
            assert!(connect_should_bypass_inspection(
                &executor.context,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                host,
                443
            ));
        }
        assert_eq!(count.load(Ordering::SeqCst), 0);
        origin.abort();
    }

    #[tokio::test]
    async fn all_supported_https_prepares_unlisted_origin_and_scope_controls_readiness() {
        use rcgen::{CertificateParams, KeyPair};
        use rustls::{
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
            RootCertStore, ServerConfig,
        };
        use tokio_rustls::TlsAcceptor;

        let directory = tempfile::tempdir().unwrap();
        let settings = Settings {
            cache_enabled: true,
            compression_preset: crate::CompressionPreset::Off,
            adblock_mode: AdblockMode::Off,
            https_mode: HttpsMode::Inspect,
            https_client_trust_acknowledged: true,
            https_inspect_hosts: vec!["selected.example".into()],
            ..Settings::default()
        };
        let mut context =
            super::super::service_port_tests::context(directory.path(), settings).await;
        context.cache_enabled.store(true, Ordering::Release);
        context.cache.configure_limits(
            context.settings.cache_limit_bytes(),
            context.settings.cache_max_object_bytes(),
        );
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["prepare.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificate.der().clone()).unwrap();
        context.tls_inspection =
            TlsInspection::for_tests(directory.path().join("origin-ca.json"), roots).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap(),
        ));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let public = SocketAddr::from(([9, 9, 9, 9], 443));
        context
            .resolver
            .set_test_answer("prepare.example", vec![public.ip()], Duration::ZERO);
        context
            .resolver
            .map_test_dial(public, listener.local_addr().unwrap());
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let origin_count = count.clone();
        let origin = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                let request = super::super::tests::read_tls_headers(&mut stream).await;
                assert!(String::from_utf8_lossy(&request)
                    .to_ascii_lowercase()
                    .contains("host: prepare.example"));
                origin_count.fetch_add(1, Ordering::SeqCst);
                stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\nContent-Length: 11\r\nConnection: close\r\n\r\npublic-file").await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        let mut executor = PrefetchExecutor::new(context);
        let url = "https://prepare.example/file";
        assert_eq!(
            executor.check_url(url).unwrap_err().code,
            "https-not-inspected"
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
        executor.context.settings.https_inspection_scope =
            crate::HttpsInspectionScope::AllSupportedHosts;
        assert!(executor.check_url(url).is_ok());
        for host in [
            "youtube.com",
            "chat.signal.org",
            "geo.do.dsp.mp.microsoft.com",
        ] {
            assert_eq!(
                executor
                    .check_url(&format!("https://{host}/file"))
                    .unwrap_err()
                    .code,
                "https-not-inspected"
            );
        }
        executor.context.settings.https_bypass_hosts = vec!["prepare.example".into()];
        assert_eq!(
            executor.check_url(url).unwrap_err().code,
            "https-not-inspected"
        );
        executor.context.settings.https_bypass_hosts.clear();
        let manager = crate::offline_preparation::OfflinePreparation::new(
            directory.path().join("offline-preparation.json"),
        );
        manager
            .queue(
                crate::OfflinePreparationRequest {
                    urls: vec![url.into()],
                    budget_mib: 1,
                    pin: true,
                },
                executor.clone(),
                executor.context.cache.clone(),
            )
            .await
            .unwrap();
        let status = timeout(Duration::from_secs(3), async {
            loop {
                let status = manager
                    .status(&executor.context.cache, &executor.context.settings)
                    .await;
                if status.active_job.is_none() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(status.jobs[0].state, "completed");
        assert!(status.jobs[0].items[0].offline_ready);
        assert!(status.pins[0].offline_ready);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        executor
            .fetch(url, 1024, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        executor.context.settings.https_inspection_scope =
            crate::HttpsInspectionScope::SelectedHosts;
        let status = manager
            .status(&executor.context.cache, &executor.context.settings)
            .await;
        assert!(!status.jobs[0].items[0].offline_ready && !status.pins[0].offline_ready);
        for rule in ["prepare.example", "*.example"] {
            executor.context.settings.https_inspect_hosts = vec![rule.into()];
            assert!(
                manager
                    .status(&executor.context.cache, &executor.context.settings)
                    .await
                    .jobs[0]
                    .items[0]
                    .offline_ready
            );
        }
        executor.context.settings.https_inspection_scope =
            crate::HttpsInspectionScope::AllSupportedHosts;
        executor.context.settings.https_bypass_hosts = vec!["*.example".into()];
        assert!(
            !manager
                .status(&executor.context.cache, &executor.context.settings)
                .await
                .jobs[0]
                .items[0]
                .offline_ready
        );
        executor.context.settings.https_bypass_hosts.clear();
        executor.context.settings.https_client_trust_acknowledged = false;
        assert!(
            !manager
                .status(&executor.context.cache, &executor.context.settings)
                .await
                .jobs[0]
                .items[0]
                .offline_ready
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        origin.abort();
        executor.context.cancellation.cancel();
    }

    #[tokio::test]
    async fn manager_pins_verified_object_and_restart_has_no_network_resumption() {
        let (directory, executor, count, origin) = fixture(
            "Cache-Control: public, max-age=60\r\nETag: \"pin\"",
            b"public-file",
        )
        .await;
        let manager = crate::offline_preparation::OfflinePreparation::new(
            directory.path().join("offline-preparation.json"),
        );
        manager
            .queue(
                crate::OfflinePreparationRequest {
                    urls: vec!["http://prepare.example/file?token=never-persist".into()],
                    budget_mib: 1,
                    pin: true,
                },
                executor.clone(),
                executor.context.cache.clone(),
            )
            .await
            .unwrap_err();
        manager
            .queue(
                crate::OfflinePreparationRequest {
                    urls: vec!["http://prepare.example/file".into()],
                    budget_mib: 1,
                    pin: true,
                },
                executor.clone(),
                executor.context.cache.clone(),
            )
            .await
            .unwrap();
        let status = timeout(Duration::from_secs(3), async {
            loop {
                let status = manager
                    .status(&executor.context.cache, &executor.context.settings)
                    .await;
                if status.active_job.is_none() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(status.jobs.last().unwrap().state, "completed");
        assert_eq!(status.pins.len(), 1);
        assert!(status.jobs.last().unwrap().items[0].offline_ready);
        let restored = crate::offline_preparation::OfflinePreparation::new(
            directory.path().join("offline-preparation.json"),
        );
        assert!(restored
            .status(&executor.context.cache, &executor.context.settings)
            .await
            .active_job
            .is_none());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        origin.abort();
    }

    #[tokio::test]
    async fn oversized_hostname_is_rejected_without_poisoning_restart_manifest() {
        let (directory, executor, count, origin) =
            fixture("Cache-Control: public, max-age=60", b"public-file").await;
        let path = directory.path().join("offline-preparation.json");
        let manager = crate::offline_preparation::OfflinePreparation::new(path.clone());
        let host = format!("{}.example", vec!["a".repeat(63); 4].join("."));
        let url = format!("http://{host}/file");
        assert!(url.parse::<Uri>().is_ok());
        assert!(host.len() > 253);
        let error = manager
            .queue(
                crate::OfflinePreparationRequest {
                    urls: vec![url],
                    budget_mib: 1,
                    pin: false,
                },
                executor.clone(),
                executor.context.cache.clone(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, "invalid-url");
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert!(!path.exists());
        let restored = crate::offline_preparation::OfflinePreparation::new(path);
        let status = restored
            .status(&executor.context.cache, &executor.context.settings)
            .await;
        assert!(status.jobs.is_empty());
        assert!(status.error_code.is_none());
        restored
            .queue(
                crate::OfflinePreparationRequest {
                    urls: vec!["http://prepare.example/file".into()],
                    budget_mib: 1,
                    pin: false,
                },
                executor.clone(),
                executor.context.cache.clone(),
            )
            .await
            .unwrap();
        origin.abort();
    }

    #[tokio::test]
    async fn public_query_is_not_persisted_and_no_cache_is_never_ready_offline() {
        let (directory, mut executor, count, origin) = fixture(
            "Cache-Control: public, no-cache\r\nETag: \"query\"",
            b"public-file",
        )
        .await;
        executor
            .context
            .settings
            .public_cache_endpoints
            .push(crate::PublicCacheEndpoint {
                host: "prepare.example".into(),
                path_prefix: "/".into(),
            });
        let manager = crate::offline_preparation::OfflinePreparation::new(
            directory.path().join("offline-preparation.json"),
        );
        manager
            .queue(
                crate::OfflinePreparationRequest {
                    urls: vec![
                        "http://prepare.example/file?fixture-secret=must-not-persist".into(),
                    ],
                    budget_mib: 1,
                    pin: true,
                },
                executor.clone(),
                executor.context.cache.clone(),
            )
            .await
            .unwrap();
        let status = timeout(Duration::from_secs(3), async {
            loop {
                let status = manager
                    .status(&executor.context.cache, &executor.context.settings)
                    .await;
                if status.active_job.is_none() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(status.jobs[0].state, "completed");
        assert!(status.jobs[0].items[0].pinned);
        assert!(!status.jobs[0].items[0].offline_ready);
        let raw =
            std::fs::read_to_string(directory.path().join("offline-preparation.json")).unwrap();
        assert!(!raw.contains("fixture-secret"));
        assert!(!raw.contains("must-not-persist"));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        origin.abort();
    }

    #[tokio::test]
    async fn cancel_during_origin_body_releases_reservation_and_does_not_pin_partial_content() {
        let (directory, executor, _count, initial_origin) =
            fixture("Cache-Control: public, max-age=60", b"unused").await;
        initial_origin.abort();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        executor.context.resolver.map_test_dial(
            SocketAddr::from(([9, 9, 9, 9], 80)),
            listener.local_addr().unwrap(),
        );
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\nContent-Length: 6\r\n\r\nabc").await.unwrap();
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let manager = crate::offline_preparation::OfflinePreparation::new(
            directory.path().join("offline-preparation.json"),
        );
        let id = manager
            .queue(
                crate::OfflinePreparationRequest {
                    urls: vec!["http://prepare.example/slow".into()],
                    budget_mib: 1,
                    pin: true,
                },
                executor.clone(),
                executor.context.cache.clone(),
            )
            .await
            .unwrap();
        timeout(Duration::from_secs(3), started_rx)
            .await
            .unwrap()
            .unwrap();
        // The origin's write only proves socket delivery. Wait until the cache
        // actually owns a nonempty partial temp file before cancelling.
        timeout(Duration::from_secs(3), async {
            loop {
                if std::fs::read_dir(executor.context.cache.root()).is_ok_and(|entries| {
                    entries.filter_map(Result::ok).any(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".cache-tmp-")
                            && entry.metadata().is_ok_and(|metadata| metadata.len() > 0)
                    })
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        manager.cancel(&id).await.unwrap();
        let status = timeout(Duration::from_secs(3), async {
            loop {
                let status = manager
                    .status(&executor.context.cache, &executor.context.settings)
                    .await;
                if status.active_job.is_none() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(status.jobs[0].state, "cancelled");
        assert!(status.pins.is_empty());
        assert_eq!(executor.context.cache.usage().await.entry_count, 0);
        timeout(Duration::from_secs(3), async {
            loop {
                if !std::fs::read_dir(executor.context.cache.root())
                    .unwrap()
                    .any(|entry| {
                        entry
                            .unwrap()
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".cache-tmp-")
                    })
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        origin.abort();
    }

    #[tokio::test]
    async fn manager_cancel_fences_a_commit_already_running_on_the_blocking_pool() {
        let (_directory, executor, count, origin) =
            fixture("Cache-Control: public, max-age=60", b"complete body").await;
        let started = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        executor
            .context
            .cache
            .set_commit_gate(Some((started.clone(), resume.clone())));
        let manager = crate::offline_preparation::OfflinePreparation::new(
            _directory.path().join("offline-preparation.json"),
        );
        let id = manager
            .queue(
                crate::OfflinePreparationRequest {
                    urls: vec!["http://prepare.example/commit".into()],
                    budget_mib: 1,
                    pin: true,
                },
                executor.clone(),
                executor.context.cache.clone(),
            )
            .await
            .unwrap();
        timeout(
            Duration::from_secs(3),
            tokio::task::spawn_blocking(move || started.wait()),
        )
        .await
        .unwrap()
        .unwrap();
        // The blocking commit has started, but cancellation must linearize before
        // its publication. It must not depend on dropping the async future.
        manager.cancel(&id).await.unwrap();
        tokio::task::spawn_blocking(move || resume.wait())
            .await
            .unwrap();
        executor.context.cache.set_commit_gate(None);
        timeout(Duration::from_secs(3), async {
            loop {
                let status = manager
                    .status(&executor.context.cache, &executor.context.settings)
                    .await;
                if status.active_job.is_none() {
                    assert_eq!(status.jobs[0].state, "cancelled");
                    assert!(status.pins.is_empty());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        timeout(Duration::from_secs(3), async {
            loop {
                let has_temp = std::fs::read_dir(executor.context.cache.root())
                    .unwrap()
                    .filter_map(Result::ok)
                    .any(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".cache-tmp-")
                    });
                if !has_temp {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(executor.context.cache.usage().await.entry_count, 0);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        origin.abort();
    }

    #[tokio::test]
    async fn header_selected_representation_is_stored_but_generic_offline_readiness_is_false() {
        let (directory, executor, count, origin) = fixture(
            "Cache-Control: public, max-age=60\r\nVary: Accept-Encoding",
            b"public variant",
        )
        .await;
        let prepared = executor
            .fetch(
                "http://prepare.example/variant",
                1024,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(!offline_ready(
            &prepared.snapshot,
            &executor.context.settings,
            "prepare.example"
        ));
        assert!(executor
            .context
            .cache
            .snapshot(&prepared.key)
            .await
            .is_some());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        drop(directory);
        origin.abort();
    }

    #[tokio::test]
    async fn initially_expired_age_is_stored_for_validation_but_never_offline_ready() {
        let (_directory, executor, count, origin) = fixture(
            "Cache-Control: public, max-age=60\r\nAge: 100000\r\nETag: \"aged\"",
            b"aged body",
        )
        .await;
        let prepared = executor
            .fetch(
                "http://prepare.example/aged",
                1024,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(prepared.snapshot.online_validation_required);
        assert!(!offline_ready(
            &prepared.snapshot,
            &executor.context.settings,
            "prepare.example"
        ));
        assert!(!cache_policy::offline_allowed(
            &prepared.snapshot,
            &HeaderMap::new(),
            72 * 3600
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        origin.abort();
    }
}
