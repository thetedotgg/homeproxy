//! Regression coverage for independent cache and image-compression controls.
use super::{tests::*, *};
use crate::config::CompressionPreset;
use std::sync::atomic::AtomicUsize;

fn response_body(response: &[u8]) -> &[u8] {
    let offset = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    &response[offset..]
}

#[tokio::test]
async fn compression_without_cache_preserves_privacy_and_disabled_controls() {
    let source = Arc::new(transformable_https_jpeg());
    for (response_policy, request_headers, preset, buffer, transformed) in [
        (
            "public, max-age=60",
            "",
            CompressionPreset::Balanced,
            8,
            true,
        ),
        (
            "public, max-age=60, no-transform",
            "",
            CompressionPreset::Balanced,
            8,
            false,
        ),
        (
            "private, max-age=60",
            "",
            CompressionPreset::Balanced,
            8,
            false,
        ),
        ("no-store", "", CompressionPreset::Balanced, 8, false),
        (
            "public, max-age=60\r\nSet-Cookie: fixture=private",
            "",
            CompressionPreset::Balanced,
            8,
            false,
        ),
        (
            "public, max-age=60",
            "Cookie: fixture=private\r\n",
            CompressionPreset::Balanced,
            8,
            false,
        ),
        (
            "public, max-age=60",
            "Authorization: Bearer fixture\r\n",
            CompressionPreset::Balanced,
            8,
            false,
        ),
        ("public, max-age=60", "", CompressionPreset::Off, 8, false),
        (
            "public, max-age=60",
            "",
            CompressionPreset::Balanced,
            0,
            false,
        ),
    ] {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let origin_source = source.clone();
        let upstream = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = origin.accept().await.unwrap();
                read_tls_headers(&mut stream).await;
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nCache-Control: {response_policy}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", origin_source.len()).as_bytes()).await.unwrap();
                stream.write_all(&origin_source).await.unwrap();
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheStore::new(directory.path().join("cache"));
        let stats = Arc::new(Stats::default());
        let handle = spawn_proxy_with_listeners(
            Settings {
                cache_enabled: false,
                compression_preset: preset,
                response_buffer_limit_mib: buffer,
                ..Settings::default()
            },
            cache.clone(),
            stats.clone(),
            test_tls_inspection(directory.path()),
            vec![listener],
            true,
        )
        .unwrap();
        let request = format!("GET http://127.0.0.1:{origin_port}/image.jpg HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n{request_headers}Connection: close\r\n\r\n");
        for count in 1..=2 {
            let response = raw_http_exchange(port, &request).await;
            let body = response_body(&response);
            assert_eq!(
                body.len() < source.len(),
                transformed,
                "{response_policy}, {request_headers}, {preset:?}, buffer={buffer}"
            );
            if transformed {
                assert_eq!(image::load_from_memory(body).unwrap().width(), 800);
            } else {
                assert!(
                    body == source.as_slice(),
                    "Expected byte-exact original image"
                );
            }
            let snapshot = stats.snapshot();
            assert_eq!(
                snapshot.compressed_images,
                if transformed { count } else { 0 }
            );
            assert_eq!(
                snapshot.compression_bytes_saved,
                count * (source.len() - body.len()) as u64
            );
            assert_eq!(snapshot.cache_hits, 0);
            assert_eq!(snapshot.cache_bytes_saved, 0);
            assert_eq!(snapshot.origin_bytes, count * source.len() as u64);
            assert_eq!(snapshot.delivered_bytes, count * body.len() as u64);
        }
        assert_eq!(cache.usage().await.entry_count, 0);
        handle.stop().await;
        upstream.await.unwrap();
    }
}

#[tokio::test]
async fn request_no_transform_bypasses_a_previously_transformed_cache_hit() {
    let source = Arc::new(transformable_https_jpeg());
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let origin_source = source.clone();
    let hits = Arc::new(AtomicUsize::new(0));
    let origin_hits = hits.clone();
    let upstream = tokio::spawn(async move {
        loop {
            let (mut stream, _) = origin.accept().await.unwrap();
            let request = read_tls_headers(&mut stream).await;
            let index = origin_hits.fetch_add(1, Ordering::SeqCst);
            if index == 1 {
                assert!(String::from_utf8_lossy(&request)
                    .to_ascii_lowercase()
                    .contains("cache-control: no-transform"));
            }
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nCache-Control: public, max-age=60\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", origin_source.len()).as_bytes()).await.unwrap();
            stream.write_all(&origin_source).await.unwrap();
        }
    });
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let directory = tempfile::tempdir().unwrap();
    let stats = Arc::new(Stats::default());
    let handle = spawn_proxy_with_listeners(
        Settings {
            cache_enabled: true,
            ..Settings::default()
        },
        CacheStore::new(directory.path().join("cache")),
        stats.clone(),
        test_tls_inspection(directory.path()),
        vec![listener],
        true,
    )
    .unwrap();
    let request = |headers: &str| {
        format!("GET http://127.0.0.1:{origin_port}/image.jpg HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n{headers}Connection: close\r\n\r\n")
    };
    let first = raw_http_exchange(port, &request("")).await;
    assert!(response_body(&first).len() < source.len());
    let before = stats.snapshot();
    let original = raw_http_exchange(port, &request("Cache-Control: no-transform\r\n")).await;
    assert!(
        response_body(&original) == source.as_slice(),
        "Client no-transform must return byte-exact original"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let after = stats.snapshot();
    assert_eq!(
        after.compression_bytes_saved,
        before.compression_bytes_saved
    );
    assert_eq!(after.cache_bytes_saved, before.cache_bytes_saved);
    let hit = raw_http_exchange(port, &request("")).await;
    assert!(response_body(&hit) == response_body(&first));
    assert!(String::from_utf8_lossy(&hit).contains("cache-status: HomeProxy; hit"));
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    handle.stop().await;
    upstream.abort();
    let _ = upstream.await;
}

#[tokio::test]
async fn https_compression_without_cache_requires_explicit_inspection() {
    use rcgen::{CertificateParams, KeyPair};
    use rustls::{
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        ClientConfig, RootCertStore, ServerConfig,
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    for (mode, scope, selected) in [
        (
            HttpsMode::Tunnel,
            crate::HttpsInspectionScope::SelectedHosts,
            true,
        ),
        (
            HttpsMode::Inspect,
            crate::HttpsInspectionScope::SelectedHosts,
            true,
        ),
        (
            HttpsMode::Inspect,
            crate::HttpsInspectionScope::AllSupportedHosts,
            false,
        ),
        (
            HttpsMode::Inspect,
            crate::HttpsInspectionScope::SelectedHosts,
            false,
        ),
    ] {
        let inspected = mode == HttpsMode::Inspect
            && (selected || scope == crate::HttpsInspectionScope::AllSupportedHosts);
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = certificate.der().clone();
        let acceptor = TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .unwrap(),
        ));
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let source = Arc::new(transformable_https_jpeg());
        let origin_source = source.clone();
        let upstream = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = origin.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                read_tls_headers(&mut stream).await;
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nCache-Control: public, max-age=60\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", origin_source.len()).as_bytes()).await.unwrap();
                stream.write_all(&origin_source).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let mut origin_roots = RootCertStore::empty();
        origin_roots.add(der.clone()).unwrap();
        let inspection = TlsInspection::for_tests(
            directory.path().join("inspection-authority.json"),
            origin_roots,
        )
        .unwrap();
        let mut client_roots = RootCertStore::empty();
        client_roots.add(der).unwrap();
        client_roots.add(inspection.root_certificate_der()).unwrap();
        let client = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(client_roots)
                .with_no_client_auth(),
        ));
        let stats = Arc::new(Stats::default());
        let cache = CacheStore::new(directory.path().join("cache"));
        let handle = spawn_proxy_with_listeners(
            Settings {
                cache_enabled: false,
                https_mode: mode,
                https_inspection_scope: scope,
                https_client_trust_acknowledged: true,
                https_inspect_hosts: if selected {
                    vec!["127.0.0.1".into()]
                } else {
                    vec!["example.com".into()]
                },
                ..Settings::default()
            },
            cache.clone(),
            stats.clone(),
            inspection,
            vec![listener],
            true,
        )
        .unwrap();
        for _ in 0..2 {
            let response = https_exchange(&client, port, origin_port, "/image.jpg").await;
            let body = response_body(&response);
            assert_eq!(body.len() < source.len(), inspected);
            assert_eq!(image::load_from_memory(body).unwrap().width(), 800);
            if !inspected {
                assert!(body == source.as_slice());
            }
        }
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.compressed_images, if inspected { 2 } else { 0 });
        assert_eq!(snapshot.cache_bytes_saved, 0);
        assert_eq!(snapshot.cache_hits, 0);
        if inspected {
            assert!(snapshot.compression_bytes_saved > 0);
            assert_eq!(
                snapshot.compression_bytes_saved,
                snapshot.origin_bytes - snapshot.delivered_bytes
            );
        } else {
            assert_eq!(snapshot.compression_bytes_saved, 0);
        }
        assert_eq!(cache.usage().await.entry_count, 0);
        handle.stop().await;
        upstream.await.unwrap();
    }
}

async fn buffered_context(directory: &std::path::Path, cache_enabled: bool) -> ProxyContext {
    let settings = Settings {
        cache_enabled,
        compression_preset: CompressionPreset::Balanced,
        tunnel_idle_timeout_seconds: 60,
        ..Settings::default()
    };
    let mut context = service_port_tests::context(directory, settings).await;
    context
        .cache_enabled
        .store(cache_enabled, Ordering::Release);
    context.allow_private_destinations = true;
    context
        .stats
        .configure_history(directory.join("usage.json"), &context.settings)
        .unwrap();
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    context.activity_id = context.stats.begin_activity(peer, peer);
    let mut permit = context.connections.try_acquire(peer).unwrap();
    permit.track(&context.stats, context.activity_id);
    context.connection_permit = Some(Arc::new(permit));
    context
}

async fn buffered_request(
    context: &ProxyContext,
    port: u16,
    path: &str,
) -> Result<Response<ProxyBody>, ProxyError> {
    forward_web_request(
        Request::builder()
            .uri(format!("http://127.0.0.1:{port}/{path}"))
            .body(empty_body())
            .unwrap(),
        context,
        WebOrigin::Plain {
            host: "127.0.0.1".into(),
            port,
        },
    )
    .await
}

fn history_saved(context: &ProxyContext) -> u64 {
    let report = context.stats.history_report().unwrap();
    assert!(report.healthy);
    report.rows.iter().map(|row| row.counters.saved_bytes).sum()
}

async fn stop_buffered_context(context: &ProxyContext) {
    context.cancellation.cancel();
    context.tasks.close();
    context.tasks.wait().await;
}

#[tokio::test]
async fn buffered_compression_is_credited_only_when_the_client_polls_data() {
    let source = Arc::new(transformable_https_jpeg());
    for cache_enabled in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let context = buffered_context(directory.path(), cache_enabled).await;
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let origin_source = source.clone();
        let upstream = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = origin.accept().await.unwrap();
                read_tls_headers(&mut stream).await;
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nCache-Control: public, max-age=60\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", origin_source.len()).as_bytes()).await.unwrap();
                stream.write_all(&origin_source).await.unwrap();
            }
        });
        let unpolled = buffered_request(&context, port, "dropped.jpg")
            .await
            .unwrap();
        assert!(
            unpolled.headers()[CONTENT_LENGTH]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap()
                < source.len()
        );
        assert_eq!(context.stats.snapshot().origin_bytes, source.len() as u64);
        assert_eq!(context.stats.snapshot().delivered_bytes, 0);
        assert_eq!(context.stats.snapshot().compressed_images, 0);
        assert_eq!(context.stats.snapshot().compression_bytes_saved, 0);
        assert_eq!(history_saved(&context), 0);
        drop(unpolled);
        assert_eq!(
            context.buffer_budget.available_permits(),
            MAX_BUFFERED_BYTES
        );
        assert_eq!(history_saved(&context), 0);

        let response = buffered_request(&context, port, "polled.jpg")
            .await
            .unwrap();
        assert_eq!(context.stats.snapshot().compressed_images, 0);
        let mut body = response.into_body();
        let frame = body.frame().await.unwrap().unwrap();
        let bytes = frame.data_ref().unwrap();
        assert!(!bytes.is_empty());
        assert!(bytes.len() < source.len());
        assert_eq!(image::load_from_memory(bytes).unwrap().width(), 800);
        let delivered = bytes.len() as u64;
        let saved = source.len() as u64 - delivered;
        assert_eq!(context.stats.snapshot().compressed_images, 1);
        assert_eq!(context.stats.snapshot().compression_bytes_saved, saved);
        assert_eq!(
            context.stats.snapshot().origin_bytes,
            2 * source.len() as u64
        );
        assert_eq!(context.stats.snapshot().delivered_bytes, delivered);
        assert_eq!(history_saved(&context), saved);
        assert!(body.frame().await.is_none());
        assert!(body.frame().await.is_none());
        assert_eq!(context.stats.snapshot().compressed_images, 1);
        drop(frame);
        drop(body);
        assert_eq!(
            context.buffer_budget.available_permits(),
            MAX_BUFFERED_BYTES
        );
        if cache_enabled {
            let hit = buffered_request(&context, port, "polled.jpg")
                .await
                .unwrap();
            assert_eq!(context.stats.snapshot().cache_bytes_saved, 0);
            let hit_bytes = hit.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(hit_bytes.len() as u64, delivered);
            assert_eq!(context.stats.snapshot().compressed_images, 1);
            assert_eq!(context.stats.snapshot().compression_bytes_saved, saved);
            assert_eq!(context.stats.snapshot().cache_bytes_saved, delivered);
            assert_eq!(context.stats.snapshot().delivered_bytes, 2 * delivered);
            assert_eq!(
                context.stats.snapshot().origin_bytes,
                2 * source.len() as u64
            );
            assert_eq!(history_saved(&context), saved + delivered);
        }
        stop_buffered_context(&context).await;
        upstream.await.unwrap();
    }
}

#[tokio::test]
async fn progressing_buffered_image_survives_35_seconds_with_cache_on_and_off() {
    let source = Arc::new(transformable_https_jpeg());
    let exercise = |cache_enabled| {
        let source = source.clone();
        async move {
            let directory = tempfile::tempdir().unwrap();
            let context = buffered_context(directory.path(), cache_enabled).await;
            let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = origin.local_addr().unwrap().port();
            let origin_source = source.clone();
            let upstream = tokio::spawn(async move {
                let (mut stream, _) = origin.accept().await.unwrap();
                read_tls_headers(&mut stream).await;
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nCache-Control: public, max-age=120\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", origin_source.len()).as_bytes()).await.unwrap();
                let chunk_size = origin_source.len().div_ceil(8);
                for (index, chunk) in origin_source.chunks(chunk_size).enumerate() {
                    if index > 0 {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    stream.write_all(chunk).await.unwrap();
                }
            });
            let started = tokio::time::Instant::now();
            let result = buffered_request(&context, port, "progress.jpg").await;
            assert!(
                result.is_ok(),
                "35s progressing image, cache={cache_enabled}: {}",
                result
                    .as_ref()
                    .err()
                    .map(ToString::to_string)
                    .unwrap_or_default()
            );
            assert!(started.elapsed() >= Duration::from_secs(35));
            let body = result
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes();
            assert!(body.len() < source.len());
            assert_eq!(image::load_from_memory(&body).unwrap().width(), 800);
            let stats = context.stats.snapshot();
            assert_eq!(stats.origin_bytes, source.len() as u64);
            assert_eq!(stats.delivered_bytes, body.len() as u64);
            assert_eq!(
                stats.compression_bytes_saved,
                source.len() as u64 - body.len() as u64
            );
            assert_eq!(stats.compressed_images, 1);
            drop(body);
            assert_eq!(
                context.buffer_budget.available_permits(),
                MAX_BUFFERED_BYTES
            );
            assert_eq!(
                context.cache.usage().await.entry_count,
                usize::from(cache_enabled) as u64
            );
            stop_buffered_context(&context).await;
            upstream.await.unwrap();
        }
    };
    tokio::join!(exercise(false), exercise(true));
}

#[tokio::test]
async fn buffered_collection_releases_memory_after_inactivity_and_cancellation() {
    for cancel in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut context = buffered_context(directory.path(), false).await;
        // A short fixture window exercises the identical bounded path without
        // spending the production minimum of 60 seconds on a stalled origin.
        context.settings.tunnel_idle_timeout_seconds = 1;
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let (sent, received) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            read_tls_headers(&mut stream).await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nCache-Control: public, max-age=60\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx").await.unwrap();
            sent.send(()).unwrap();
            let mut byte = [0];
            let _ = stream.read(&mut byte).await;
        });
        let task_context = context.clone();
        let task =
            tokio::spawn(async move { buffered_request(&task_context, port, "stalled.jpg").await });
        received.await.unwrap();
        timeout(Duration::from_secs(2), async {
            while context.stats.snapshot().origin_bytes != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(context.buffer_budget.available_permits() < MAX_BUFFERED_BYTES);
        if cancel {
            context.cancellation.cancel();
        }
        let result = timeout(Duration::from_secs(if cancel { 1 } else { 3 }), task)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err());
        assert_eq!(
            context.buffer_budget.available_permits(),
            MAX_BUFFERED_BYTES
        );
        let stats = context.stats.snapshot();
        assert_eq!(stats.origin_bytes, 1);
        assert_eq!(stats.delivered_bytes, 0);
        assert_eq!(stats.compressed_images, 0);
        assert_eq!(stats.compression_bytes_saved, 0);
        assert_eq!(history_saved(&context), 0);
        stop_buffered_context(&context).await;
        upstream.await.unwrap();
    }
}
