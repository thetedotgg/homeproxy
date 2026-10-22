//! Explicit native Windows regression. Uses only isolated files and an unused port.
//! Never calls Engine::new or installs a certificate, changes adapters or system proxy.
use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};

fn isolated_engine(directory: &std::path::Path) -> Engine {
    let settings_store = SettingsStore::new(directory.join("settings.json"));
    let settings = settings_store.load_or_create().unwrap();
    Engine {
        install_system_trust: false,
        headless: false,
        maintenance_cancellation: CancellationToken::new(),
        settings_store,
        history_path: directory.join("history.json"),
        cache: CacheStore::new(directory.join("cache")),
        offline_preparation: OfflinePreparation::new(directory.join("offline-preparation.json")),
        stats: Arc::new(Stats::default()),
        tls_inspection: TlsInspection::for_tests(
            directory.join("test-ca.json"),
            rustls::RootCertStore::empty(),
        )
        .unwrap(),
        state: Mutex::new(EngineState {
            settings,
            proxy: None,
            last_error: None,
            listener_error: None,
            // Test fixture trust readiness avoids the OS certificate installation path.
            tls_inspection_ready: true,
        }),
    }
}

#[tokio::test]
#[ignore = "native Windows only; explicitly supply HOMEPROXY_NATIVE_TEST_IP"]
async fn native_windows_adapter_reselection() {
    let selected = std::env::var("HOMEPROXY_NATIVE_TEST_IP").expect("explicit adapter IP required");
    let selected_ip: Ipv4Addr = selected.parse().unwrap();
    let addresses = available_lan_addresses();
    assert!(addresses.iter().any(|a| a.ip == selected_ip));
    let old = "192.168.68.52";
    assert!(
        !addresses.iter().any(|a| a.ip.to_string() == old),
        "old address must really be absent"
    );
    println!(
        "NATIVE detected={:?}; selected={selected}; saved_before={old}",
        addresses
    );
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = reservation.local_addr().unwrap().port();
    let lan_reservation = TcpListener::bind((selected_ip, port)).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = SettingsStore::new(directory.path().join("settings.json"));
    store
        .save(&Settings {
            enabled: true,
            lan_enabled: true,
            listen_ip: Some(old.into()),
            proxy_port: port,
            socks5_enabled: false,
            ..Settings::default()
        })
        .unwrap();
    let engine = isolated_engine(directory.path());
    drop(lan_reservation);
    drop(reservation);
    assert!(engine
        .start_saved()
        .await
        .unwrap_err()
        .to_string()
        .contains("Vybraná adresa"));
    let snapshot = engine.snapshot().await;
    assert!(!snapshot.running);
    assert!(snapshot
        .available_addresses
        .iter()
        .any(|a| a.ip == selected_ip));
    assert!(
        engine.start().await.is_err(),
        "old global start path must reproduce the failure"
    );
    println!("NATIVE RED boundary: saved-address startup fails although selected Windows adapter is available");
    timeout(
        Duration::from_secs(5),
        engine.configure_lan_and_start(snapshot.settings, selected.clone(), false),
    )
    .await
    .unwrap()
    .unwrap();
    let snapshot = engine.snapshot().await;
    assert!(snapshot.running);
    assert_eq!(
        snapshot.settings.listen_ip.as_deref(),
        Some(selected.as_str())
    );
    assert!(snapshot.last_error.is_none());
    assert_eq!(
        store.load_or_create().unwrap().listen_ip,
        Some(selected.clone())
    );
    assert!(snapshot
        .proxy_addresses
        .contains(&format!("{selected}:{port}")));
    for address in [Ipv4Addr::LOCALHOST, selected_ip] {
        let mut stream = TcpStream::connect((address, port)).await.unwrap();
        stream.write_all(b"GET http://homeproxy.test/ca.cer HTTP/1.1\r\nHost: homeproxy.test\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let expected = if address.is_loopback() {
            b"HTTP/1.1 200"
        } else {
            b"HTTP/1.1 407"
        };
        assert!(response.starts_with(expected));
    }
    // If the next choice disappears, validation must preserve the currently working listener.
    assert!(engine
        .configure_lan_and_start(snapshot.settings.clone(), old.into(), false)
        .await
        .is_err());
    assert!(engine.snapshot().await.running);
    assert_eq!(
        store.load_or_create().unwrap().listen_ip,
        Some(selected.clone())
    );
    engine.stop().await.unwrap();
    let mut saved = store.load_or_create().unwrap();
    saved.enabled = true;
    store.save(&saved).unwrap();
    let restarted = isolated_engine(directory.path());
    restarted.start_saved().await.unwrap();
    assert!(restarted.snapshot().await.running);
    restarted.stop().await.unwrap();
    println!("NATIVE PASS: selected/saved/live={selected}; loopback HTTP200 + LAN authenticated listener HTTP407; stale replacement rejected safely; persisted restart PASS; port={port}");
}
