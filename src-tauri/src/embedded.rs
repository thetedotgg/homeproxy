//! Windows runtime: the desktop process owns the proxy Engine and the system tray.
//! Linux never enters this module at runtime; it is still compiled there so the
//! Windows path keeps type-checking on the Linux development host.
#![cfg_attr(target_os = "linux", allow(dead_code))]

use std::sync::{Arc, OnceLock};

use homeproxy_core::{
    AppSnapshot, CertificateFormat, Engine, FilterFeed, OfflinePreparationRequest,
    OfflinePreparationStatus, Settings, StatsSnapshot,
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, State,
};

const APP_STATE_INITIALIZING: &str = "APP_STATE_INITIALIZING";

#[derive(Default)]
struct AppState {
    engine: OnceLock<Arc<Engine>>,
}

impl AppState {
    fn engine(&self) -> Result<&Arc<Engine>, String> {
        self.engine
            .get()
            .ok_or_else(|| APP_STATE_INITIALIZING.to_string())
    }
}

#[tauri::command]
async fn get_diagnostics_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    Ok(state.engine()?.diagnostics().status())
}

#[tauri::command]
async fn export_diagnostics(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let source = state.engine().map(|engine| engine.diagnostics().export());
    crate::diagnostic_export::save(app, source).await
}

#[tauri::command]
async fn get_snapshot(state: State<'_, AppState>) -> Result<AppSnapshot, String> {
    Ok(state.engine()?.snapshot().await)
}

async fn public_tls_status(engine: &Engine) -> Result<serde_json::Value, String> {
    let status = engine.https_authority().await;
    let mut value = serde_json::to_value(&status).map_err(|error| error.to_string())?;
    value["clientTrustAcknowledged"] = serde_json::json!(status.client_trust_declared);
    if status.prepared {
        value["certificatePem"] = serde_json::json!(
            engine
                .export_https_certificate(CertificateFormat::Pem)
                .await
                .map_err(|error| error.to_string())?
                .certificate
        );
    }
    Ok(value)
}

#[tauri::command]
async fn get_tls_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    public_tls_status(state.engine()?.as_ref()).await
}

#[tauri::command]
async fn prepare_tls_authority(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let engine = state.engine()?;
    engine
        .prepare_https_authority()
        .await
        .map_err(|error| error.to_string())?;
    public_tls_status(engine).await
}

#[tauri::command]
async fn export_tls_certificate(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let exported = state
        .engine()?
        .export_https_certificate(CertificateFormat::Pem)
        .await
        .map_err(|error| error.to_string())?;
    Ok(
        serde_json::json!({"certificatePem":exported.certificate,"sha256Fingerprint":exported.sha256_fingerprint}),
    )
}

#[tauri::command]
async fn get_usage_history(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    Ok(state.engine()?.usage_history_summary(512))
}

#[tauri::command]
async fn export_usage_history(
    format: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let csv = match format.as_str() {
        "csv" => true,
        "json" => false,
        _ => return Err("History format must be json or csv".into()),
    };
    let engine = state.engine()?;
    engine
        .checkpoint_history()
        .await
        .map_err(|error| error.to_string())?;
    let content = engine
        .export_usage_history(csv)
        .map_err(|error| error.to_string())?;
    Ok(serde_json::json!({"format":format,"content":content}))
}

#[tauri::command]
async fn import_filter_feed(
    name: String,
    content: String,
    #[allow(unused_variables)] expected_revision: Option<String>,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let feed = FilterFeed::parse(&name, &content).map_err(|error| error.to_string())?;
    let engine = state.engine()?;
    engine
        .import_filter_feed(feed)
        .await
        .map_err(|error| error.to_string())?;
    Ok(engine.snapshot().await)
}

#[tauri::command]
async fn remove_filter_feed(
    id: String,
    #[allow(unused_variables)] expected_revision: Option<String>,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let engine = state.engine()?;
    engine
        .remove_filter_feed(&id)
        .await
        .map_err(|error| error.to_string())?;
    Ok(engine.snapshot().await)
}

#[tauri::command]
async fn set_running(running: bool, state: State<'_, AppState>) -> Result<AppSnapshot, String> {
    let engine = state.engine()?;
    if running {
        engine.start().await.map_err(|error| error.to_string())?;
    } else {
        engine.stop().await.map_err(|error| error.to_string())?;
    }
    Ok(engine.snapshot().await)
}

// `expected_revision` is the Linux service's optimistic-concurrency token; the embedded
// engine is the only writer, so it is accepted and ignored.
#[tauri::command]
async fn apply_settings(
    settings: Settings,
    #[allow(unused_variables)] expected_revision: Option<String>,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let engine = state.engine()?;
    engine
        .apply_settings(settings)
        .await
        .map_err(|error| error.to_string())?;
    Ok(engine.snapshot().await)
}

#[tauri::command]
async fn configure_lan_and_start(
    settings: Settings,
    listen_ip: String,
    cache_enabled: bool,
    #[allow(unused_variables)] expected_revision: Option<String>,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let engine = state.engine()?;
    engine
        .configure_lan_and_start(settings, listen_ip, cache_enabled)
        .await
        .map_err(|error| error.to_string())?;
    Ok(engine.snapshot().await)
}

#[tauri::command]
async fn rotate_proxy_password(state: State<'_, AppState>) -> Result<AppSnapshot, String> {
    let engine = state.engine()?;
    engine
        .rotate_proxy_password()
        .await
        .map_err(|error| error.to_string())?;
    Ok(engine.snapshot().await)
}

#[tauri::command]
async fn set_device_allowed(
    ip: String,
    allowed: bool,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let engine = state.engine()?;
    engine
        .set_device_allowed(ip, allowed)
        .await
        .map_err(|error| error.to_string())?;
    Ok(engine.snapshot().await)
}

#[tauri::command]
async fn clear_cache(state: State<'_, AppState>) -> Result<(), String> {
    state
        .engine()?
        .clear_cache()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn prepare_offline(
    request_data: OfflinePreparationRequest,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let id = state
        .engine()?
        .prepare_offline(request_data)
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"id":id}))
}

#[tauri::command]
async fn cancel_offline_preparation(
    id: String,
    state: State<'_, AppState>,
) -> Result<OfflinePreparationStatus, String> {
    let engine = state.engine()?;
    engine
        .cancel_offline_preparation(&id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(engine.offline_preparation_status().await)
}

#[tauri::command]
async fn release_offline_pin(
    key: String,
    state: State<'_, AppState>,
) -> Result<OfflinePreparationStatus, String> {
    let engine = state.engine()?;
    engine
        .release_offline_pin(&key)
        .await
        .map_err(|e| e.to_string())?;
    Ok(engine.offline_preparation_status().await)
}

#[tauri::command]
async fn clear_activity(state: State<'_, AppState>) -> Result<(), String> {
    state.engine()?.clear_activity();
    Ok(())
}

#[tauri::command]
async fn reset_transfer_stats(state: State<'_, AppState>) -> Result<StatsSnapshot, String> {
    Ok(state.engine()?.reset_transfer_stats())
}

fn restore_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
fn hide_to_tray(app: tauri::AppHandle) -> Result<(), String> {
    if app.tray_by_id("homeproxy").is_none() {
        return Err("System tray is unavailable.".to_string());
    }
    app.get_webview_window("main")
        .ok_or_else(|| "HomeProxy window is unavailable.".to_string())?
        .hide()
        .map_err(|error| error.to_string())
}

pub fn run() {
    let autostart_launch = std::env::args_os().any(|argument| argument == "--autostart");

    let builder = tauri::Builder::default().manage(AppState::default());
    // Isolated acceptance builds must never forward startup into the live app.
    #[cfg(not(feature = "isolated-test"))]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        restore_window(app);
    }));
    builder
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.app_handle().tray_by_id("homeproxy").is_some() && window.hide().is_ok() {
                    api.prevent_close();
                }
            }
        })
        .setup(move |app| {
            let show = MenuItem::with_id(app, "show", "Zobrazit / Show", true, None::<&str>)?;
            let hide = MenuItem::with_id(app, "hide", "Skrýt / Hide", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Ukončit / Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &hide, &quit])?;
            let icon = app
                .default_window_icon()
                .cloned()
                .ok_or("HomeProxy tray icon is missing")?;
            TrayIconBuilder::with_id("homeproxy")
                .icon(icon)
                .tooltip("HomeProxy")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => restore_window(app),
                    "hide" => {
                        let _ = hide_to_tray(app.clone());
                    }
                    "quit" => {
                        if let Ok(engine) = app.state::<AppState>().engine() {
                            let engine = engine.clone();
                            let app = app.clone();
                            tauri::async_runtime::spawn(async move {
                                engine.shutdown().await;
                                app.exit(0);
                            });
                        } else {
                            app.exit(0);
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        }
                    ) {
                        restore_window(tray.app_handle());
                    }
                })
                .build(app)?;
            #[cfg(not(feature = "isolated-test"))]
            let config_directory = app.path().app_config_dir()?;
            #[cfg(not(feature = "isolated-test"))]
            let cache_directory = app.path().app_cache_dir()?.join("public-http-v1");
            #[cfg(feature = "isolated-test")]
            let isolated_root = std::env::var_os("HOMEPROXY_ISOLATED_ROOT")
                .map(std::path::PathBuf::from)
                .filter(|path| path.is_absolute() && path.is_dir())
                .ok_or("Isolated test requires an existing absolute temporary root")?;
            #[cfg(feature = "isolated-test")]
            let engine = Arc::new(
                Engine::new_isolated(isolated_root.join("config"), isolated_root.join("cache"))
                    .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?,
            );
            #[cfg(not(feature = "isolated-test"))]
            let engine = Arc::new(
                Engine::new(config_directory, cache_directory)
                    .map_err(|error| Box::<dyn std::error::Error>::from(error.to_string()))?,
            );
            app.state::<AppState>()
                .engine
                .set(engine.clone())
                .map_err(|_| {
                    Box::<dyn std::error::Error>::from("HomeProxy AppState už byl inicializován")
                })?;
            let watchdog_engine = engine.clone();
            tauri::async_runtime::spawn(async move {
                watchdog_engine.run_watchdog().await;
            });
            let startup_engine = engine.clone();
            tauri::async_runtime::spawn(async move {
                let _ = startup_engine.start_saved().await;
                startup_engine.run_periodic_maintenance().await;
            });

            if !autostart_launch {
                if let Some(window) = app.get_webview_window("main") {
                    window.show()?;
                    window.set_focus()?;
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            get_diagnostics_status,
            export_diagnostics,
            get_tls_status,
            prepare_tls_authority,
            export_tls_certificate,
            get_usage_history,
            export_usage_history,
            import_filter_feed,
            remove_filter_feed,
            set_running,
            apply_settings,
            configure_lan_and_start,
            rotate_proxy_password,
            set_device_allowed,
            clear_cache,
            prepare_offline,
            cancel_offline_preparation,
            release_offline_pin,
            clear_activity,
            reset_transfer_stats,
            hide_to_tray
        ])
        .run(tauri::generate_context!())
        .expect("HomeProxy se nedokázal spustit");
}

#[cfg(test)]
mod tests {
    use super::{AppState, APP_STATE_INITIALIZING};

    #[cfg(target_os = "linux")]
    #[test]
    fn embedded_public_authority_adapter_keeps_preparation_separate_from_inspection_and_trust() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "homeproxy-embedded-authority-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        tauri::async_runtime::block_on(async {
            let engine =
                homeproxy_core::Engine::new_headless(root.join("config"), root.join("cache"))
                    .unwrap();
            let before = super::public_tls_status(&engine).await.unwrap();
            assert_eq!(before["prepared"], false);
            assert!(before.get("certificatePem").is_none());
            engine.prepare_https_authority().await.unwrap();
            let prepared = super::public_tls_status(&engine).await.unwrap();
            assert_eq!(prepared["prepared"], true);
            assert_eq!(prepared["inspectionEnabled"], false);
            assert_eq!(prepared["clientTrustAcknowledged"], false);
            assert_eq!(prepared["localTrustInstalled"], false);
            assert!(prepared["certificatePem"]
                .as_str()
                .unwrap()
                .starts_with("-----BEGIN CERTIFICATE-----"));
            assert!(!prepared.to_string().contains("PRIVATE"));
            engine.shutdown().await;
        });
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_placeholder_reports_initializing_until_the_engine_is_ready() {
        match AppState::default().engine() {
            Err(message) => assert_eq!(message, APP_STATE_INITIALIZING),
            Ok(_) => panic!("a fresh AppState unexpectedly contains an engine"),
        }
    }
}
