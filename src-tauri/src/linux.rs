//! Ubuntu/Linux desktop: a thin client of the system service (`homeproxy-control`).
//!
//! This process never owns a proxy runtime and never starts or stops the daemon by
//! itself; closing the window only quits the client. Errors are handed to the UI as
//! `HOMEPROXY_SERVICE:<code>:<message>` so the frontend can show localized guidance.
use std::path::Path;

use gtk::prelude::*;
use homeproxy_control::{
    call, default_socket, CertificateFormat, Command, ControlError, HistoryFormat,
};
use serde_json::Value;
use tauri::Manager;

const SERVICE_ERROR_PREFIX: &str = "HOMEPROXY_SERVICE";

fn service_error(error: ControlError) -> String {
    format!("{SERVICE_ERROR_PREFIX}:{}:{}", error.code, error.message)
}

async fn request_at(socket: &Path, command: Command) -> Result<Value, String> {
    call(socket, command).await.map_err(service_error)
}

async fn request(command: Command) -> Result<Value, String> {
    request_at(&default_socket(), command).await
}

async fn snapshot() -> Result<Value, String> {
    request(Command::DesktopSnapshot).await
}

/// Mutations answer with a sanitized snapshot; the UI needs the editable settings
/// (and the new revision), so a successful mutation is followed by a full snapshot.
async fn mutate(command: Command) -> Result<Value, String> {
    mutate_at(&default_socket(), command).await
}

/// The command was applied, so a failed follow-up snapshot must not look like a
/// failed mutation: a blind retry could repeat or clobber the change.
async fn mutate_at(socket: &Path, command: Command) -> Result<Value, String> {
    request_at(socket, command).await?;
    request_at(socket, Command::DesktopSnapshot)
        .await
        .map_err(|error| {
            let detail = error
                .strip_prefix(&format!("{SERVICE_ERROR_PREFIX}:"))
                .unwrap_or(&error);
            service_error(ControlError::new("applied_refresh_failed", detail))
        })
}

fn require_revision(expected_revision: Option<String>) -> Result<String, String> {
    expected_revision
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            service_error(ControlError::new(
                "revision_required",
                "The settings revision is missing. Reload the window before saving.",
            ))
        })
}

#[tauri::command]
async fn get_diagnostics_status() -> Result<Value, String> {
    request(Command::DiagnosticsStatus).await
}

#[tauri::command]
async fn export_diagnostics(app: tauri::AppHandle) -> Result<Value, String> {
    let source = request(Command::ExportDiagnostics).await;
    crate::diagnostic_export::save(app, source).await
}

#[tauri::command]
async fn get_snapshot() -> Result<Value, String> {
    snapshot().await
}

async fn public_tls_status(mut status: Value) -> Result<Value, String> {
    status["clientTrustAcknowledged"] = status
        .get("clientTrustDeclared")
        .cloned()
        .unwrap_or(Value::Bool(false));
    if status.get("prepared").and_then(Value::as_bool) == Some(true) {
        let certificate = request(Command::ExportCa {
            format: CertificateFormat::Pem,
        })
        .await?;
        status["certificatePem"] = certificate["certificate"].clone();
    }
    Ok(status)
}

#[tauri::command]
async fn get_tls_status() -> Result<Value, String> {
    public_tls_status(request(Command::TlsStatus).await?).await
}

#[tauri::command]
async fn prepare_tls_authority() -> Result<Value, String> {
    public_tls_status(request(Command::PrepareCa).await?).await
}

#[tauri::command]
async fn export_tls_certificate() -> Result<Value, String> {
    let certificate = request(Command::ExportCa {
        format: CertificateFormat::Pem,
    })
    .await?;
    Ok(
        serde_json::json!({"certificatePem":certificate["certificate"],"sha256Fingerprint":certificate["sha256Fingerprint"]}),
    )
}

#[tauri::command]
async fn get_usage_history() -> Result<Value, String> {
    request(Command::UsageHistory).await
}

#[tauri::command]
async fn export_usage_history(format: String) -> Result<Value, String> {
    let format = match format.as_str() {
        "csv" => HistoryFormat::Csv,
        "json" => HistoryFormat::Json,
        _ => {
            return Err(service_error(ControlError::new(
                "invalid_input",
                "History format must be json or csv",
            )))
        }
    };
    request(Command::ExportUsageHistory { format }).await
}

#[tauri::command]
async fn set_running(running: bool) -> Result<Value, String> {
    mutate(if running {
        Command::Start
    } else {
        Command::Stop
    })
    .await
}

#[tauri::command]
async fn apply_settings(
    settings: Value,
    expected_revision: Option<String>,
) -> Result<Value, String> {
    let expected_revision = require_revision(expected_revision)?;
    mutate(Command::ApplySettings {
        settings,
        expected_revision,
    })
    .await
}

#[tauri::command]
async fn configure_lan_and_start(
    settings: Value,
    listen_ip: String,
    cache_enabled: bool,
    expected_revision: Option<String>,
) -> Result<Value, String> {
    let expected_revision = require_revision(expected_revision)?;
    mutate(Command::ConfigureLan {
        settings,
        listen_ip,
        cache_enabled,
        expected_revision,
    })
    .await
}

#[tauri::command]
async fn rotate_proxy_password() -> Result<Value, String> {
    mutate(Command::RotatePassword).await
}

#[tauri::command]
async fn set_device_allowed(ip: String, allowed: bool) -> Result<Value, String> {
    mutate(Command::SetDeviceAllowed { ip, allowed }).await
}

#[tauri::command]
async fn clear_cache() -> Result<(), String> {
    request(Command::ClearCache).await.map(|_| ())
}

#[tauri::command]
async fn prepare_offline(request_data: Value) -> Result<Value, String> {
    request(Command::PrepareOffline {
        request: request_data,
    })
    .await
}

#[tauri::command]
async fn cancel_offline_preparation(id: String) -> Result<Value, String> {
    request(Command::CancelOfflinePreparation { id }).await
}

#[tauri::command]
async fn release_offline_pin(key: String) -> Result<Value, String> {
    request(Command::ReleaseOfflinePin { key }).await
}

#[tauri::command]
async fn clear_activity() -> Result<(), String> {
    request(Command::ClearActivity).await.map(|_| ())
}

#[tauri::command]
async fn reset_transfer_stats() -> Result<Value, String> {
    request(Command::ResetTransferStats).await
}

#[tauri::command]
async fn import_filter_feed(
    name: String,
    content: String,
    expected_revision: Option<String>,
) -> Result<Value, String> {
    let expected_revision = require_revision(expected_revision)?;
    let feed = homeproxy_core::FilterFeed::parse(&name, &content)
        .map_err(|error| service_error(ControlError::new("invalid_config", error.to_string())))?;
    let feed = serde_json::to_value(feed)
        .map_err(|error| service_error(ControlError::new("invalid_config", error.to_string())))?;
    mutate(Command::ImportFilterFeed {
        feed,
        expected_revision,
    })
    .await
}

#[tauri::command]
async fn remove_filter_feed(
    id: String,
    expected_revision: Option<String>,
) -> Result<Value, String> {
    mutate(Command::RemoveFilterFeed {
        id,
        expected_revision: require_revision(expected_revision)?,
    })
    .await
}

/// Linux has no tray: the UI hides the control, and the window closes normally.
#[tauri::command]
fn hide_to_tray() -> Result<(), String> {
    Err("System tray is unavailable.".to_string())
}

#[cfg_attr(feature = "isolated-test", allow(dead_code))]
fn restore_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn embedded_window_icon() -> Result<gtk::gdk_pixbuf::Pixbuf, gtk::glib::Error> {
    gtk::gdk_pixbuf::Pixbuf::from_read(std::io::Cursor::new(include_bytes!("../icons/128x128.png")))
}

fn configure_window_icon(window: &gtk::ApplicationWindow) -> Result<(), gtk::glib::Error> {
    let icon = gtk::IconTheme::default()
        .and_then(|theme| {
            theme
                .load_icon("klidna-sit", 128, gtk::IconLookupFlags::empty())
                .ok()
                .flatten()
        })
        .map(Ok)
        .unwrap_or_else(embedded_window_icon)?;
    // Set the native pixbuf before showing the window so GTK publishes its
    // X11 window icon too. Embedded bytes also cover uninstalled/dev launches.
    window.set_icon(Some(&icon));
    Ok(())
}

pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(not(feature = "isolated-test"))]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        restore_window(app);
    }));
    builder
        .setup(|app| {
            // Keep the three controls previously provided by Tao's custom header.
            // This changes GTK settings only in this process, not the user's desktop.
            // Tao now uses GTK's native decorations without the input-blocking EventBox.
            if let Some(settings) = gtk::Settings::default() {
                settings.set_gtk_decoration_layout(Some("menu:minimize,maximize,close"));
            }
            // The window starts hidden in tauri.conf.json to avoid a blank first paint.
            if let Some(window) = app.get_webview_window("main") {
                configure_window_icon(&window.gtk_window()?)?;
                window.show()?;
                window.set_focus()?;
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
    use super::*;

    #[test]
    fn embedded_window_icon_decodes_without_an_installed_icon_theme() {
        let icon = embedded_window_icon().unwrap();
        assert_eq!(icon.width(), 128);
        assert_eq!(icon.height(), 128);
        assert!(icon.has_alpha());
    }

    #[test]
    fn service_errors_carry_a_stable_code_for_the_ui() {
        let message = service_error(ControlError::new("conflict", "Reload settings."));
        assert_eq!(message, "HOMEPROXY_SERVICE:conflict:Reload settings.");
    }

    #[test]
    fn mutations_without_a_revision_never_reach_the_service() {
        for missing in [None, Some(String::new())] {
            let error = require_revision(missing).unwrap_err();
            assert!(error.starts_with("HOMEPROXY_SERVICE:revision_required:"));
        }
        assert_eq!(require_revision(Some("a:1".into())).unwrap(), "a:1");
    }

    #[test]
    fn a_missing_socket_reports_unavailable_without_starting_anything() {
        let socket = std::env::temp_dir().join("homeproxy-desktop-test-missing/control.sock");
        let error = tauri::async_runtime::block_on(request_at(&socket, Command::DesktopSnapshot))
            .unwrap_err();
        assert!(
            error.starts_with("HOMEPROXY_SERVICE:unavailable:"),
            "{error}"
        );
    }

    #[test]
    fn an_applied_mutation_whose_snapshot_fails_is_not_reported_as_a_plain_failure() {
        use std::io::{Read, Write};
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        use homeproxy_control::{Response, VERSION};

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "homeproxy-desktop-test-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();

        let server = std::thread::spawn(move || {
            let mut methods = Vec::new();
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut size = [0u8; 4];
                stream.read_exact(&mut size).unwrap();
                let mut request = vec![0u8; u32::from_be_bytes(size) as usize];
                stream.read_exact(&mut request).unwrap();
                let request: Value = serde_json::from_slice(&request).unwrap();
                methods.push(request["command"]["method"].as_str().unwrap().to_string());
                let result = if index == 0 {
                    Ok(serde_json::json!({}))
                } else {
                    Err(ControlError::new("timeout", "snapshot timed out"))
                };
                let bytes = serde_json::to_vec(&Response {
                    version: VERSION,
                    result,
                })
                .unwrap();
                stream
                    .write_all(&(bytes.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&bytes).unwrap();
            }
            methods
        });

        let error = tauri::async_runtime::block_on(mutate_at(&socket, Command::Start)).unwrap_err();
        let methods = server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            error.starts_with("HOMEPROXY_SERVICE:applied_refresh_failed:"),
            "{error}"
        );
        assert_eq!(methods.len(), 2);
        assert_ne!(methods[0], methods[1]);
        assert_eq!(methods[1], "desktop_snapshot");
    }

    #[test]
    fn the_tray_command_is_an_honest_error_on_linux() {
        assert!(hide_to_tray().is_err());
    }
}
