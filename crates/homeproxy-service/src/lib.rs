#![cfg(target_os = "linux")]
use clap::Parser;
use homeproxy_control::{
    read_frame, write_response, Command, ControlError, Request, Response, MAX_FRAME, VERSION,
};
use homeproxy_core::{
    available_lan_addresses, CertificateFormat, Engine, EngineError, FilterFeed, HttpsMode,
    Settings, TlsInspectionError,
};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    future::Future,
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

#[derive(Clone, Debug, Parser)]
#[command(
    name = "homeproxyd",
    version,
    about = "HomeProxy unattended Linux service"
)]
pub struct Options {
    #[arg(long, default_value = "/var/lib/homeproxy")]
    pub state_dir: PathBuf,
    #[arg(long, default_value = "/var/cache/homeproxy")]
    pub cache_dir: PathBuf,
    #[arg(long, env = "HOMEPROXY_SOCKET", default_value = homeproxy_control::SYSTEM_SOCKET)]
    pub socket: PathBuf,
    /// Authorize the service's primary group through a 0660 socket in a 0750 directory.
    /// Intended only for the packaged homeproxy:homeproxy-admin system service.
    #[arg(long)]
    pub shared_socket: bool,
    /// The service always runs in foreground, including under systemd.
    #[arg(long)]
    pub foreground: bool,
}

struct ControlState {
    engine: Arc<Engine>,
    generation: u64,
    instance: String,
}

impl ControlState {
    fn revision(&self) -> String {
        format!("{}:{}", self.instance, self.generation)
    }

    async fn snapshot(&self, secrets: bool) -> Result<Value, ControlError> {
        let mut value =
            serde_json::to_value(self.engine.snapshot().await).map_err(internal_error)?;
        if !secrets {
            if let Some(settings) = value["settings"].as_object_mut() {
                settings.remove("proxyPassword");
                settings.remove("proxyUsername");
            }
            redact_secrets(&mut value);
        }
        value["revision"] = json!(self.revision());
        value["platform"] = json!("linux");
        value["serviceVersion"] = json!(env!("CARGO_PKG_VERSION"));
        value["supportsHttpsInspection"] = json!(self.engine.https_inspection_capability());
        value["usageHistory"] = history_summary(self.engine.usage_history(), 60);
        value["quotaStatuses"] =
            serde_json::to_value(self.engine.quota_statuses()).map_err(internal_error)?;
        Ok(value)
    }

    async fn validate_saved(&self) -> Result<(), ControlError> {
        let settings = self.engine.snapshot().await.settings;
        validate_settings(&self.engine, &settings)?;
        // A saved Inspect profile is only usable with a prepared, safely stored authority.
        if settings.https_mode == HttpsMode::Inspect {
            let authority = self.engine.https_authority().await;
            if !authority.prepared {
                return Err(match authority.error {
                    Some(message) => ControlError::new("tls_unavailable", message),
                    None => engine_error(EngineError::Tls(TlsInspectionError::NotPrepared)),
                });
            }
        }
        Ok(())
    }

    fn check_revision(&self, expected: &str) -> Result<(), ControlError> {
        if self.revision() == expected {
            Ok(())
        } else {
            Err(ControlError::new("conflict", "Settings changed in another client or the daemon restarted. Reload settings before saving."))
        }
    }

    async fn dispatch(&mut self, command: Command) -> Result<Value, ControlError> {
        match command {
            Command::ExportDiagnostics => return Ok(self.engine.diagnostics().export()),
            Command::DiagnosticsStatus => return Ok(self.engine.diagnostics().status()),
            Command::Status => return self.snapshot(false).await,
            Command::DesktopSnapshot => return self.snapshot(true).await,
            Command::ResetTransferStats => {
                return serde_json::to_value(self.engine.reset_transfer_stats())
                    .map_err(internal_error);
            }
            Command::OfflinePreparationStatus => {
                return serde_json::to_value(self.engine.offline_preparation_status().await)
                    .map_err(internal_error);
            }
            Command::PrepareOffline { request } => {
                let request = serde_json::from_value(request).map_err(|_| {
                    ControlError::new("invalid_input", "Invalid offline preparation request")
                })?;
                let id = self
                    .engine
                    .prepare_offline(request)
                    .await
                    .map_err(engine_error)?;
                return Ok(json!({"id":id}));
            }
            Command::CancelOfflinePreparation { id } => {
                self.engine
                    .cancel_offline_preparation(&id)
                    .await
                    .map_err(engine_error)?;
                return serde_json::to_value(self.engine.offline_preparation_status().await)
                    .map_err(internal_error);
            }
            Command::ReleaseOfflinePin { key } => {
                self.engine
                    .release_offline_pin(&key)
                    .await
                    .map_err(engine_error)?;
                return serde_json::to_value(self.engine.offline_preparation_status().await)
                    .map_err(internal_error);
            }
            Command::Credentials => {
                let settings = self.engine.snapshot().await.settings;
                return Ok(
                    json!({"username":settings.proxy_username,"password":settings.proxy_password}),
                );
            }
            Command::ConfigCheck => {
                self.validate_saved().await?;
                return Ok(json!({"valid":true}));
            }
            Command::FilterFeeds => {
                return serde_json::to_value(self.engine.snapshot().await.settings.filter_feeds)
                    .map_err(internal_error)
            }
            Command::ImportFilterFeed {
                feed,
                expected_revision,
            } => {
                self.check_revision(&expected_revision)?;
                let feed: FilterFeed = serde_json::from_value(feed).map_err(|_| {
                    ControlError::new("invalid_config", "Invalid filter feed structure")
                })?;
                let mut settings = self.engine.snapshot().await.settings;
                if let Some(existing) = settings
                    .filter_feeds
                    .iter_mut()
                    .find(|existing| existing.id == feed.id)
                {
                    *existing = feed;
                } else {
                    settings.filter_feeds.push(feed);
                }
                validate_settings(&self.engine, &settings)?;
                self.engine
                    .apply_settings(settings)
                    .await
                    .map_err(engine_error)?;
            }
            Command::RemoveFilterFeed {
                id,
                expected_revision,
            } => {
                self.check_revision(&expected_revision)?;
                let mut settings = self.engine.snapshot().await.settings;
                let before = settings.filter_feeds.len();
                settings.filter_feeds.retain(|feed| feed.id != id);
                if before == settings.filter_feeds.len() {
                    return Err(ControlError::new(
                        "invalid_config",
                        "Filter feed was not found",
                    ));
                }
                validate_settings(&self.engine, &settings)?;
                self.engine
                    .apply_settings(settings)
                    .await
                    .map_err(engine_error)?;
            }
            Command::TlsStatus => {
                return serde_json::to_value(self.engine.https_authority().await)
                    .map_err(internal_error);
            }
            Command::UsageHistory => return Ok(history_summary(self.engine.usage_history(), 512)),
            Command::ExportUsageHistory { format } => {
                self.engine
                    .checkpoint_history()
                    .await
                    .map_err(engine_error)?;
                let csv = format == homeproxy_control::HistoryFormat::Csv;
                let content = self
                    .engine
                    .export_usage_history(csv)
                    .map_err(engine_error)?;
                return Ok(json!({"format":format,"content":content}));
            }
            // Neither command changes settings, so drafts keep their revision.
            Command::PrepareCa => {
                let status = self
                    .engine
                    .prepare_https_authority()
                    .await
                    .map_err(engine_error)?;
                return serde_json::to_value(status).map_err(internal_error);
            }
            Command::ExportCa { format } => {
                let format = match format {
                    homeproxy_control::CertificateFormat::Pem => CertificateFormat::Pem,
                    homeproxy_control::CertificateFormat::Der => CertificateFormat::Der,
                };
                let exported = self
                    .engine
                    .export_https_certificate(format)
                    .await
                    .map_err(engine_error)?;
                return serde_json::to_value(exported).map_err(internal_error);
            }
            Command::Start => {
                self.engine.start().await.map_err(engine_error)?;
                return self.snapshot(false).await;
            }
            Command::Stop => {
                self.engine.stop().await.map_err(engine_error)?;
                return self.snapshot(false).await;
            }
            Command::ApplySettings {
                settings,
                expected_revision,
            } => {
                self.check_revision(&expected_revision)?;
                let settings = parse_settings(&self.engine, settings)?;
                self.engine
                    .apply_settings(settings)
                    .await
                    .map_err(engine_error)?;
            }
            Command::ConfigureLan {
                settings,
                listen_ip,
                cache_enabled,
                expected_revision,
            } => {
                self.check_revision(&expected_revision)?;
                let settings = parse_settings(&self.engine, settings)?;
                self.engine
                    .configure_lan_and_start(settings, listen_ip, cache_enabled)
                    .await
                    .map_err(engine_error)?;
            }
            Command::ConfigPatch { patch } => {
                let patch = patch.as_object().ok_or_else(|| {
                    ControlError::new(
                        "invalid_config",
                        "Configuration patch must be a JSON object",
                    )
                })?;
                let mut current = serde_json::to_value(self.engine.snapshot().await.settings)
                    .map_err(internal_error)?;
                let object = current.as_object_mut().ok_or_else(|| {
                    ControlError::new("internal", "Invalid settings representation")
                })?;
                for (key, value) in patch {
                    if key == "enabled" || key == "version" || !object.contains_key(key) {
                        return Err(ControlError::new(
                            "invalid_config",
                            "Unknown or read-only setting; use start/stop to control the service",
                        ));
                    }
                    object.insert(key.clone(), value.clone());
                }
                // Single-address CLI edits replace the previous multi-address selection.
                // Conversely, a list-only edit selects its first entry as the primary address.
                if let Some(ip) = patch
                    .get("listenIp")
                    .filter(|_| !patch.contains_key("listenIps"))
                {
                    object.insert(
                        "listenIps".into(),
                        if ip.is_null() { json!([]) } else { json!([ip]) },
                    );
                } else if let Some(ips) = patch
                    .get("listenIps")
                    .filter(|_| !patch.contains_key("listenIp"))
                {
                    object.insert(
                        "listenIp".into(),
                        ips.as_array()
                            .and_then(|ips| ips.first())
                            .cloned()
                            .unwrap_or(Value::Null),
                    );
                }
                let settings = parse_settings(&self.engine, current)?;
                self.engine
                    .apply_settings(settings)
                    .await
                    .map_err(engine_error)?;
            }
            Command::RotatePassword => self
                .engine
                .rotate_proxy_password()
                .await
                .map_err(engine_error)?,
            Command::SetDeviceAllowed { ip, allowed } => self
                .engine
                .set_device_allowed(ip, allowed)
                .await
                .map_err(engine_error)?,
            Command::ClearCache => {
                self.engine.clear_cache().await.map_err(engine_error)?;
                return self.snapshot(false).await;
            }
            Command::ClearActivity => {
                self.engine.clear_activity();
                return self.snapshot(false).await;
            }
        }
        self.generation = self.generation.wrapping_add(1);
        self.snapshot(false).await
    }
}

fn parse_settings(engine: &Engine, value: Value) -> Result<Settings, ControlError> {
    // Settings' serde compatibility defaults are for persisted legacy profiles, not malformed RPC.
    let allowed = serde_json::to_value(Settings::default()).map_err(internal_error)?;
    let supplied = value
        .as_object()
        .ok_or_else(|| ControlError::new("invalid_config", "Settings must be an object"))?;
    if supplied.len() != allowed.as_object().map_or(0, |object| object.len())
        || supplied.keys().any(|key| allowed.get(key).is_none())
    {
        return Err(ControlError::new(
            "invalid_config",
            "Missing or unknown configuration field; send the complete settings object",
        ));
    }
    let settings: Settings = serde_json::from_value(value).map_err(|_| {
        ControlError::new(
            "invalid_config",
            "Invalid configuration types or missing fields",
        )
    })?;
    validate_settings(engine, &settings)?;
    Ok(settings)
}

fn redact_secrets(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.retain(|key, _| !matches!(key.as_str(), "proxyPassword" | "password"));
            for child in fields.values_mut() {
                redact_secrets(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                redact_secrets(child);
            }
        }
        _ => {}
    }
}

fn history_summary(report: Option<homeproxy_core::HistoryReport>, limit: usize) -> Value {
    homeproxy_core::summarize_usage_history(report, limit)
}

/// Inspect is accepted only when this daemon genuinely implements it; the engine then also
/// requires the saved acknowledgement, allowlist and a prepared authority before saving it.
fn validate_settings(engine: &Engine, settings: &Settings) -> Result<(), ControlError> {
    if settings.https_mode == HttpsMode::Inspect && !engine.https_inspection_capability() {
        return Err(engine_error(EngineError::InspectionUnsupported));
    }
    if !settings.listen_ips.is_empty()
        && !settings
            .listen_ip
            .as_ref()
            .is_some_and(|ip| settings.listen_ips.contains(ip))
    {
        return Err(ControlError::new(
            "invalid_config",
            "listenIp must be one of listenIps",
        ));
    }
    settings
        .validate(&available_lan_addresses())
        .map_err(|error| ControlError::new("invalid_config", error.to_string()))
}

fn internal_error(_: serde_json::Error) -> ControlError {
    ControlError::new("internal", "Cannot encode service state")
}
fn engine_error(error: EngineError) -> ControlError {
    if let Some(failure) = error.listener_bind_failure() {
        let code = match failure.reason {
            homeproxy_core::ListenerBindReason::InUse => "listener_in_use",
            homeproxy_core::ListenerBindReason::AccessDenied => "listener_access_denied",
            homeproxy_core::ListenerBindReason::AddressUnavailable => {
                "listener_address_unavailable"
            }
            homeproxy_core::ListenerBindReason::Other => "listener_start_failed",
        };
        return ControlError::new(code, error.to_string());
    }
    let code = match &error {
        EngineError::InspectionUnsupported => "inspection_unsupported",
        EngineError::StopPersistence(_) => "stop_persistence",
        EngineError::Tls(TlsInspectionError::NotPrepared) => "tls_not_prepared",
        EngineError::Tls(_) => "tls_unavailable",
        _ => "operation_failed",
    };
    ControlError::new(code, error.to_string())
}

fn effective_uid() -> u32 {
    // SAFETY: this libc function has no arguments or preconditions.
    unsafe { libc::geteuid() }
}

fn effective_gid() -> u32 {
    // SAFETY: this libc function has no arguments or preconditions.
    unsafe { libc::getegid() }
}

fn prepare_directory(path: &Path, mode: u32) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(io::Error::other(
            "Service paths must be absolute and contain no '..'",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != effective_uid()
                || metadata.mode() & 0o777 != mode
            {
                return Err(io::Error::other(format!(
                    "{} must be an owned directory with mode {mode:o}",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Only create the final directory: don't change an existing ancestor's permissions.
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn lock_directory(directory: &Path) -> io::Result<File> {
    let path = directory.join(".homeproxy.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != effective_uid()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::other("Unsafe service lock file"));
    }
    file.try_lock().map_err(|_| {
        io::Error::other("Another HomeProxy daemon owns this state, cache or socket directory")
    })?;
    Ok(file)
}

fn check_settings_file(directory: &Path) -> io::Result<()> {
    match fs::symlink_metadata(directory.join("settings.json")) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.uid() != effective_uid() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 || metadata.len() > MAX_FRAME as u64 => Err(io::Error::other("Unsafe settings file: require owned regular file, mode 0600, no links, at most 256 KiB")),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

struct SocketGuard {
    path: PathBuf,
    inode: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|m| {
            m.file_type().is_socket() && m.ino() == self.inode && m.uid() == effective_uid()
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn bind_socket(path: &Path, shared: bool) -> io::Result<(UnixListener, SocketGuard)> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == effective_uid()
                && (!shared || metadata.gid() == effective_gid()) =>
        {
            fs::remove_file(path)?
        }
        Ok(_) => {
            return Err(io::Error::other(
                "Refusing to replace a non-socket or foreign control endpoint",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    let guard = SocketGuard {
        path: path.to_owned(),
        inode: fs::symlink_metadata(path)?.ino(),
    };
    if shared && fs::symlink_metadata(path)?.gid() != effective_gid() {
        return Err(io::Error::other(
            "Shared control socket must use the daemon's effective group",
        ));
    }
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if shared { 0o660 } else { 0o600 }),
    )?;
    Ok((listener, guard))
}

async fn handle(
    mut stream: UnixStream,
    shared: bool,
    state: Arc<Mutex<ControlState>>,
    diagnostics: Arc<homeproxy_core::Diagnostics>,
) {
    let Ok(peer) = stream.peer_cred() else { return };
    // In shared mode, Linux enforces directory traversal + write access to the 0660
    // pathname socket. Its group is the service's primary homeproxy-admin group.
    // The containing directory is owned and not group-writable. No abstract/TCP listener.
    if !shared && peer.uid() != effective_uid() && peer.uid() != 0 {
        return;
    }
    let bytes = match tokio::time::timeout(Duration::from_secs(3), read_frame(&mut stream)).await {
        Ok(Ok(bytes)) => bytes,
        _ => return,
    };
    let result = match serde_json::from_slice::<Request>(&bytes) {
        Err(_) => Err(ControlError::new(
            "invalid_request",
            "Malformed or unsupported control request",
        )),
        Ok(request) if request.version != VERSION => Err(ControlError::new(
            "version_mismatch",
            "CLI and daemon protocol versions differ",
        )),
        // These projections use bounded, nonblocking diagnostic state. In particular,
        // an export must not queue behind the mutation which caused an incident.
        // Peer/socket authorization and exact wire validation above still apply.
        Ok(Request {
            command: Command::ExportDiagnostics,
            ..
        }) => Ok(diagnostics.export()),
        Ok(Request {
            command: Command::DiagnosticsStatus,
            ..
        }) => Ok(diagnostics.status()),
        Ok(request) => {
            match tokio::time::timeout(Duration::from_secs(10), state.lock()).await {
                Err(_) => Err(ControlError::new(
                    "busy",
                    "Service is busy; retry after checking status",
                )),
                // Do not cancel an in-flight settings transition on client disconnect/timeout.
                Ok(mut state) => state.dispatch(request.command).await,
            }
        }
    };
    let response = Response {
        version: VERSION,
        result,
    };
    // Bound slow consumers without cancelling the completed mutation.
    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        write_response(&mut stream, &response),
    )
    .await;
}

pub async fn run(options: Options, shutdown: impl Future<Output = ()>) -> io::Result<()> {
    if effective_uid() == 0 {
        return Err(io::Error::other(
            "Run homeproxyd as an unprivileged user, not root",
        ));
    }
    prepare_directory(&options.state_dir, 0o700)?;
    prepare_directory(&options.cache_dir, 0o700)?;
    let socket_parent = options
        .socket
        .parent()
        .ok_or_else(|| io::Error::other("Missing socket parent"))?;
    prepare_directory(
        socket_parent,
        if options.shared_socket { 0o750 } else { 0o700 },
    )?;
    if options.shared_socket && fs::symlink_metadata(socket_parent)?.gid() != effective_gid() {
        return Err(io::Error::other(
            "Shared control directory must use the daemon's effective group",
        ));
    }
    let _state_lock = lock_directory(&options.state_dir)?;
    let _cache_lock = lock_directory(&options.cache_dir)?;
    let _socket_lock = lock_directory(socket_parent)?;
    check_settings_file(&options.state_dir)?;
    let engine = Arc::new(
        Engine::new_headless(options.state_dir, options.cache_dir).map_err(io::Error::other)?,
    );
    let _ = engine.start_saved().await; // Error is observable through status/doctor; control stays available.
    let instance = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos()
    );
    let state = Arc::new(Mutex::new(ControlState {
        engine: engine.clone(),
        generation: 0,
        instance,
    }));
    let (listener, _socket_guard) = bind_socket(&options.socket, options.shared_socket)?;
    eprintln!("HomeProxy control ready at {}", options.socket.display());
    let capacity = Arc::new(Semaphore::new(32));
    let mut requests = JoinSet::new();
    // History I/O and saved-enabled retry must not block the socket accept loop or
    // the independent local health observer.
    let maintenance_engine = engine.clone();
    let maintenance =
        tokio::spawn(async move { maintenance_engine.run_periodic_maintenance().await });
    let watchdog_engine = engine.clone();
    let watchdog = tokio::spawn(async move { watchdog_engine.run_watchdog().await });
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            Some(result) = requests.join_next(), if !requests.is_empty() => {
                if result.is_err() { eprintln!("HomeProxy control worker failed"); }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        eprintln!("HomeProxy control accept failed: {error}; retrying");
                        tokio::select! {
                            _ = &mut shutdown => break,
                            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                        }
                        continue;
                    }
                };
                let Ok(permit) = capacity.clone().try_acquire_owned() else { continue };
                let state = state.clone();
                let diagnostics = engine.diagnostics();
                let shared = options.shared_socket;
                requests.spawn(async move { let _permit = permit; handle(stream, shared, state, diagnostics).await; });
            }
        }
    }
    drop(listener);
    while requests.join_next().await.is_some() {}
    engine.shutdown().await;
    let _ = maintenance.await;
    let _ = watchdog.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transfer_reset_returns_only_stats_without_changing_revision_or_settings() {
        let root = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            Engine::new_headless(root.path().join("state"), root.path().join("cache")).unwrap(),
        );
        let diagnostics = engine.diagnostics();
        let state = Arc::new(Mutex::new(ControlState {
            engine,
            generation: 7,
            instance: "test".into(),
        }));
        let before = state.lock().await.snapshot(true).await.unwrap();
        for _ in 0..2 {
            let (server, mut client) = UnixStream::pair().unwrap();
            let task = tokio::spawn(handle(server, false, state.clone(), diagnostics.clone()));
            homeproxy_control::write_frame(
                &mut client,
                &Request {
                    version: VERSION,
                    command: Command::ResetTransferStats,
                },
            )
            .await
            .unwrap();
            let response: Response =
                serde_json::from_slice(&read_frame(&mut client).await.unwrap()).unwrap();
            let stats = response.result.unwrap();
            assert_eq!(stats["uploadBytes"], 0);
            assert_eq!(stats["downloadBytes"], 0);
            assert!(stats["transferStatsResetUnixMs"].as_u64().is_some());
            assert!(stats.get("settings").is_none());
            assert!(stats.get("revision").is_none());
            task.await.unwrap();
        }
        let after = state.lock().await.snapshot(true).await.unwrap();
        assert_eq!(after["settings"], before["settings"]);
        assert_eq!(after["revision"], before["revision"]);
    }

    #[tokio::test]
    async fn transfer_reset_still_validates_protocol_and_exact_request_shape() {
        let root = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            Engine::new_headless(root.path().join("state"), root.path().join("cache")).unwrap(),
        );
        let diagnostics = engine.diagnostics();
        let state = Arc::new(Mutex::new(ControlState {
            engine,
            generation: 0,
            instance: "test".into(),
        }));
        for (request, code) in [
            (
                json!({"version":VERSION+1,"command":{"method":"reset_transfer_stats"}}),
                "version_mismatch",
            ),
            (
                json!({"version":VERSION,"command":{"method":"reset_transfer_stats","scope":"all"}}),
                "invalid_request",
            ),
        ] {
            let (server, mut client) = UnixStream::pair().unwrap();
            let task = tokio::spawn(handle(server, false, state.clone(), diagnostics.clone()));
            homeproxy_control::write_frame(&mut client, &request)
                .await
                .unwrap();
            let response: Response =
                serde_json::from_slice(&read_frame(&mut client).await.unwrap()).unwrap();
            assert_eq!(response.result.unwrap_err().code, code);
            task.await.unwrap();
            let snapshot = state.lock().await.snapshot(true).await.unwrap();
            assert!(snapshot["stats"]["transferStatsResetUnixMs"].is_null());
        }
    }

    #[tokio::test]
    async fn diagnostics_bypasses_a_busy_control_transition() {
        let root = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            Engine::new_headless(root.path().join("state"), root.path().join("cache")).unwrap(),
        );
        let diagnostics = engine.diagnostics();
        let state = Arc::new(Mutex::new(ControlState {
            engine,
            generation: 0,
            instance: "test".into(),
        }));
        let _busy = state.lock().await;
        for command in [Command::DiagnosticsStatus, Command::ExportDiagnostics] {
            let (server, mut client) = UnixStream::pair().unwrap();
            let task = tokio::spawn(handle(server, false, state.clone(), diagnostics.clone()));
            homeproxy_control::write_frame(
                &mut client,
                &Request {
                    version: VERSION,
                    command,
                },
            )
            .await
            .unwrap();
            let bytes = tokio::time::timeout(Duration::from_secs(1), read_frame(&mut client))
                .await
                .unwrap()
                .unwrap();
            let response: Response = serde_json::from_slice(&bytes).unwrap();
            assert!(
                response.result.is_ok(),
                "diagnostics waited for ControlState"
            );
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn diagnostic_commands_still_validate_protocol_and_exact_wire_shape() {
        let root = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            Engine::new_headless(root.path().join("state"), root.path().join("cache")).unwrap(),
        );
        let diagnostics = engine.diagnostics();
        let state = Arc::new(Mutex::new(ControlState {
            engine,
            generation: 0,
            instance: "test".into(),
        }));
        for (request, code) in [
            (
                json!({"version": VERSION + 1, "command": {"method":"export_diagnostics"}}),
                "version_mismatch",
            ),
            (
                json!({"version": VERSION, "command": {"method":"export_diagnostics", "path":"/tmp/foreign"}}),
                "invalid_request",
            ),
        ] {
            let (server, mut client) = UnixStream::pair().unwrap();
            let task = tokio::spawn(handle(server, false, state.clone(), diagnostics.clone()));
            homeproxy_control::write_frame(&mut client, &request)
                .await
                .unwrap();
            let response: Response =
                serde_json::from_slice(&read_frame(&mut client).await.unwrap()).unwrap();
            assert_eq!(response.result.unwrap_err().code, code);
            task.await.unwrap();
        }
    }

    #[test]
    fn ordinary_status_redacts_nested_profile_and_upstream_secrets() {
        let mut value = json!({"settings":{"proxyPassword":"shared","deviceProfiles":[{"password":"personal","id":"tv"}],"upstreamProxies":[{"password":"parent","host":"proxy.example"}]}});
        redact_secrets(&mut value);
        assert_eq!(
            value,
            json!({"settings":{"deviceProfiles":[{"id":"tv"}],"upstreamProxies":[{"host":"proxy.example"}]}})
        );
    }

    #[test]
    fn status_history_window_has_explicit_truncation_and_full_retained_totals() {
        let rows = (0..100).map(|day| serde_json::json!({"identity":"tv","day":day,"counters":{"uploadBytes":1,"downloadBytes":2,"savedBytes":3,"requests":4}})).collect::<Vec<_>>();
        let report = homeproxy_core::HistoryReport {
            healthy: true,
            error: None,
            retention_days: 90,
            rows: serde_json::from_value(json!(rows)).unwrap(),
            months: Vec::new(),
            quota_debts: Vec::new(),
            quota_credits: Vec::new(),
        };
        let summary = history_summary(Some(report), 60);
        assert_eq!(summary["rowCount"], 100);
        assert_eq!(summary["truncated"], true);
        assert_eq!(summary["rows"].as_array().unwrap().len(), 60);
        assert_eq!(summary["rows"][0]["day"], 99);
        assert_eq!(summary["totals"]["downloadBytes"], 200);
        assert_eq!(summary["totals"]["savedBytes"], 300);
        assert!(history_summary(None, 60).is_null());
    }
}
