mod auth;
mod cache;
mod config;
mod diagnostics;
mod dns;
mod filter;
mod filter_feeds;
mod https_policy;
mod image_transform;
mod lan_dns;
mod offline_preparation;
mod policy;
mod proxy;
mod stats;
mod tls_inspection;
mod traffic;
mod usage_history;
mod watchdog;

use std::{net::Ipv4Addr, path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;

pub use config::{
    available_lan_addresses, AdblockMode, CacheMode, CompressionPreset, DeviceLimit, DnsMode,
    HttpsInspectionScope, HttpsMode, LanAddress, PublicCacheEndpoint, Settings, UpstreamProxy,
    DEFAULT_PROXY_PORT, DEFAULT_SOCKS5_PORT,
};
use config::{ConfigError, SettingsStore};
pub use diagnostics::Diagnostics;
pub use filter_feeds::{FilterFeed, FilterFeedError, MAX_FILTER_FILE_BYTES};
pub use policy::{DeviceProfile, ScheduleAction, ScheduleWindow};
use proxy::{start_proxy, ProxyHandle};
use serde::Serialize;
use stats::Stats;
pub use stats::{
    ConnectionRejectionReason, ConnectionRejectionSnapshot, QuotaStatus, StatsSnapshot,
};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::cache::CacheStore;
pub use crate::cache::CacheUsage;
pub use crate::tls_inspection::{CertificateFormat, ExportedCertificate, TlsInspectionError};
use crate::tls_inspection::{TlsInspection, AUTHORITY_RECORD_FILE};
pub use crate::usage_history::{HistoryError, HistoryReport};
use offline_preparation::OfflinePreparation;
pub use offline_preparation::{
    OfflinePreparationError, OfflinePreparationRequest, OfflinePreparationStatus,
};

/// The unattended service implements HTTPS Inspect with private on-disk authority storage
/// only on Linux. It never installs that authority into any trust store.
const HEADLESS_INSPECTION_CAPABILITY: bool = cfg!(target_os = "linux");

/// HTTPS authority facts kept separate on purpose: capability is not readiness, a prepared
/// authority does not enable Inspect, and the client-trust declaration is only the user's
/// statement, never evidence that any device trusts the authority.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpsAuthorityStatus {
    /// This engine implements HTTPS Inspect on this platform.
    pub capability: bool,
    /// A valid authority exists; created only by an explicit prepare (or Windows Inspect).
    pub prepared: bool,
    /// The authority is loaded for live inspection in this process.
    pub loaded: bool,
    /// Saved settings select HTTPS Inspect.
    pub inspection_enabled: bool,
    /// The running proxy inspects compatible hosts in the configured scope right now.
    pub inspection_active: bool,
    /// User acknowledgement that clients were prepared; not verified client trust.
    pub client_trust_declared: bool,
    /// HomeProxy added its root to this computer's current-user store (Windows desktop only).
    pub local_trust_installed: bool,
    pub sha256_fingerprint: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ListenerService {
    Http,
    Socks5,
    Dns,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ListenerBindReason {
    InUse,
    AccessDenied,
    AddressUnavailable,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenerBindFailure {
    pub service: ListenerService,
    pub endpoint: String,
    pub reason: ListenerBindReason,
}

pub struct Engine {
    maintenance_cancellation: CancellationToken,
    install_system_trust: bool,
    /// Headless activation never creates an authority or touches a trust store.
    headless: bool,
    settings_store: SettingsStore,
    history_path: PathBuf,
    cache: CacheStore,
    offline_preparation: OfflinePreparation,
    stats: Arc<Stats>,
    diagnostics: Arc<Diagnostics>,
    tls_inspection: TlsInspection,
    state: Mutex<EngineState>,
}

struct EngineState {
    generation: u64,
    runtime_started_at: Option<u64>,
    settings: Settings,
    proxy: Option<ProxyHandle>,
    last_error: Option<String>,
    listener_error: Option<ListenerBindFailure>,
    tls_inspection_ready: bool,
}

/// Holds the state lock through a whole transition; Drop publishes even error exits.
struct RuntimePublication<'a> {
    state: tokio::sync::MutexGuard<'a, EngineState>,
    diagnostics: &'a Diagnostics,
}
impl<'a> RuntimePublication<'a> {
    fn new(
        mut state: tokio::sync::MutexGuard<'a, EngineState>,
        diagnostics: &'a Diagnostics,
    ) -> Self {
        state.generation = state.generation.wrapping_add(1);
        state.runtime_started_at = None;
        let mut publication =
            diagnostics::RuntimeConfig::new(&state.settings, state.generation, false, None);
        publication.transitioning = true;
        diagnostics.publish(publication);
        diagnostics.set_state(diagnostics::HealthState::Checking);
        Self { state, diagnostics }
    }
}
impl std::ops::Deref for RuntimePublication<'_> {
    type Target = EngineState;
    fn deref(&self) -> &EngineState {
        &self.state
    }
}
impl std::ops::DerefMut for RuntimePublication<'_> {
    fn deref_mut(&mut self) -> &mut EngineState {
        &mut self.state
    }
}
impl Drop for RuntimePublication<'_> {
    fn drop(&mut self) {
        let running = self
            .state
            .proxy
            .as_ref()
            .is_some_and(ProxyHandle::is_running);
        if running {
            self.state.runtime_started_at = Some(diagnostics::epoch_ms());
        }
        self.diagnostics.publish(diagnostics::RuntimeConfig::new(
            &self.state.settings,
            self.state.generation,
            running,
            self.state.runtime_started_at,
        ));
        let status = if !self.state.settings.automatic_recovery {
            diagnostics::HealthState::Disabled
        } else if self.diagnostics.suspended() {
            diagnostics::HealthState::Suspended
        } else if running {
            diagnostics::HealthState::WarmingUp
        } else {
            diagnostics::HealthState::Stopped
        };
        self.diagnostics.set_state(status);
    }
}

/// Capability only: whether this engine kind implements Inspect at all on this platform.
/// The desktop path depends on the Windows current-user installer; isolated engines never
/// install trust. Readiness (a prepared, loaded authority) is checked separately.
fn inspection_capability(headless: bool, install_system_trust: bool) -> bool {
    if headless {
        HEADLESS_INSPECTION_CAPABILITY
    } else {
        cfg!(windows) || !install_system_trust
    }
}

fn install_tls_root_once<E>(
    ready: &mut bool,
    install: impl FnOnce() -> Result<(), E>,
) -> Result<(), E> {
    if *ready {
        return Ok(());
    }
    install()?;
    *ready = true;
    Ok(())
}

impl Engine {
    pub fn diagnostics(&self) -> Arc<Diagnostics> {
        self.diagnostics.clone()
    }

    pub fn new(config_directory: PathBuf, cache_directory: PathBuf) -> Result<Self, EngineError> {
        Self::construct(config_directory, cache_directory, true)
    }

    /// Engine for the unattended Linux service: never installs trust and never creates an
    /// authority implicitly. HTTPS Inspect needs an explicitly prepared authority plus valid
    /// saved acknowledgement and allowlist; otherwise a saved Inspect profile stays stopped.
    pub fn new_headless(
        config_directory: PathBuf,
        cache_directory: PathBuf,
    ) -> Result<Self, EngineError> {
        let mut directory_builder = std::fs::DirBuilder::new();
        directory_builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut directory_builder, 0o700);
        directory_builder.create(&config_directory)?;
        let settings_store = SettingsStore::new(config_directory.join("settings.json"));
        let settings = settings_store.load_or_create()?;
        // Keep control/repair available while malformed saved limits leave the proxy stopped.
        let cache_error = settings
            .validate_cache_controls()
            .err()
            .map(|error| error.to_string());
        let cache = CacheStore::new_with_recovery(
            cache_directory,
            config_directory.join("cache-recovery-v1"),
        );
        if cache_error.is_none() {
            cache.configure_limits(
                settings.cache_limit_bytes(),
                settings.cache_max_object_bytes(),
            );
        }
        let last_error = cache_error
            .or_else(|| {
                settings
                    .validate_web_policies()
                    .err()
                    .map(|error| EngineError::from(error).to_string())
            })
            .or_else(|| {
                (settings.https_mode == HttpsMode::Inspect && !HEADLESS_INSPECTION_CAPABILITY)
                    .then(|| EngineError::InspectionUnsupported.to_string())
            });
        let history_path = config_directory.join("usage-history.json");
        let stats = Arc::new(Stats::default());
        stats.configure_history(history_path.clone(), &settings)?;
        Ok(Self {
            maintenance_cancellation: CancellationToken::new(),
            install_system_trust: false,
            headless: true,
            offline_preparation: OfflinePreparation::new(
                config_directory.join("offline-preparation.json"),
            ),
            settings_store,
            history_path,
            cache,
            diagnostics: Diagnostics::new(
                config_directory.join("diagnostics"),
                stats.clone(),
                &settings,
            ),
            stats,
            tls_inspection: TlsInspection::lazy(config_directory.join(AUTHORITY_RECORD_FILE)),
            state: Mutex::new(EngineState {
                generation: 0,
                runtime_started_at: None,
                settings,
                proxy: None,
                last_error,
                listener_error: None,
                tls_inspection_ready: false,
            }),
        })
    }

    /// Runtime-only stop: closes listeners and clients but keeps the saved `enabled` setting,
    /// so `start_saved` restores the service on the next launch.
    pub async fn shutdown(&self) {
        self.maintenance_cancellation.cancel();
        let mut state = RuntimePublication::new(self.state.lock().await, &self.diagnostics);
        if let Some(handle) = state.proxy.take() {
            handle.stop().await;
        }
        state.listener_error = None;
        drop(state);
        let _ = self.checkpoint_history().await;
    }

    #[cfg(feature = "isolated-test")]
    pub fn new_isolated(
        config_directory: PathBuf,
        cache_directory: PathBuf,
    ) -> Result<Self, EngineError> {
        Self::construct(config_directory, cache_directory, false)
    }

    fn construct(
        config_directory: PathBuf,
        cache_directory: PathBuf,
        install_system_trust: bool,
    ) -> Result<Self, EngineError> {
        let mut directory_builder = std::fs::DirBuilder::new();
        directory_builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut directory_builder, 0o700);
        directory_builder.create(&config_directory)?;
        let settings_store = SettingsStore::new(config_directory.join("settings.json"));
        let settings = settings_store.load_or_create()?;
        // Keep control/repair available while malformed saved limits leave the proxy stopped.
        let cache_error = settings
            .validate_cache_controls()
            .err()
            .map(|error| error.to_string());
        let cache = CacheStore::new_with_recovery(
            cache_directory,
            config_directory.join("cache-recovery-v1"),
        );
        if cache_error.is_none() {
            cache.configure_limits(
                settings.cache_limit_bytes(),
                settings.cache_max_object_bytes(),
            );
        }
        // Validate the complete saved configuration before creating an authority or touching
        // trust. Malformed saved Inspect profiles stay available for repair through the UI.
        let configuration_error = cache_error.or_else(|| {
            settings
                .validate(&available_lan_addresses())
                .err()
                .map(|error| error.to_string())
        });
        let tls_inspection = TlsInspection::lazy(config_directory.join(AUTHORITY_RECORD_FILE));
        let activation_error =
            if configuration_error.is_none() && settings.https_mode == HttpsMode::Inspect {
                if inspection_capability(false, install_system_trust) {
                    tls_inspection
                        .activate(true)
                        .err()
                        .map(|error| error.to_string())
                } else {
                    Some(EngineError::InspectionUnsupported.to_string())
                }
            } else {
                None
            };
        let trust_result = if configuration_error.is_none()
            && activation_error.is_none()
            && install_system_trust
            && settings.https_mode == HttpsMode::Inspect
        {
            tls_inspection.install_current_user_root()
        } else {
            Ok(())
        };
        let tls_inspection_ready = configuration_error.is_none()
            && activation_error.is_none()
            && install_system_trust
            && settings.https_mode == HttpsMode::Inspect
            && trust_result.is_ok();
        let last_error = configuration_error
            .or(activation_error)
            .or_else(|| trust_result.err().map(|error| error.to_string()));
        let history_path = config_directory.join("usage-history.json");
        let stats = Arc::new(Stats::default());
        stats.configure_history(history_path.clone(), &settings)?;
        Ok(Self {
            maintenance_cancellation: CancellationToken::new(),
            install_system_trust,
            headless: false,
            offline_preparation: OfflinePreparation::new(
                config_directory.join("offline-preparation.json"),
            ),
            settings_store,
            history_path,
            cache,
            diagnostics: Diagnostics::new(
                config_directory.join("diagnostics"),
                stats.clone(),
                &settings,
            ),
            stats,
            tls_inspection,
            state: Mutex::new(EngineState {
                generation: 0,
                runtime_started_at: None,
                settings,
                proxy: None,
                last_error,
                listener_error: None,
                tls_inspection_ready,
            }),
        })
    }

    pub async fn start_saved(&self) -> Result<(), EngineError> {
        self.restore_saved(None).await
    }

    async fn restore_saved(
        &self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), EngineError> {
        let _ = self.cache.maintain().await;
        let state = self.state.lock().await;
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Ok(());
        }
        // Explicit start_saved(None) preserves the existing runtime restore API.
        // Background retry supplies its token and checks it above under this lock.
        if self.diagnostics.suspended()
            || !state.settings.enabled
            || state.proxy.as_ref().is_some_and(ProxyHandle::is_running)
        {
            return Ok(());
        }
        let mut state = RuntimePublication::new(state, &self.diagnostics);
        let available = available_lan_addresses();
        if let Err(error) = state.settings.validate(&available) {
            let error = EngineError::from(error);
            state.last_error = Some(error.to_string());
            return Err(error);
        }
        // Only a valid saved Inspect profile (acknowledgement, allowlist) loads the authority.
        let https_mode = state.settings.https_mode;
        self.ensure_tls_inspection_ready(&mut state, https_mode)?;
        match start_proxy(
            state.settings.clone(),
            self.cache.clone(),
            self.stats.clone(),
            self.tls_inspection.clone(),
        )
        .await
        {
            Ok(handle) => {
                state.proxy = Some(handle);
                state.last_error = None;
                state.listener_error = None;
                Ok(())
            }
            Err(error) => {
                state.listener_error = error.listener_bind_failure();
                let error = EngineError::from(error);
                state.last_error = Some(error.to_string());
                Err(error)
            }
        }
    }

    pub async fn start(&self) -> Result<(), EngineError> {
        let mut state = RuntimePublication::new(self.state.lock().await, &self.diagnostics);
        if state.proxy.as_ref().is_some_and(ProxyHandle::is_running) {
            self.diagnostics.clear_suspension();
            return Ok(());
        }
        let available = available_lan_addresses();
        state.settings.validate(&available)?;
        let https_mode = state.settings.https_mode;
        self.ensure_tls_inspection_ready(&mut state, https_mode)?;
        let handle = match start_proxy(
            state.settings.clone(),
            self.cache.clone(),
            self.stats.clone(),
            self.tls_inspection.clone(),
        )
        .await
        {
            Ok(handle) => handle,
            Err(error) => {
                state.listener_error = error.listener_bind_failure();
                let error = EngineError::from(error);
                state.last_error = Some(error.to_string());
                return Err(error);
            }
        };
        let mut updated = state.settings.clone();
        updated.enabled = true;
        if let Err(error) = self.settings_store.save(&updated) {
            handle.stop().await;
            let error = EngineError::from(error);
            state.last_error = Some(error.to_string());
            return Err(error);
        }
        self.cache.configure_limits(
            updated.cache_limit_bytes(),
            updated.cache_max_object_bytes(),
        );
        state.settings = updated;
        state.proxy = Some(handle);
        state.last_error = None;
        state.listener_error = None;
        self.diagnostics.clear_suspension();
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), EngineError> {
        let mut state = RuntimePublication::new(self.state.lock().await, &self.diagnostics);
        let mut updated = state.settings.clone();
        updated.enabled = false;
        // Stopping live traffic must not depend on configuration storage being writable.
        if let Some(handle) = state.proxy.take() {
            handle.stop().await;
        }
        state.settings = updated;
        // The retired listener set has no current accept failure. Keep the
        // cumulative counter for diagnosis, including when saving Stop fails.
        self.stats.listener_recovered();
        state.listener_error = None;
        if let Err(error) = self.settings_store.save(&state.settings) {
            let error = EngineError::StopPersistence(error);
            state.last_error = Some(error.to_string());
            return Err(error);
        }
        state.last_error = None;
        drop(state);
        self.checkpoint_history().await?;
        Ok(())
    }

    pub async fn apply_settings(&self, mut settings: Settings) -> Result<(), EngineError> {
        let available = available_lan_addresses();
        let mut state = RuntimePublication::new(self.state.lock().await, &self.diagnostics);
        settings.enabled = state.settings.enabled;
        settings.validate(&available)?;
        if self.headless {
            // A stopped headless profile also requires a prepared authority before saving Inspect.
            self.ensure_tls_inspection_ready(&mut state, settings.https_mode)?;
        }
        let previous = state.settings.clone();
        let mut cache_only = previous.clone();
        cache_only.cache_enabled = settings.cache_enabled;
        cache_only.automatic_recovery = settings.automatic_recovery;
        if cache_only == settings {
            self.settings_store.save(&settings)?;
            if let Some(handle) = &state.proxy {
                handle.set_cache_enabled(settings.cache_enabled);
            }
            state.settings = settings;
            state.last_error = None;
            self.diagnostics.clear_suspension();
            return Ok(());
        }
        let currently_running = state.proxy.as_ref().is_some_and(ProxyHandle::is_running);
        if currently_running {
            self.ensure_tls_inspection_ready(&mut state, settings.https_mode)?;
        }
        let previous_handle = state.proxy.take();
        let was_running = previous_handle
            .as_ref()
            .is_some_and(ProxyHandle::is_running);
        if let Some(handle) = previous_handle {
            handle.stop().await;
        }

        if let Err(error) = self.stage_history_settings(&previous, &settings) {
            return Err(self
                .restore_previous_after_failure(&mut state, previous, was_running, error.into())
                .await);
        }

        let next_handle = if was_running {
            match start_proxy(
                settings.clone(),
                self.cache.clone(),
                self.stats.clone(),
                self.tls_inspection.clone(),
            )
            .await
            {
                Ok(handle) => Some(handle),
                Err(error) => {
                    let error = self
                        .restore_previous_after_failure(
                            &mut state,
                            previous,
                            was_running,
                            error.into(),
                        )
                        .await;
                    return Err(error);
                }
            }
        } else {
            None
        };

        if let Err(error) = self.settings_store.save(&settings) {
            if let Some(handle) = next_handle {
                handle.stop().await;
            }
            let error = self
                .restore_previous_after_failure(&mut state, previous, was_running, error.into())
                .await;
            return Err(error);
        }
        self.stats.commit_history_settings(&settings);
        self.cache.configure_limits(
            settings.cache_limit_bytes(),
            settings.cache_max_object_bytes(),
        );
        // Failures remain visible in the cache overview and retry at the next access.
        let _ = self.cache.maintain().await;
        state.settings = settings;
        state.proxy = next_handle;
        state.last_error = None;
        state.listener_error = None;
        self.diagnostics.clear_suspension();
        Ok(())
    }

    pub async fn configure_lan_and_start(
        &self,
        mut settings: Settings,
        listen_ip: String,
        cache_enabled: bool,
    ) -> Result<(), EngineError> {
        let available = available_lan_addresses();
        let mut state = RuntimePublication::new(self.state.lock().await, &self.diagnostics);
        let previous = state.settings.clone();
        settings.enabled = true;
        settings.lan_enabled = true;
        settings.listen_ip = Some(listen_ip.clone());
        if !settings.listen_ips.contains(&listen_ip) {
            settings.listen_ips = vec![listen_ip];
        }
        settings.cache_enabled = cache_enabled;
        settings.validate(&available)?;
        self.ensure_tls_inspection_ready(&mut state, settings.https_mode)?;

        let previous_handle = state.proxy.take();
        let was_running = previous_handle
            .as_ref()
            .is_some_and(ProxyHandle::is_running);
        if let Some(handle) = previous_handle {
            handle.stop().await;
        }

        if let Err(error) = self.stage_history_settings(&previous, &settings) {
            return Err(self
                .restore_previous_after_failure(&mut state, previous, was_running, error.into())
                .await);
        }

        let next_handle = match start_proxy(
            settings.clone(),
            self.cache.clone(),
            self.stats.clone(),
            self.tls_inspection.clone(),
        )
        .await
        {
            Ok(handle) => handle,
            Err(error) => {
                let error = self
                    .restore_previous_after_failure(&mut state, previous, was_running, error.into())
                    .await;
                return Err(error);
            }
        };

        if let Err(error) = self.settings_store.save(&settings) {
            next_handle.stop().await;
            let error = self
                .restore_previous_after_failure(&mut state, previous, was_running, error.into())
                .await;
            return Err(error);
        }

        self.stats.commit_history_settings(&settings);

        self.cache.configure_limits(
            settings.cache_limit_bytes(),
            settings.cache_max_object_bytes(),
        );
        let _ = self.cache.maintain().await;
        state.settings = settings;
        state.proxy = Some(next_handle);
        state.last_error = None;
        state.listener_error = None;
        self.diagnostics.clear_suspension();
        Ok(())
    }

    fn stage_history_settings(
        &self,
        _previous: &Settings,
        candidate: &Settings,
    ) -> Result<(), HistoryError> {
        let mut staged = candidate.clone();
        // New connections use the prospective policy, while historical data keeps the
        // committed retention until configuration publication succeeds.
        staged.history_retention_days = self.stats.history_retention_days().unwrap_or(366);
        self.stats
            .configure_history(self.history_path.clone(), &staged)
    }

    async fn restore_previous_after_failure(
        &self,
        state: &mut EngineState,
        previous: Settings,
        was_running: bool,
        primary: EngineError,
    ) -> EngineError {
        let listener_error = primary.listener_bind_failure();
        state.settings = previous.clone();
        state.proxy = None;
        let mut restored_history_settings = previous.clone();
        restored_history_settings.history_retention_days =
            self.stats.history_retention_days().unwrap_or(366);
        if let Err(rollback) = self
            .stats
            .configure_history(self.history_path.clone(), &restored_history_settings)
        {
            let error = EngineError::Transition {
                primary: primary.to_string(),
                rollback: rollback.to_string(),
            };
            state.last_error = Some(error.to_string());
            state.listener_error = listener_error;
            return error;
        }
        if was_running {
            match start_proxy(
                previous,
                self.cache.clone(),
                self.stats.clone(),
                self.tls_inspection.clone(),
            )
            .await
            {
                Ok(handle) => {
                    state.proxy = Some(handle);
                    // The rejected action is returned to its caller; the restored
                    // running service is healthy and has no current bind failure.
                    state.last_error = None;
                    state.listener_error = None;
                    return primary;
                }
                Err(rollback) => {
                    let error = EngineError::Transition {
                        primary: primary.to_string(),
                        rollback: rollback.to_string(),
                    };
                    state.last_error = Some(error.to_string());
                    state.listener_error = listener_error;
                    return error;
                }
            }
        }
        state.last_error = Some(primary.to_string());
        state.listener_error = listener_error;
        primary
    }

    pub async fn rotate_proxy_password(&self) -> Result<(), EngineError> {
        let mut settings = self.state.lock().await.settings.clone();
        settings.proxy_password = Settings::default().proxy_password;
        self.apply_settings(settings).await
    }

    pub async fn set_device_allowed(&self, ip: String, allowed: bool) -> Result<(), EngineError> {
        let ip = ip
            .parse::<Ipv4Addr>()
            .map_err(|_| ConfigError::Invalid("Adresa zařízení není platná IPv4."))?;
        if !config::is_private_lan_ip(ip) {
            return Err(ConfigError::Invalid(
                "Povolit nebo zakázat lze jen zařízení v privátní domácí síti.",
            )
            .into());
        }
        if available_lan_addresses()
            .iter()
            .any(|address| address.ip == ip)
        {
            return Err(ConfigError::Invalid("Adresu tohoto počítače nelze zakázat.").into());
        }

        let mut settings = self.state.lock().await.settings.clone();
        settings.denied_client_ips.retain(|denied| *denied != ip);
        if !allowed {
            settings.denied_client_ips.push(ip);
            settings.denied_client_ips.sort_unstable();
            settings.denied_client_ips.dedup();
        }
        self.apply_settings(settings).await
    }

    pub async fn prepare_offline(
        &self,
        request: OfflinePreparationRequest,
    ) -> Result<String, EngineError> {
        let state = self.state.lock().await;
        let handle = state
            .proxy
            .as_ref()
            .filter(|handle| handle.is_running())
            .ok_or_else(|| OfflinePreparationError {
                code: "proxy-stopped".into(),
            })?;
        Ok(self
            .offline_preparation
            .queue(request, handle.prefetch_executor(), self.cache.clone())
            .await?)
    }

    pub async fn cancel_offline_preparation(&self, id: &str) -> Result<(), EngineError> {
        Ok(self.offline_preparation.cancel(id).await?)
    }

    pub async fn release_offline_pin(&self, key: &str) -> Result<(), EngineError> {
        self.cache.unpin(key).await?;
        Ok(())
    }

    pub async fn offline_preparation_status(&self) -> OfflinePreparationStatus {
        self.snapshot().await.offline_preparation
    }

    pub async fn clear_cache(&self) -> Result<(), EngineError> {
        let _state = self.state.lock().await;
        self.offline_preparation.clear().await?;
        self.cache.clear().await?;
        Ok(())
    }

    pub async fn snapshot(&self) -> AppSnapshot {
        let state = self.state.lock().await;
        let running = state.proxy.as_ref().is_some_and(ProxyHandle::is_running);
        let mut proxy_addresses = Vec::new();
        let mut socks5_addresses = Vec::new();
        if running {
            proxy_addresses.push(format!("127.0.0.1:{}", state.settings.proxy_port));
            if state.settings.lan_enabled {
                for ip in state.settings.selected_listen_ips().unwrap_or_default() {
                    proxy_addresses.push(format!("{ip}:{}", state.settings.proxy_port));
                }
            }
            if state.settings.socks5_enabled {
                socks5_addresses.push(format!("127.0.0.1:{}", state.settings.socks5_port));
                if state.settings.lan_enabled {
                    for ip in state.settings.selected_listen_ips().unwrap_or_default() {
                        socks5_addresses.push(format!("{ip}:{}", state.settings.socks5_port));
                    }
                }
            }
        }
        let mut snapshot = AppSnapshot {
            running,
            settings: state.settings.clone(),
            stats: self.stats.snapshot(),
            cache: CacheUsage::default(),
            offline_preparation: OfflinePreparationStatus::default(),
            available_addresses: available_lan_addresses(),
            proxy_addresses,
            socks5_addresses,
            last_error: state
                .last_error
                .clone()
                .or_else(|| state.proxy.as_ref().and_then(ProxyHandle::runtime_error)),
            listener_error: state.listener_error.clone(),
            tls_inspection_ready: state.settings.https_mode == HttpsMode::Inspect
                && state.tls_inspection_ready,
            https_authority: self.https_authority_status(&state, running),
            quota_statuses: self.stats.quota_statuses(),
        };
        drop(state);
        snapshot.cache = self.cache.usage().await;
        snapshot.offline_preparation = self
            .offline_preparation
            .status(&self.cache, &snapshot.settings)
            .await;
        if !running {
            for job in &mut snapshot.offline_preparation.jobs {
                for item in &mut job.items {
                    item.offline_ready = false;
                }
            }
            for pin in &mut snapshot.offline_preparation.pins {
                pin.offline_ready = false;
            }
        }
        snapshot
    }

    pub fn clear_activity(&self) {
        self.stats.clear_activity();
    }

    pub fn reset_transfer_stats(&self) -> StatsSnapshot {
        self.stats.reset_transfer_stats();
        self.stats.snapshot()
    }

    pub fn usage_history(&self) -> Option<HistoryReport> {
        self.stats.history_report()
    }

    pub fn quota_statuses(&self) -> Vec<QuotaStatus> {
        self.stats.quota_statuses()
    }

    pub fn usage_history_summary(&self, limit: usize) -> serde_json::Value {
        summarize_usage_history(self.usage_history(), limit)
    }

    pub async fn import_filter_feed(&self, feed: FilterFeed) -> Result<(), EngineError> {
        let mut settings = self.snapshot().await.settings;
        if let Some(existing) = settings
            .filter_feeds
            .iter_mut()
            .find(|existing| existing.id == feed.id)
        {
            *existing = feed;
        } else {
            settings.filter_feeds.push(feed);
        }
        self.apply_settings(settings).await
    }

    pub async fn remove_filter_feed(&self, id: &str) -> Result<(), EngineError> {
        let mut settings = self.snapshot().await.settings;
        let before = settings.filter_feeds.len();
        settings.filter_feeds.retain(|feed| feed.id != id);
        if before == settings.filter_feeds.len() {
            return Err(ConfigError::Invalid("Importovaný filtr nebyl nalezen.").into());
        }
        self.apply_settings(settings).await
    }

    pub fn export_usage_history(&self, csv: bool) -> Result<String, EngineError> {
        Ok(if csv {
            self.stats.history_csv()?
        } else {
            self.stats.history_json()?
        })
    }

    pub async fn checkpoint_history(&self) -> Result<(), EngineError> {
        let stats = self.stats.clone();
        tokio::task::spawn_blocking(move || stats.checkpoint_history())
            .await
            .map_err(|error| EngineError::Cache(std::io::Error::other(error.to_string())))??;
        Ok(())
    }

    pub async fn run_periodic_history_checkpoints(&self) {
        let mut checkpoint = tokio::time::interval(std::time::Duration::from_secs(60));
        checkpoint.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            checkpoint.tick().await;
            if let Err(error) = self.checkpoint_history().await {
                eprintln!("HomeProxy history checkpoint failed: {error}");
            }
        }
    }

    /// Embedded desktops have the same saved-state retry as the Linux daemon.
    /// Healthy listeners are left intact; explicit Stop remains persisted disabled.
    pub async fn run_periodic_maintenance(&self) {
        let mut retry = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut checkpoint = tokio::time::interval(std::time::Duration::from_secs(60));
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        checkpoint.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = self.maintenance_cancellation.cancelled() => break,
                _ = retry.tick() => {
                    // The cancellation is checked again under the state lock so
                    // a queued retry cannot reopen listeners after shutdown.
                    let _ = self.restore_saved(Some(&self.maintenance_cancellation)).await;
                }
                _ = checkpoint.tick() => {
                    if let Err(error) = self.checkpoint_history().await {
                        eprintln!("HomeProxy history checkpoint failed: {error}");
                    }
                }
            }
        }
    }

    /// Whether this engine implements HTTPS Inspect at all; see [`HttpsAuthorityStatus`].
    pub fn https_inspection_capability(&self) -> bool {
        inspection_capability(self.headless, self.install_system_trust)
    }

    pub async fn https_authority(&self) -> HttpsAuthorityStatus {
        let state = self.state.lock().await;
        let running = state.proxy.as_ref().is_some_and(ProxyHandle::is_running);
        self.https_authority_status(&state, running)
    }

    /// Explicitly creates (or validates) the private authority. It neither switches settings
    /// to Inspect, nor installs or claims trust anywhere.
    pub async fn prepare_https_authority(&self) -> Result<HttpsAuthorityStatus, EngineError> {
        let state = self.state.lock().await;
        if !self.https_inspection_capability() {
            return Err(EngineError::InspectionUnsupported);
        }
        self.tls_inspection.prepare()?;
        let running = state.proxy.as_ref().is_some_and(ProxyHandle::is_running);
        Ok(self.https_authority_status(&state, running))
    }

    /// Public certificate and fingerprint of a prepared authority. Never creates one and
    /// never includes private key material.
    pub async fn export_https_certificate(
        &self,
        format: CertificateFormat,
    ) -> Result<ExportedCertificate, EngineError> {
        let _state = self.state.lock().await;
        Ok(self.tls_inspection.export_certificate(format)?)
    }

    fn https_authority_status(&self, state: &EngineState, running: bool) -> HttpsAuthorityStatus {
        let authority = self.tls_inspection.authority_state();
        let inspection_enabled = state.settings.https_mode == HttpsMode::Inspect;
        HttpsAuthorityStatus {
            capability: self.https_inspection_capability(),
            prepared: authority.prepared,
            loaded: authority.active,
            inspection_enabled,
            inspection_active: running && inspection_enabled && authority.active,
            client_trust_declared: state.settings.https_client_trust_acknowledged,
            local_trust_installed: self.install_system_trust
                && !self.headless
                && state.tls_inspection_ready,
            sha256_fingerprint: authority.sha256_fingerprint,
            error: authority.error,
        }
    }

    fn ensure_tls_inspection_ready(
        &self,
        state: &mut EngineState,
        mode: HttpsMode,
    ) -> Result<(), EngineError> {
        if mode == HttpsMode::Tunnel {
            return Ok(());
        }
        if !self.https_inspection_capability() {
            let error = EngineError::InspectionUnsupported;
            state.last_error = Some(error.to_string());
            return Err(error);
        }
        // Headless readiness is the explicitly prepared authority only; nothing is created
        // here and no trust store is touched. The desktop keeps creating it on Inspect.
        if let Err(error) = self.tls_inspection.activate(!self.headless) {
            state.tls_inspection_ready = false;
            let error = EngineError::Tls(error);
            state.last_error = Some(error.to_string());
            return Err(error);
        }
        if self.headless {
            state.tls_inspection_ready = true;
            return Ok(());
        }
        if !self.install_system_trust {
            return Ok(());
        }
        match install_tls_root_once(&mut state.tls_inspection_ready, || {
            self.tls_inspection.install_current_user_root()
        }) {
            Ok(()) => Ok(()),
            Err(error) => {
                state.tls_inspection_ready = false;
                let error = EngineError::Tls(error);
                state.last_error = Some(error.to_string());
                Err(error)
            }
        }
    }

    pub fn settings_path(&self) -> &std::path::Path {
        self.settings_store.path()
    }

    pub fn cache_path(&self) -> &std::path::Path {
        self.cache.root()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSnapshot {
    pub running: bool,
    pub settings: Settings,
    pub stats: StatsSnapshot,
    pub cache: CacheUsage,
    pub offline_preparation: OfflinePreparationStatus,
    pub available_addresses: Vec<LanAddress>,
    pub proxy_addresses: Vec<String>,
    pub socks5_addresses: Vec<String>,
    pub last_error: Option<String>,
    pub listener_error: Option<ListenerBindFailure>,
    pub tls_inspection_ready: bool,
    pub https_authority: HttpsAuthorityStatus,
    pub quota_statuses: Vec<QuotaStatus>,
}

pub fn summarize_usage_history(report: Option<HistoryReport>, limit: usize) -> serde_json::Value {
    let limit = limit.clamp(1, 512);
    let Some(mut report) = report else {
        return serde_json::Value::Null;
    };
    let row_count = report.rows.len();
    let month_count = report.months.len();
    let debt_count = report.quota_debts.len();
    let credit_count = report.quota_credits.len();
    let quota_debt_bytes = report
        .quota_debts
        .iter()
        .fold(0u64, |sum, debt| sum.saturating_add(debt.bytes));
    let mut upload = 0u64;
    let mut download = 0u64;
    let mut saved = 0u64;
    let mut requests = 0u64;
    for row in &report.rows {
        upload = upload.saturating_add(row.counters.upload_bytes);
        download = download.saturating_add(row.counters.download_bytes);
        saved = saved.saturating_add(row.counters.saved_bytes);
        requests = requests.saturating_add(row.counters.requests);
    }
    report.rows.sort_by_key(|row| std::cmp::Reverse(row.day));
    report.rows.truncate(limit);
    report
        .months
        .sort_by_key(|row| std::cmp::Reverse((row.year, row.month)));
    report.months.truncate(limit);
    report
        .quota_debts
        .sort_by_key(|debt| std::cmp::Reverse(debt.day));
    report.quota_debts.truncate(limit);
    report
        .quota_credits
        .sort_by_key(|credit| std::cmp::Reverse(credit.day));
    report.quota_credits.truncate(limit);
    serde_json::json!({"healthy":report.healthy,"error":report.error,"retentionDays":report.retention_days,
        "rowCount":row_count,"monthCount":month_count,"quotaDebtCount":debt_count,
        "quotaCreditCount":credit_count,
        "truncated":row_count > limit || month_count > limit || debt_count > limit || credit_count > limit,
        "rows":report.rows,"months":report.months,"quotaDebts":report.quota_debts,"quotaCredits":report.quota_credits,
        "totals":{"uploadBytes":upload,"downloadBytes":download,"savedBytes":saved,"requests":requests,"quotaDebtBytes":quota_debt_bytes}})
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("{0}")]
    OfflinePreparation(#[from] OfflinePreparationError),
    #[error("Historie provozu není dostupná: {0}")]
    History(#[from] HistoryError),
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("{0}")]
    Proxy(#[from] proxy::ProxyError),
    #[error("Proxy je zastavená, ale vypnutý stav se nepodařilo uložit. Při příštím spuštění aplikace se může znovu zapnout.")]
    StopPersistence(#[source] ConfigError),
    #[error(
        "HTTPS Inspect není v této instalaci HomeProxy podporován. Přepněte režim HTTPS na Tunnel."
    )]
    InspectionUnsupported,
    #[error("Cache nelze změnit: {0}")]
    Cache(#[from] std::io::Error),
    #[error("{0}")]
    Tls(#[from] tls_inspection::TlsInspectionError),
    #[error("{primary} Obnovení předchozího stavu selhalo: {rollback}")]
    Transition { primary: String, rollback: String },
}

impl EngineError {
    /// Structured listener failure for clients that localize actionable errors.
    pub fn listener_bind_failure(&self) -> Option<ListenerBindFailure> {
        match self {
            Self::Proxy(error) => error.listener_bind_failure(),
            Self::History(_)
            | Self::OfflinePreparation(_)
            | Self::Config(_)
            | Self::StopPersistence(_)
            | Self::InspectionUnsupported
            | Self::Cache(_)
            | Self::Tls(_)
            | Self::Transition { .. } => None,
        }
    }
}

#[cfg(test)]
mod engine_tests {
    use super::*;
    use std::cell::Cell;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{timeout, Duration},
    };

    #[tokio::test]
    async fn transfer_reset_returns_stats_without_changing_engine_or_persisted_settings() {
        let directory = tempfile::tempdir().unwrap();
        let engine = headless_engine(directory.path());
        let before = engine.snapshot().await;
        let file = std::fs::read(engine.settings_path()).unwrap();
        let peer = std::net::IpAddr::V4(Ipv4Addr::LOCALHOST);
        let id = engine.stats.begin_activity(peer, peer);
        engine.stats.traffic(peer, id, 100, 200);
        let stats = engine.reset_transfer_stats();
        assert_eq!((stats.upload_bytes, stats.download_bytes), (0, 0));
        assert!(stats.transfer_stats_reset_unix_ms.is_some());
        assert_eq!(stats.activity[0].upload_bytes, 100);
        let after = engine.snapshot().await;
        assert_eq!(after.settings, before.settings);
        assert_eq!(after.running, before.running);
        assert_eq!(after.last_error, before.last_error);
        assert_eq!(std::fs::read(engine.settings_path()).unwrap(), file);
    }

    #[tokio::test]
    async fn failed_settings_save_preserves_recovery_suspension_and_blocks_saved_retry() {
        let directory = tempfile::tempdir().unwrap();
        let config = private_config(directory.path());
        let settings = Settings {
            enabled: true,
            proxy_port: unused_loopback_port().await,
            ..Settings::default()
        };
        SettingsStore::new(config.join("settings.json"))
            .save(&settings)
            .unwrap();
        let engine = headless_engine(directory.path());
        engine.diagnostics.suspend().await;
        let mut candidate = settings.clone();
        candidate.cache_enabled = !candidate.cache_enabled;
        std::fs::rename(config.join("settings.json"), config.join("settings.saved")).unwrap();
        std::fs::create_dir(config.join("settings.json")).unwrap();
        assert!(engine.apply_settings(candidate).await.is_err());
        assert!(
            engine.diagnostics.suspended(),
            "Failed settings changes must preserve the safety latch"
        );
        assert_eq!(engine.snapshot().await.settings, settings);
        let retry = CancellationToken::new();
        engine.restore_saved(Some(&retry)).await.unwrap();
        assert!(!engine.snapshot().await.running);
    }

    #[tokio::test]
    async fn failed_manual_start_preserves_recovery_suspension_after_port_becomes_free() {
        let directory = tempfile::tempdir().unwrap();
        let config = private_config(directory.path());
        let blocker = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let settings = Settings {
            enabled: true,
            proxy_port: blocker.local_addr().unwrap().port(),
            ..Settings::default()
        };
        SettingsStore::new(config.join("settings.json"))
            .save(&settings)
            .unwrap();
        let engine = headless_engine(directory.path());
        engine.diagnostics.suspend().await;
        assert!(engine.start().await.is_err());
        assert!(
            engine.diagnostics.suspended(),
            "Failed manual Start must preserve the safety latch"
        );
        drop(blocker);
        let retry = CancellationToken::new();
        engine.restore_saved(Some(&retry)).await.unwrap();
        assert!(!engine.snapshot().await.running);
    }

    #[tokio::test]
    async fn invalid_saved_retention_is_repairable_without_poisoning_or_erasing_history() {
        for corrupted in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let config = private_config(directory.path());
            let mut settings = Settings {
                enabled: false,
                history_retention_days: 0,
                ..Default::default()
            };
            settings.device_profiles.push(
                serde_json::from_value(serde_json::json!({
                    "id":"repair", "name":"Repair fixture", "username":"fixture-repair",
                    "password":"fixture-password-16", "dailyQuotaMib":1, "monthlyQuotaMib":1
                }))
                .unwrap(),
            );
            SettingsStore::new(config.join("settings.json"))
                .save(&settings)
                .unwrap();
            let now = time::OffsetDateTime::now_utc();
            let counters = serde_json::json!({
                "uploadBytes":0,"downloadBytes":100,"savedBytes":0,"requests":1
            });
            let original = if corrupted {
                b"{invalid history".to_vec()
            } else {
                serde_json::to_vec(&serde_json::json!({"version":1,
                    "rows":[{"identity":"profile:repair","day":now.unix_timestamp().div_euclid(86_400),"counters":counters}],
                    "months":[{"identity":"profile:repair","year":now.year(),"month":u8::from(now.month()),"counters":counters}]}))
                    .unwrap()
            };
            let history_path = config.join("usage-history.json");
            std::fs::write(&history_path, &original).unwrap();
            let engine = headless_engine(directory.path());
            let snapshot = engine.snapshot().await;
            assert!(!snapshot.running);
            assert!(snapshot.last_error.is_some());
            assert_eq!(engine.usage_history().unwrap().healthy, !corrupted);
            assert_eq!(engine.stats.history_retention_days(), Some(366));
            let mut repaired = snapshot.settings;
            repaired.history_retention_days = 90;
            if !corrupted {
                // Failure before publication restores the actual retained-history
                // setting, rather than reintroducing the invalid saved zero.
                let backup = engine.settings_path().with_extension("saved");
                std::fs::rename(engine.settings_path(), &backup).unwrap();
                std::fs::create_dir(engine.settings_path()).unwrap();
                assert!(engine.apply_settings(repaired.clone()).await.is_err());
                assert_eq!(engine.snapshot().await.settings.history_retention_days, 0);
                assert_eq!(engine.stats.history_retention_days(), Some(366));
                assert!(engine.usage_history().unwrap().healthy);
                std::fs::remove_dir(engine.settings_path()).unwrap();
                std::fs::rename(backup, engine.settings_path()).unwrap();
            }
            engine.apply_settings(repaired).await.unwrap();
            assert!(engine.snapshot().await.last_error.is_none());
            assert_eq!(engine.stats.history_retention_days(), Some(90));
            engine
                .stats
                .bind_principal(
                    991,
                    std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
                    Some("fixture-repair"),
                )
                .unwrap();
            let decision = engine.stats.policy_decision(991, "example.org");
            if corrupted {
                assert!(!decision.allowed);
                assert_eq!(decision.reason, policy::PolicyReason::HistoryUnavailable);
                assert!(!engine.usage_history().unwrap().healthy);
                assert!(engine.stats.checkpoint_history().is_err());
                assert_eq!(std::fs::read(&history_path).unwrap(), original);
            } else {
                assert!(decision.allowed);
                let report = engine.usage_history().unwrap();
                assert!(report.healthy);
                let row = report
                    .rows
                    .iter()
                    .find(|row| row.identity == "profile:repair")
                    .unwrap();
                assert_eq!(row.counters.download_bytes, 100);
                assert_eq!(engine.stats.quota_statuses()[0].daily_bytes, 100);
            }
        }
    }

    #[tokio::test]
    async fn prospective_retention_preserves_history_during_transfer_and_failed_publication() {
        let directory = tempfile::tempdir().unwrap();
        let config = private_config(directory.path());
        let old = time::OffsetDateTime::now_utc() - time::Duration::days(10);
        let old_day = old.unix_timestamp().div_euclid(86_400);
        let counters =
            serde_json::json!({"uploadBytes":0,"downloadBytes":100,"savedBytes":0,"requests":1});
        let path = config.join("usage-history.json");
        std::fs::write(&path,serde_json::to_vec(&serde_json::json!({"version":1,
            "rows":[{"identity":"ip:127.0.0.1","day":old_day,"counters":counters}],
            "months":[{"identity":"ip:127.0.0.1","year":old.year(),"month":u8::from(old.month()),"counters":counters}]})).unwrap()).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let engine = headless_engine(directory.path());
        let previous = engine.snapshot().await.settings;
        let mut candidate = previous.clone();
        candidate.history_retention_days = 1;
        engine
            .stage_history_settings(&previous, &candidate)
            .unwrap();
        let peer = std::net::IpAddr::V4(Ipv4Addr::LOCALHOST);
        engine.stats.bind_principal(7, peer, None).unwrap();
        // Forces the record/prune interleaving that can happen while a new listener is
        // live and configuration publication has not finished yet.
        engine.stats.traffic(peer, 7, 0, 20);
        assert_eq!(engine.usage_history().unwrap().retention_days, 90);
        assert!(engine
            .usage_history()
            .unwrap()
            .rows
            .iter()
            .any(|row| row.day == old_day));
        let settings_path = engine.settings_path();
        let backup = settings_path.with_extension("saved");
        std::fs::rename(settings_path, &backup).unwrap();
        std::fs::create_dir(settings_path).unwrap();
        assert!(engine.apply_settings(candidate.clone()).await.is_err());
        assert_eq!(engine.snapshot().await.settings.history_retention_days, 90);
        assert!(engine
            .usage_history()
            .unwrap()
            .rows
            .iter()
            .any(|row| row.day == old_day));
        std::fs::remove_dir(settings_path).unwrap();
        std::fs::rename(backup, settings_path).unwrap();
        engine.apply_settings(candidate).await.unwrap();
        assert_eq!(engine.usage_history().unwrap().retention_days, 1);
        engine.stats.traffic(peer, 7, 0, 20);
        assert!(!engine
            .usage_history()
            .unwrap()
            .rows
            .iter()
            .any(|row| row.day == old_day));
    }

    #[tokio::test]
    async fn embedded_feed_mutation_helpers_validate_and_persist_the_shared_settings_path() {
        let directory = tempfile::tempdir().unwrap();
        let engine = headless_engine(directory.path());
        let feed = FilterFeed::parse("trusted", "||feed.example^").unwrap();
        let id = feed.id.clone();
        engine.import_filter_feed(feed).await.unwrap();
        assert_eq!(saved_settings(&engine).filter_feeds.len(), 1);
        let updated = FilterFeed::parse("trusted", "updated.example").unwrap();
        engine.import_filter_feed(updated.clone()).await.unwrap();
        assert_eq!(saved_settings(&engine).filter_feeds, vec![updated.clone()]);
        let mut invalid = updated.clone();
        invalid.domains_sorted_exact.push("INVALID_DOMAIN".into());
        assert!(engine.import_filter_feed(invalid).await.is_err());
        assert_eq!(saved_settings(&engine).filter_feeds, vec![updated]);
        assert!(engine.remove_filter_feed("missing").await.is_err());
        engine.remove_filter_feed(&id).await.unwrap();
        assert!(saved_settings(&engine).filter_feeds.is_empty());
    }

    #[tokio::test]
    async fn malformed_embedded_inspect_profile_creates_no_authority_and_keeps_repair_available() {
        for broken in 0..3 {
            let directory = tempfile::tempdir().unwrap();
            let config = private_config(directory.path());
            let store = SettingsStore::new(config.join("settings.json"));
            let mut settings = Settings::default();
            allow_inspect(&mut settings);
            match broken {
                0 => settings.https_client_trust_acknowledged = false,
                1 => settings.https_inspect_hosts.clear(),
                _ => settings.proxy_port = 0,
            }
            store.save(&settings).unwrap();
            let original = std::fs::read(store.path()).unwrap();
            // The isolated constructor implements Inspect on Linux but never installs trust.
            let engine = Engine::construct(config, directory.path().join("cache"), false).unwrap();
            let snapshot = engine.snapshot().await;
            assert!(!snapshot.running && !snapshot.tls_inspection_ready);
            assert!(snapshot.last_error.is_some());
            assert!(
                !snapshot.https_authority.prepared
                    && !snapshot.https_authority.local_trust_installed
            );
            assert!(!authority_record(directory.path()).exists());
            assert_eq!(std::fs::read(engine.settings_path()).unwrap(), original);
            let mut repaired = snapshot.settings;
            repaired.https_mode = HttpsMode::Tunnel;
            repaired.proxy_port = unused_loopback_port().await;
            engine.apply_settings(repaired).await.unwrap();
            assert!(engine.snapshot().await.last_error.is_none());
            assert!(!authority_record(directory.path()).exists());
        }
    }

    #[tokio::test]
    async fn invalid_saved_cache_limits_leave_control_available_without_pruning() {
        for invalid_limit in [0, 2000] {
            let directory = tempfile::tempdir().unwrap();
            let config = directory.path().join("config");
            let root = directory.path().join("cache");
            std::fs::create_dir_all(&root).unwrap();
            let existing = root.join("existing.body");
            std::fs::write(&existing, b"preserve").unwrap();
            SettingsStore::new(config.join("settings.json"))
                .save(&Settings {
                    enabled: true,
                    cache_limit_gib: invalid_limit,
                    ..Settings::default()
                })
                .unwrap();
            let engine = Engine::new_headless(config, root).unwrap();
            assert!(engine.start_saved().await.is_err());
            let snapshot = engine.snapshot().await;
            assert!(!snapshot.running);
            assert!(snapshot.last_error.is_some());
            assert!(snapshot.settings.validate(&[]).is_err());
            assert_eq!(std::fs::read(&existing).unwrap(), b"preserve");
            let mut corrected = snapshot.settings;
            corrected.cache_limit_gib = 8;
            corrected.proxy_port = unused_loopback_port().await;
            engine.apply_settings(corrected.clone()).await.unwrap();
            assert_eq!(engine.settings_store.load_or_create().unwrap(), corrected);
            assert!(engine.snapshot().await.last_error.is_none());
            engine.start_saved().await.unwrap();
            assert!(engine.snapshot().await.running);
            engine.shutdown().await;
        }
    }

    #[tokio::test]
    async fn failed_save_or_bind_never_applies_lower_uncommitted_cache_limits() {
        let directory = tempfile::tempdir().unwrap();
        let engine = headless_engine(directory.path());
        let mut original = engine.snapshot().await.settings;
        original.proxy_port = unused_loopback_port().await;
        original.cache_enabled = true;
        engine.apply_settings(original).await.unwrap();
        engine.start().await.unwrap();
        let original = engine.snapshot().await.settings;
        let cache_key = "a".repeat(64);
        engine
            .cache
            .put(
                &cache_key,
                http::StatusCode::OK,
                &http::HeaderMap::new(),
                bytes::Bytes::from(vec![42; 2 * 1024 * 1024]),
                Duration::from_secs(60),
                original.cache_limit_bytes(),
            )
            .await
            .unwrap();
        let root = engine.cache.root();
        for letter in ["b", "c"] {
            let file =
                std::fs::File::create(root.join(format!("{}.body", letter.repeat(64)))).unwrap();
            file.set_len(700 * 1024 * 1024).unwrap();
            std::fs::write(root.join(format!("{}.json", letter.repeat(64))), b"{}").unwrap();
        }
        let before = engine.snapshot().await.cache;
        assert_eq!(before.entry_count, 3);
        assert!(before.used_bytes > 1024 * 1024 * 1024);
        let path = engine.settings_path();
        let backup = path.with_extension("saved");
        std::fs::rename(path, &backup).unwrap();
        std::fs::create_dir(path).unwrap();
        let mut prospective = original.clone();
        prospective.cache_limit_gib = 1;
        prospective.cache_max_object_mib = 1;
        assert!(engine.apply_settings(prospective.clone()).await.is_err());
        assert_eq!(engine.snapshot().await.settings, original);
        assert!(engine.snapshot().await.running);
        assert!(engine.cache.get(&cache_key).await.is_some());
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 6);
        assert_eq!(
            std::fs::metadata(root.join(format!("{}.body", "b".repeat(64))))
                .unwrap()
                .len(),
            700 * 1024 * 1024
        );
        std::fs::remove_dir(path).unwrap();
        std::fs::rename(&backup, path).unwrap();
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        prospective.proxy_port = occupied.local_addr().unwrap().port();
        assert!(engine.apply_settings(prospective).await.is_err());
        assert_eq!(engine.snapshot().await.settings, original);
        assert!(engine.snapshot().await.running);
        assert!(engine.cache.get(&cache_key).await.is_some());
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 6);
        assert_eq!(engine.settings_store.load_or_create().unwrap(), original);
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn prospective_spawn_and_failed_rollback_leave_committed_object_cap_intact() {
        let directory = tempfile::tempdir().unwrap();
        let engine = headless_engine(directory.path());
        let mut original = engine.snapshot().await.settings;
        original.proxy_port = unused_loopback_port().await;
        engine.apply_settings(original).await.unwrap();
        engine.start().await.unwrap();
        let original = engine.snapshot().await.settings;
        let cache_key = "a".repeat(64);
        engine
            .cache
            .put(
                &cache_key,
                http::StatusCode::OK,
                &http::HeaderMap::new(),
                bytes::Bytes::from(vec![42; 2 * 1024 * 1024]),
                Duration::from_secs(60),
                original.cache_limit_bytes(),
            )
            .await
            .unwrap();
        let mut state = engine.state.lock().await;
        state.proxy.take().unwrap().stop().await;
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, original.proxy_port))
            .await
            .unwrap();
        let mut prospective = original.clone();
        prospective.proxy_port = unused_loopback_port().await;
        prospective.cache_limit_gib = 1;
        prospective.cache_max_object_mib = 1;
        let handle = start_proxy(
            prospective,
            engine.cache.clone(),
            engine.stats.clone(),
            engine.tls_inspection.clone(),
        )
        .await
        .unwrap();
        assert!(engine.cache.get(&cache_key).await.is_some());
        handle.stop().await;
        let error = engine
            .restore_previous_after_failure(
                &mut state,
                original.clone(),
                true,
                ConfigError::Invalid("forced persistence failure").into(),
            )
            .await;
        assert!(matches!(error, EngineError::Transition { .. }));
        drop(state);
        assert!(!engine.snapshot().await.running);
        assert_eq!(engine.snapshot().await.settings, original);
        assert!(engine.cache.get(&cache_key).await.is_some());
        assert_eq!(std::fs::read_dir(engine.cache.root()).unwrap().count(), 2);
        drop(occupied);
    }

    #[tokio::test]
    async fn cache_controls_apply_persist_and_prune_on_daemon_reconstruction() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config");
        let root = directory.path().join("cache");
        let engine = Engine::new_headless(config.clone(), root.clone()).unwrap();
        let mut settings = engine.snapshot().await.settings;
        settings.cache_enabled = true;
        settings.cache_limit_gib = 1;
        settings.cache_max_object_mib = 1024;
        settings.response_buffer_limit_mib = 0;
        settings.response_buffer_budget_mib = 0;
        engine.apply_settings(settings.clone()).await.unwrap();
        let key = "a".repeat(64);
        engine
            .cache
            .put(
                &key,
                http::StatusCode::OK,
                &http::HeaderMap::new(),
                bytes::Bytes::from(vec![42; 1024 * 1024 + 1]),
                std::time::Duration::from_secs(60),
                settings.cache_limit_bytes(),
            )
            .await
            .unwrap();
        assert_eq!(engine.snapshot().await.cache.entry_count, 1);
        drop(engine);
        // Seed two sparse, complete file pairs to verify disk pruning without a large
        // allocation or network transfer. Maintenance only needs logical file lengths.
        for letter in ["b", "c"] {
            let file =
                std::fs::File::create(root.join(format!("{}.body", letter.repeat(64)))).unwrap();
            file.set_len(700 * 1024 * 1024).unwrap();
            std::fs::write(root.join(format!("{}.json", letter.repeat(64))), b"{}").unwrap();
        }
        let restarted = Engine::new_headless(config, root).unwrap();
        let snapshot = restarted.snapshot().await;
        assert_eq!(snapshot.settings, settings);
        assert!(snapshot.cache.used_bytes <= 1024 * 1024 * 1024);
        assert!(snapshot.cache.usage_is_current);
        assert!(!snapshot.cache.pending_maintenance);
        assert!(snapshot.cache.measurement_error.is_none());
        assert_eq!(snapshot.cache.entry_count, 1);
        assert!(snapshot.cache.used_bytes >= 700 * 1024 * 1024);
        // Quota eviction may remove the older real object. Reinsert it to exercise
        // the separate object-size change through Engine::apply_settings.
        restarted
            .cache
            .put(
                &key,
                http::StatusCode::OK,
                &http::HeaderMap::new(),
                bytes::Bytes::from(vec![42; 1024 * 1024 + 1]),
                std::time::Duration::from_secs(60),
                settings.cache_limit_bytes(),
            )
            .await
            .unwrap();
        assert!(restarted.cache.get(&key).await.is_some());
        settings.cache_max_object_mib = 1;
        restarted.apply_settings(settings.clone()).await.unwrap();
        assert!(restarted.cache.get(&key).await.is_none());
        assert_eq!(restarted.snapshot().await.cache.entry_count, 0);
        let mut invalid = settings.clone();
        invalid.response_buffer_limit_mib = 1;
        assert!(restarted.apply_settings(invalid).await.is_err());
        assert_eq!(restarted.snapshot().await.settings, settings);
        assert_eq!(restarted.settings_store.load_or_create().unwrap(), settings);
    }

    #[tokio::test]
    async fn isolated_https_modes_never_claim_system_trust() {
        for mode in [HttpsMode::Tunnel, HttpsMode::Inspect] {
            let directory = tempfile::tempdir().unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(
                directory.path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            let store = SettingsStore::new(directory.path().join("settings.json"));
            store
                .save(&Settings {
                    https_mode: mode,
                    https_inspect_hosts: vec!["example.com".into()],
                    https_client_trust_acknowledged: true,
                    ..Settings::default()
                })
                .unwrap();
            let engine = Engine::construct(
                directory.path().to_path_buf(),
                directory.path().join("cache"),
                false,
            )
            .unwrap();
            assert!(!engine.snapshot().await.tls_inspection_ready);
            let mut state = engine.state.lock().await;
            for requested in [HttpsMode::Inspect, HttpsMode::Tunnel] {
                engine
                    .ensure_tls_inspection_ready(&mut state, requested)
                    .unwrap();
                assert!(!state.tls_inspection_ready);
            }
        }
    }

    #[tokio::test]
    async fn stop_closes_listeners_and_clients_even_when_settings_cannot_be_saved() {
        let directory = tempfile::tempdir().unwrap();
        let engine = Engine::construct(
            directory.path().join("config"),
            directory.path().join("cache"),
            false,
        )
        .unwrap();
        let mut settings = engine.snapshot().await.settings;
        settings.proxy_port = unused_loopback_port().await;
        settings.socks5_enabled = true;
        settings.socks5_port = unused_loopback_port().await;
        while settings.socks5_port == settings.proxy_port {
            settings.socks5_port = unused_loopback_port().await;
        }
        engine.apply_settings(settings).await.unwrap();
        engine.start().await.unwrap();
        let before = engine.snapshot().await;
        let mut client = TcpStream::connect(("127.0.0.1", before.settings.socks5_port))
            .await
            .unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0; 2];
        timeout(Duration::from_secs(2), client.read_exact(&mut greeting))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(greeting, [5, 0]);
        let path = engine.settings_path().to_path_buf();
        let backup = path.with_extension("saved");
        let saved = std::fs::read(&path).unwrap();
        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();

        let error = timeout(Duration::from_secs(3), engine.stop())
            .await
            .unwrap()
            .unwrap_err();
        let after = engine.snapshot().await;
        assert!(
            !after.running,
            "Stop must close the proxy even when persistence fails"
        );
        assert!(!after.settings.enabled);
        assert!(after.proxy_addresses.is_empty());
        assert!(after.socks5_addresses.is_empty());
        assert!(after.listener_error.is_none());
        assert_eq!(
            after.last_error.as_deref(),
            Some(error.to_string().as_str())
        );
        assert!(error
            .to_string()
            .contains("Při příštím spuštění aplikace se může znovu zapnout."));
        let closed = timeout(Duration::from_secs(2), client.read(&mut [0; 1]))
            .await
            .unwrap();
        assert!(matches!(closed, Ok(0) | Err(_)));
        for port in [before.settings.proxy_port, before.settings.socks5_port] {
            let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
            drop(listener);
        }
        assert_eq!(std::fs::read(&backup).unwrap(), saved);
        assert!(serde_json::from_slice::<Settings>(&saved).unwrap().enabled);

        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&backup, &path).unwrap();
        // Retrying Stop must save false even when the runtime is already stopped.
        engine.stop().await.unwrap();
        assert!(!engine.settings_store.load_or_create().unwrap().enabled);
        assert!(engine.snapshot().await.last_error.is_none());
        engine.start_saved().await.unwrap();
        assert!(!engine.snapshot().await.running);
        engine.start().await.unwrap();
        assert!(engine.snapshot().await.running);
        engine.stop().await.unwrap();
        assert!(!engine.snapshot().await.running);
    }

    fn headless_engine(directory: &std::path::Path) -> Engine {
        Engine::new_headless(directory.join("config"), directory.join("cache")).unwrap()
    }

    async fn use_unused_proxy_port(engine: &Engine) -> u16 {
        let mut settings = engine.snapshot().await.settings;
        settings.proxy_port = unused_loopback_port().await;
        let port = settings.proxy_port;
        engine.apply_settings(settings).await.unwrap();
        port
    }

    fn saved_settings(engine: &Engine) -> Settings {
        engine.settings_store.load_or_create().unwrap()
    }

    async fn wait_for_maintenance_running(engine: &Engine) {
        timeout(Duration::from_secs(8), async {
            while !engine.snapshot().await.running {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stopping_retires_listener_errors_and_preserves_failure_counters() {
        let directory = tempfile::tempdir().unwrap();
        let engine = headless_engine(directory.path());
        let port = use_unused_proxy_port(&engine).await;
        engine.start().await.unwrap();
        engine.stats.listener_accept_error(
            (Ipv4Addr::LOCALHOST, port).into(),
            "accept-resource-unavailable".into(),
        );
        engine
            .stats
            .listener_runtime_error("runtime-ended-with-error".into());
        let failed = engine.snapshot().await;
        assert!(failed.stats.listener_runtime_error.is_some());
        assert!(failed.last_error.is_some());
        engine.stop().await.unwrap();
        let stopped = engine.snapshot().await;
        assert!(!stopped.running && !stopped.settings.enabled);
        assert!(stopped.last_error.is_none());
        assert!(stopped.stats.listener_runtime_error.is_none());
        assert_eq!(stopped.stats.listener_runtime_errors, 2);
        assert_eq!(stopped.stats.active_connections, 0);
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn maintenance_recovers_saved_enabled_after_bind_failure_and_respects_stop() {
        let directory = tempfile::tempdir().unwrap();
        let blocker = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = blocker.local_addr().unwrap().port();
        let config = private_config(directory.path());
        SettingsStore::new(config.join("settings.json"))
            .save(&Settings {
                enabled: true,
                proxy_port: port,
                ..Settings::default()
            })
            .unwrap();
        let engine = Arc::new(headless_engine(directory.path()));
        assert!(engine.start_saved().await.is_err());
        let maintenance_engine = engine.clone();
        let maintenance = tokio::spawn(async move {
            maintenance_engine.run_periodic_maintenance().await;
        });
        // Ensure the immediate tick has already encountered the occupied port.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!engine.snapshot().await.running);
        drop(blocker);
        wait_for_maintenance_running(&engine).await;
        assert!(engine.snapshot().await.last_error.is_none());

        // A maintenance tick must leave a live listener and its client intact.
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        client.write_all(b"G").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let live = engine.snapshot().await.stats.live_connections;
        assert_eq!(live.len(), 1);
        tokio::time::sleep(Duration::from_millis(5_100)).await;
        assert_eq!(
            engine.snapshot().await.stats.live_connections[0].id,
            live[0].id
        );
        client.write_all(b"ET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut bytes = [0; 16];
        assert!(
            timeout(Duration::from_secs(2), client.read(&mut bytes))
                .await
                .unwrap()
                .unwrap()
                > 0
        );
        assert!(bytes.starts_with(b"HTTP/1.1 "));

        engine.stop().await.unwrap();
        tokio::time::sleep(Duration::from_millis(5_100)).await;
        assert!(!engine.snapshot().await.running);
        assert!(!saved_settings(&engine).enabled);
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_err());
        engine.shutdown().await;
        timeout(Duration::from_secs(2), maintenance)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn maintenance_shutdown_cancels_a_retry_queued_on_state_lock() {
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(headless_engine(directory.path()));
        use_unused_proxy_port(&engine).await;
        engine.start().await.unwrap();
        let mut locked = engine.state.lock().await;
        // Emulate a stopped runtime with its saved enabled flag still true.
        locked.proxy.take().unwrap().stop().await;
        let retry_engine = engine.clone();
        let retry = tokio::spawn(async move {
            retry_engine
                .restore_saved(Some(&retry_engine.maintenance_cancellation))
                .await
                .unwrap();
        });
        tokio::task::yield_now().await;
        let mut shutdown = Box::pin(engine.shutdown());
        // Poll shutdown through cancellation, then leave it waiting on our lock.
        tokio::select! {
            biased;
            _ = &mut shutdown => panic!("shutdown must wait on held state lock"),
            _ = tokio::task::yield_now() => {}
        }
        assert!(engine.maintenance_cancellation.is_cancelled());
        // Release shutdown's pending mutex waiter so the retry can be inspected
        // before any shutdown cleanup masks an accidental listener creation.
        drop(shutdown);
        drop(locked);
        retry.await.unwrap();
        // Shutdown has not taken the lock yet: a cancelled queued retry itself
        // must not create a listener that shutdown would only close afterwards.
        assert!(!engine.snapshot().await.running);
        engine.shutdown().await;
        assert!(!engine.snapshot().await.running);
        assert!(saved_settings(&engine).enabled);
        // A cancelled maintenance loop cannot restore the preserved enabled flag.
        timeout(Duration::from_secs(1), engine.run_periodic_maintenance())
            .await
            .unwrap();
        assert!(!engine.snapshot().await.running);
    }

    #[tokio::test]
    async fn headless_construction_creates_no_authority() {
        let directory = tempfile::tempdir().unwrap();
        let engine = headless_engine(directory.path());
        let snapshot = engine.snapshot().await;
        assert!(!snapshot.running);
        assert!(!snapshot.tls_inspection_ready);
        assert_eq!(snapshot.settings.https_mode, HttpsMode::Tunnel);
        assert!(snapshot.last_error.is_none());
        assert!(!snapshot.https_authority.prepared);
        assert!(!snapshot.https_authority.inspection_enabled);
        assert!(!snapshot.https_authority.client_trust_declared);
        assert!(snapshot.https_authority.error.is_none());
        assert!(matches!(
            engine
                .export_https_certificate(CertificateFormat::Pem)
                .await
                .unwrap_err(),
            EngineError::Tls(TlsInspectionError::NotPrepared)
        ));
        assert!(!authority_record(directory.path()).exists());

        // Default desktop Tunnel startup is equally lazy.
        let desktop = tempfile::tempdir().unwrap();
        let engine = Engine::construct(
            desktop.path().join("config"),
            desktop.path().join("cache"),
            false,
        )
        .unwrap();
        assert!(!engine.snapshot().await.https_authority.prepared);
        assert!(!authority_record(desktop.path()).exists());
    }

    #[tokio::test]
    async fn headless_shutdown_keeps_enabled_and_start_saved_restores_service() {
        let directory = tempfile::tempdir().unwrap();
        let engine = headless_engine(directory.path());
        let port = use_unused_proxy_port(&engine).await;
        engine.start().await.unwrap();
        assert!(saved_settings(&engine).enabled);

        engine.shutdown().await;
        let snapshot = engine.snapshot().await;
        assert!(!snapshot.running);
        assert!(snapshot.settings.enabled);
        assert!(saved_settings(&engine).enabled);
        drop(
            TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap(),
        );

        engine.start_saved().await.unwrap();
        assert!(engine.snapshot().await.running);
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok());

        // A restarted process also restores from the preserved setting.
        engine.shutdown().await;
        drop(engine);
        let engine = headless_engine(directory.path());
        engine.start_saved().await.unwrap();
        assert!(engine.snapshot().await.running);

        engine.stop().await.unwrap();
        assert!(!saved_settings(&engine).enabled);
        engine.start_saved().await.unwrap();
        assert!(!engine.snapshot().await.running);
        assert!(!directory
            .path()
            .join("config/https-inspection-authority-v1.json")
            .exists());
    }

    /// Valid opt-in Inspect: explicit allowlist and client-trust acknowledgement.
    fn allow_inspect(settings: &mut Settings) {
        settings.https_mode = HttpsMode::Inspect;
        settings.https_inspect_hosts = vec!["example.com".into()];
        settings.https_client_trust_acknowledged = true;
    }

    /// Mirrors the daemon, whose state directory is always an owned 0700 directory.
    fn private_config(directory: &std::path::Path) -> std::path::PathBuf {
        let config = directory.join("config");
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&config).unwrap();
        config
    }

    fn authority_record(directory: &std::path::Path) -> std::path::PathBuf {
        directory.join("config").join(AUTHORITY_RECORD_FILE)
    }

    #[tokio::test]
    async fn all_supported_inspect_requires_trust_and_prepared_ca_without_mutation() {
        let directory = tempfile::tempdir().unwrap();
        private_config(directory.path());
        let engine = headless_engine(directory.path());
        let original = engine.snapshot().await.settings;
        let before = std::fs::read(engine.settings_path()).unwrap();
        let mut settings = original.clone();
        settings.https_mode = HttpsMode::Inspect;
        settings.https_inspection_scope = HttpsInspectionScope::AllSupportedHosts;
        assert!(settings.https_inspect_hosts.is_empty());
        assert!(matches!(
            engine.apply_settings(settings.clone()).await,
            Err(EngineError::Config(_))
        ));
        assert_eq!(engine.snapshot().await.settings, original);
        assert_eq!(std::fs::read(engine.settings_path()).unwrap(), before);
        let mut encoded = serde_json::to_value(&settings).unwrap();
        encoded["httpsInspectionScope"] = serde_json::json!("*");
        assert!(serde_json::from_value::<Settings>(encoded).is_err());
        assert_eq!(engine.snapshot().await.settings, original);
        assert_eq!(std::fs::read(engine.settings_path()).unwrap(), before);
        settings.https_client_trust_acknowledged = true;
        assert!(settings.validate(&[]).is_ok());
        let error = engine.apply_settings(settings.clone()).await.unwrap_err();
        if HEADLESS_INSPECTION_CAPABILITY {
            assert!(matches!(
                error,
                EngineError::Tls(TlsInspectionError::NotPrepared)
            ));
        } else {
            assert!(matches!(error, EngineError::InspectionUnsupported));
        }
        assert_eq!(engine.snapshot().await.settings, original);
        assert_eq!(std::fs::read(engine.settings_path()).unwrap(), before);
        assert!(!authority_record(directory.path()).exists());
        if HEADLESS_INSPECTION_CAPABILITY {
            engine.prepare_https_authority().await.unwrap();
            engine.apply_settings(settings.clone()).await.unwrap();
            assert_eq!(engine.snapshot().await.settings, settings);
            assert_eq!(saved_settings(&engine), settings);
        }
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn headless_inspect_requires_acknowledged_allowlist_and_prepared_authority() {
        let directory = tempfile::tempdir().unwrap();
        private_config(directory.path());
        let engine = headless_engine(directory.path());
        let port = use_unused_proxy_port(&engine).await;
        let before = std::fs::read(engine.settings_path()).unwrap();
        let status = engine.https_authority().await;
        assert_eq!(status.capability, HEADLESS_INSPECTION_CAPABILITY);
        assert!(!status.prepared && !status.loaded && !status.inspection_enabled);
        assert!(!status.client_trust_declared && !status.local_trust_installed);
        assert!(status.sha256_fingerprint.is_none());

        let mut unacknowledged = engine.snapshot().await.settings;
        unacknowledged.https_mode = HttpsMode::Inspect;
        let error = engine
            .apply_settings(unacknowledged.clone())
            .await
            .unwrap_err();
        assert!(matches!(error, EngineError::Config(_)));
        assert_eq!(std::fs::read(engine.settings_path()).unwrap(), before);

        let mut inspect = engine.snapshot().await.settings;
        allow_inspect(&mut inspect);
        if !HEADLESS_INSPECTION_CAPABILITY {
            let error = engine.apply_settings(inspect).await.unwrap_err();
            assert!(matches!(error, EngineError::InspectionUnsupported));
            assert!(engine.prepare_https_authority().await.is_err());
            assert!(!authority_record(directory.path()).exists());
            return;
        }
        // Acknowledgement alone never creates an authority implicitly.
        let error = engine.apply_settings(inspect.clone()).await.unwrap_err();
        assert!(matches!(
            error,
            EngineError::Tls(TlsInspectionError::NotPrepared)
        ));
        assert_eq!(std::fs::read(engine.settings_path()).unwrap(), before);
        if let Some(address) = available_lan_addresses().first() {
            let error = engine
                .configure_lan_and_start(inspect.clone(), address.ip.to_string(), false)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                EngineError::Tls(TlsInspectionError::NotPrepared)
            ));
            assert_eq!(std::fs::read(engine.settings_path()).unwrap(), before);
        }
        assert!(!engine.snapshot().await.running);
        assert!(!authority_record(directory.path()).exists());

        // Preparing creates the authority but neither enables Inspect nor declares trust.
        let prepared = engine.prepare_https_authority().await.unwrap();
        assert!(authority_record(directory.path()).exists());
        assert!(prepared.prepared && !prepared.loaded && !prepared.inspection_enabled);
        assert!(!prepared.inspection_active && !prepared.client_trust_declared);
        assert!(!prepared.local_trust_installed);
        let fingerprint = prepared.sha256_fingerprint.clone().unwrap();
        assert_eq!(std::fs::read(engine.settings_path()).unwrap(), before);
        assert_eq!(
            engine.snapshot().await.settings.https_mode,
            HttpsMode::Tunnel
        );
        let exported = engine
            .export_https_certificate(CertificateFormat::Der)
            .await
            .unwrap();
        assert_eq!(exported.sha256_fingerprint, fingerprint);
        // Preparing again keeps the same authority.
        assert_eq!(
            engine
                .prepare_https_authority()
                .await
                .unwrap()
                .sha256_fingerprint,
            Some(fingerprint.clone())
        );

        engine.apply_settings(inspect).await.unwrap();
        let saved = saved_settings(&engine);
        assert_eq!(saved.https_mode, HttpsMode::Inspect);
        let status = engine.https_authority().await;
        assert!(status.inspection_enabled && status.loaded && status.client_trust_declared);
        assert!(!status.inspection_active && !status.local_trust_installed);

        engine.start().await.unwrap();
        let snapshot = engine.snapshot().await;
        assert!(snapshot.running && snapshot.tls_inspection_ready);
        assert!(snapshot.https_authority.inspection_active);
        assert!(!snapshot.https_authority.local_trust_installed);
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok());

        // A restarted daemon resumes Inspect with the persisted authority.
        engine.shutdown().await;
        drop(engine);
        let engine = headless_engine(directory.path());
        assert!(engine.snapshot().await.last_error.is_none());
        engine.start_saved().await.unwrap();
        let snapshot = engine.snapshot().await;
        assert!(snapshot.running && snapshot.https_authority.inspection_active);
        assert_eq!(
            snapshot.https_authority.sha256_fingerprint,
            Some(fingerprint)
        );
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn headless_loads_saved_inspect_profile_stopped_and_allows_switching_to_tunnel() {
        let mut acknowledged = Settings::default();
        allow_inspect(&mut acknowledged);
        let unacknowledged = Settings {
            https_mode: HttpsMode::Inspect,
            ..Settings::default()
        };
        for (saved_profile, valid_profile) in [(unacknowledged, false), (acknowledged, true)] {
            let directory = tempfile::tempdir().unwrap();
            let config = private_config(directory.path());
            let port = unused_loopback_port().await;
            SettingsStore::new(config.join("settings.json"))
                .save(&Settings {
                    enabled: true,
                    proxy_port: port,
                    ..saved_profile
                })
                .unwrap();
            let engine = headless_engine(directory.path());
            let snapshot = engine.snapshot().await;
            assert!(!snapshot.running);
            assert!(!snapshot.tls_inspection_ready);
            assert_eq!(snapshot.settings.https_mode, HttpsMode::Inspect);
            // A malformed profile is reported before any start attempt.
            assert_eq!(snapshot.last_error.is_some(), !valid_profile);

            for result in [engine.start_saved().await, engine.start().await] {
                let error = result.unwrap_err();
                if !valid_profile {
                    assert!(matches!(error, EngineError::Config(_)), "{error}");
                } else if HEADLESS_INSPECTION_CAPABILITY {
                    assert!(matches!(
                        error,
                        EngineError::Tls(TlsInspectionError::NotPrepared)
                    ));
                } else {
                    assert!(matches!(error, EngineError::InspectionUnsupported));
                }
            }
            let snapshot = engine.snapshot().await;
            assert!(!snapshot.running);
            assert!(snapshot.last_error.is_some());
            assert!(snapshot.proxy_addresses.is_empty());
            assert_eq!(saved_settings(&engine).https_mode, HttpsMode::Inspect);
            drop(
                TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                    .await
                    .unwrap(),
            );

            // The repair path stays available while the saved profile is unusable.
            let mut tunnel = snapshot.settings;
            tunnel.https_mode = HttpsMode::Tunnel;
            engine.apply_settings(tunnel).await.unwrap();
            let saved = saved_settings(&engine);
            assert_eq!(saved.https_mode, HttpsMode::Tunnel);
            assert!(saved.enabled);
            assert!(engine.snapshot().await.last_error.is_none());
            engine.start_saved().await.unwrap();
            assert!(engine.snapshot().await.running);
            engine.shutdown().await;
            assert!(!authority_record(directory.path()).exists());
        }
    }

    #[tokio::test]
    async fn headless_unsafe_authority_record_keeps_inspect_stopped() {
        if !cfg!(unix) || !HEADLESS_INSPECTION_CAPABILITY {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        private_config(directory.path());
        let engine = headless_engine(directory.path());
        use_unused_proxy_port(&engine).await;
        engine.prepare_https_authority().await.unwrap();
        let mut inspect = engine.snapshot().await.settings;
        allow_inspect(&mut inspect);
        engine.apply_settings(inspect).await.unwrap();
        engine.start().await.unwrap();
        engine.shutdown().await;
        drop(engine);
        let record = authority_record(directory.path());
        let original = std::fs::read(&record).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&record, std::os::unix::fs::PermissionsExt::from_mode(0o644))
            .unwrap();

        let engine = headless_engine(directory.path());
        let status = engine.https_authority().await;
        assert!(!status.prepared && status.error.is_some());
        assert!(matches!(
            engine.start_saved().await.unwrap_err(),
            EngineError::Tls(TlsInspectionError::UnsafeStorage(_))
        ));
        assert!(!engine.snapshot().await.running);
        assert!(engine.prepare_https_authority().await.is_err());
        assert!(engine
            .export_https_certificate(CertificateFormat::Pem)
            .await
            .is_err());
        assert_eq!(std::fs::read(&record).unwrap(), original);
    }

    async fn unused_loopback_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn ready_tls_state_does_not_reopen_the_windows_root_store() {
        let install_calls = Cell::new(0);
        let mut ready = true;

        let result: Result<(), ()> = install_tls_root_once(&mut ready, || {
            install_calls.set(install_calls.get() + 1);
            Ok(())
        });

        assert_eq!(result, Ok(()));
        assert!(ready);
        assert_eq!(install_calls.get(), 0);
    }

    /// Windows keeps its current-user installer path; elsewhere Inspect runs only through the
    /// headless engine with an explicitly prepared authority and no trust-store changes.
    async fn inspecting_engine(directory: &std::path::Path) -> Engine {
        #[cfg(windows)]
        {
            Engine::new(directory.join("config"), directory.join("cache")).unwrap()
        }
        #[cfg(not(windows))]
        {
            private_config(directory);
            let engine = headless_engine(directory);
            engine.prepare_https_authority().await.unwrap();
            engine
        }
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn non_windows_desktop_engine_never_claims_installed_trust() {
        let directory = tempfile::tempdir().unwrap();
        let engine = Engine::new(
            directory.path().join("config"),
            directory.path().join("cache"),
        )
        .unwrap();
        assert!(!engine.https_inspection_capability());
        let mut inspect = engine.snapshot().await.settings;
        allow_inspect(&mut inspect);
        inspect.proxy_port = unused_loopback_port().await;
        engine.apply_settings(inspect).await.unwrap();
        assert!(matches!(
            engine.start().await.unwrap_err(),
            EngineError::InspectionUnsupported
        ));
        let snapshot = engine.snapshot().await;
        assert!(!snapshot.running && !snapshot.tls_inspection_ready);
        assert!(!snapshot.https_authority.local_trust_installed);
        assert!(!authority_record(directory.path()).exists());
    }

    #[tokio::test]
    async fn engine_controls_the_live_proxy_tls_readiness_and_cache_setting() {
        if !cfg!(windows) && !HEADLESS_INSPECTION_CAPABILITY {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let engine = inspecting_engine(directory.path()).await;

        let mut initial = engine.snapshot().await.settings;
        allow_inspect(&mut initial);
        initial.proxy_port = unused_loopback_port().await;
        initial.socks5_enabled = true;
        initial.socks5_port = unused_loopback_port().await;
        while initial.socks5_port == initial.proxy_port {
            initial.socks5_port = unused_loopback_port().await;
        }
        engine.apply_settings(initial).await.unwrap();
        engine.start().await.unwrap();
        let snapshot = engine.snapshot().await;
        assert!(snapshot.running);
        assert!(snapshot.tls_inspection_ready);
        assert!(!snapshot.settings.cache_enabled);
        assert!(snapshot
            .proxy_addresses
            .iter()
            .any(|address| address == &format!("127.0.0.1:{}", snapshot.settings.proxy_port)));
        assert_eq!(
            snapshot.socks5_addresses,
            vec![format!("127.0.0.1:{}", snapshot.settings.socks5_port)]
        );

        let mut client = TcpStream::connect(("127.0.0.1", snapshot.settings.proxy_port))
            .await
            .unwrap();
        client
            .write_all(
                b"GET http://homeproxy.test/ca.cer HTTP/1.1\r\nHost: homeproxy.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&response).contains("content-type: application/pkix-cert"));

        let mut settings = snapshot.settings;
        settings.cache_enabled = true;
        engine.apply_settings(settings).await.unwrap();
        let snapshot = engine.snapshot().await;
        assert!(snapshot.running);
        assert!(snapshot.settings.cache_enabled);

        // A device that never sends ClientHello must not stall disabling cache.
        let mut stalled = TcpStream::connect((Ipv4Addr::LOCALHOST, snapshot.settings.proxy_port))
            .await
            .unwrap();
        stalled
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut headers = Vec::new();
        timeout(Duration::from_secs(1), async {
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stalled.read_u8().await.unwrap());
            }
        })
        .await
        .unwrap();
        assert!(headers.starts_with(b"HTTP/1.1 200"));
        let mut changed = snapshot.settings.clone();
        changed.cache_enabled = false;
        timeout(Duration::from_secs(1), engine.apply_settings(changed))
            .await
            .expect("disabling cache must finish while a TLS client is stalled")
            .unwrap();
        let snapshot = engine.snapshot().await;
        assert!(snapshot.running);
        assert!(!snapshot.settings.cache_enabled);
        assert!(
            timeout(Duration::from_millis(100), stalled.read_u8())
                .await
                .is_err(),
            "cache toggle must preserve open CONNECT"
        );
        assert!(
            TcpStream::connect((Ipv4Addr::LOCALHOST, snapshot.settings.proxy_port))
                .await
                .is_ok()
        );

        let mut settings = snapshot.settings;
        settings.https_mode = HttpsMode::Tunnel;
        engine.apply_settings(settings).await.unwrap();
        let snapshot = engine.snapshot().await;
        assert!(!snapshot.tls_inspection_ready);
        assert!(snapshot.running);
        assert_eq!(
            timeout(Duration::from_secs(1), stalled.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let mut settings = snapshot.settings;
        settings.lan_auth_enabled = false;
        settings.proxy_username.clear();
        settings.proxy_password.clear();
        timeout(Duration::from_secs(2), engine.apply_settings(settings))
            .await
            .expect("disabling LAN authentication must not wait on the root store")
            .unwrap();
        let snapshot = engine.snapshot().await;
        assert!(snapshot.running);
        assert!(!snapshot.settings.lan_auth_enabled);
        assert!(snapshot.settings.proxy_username.is_empty());
        assert!(snapshot.settings.proxy_password.is_empty());

        engine.stop().await.unwrap();
        assert!(!engine.snapshot().await.running);
    }

    #[tokio::test]
    async fn occupied_port_restores_the_previous_running_service() {
        let directory = tempfile::tempdir().unwrap();
        let engine = Engine::new(
            directory.path().join("config"),
            directory.path().join("cache"),
        )
        .unwrap();
        let previous_port = unused_loopback_port().await;
        let mut settings = engine.snapshot().await.settings;
        settings.proxy_port = previous_port;
        engine.apply_settings(settings).await.unwrap();
        engine.start().await.unwrap();

        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let mut changed = engine.snapshot().await.settings;
        changed.proxy_port = occupied_port;
        let error = engine.apply_settings(changed).await.unwrap_err();

        let snapshot = engine.snapshot().await;
        assert!(snapshot.running);
        assert_eq!(snapshot.settings.proxy_port, previous_port);
        assert_eq!(
            error.listener_bind_failure(),
            Some(ListenerBindFailure {
                service: ListenerService::Http,
                endpoint: format!("127.0.0.1:{occupied_port}"),
                reason: ListenerBindReason::InUse,
            })
        );
        assert!(snapshot.last_error.is_none());
        assert!(snapshot.listener_error.is_none());
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, previous_port))
            .await
            .is_ok());

        engine.stop().await.unwrap();
    }

    #[tokio::test]
    async fn denied_devices_persist_and_can_be_allowed_again() {
        let directory = tempfile::tempdir().unwrap();
        let config_directory = directory.path().join("config");
        let cache_directory = directory.path().join("cache");
        let denied_ip = "192.168.68.81";

        let engine = Engine::new(config_directory.clone(), cache_directory.clone()).unwrap();
        engine
            .set_device_allowed(denied_ip.to_string(), false)
            .await
            .unwrap();
        assert!(engine
            .snapshot()
            .await
            .settings
            .denied_client_ips
            .contains(&denied_ip.parse().unwrap()));
        drop(engine);

        let engine = Engine::new(config_directory, cache_directory).unwrap();
        assert!(engine
            .snapshot()
            .await
            .settings
            .denied_client_ips
            .contains(&denied_ip.parse().unwrap()));
        engine
            .set_device_allowed(denied_ip.to_string(), true)
            .await
            .unwrap();
        assert!(engine
            .snapshot()
            .await
            .settings
            .denied_client_ips
            .is_empty());
    }
}

#[cfg(all(test, windows))]
#[path = "lib/native_tests.rs"]
mod native_tests;
