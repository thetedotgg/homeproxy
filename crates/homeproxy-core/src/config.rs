use std::{
    collections::HashSet,
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use if_addrs::get_if_addrs;
use rand::random;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;

pub const DEFAULT_PROXY_PORT: u16 = 17_891;
pub const DEFAULT_SOCKS5_PORT: u16 = 1_080;
const MAX_DENIED_CLIENTS: usize = 256;

pub(crate) fn valid_policy_host(value: &str, wildcard: bool) -> bool {
    let host = if wildcard {
        value.strip_prefix("*.").unwrap_or(value)
    } else {
        value
    };
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// Exact match by default; wildcard matches subdomains only, with a DNS label boundary.
pub(crate) fn policy_host_matches(rule: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let rule = rule.to_ascii_lowercase();
    match rule.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
        None => host == rule,
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AdblockMode {
    Off,
    #[default]
    Mild,
    Strict,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CompressionPreset {
    Off,
    Sharper,
    #[default]
    Balanced,
    Maximum,
}

impl CompressionPreset {
    pub fn jpeg_quality(self) -> Option<u8> {
        match self {
            Self::Off => None,
            Self::Sharper => Some(84),
            Self::Balanced => Some(77),
            Self::Maximum => Some(68),
        }
    }

    pub fn cache_key(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Sharper => "sharper-v1",
            Self::Balanced => "balanced-v1",
            Self::Maximum => "maximum-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DnsMode {
    #[default]
    System,
    Cloudflare,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HttpsMode {
    #[default]
    Tunnel,
    Inspect,
}

/// Broad inspection is an explicit opt-in, never inferred from a host list.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HttpsInspectionScope {
    #[default]
    SelectedHosts,
    AllSupportedHosts,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CacheMode {
    #[default]
    Online,
    Offline,
}

/// Explicitly declared public resources; URL queries remain part of the cache identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicCacheEndpoint {
    pub host: String,
    pub path_prefix: String,
}

fn default_offline_max_stale_hours() -> u16 {
    168
}
fn default_tunnel_idle_timeout_seconds() -> u32 {
    30 * 60
}
fn legacy_https_mode() -> HttpsMode {
    HttpsMode::Inspect
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceLimit {
    pub ip: Ipv4Addr,
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    #[serde(default = "default_automatic_recovery")]
    pub automatic_recovery: bool,
    /// Maximum continuous inactivity of upgraded TCP relays, never total lifetime.
    #[serde(default = "default_tunnel_idle_timeout_seconds")]
    pub tunnel_idle_timeout_seconds: u32,
    #[serde(default)]
    pub pac_enabled: bool,
    #[serde(default)]
    pub pac_direct_fallback: bool,
    #[serde(default)]
    pub upstream_proxies: Vec<UpstreamProxy>,
    #[serde(default)]
    pub upstream_direct_fallback: bool,
    #[serde(default)]
    pub lan_dns_enabled: bool,
    #[serde(default = "default_lan_dns_port")]
    pub lan_dns_port: u16,
    #[serde(default = "default_lan_dns_upstream")]
    pub lan_dns_upstream: SocketAddr,
    #[serde(default)]
    pub allow_domains: Vec<String>,
    #[serde(default)]
    pub block_domains: Vec<String>,
    #[serde(default)]
    pub filter_feeds: Vec<crate::filter_feeds::FilterFeed>,
    #[serde(default)]
    pub no_cache_domains: Vec<String>,
    #[serde(default)]
    pub device_profiles: Vec<crate::policy::DeviceProfile>,
    #[serde(default = "default_history_retention_days")]
    pub history_retention_days: u16,
    #[serde(default)]
    pub schedule_utc_offset_minutes: i16,
    pub version: u8,
    pub enabled: bool,
    pub lan_enabled: bool,
    #[serde(default = "legacy_https_mode")]
    pub https_mode: HttpsMode,
    #[serde(default)]
    pub https_inspection_scope: HttpsInspectionScope,
    #[serde(default)]
    pub https_inspect_hosts: Vec<String>,
    #[serde(default)]
    pub https_bypass_hosts: Vec<String>,
    #[serde(default)]
    pub https_client_trust_acknowledged: bool,
    #[serde(default)]
    pub dns_mode: DnsMode,
    pub listen_ip: Option<String>,
    #[serde(default)]
    pub listen_ips: Vec<String>,
    #[serde(default)]
    pub device_limits: Vec<DeviceLimit>,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default)]
    pub socks5_enabled: bool,
    #[serde(default)]
    pub socks5_udp_enabled: bool,
    #[serde(default = "default_socks5_port")]
    pub socks5_port: u16,
    #[serde(default = "default_lan_auth_enabled")]
    pub lan_auth_enabled: bool,
    pub proxy_username: String,
    pub proxy_password: String,
    #[serde(default)]
    pub denied_client_ips: Vec<Ipv4Addr>,
    pub adblock_mode: AdblockMode,
    pub compression_preset: CompressionPreset,
    pub cache_enabled: bool,
    #[serde(default)]
    pub cache_mode: CacheMode,
    #[serde(default = "default_offline_max_stale_hours")]
    pub offline_max_stale_hours: u16,
    #[serde(default)]
    pub public_cache_endpoints: Vec<PublicCacheEndpoint>,
    pub cache_limit_gib: u16,
    #[serde(default = "default_cache_max_object_mib")]
    pub cache_max_object_mib: u16,
    #[serde(default = "default_response_buffer_limit_mib")]
    pub response_buffer_limit_mib: u8,
    #[serde(default = "default_response_buffer_budget_mib")]
    pub response_buffer_budget_mib: u16,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("version", &self.version)
            .field("enabled", &self.enabled)
            .field("lan_enabled", &self.lan_enabled)
            .field("https_mode", &self.https_mode)
            .field("cache_mode", &self.cache_mode)
            .field("device_profile_count", &self.device_profiles.len())
            .field("upstream_proxy_count", &self.upstream_proxies.len())
            .finish_non_exhaustive()
    }
}

fn default_lan_dns_port() -> u16 {
    5353
}
fn default_lan_dns_upstream() -> SocketAddr {
    SocketAddr::from(([1, 1, 1, 1], 53))
}
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamProxy {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}
impl std::fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamProxy")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("authenticated", &self.username.is_some())
            .finish_non_exhaustive()
    }
}
fn default_history_retention_days() -> u16 {
    90
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            automatic_recovery: true,
            tunnel_idle_timeout_seconds: default_tunnel_idle_timeout_seconds(),
            pac_enabled: false,
            pac_direct_fallback: false,
            upstream_proxies: Vec::new(),
            upstream_direct_fallback: false,
            lan_dns_enabled: false,
            lan_dns_port: default_lan_dns_port(),
            lan_dns_upstream: default_lan_dns_upstream(),
            allow_domains: Vec::new(),
            block_domains: Vec::new(),
            filter_feeds: Vec::new(),
            no_cache_domains: Vec::new(),
            device_profiles: Vec::new(),
            history_retention_days: default_history_retention_days(),
            schedule_utc_offset_minutes: 0,
            version: 1,
            enabled: false,
            lan_enabled: false,
            https_mode: HttpsMode::Tunnel,
            https_inspection_scope: HttpsInspectionScope::SelectedHosts,
            https_inspect_hosts: Vec::new(),
            https_bypass_hosts: Vec::new(),
            https_client_trust_acknowledged: false,
            dns_mode: DnsMode::System,
            listen_ip: None,
            listen_ips: Vec::new(),
            device_limits: Vec::new(),
            proxy_port: DEFAULT_PROXY_PORT,
            socks5_enabled: false,
            socks5_udp_enabled: false,
            socks5_port: DEFAULT_SOCKS5_PORT,
            lan_auth_enabled: true,
            proxy_username: "domov".to_string(),
            proxy_password: random_password(),
            denied_client_ips: Vec::new(),
            adblock_mode: AdblockMode::Mild,
            compression_preset: CompressionPreset::Balanced,
            cache_enabled: false,
            cache_mode: CacheMode::Online,
            offline_max_stale_hours: default_offline_max_stale_hours(),
            public_cache_endpoints: Vec::new(),
            cache_limit_gib: 8,
            cache_max_object_mib: default_cache_max_object_mib(),
            response_buffer_limit_mib: default_response_buffer_limit_mib(),
            response_buffer_budget_mib: default_response_buffer_budget_mib(),
        }
    }
}

impl Settings {
    pub fn validate(&self, available_addresses: &[LanAddress]) -> Result<(), ConfigError> {
        crate::filter_feeds::validate_feeds(&self.filter_feeds).map_err(|_| {
            ConfigError::Invalid("Importované filtry jsou neplatné nebo překračují limity.")
        })?;
        if self.version != 1 {
            return Err(ConfigError::Invalid("Neznámá verze nastavení."));
        }
        if !(60..=86_400).contains(&self.tunnel_idle_timeout_seconds) {
            return Err(ConfigError::Invalid(
                "Nečinnost tunelu musí být mezi 60 a 86400 sekundami.",
            ));
        }
        self.validate_routing_controls()?;
        self.validate_cache_controls()?;
        self.validate_web_policies()?;
        if self.proxy_port == 0 {
            return Err(ConfigError::Invalid(
                "Port HTTP proxy musí být mezi 1 a 65535.",
            ));
        }
        if self.socks5_port == 0 {
            return Err(ConfigError::Invalid("Port SOCKS5 musí být mezi 1 a 65535."));
        }
        if self.socks5_enabled && self.proxy_port == self.socks5_port {
            return Err(ConfigError::Invalid(
                "HTTP proxy a SOCKS5 musí používat rozdílné porty.",
            ));
        }
        if self.lan_auth_enabled {
            if self.proxy_username.len() < 3
                || self.proxy_username.len() > 32
                || !self
                    .proxy_username
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(ConfigError::Invalid(
                    "Uživatelské jméno proxy má neplatný formát.",
                ));
            }
            if self.proxy_password.len() < 16
                || self.proxy_password.len() > 128
                || !self
                    .proxy_password
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic())
            {
                return Err(ConfigError::Invalid(
                    "Přístupový klíč proxy musí mít alespoň 16 znaků.",
                ));
            }
        }

        if self.denied_client_ips.len() > MAX_DENIED_CLIENTS
            || self
                .denied_client_ips
                .iter()
                .any(|ip| !is_private_lan_ip(*ip))
            || self.denied_client_ips.iter().collect::<HashSet<_>>().len()
                != self.denied_client_ips.len()
        {
            return Err(ConfigError::Invalid(
                "Seznam zakázaných zařízení obsahuje neplatnou adresu.",
            ));
        }

        if self.device_limits.len() > 256
            || self.device_limits.iter().any(|limit| {
                !is_private_lan_ip(limit.ip)
                    || limit.upload_bytes_per_second > 1_000_000_000
                    || limit.download_bytes_per_second > 1_000_000_000
            })
            || self
                .device_limits
                .iter()
                .map(|limit| limit.ip)
                .collect::<HashSet<_>>()
                .len()
                != self.device_limits.len()
        {
            return Err(ConfigError::Invalid(
                "Limity zařízení obsahují neplatnou adresu nebo rychlost.",
            ));
        }
        if self.listen_ips.len() > 32 {
            return Err(ConfigError::Invalid(
                "Je vybráno příliš mnoho síťových adres.",
            ));
        }
        if self.lan_enabled {
            let selected = self.selected_listen_ips()?;
            if selected.is_empty()
                || selected.iter().collect::<HashSet<_>>().len() != selected.len()
            {
                return Err(ConfigError::Invalid(
                    "Vyberte jedinečné adresy tohoto počítače.",
                ));
            }
            for ip in selected {
                if !is_private_lan_ip(ip) {
                    return Err(ConfigError::Invalid(
                        "Proxy lze otevřít jen na privátní adrese domácí sítě.",
                    ));
                }
                if !available_addresses.iter().any(|address| address.ip == ip) {
                    return Err(ConfigError::Invalid(
                        "Vybraná adresa teď není na tomto počítači dostupná.",
                    ));
                }
            }
        }

        Ok(())
    }

    fn validate_routing_controls(&self) -> Result<(), ConfigError> {
        if self.lan_dns_port == 0
            || (self.lan_dns_enabled
                && (self.lan_dns_port == self.proxy_port
                    || (self.socks5_enabled && self.lan_dns_port == self.socks5_port)))
            || self.lan_dns_upstream.port() == 0
        {
            return Err(ConfigError::Invalid(
                "LAN DNS vyžaduje vlastní nenulový port a platný port resolveru.",
            ));
        }
        let ip = self.lan_dns_upstream.ip();
        if ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
            || matches!(ip,IpAddr::V4(ip) if ip.is_broadcast())
        {
            return Err(ConfigError::Invalid(
                "Upstream LAN DNS nesmí mířit na loopback, multicast ani neurčenou adresu.",
            ));
        }
        if self.upstream_proxies.len() > 4 {
            return Err(ConfigError::Invalid(
                "Lze zadat nejvýše čtyři upstream proxy.",
            ));
        }
        let mut hosts = HashSet::new();
        for upstream in &self.upstream_proxies {
            let host = upstream
                .host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(&upstream.host);
            let address = host.parse::<IpAddr>().ok();
            let bracketed = host != upstream.host;
            if bracketed && !matches!(address, Some(IpAddr::V6(_))) {
                return Err(ConfigError::Invalid(
                    "Hranaté závorky upstream hostitele jsou povoleny pouze pro IPv6.",
                ));
            }
            if upstream.port == 0
                || !(valid_policy_host(host, false) || address.is_some())
                || upstream.host.len() > 253
                || host.eq_ignore_ascii_case("localhost")
                || host.to_ascii_lowercase().ends_with(".localhost")
                || address.is_some_and(|ip| {
                    ip.is_loopback()
                        || ip.is_unspecified()
                        || ip.is_multicast()
                        || matches!(ip,IpAddr::V4(ip) if ip.is_broadcast())
                })
                || !hosts.insert((host.to_ascii_lowercase(), upstream.port))
            {
                return Err(ConfigError::Invalid("Upstream proxy vyžaduje jedinečného platného hostitele a port; loopback není povolen."));
            }
            match (&upstream.username,&upstream.password) {
                (None,None)=>{},
                (Some(username),Some(password)) if !username.is_empty() && username.len()<=128 && !password.is_empty() && password.len()<=256 && username.bytes().all(|b|b.is_ascii_graphic()&&b!=b':') && password.bytes().all(|b|b.is_ascii_graphic())=>{},
                _=>return Err(ConfigError::Invalid("Upstream přihlášení vyžaduje současně platné jméno i heslo bez řídicích znaků.")),
            }
        }
        Ok(())
    }

    pub(crate) fn validate_web_policies(&self) -> Result<(), ConfigError> {
        crate::policy::validate_settings(self)?;
        for hosts in [&self.https_inspect_hosts, &self.https_bypass_hosts] {
            if hosts.len() > 128 || hosts.iter().any(|host| !valid_policy_host(host, true)) {
                return Err(ConfigError::Invalid(
                    "Seznam HTTPS hostitelů je neplatný (nejvýše 128 názvů, volitelně *.domena).",
                ));
            }
            let normalized = hosts
                .iter()
                .map(|host| host.to_ascii_lowercase())
                .collect::<HashSet<_>>();
            if normalized.len() != hosts.len() {
                return Err(ConfigError::Invalid("HTTPS hostitelé se nesmějí opakovat."));
            }
        }
        if self.https_mode == HttpsMode::Inspect
            && (!self.https_client_trust_acknowledged
                || (self.https_inspection_scope == HttpsInspectionScope::SelectedHosts
                    && self.https_inspect_hosts.is_empty()))
        {
            return Err(ConfigError::Invalid(
                "HTTPS Inspect vyžaduje potvrzení přípravy důvěry klientů a ve vybraném rozsahu také hostitele.",
            ));
        }
        if self.offline_max_stale_hours > 8760 {
            return Err(ConfigError::Invalid(
                "Offline stáří musí být mezi 0 a 8760 hodinami.",
            ));
        }
        if self.public_cache_endpoints.len() > 128
            || self.public_cache_endpoints.iter().any(|endpoint| {
                !valid_policy_host(&endpoint.host, false)
                    || !endpoint.path_prefix.starts_with('/')
                    || endpoint.path_prefix.len() > 2048
                    || !endpoint
                        .path_prefix
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'?' | b'#' | b'\\'))
            })
        {
            return Err(ConfigError::Invalid(
                "Veřejná cache vyžaduje nejvýše 128 přesných hostitelů a platné prefixy cest.",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_cache_controls(&self) -> Result<(), ConfigError> {
        if !(1..=1024).contains(&self.cache_limit_gib) {
            return Err(ConfigError::Invalid(
                "Kapacita cache musí být mezi 1 a 1024 GiB.",
            ));
        }
        if !(1..=1024).contains(&self.cache_max_object_mib) {
            return Err(ConfigError::Invalid(
                "Maximální objekt cache musí být mezi 1 a 1024 MiB.",
            ));
        }
        if self.response_buffer_limit_mib > 8 {
            return Err(ConfigError::Invalid(
                "Buffer odpovědi musí být mezi 0 a 8 MiB.",
            ));
        }
        if self.response_buffer_budget_mib > 512 {
            return Err(ConfigError::Invalid(
                "Sdílený rozpočet bufferů musí být mezi 0 a 512 MiB.",
            ));
        }
        if u16::from(self.response_buffer_limit_mib) > self.response_buffer_budget_mib {
            return Err(ConfigError::Invalid(
                "Buffer odpovědi nesmí překročit sdílený rozpočet bufferů.",
            ));
        }
        Ok(())
    }

    pub fn selected_listen_ips(&self) -> Result<Vec<Ipv4Addr>, ConfigError> {
        let values = if self.listen_ips.is_empty() {
            self.listen_ip.iter().collect::<Vec<_>>()
        } else {
            self.listen_ips.iter().collect::<Vec<_>>()
        };
        values
            .into_iter()
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| ConfigError::Invalid("Adresa tohoto počítače není platná IPv4."))
            })
            .collect()
    }

    pub fn listen_ip(&self) -> Option<Ipv4Addr> {
        self.listen_ip.as_deref()?.parse().ok()
    }

    pub fn cache_max_object_bytes(&self) -> u64 {
        u64::from(self.cache_max_object_mib) * 1024 * 1024
    }

    pub fn response_buffer_limit_bytes(&self) -> usize {
        usize::from(self.response_buffer_limit_mib) * 1024 * 1024
    }

    pub fn response_buffer_budget_bytes(&self) -> usize {
        usize::from(self.response_buffer_budget_mib) * 1024 * 1024
    }

    pub fn cache_limit_bytes(&self) -> u64 {
        u64::from(self.cache_limit_gib) * 1024 * 1024 * 1024
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LanAddress {
    pub interface_name: String,
    pub ip: Ipv4Addr,
}

pub fn available_lan_addresses() -> Vec<LanAddress> {
    let mut addresses = get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|interface| match interface.addr.ip() {
            IpAddr::V4(ip) if is_private_lan_ip(ip) => Some(LanAddress {
                interface_name: interface.name,
                ip,
            }),
            _ => None,
        })
        .collect::<Vec<_>>();

    addresses.sort_by(|left, right| {
        left.ip
            .octets()
            .cmp(&right.ip.octets())
            .then_with(|| left.interface_name.cmp(&right.interface_name))
    });
    addresses.dedup_by_key(|address| address.ip);
    addresses
}

pub fn is_private_lan_ip(ip: Ipv4Addr) -> bool {
    ip.is_private() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified()
}

pub struct SettingsStore {
    path: PathBuf,
}

impl SettingsStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn load_or_create(&self) -> Result<Settings, ConfigError> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(ConfigError::Deserialize),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let settings = Settings::default();
                self.save(&settings)?;
                Ok(settings)
            }
            Err(error) => Err(ConfigError::Io(error)),
        }
    }

    pub fn save(&self, settings: &Settings) -> Result<(), ConfigError> {
        let parent = self
            .path
            .parent()
            .ok_or(ConfigError::Invalid("Nastavení nemá platný adresář."))?;
        fs::create_dir_all(parent)?;
        let bytes = serde_json::to_vec_pretty(settings)?;
        let mut temporary = NamedTempFile::new_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.as_file_mut().sync_all()?;
        temporary
            .persist(&self.path)
            .map_err(|error| ConfigError::Io(error.error))?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn random_password() -> String {
    hex::encode(random::<[u8; 16]>())
}

const fn default_cache_max_object_mib() -> u16 {
    1024
}
const fn default_response_buffer_limit_mib() -> u8 {
    8
}
const fn default_response_buffer_budget_mib() -> u16 {
    64
}

const fn default_automatic_recovery() -> bool {
    true
}

const fn default_lan_auth_enabled() -> bool {
    true
}

const fn default_proxy_port() -> u16 {
    DEFAULT_PROXY_PORT
}

const fn default_socks5_port() -> u16 {
    DEFAULT_SOCKS5_PORT
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("Nastavení nelze přečíst: {0}")]
    Deserialize(#[from] serde_json::Error),
    #[error("Nastavení nelze uložit: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_inactivity_defaults_migrate_and_persist_with_bounded_validation() {
        let mut legacy = serde_json::to_value(Settings::default()).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("tunnelIdleTimeoutSeconds");
        let settings: Settings = serde_json::from_value(legacy).unwrap();
        assert_eq!(settings.tunnel_idle_timeout_seconds, 1_800);
        for (seconds, valid) in [
            (0, false),
            (59, false),
            (60, true),
            (86_400, true),
            (86_401, false),
        ] {
            let candidate = Settings {
                tunnel_idle_timeout_seconds: seconds,
                ..settings.clone()
            };
            assert_eq!(candidate.validate(&[]).is_ok(), valid, "{seconds}");
        }
        let directory = tempfile::tempdir().unwrap();
        let store = SettingsStore::new(directory.path().join("settings.json"));
        let changed = Settings {
            tunnel_idle_timeout_seconds: 3_600,
            ..settings
        };
        store.save(&changed).unwrap();
        assert_eq!(store.load_or_create().unwrap(), changed);
    }

    #[test]
    fn cache_controls_preserve_legacy_defaults_and_persist_new_values() {
        let mut legacy = serde_json::to_value(Settings::default()).unwrap();
        for field in [
            "cacheMaxObjectMib",
            "responseBufferLimitMib",
            "responseBufferBudgetMib",
        ] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        let settings: Settings = serde_json::from_value(legacy).unwrap();
        assert_eq!(settings.cache_max_object_mib, 1024);
        assert_eq!(settings.response_buffer_limit_mib, 8);
        assert_eq!(settings.response_buffer_budget_mib, 64);
        let directory = tempfile::tempdir().unwrap();
        let store = SettingsStore::new(directory.path().join("settings.json"));
        let updated = Settings {
            cache_limit_gib: 1024,
            cache_max_object_mib: 1,
            response_buffer_limit_mib: 0,
            response_buffer_budget_mib: 0,
            ..settings
        };
        store.save(&updated).unwrap();
        assert_eq!(store.load_or_create().unwrap(), updated);
        assert_eq!(updated.cache_limit_bytes(), 1024u64.pow(4));
        assert_eq!(updated.cache_max_object_bytes(), 1024 * 1024);
    }

    #[test]
    fn cache_control_boundaries_and_cross_field_validation() {
        for value in [1, 2, 8, 20, 256, 1024] {
            assert!(Settings {
                cache_limit_gib: value,
                cache_max_object_mib: value,
                ..Settings::default()
            }
            .validate(&[])
            .is_ok());
        }
        for value in [0, 1025, u16::MAX] {
            assert!(Settings {
                cache_limit_gib: value,
                ..Settings::default()
            }
            .validate(&[])
            .is_err());
            assert!(Settings {
                cache_max_object_mib: value,
                ..Settings::default()
            }
            .validate(&[])
            .is_err());
        }
        for (limit, budget, valid) in [
            (0, 0, true),
            (0, 64, true),
            (1, 1, true),
            (8, 512, true),
            (9, 64, false),
            (8, 7, false),
            (1, 0, false),
            (0, 513, false),
        ] {
            assert_eq!(
                Settings {
                    response_buffer_limit_mib: limit,
                    response_buffer_budget_mib: budget,
                    ..Settings::default()
                }
                .validate(&[])
                .is_ok(),
                valid,
                "{limit}/{budget}"
            );
        }
        for (field, value) in [
            ("cacheLimitGib", 65536),
            ("cacheMaxObjectMib", 65536),
            ("responseBufferLimitMib", 256),
            ("responseBufferBudgetMib", 65536),
        ] {
            let mut encoded = serde_json::to_value(Settings::default()).unwrap();
            encoded[field] = serde_json::json!(value);
            assert!(serde_json::from_value::<Settings>(encoded).is_err());
        }
    }

    #[test]
    fn fresh_https_tunnels_and_legacy_inspection_migrate_without_changing_dns_provider() {
        let fresh = Settings::default();
        assert_eq!(fresh.https_mode, HttpsMode::Tunnel);
        assert_eq!(
            fresh.https_inspection_scope,
            HttpsInspectionScope::SelectedHosts
        );
        assert_eq!(fresh.dns_mode, DnsMode::System);
        let mut old = serde_json::to_value(&fresh).unwrap();
        old.as_object_mut().unwrap().remove("httpsMode");
        old.as_object_mut().unwrap().remove("httpsInspectionScope");
        old.as_object_mut().unwrap().remove("dnsMode");
        let legacy: Settings = serde_json::from_value(old).unwrap();
        assert_eq!(legacy.https_mode, HttpsMode::Inspect);
        assert_eq!(
            legacy.https_inspection_scope,
            HttpsInspectionScope::SelectedHosts
        );
        assert_eq!(legacy.dns_mode, DnsMode::System);
        let encoded = serde_json::to_value(&fresh).unwrap();
        assert_eq!(encoded["httpsMode"], "tunnel");
        assert_eq!(encoded["dnsMode"], "system");
    }

    #[test]
    fn inspection_scope_requires_explicit_valid_opt_in_and_trust() {
        let mut settings = Settings {
            https_mode: HttpsMode::Inspect,
            https_client_trust_acknowledged: true,
            ..Settings::default()
        };
        assert!(settings.validate(&[]).is_err());
        settings.https_inspection_scope = HttpsInspectionScope::AllSupportedHosts;
        assert!(settings.validate(&[]).is_ok());
        let encoded = serde_json::to_value(&settings).unwrap();
        assert_eq!(encoded["httpsInspectionScope"], "allSupportedHosts");
        for scope in [
            HttpsInspectionScope::SelectedHosts,
            HttpsInspectionScope::AllSupportedHosts,
        ] {
            settings.https_inspection_scope = scope;
            for host in ["*", "*.bad..example", "https://example.com", "example.com."] {
                settings.https_inspect_hosts = vec![host.into()];
                assert!(settings.validate(&[]).is_err(), "{scope:?}: {host}");
            }
            settings.https_inspect_hosts = vec!["example.com".into()];
            settings.https_bypass_hosts = vec!["*".into()];
            assert!(settings.validate(&[]).is_err());
            settings.https_bypass_hosts.clear();
            settings.https_client_trust_acknowledged = false;
            assert!(settings.validate(&[]).is_err());
            settings.https_client_trust_acknowledged = true;
        }
        for invalid in [
            serde_json::json!("all"),
            serde_json::json!("*"),
            serde_json::json!(null),
            serde_json::json!(true),
        ] {
            let mut malformed = encoded.clone();
            malformed["httpsInspectionScope"] = invalid;
            assert!(serde_json::from_value::<Settings>(malformed).is_err());
        }
    }

    #[test]
    fn multiple_lan_addresses_validate_each_entry_and_migrate_legacy_selection() {
        let mut settings = Settings {
            lan_enabled: true,
            listen_ip: Some("192.168.1.2".into()),
            ..Settings::default()
        };
        let addresses = vec![
            LanAddress {
                interface_name: "a".into(),
                ip: "192.168.1.2".parse().unwrap(),
            },
            LanAddress {
                interface_name: "b".into(),
                ip: "10.0.0.2".parse().unwrap(),
            },
        ];
        assert_eq!(
            settings.selected_listen_ips().unwrap(),
            vec![addresses[0].ip]
        );
        settings.listen_ips = vec!["192.168.1.2".into(), "10.0.0.2".into()];
        assert!(settings.validate(&addresses).is_ok());
        for second in ["127.0.0.2", "8.8.8.8", "192.168.1.2", "10.0.0.3"] {
            settings.listen_ips[1] = second.into();
            assert!(settings.validate(&addresses).is_err());
        }
    }

    #[test]
    fn lan_requires_an_available_private_address() {
        let available = vec![LanAddress {
            interface_name: "test".into(),
            ip: Ipv4Addr::new(192, 168, 10, 1),
        }];
        let mut settings = Settings {
            lan_enabled: true,
            listen_ip: Some("192.168.10.1".into()),
            ..Settings::default()
        };
        assert!(settings.validate(&available).is_ok());

        settings.listen_ip = Some("8.8.8.8".into());
        assert!(settings.validate(&available).is_err());
    }

    #[test]
    fn settings_round_trip_without_losing_the_generated_secret() {
        let directory = tempfile::tempdir().unwrap();
        let store = SettingsStore::new(directory.path().join("settings.json"));
        let mut initial = store.load_or_create().unwrap();
        initial.proxy_port = 3128;
        initial.socks5_enabled = true;
        initial.socks5_port = 1080;
        store.save(&initial).unwrap();
        let loaded = store.load_or_create().unwrap();
        assert_eq!(initial, loaded);
        assert!(initial.proxy_password.len() >= 16);
        assert_eq!(loaded.proxy_port, 3128);
        assert!(loaded.socks5_enabled);
        assert_eq!(loaded.socks5_port, 1080);
    }

    #[test]
    fn shared_cache_is_opt_in_for_a_fresh_install() {
        assert!(!Settings::default().cache_enabled);
    }

    #[test]
    fn lan_authentication_can_be_disabled_and_credentials_cleared() {
        let settings = Settings {
            lan_auth_enabled: false,
            proxy_username: String::new(),
            proxy_password: String::new(),
            ..Settings::default()
        };

        assert!(settings.validate(&[]).is_ok());
    }

    #[test]
    fn old_settings_enable_lan_authentication_and_start_with_no_denied_clients() {
        let settings: Settings = serde_json::from_str(
            r#"{
                "version": 1,
                "enabled": false,
                "lanEnabled": false,
                "listenIp": null,
                "proxyUsername": "domov",
                "proxyPassword": "0123456789abcdef",
                "adblockMode": "mild",
                "compressionPreset": "balanced",
                "cacheEnabled": false,
                "cacheLimitGib": 8
            }"#,
        )
        .unwrap();

        assert!(settings.lan_auth_enabled);
        assert!(settings.denied_client_ips.is_empty());
        assert_eq!(settings.proxy_port, DEFAULT_PROXY_PORT);
        assert!(!settings.socks5_enabled);
        assert_eq!(settings.socks5_port, DEFAULT_SOCKS5_PORT);
    }

    #[test]
    fn service_ports_are_validated() {
        for proxy_port in [80, 3128, DEFAULT_PROXY_PORT] {
            let settings = Settings {
                proxy_port,
                ..Settings::default()
            };
            assert!(settings.validate(&[]).is_ok());
        }

        let zero_proxy = Settings {
            proxy_port: 0,
            ..Settings::default()
        };
        assert!(zero_proxy.validate(&[]).is_err());

        let zero_socks = Settings {
            socks5_port: 0,
            ..Settings::default()
        };
        assert!(zero_socks.validate(&[]).is_err());

        let same_port = Settings {
            proxy_port: 1080,
            socks5_enabled: true,
            socks5_port: 1080,
            ..Settings::default()
        };
        assert!(same_port.validate(&[]).is_err());

        for field in ["proxyPort", "socks5Port"] {
            let mut serialized = serde_json::to_value(Settings::default()).unwrap();
            serialized[field] = serde_json::json!(65_536);
            assert!(serde_json::from_value::<Settings>(serialized).is_err());
        }
    }
}

#[cfg(test)]
mod routing_policy_tests {
    use super::*;
    #[test]
    fn routing_defaults_preserve_old_settings_and_private_dns_router_is_valid() {
        let mut settings = Settings::default();
        assert!(
            !settings.pac_enabled
                && !settings.pac_direct_fallback
                && !settings.upstream_direct_fallback
                && !settings.lan_dns_enabled
        );
        assert_eq!(settings.lan_dns_port, 5353);
        assert_eq!(settings.lan_dns_upstream, "1.1.1.1:53".parse().unwrap());
        let mut json = serde_json::to_value(&settings).unwrap();
        let object = json.as_object_mut().unwrap();
        for name in [
            "pacEnabled",
            "pacDirectFallback",
            "upstreamProxies",
            "upstreamDirectFallback",
            "lanDnsEnabled",
            "lanDnsPort",
            "lanDnsUpstream",
            "deviceProfiles",
            "historyRetentionDays",
            "scheduleUtcOffsetMinutes",
        ] {
            object.remove(name);
        }
        let migrated: Settings = serde_json::from_value(json).unwrap();
        assert_eq!(migrated.history_retention_days, 90);
        assert_eq!(migrated.schedule_utc_offset_minutes, 0);
        assert!(migrated.validate(&[]).is_ok());
        settings.lan_dns_upstream = "192.168.1.1:53".parse().unwrap();
        assert!(settings.validate(&[]).is_ok());
        settings.lan_dns_port = settings.proxy_port;
        assert!(settings.validate(&[]).is_ok());
        settings.lan_dns_enabled = true;
        assert!(settings.validate(&[]).is_err());
        settings.lan_dns_port = 5353;
        settings.lan_dns_upstream = "127.0.0.1:53".parse().unwrap();
        assert!(settings.validate(&[]).is_err());
    }
    #[test]
    fn upstream_rejects_partial_credentials_urls_loopback_and_redacts_debug() {
        let mut settings = Settings::default();
        let proxy = UpstreamProxy {
            host: "proxy.example.com".into(),
            port: 3128,
            username: Some("user".into()),
            password: Some("top-secret".into()),
        };
        settings.upstream_proxies = vec![proxy.clone()];
        assert!(settings.validate(&[]).is_ok());
        let debug = format!("{proxy:?}");
        assert!(!debug.contains("top-secret") && !debug.contains("user"));
        settings.upstream_proxies[0].password = None;
        assert!(settings.validate(&[]).is_err());
        settings.upstream_proxies[0] = proxy;
        for host in [
            "http://proxy.example.com",
            "localhost",
            "127.0.0.1",
            "[::1]",
            "[proxy.example.com]",
            "[[2001:db8::1]]",
        ] {
            settings.upstream_proxies[0].host = host.into();
            assert!(settings.validate(&[]).is_err(), "accepted {host}");
        }
        settings.upstream_proxies[0].host = "[2001:db8::1]".into();
        assert!(settings.validate(&[]).is_ok());
        settings.upstream_proxies[0].password = Some("secret\r\nheader:bad".into());
        assert!(settings.validate(&[]).is_err());
    }
}

#[cfg(test)]
mod automatic_recovery_tests {
    use super::*;
    #[test]
    fn watchdog_setting_defaults_for_legacy_json_and_round_trips_false() {
        let mut json = serde_json::to_value(Settings::default()).unwrap();
        assert_eq!(json["automaticRecovery"], true);
        json.as_object_mut().unwrap().remove("automaticRecovery");
        assert!(
            serde_json::from_value::<Settings>(json.clone())
                .unwrap()
                .automatic_recovery
        );
        json["automaticRecovery"] = serde_json::Value::Bool(false);
        let settings = serde_json::from_value::<Settings>(json).unwrap();
        assert!(!settings.automatic_recovery);
        let root = tempfile::tempdir().unwrap();
        let store = SettingsStore::new(root.path().join("settings.json"));
        store.save(&settings).unwrap();
        assert!(!store.load_or_create().unwrap().automatic_recovery);
    }
}
