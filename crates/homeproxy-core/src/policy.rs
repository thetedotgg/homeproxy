//! Deterministic policy evaluation. Identity must come from verified authentication;
//! configured IP aliases are a manual fallback only. Never infer identity from DHCP.
use crate::config::{
    is_private_lan_ip, policy_host_matches, valid_policy_host, ConfigError, Settings,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::Ipv4Addr};

fn default_warning_percent() -> u8 {
    80
}
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceProfile {
    pub id: String,
    pub name: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub ips: Vec<Ipv4Addr>,
    #[serde(default)]
    pub upload_bytes_per_second: u64,
    #[serde(default)]
    pub download_bytes_per_second: u64,
    #[serde(default)]
    pub daily_quota_mib: u64,
    #[serde(default)]
    pub monthly_quota_mib: u64,
    #[serde(default = "default_warning_percent")]
    pub warning_percent: u8,
    #[serde(default)]
    pub allow_domains: Vec<String>,
    #[serde(default)]
    pub block_domains: Vec<String>,
    #[serde(default)]
    pub no_cache_domains: Vec<String>,
    #[serde(default)]
    pub schedules: Vec<ScheduleWindow>,
}
impl std::fmt::Debug for DeviceProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceProfile")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("password", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScheduleAction {
    Deny,
    Limit,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScheduleWindow {
    pub days: Vec<u8>,
    pub start_minute: u16,
    pub end_minute: u16,
    pub action: ScheduleAction,
    #[serde(default)]
    pub upload_bytes_per_second: u64,
    #[serde(default)]
    pub download_bytes_per_second: u64,
}
impl ScheduleWindow {
    /// Half-open windows; overnight tail belongs to the preceding start day.
    pub fn active_at(&self, unix_seconds: i64, offset_minutes: i16) -> bool {
        let Some(local) = unix_seconds
            .checked_add(i64::from(offset_minutes) * 60)
            .and_then(|ts| time::OffsetDateTime::from_unix_timestamp(ts).ok())
        else {
            return false;
        };
        let day = local.weekday().number_from_monday();
        let previous = if day == 1 { 7 } else { day - 1 };
        let minute = u16::from(local.hour()) * 60 + u16::from(local.minute());
        if self.start_minute < self.end_minute {
            self.days.contains(&day) && minute >= self.start_minute && minute < self.end_minute
        } else if self.start_minute > self.end_minute {
            (self.days.contains(&day) && minute >= self.start_minute)
                || (self.days.contains(&previous) && minute < self.end_minute)
        } else {
            false
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaUsage {
    pub daily_bytes: u64,
    pub monthly_bytes: u64,
    pub healthy: bool,
}
impl Default for QuotaUsage {
    fn default() -> Self {
        Self {
            daily_bytes: 0,
            monthly_bytes: 0,
            healthy: true,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyReason {
    Allowed,
    ExplicitDeny,
    Adblock,
    Schedule,
    DailyQuota,
    MonthlyQuota,
    HistoryUnavailable,
    InvalidHost,
    UnknownProfile,
    InvalidTime,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: PolicyReason,
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
    /// Additional restriction only; never overrides cache privacy checks.
    pub no_cache: bool,
    pub explicit_allow: bool,
    pub quota_warning: bool,
}
pub fn resolve_profile<'a>(
    settings: &'a Settings,
    verified_username: Option<&str>,
    peer: Ipv4Addr,
) -> Option<&'a DeviceProfile> {
    // An authenticated unknown/shared identity must never silently become an IP identity.
    match verified_username {
        Some(username) => settings
            .device_profiles
            .iter()
            .find(|profile| profile.username == username),
        None => settings
            .device_profiles
            .iter()
            .find(|profile| profile.ips.contains(&peer)),
    }
}
fn matches(rules: &[String], host: &str) -> bool {
    rules.iter().any(|rule| policy_host_matches(rule, host))
}
fn tighter(a: u64, b: u64) -> u64 {
    match (a, b) {
        (0, _) => b,
        (_, 0) => a,
        _ => a.min(b),
    }
}
fn quota_bytes(mib: u64) -> u64 {
    mib.saturating_mul(1024 * 1024)
}

pub fn decision_at(
    settings: &Settings,
    profile_id: Option<&str>,
    host: &str,
    unix_seconds: i64,
    usage: QuotaUsage,
) -> PolicyDecision {
    evaluate(settings, profile_id, host, unix_seconds, usage, true)
}
/// Ongoing transfer guard. Destination ACLs are checked before forwarding by the proxy,
/// so a denied destination can still receive its local 403/407 response.
pub fn transfer_decision_at(
    settings: &Settings,
    profile_id: Option<&str>,
    unix_seconds: i64,
    usage: QuotaUsage,
) -> PolicyDecision {
    evaluate(
        settings,
        profile_id,
        "homeproxy.invalid",
        unix_seconds,
        usage,
        false,
    )
}
fn evaluate(
    settings: &Settings,
    profile_id: Option<&str>,
    host: &str,
    unix_seconds: i64,
    usage: QuotaUsage,
    evaluate_domains: bool,
) -> PolicyDecision {
    let profile = profile_id.and_then(|id| settings.device_profiles.iter().find(|p| p.id == id));
    let mut decision = PolicyDecision {
        allowed: true,
        reason: PolicyReason::Allowed,
        upload_bytes_per_second: profile.map_or(0, |p| p.upload_bytes_per_second),
        download_bytes_per_second: profile.map_or(0, |p| p.download_bytes_per_second),
        no_cache: matches(&settings.no_cache_domains, host)
            || profile.is_some_and(|p| matches(&p.no_cache_domains, host)),
        explicit_allow: matches(&settings.allow_domains, host)
            || profile.is_some_and(|p| matches(&p.allow_domains, host)),
        quota_warning: false,
    };
    let reason = if evaluate_domains
        && !valid_policy_host(host.trim_end_matches('.'), false)
        && host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_err()
    {
        Some(PolicyReason::InvalidHost)
    } else if profile_id.is_some() && profile.is_none() {
        Some(PolicyReason::UnknownProfile)
    } else if time::OffsetDateTime::from_unix_timestamp(unix_seconds).is_err() {
        Some(PolicyReason::InvalidTime)
    } else if evaluate_domains
        && (matches(&settings.block_domains, host)
            || profile.is_some_and(|p| matches(&p.block_domains, host)))
    {
        Some(PolicyReason::ExplicitDeny)
    } else {
        None
    };
    if let Some(reason) = reason {
        decision.allowed = false;
        decision.reason = reason;
        return decision;
    }
    if let Some(profile) = profile {
        if (profile.daily_quota_mib > 0 || profile.monthly_quota_mib > 0) && !usage.healthy {
            decision.allowed = false;
            decision.reason = PolicyReason::HistoryUnavailable;
            return decision;
        }
        for (limit, used, reason) in [
            (
                profile.daily_quota_mib,
                usage.daily_bytes,
                PolicyReason::DailyQuota,
            ),
            (
                profile.monthly_quota_mib,
                usage.monthly_bytes,
                PolicyReason::MonthlyQuota,
            ),
        ] {
            if limit != 0 {
                let bytes = quota_bytes(limit);
                if used >= bytes {
                    decision.allowed = false;
                    decision.reason = reason;
                    return decision;
                }
                if u128::from(used) * 100 >= u128::from(bytes) * u128::from(profile.warning_percent)
                {
                    decision.quota_warning = true;
                }
            }
        }
        for schedule in &profile.schedules {
            if schedule.active_at(unix_seconds, settings.schedule_utc_offset_minutes) {
                if schedule.action == ScheduleAction::Deny {
                    decision.allowed = false;
                    decision.reason = PolicyReason::Schedule;
                    return decision;
                }
                decision.upload_bytes_per_second = tighter(
                    decision.upload_bytes_per_second,
                    schedule.upload_bytes_per_second,
                );
                decision.download_bytes_per_second = tighter(
                    decision.download_bytes_per_second,
                    schedule.download_bytes_per_second,
                );
            }
        }
    }
    if evaluate_domains
        && !decision.explicit_allow
        && (crate::filter::is_blocked_host(host, settings.adblock_mode)
            || (settings.adblock_mode != crate::config::AdblockMode::Off
                && settings
                    .filter_feeds
                    .iter()
                    .any(|feed| feed.matches_host(host))))
    {
        decision.allowed = false;
        decision.reason = PolicyReason::Adblock;
    }
    decision
}
pub(crate) fn validate_settings(settings: &Settings) -> Result<(), ConfigError> {
    let invalid = || {
        ConfigError::Invalid(
            "Profily zařízení, domény, historie nebo časová pravidla jsou neplatné.",
        )
    };
    if !(1..=366).contains(&settings.history_retention_days)
        || !(-720..=840).contains(&settings.schedule_utc_offset_minutes)
        || settings.device_profiles.len() > 256
    {
        return Err(invalid());
    }
    for list in [
        &settings.allow_domains,
        &settings.block_domains,
        &settings.no_cache_domains,
    ] {
        validate_domains(list)?;
    }
    let mut ids = HashSet::new();
    let mut usernames = HashSet::new();
    let mut ips = HashSet::new();
    for profile in &settings.device_profiles {
        if !valid_identifier(&profile.id, 64)
            || !ids.insert(&profile.id)
            || !valid_identifier(&profile.username, 32)
            || profile.username.len() < 3
            || profile.username == settings.proxy_username
            || !usernames.insert(&profile.username)
            || profile.name.trim().is_empty()
            || profile.name.len() > 128
            || profile.name.chars().any(char::is_control)
            || !(16..=128).contains(&profile.password.len())
            || !profile.password.bytes().all(|b| b.is_ascii_graphic())
            || profile.ips.len() > 32
            || profile
                .ips
                .iter()
                .any(|ip| !is_private_lan_ip(*ip) || !ips.insert(*ip))
            || profile.upload_bytes_per_second > 1_000_000_000
            || profile.download_bytes_per_second > 1_000_000_000
            || profile.daily_quota_mib > u64::MAX / (1024 * 1024)
            || profile.monthly_quota_mib > u64::MAX / (1024 * 1024)
            || !(1..=100).contains(&profile.warning_percent)
            || profile.schedules.len() > 64
        {
            return Err(invalid());
        }
        for list in [
            &profile.allow_domains,
            &profile.block_domains,
            &profile.no_cache_domains,
        ] {
            validate_domains(list)?;
        }
        for schedule in &profile.schedules {
            if schedule.days.is_empty()
                || schedule.days.len() > 7
                || schedule.days.iter().any(|d| !(1..=7).contains(d))
                || schedule.days.iter().collect::<HashSet<_>>().len() != schedule.days.len()
                || schedule.start_minute > 1439
                || schedule.end_minute > 1439
                || schedule.start_minute == schedule.end_minute
                || schedule.upload_bytes_per_second > 1_000_000_000
                || schedule.download_bytes_per_second > 1_000_000_000
                || (schedule.action == ScheduleAction::Limit
                    && schedule.upload_bytes_per_second == 0
                    && schedule.download_bytes_per_second == 0)
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn validate_domains(list: &[String]) -> Result<(), ConfigError> {
    if list.len() > 256
        || list.iter().any(|h| !valid_policy_host(h, true))
        || list
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect::<HashSet<_>>()
            .len()
            != list.len()
    {
        Err(ConfigError::Invalid(
            "Seznam domén vyžaduje jedinečné DNS názvy (nejvýše 256, povoleno *.domena).",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> DeviceProfile {
        DeviceProfile {
            id: "living-room".into(),
            name: "Obývák".into(),
            username: "living_room".into(),
            password: "0123456789abcdef".into(),
            ips: vec!["192.168.1.20".parse().unwrap()],
            upload_bytes_per_second: 0,
            download_bytes_per_second: 0,
            daily_quota_mib: 0,
            monthly_quota_mib: 0,
            warning_percent: 80,
            allow_domains: vec![],
            block_domains: vec![],
            no_cache_domains: vec![],
            schedules: vec![],
        }
    }
    fn ts(year: i32, month: time::Month, day: u8, hour: u8, minute: u8) -> i64 {
        time::Date::from_calendar_date(year, month, day)
            .unwrap()
            .with_hms(hour, minute, 0)
            .unwrap()
            .assume_utc()
            .unix_timestamp()
    }
    #[test]
    fn overnight_tail_uses_start_day_and_half_open_end() {
        // Monday 2026-09-28 -> Tuesday; Sunday -> Monday wrap.
        let mut rule = ScheduleWindow {
            days: vec![1],
            start_minute: 23 * 60,
            end_minute: 60,
            action: ScheduleAction::Deny,
            upload_bytes_per_second: 0,
            download_bytes_per_second: 0,
        };
        let mon = ts(2026, time::Month::September, 28, 23, 0);
        assert!(!rule.active_at(mon - 1, 0));
        assert!(rule.active_at(mon, 0));
        assert!(rule.active_at(mon + 3600, 0));
        assert!(rule.active_at(mon + 7199, 0));
        assert!(!rule.active_at(mon + 7200, 0));
        assert!(!rule.active_at(mon + 86400, 0));
        rule.days = vec![7];
        assert!(rule.active_at(mon - 86400, 0));
        assert!(rule.active_at(mon - 23 * 3600, 0));
    }
    #[test]
    fn fixed_offset_changes_day_deterministically() {
        let rule = ScheduleWindow {
            days: vec![2],
            start_minute: 0,
            end_minute: 60,
            action: ScheduleAction::Deny,
            upload_bytes_per_second: 0,
            download_bytes_per_second: 0,
        };
        let mon = ts(2026, time::Month::September, 28, 23, 0);
        assert!(!rule.active_at(mon, 0));
        assert!(rule.active_at(mon, 60));
        assert!(!rule.active_at(mon, 120));
    }
    #[test]
    fn explicit_deny_wins_and_allow_only_overrides_builtin_adblock() {
        let mut settings = Settings {
            allow_domains: vec!["*.doubleclick.net".into()],
            no_cache_domains: vec!["*.doubleclick.net".into()],
            ..Default::default()
        };
        let d = decision_at(
            &settings,
            None,
            "ads.doubleclick.net",
            0,
            QuotaUsage::default(),
        );
        assert!(d.allowed && d.explicit_allow && d.no_cache);
        assert!(!decision_at(&settings, None, "doubleclick.net", 0, QuotaUsage::default()).allowed);
        assert!(
            !decision_at(
                &settings,
                None,
                "ads.doubleclick.net.evil",
                0,
                QuotaUsage::default()
            )
            .explicit_allow
        );
        settings.block_domains = vec!["ads.doubleclick.net".into()];
        assert_eq!(
            decision_at(
                &settings,
                None,
                "ADS.DOUBLECLICK.NET.",
                0,
                QuotaUsage::default()
            )
            .reason,
            PolicyReason::ExplicitDeny
        );
        let mut p = profile();
        p.allow_domains = settings.allow_domains.clone();
        settings.device_profiles = vec![p];
        assert_eq!(
            decision_at(
                &settings,
                Some("living-room"),
                "ads.doubleclick.net",
                0,
                QuotaUsage::default()
            )
            .reason,
            PolicyReason::ExplicitDeny
        );
    }
    #[test]
    fn authenticated_identity_survives_dhcp_and_never_falls_back_from_unknown_username() {
        let settings = Settings {
            device_profiles: vec![profile()],
            ..Default::default()
        };
        assert_eq!(
            resolve_profile(
                &settings,
                Some("living_room"),
                "192.168.1.99".parse().unwrap()
            )
            .unwrap()
            .id,
            "living-room"
        );
        assert!(
            resolve_profile(&settings, Some("unknown"), "192.168.1.20".parse().unwrap()).is_none()
        );
        assert!(resolve_profile(&settings, None, "192.168.1.20".parse().unwrap()).is_some());
    }
    #[test]
    fn quota_history_failure_schedule_and_warning_are_enforced() {
        let mut settings = Settings::default();
        let mut p = profile();
        p.daily_quota_mib = 1;
        p.schedules = vec![ScheduleWindow {
            days: vec![4],
            start_minute: 0,
            end_minute: 1439,
            action: ScheduleAction::Limit,
            upload_bytes_per_second: 100,
            download_bytes_per_second: 200,
        }];
        settings.device_profiles = vec![p];
        assert_eq!(
            decision_at(
                &settings,
                Some("living-room"),
                "example.com",
                0,
                QuotaUsage {
                    healthy: false,
                    ..QuotaUsage::default()
                }
            )
            .reason,
            PolicyReason::HistoryUnavailable
        );
        assert_eq!(
            decision_at(
                &settings,
                Some("living-room"),
                "example.com",
                0,
                QuotaUsage {
                    daily_bytes: 1024 * 1024,
                    ..QuotaUsage::default()
                }
            )
            .reason,
            PolicyReason::DailyQuota
        );
        let d = decision_at(
            &settings,
            Some("living-room"),
            "example.com",
            0,
            QuotaUsage {
                daily_bytes: 900_000,
                ..QuotaUsage::default()
            },
        );
        assert!(d.allowed && d.quota_warning);
        assert_eq!(d.download_bytes_per_second, 200);
    }
    #[test]
    fn profile_validation_rejects_collisions_public_ips_and_bad_rules() {
        let mut settings = Settings {
            device_profiles: vec![profile()],
            ..Default::default()
        };
        assert!(validate_settings(&settings).is_ok());
        settings.device_profiles.push(profile());
        assert!(validate_settings(&settings).is_err());
        settings.device_profiles.pop();
        settings.device_profiles[0].username = settings.proxy_username.clone();
        assert!(validate_settings(&settings).is_err());
        settings.device_profiles[0] = profile();
        settings.device_profiles[0].ips = vec!["8.8.8.8".parse().unwrap()];
        assert!(validate_settings(&settings).is_err());
        settings.device_profiles[0] = profile();
        settings.block_domains = vec!["https://example.com".into()];
        assert!(validate_settings(&settings).is_err());
        assert!(!format!("{:?}", settings.device_profiles[0]).contains("0123456789abcdef"));
    }
}
