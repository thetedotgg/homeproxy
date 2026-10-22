//! Private aggregate history. No destinations, URLs, queries or credentials.
//! All methods use UTC calendar boundaries. A caller using a fixed local offset
//! must apply the same offset to every timestamp passed to policy and this module.
use crate::policy::QuotaUsage;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Mutex,
    },
};
use tempfile::NamedTempFile;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ROWS: usize = 100_000;
const VERSION: u8 = 2;
const CREDIT_WINDOW: u64 = 1024 * 1024;
const MAX_IDENTITIES: usize = 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageCounters {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub saved_bytes: u64,
    pub requests: u64,
}
impl UsageCounters {
    fn add(&mut self, other: Self) {
        self.upload_bytes = self.upload_bytes.saturating_add(other.upload_bytes);
        self.download_bytes = self.download_bytes.saturating_add(other.download_bytes);
        self.saved_bytes = self.saved_bytes.saturating_add(other.saved_bytes);
        self.requests = self.requests.saturating_add(other.requests);
    }
    fn bytes(self) -> u64 {
        self.upload_bytes.saturating_add(self.download_bytes)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DailyUsage {
    pub identity: String,
    pub day: i64,
    pub counters: UsageCounters,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MonthlyUsage {
    pub identity: String,
    pub year: i32,
    pub month: u8,
    pub counters: UsageCounters,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuotaDebt {
    pub identity: String,
    pub day: i64,
    pub bytes: u64,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryReport {
    pub healthy: bool,
    pub error: Option<String>,
    pub retention_days: u16,
    pub rows: Vec<DailyUsage>,
    pub months: Vec<MonthlyUsage>,
    pub quota_debts: Vec<QuotaDebt>,
    pub quota_credits: Vec<QuotaDebt>,
}
#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("Historie provozu není dostupná: {0}")]
    Unavailable(String),
    #[error("Neplatná identita nebo čas historie.")]
    InvalidInput,
    #[error("Datová kvóta byla vyčerpána.")]
    QuotaExceeded,
    #[error("Kredit kvóty je právě rezervován jiným přenosem.")]
    CreditBusy,
    #[error("Vyúčtovaný přenos překračuje rezervaci.")]
    ReservationExceeded,
    #[error("Nelze uložit historii provozu: {0}")]
    Io(#[from] std::io::Error),
    #[error("Neplatný formát historie provozu.")]
    Format,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredHistory {
    version: u8,
    rows: Vec<DailyUsage>,
    months: Vec<MonthlyUsage>,
    #[serde(default)]
    credits: Vec<QuotaDebt>,
    #[serde(default)]
    quota_debts: Vec<QuotaDebt>,
}
struct State {
    rows: BTreeMap<(String, i64), UsageCounters>,
    months: BTreeMap<(String, i32, u8), UsageCounters>,
    pending: BTreeMap<(String, i64), u64>,
    credit_available: BTreeMap<(String, i64), u64>,
    credit_pending: BTreeMap<(String, i64), u64>,
    debts: BTreeMap<(String, i64), u64>,
    monthly_debts: BTreeMap<(String, i32, u8), u64>,
    identities: BTreeSet<String>,
    last_pruned_day: Option<i64>,
    durable_writes: u64,
    error: Option<String>,
    // Only a failed write is retried by the periodic checkpoint. Load, format and
    // capacity errors stay fail-closed until the operator repairs the history.
    error_retryable: bool,
    revision: u64,
}
struct Inner {
    path: PathBuf,
    retention_days: AtomicU16,
    state: Mutex<State>,
    checkpoint_lock: Mutex<()>,
}
#[derive(Clone)]
pub struct UsageHistory {
    inner: Arc<Inner>,
}
fn valid_identity(value: &str) -> bool {
    if let Some(id) = value.strip_prefix("profile:") {
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    } else if let Some(ip) = value.strip_prefix("ip:") {
        ip.parse::<std::net::IpAddr>().is_ok()
    } else {
        false
    }
}
fn calendar(unix_seconds: i64) -> Result<(i64, i32, u8), HistoryError> {
    let dt = time::OffsetDateTime::from_unix_timestamp(unix_seconds)
        .map_err(|_| HistoryError::InvalidInput)?;
    Ok((unix_seconds.div_euclid(86_400), dt.year(), dt.month() as u8))
}
fn month_of_day(day: i64) -> Option<(i32, u8)> {
    let ts = day.checked_mul(86_400)?;
    let (_, year, month) = calendar(ts).ok()?;
    Some((year, month))
}
fn check_health(state: &State) -> Result<(), HistoryError> {
    state
        .error
        .as_ref()
        .map_or(Ok(()), |e| Err(HistoryError::Unavailable(e.clone())))
}
fn check_health_or_retryable(state: &State) -> Result<(), HistoryError> {
    if state.error_retryable {
        return Ok(());
    }
    check_health(state)
}
fn lock_state(inner: &Inner) -> Result<std::sync::MutexGuard<'_, State>, HistoryError> {
    inner
        .state
        .lock()
        .map_err(|_| HistoryError::Unavailable("Zámek historie byl poškozen.".into()))
}
fn usage_locked(state: &State, identity: &str, day: i64, year: i32, month: u8) -> QuotaUsage {
    let daily = state
        .rows
        .get(&(identity.to_owned(), day))
        .copied()
        .unwrap_or_default()
        .bytes()
        .saturating_add(*state.pending.get(&(identity.to_owned(), day)).unwrap_or(&0))
        .saturating_add(*state.debts.get(&(identity.to_owned(), day)).unwrap_or(&0));
    let confirmed = state
        .months
        .get(&(identity.to_owned(), year, month))
        .copied()
        .unwrap_or_default()
        .bytes();
    let pending = state
        .pending
        .iter()
        .filter(|((id, d), _)| id == identity && month_of_day(*d) == Some((year, month)))
        .fold(0u64, |sum, (_, bytes)| sum.saturating_add(*bytes));
    QuotaUsage {
        daily_bytes: daily,
        monthly_bytes: confirmed.saturating_add(pending).saturating_add(
            *state
                .monthly_debts
                .get(&(identity.to_owned(), year, month))
                .unwrap_or(&0),
        ),
        healthy: true,
    }
}
impl UsageHistory {
    /// A damaged file is preserved and surfaced through report/queries, never replaced with zeros.
    pub fn open(path: impl Into<PathBuf>, retention_days: u16) -> Self {
        let path = path.into();
        let loaded = load(&path);
        let (rows, months, debts, error) = match loaded {
            Ok((rows, months, debts)) => (rows, months, debts, None),
            Err(e) => (
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                Some(e.to_string()),
            ),
        };
        let mut identities = BTreeSet::new();
        for (id, _) in rows.keys() {
            identities.insert(id.clone());
        }
        for (id, _, _) in months.keys() {
            identities.insert(id.clone());
        }
        for (id, _) in debts.keys() {
            identities.insert(id.clone());
        }
        let monthly_debts = aggregate_debts(&debts);
        // Settings validation owns configuration errors. Preserve all available data
        // while an invalid saved setting is being repaired; only load/I/O errors
        // poison history and make configured quotas fail closed.
        let retention_days = if !(1..=366).contains(&retention_days) {
            366
        } else {
            retention_days
        };
        Self {
            inner: Arc::new(Inner {
                path,
                retention_days: AtomicU16::new(retention_days),
                state: Mutex::new(State {
                    rows,
                    months,
                    pending: BTreeMap::new(),
                    credit_available: BTreeMap::new(),
                    credit_pending: BTreeMap::new(),
                    debts,
                    monthly_debts,
                    identities,
                    last_pruned_day: None,
                    durable_writes: 0,
                    error,
                    error_retryable: false,
                    revision: 0,
                }),
                checkpoint_lock: Mutex::new(()),
            }),
        }
    }
    pub fn retention_days(&self) -> u16 {
        self.inner.retention_days.load(Ordering::Relaxed)
    }
    pub fn set_retention_days(&self, days: u16) -> Result<(), HistoryError> {
        if !(1..=366).contains(&days) {
            return Err(HistoryError::InvalidInput);
        }
        self.checkpoint()?;
        self.commit_retention_days(days);
        Ok(())
    }
    /// Commit only previously validated retention after configuration persistence.
    /// No I/O and no state/Arc replacement; poison remains fail-closed for reads.
    pub(crate) fn commit_retention_days(&self, days: u16) {
        self.inner.retention_days.store(days, Ordering::Relaxed);
        self.inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_pruned_day = None;
    }
    /// Known counters for status displays, with an explicit health flag on errors.
    pub fn usage_status_at(&self, identity: &str, unix_seconds: i64) -> QuotaUsage {
        let unhealthy = QuotaUsage {
            healthy: false,
            ..Default::default()
        };
        if !valid_identity(identity) {
            return unhealthy;
        }
        let Ok((day, year, month)) = calendar(unix_seconds) else {
            return unhealthy;
        };
        let Ok(state) = lock_state(&self.inner) else {
            return unhealthy;
        };
        let mut usage = usage_locked(&state, identity, day, year, month);
        usage.healthy = state.error.is_none();
        usage
    }
    pub fn usage_at(&self, identity: &str, unix_seconds: i64) -> Result<QuotaUsage, HistoryError> {
        if !valid_identity(identity) {
            return Err(HistoryError::InvalidInput);
        }
        let (day, year, month) = calendar(unix_seconds)?;
        let state = lock_state(&self.inner)?;
        check_health(&state)?;
        Ok(usage_locked(&state, identity, day, year, month))
    }
    /// Reserve at most requested bytes atomically. Concurrent reservations count toward both quotas.
    /// Zero quota means unlimited. Settle only after bytes were actually sent; Drop refunds the rest.
    pub fn reserve(
        &self,
        identity: &str,
        unix_seconds: i64,
        requested: u64,
        daily_quota_mib: u64,
        monthly_quota_mib: u64,
    ) -> Result<QuotaReservation, HistoryError> {
        if !valid_identity(identity)
            || daily_quota_mib > u64::MAX / (1024 * 1024)
            || monthly_quota_mib > u64::MAX / (1024 * 1024)
        {
            return Err(HistoryError::InvalidInput);
        }
        let (day, year, month) = calendar(unix_seconds)?;
        // One lock order for checkpoint/credit purchase: writer -> state. The writer
        // mutex is cheap for ordinary chunks; disk I/O only buys a new <=1MiB window.
        let _writer =
            self.inner.checkpoint_lock.lock().map_err(|_| {
                HistoryError::Unavailable("Zámek zápisu historie byl poškozen.".into())
            })?;
        let mut state = lock_state(&self.inner)?;
        check_health(&state)?;
        prune(&mut state, day, self.retention_days());
        admit_identity(&mut state, identity)?;
        let key = (identity.to_owned(), day);
        let durable = daily_quota_mib > 0 || monthly_quota_mib > 0;
        admit_key(&mut state, &key, year, month, durable)?;
        let used = usage_locked(&state, identity, day, year, month);
        let mut remaining = u64::MAX;
        for (limit, used) in [
            (daily_quota_mib, used.daily_bytes),
            (monthly_quota_mib, used.monthly_bytes),
        ] {
            if limit > 0 {
                remaining = remaining.min((limit * 1024 * 1024).saturating_sub(used));
            }
        }
        if requested > 0 && remaining == 0 {
            return Err(HistoryError::QuotaExceeded);
        }
        let mut granted = requested.min(remaining);
        if durable && granted > 0 {
            // A calendar change abandons the previous day's unused pool. Any new
            // pool is persisted together with that refund before returning bytes.
            state
                .credit_available
                .retain(|(id, d), _| id != identity || *d == day);
            let available = *state.credit_available.get(&key).unwrap_or(&0);
            if available < granted {
                let in_flight = state
                    .credit_pending
                    .iter()
                    .filter(|((id, _), _)| id == identity)
                    .fold(0u64, |sum, (_, bytes)| sum.saturating_add(*bytes));
                let credit = CREDIT_WINDOW
                    .saturating_sub(in_flight)
                    .saturating_sub(available)
                    .min(remaining.saturating_sub(available));
                if credit > 0 {
                    state
                        .credit_available
                        .insert(key.clone(), available + credit);
                    if let Err(error) = persist_locked(&self.inner, &mut state, true) {
                        // Never keep credit that was not durably issued.
                        if available == 0 {
                            state.credit_available.remove(&key);
                        } else {
                            state.credit_available.insert(key.clone(), available);
                        }
                        return Err(error);
                    }
                } else if available == 0 {
                    return Err(HistoryError::CreditBusy);
                }
            }
            granted = granted.min(*state.credit_available.get(&key).unwrap_or(&0));
            *state.credit_available.entry(key.clone()).or_default() -= granted;
            if state.credit_available[&key] == 0 {
                state.credit_available.remove(&key);
            }
            let pending = state.credit_pending.entry(key.clone()).or_default();
            *pending = pending
                .checked_add(granted)
                .ok_or(HistoryError::InvalidInput)?;
        }
        let pending = state.pending.entry(key.clone()).or_default();
        *pending = pending
            .checked_add(granted)
            .ok_or(HistoryError::InvalidInput)?;
        Ok(QuotaReservation {
            inner: self.inner.clone(),
            key,
            bytes: granted,
            durable,
            finished: false,
        })
    }
    /// Record confirmed transfer outside quota accounting, or extra savings/request counters.
    /// Do not record upload/download again for bytes already settled through a reservation.
    pub fn record(
        &self,
        identity: &str,
        unix_seconds: i64,
        counters: UsageCounters,
    ) -> Result<(), HistoryError> {
        if !valid_identity(identity) {
            return Err(HistoryError::InvalidInput);
        }
        let (day, year, month) = calendar(unix_seconds)?;
        let mut state = lock_state(&self.inner)?;
        check_health(&state)?;
        prune(&mut state, day, self.retention_days());
        let key = (identity.to_owned(), day);
        admit_identity(&mut state, identity)?;
        admit_key(&mut state, &key, year, month, false)?;
        state.rows.entry(key.clone()).or_default().add(counters);
        let (_, year, month) = calendar(unix_seconds)?;
        state
            .months
            .entry((key.0, year, month))
            .or_default()
            .add(counters);
        state.revision = state.revision.wrapping_add(1);
        Ok(())
    }
    pub fn prune_at(&self, unix_seconds: i64) -> Result<(), HistoryError> {
        let (day, _, _) = calendar(unix_seconds)?;
        let mut state = lock_state(&self.inner)?;
        check_health_or_retryable(&state)?;
        prune(&mut state, day, self.retention_days());
        Ok(())
    }
    /// Persist real counters and refund unused credits. In-flight reservations stay
    /// durably covered; clean shutdown cancels them first and then checkpoints.
    /// After a failed write (e.g. a full disk) a later successful checkpoint makes
    /// the complete in-memory state durable again and restores quota admission.
    pub fn checkpoint(&self) -> Result<(), HistoryError> {
        let _writer =
            self.inner.checkpoint_lock.lock().map_err(|_| {
                HistoryError::Unavailable("Zámek zápisu historie byl poškozen.".into())
            })?;
        let mut state = lock_state(&self.inner)?;
        check_health_or_retryable(&state)?;
        persist_locked(&self.inner, &mut state, false)?;
        state.error = None;
        state.error_retryable = false;
        state.credit_available.clear();
        Ok(())
    }
    #[cfg(test)]
    pub fn durable_write_count(&self) -> u64 {
        lock_state(&self.inner)
            .map(|s| s.durable_writes)
            .unwrap_or(0)
    }
    pub fn report(&self) -> HistoryReport {
        match lock_state(&self.inner) {
            Ok(state) => HistoryReport {
                healthy: state.error.is_none(),
                error: state.error.clone(),
                retention_days: self.retention_days(),
                rows: rows(&state),
                months: months(&state),
                quota_debts: debt_rows(&state.debts),
                quota_credits: debt_rows(&outstanding_credits(&state)),
            },
            Err(error) => HistoryReport {
                healthy: false,
                error: Some(error.to_string()),
                retention_days: self.retention_days(),
                rows: Vec::new(),
                months: Vec::new(),
                quota_debts: Vec::new(),
                quota_credits: Vec::new(),
            },
        }
    }
    pub fn json_report(&self) -> Result<String, HistoryError> {
        serde_json::to_string(&self.report()).map_err(|_| HistoryError::Format)
    }
    pub fn csv(&self) -> Result<String, HistoryError> {
        let state = lock_state(&self.inner)?;
        check_health(&state)?;
        let mut csv="identity,utcDay,uploadBytes,downloadBytes,savedBytes,requests,quotaDebtBytes,quotaCreditBytes\r\n".to_string();
        let credits = outstanding_credits(&state);
        let keys: BTreeSet<_> = state
            .rows
            .keys()
            .chain(state.debts.keys())
            .chain(credits.keys())
            .collect();
        for key in keys {
            let counters = state.rows.get(key).copied().unwrap_or_default();
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{}\r\n",
                csv_cell(&key.0),
                key.1,
                counters.upload_bytes,
                counters.download_bytes,
                counters.saved_bytes,
                counters.requests,
                state.debts.get(key).copied().unwrap_or(0),
                credits.get(key).copied().unwrap_or(0)
            ));
        }
        Ok(csv)
    }
}
fn rows(state: &State) -> Vec<DailyUsage> {
    state
        .rows
        .iter()
        .map(|((identity, day), counters)| DailyUsage {
            identity: identity.clone(),
            day: *day,
            counters: *counters,
        })
        .collect()
}
fn months(state: &State) -> Vec<MonthlyUsage> {
    state
        .months
        .iter()
        .map(|((identity, year, month), counters)| MonthlyUsage {
            identity: identity.clone(),
            year: *year,
            month: *month,
            counters: *counters,
        })
        .collect()
}
fn aggregate_debts(debts: &BTreeMap<(String, i64), u64>) -> BTreeMap<(String, i32, u8), u64> {
    let mut months = BTreeMap::new();
    for ((id, day), bytes) in debts {
        if let Some((year, month)) = month_of_day(*day) {
            let total = months.entry((id.clone(), year, month)).or_insert(0u64);
            *total = total.saturating_add(*bytes);
        }
    }
    months
}
fn outstanding_credits(state: &State) -> BTreeMap<(String, i64), u64> {
    let mut credits = state.credit_pending.clone();
    for (key, bytes) in &state.credit_available {
        let credit = credits.entry(key.clone()).or_default();
        *credit = credit.saturating_add(*bytes);
    }
    credits
}
fn debt_rows(debts: &BTreeMap<(String, i64), u64>) -> Vec<QuotaDebt> {
    debts
        .iter()
        .filter(|(_, bytes)| **bytes > 0)
        .map(|((identity, day), bytes)| QuotaDebt {
            identity: identity.clone(),
            day: *day,
            bytes: *bytes,
        })
        .collect()
}
fn prune(state: &mut State, current_day: i64, retention: u16) {
    if state
        .last_pruned_day
        .is_some_and(|previous| current_day <= previous)
    {
        return;
    }
    state.last_pruned_day = Some(current_day);
    let oldest = current_day.saturating_sub(i64::from(retention).saturating_sub(1));
    if let Some(oldest_month) = month_of_day(oldest) {
        state.months.retain(|(id, year, month), _| {
            (*year, *month) >= oldest_month
                || state.pending.keys().any(|(pending_id, day)| {
                    pending_id == id && month_of_day(*day) == Some((*year, *month))
                })
        });
        // Coarse quota debt for the current month survives short daily retention.
        state
            .debts
            .retain(|(_, day), _| month_of_day(*day).is_some_and(|month| month >= oldest_month));
        state.monthly_debts = aggregate_debts(&state.debts);
    }
    state
        .rows
        .retain(|key, _| key.1 >= oldest || state.pending.contains_key(key));
    state.credit_available.retain(|key, _| key.1 >= oldest);
    state.identities = state
        .rows
        .keys()
        .map(|(id, _)| id.clone())
        .chain(state.months.keys().map(|(id, _, _)| id.clone()))
        .chain(state.debts.keys().map(|(id, _)| id.clone()))
        .chain(state.pending.keys().map(|(id, _)| id.clone()))
        .chain(state.credit_available.keys().map(|(id, _)| id.clone()))
        .collect();
}
fn admit_identity(state: &mut State, id: &str) -> Result<(), HistoryError> {
    if state.identities.len() >= MAX_IDENTITIES && !state.identities.contains(id) {
        state.error = Some("Historie překročila počet identit.".into());
        return Err(HistoryError::Unavailable(state.error.clone().unwrap()));
    }
    state.identities.insert(id.to_owned());
    Ok(())
}
fn admit_key(
    state: &mut State,
    key: &(String, i64),
    year: i32,
    month: u8,
    reserve_credit: bool,
) -> Result<(), HistoryError> {
    let credit_keys = state.credit_available.len()
        + state
            .credit_pending
            .keys()
            .filter(|key| !state.credit_available.contains_key(*key))
            .count();
    let added = usize::from(!state.rows.contains_key(key))
        + usize::from(!state.months.contains_key(&(key.0.clone(), year, month)))
        + usize::from(
            reserve_credit
                && !state.credit_available.contains_key(key)
                && !state.credit_pending.contains_key(key),
        );
    if state.rows.len() + state.months.len() + state.debts.len() + credit_keys + added > MAX_ROWS {
        state.error = Some("Historie překročila kapacitu záznamů.".into());
        return Err(HistoryError::Unavailable(state.error.clone().unwrap()));
    }
    state.rows.entry(key.clone()).or_default();
    state
        .months
        .entry((key.0.clone(), year, month))
        .or_default();
    Ok(())
}
fn persist_locked(
    inner: &Inner,
    state: &mut State,
    preserve_available: bool,
) -> Result<(), HistoryError> {
    let result = (|| -> Result<(), HistoryError> {
        let mut credits = state.credit_pending.clone();
        if preserve_available {
            for (key, available) in &state.credit_available {
                let credit = credits.entry(key.clone()).or_default();
                *credit = credit.checked_add(*available).ok_or(HistoryError::Format)?;
            }
        }
        let data = StoredHistory {
            version: VERSION,
            rows: rows(state),
            months: months(state),
            credits: debt_rows(&credits),
            quota_debts: debt_rows(&state.debts),
        };
        if data.rows.len() + data.months.len() + data.credits.len() + data.quota_debts.len()
            > MAX_ROWS
        {
            return Err(HistoryError::Format);
        }
        let encoded = serde_json::to_vec(&data).map_err(|_| HistoryError::Format)?;
        if encoded.len() as u64 > MAX_FILE_BYTES {
            return Err(HistoryError::Format);
        }
        let parent = inner
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let mut file = NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&encoded)?;
        file.as_file().sync_all()?;
        file.persist(&inner.path)
            .map_err(|e| HistoryError::Io(e.error))?;
        #[cfg(unix)]
        {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            state.durable_writes = state.durable_writes.saturating_add(1);
            Ok(())
        }
        Err(error) => {
            state.error_retryable = matches!(error, HistoryError::Io(_))
                && (state.error.is_none() || state.error_retryable);
            state.error = Some(error.to_string());
            Err(error)
        }
    }
}
fn release_reservation(
    state: &mut State,
    key: &(String, i64),
    reserved: u64,
    unused: u64,
    durable: bool,
) {
    refund(state, key, reserved);
    if durable {
        if let Some(pending) = state.credit_pending.get_mut(key) {
            *pending = pending.saturating_sub(reserved);
            if *pending == 0 {
                state.credit_pending.remove(key);
            }
        }
        if unused > 0 {
            let available = state.credit_available.entry(key.clone()).or_default();
            *available = available.saturating_add(unused);
        }
    }
}
type LoadedHistory = (
    BTreeMap<(String, i64), UsageCounters>,
    BTreeMap<(String, i32, u8), UsageCounters>,
    BTreeMap<(String, i64), u64>,
);
fn load(path: &Path) -> Result<LoadedHistory, HistoryError> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((BTreeMap::new(), BTreeMap::new(), BTreeMap::new()))
        }
        Err(e) => return Err(e.into()),
    };
    if file.metadata()?.len() > MAX_FILE_BYTES {
        return Err(HistoryError::Format);
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(HistoryError::Format);
    }
    let data: StoredHistory = serde_json::from_slice(&bytes).map_err(|_| HistoryError::Format)?;
    if !matches!(data.version, 1 | VERSION)
        || data.rows.len() + data.months.len() + data.credits.len() + data.quota_debts.len()
            > MAX_ROWS
    {
        return Err(HistoryError::Format);
    }
    let mut rows = BTreeMap::new();
    for row in data.rows {
        if !valid_identity(&row.identity)
            || month_of_day(row.day).is_none()
            || rows.insert((row.identity, row.day), row.counters).is_some()
        {
            return Err(HistoryError::Format);
        }
    }
    let mut months = BTreeMap::new();
    for month in data.months {
        if !valid_identity(&month.identity)
            || !(1..=12).contains(&month.month)
            || !(-9999..=9999).contains(&month.year)
            || months
                .insert((month.identity, month.year, month.month), month.counters)
                .is_some()
        {
            return Err(HistoryError::Format);
        }
    }
    let mut daily_totals: BTreeMap<(String, i32, u8), UsageCounters> = BTreeMap::new();
    for ((id, day), counters) in &rows {
        let (year, month) = month_of_day(*day).ok_or(HistoryError::Format)?;
        daily_totals
            .entry((id.clone(), year, month))
            .or_default()
            .add(*counters);
    }
    for (key, daily) in daily_totals {
        let total = months.get(&key).ok_or(HistoryError::Format)?;
        if total.upload_bytes < daily.upload_bytes
            || total.download_bytes < daily.download_bytes
            || total.saved_bytes < daily.saved_bytes
            || total.requests < daily.requests
        {
            return Err(HistoryError::Format);
        }
    }
    let mut debts = BTreeMap::new();
    for list in [data.quota_debts, data.credits] {
        let mut seen = BTreeSet::new();
        for debt in list {
            if !valid_identity(&debt.identity)
                || month_of_day(debt.day).is_none()
                || debt.bytes == 0
                || !seen.insert((debt.identity.clone(), debt.day))
            {
                return Err(HistoryError::Format);
            }
            let bytes = debts.entry((debt.identity, debt.day)).or_insert(0u64);
            *bytes = bytes.checked_add(debt.bytes).ok_or(HistoryError::Format)?;
        }
    }
    let mut identities = BTreeSet::new();
    for (id, _) in rows.keys() {
        identities.insert(id);
    }
    for (id, _, _) in months.keys() {
        identities.insert(id);
    }
    for (id, _) in debts.keys() {
        identities.insert(id);
    }
    if identities.len() > MAX_IDENTITIES {
        return Err(HistoryError::Format);
    }
    Ok((rows, months, debts))
}
/// Quote every textual cell and neutralize spreadsheet formulas, including whitespace prefixes.
pub fn csv_cell(value: &str) -> String {
    let dangerous = value
        .trim_start_matches(|c: char| c.is_whitespace())
        .starts_with(['=', '+', '-', '@']);
    let prefix = if dangerous { "'" } else { "" };
    format!("\"{}{}\"", prefix, value.replace('"', "\"\""))
}
pub struct QuotaReservation {
    inner: Arc<Inner>,
    key: (String, i64),
    bytes: u64,
    durable: bool,
    finished: bool,
}
impl QuotaReservation {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn settle(mut self, upload_bytes: u64, download_bytes: u64) -> Result<(), HistoryError> {
        let sent = upload_bytes
            .checked_add(download_bytes)
            .ok_or(HistoryError::ReservationExceeded)?;
        if sent > self.bytes {
            return Err(HistoryError::ReservationExceeded);
        }
        let mut state = lock_state(&self.inner)?;
        // Even a failed checkpoint cannot erase already transmitted bytes.
        release_reservation(
            &mut state,
            &self.key,
            self.bytes,
            self.bytes - sent,
            self.durable,
        );
        state
            .rows
            .entry(self.key.clone())
            .or_default()
            .add(UsageCounters {
                upload_bytes,
                download_bytes,
                ..UsageCounters::default()
            });
        let (year, month) = month_of_day(self.key.1).ok_or(HistoryError::InvalidInput)?;
        state
            .months
            .entry((self.key.0.clone(), year, month))
            .or_default()
            .add(UsageCounters {
                upload_bytes,
                download_bytes,
                ..UsageCounters::default()
            });
        state.revision = state.revision.wrapping_add(1);
        self.finished = true;
        Ok(())
    }
}
fn refund(state: &mut State, key: &(String, i64), bytes: u64) {
    if let Some(pending) = state.pending.get_mut(key) {
        *pending = pending.saturating_sub(bytes);
        if *pending == 0 {
            state.pending.remove(key);
        }
    }
}
impl Drop for QuotaReservation {
    fn drop(&mut self) {
        if !self.finished {
            if let Ok(mut state) = self.inner.state.lock() {
                release_reservation(&mut state, &self.key, self.bytes, self.bytes, self.durable);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MIB: u64 = 1024 * 1024;
    fn history(retention: u16) -> (tempfile::TempDir, UsageHistory) {
        let dir = tempfile::tempdir().unwrap();
        let history = UsageHistory::open(dir.path().join("history.json"), retention);
        (dir, history)
    }
    fn ts(day: u8) -> i64 {
        time::Date::from_calendar_date(2026, time::Month::January, day)
            .unwrap()
            .midnight()
            .assume_utc()
            .unix_timestamp()
    }
    #[test]
    fn concurrent_reservations_cannot_exceed_quota_and_cancel_refunds() {
        let (_dir, history) = history(90);
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let history = history.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let reservation = history.reserve("profile:tv", ts(1), MIB, 1, 1);
                    barrier.wait();
                    reservation
                })
            })
            .collect();
        barrier.wait();
        let reservations: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(reservations.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            history.usage_at("profile:tv", ts(1)).unwrap().daily_bytes,
            MIB
        );
        drop(reservations);
        assert_eq!(
            history.usage_at("profile:tv", ts(1)).unwrap().daily_bytes,
            0
        );
        let reservation = history.reserve("profile:tv", ts(1), MIB, 1, 1).unwrap();
        reservation.settle(100, 200).unwrap();
        assert_eq!(
            history.usage_at("profile:tv", ts(1)).unwrap().daily_bytes,
            300
        );
        assert_eq!(
            history
                .reserve("profile:tv", ts(1), MIB, 1, 1)
                .unwrap()
                .bytes(),
            MIB - 300
        );
    }
    #[test]
    fn restart_preserves_confirmed_consumption_but_not_cancelled_reservations() {
        let (dir, history) = history(90);
        history
            .reserve("profile:tv", ts(1), 1000, 1, 1)
            .unwrap()
            .settle(200, 400)
            .unwrap();
        let pending = history.reserve("profile:tv", ts(1), 1000, 1, 1).unwrap();
        drop(pending);
        history.checkpoint().unwrap();
        let reopened = UsageHistory::open(dir.path().join("history.json"), 90);
        assert_eq!(
            reopened.usage_at("profile:tv", ts(1)).unwrap().daily_bytes,
            600
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.path().join("history.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn corrupt_history_is_preserved_and_queries_fail_closed() {
        let (dir, history) = history(90);
        let path = dir.path().join("history.json");
        fs::write(&path, b"{broken").unwrap();
        drop(history);
        let history = UsageHistory::open(&path, 90);
        assert!(!history.report().healthy);
        assert!(history.report().error.is_some());
        assert!(history.reserve("profile:tv", ts(1), 100, 1, 1).is_err());
        assert!(history.csv().is_err());
        assert!(history.checkpoint().is_err());
        assert_eq!(fs::read(path).unwrap(), b"{broken");
    }
    #[test]
    fn retention_keeps_current_month_quota_even_when_daily_details_expire() {
        let (dir, history) = history(1);
        history
            .record(
                "profile:tv",
                ts(1),
                UsageCounters {
                    download_bytes: MIB,
                    ..UsageCounters::default()
                },
            )
            .unwrap();
        history.prune_at(ts(20)).unwrap();
        assert!(history.report().rows.is_empty());
        assert_eq!(
            history
                .usage_at("profile:tv", ts(20))
                .unwrap()
                .monthly_bytes,
            MIB
        );
        assert!(matches!(
            history.reserve("profile:tv", ts(20), 1, 0, 1),
            Err(HistoryError::QuotaExceeded)
        ));
        history.checkpoint().unwrap();
        let history = UsageHistory::open(dir.path().join("history.json"), 1);
        assert_eq!(
            history
                .usage_at("profile:tv", ts(20))
                .unwrap()
                .monthly_bytes,
            MIB
        );
        let feb = time::Date::from_calendar_date(2026, time::Month::February, 1)
            .unwrap()
            .midnight()
            .assume_utc()
            .unix_timestamp();
        history.prune_at(feb).unwrap();
        assert!(history.report().months.is_empty());
        assert_eq!(
            history.usage_at("profile:tv", feb).unwrap().monthly_bytes,
            0
        );
    }
    #[test]
    fn monthly_quota_spans_days_and_reservations_refund_over_settle() {
        let (_dir, history) = history(90);
        history
            .reserve("profile:tv", ts(1), MIB, 0, 1)
            .unwrap()
            .settle(0, MIB - 10)
            .unwrap();
        assert_eq!(
            history
                .reserve("profile:tv", ts(2), 100, 0, 1)
                .unwrap()
                .bytes(),
            10
        );
        let reservation = history.reserve("profile:tv", ts(2), 10, 0, 1).unwrap();
        assert!(matches!(
            reservation.settle(0, 11),
            Err(HistoryError::ReservationExceeded)
        ));
        assert_eq!(
            history.usage_at("profile:tv", ts(2)).unwrap().monthly_bytes,
            MIB - 10
        );
    }
    #[test]
    fn report_json_and_csv_escape_formulas_quotes_and_newlines() {
        assert_eq!(csv_cell("=1+1"), "\"'=1+1\"");
        assert_eq!(csv_cell(" \t@SUM(1)"), "\"' \t@SUM(1)\"");
        assert_eq!(csv_cell("a,\"b\"\n"), "\"a,\"\"b\"\"\n\"");
        let (_dir, history) = history(90);
        history
            .record(
                "profile:tv",
                ts(1),
                UsageCounters {
                    requests: 1,
                    ..UsageCounters::default()
                },
            )
            .unwrap();
        assert!(history.csv().unwrap().contains("\"profile:tv\""));
        let json: serde_json::Value =
            serde_json::from_str(&history.json_report().unwrap()).unwrap();
        assert_eq!(json["healthy"], true);
        assert_eq!(json["rows"][0]["counters"]["requests"], 1);
        assert!(history
            .record("=1+1", ts(1), UsageCounters::default())
            .is_err());
    }
    #[test]
    fn checkpoint_errors_are_exposed_in_report_and_stop_quota_admission() {
        let (dir, history) = history(90);
        fs::create_dir(dir.path().join("history.json")).unwrap();
        assert!(history.checkpoint().is_err());
        assert!(!history.report().healthy);
        assert!(history.reserve("profile:tv", ts(1), 10, 1, 1).is_err());
    }
    #[test]
    fn failed_write_recovers_on_the_next_successful_checkpoint() {
        let (dir, history) = history(90);
        let path = dir.path().join("history.json");
        history
            .record(
                "ip:192.168.1.20",
                ts(1),
                UsageCounters {
                    requests: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        fs::create_dir(&path).unwrap();
        // A failed credit purchase keeps no undurable credit and quotas fail closed.
        assert!(history.reserve("profile:tv", ts(1), 10, 1, 1).is_err());
        assert!(history.report().quota_credits.is_empty());
        assert!(history
            .inner
            .state
            .lock()
            .unwrap()
            .credit_available
            .is_empty());
        assert!(history.checkpoint().is_err());
        assert!(!history.report().healthy);
        assert!(history.prune_at(ts(1)).is_ok());
        assert!(history.reserve("profile:tv", ts(1), 10, 1, 1).is_err());

        fs::remove_dir(&path).unwrap();
        history.prune_at(ts(1)).unwrap();
        history.checkpoint().unwrap();
        let report = history.report();
        assert!(report.healthy);
        assert!(report.quota_credits.is_empty());
        history
            .reserve("profile:tv", ts(1), 10, 1, 1)
            .unwrap()
            .settle(0, 10)
            .unwrap();
        history.checkpoint().unwrap();
        let reopened = UsageHistory::open(path, 90).report();
        assert!(reopened.healthy);
        let json = serde_json::to_value(&reopened).unwrap();
        assert_eq!(json["rows"].as_array().unwrap().len(), 2, "{json}");
    }
    #[test]
    fn failed_credit_top_up_restores_the_previous_durable_credit() {
        let (dir, history) = history(90);
        let path = dir.path().join("history.json");
        let key = ("profile:tv".to_owned(), (ts(1)).div_euclid(86_400));
        // A small daily quota leaves a durable credit pool smaller than one window.
        let first = history.reserve("profile:tv", ts(1), 10, 1, 0).unwrap();
        first.settle(0, 10).unwrap();
        let before = history.inner.state.lock().unwrap().credit_available[&key];
        assert!(before > 0);
        // Force a top-up while writes fail: the previous credit must stay exactly.
        history
            .inner
            .state
            .lock()
            .unwrap()
            .credit_available
            .insert(key.clone(), 1);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(history.reserve("profile:tv", ts(1), 10, 1, 0).is_err());
        assert_eq!(
            history.inner.state.lock().unwrap().credit_available[&key],
            1
        );
        assert!(!history.report().healthy);
    }
    #[test]
    fn failed_maintenance_checkpoint_keeps_issued_credit_durable_after_retry() {
        let (dir, history) = history(90);
        let path = dir.path().join("history.json");
        let key = ("profile:tv".to_owned(), (ts(1)).div_euclid(86_400));
        // Credit is bought and persisted, then the disk fails before maintenance.
        let reservation = history.reserve("profile:tv", ts(1), 10, 1, 0).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        reservation.settle(0, 10).unwrap();
        assert!(history.checkpoint().is_err());
        assert!(!history.report().healthy);
        assert!(history.reserve("profile:tv", ts(1), 10, 1, 0).is_err());

        fs::remove_dir(&path).unwrap();
        history.prune_at(ts(1)).unwrap();
        history.checkpoint().unwrap();
        assert!(history.report().healthy);
        assert!(!history
            .inner
            .state
            .lock()
            .unwrap()
            .credit_available
            .contains_key(&key));
        let reopened = UsageHistory::open(path.clone(), 90);
        let usage = reopened.usage_at("profile:tv", ts(1)).unwrap();
        assert_eq!(usage.daily_bytes, 10);
        // The recovered history keeps admitting within the same quota.
        reopened
            .reserve("profile:tv", ts(1), 10, 1, 0)
            .unwrap()
            .settle(0, 10)
            .unwrap();
        reopened.checkpoint().unwrap();
        assert_eq!(
            UsageHistory::open(path, 90)
                .usage_at("profile:tv", ts(1))
                .unwrap()
                .daily_bytes,
            20
        );
    }
    #[test]
    fn capacity_errors_stay_fail_closed_after_checkpoint() {
        let (_dir, history) = history(90);
        history.inner.state.lock().unwrap().error =
            Some("Historie překročila kapacitu záznamů.".into());
        assert!(history.checkpoint().is_err());
        assert!(history.prune_at(ts(1)).is_err());
        assert!(!history.report().healthy);
    }
}

#[cfg(test)]
mod durability_tests {
    use super::*;
    const MIB: u64 = 1024 * 1024;
    fn ts(day: u8) -> i64 {
        time::Date::from_calendar_date(2026, time::Month::January, day)
            .unwrap()
            .midnight()
            .assume_utc()
            .unix_timestamp()
    }
    fn history() -> (tempfile::TempDir, UsageHistory) {
        let dir = tempfile::tempdir().unwrap();
        let history = UsageHistory::open(dir.path().join("usage.json"), 90);
        (dir, history)
    }
    #[test]
    fn persist_before_credit_and_conservative_reopen_never_reset_issued_bytes() {
        let (dir, history) = history();
        history
            .reserve("profile:tv", ts(1), 16_384, 2, 2)
            .unwrap()
            .settle(0, 16_384)
            .unwrap();
        assert_eq!(history.durable_write_count(), 1);
        // Reopen without checkpoint models abrupt loss of volatile actual counters.
        let reopened = UsageHistory::open(dir.path().join("usage.json"), 90);
        let usage = reopened.usage_at("profile:tv", ts(1)).unwrap();
        assert_eq!(usage.daily_bytes, MIB);
        assert_eq!(usage.monthly_bytes, MIB);
        assert_eq!(reopened.report().rows[0].counters.download_bytes, 0);
        assert_eq!(reopened.report().quota_debts[0].bytes, MIB);
        reopened
            .reserve("profile:tv", ts(1), MIB, 2, 2)
            .unwrap()
            .settle(0, MIB)
            .unwrap();
        let again = UsageHistory::open(dir.path().join("usage.json"), 90);
        assert_eq!(
            again.usage_at("profile:tv", ts(1)).unwrap().monthly_bytes,
            2 * MIB
        );
        assert!(matches!(
            again.reserve("profile:tv", ts(1), 1, 2, 2),
            Err(HistoryError::QuotaExceeded)
        ));
    }
    #[test]
    fn clean_cancel_and_checkpoint_refund_unused_window_instead_of_inventing_traffic() {
        let (dir, history) = history();
        let reservation = history.reserve("profile:tv", ts(1), 16_384, 1, 1).unwrap();
        drop(reservation);
        assert_eq!(
            history.usage_at("profile:tv", ts(1)).unwrap().daily_bytes,
            0
        );
        assert_eq!(history.report().quota_credits[0].bytes, MIB);
        history.checkpoint().unwrap();
        let reopened = UsageHistory::open(dir.path().join("usage.json"), 90);
        assert_eq!(
            reopened.usage_at("profile:tv", ts(1)).unwrap().daily_bytes,
            0
        );
        assert!(reopened.report().quota_debts.is_empty());
        assert!(reopened.report().quota_credits.is_empty());
    }
    #[test]
    fn checkpoint_keeps_in_flight_credit_durable_and_bounds_parallel_windows() {
        let (dir, history) = history();
        let reservation = history.reserve("profile:tv", ts(1), MIB, 4, 4).unwrap();
        assert!(matches!(
            history.reserve("profile:tv", ts(1), 1, 4, 4),
            Err(HistoryError::CreditBusy)
        ));
        assert_eq!(history.durable_write_count(), 1);
        history.checkpoint().unwrap();
        let reopened = UsageHistory::open(dir.path().join("usage.json"), 90);
        assert_eq!(
            reopened.usage_at("profile:tv", ts(1)).unwrap().daily_bytes,
            MIB
        );
        reservation.settle(0, 100).unwrap();
        history.checkpoint().unwrap();
        let reopened = UsageHistory::open(dir.path().join("usage.json"), 90);
        assert_eq!(
            reopened.usage_at("profile:tv", ts(1)).unwrap().daily_bytes,
            100
        );
        assert!(reopened.report().quota_debts.is_empty());
    }
    #[test]
    fn day_rollover_refunds_old_unused_window_without_bypassing_monthly_quota() {
        let (dir, history) = history();
        history
            .reserve("profile:tv", ts(1), 16_384, 1, 1)
            .unwrap()
            .settle(0, 16_384)
            .unwrap();
        let reservation = history.reserve("profile:tv", ts(2), 16_384, 1, 1).unwrap();
        drop(reservation);
        let reopened = UsageHistory::open(dir.path().join("usage.json"), 90);
        let usage = reopened.usage_at("profile:tv", ts(2)).unwrap();
        assert_eq!(usage.monthly_bytes, MIB);
        assert_eq!(usage.daily_bytes, MIB - 16_384);
        assert!(matches!(
            reopened.reserve("profile:tv", ts(2), 1, 1, 1),
            Err(HistoryError::QuotaExceeded)
        ));
        history.checkpoint().unwrap();
        let reopened = UsageHistory::open(dir.path().join("usage.json"), 90);
        assert_eq!(
            reopened
                .usage_at("profile:tv", ts(2))
                .unwrap()
                .monthly_bytes,
            16_384
        );
    }
    #[test]
    fn current_month_crash_debt_survives_one_day_retention_and_clean_checkpoint() {
        let (dir, history) = history();
        history
            .reserve("profile:tv", ts(1), 16_384, 0, 1)
            .unwrap()
            .settle(0, 16_384)
            .unwrap();
        let reopened = UsageHistory::open(dir.path().join("usage.json"), 1);
        reopened.prune_at(ts(3)).unwrap();
        assert!(reopened.report().rows.is_empty());
        assert_eq!(
            reopened
                .usage_at("profile:tv", ts(3))
                .unwrap()
                .monthly_bytes,
            MIB
        );
        assert!(matches!(
            reopened.reserve("profile:tv", ts(3), 1, 0, 1),
            Err(HistoryError::QuotaExceeded)
        ));
        reopened.checkpoint().unwrap();
        let again = UsageHistory::open(dir.path().join("usage.json"), 1);
        assert_eq!(
            again.usage_at("profile:tv", ts(3)).unwrap().monthly_bytes,
            MIB
        );
        let feb = time::Date::from_calendar_date(2026, time::Month::February, 1)
            .unwrap()
            .midnight()
            .assume_utc()
            .unix_timestamp();
        again.prune_at(feb).unwrap();
        assert!(again.report().quota_debts.is_empty());
        assert_eq!(again.usage_at("profile:tv", feb).unwrap().monthly_bytes, 0);
        assert!(again.reserve("profile:tv", feb, 1, 0, 1).is_ok());
    }
    #[test]
    fn quota_refill_fails_before_transfer_when_durable_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let history = UsageHistory::open(dir.path().join("usage.json"), 90);
        fs::create_dir(dir.path().join("usage.json")).unwrap();
        assert!(history.reserve("profile:tv", ts(1), 16_384, 1, 1).is_err());
        assert!(!history.report().healthy);
        assert_eq!(history.report().rows[0].counters.download_bytes, 0);
    }
    #[test]
    fn four_mib_in_sixteen_kib_chunks_requires_four_durable_window_writes() {
        let (_dir, history) = history();
        let started = std::time::Instant::now();
        for _ in 0..256 {
            history
                .reserve("profile:tv", ts(1), 16_384, 5, 5)
                .unwrap()
                .settle(0, 16_384)
                .unwrap();
        }
        let elapsed = started.elapsed();
        assert_eq!(history.durable_write_count(), 4);
        assert_eq!(
            history.usage_at("profile:tv", ts(1)).unwrap().daily_bytes,
            4 * MIB
        );
        history.checkpoint().unwrap();
        assert_eq!(history.durable_write_count(), 5);
        eprintln!(
            "quota credit measurement: 256 chunks / 4MiB, 4 durable window writes, elapsed {:?}",
            elapsed
        );
    }
    #[test]
    #[ignore = "opt-in local performance fixture: fsyncs 20,000 retained rows for 16 MiB of quota-limited transfers"]
    fn large_history_durable_credit_performance_fixture() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.json");
        let timestamp = ts(1);
        let today = timestamp.div_euclid(86_400);
        let mut retained_rows = Vec::with_capacity(20_000);
        let mut retained_months: BTreeMap<(String, i32, u8), UsageCounters> = BTreeMap::new();
        for identity_index in 0..100 {
            let identity = format!("profile:fixture{identity_index}");
            for age in 0..200 {
                let day = today - age;
                let counters = if identity_index == 0 && age == 0 {
                    UsageCounters::default()
                } else {
                    UsageCounters {
                        download_bytes: 4096,
                        requests: 1,
                        ..UsageCounters::default()
                    }
                };
                retained_rows.push(DailyUsage {
                    identity: identity.clone(),
                    day,
                    counters,
                });
                let (year, month) = month_of_day(day).unwrap();
                retained_months
                    .entry((identity.clone(), year, month))
                    .or_default()
                    .add(counters);
            }
        }
        let fixture = StoredHistory {
            version: VERSION,
            rows: retained_rows,
            months: retained_months
                .into_iter()
                .map(|((identity, year, month), counters)| MonthlyUsage {
                    identity,
                    year,
                    month,
                    counters,
                })
                .collect(),
            credits: Vec::new(),
            quota_debts: Vec::new(),
        };
        fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
        let history = UsageHistory::open(&path, 366);
        assert!(history.report().healthy);
        assert_eq!(history.report().rows.len(), 20_000);
        let started = std::time::Instant::now();
        for _ in 0..1024 {
            history
                .reserve("profile:fixture0", timestamp, 16_384, 16, 16)
                .unwrap()
                .settle(0, 16_384)
                .unwrap();
        }
        let transfer_elapsed = started.elapsed();
        assert_eq!(history.durable_write_count(), 16);
        let usage = history.usage_at("profile:fixture0", timestamp).unwrap();
        assert_eq!(usage.daily_bytes, 16 * MIB);
        assert_eq!(usage.monthly_bytes, 16 * MIB);
        assert!(matches!(
            history.reserve("profile:fixture0", timestamp, 1, 16, 16),
            Err(HistoryError::QuotaExceeded)
        ));
        let checkpoint_started = std::time::Instant::now();
        history.checkpoint().unwrap();
        let checkpoint_elapsed = checkpoint_started.elapsed();
        assert_eq!(history.durable_write_count(), 17);
        let reopened = UsageHistory::open(&path, 366);
        let report = reopened.report();
        assert!(report.healthy);
        assert_eq!(report.rows.len(), 20_000);
        assert!(report.quota_debts.is_empty());
        assert!(report.quota_credits.is_empty());
        let actual = report
            .rows
            .iter()
            .find(|row| row.identity == "profile:fixture0" && row.day == today)
            .unwrap();
        assert_eq!(actual.counters.download_bytes, 16 * MIB);
        assert_eq!(actual.counters.upload_bytes, 0);
        assert_eq!(
            reopened
                .usage_at("profile:fixture0", timestamp)
                .unwrap()
                .monthly_bytes,
            16 * MIB
        );
        let file_bytes = fs::metadata(&path).unwrap().len();
        assert!(file_bytes <= MAX_FILE_BYTES);
        eprintln!(
            "local quota credit fixture: rows={}, monthlyRows={}, transferredBytes={}, chunks=1024, durableWindowWrites=16, cleanCheckpoints=1, fileBytes={}, transferElapsed={:?}, checkpointElapsed={:?}",
            report.rows.len(), report.months.len(), 16 * MIB, file_bytes,
            transfer_elapsed, checkpoint_elapsed
        );
    }
    #[test]
    fn identity_and_combined_record_bounds_reject_excess_without_export_growth() {
        let (_dir, history) = history();
        for index in 0..MAX_IDENTITIES {
            history
                .record(
                    &format!("profile:p{index}"),
                    ts(1),
                    UsageCounters::default(),
                )
                .unwrap();
        }
        assert!(history
            .record("profile:overflow", ts(1), UsageCounters::default())
            .is_err());
        assert!(!history.report().healthy);
        let (_dir, history) = self::history();
        {
            let mut state = lock_state(&history.inner).unwrap();
            for index in 0..MAX_ROWS / 2 {
                let id = format!("profile:p{index}");
                state.rows.insert((id.clone(), 0), UsageCounters::default());
                state.months.insert((id, 1970, 1), UsageCounters::default());
            }
            state.last_pruned_day = Some(ts(1).div_euclid(86_400));
        }
        assert!(history
            .record("profile:next", ts(1), UsageCounters::default())
            .is_err());
        assert!(history.report().rows.len() + history.report().months.len() <= MAX_ROWS);
    }
    #[test]
    fn crash_credit_child() {
        let Some(directory) = std::env::var_os("HOMEPROXY_CREDIT_CRASH_DIR") else {
            return;
        };
        let directory = PathBuf::from(directory);
        let address = std::env::var("HOMEPROXY_CREDIT_CRASH_PEER").unwrap();
        let history = UsageHistory::open(directory.join("usage.json"), 90);
        let mut socket = std::net::TcpStream::connect(address).unwrap();
        let data = [0u8; 16_384];
        for _ in 0..32 {
            let reservation = history
                .reserve("profile:tv", ts(1), data.len() as u64, 2, 2)
                .unwrap();
            socket.write_all(&data).unwrap();
            reservation.settle(0, data.len() as u64).unwrap();
        }
        fs::write(directory.join("transmitted"), b"512KiB").unwrap();
        loop {
            std::thread::park();
        }
    }
    #[test]
    fn killed_process_after_real_tcp_transfer_keeps_durable_quota_charge() {
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "usage_history::durability_tests::crash_credit_child",
                "--nocapture",
            ])
            .env("HOMEPROXY_CREDIT_CRASH_DIR", dir.path())
            .env(
                "HOMEPROXY_CREDIT_CRASH_PEER",
                listener.local_addr().unwrap().to_string(),
            )
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(child);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let (mut socket, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "crash child did not connect"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("{error}"),
            }
        };
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut data = vec![0u8; 512 * 1024];
        socket.read_exact(&mut data).unwrap();
        while !dir.path().join("transmitted").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        assert!(!status.success());
        let reopened = UsageHistory::open(dir.path().join("usage.json"), 90);
        assert!(reopened.report().healthy);
        assert_eq!(
            reopened.usage_at("profile:tv", ts(1)).unwrap().daily_bytes,
            MIB
        );
        assert_eq!(reopened.report().rows[0].counters.download_bytes, 0);
        assert_eq!(reopened.report().quota_debts[0].bytes, MIB);
        assert_eq!(data.len(), 512 * 1024);
    }
}
