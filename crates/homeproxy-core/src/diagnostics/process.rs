//! Allowlisted process resource facts. Never read command lines or environment.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProcessFacts {
    pub pid: u32,
    pub uptime_ms: u64,
    pub open_files: Option<u64>,
    pub open_files_soft_limit: Option<u64>,
    pub resident_memory_kib: Option<u64>,
    pub threads: Option<u64>,
}

impl ProcessFacts {
    pub(super) fn collect(started: std::time::Instant) -> Self {
        let value = Self {
            pid: std::process::id(),
            uptime_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            ..Self::default()
        };
        #[cfg(target_os = "linux")]
        {
            let mut value = value;
            value.open_files = std::fs::read_dir("/proc/self/fd")
                .ok()
                .and_then(|entries| entries.take(65_537).collect::<Result<Vec<_>, _>>().ok())
                .filter(|entries| entries.len() <= 65_536)
                .map(|entries| entries.len() as u64);
            if let Some(status) = read_limited("/proc/self/status") {
                for line in status.lines() {
                    if let Some(rest) = line.strip_prefix("VmRSS:") {
                        value.resident_memory_kib =
                            rest.split_whitespace().next().and_then(|s| s.parse().ok());
                    } else if let Some(rest) = line.strip_prefix("Threads:") {
                        value.threads = rest.trim().parse().ok();
                    }
                }
            }
            if let Some(limits) = read_limited("/proc/self/limits") {
                value.open_files_soft_limit = limits
                    .lines()
                    .find_map(|line| line.strip_prefix("Max open files"))
                    .and_then(|line| line.split_whitespace().next())
                    .and_then(|s| s.parse().ok());
            }
            value
        }
        #[cfg(not(target_os = "linux"))]
        value
    }
}

#[cfg(target_os = "linux")]
fn read_limited(path: &str) -> Option<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(16_384)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_facts_use_own_process_and_only_numeric_fields() {
        let facts = ProcessFacts::collect(std::time::Instant::now());
        assert_eq!(facts.pid, std::process::id());
        let json = serde_json::to_value(facts).unwrap();
        assert!(json
            .as_object()
            .unwrap()
            .values()
            .all(|value| value.is_number() || value.is_null()));
        #[cfg(target_os = "linux")]
        assert!(json["openFiles"].as_u64().unwrap() > 0);
    }
}
