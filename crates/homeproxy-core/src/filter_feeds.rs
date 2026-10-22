//! Explicit imports of trusted, domain-only filter files. No network updater or URL filtering.
use crate::config::valid_policy_host;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_FILTER_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_FEEDS: usize = 8;
const MAX_RULES: usize = 10_000;
// Leaves room for the import envelope inside the existing 256 KiB request bound.
const MAX_SERIALIZED_FEEDS_BYTES: usize = 192 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilterFeed {
    pub id: String,
    pub name: String,
    pub domains_sorted_exact: Vec<String>,
    /// Domain-anchored `||domain^` rules match the domain itself and its subdomains.
    pub domains_sorted_wildcard: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum FilterFeedError {
    #[error("Název filtru musí mít 1–80 znaků bez řídicích znaků.")]
    Name,
    #[error("Soubor filtru překračuje povolenou velikost 2 MiB.")]
    FileTooLarge,
    #[error("Řádek {0}: nepodporované pravidlo. Použijte domény, hosts nebo ||domain^ bez dalších voleb.")]
    UnsupportedLine(usize),
    #[error("Filtr neobsahuje žádné platné domény.")]
    Empty,
    #[error("Lze uložit nejvýše 8 filtrů a celkem 10 000 domén v omezené velikosti konfigurace.")]
    Capacity,
    #[error("Importovaný filtr má neplatný identifikátor nebo neuspořádaná pravidla.")]
    Invalid,
}

fn feed_id(name: &str) -> String {
    format!(
        "feed-{}",
        hex::encode(&Sha256::digest(name.to_lowercase().as_bytes())[..16])
    )
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name == name.trim()
        && name.chars().count() <= 80
        && name.len() <= 256
        && !name.chars().any(char::is_control)
}

fn normalized_domain(domain: &str) -> Option<String> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    (valid_policy_host(&domain, false)
        && domain.contains('.')
        && domain.parse::<std::net::IpAddr>().is_err())
    .then_some(domain)
}

impl FilterFeed {
    pub fn parse(name: &str, text: &str) -> Result<Self, FilterFeedError> {
        let name = name.trim();
        if !valid_name(name) {
            return Err(FilterFeedError::Name);
        }
        if text.len() > MAX_FILTER_FILE_BYTES {
            return Err(FilterFeedError::FileTooLarge);
        }
        let mut exact = BTreeSet::new();
        let mut wildcard = BTreeSet::new();
        for (index, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
            let line = line.trim();
            if line.starts_with("##") || line.starts_with("#@#") {
                return Err(FilterFeedError::UnsupportedLine(index + 1));
            }
            if line.is_empty() || line.starts_with(['#', '!']) || line == "[Adblock Plus 2.0]" {
                continue;
            }
            if line.contains("##") || line.contains("#@#") {
                return Err(FilterFeedError::UnsupportedLine(index + 1));
            }
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(domain) = line
                .strip_prefix("||")
                .and_then(|line| line.strip_suffix('^'))
            {
                wildcard.insert(
                    normalized_domain(domain).ok_or(FilterFeedError::UnsupportedLine(index + 1))?,
                );
            } else {
                let mut fields = line.split_ascii_whitespace();
                let first = fields.next().unwrap();
                let hosts = matches!(first, "0.0.0.0" | "127.0.0.1");
                let domains: Vec<&str> = if hosts {
                    fields.collect()
                } else {
                    if fields.next().is_some() {
                        return Err(FilterFeedError::UnsupportedLine(index + 1));
                    }
                    vec![first]
                };
                if domains.is_empty() {
                    return Err(FilterFeedError::UnsupportedLine(index + 1));
                }
                for domain in domains {
                    if hosts
                        && matches!(
                            domain,
                            "localhost" | "localhost.localdomain" | "broadcasthost"
                        )
                    {
                        continue;
                    }
                    exact.insert(
                        normalized_domain(domain)
                            .ok_or(FilterFeedError::UnsupportedLine(index + 1))?,
                    );
                }
            }
            if exact.len() + wildcard.len() > MAX_RULES {
                return Err(FilterFeedError::Capacity);
            }
        }
        if exact.is_empty() && wildcard.is_empty() {
            return Err(FilterFeedError::Empty);
        }
        let feed = Self {
            id: feed_id(name),
            name: name.into(),
            domains_sorted_exact: exact.into_iter().collect(),
            domains_sorted_wildcard: wildcard.into_iter().collect(),
        };
        validate_feeds(std::slice::from_ref(&feed))?;
        Ok(feed)
    }

    pub fn matches_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if self.domains_sorted_exact.binary_search(&host).is_ok() {
            return true;
        }
        let mut suffix = host.as_str();
        loop {
            if self
                .domains_sorted_wildcard
                .binary_search_by(|rule| rule.as_str().cmp(suffix))
                .is_ok()
            {
                return true;
            }
            let Some((_, next)) = suffix.split_once('.') else {
                return false;
            };
            suffix = next;
        }
    }
}

pub fn validate_feeds(feeds: &[FilterFeed]) -> Result<(), FilterFeedError> {
    if feeds.len() > MAX_FEEDS {
        return Err(FilterFeedError::Capacity);
    }
    let mut ids = BTreeSet::new();
    let mut count = 0usize;
    for feed in feeds {
        if !valid_name(&feed.name) || feed.id != feed_id(&feed.name) || !ids.insert(&feed.id) {
            return Err(FilterFeedError::Invalid);
        }
        for rules in [&feed.domains_sorted_exact, &feed.domains_sorted_wildcard] {
            if rules.windows(2).any(|pair| pair[0] >= pair[1])
                || rules
                    .iter()
                    .any(|rule| normalized_domain(rule).as_ref() != Some(rule))
            {
                return Err(FilterFeedError::Invalid);
            }
            count += rules.len();
        }
        if feed.domains_sorted_exact.is_empty() && feed.domains_sorted_wildcard.is_empty() {
            return Err(FilterFeedError::Empty);
        }
    }
    if count > MAX_RULES
        || serde_json::to_vec(feeds)
            .map_err(|_| FilterFeedError::Invalid)?
            .len()
            > MAX_SERIALIZED_FEEDS_BYTES
    {
        return Err(FilterFeedError::Capacity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trusted_hosts_and_domain_rules_are_normalized_deduplicated_and_sorted() {
        let feed = FilterFeed::parse("Domácí", "# source\n127.0.0.1 localhost\n0.0.0.0 Z.ads.example a.ads.example # note\na.ads.example\n||Tracking.example^\n").unwrap();
        assert_eq!(
            feed.domains_sorted_exact,
            vec!["a.ads.example", "z.ads.example"]
        );
        assert!(feed.matches_host("Z.ADS.EXAMPLE."));
        assert!(!feed.matches_host("sub.z.ads.example"));
        assert!(feed.matches_host("tracking.example") && feed.matches_host("a.tracking.example"));
        assert!(
            !feed.matches_host("eviltracking.example")
                && !feed.matches_host("tracking.example.evil")
        );
    }
    #[test]
    fn browser_filters_regex_and_exceptions_are_explicitly_rejected() {
        for rule in [
            "/ads[0-9]/",
            "##.ad",
            "||ads.example^$third-party",
            "@@||ads.example^",
            "example.com##.ad",
            "https://ads.example/",
            "*.example.com",
            "ads.example extra",
            "0.0.0.0",
            "0.0.0.0 bad_host",
        ] {
            assert!(
                matches!(
                    FilterFeed::parse("feed", &format!("valid.example\n{rule}")),
                    Err(FilterFeedError::UnsupportedLine(2))
                ),
                "{rule}"
            );
        }
    }
    #[test]
    fn validation_rejects_duplicate_feeds_unsorted_or_noncanonical_wire_rules() {
        let mut feed = FilterFeed::parse("feed", "a.example\nz.example").unwrap();
        assert!(validate_feeds(&[feed.clone(), feed.clone()]).is_err());
        feed.domains_sorted_exact.reverse();
        assert!(validate_feeds(&[feed]).is_err());
        assert!(FilterFeed::parse("bad\nname", "a.example").is_err());
        assert!(FilterFeed::parse("feed", &"x".repeat(MAX_FILTER_FILE_BYTES + 1)).is_err());
    }

    #[test]
    fn imported_filters_respect_adblock_off_allow_and_explicit_deny_precedence() {
        let mut settings = crate::config::Settings::default();
        settings
            .filter_feeds
            .push(FilterFeed::parse("feed", "||imported.example^").unwrap());
        let decide = |settings: &crate::config::Settings| {
            crate::policy::decision_at(
                settings,
                None,
                "sub.imported.example",
                0,
                crate::policy::QuotaUsage::default(),
            )
        };
        assert!(!decide(&settings).allowed);
        settings.allow_domains.push("*.imported.example".into());
        assert!(decide(&settings).allowed);
        settings.block_domains.push("sub.imported.example".into());
        assert_eq!(
            decide(&settings).reason,
            crate::policy::PolicyReason::ExplicitDeny
        );
        settings.allow_domains.clear();
        settings.block_domains.clear();
        settings.adblock_mode = crate::config::AdblockMode::Off;
        assert!(decide(&settings).allowed);
    }

    #[test]
    fn import_and_aggregate_capacity_are_bounded_before_persistence() {
        let text = (0..MAX_RULES + 1)
            .map(|number| format!("a{number}.example\n"))
            .collect::<String>();
        assert!(matches!(
            FilterFeed::parse("large", &text),
            Err(FilterFeedError::Capacity)
        ));
        let feeds = (0..9)
            .map(|number| FilterFeed::parse(&format!("feed-{number}"), "a.example").unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            validate_feeds(&feeds),
            Err(FilterFeedError::Capacity)
        ));
    }
}
