use crate::config::DnsMode;
use hickory_resolver::{
    config::{LookupIpStrategy, ResolveHosts, ResolverConfig, CLOUDFLARE},
    net::runtime::TokioRuntimeProvider,
};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{net::lookup_host, sync::Mutex as AsyncMutex, time::timeout};
const MAX_ENTRIES: usize = 256;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) fn valid_host(host: &str) -> bool {
    let ip_host = if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    };
    if ip_host.parse::<IpAddr>().is_ok() {
        return true;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

type Answer = Result<Vec<SocketAddr>, &'static str>;
struct Entry {
    answer: Option<(Instant, Answer)>,
}
type Entries = HashMap<(String, u16), Arc<AsyncMutex<Entry>>>;
#[cfg(test)]
type TestAnswers = Arc<Mutex<HashMap<String, (Vec<IpAddr>, Duration)>>>;
#[derive(Clone, Default)]
pub(crate) struct Resolver {
    entries: Arc<Mutex<Entries>>,
    encrypted: Option<Arc<hickory_resolver::TokioResolver>>,
    #[cfg(test)]
    test_dials: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>,
    #[cfg(test)]
    test_answers: TestAnswers,
}
impl Resolver {
    pub fn new(mode: DnsMode) -> Result<Self, &'static str> {
        if mode == DnsMode::System {
            return Ok(Self::default());
        }
        let resolver = encrypted_resolver(ResolverConfig::https(&CLOUDFLARE), None)?;
        Ok(Self {
            entries: Arc::default(),
            encrypted: Some(Arc::new(resolver)),
            #[cfg(test)]
            test_dials: Arc::default(),
            #[cfg(test)]
            test_answers: Arc::default(),
        })
    }
    // Fixture mapping applies only to the final dial, after destination validation.
    #[cfg(test)]
    pub(crate) fn map_test_dial(&self, target: SocketAddr, fixture: SocketAddr) {
        self.test_dials.lock().unwrap().insert(target, fixture);
    }

    #[cfg(test)]
    pub(crate) fn test_datagram_target(&self, target: SocketAddr) -> SocketAddr {
        self.test_dials
            .lock()
            .unwrap()
            .get(&target)
            .copied()
            .unwrap_or(target)
    }

    #[cfg(test)]
    pub(crate) async fn test_dial(
        &self,
        target: SocketAddr,
    ) -> std::io::Result<tokio::net::TcpStream> {
        let address = self
            .test_dials
            .lock()
            .unwrap()
            .get(&target)
            .copied()
            .unwrap_or(target);
        tokio::net::TcpStream::connect(address).await
    }

    #[cfg(test)]
    pub(crate) fn set_test_answer(&self, host: &str, addresses: Vec<IpAddr>, delay: Duration) {
        self.test_answers
            .lock()
            .unwrap()
            .insert(host.to_owned(), (addresses, delay));
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Answer {
        #[cfg(test)]
        {
            let answer = self.test_answers.lock().unwrap().get(host).cloned();
            if let Some((addresses, delay)) = answer {
                tokio::time::sleep(delay).await;
                return Ok(addresses
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect());
            }
        }

        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        if let Some(resolver) = &self.encrypted {
            let fqdn = format!("{}.", host.trim_end_matches('.'));
            return self
                .resolve_with_ttl(host, port, LOOKUP_TIMEOUT, || async {
                    let lookup = resolver.lookup_ip(fqdn).await.map_err(|error| {
                        if error.is_nx_domain() || error.is_no_records_found() {
                            "Šifrované DNS Cloudflare nenašlo hostitele."
                        } else {
                            "Šifrované DNS Cloudflare selhalo; systémové DNS nebylo použito."
                        }
                    })?;
                    let addresses = lookup
                        .iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect::<Vec<_>>();
                    if addresses.len() > 64 {
                        return Err("DNS odpověď má příliš mnoho adres.");
                    }
                    if addresses.is_empty() {
                        return Err("Hostitel nemá žádnou adresu.");
                    }
                    Ok((
                        addresses,
                        lookup
                            .valid_until()
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_secs(30)),
                    ))
                })
                .await
                .map_err(|error| {
                    if error == "Vypršel čas pro DNS." {
                        "Vypršel čas pro šifrované DNS Cloudflare; systémové DNS nebylo použito."
                    } else {
                        error
                    }
                });
        }
        self.resolve_with(host, port, LOOKUP_TIMEOUT, || async {
            let answer = lookup_host((host, port))
                .await
                .map_err(|_| "Hostitele se nepodařilo najít.")?
                .collect::<Vec<_>>();
            if answer.len() > 64 {
                return Err("DNS odpověď má příliš mnoho adres.");
            }
            if answer.is_empty() {
                return Err("Hostitel nemá žádnou adresu.");
            }
            Ok(answer)
        })
        .await
    }
    async fn resolve_with<F, Fut>(
        &self,
        host: &str,
        port: u16,
        deadline: Duration,
        lookup: F,
    ) -> Answer
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Answer>,
    {
        self.resolve_with_ttl(host, port, deadline, || async {
            lookup()
                .await
                .map(|answer| (answer, Duration::from_secs(30)))
        })
        .await
    }
    async fn resolve_with_ttl<F, Fut>(
        &self,
        host: &str,
        port: u16,
        deadline: Duration,
        lookup: F,
    ) -> Answer
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(Vec<SocketAddr>, Duration), &'static str>>,
    {
        let key = (host.to_ascii_lowercase(), port);
        let entry = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if !entries.contains_key(&key) && entries.len() >= MAX_ENTRIES {
                // Never evict an in-flight key: parallel connections must join its lookup.
                if let Some(old) = entries
                    .iter()
                    .find(|(_, value)| Arc::strong_count(value) == 1)
                    .map(|(key, _)| key.clone())
                {
                    entries.remove(&old);
                } else {
                    return Err("DNS resolver je vytížený.");
                }
            }
            entries
                .entry(key)
                .or_insert_with(|| Arc::new(AsyncMutex::new(Entry { answer: None })))
                .clone()
        };
        timeout(deadline, async {
            let mut entry = entry.lock().await;
            if let Some((expiry, answer)) = &entry.answer {
                if *expiry > Instant::now() {
                    return answer.clone();
                }
            }
            let answer = timeout(deadline, lookup())
                .await
                .unwrap_or(Err("Vypršel čas pro DNS."));
            let (answer, ttl) = match answer {
                Ok((addresses, ttl)) => (Ok(addresses), ttl),
                Err(error) => (Err(error), Duration::from_secs(2)),
            };
            entry.answer = Some((Instant::now() + ttl, answer.clone()));
            answer
        })
        .await
        .unwrap_or(Err("Vypršel čas pro DNS."))
    }
}
fn encrypted_resolver(
    config: ResolverConfig,
    tls: Option<rustls::ClientConfig>,
) -> Result<hickory_resolver::TokioResolver, &'static str> {
    let mut builder =
        hickory_resolver::Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    if let Some(tls) = tls {
        builder = builder.with_tls_config(tls);
    }
    let options = builder.options_mut();
    options.use_hosts_file = ResolveHosts::Never;
    options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    options.cache_size = 0; // The outer bounded single-flight cache retains provider TTLs.
    options.positive_max_ttl = Some(Duration::from_secs(30));
    options.negative_max_ttl = Some(Duration::from_secs(2));
    options.timeout = Duration::from_secs(3);
    options.attempts = 1;
    options.num_concurrent_reqs = 2;
    options.max_active_requests = 32;
    // No search domains, discovery, opportunistic encryption or unencrypted fallback.
    builder
        .build()
        .map_err(|_| "Šifrované DNS Cloudflare nelze připravit.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test]
    async fn dns_cold_warm_singleflight_and_errors_are_bounded() {
        let resolver = Resolver::default();
        let calls = AtomicUsize::new(0);
        let lookup = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(vec!["93.184.216.34:443".parse().unwrap()])
        };
        let (a, b) = tokio::join!(
            resolver.resolve_with("example.test", 443, LOOKUP_TIMEOUT, lookup),
            resolver.resolve_with("example.test", 443, LOOKUP_TIMEOUT, lookup)
        );
        assert_eq!(a, b);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(resolver
            .resolve_with("example.test", 443, LOOKUP_TIMEOUT, || async {
                panic!("warm cache must not query")
            })
            .await
            .is_ok());
        let failure = resolver
            .resolve_with("missing.test", 443, LOOKUP_TIMEOUT, || async {
                Err("not found")
            })
            .await;
        assert_eq!(failure, Err("not found"));
        assert_eq!(
            resolver
                .resolve_with("missing.test", 443, LOOKUP_TIMEOUT, || async {
                    panic!("negative cache")
                })
                .await,
            failure
        );
        assert_eq!(
            resolver
                .resolve_with(
                    "slow.test",
                    443,
                    Duration::from_millis(5),
                    std::future::pending
                )
                .await,
            Err("Vypršel čas pro DNS.")
        );
        for n in 0..300 {
            let _ = resolver
                .resolve_with(&format!("{n}.test"), 443, LOOKUP_TIMEOUT, || async {
                    Err("missing")
                })
                .await;
        }
        assert!(resolver.entries.lock().unwrap().len() <= MAX_ENTRIES);
        assert_eq!(
            resolver.resolve("127.0.0.1", 123).await.unwrap(),
            vec!["127.0.0.1:123".parse().unwrap()]
        );
    }
}

#[cfg(test)]
mod doh_tests;
