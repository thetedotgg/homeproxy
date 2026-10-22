//! Optional LAN DNS forwarding. It filters DNS names only and never configures a router.
use crate::{
    config::{CacheMode, Settings},
    policy::{decision_at, resolve_profile, QuotaUsage},
};
use hickory_resolver::proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::DNSClass,
};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
const MAX_PACKET: usize = 4096;
const MAX_CACHE: usize = 512;
const MAX_ACTIVE: usize = 32;
#[derive(Default)]
pub(crate) struct AnswerCache {
    generation: u64,
    entries: HashMap<Vec<u8>, (Instant, Duration, Message)>,
}
impl AnswerCache {
    pub(crate) fn clear(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.entries.clear();
    }
}
pub(crate) type Answers = Arc<Mutex<AnswerCache>>;
pub(crate) struct LanDnsHandle {
    token: CancellationToken,
    join: JoinHandle<()>,
}
impl LanDnsHandle {
    pub(crate) async fn stop(self) {
        self.token.cancel();
        let mut join = self.join;
        if timeout(Duration::from_secs(2), &mut join).await.is_err() {
            join.abort();
        }
    }
}
pub(crate) async fn start(
    settings: Settings,
    parent: &CancellationToken,
    answers: Answers,
) -> io::Result<Option<LanDnsHandle>> {
    if !settings.lan_dns_enabled {
        return Ok(None);
    }
    let ips: Vec<Ipv4Addr> = if settings.lan_enabled {
        settings.selected_listen_ips().map_err(io::Error::other)?
    } else {
        vec![Ipv4Addr::LOCALHOST]
    };
    let mut listeners = Vec::new();
    for ip in ips {
        let addr = SocketAddr::new(IpAddr::V4(ip), settings.lan_dns_port);
        let udp = Arc::new(UdpSocket::bind(addr).await?);
        let tcp = TcpListener::bind(addr).await?;
        listeners.push((udp, tcp));
    }
    let token = parent.child_token();
    let failure_parent = parent.clone();
    let run_token = token.clone();
    let settings = Arc::new(settings);
    let join = tokio::spawn(async move {
        let slots = Arc::new(Semaphore::new(MAX_ACTIVE));
        let mut tasks = JoinSet::new();
        for (udp, tcp) in listeners {
            let s = settings.clone();
            let a = answers.clone();
            let p = slots.clone();
            let t = run_token.clone();
            tasks.spawn(async move {
                serve_udp(udp, s, a, p, t).await;
            });
            let s = settings.clone();
            let a = answers.clone();
            let p = slots.clone();
            let t = run_token.clone();
            tasks.spawn(async move {
                serve_tcp(tcp, s, a, p, t).await;
            });
        }
        tokio::select! {_=run_token.cancelled()=>{},_=tasks.join_next()=>{run_token.cancel();failure_parent.cancel();}}
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    });
    Ok(Some(LanDnsHandle { token, join }))
}
fn allowed_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || crate::config::is_private_lan_ip(ip),
        IpAddr::V6(_) => false,
    }
}
async fn serve_udp(
    socket: Arc<UdpSocket>,
    settings: Arc<Settings>,
    answers: Answers,
    slots: Arc<Semaphore>,
    token: CancellationToken,
) {
    let mut buf = [0u8; MAX_PACKET + 1];
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _=token.cancelled()=>break,
            result=socket.recv_from(&mut buf)=>{let Ok((len,peer))=result else{break};if len>MAX_PACKET||!allowed_peer(peer.ip()){continue}
              let Ok(permit)=slots.clone().try_acquire_owned()else{continue};let packet=buf[..len].to_vec();let socket=socket.clone();let s=settings.clone();let a=answers.clone();let t=token.clone();
        tasks.spawn(async move{let _permit=permit;tokio::select!{_=t.cancelled()=>{},response=answer(&packet,peer.ip(),&s,&a,false)=>{if let Some(response)=response{let _=socket.send_to(&response,peer).await;}}}});
            },
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{}
          }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
async fn serve_tcp(
    listener: TcpListener,
    settings: Arc<Settings>,
    answers: Answers,
    slots: Arc<Semaphore>,
    token: CancellationToken,
) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
          _=token.cancelled()=>break,
          result=listener.accept()=>{let Ok((socket,peer))=result else{break};if !allowed_peer(peer.ip()){continue}let Ok(permit)=slots.clone().try_acquire_owned()else{continue};let s=settings.clone();let a=answers.clone();let t=token.clone();tasks.spawn(async move{let _permit=permit;tokio::select!{_=t.cancelled()=>{},_=tcp_session(socket,peer.ip(),s,a)=>{}}});},
          Some(_)=tasks.join_next(),if !tasks.is_empty()=>{}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
async fn tcp_session(
    mut socket: TcpStream,
    peer: IpAddr,
    settings: Arc<Settings>,
    answers: Answers,
) {
    for _ in 0..64 {
        let Ok(Ok(len)) = timeout(Duration::from_secs(5), socket.read_u16()).await else {
            return;
        };
        if len == 0 || usize::from(len) > MAX_PACKET {
            return;
        }
        let mut packet = vec![0; usize::from(len)];
        if !matches!(
            timeout(Duration::from_secs(5), socket.read_exact(&mut packet)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        let Some(response) = answer(&packet, peer, &settings, &answers, true).await else {
            return;
        };
        if !matches!(
            timeout(Duration::from_secs(5), async {
                socket.write_u16(response.len() as u16).await?;
                socket.write_all(&response).await
            })
            .await,
            Ok(Ok(()))
        ) {
            return;
        }
    }
}
fn failure(query: &Message, code: ResponseCode) -> Option<Vec<u8>> {
    let mut response = Message::error_msg(query.metadata.id, OpCode::Query, code);
    response.queries = query.queries.clone();
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.to_vec().ok()
}
async fn answer(
    packet: &[u8],
    peer: IpAddr,
    settings: &Settings,
    answers: &Answers,
    tcp: bool,
) -> Option<Vec<u8>> {
    let query = Message::from_vec(packet).ok()?;
    if query.metadata.message_type != MessageType::Query
        || query.metadata.op_code != OpCode::Query
        || query.queries.len() != 1
        || query.queries[0].query_class != DNSClass::IN
        || !query.answers.is_empty()
        || !query.authorities.is_empty()
        || !query.additionals.is_empty()
        || query.signature.is_some()
    {
        return failure(&query, ResponseCode::FormErr);
    }
    let host = query.queries[0]
        .name
        .to_utf8()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !crate::config::valid_policy_host(&host, false) {
        return failure(&query, ResponseCode::FormErr);
    }
    if let IpAddr::V4(ip) = peer {
        if settings.denied_client_ips.contains(&ip) {
            return failure(&query, ResponseCode::Refused);
        }
        let profile = resolve_profile(settings, None, ip);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
        if !decision_at(
            settings,
            profile.map(|p| p.id.as_str()),
            &host,
            now,
            QuotaUsage::default(),
        )
        .allowed
        {
            return failure(&query, ResponseCode::Refused);
        }
    }
    let mut key_query = query.clone();
    key_query.metadata.id = 0;
    let mut key = settings.lan_dns_upstream.to_string().into_bytes();
    key.push(0);
    key.extend(key_query.to_vec().ok()?);
    let generation = {
        let mut cache = answers.lock().ok()?;
        cache.entries.retain(|_, (at, ttl, _)| at.elapsed() < *ttl);
        if let Some((at, _, cached)) = cache.entries.get(&key) {
            let mut response = cached.clone();
            response.metadata.id = query.metadata.id;
            let elapsed = at.elapsed().as_secs() as u32;
            for record in response
                .answers
                .iter_mut()
                .chain(&mut response.authorities)
                .chain(&mut response.additionals)
            {
                record.ttl = record.ttl.saturating_sub(elapsed)
            }
            return encode_reply(&query, response, tcp);
        }
        cache.generation
    };
    if settings.cache_mode == CacheMode::Offline {
        return failure(&query, ResponseCode::ServFail);
    }
    let fetched = timeout(Duration::from_secs(2), async {
        let bind = if settings.lan_dns_upstream.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(settings.lan_dns_upstream).await?;
        socket.send(packet).await?;
        let mut buf = [0u8; MAX_PACKET + 1];
        let len = socket.recv(&mut buf).await?;
        if len > MAX_PACKET {
            return Err(io::Error::other("Oversized DNS answer"));
        }
        let response = Message::from_vec(&buf[..len]).map_err(io::Error::other)?;
        if response.metadata.truncation {
            let mut stream = TcpStream::connect(settings.lan_dns_upstream).await?;
            stream.write_u16(packet.len() as u16).await?;
            stream.write_all(packet).await?;
            let len = usize::from(stream.read_u16().await?);
            if len > MAX_PACKET {
                return Err(io::Error::other("Oversized TCP DNS answer"));
            }
            let mut bytes = vec![0; len];
            stream.read_exact(&mut bytes).await?;
            return Message::from_vec(&bytes).map_err(io::Error::other);
        }
        Ok(response)
    })
    .await;
    let Ok(Ok(response)) = fetched else {
        return failure(&query, ResponseCode::ServFail);
    };
    if response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != OpCode::Query
        || response.metadata.id != query.metadata.id
        || response.queries != query.queries
        || response.signature.is_some()
        || response.answers.len() + response.authorities.len() + response.additionals.len() > 128
    {
        return failure(&query, ResponseCode::ServFail);
    }
    if response.metadata.response_code == ResponseCode::NoError
        && !response.metadata.truncation
        && !response.answers.is_empty()
    {
        let ttl = response
            .answers
            .iter()
            .chain(&response.authorities)
            .chain(&response.additionals)
            .map(|r| r.ttl)
            .min()
            .unwrap_or(0)
            .min(3600);
        if ttl > 0 {
            if let Ok(mut cache) = answers.lock() {
                // A reply started before clear may reach its caller, but cannot refill storage.
                if cache.generation != generation {
                    return encode_reply(&query, response, tcp);
                }
                if cache.entries.len() >= MAX_CACHE {
                    if let Some(oldest) = cache
                        .entries
                        .iter()
                        .min_by_key(|(_, v)| v.0)
                        .map(|(k, _)| k.clone())
                    {
                        cache.entries.remove(&oldest);
                    }
                }
                cache.entries.insert(
                    key,
                    (
                        Instant::now(),
                        Duration::from_secs(u64::from(ttl)),
                        response.clone(),
                    ),
                );
            }
        }
    }
    encode_reply(&query, response, tcp)
}
fn encode_reply(query: &Message, response: Message, tcp: bool) -> Option<Vec<u8>> {
    let max_reply = query
        .edns
        .as_ref()
        .map(|e| usize::from(e.max_payload()))
        .unwrap_or(512)
        .clamp(512, MAX_PACKET);
    let bytes = response.to_vec().ok()?;
    if bytes.len() <= max_reply || tcp && bytes.len() <= MAX_PACKET {
        return Some(bytes);
    }
    let mut truncated = Message::response(query.metadata.id, OpCode::Query);
    truncated.queries = query.queries.clone();
    truncated.metadata.truncation = true;
    truncated.metadata.recursion_available = true;
    truncated.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::{
        op::Query,
        rr::{rdata::A, Name, RData, Record, RecordType},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    fn packet(host: &str, id: u16) -> Vec<u8> {
        let mut m = Message::new(id, MessageType::Query, OpCode::Query);
        m.queries
            .push(Query::query(Name::from_ascii(host).unwrap(), RecordType::A));
        m.to_vec().unwrap()
    }
    async fn fixture() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let handle = tokio::spawn(async move {
            let mut buf = [0; MAX_PACKET];
            loop {
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let q = Message::from_vec(&buf[..len]).unwrap();
                let mut r = Message::response(q.metadata.id, OpCode::Query);
                r.queries = q.queries.clone();
                r.answers.push(Record::from_rdata(
                    q.queries[0].name.clone(),
                    60,
                    RData::A(A("203.0.113.10".parse().unwrap())),
                ));
                socket.send_to(&r.to_vec().unwrap(), peer).await.unwrap();
            }
        });
        (addr, calls, handle)
    }
    #[tokio::test]
    async fn clear_during_dns_fetch_cannot_refill_the_offline_cache() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let settings = Settings {
            lan_dns_upstream: upstream.local_addr().unwrap(),
            ..Settings::default()
        };
        let directory = tempfile::tempdir().unwrap();
        let store = crate::cache::CacheStore::new(directory.path().join("cache"));
        let answers = store.dns_answers();
        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let origin = tokio::spawn(async move {
            let mut buf = [0; MAX_PACKET];
            let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let query = Message::from_vec(&buf[..len]).unwrap();
            received_tx.send(()).unwrap();
            release_rx.await.unwrap();
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.queries = query.queries.clone();
            response.answers.push(Record::from_rdata(
                query.queries[0].name.clone(),
                60,
                RData::A(A("203.0.113.10".parse().unwrap())),
            ));
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let pending_settings = settings.clone();
        let pending_answers = answers.clone();
        let pending = tokio::spawn(async move {
            answer(
                &packet("example.org", 1),
                "192.168.1.2".parse().unwrap(),
                &pending_settings,
                &pending_answers,
                false,
            )
            .await
            .unwrap()
        });
        received_rx.await.unwrap();
        store.clear().await.unwrap();
        release_tx.send(()).unwrap();
        assert_eq!(
            Message::from_vec(&pending.await.unwrap())
                .unwrap()
                .answers
                .len(),
            1
        );
        origin.await.unwrap();
        let offline = Settings {
            cache_mode: CacheMode::Offline,
            ..settings
        };
        let miss = answer(
            &packet("example.org", 2),
            "192.168.1.2".parse().unwrap(),
            &offline,
            &answers,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            Message::from_vec(&miss).unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
        assert!(answers.lock().unwrap().entries.is_empty());
    }
    #[tokio::test]
    async fn cached_dns_offline_miss_and_block_never_reach_upstream() {
        let (upstream, calls, task) = fixture().await;
        let mut settings = Settings {
            lan_dns_upstream: upstream,
            ..Settings::default()
        };
        let answers: Answers = Arc::default();
        let peer = "192.168.1.30".parse().unwrap();
        let response = answer(&packet("example.org", 1), peer, &settings, &answers, false)
            .await
            .unwrap();
        assert_eq!(Message::from_vec(&response).unwrap().answers.len(), 1);
        settings.cache_mode = CacheMode::Offline;
        let hit = Message::from_vec(
            &answer(&packet("example.org", 2), peer, &settings, &answers, false)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(hit.metadata.id, 2);
        assert_eq!(hit.answers.len(), 1);
        let miss = Message::from_vec(
            &answer(
                &packet("missing.example", 3),
                peer,
                &settings,
                &answers,
                false,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert_eq!(miss.metadata.response_code, ResponseCode::ServFail);
        settings.cache_mode = CacheMode::Online;
        settings.block_domains = vec!["*.example.org".into()];
        let blocked = Message::from_vec(
            &answer(
                &packet("ads.example.org", 4),
                peer,
                &settings,
                &answers,
                false,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert_eq!(blocked.metadata.response_code, ResponseCode::Refused);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        task.abort();
    }
    #[tokio::test]
    async fn udp_and_tcp_listeners_serve_real_queries_and_stop() {
        let (upstream, calls, task) = fixture().await;
        let port = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let settings = Settings {
            lan_dns_enabled: true,
            lan_dns_port: port,
            lan_dns_upstream: upstream,
            ..Settings::default()
        };
        let token = CancellationToken::new();
        let handle = start(settings, &token, Arc::default())
            .await
            .unwrap()
            .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(
                &packet("example.org", 20),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            )
            .await
            .unwrap();
        let mut buf = [0; MAX_PACKET];
        let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Message::from_vec(&buf[..len]).unwrap().metadata.id, 20);
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let q = packet("example.org", 21);
        stream.write_u16(q.len() as u16).await.unwrap();
        stream.write_all(&q).await.unwrap();
        let len = stream.read_u16().await.unwrap();
        let mut response = vec![0; usize::from(len)];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(Message::from_vec(&response).unwrap().metadata.id, 21);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        handle.stop().await;
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_err());
        task.abort();
    }
    #[tokio::test]
    async fn malformed_update_queries_are_rejected_before_dial() {
        let settings = Settings::default();
        let answers: Answers = Arc::default();
        let mut query = Message::new(2, MessageType::Query, OpCode::Update);
        query.queries.push(Query::query(
            Name::from_ascii("example.org").unwrap(),
            RecordType::A,
        ));
        let bytes = answer(
            &query.to_vec().unwrap(),
            "192.168.1.2".parse().unwrap(),
            &settings,
            &answers,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            Message::from_vec(&bytes).unwrap().metadata.response_code,
            ResponseCode::FormErr
        );
        assert!(!allowed_peer("8.8.8.8".parse().unwrap()));
    }
}
