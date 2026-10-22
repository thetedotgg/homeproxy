use super::*;
use hickory_resolver::{
    config::NameServerConfig,
    proto::{
        op::{Message, ResponseCode},
        rr::{
            rdata::{A, AAAA, CNAME},
            Name, RData, Record, RecordType,
        },
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

struct Fixture {
    resolver: Resolver,
    calls: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new(trust_certificate: bool) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["cloudflare-dns.com".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let mut server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut nameserver = NameServerConfig::https(
            "127.0.0.1".parse().unwrap(),
            "cloudflare-dns.com".into(),
            Some("/dns-query".into()),
        );
        nameserver.connections[0].port = listener.local_addr().unwrap().port();
        let mut roots = rustls::RootCertStore::empty();
        if trust_certificate {
            roots.add(cert.der().clone()).unwrap();
        }
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let resolver = Resolver {
            test_dials: Arc::default(),
            test_answers: Arc::default(),
            entries: Arc::default(),
            encrypted: Some(Arc::new(
                encrypted_resolver(
                    ResolverConfig::from_name_servers(vec![nameserver]),
                    Some(tls),
                )
                .unwrap(),
            )),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let task = tokio::spawn({
            let calls = calls.clone();
            let connections = connections.clone();
            let cancel = cancel.clone();
            async move {
                let mut children = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        accepted = listener.accept() => {
                            let (stream,_) = accepted.unwrap();
                            let acceptor=acceptor.clone(); let calls=calls.clone(); let connections=connections.clone();
                            children.spawn(async move {
                                let Ok(tls) = acceptor.accept(stream).await else { return; };
                                let mut h2 = h2::server::handshake(tls).await.unwrap();
                                connections.fetch_add(1,Ordering::SeqCst);
                                while let Some(Ok((request,mut response))) = h2.accept().await {
                                    assert_eq!(request.uri().path(),"/dns-query");
                                    let calls=calls.clone();
                                    tokio::spawn(async move {
                                        let mut body=request.into_body(); let mut wire=Vec::new();
                                        while let Some(chunk)=body.data().await { let chunk=chunk.unwrap(); body.flow_control().release_capacity(chunk.len()).unwrap(); wire.extend_from_slice(&chunk); }
                                        let request=Message::from_vec(&wire).unwrap();
                                        calls.fetch_add(1,Ordering::SeqCst);
                                        let query=request.queries[0].clone();
                                        let mut answer=Message::response(request.metadata.id,request.metadata.op_code);
                                        answer.queries=request.queries;
                                        answer.metadata.recursion_available=true;
                                        let host=query.name().to_ascii();
                                        if host=="slow.test." { tokio::time::sleep(Duration::from_secs(7)).await; return; }
                                        if host=="missing.test." { answer.metadata.response_code=ResponseCode::NXDomain; }
                                        else {
                                            let alias=Name::from_ascii("target.test.").unwrap();
                                            answer.answers.push(Record::from_rdata(query.name().clone(),1,RData::CNAME(CNAME(alias.clone()))));
                                            let data=match query.query_type() {
                                                RecordType::A => RData::A(A(if host=="reserved.test." { "192.0.0.88" } else { "93.184.216.34" }.parse().unwrap())),
                                                RecordType::AAAA => RData::AAAA(AAAA("2606:4700::1111".parse().unwrap())),
                                                other => panic!("unexpected {other:?}"),
                                            };
                                            answer.answers.push(Record::from_rdata(alias,1,data));
                                        }
                                        let response_head=http::Response::builder().status(200).header("content-type","application/dns-message").body(()).unwrap();
                                        if let Ok(mut stream)=response.send_response(response_head,false) { let _=stream.send_data(bytes::Bytes::from(answer.to_vec().unwrap()),true); }
                                    });
                                }
                                connections.fetch_sub(1,Ordering::SeqCst);
                            });
                        }
                    }
                }
                children.abort_all();
                while children.join_next().await.is_some() {}
            }
        });
        Self {
            resolver,
            calls,
            connections,
            cancel,
            task,
        }
    }
    async fn stop(self) {
        self.cancel.cancel();
        self.task.await.unwrap();
    }
}

#[tokio::test]
async fn doh_tls_h2_cname_dual_stack_ttl_negative_and_drop() {
    let fixture = Fixture::new(true).await;
    let addresses = fixture.resolver.resolve("public.test", 443).await.unwrap();
    assert!(addresses.contains(&"93.184.216.34:443".parse().unwrap()));
    assert!(addresses.contains(&"[2606:4700::1111]:443".parse().unwrap()));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture.resolver.resolve("public.test", 443).await.unwrap(),
        addresses
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    fixture.resolver.resolve("public.test", 443).await.unwrap();
    assert_eq!(
        fixture.calls.load(Ordering::SeqCst),
        4,
        "provider TTL must expire outer cache"
    );
    let reserved = fixture
        .resolver
        .resolve("reserved.test", 443)
        .await
        .unwrap();
    assert!(
        reserved
            .iter()
            .any(|address| address.ip() == "192.0.0.88".parse::<IpAddr>().unwrap()),
        "do not silently filter mixed answers before policy"
    );
    assert!(fixture
        .resolver
        .resolve("missing.test", 443)
        .await
        .unwrap_err()
        .contains("nenašlo"));
    let count = fixture.calls.load(Ordering::SeqCst);
    assert!(fixture.resolver.resolve("missing.test", 443).await.is_err());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), count);
    let Fixture {
        resolver,
        calls: _,
        connections,
        cancel,
        task,
    } = fixture;
    drop(resolver);
    timeout(Duration::from_secs(2), async {
        while connections.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("dropping resolver must release HTTP/2 transports");
    cancel.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn doh_untrusted_tls_and_timeout_fail_closed_without_system_fallback() {
    let fixture = Fixture::new(false).await;
    assert!(fixture
        .resolver
        .resolve("example.com", 443)
        .await
        .unwrap_err()
        .contains("systémové DNS nebylo použito"));
    assert_eq!(
        fixture.calls.load(Ordering::SeqCst),
        0,
        "TLS must validate before sending hostname"
    );
    fixture.stop().await;
    let fixture = Fixture::new(true).await;
    let start = Instant::now();
    let error = fixture
        .resolver
        .resolve("slow.test", 443)
        .await
        .unwrap_err();
    assert!(error.contains("systémové DNS nebylo použito"));
    assert!(start.elapsed() < Duration::from_secs(6));
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "Explicit opt-in public Cloudflare DoH lookup; no OS changes"]
async fn cloudflare_doh_public_accounts_probe() {
    assert_eq!(
        std::env::var("HOMEPROXY_DOH_PROBE").as_deref(),
        Ok("accounts.google.com")
    );
    let resolver = Resolver::new(DnsMode::Cloudflare).unwrap();
    let answers = resolver.resolve("accounts.google.com", 443).await.unwrap();
    assert!(!answers.is_empty());
    for answer in &answers {
        assert!(crate::filter::destination_is_public(answer.ip()));
    }
    println!("Cloudflare DoH public addresses: {answers:?}");
}
