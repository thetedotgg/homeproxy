//! Configured HTTP parents carry opaque CONNECT streams, preserving origin TLS validation.
use super::*;

pub(super) async fn connect(
    host: &str,
    port: u16,
    allow_private: bool,
    resolver: &Resolver,
    settings: &Settings,
    local_addresses: &HashSet<IpAddr>,
) -> Result<TcpStream, ProxyError> {
    if settings.cache_mode == CacheMode::Offline {
        return Err(ProxyError::Offline);
    }
    if settings.upstream_proxies.is_empty() {
        return connect_destination(host, port, allow_private, resolver).await;
    }
    // Validate the ultimate target before contacting any administrator-selected parent.
    let target_addresses = resolver
        .resolve(host, port)
        .await
        .map_err(ProxyError::Upstream)?;
    if target_addresses.is_empty()
        || (!allow_private
            && target_addresses
                .iter()
                .any(|a| !destination_is_public(a.ip())))
    {
        return Err(ProxyError::Forbidden(
            "Upstream cíl nemá povolenou veřejnou adresu.",
        ));
    }
    // Pin the parent to our validated answer. Sending the original hostname would
    // let a parent with different DNS resolve it to an otherwise forbidden address.
    // The caller still uses the original origin Host and TLS server name in the tunnel.
    let authority = target_addresses[0].to_string();
    for parent in &settings.upstream_proxies {
        let addresses = match resolver.resolve(&parent.host, parent.port).await {
            Ok(addresses) => addresses,
            Err(_) => continue,
        };
        if addresses.iter().any(|a| {
            local_addresses.contains(&a.ip())
                && (a.port() == settings.proxy_port
                    || (settings.socks5_enabled && a.port() == settings.socks5_port))
        }) {
            return Err(ProxyError::Forbidden(
                "Upstream proxy nesmí vytvořit smyčku na tomto listeneru.",
            ));
        }
        let mut stream = match dial_addresses(addresses, true, resolver).await {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        let credential = match (&parent.username, &parent.password) {
            (None, None) => String::new(),
            (Some(username), Some(password))
                if !username.contains(['\r', '\n', ':']) && !password.contains(['\r', '\n']) =>
            {
                format!(
                    "Proxy-Authorization: Basic {}\r\n",
                    base64(format!("{username}:{password}").as_bytes())
                )
            }
            _ => {
                return Err(ProxyError::Forbidden(
                    "Upstream přihlašovací údaje nejsou platné.",
                ))
            }
        };
        let request =
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{credential}\r\n");
        let result = timeout(CONNECT_TIMEOUT, async {
            stream.write_all(request.as_bytes()).await?;
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                if headers.len() >= MAX_HEADER_BUFFER {
                    return Err(std::io::Error::other("parent-header-limit"));
                }
                headers.push(stream.read_u8().await?);
            }
            Ok::<_, std::io::Error>(headers)
        })
        .await;
        let headers = match result {
            Ok(Ok(headers)) => headers,
            _ => continue,
        };
        let headers = std::str::from_utf8(&headers)
            .map_err(|_| ProxyError::Upstream("Upstream odpověď nemá platný formát."))?;
        let mut lines = headers.split("\r\n");
        let status = lines.next().unwrap_or_default();
        let mut fields = status.split_whitespace();
        if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
            return Err(ProxyError::Upstream("Upstream odpověď nemá platný formát."));
        }
        if fields.next() != Some("200") {
            // Auth/policy refusal is final; never downgrade to another parent or direct.
            return Err(ProxyError::Upstream("Upstream proxy odmítla CONNECT."));
        }
        for line in lines.filter(|line| !line.is_empty()) {
            let Some((name, value)) = line.split_once(':') else {
                return Err(ProxyError::Upstream("Upstream hlavičky nejsou platné."));
            };
            if name.eq_ignore_ascii_case("transfer-encoding")
                || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
            {
                return Err(ProxyError::Upstream(
                    "Upstream CONNECT obsahuje neplatné tělo.",
                ));
            }
        }
        // Byte-at-a-time bounded header parsing never consumes early tunnel payload.
        return Ok(stream);
    }
    if settings.upstream_direct_fallback {
        dial_addresses(target_addresses, allow_private, resolver).await
    } else {
        Err(ProxyError::Upstream(
            "Žádná nakonfigurovaná upstream proxy není dostupná.",
        ))
    }
}

fn base64(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(CHARS[((value >> 18) & 63) as usize] as char);
        output.push(CHARS[((value >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            CHARS[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            CHARS[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpstreamProxy;
    fn parent(host: &str) -> UpstreamProxy {
        UpstreamProxy {
            host: host.into(),
            port: 3128,
            username: Some("parent-user".into()),
            password: Some("parent-password".into()),
        }
    }
    #[test]
    fn credentials_encoding_uses_standard_padding() {
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }
    #[tokio::test]
    async fn named_target_pins_validated_ipv4_and_ipv6_and_preserves_origin_host() {
        for public_ip in ["9.9.9.9", "2606:4700:4700::1111"] {
            let parent_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let private_origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let directory = tempfile::tempdir().unwrap();
            let context = crate::proxy::service_port_tests::context(
                directory.path(),
                Settings {
                    upstream_proxies: vec![parent("1.1.1.1")],
                    upstream_direct_fallback: true,
                    ..Settings::default()
                },
            )
            .await;
            let public_ip: IpAddr = public_ip.parse().unwrap();
            let expected_authority = SocketAddr::new(public_ip, 8080).to_string();
            context
                .resolver
                .set_test_answer("split-dns.example", vec![public_ip], Duration::ZERO);
            context.resolver.map_test_dial(
                "1.1.1.1:3128".parse().unwrap(),
                parent_listener.local_addr().unwrap(),
            );
            context.resolver.map_test_dial(
                SocketAddr::new(public_ip, 8080),
                private_origin.local_addr().unwrap(),
            );
            let resolver = context.resolver.clone();
            let parent_task = tokio::spawn(async move {
                let (mut stream, _) = parent_listener.accept().await.unwrap();
                let request = crate::proxy::offline_tests::headers(&mut stream).await;
                assert!(request.starts_with(&format!("CONNECT {expected_authority} HTTP/1.1\r\n")));
                assert!(request.contains(&format!("Host: {expected_authority}\r\n")));
                assert!(!request.contains("split-dns.example"));
                assert!(!request.contains("127.0.0.1"));
                // A later/local DNS answer cannot redirect the pinned tunnel.
                resolver.set_test_answer(
                    "split-dns.example",
                    vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                    Duration::ZERO,
                );
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                let origin = crate::proxy::offline_tests::headers(&mut stream)
                    .await
                    .to_lowercase();
                assert!(origin.starts_with("get /file http/1.1\r\n"));
                assert!(origin.contains("host: split-dns.example:8080\r\n"));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none",
                    )
                    .await
                    .unwrap();
            });
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let running = context.clone();
            let proxy_task = tokio::spawn(async move {
                accept_loop(
                    BoundListener {
                        listener,
                        protocol: ListenerProtocol::HttpMultiplexed,
                    },
                    running,
                )
                .await
                .unwrap();
            });
            let response = crate::proxy::offline_tests::exchange(
                port,
                "GET http://split-dns.example:8080/file HTTP/1.1\r\nHost: split-dns.example:8080\r\nConnection: close\r\n\r\n",
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(response.ends_with("one"), "{response}");
            parent_task.await.unwrap();
            assert!(timeout(Duration::from_millis(50), private_origin.accept())
                .await
                .is_err());
            context.cancellation.cancel();
            proxy_task.await.unwrap();
            context.tasks.close();
            context.tasks.wait().await;
        }
    }
    #[tokio::test]
    async fn named_target_with_any_private_answer_never_contacts_parent() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resolver = Resolver::default();
        resolver.set_test_answer(
            "split-dns.example",
            vec!["9.9.9.9".parse().unwrap(), IpAddr::V4(Ipv4Addr::LOCALHOST)],
            Duration::ZERO,
        );
        resolver.map_test_dial(
            "1.1.1.1:3128".parse().unwrap(),
            listener.local_addr().unwrap(),
        );
        let settings = Settings {
            upstream_proxies: vec![parent("1.1.1.1")],
            upstream_direct_fallback: true,
            ..Settings::default()
        };
        assert!(matches!(
            connect(
                "split-dns.example",
                80,
                false,
                &resolver,
                &settings,
                &HashSet::new()
            )
            .await,
            Err(ProxyError::Forbidden(_))
        ));
        assert!(timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err());
    }
    #[tokio::test]
    async fn unreachable_first_parent_fails_over_without_losing_early_tunnel_bytes() {
        let second = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let closed_address = closed.local_addr().unwrap();
        drop(closed);
        let resolver = Resolver::default();
        resolver.map_test_dial("1.1.1.1:3128".parse().unwrap(), closed_address);
        resolver.map_test_dial(
            "2.2.2.2:3128".parse().unwrap(),
            second.local_addr().unwrap(),
        );
        let task = tokio::spawn(async move {
            let (mut stream, _) = second.accept().await.unwrap();
            let request = crate::proxy::offline_tests::headers(&mut stream).await;
            assert!(request.starts_with("CONNECT 9.9.9.9:80 HTTP/1.1"));
            assert!(request.contains(&format!(
                "Proxy-Authorization: Basic {}",
                base64(b"parent-user:parent-password")
            )));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nearly")
                .await
                .unwrap();
        });
        let settings = Settings {
            upstream_proxies: vec![parent("1.1.1.1"), parent("2.2.2.2")],
            ..Settings::default()
        };
        let mut stream = connect("9.9.9.9", 80, false, &resolver, &settings, &HashSet::new())
            .await
            .unwrap();
        let mut bytes = [0; 5];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"early");
        task.await.unwrap();
    }
    #[tokio::test]
    async fn refusal_never_fails_over_or_uses_direct_even_when_fallback_enabled() {
        let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let second = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let direct = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resolver = Resolver::default();
        resolver.map_test_dial("1.1.1.1:3128".parse().unwrap(), first.local_addr().unwrap());
        resolver.map_test_dial(
            "2.2.2.2:3128".parse().unwrap(),
            second.local_addr().unwrap(),
        );
        resolver.map_test_dial("9.9.9.9:80".parse().unwrap(), direct.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = first.accept().await.unwrap();
            crate::proxy::offline_tests::headers(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let settings = Settings {
            upstream_proxies: vec![parent("1.1.1.1"), parent("2.2.2.2")],
            upstream_direct_fallback: true,
            ..Settings::default()
        };
        assert!(
            connect("9.9.9.9", 80, false, &resolver, &settings, &HashSet::new())
                .await
                .is_err()
        );
        task.await.unwrap();
        assert!(timeout(Duration::from_millis(50), second.accept())
            .await
            .is_err());
        assert!(timeout(Duration::from_millis(50), direct.accept())
            .await
            .is_err());
    }
    #[tokio::test]
    async fn offline_and_self_loop_fail_before_parent_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resolver = Resolver::default();
        resolver.map_test_dial(
            "1.1.1.1:3128".parse().unwrap(),
            listener.local_addr().unwrap(),
        );
        let settings = Settings {
            cache_mode: CacheMode::Offline,
            upstream_proxies: vec![parent("1.1.1.1")],
            ..Settings::default()
        };
        assert!(matches!(
            connect("9.9.9.9", 80, false, &resolver, &settings, &HashSet::new()).await,
            Err(ProxyError::Offline)
        ));
        let settings = Settings {
            cache_mode: CacheMode::Online,
            proxy_port: 3128,
            ..settings
        };
        let locals = HashSet::from(["1.1.1.1".parse().unwrap()]);
        assert!(matches!(
            connect("9.9.9.9", 80, false, &resolver, &settings, &locals).await,
            Err(ProxyError::Forbidden(_))
        ));
        assert!(timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err());
    }
    #[tokio::test]
    async fn parent_credentials_never_reach_http_origin_inside_tunnel() {
        let parent_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let parent_address = parent_listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = parent_listener.accept().await.unwrap();
            let connect = crate::proxy::offline_tests::headers(&mut stream).await;
            assert!(connect.contains("Proxy-Authorization: Basic"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let origin = crate::proxy::offline_tests::headers(&mut stream)
                .await
                .to_lowercase();
            assert!(origin.starts_with("get /file http/1.1"));
            assert!(!origin.contains("proxy-authorization"));
            assert!(!origin.contains("parent-user"));
            assert!(!origin.contains("parent-password"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none")
                .await
                .unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            upstream_proxies: vec![parent("1.1.1.1")],
            ..Settings::default()
        };
        let context = crate::proxy::service_port_tests::context(dir.path(), settings).await;
        context
            .resolver
            .map_test_dial("1.1.1.1:3128".parse().unwrap(), parent_address);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let running = context.clone();
        let proxy = tokio::spawn(async move {
            accept_loop(
                BoundListener {
                    listener,
                    protocol: ListenerProtocol::HttpMultiplexed,
                },
                running,
            )
            .await
            .unwrap()
        });
        let response=crate::proxy::offline_tests::exchange(port,"GET http://9.9.9.9:8080/file HTTP/1.1\r\nHost: 9.9.9.9:8080\r\nConnection: close\r\n\r\n").await;
        assert!(response.ends_with("one"), "{response}");
        task.await.unwrap();
        context.cancellation.cancel();
        proxy.await.unwrap();
        context.tasks.close();
        context.tasks.wait().await;
    }
}
