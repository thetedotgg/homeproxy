//! Fixed local supervision response through the ordinary listener/admission path.
//! This endpoint never resolves, forwards, authenticates a principal or accesses cache.
use super::*;

const PATH: &str = "/.well-known/homeproxy-health";

pub(super) fn response<B>(request: &Request<B>, peer: SocketAddr) -> Option<Response<ProxyBody>> {
    if request.uri().path() != PATH {
        return None;
    }
    let valid = peer.ip().is_loopback()
        && request.method() == Method::GET
        && request.uri().scheme().is_none()
        && request.uri().authority().is_none()
        && request
            .uri()
            .path_and_query()
            .is_some_and(|path| path.as_str() == PATH)
        && !request.headers().contains_key(TRANSFER_ENCODING)
        && request
            .headers()
            .get(CONTENT_LENGTH)
            .is_none_or(|v| v == "0");
    let nonce = request
        .headers()
        .get("x-homeproxy-health-nonce")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() == 16 && value.bytes().all(|b| b.is_ascii_hexdigit()));
    let (status, body) = match (valid, nonce) {
        (true, Some(nonce)) => (StatusCode::OK, Bytes::copy_from_slice(nonce.as_bytes())),
        _ => (
            StatusCode::FORBIDDEN,
            Bytes::from_static(b"Local supervision only"),
        ),
    };
    Some(
        Response::builder()
            .status(status)
            .header(CACHE_CONTROL, "no-store")
            .header(CONNECTION, "close")
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, body.len())
            .body(
                Full::new(body)
                    .map_err(|error: Infallible| match error {})
                    .boxed_unsync(),
            )
            .expect("fixed health response"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str, nonce: &str) -> Request<()> {
        Request::builder()
            .uri(uri)
            .header("x-homeproxy-health-nonce", nonce)
            .body(())
            .unwrap()
    }

    #[tokio::test]
    async fn exact_loopback_probe_echoes_nonce_and_closes_without_caching() {
        let response = response(
            &request(PATH, "0123456789abcdef"),
            "127.0.0.1:1234".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[CONNECTION], "close");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "0123456789abcdef"
        );
    }

    #[test]
    fn lan_absolute_query_missing_nonce_and_payload_cannot_use_probe() {
        for (uri, nonce, peer) in [
            (PATH, "0123456789abcdef", "192.168.1.20:1234"),
            (
                "http://example.org/.well-known/homeproxy-health",
                "0123456789abcdef",
                "127.0.0.1:1234",
            ),
            (
                "/.well-known/homeproxy-health?target=http://example.org",
                "0123456789abcdef",
                "127.0.0.1:1234",
            ),
            (PATH, "", "127.0.0.1:1234"),
        ] {
            assert_eq!(
                response(&request(uri, nonce), peer.parse().unwrap())
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        let mut upload = request(PATH, "0123456789abcdef");
        upload
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_static("12"));
        assert_eq!(
            response(&upload, "127.0.0.1:1".parse().unwrap())
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert!(response(
            &request("/ordinary", "0123456789abcdef"),
            "127.0.0.1:1".parse().unwrap()
        )
        .is_none());
    }
}
