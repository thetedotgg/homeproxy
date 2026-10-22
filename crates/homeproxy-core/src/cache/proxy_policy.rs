//! Shared-cache policy extensions; the conservative default remains opt-in for navigations.
use super::*;

pub(super) fn public_endpoint<B>(request: &Request<B>, settings: &Settings) -> bool {
    let Some(host) = request.uri().host() else {
        return false;
    };
    settings.public_cache_endpoints.iter().any(|endpoint| {
        host.eq_ignore_ascii_case(&endpoint.host)
            && (endpoint.path_prefix == "/"
                || request.uri().path() == endpoint.path_prefix
                || request
                    .uri()
                    .path()
                    .strip_prefix(endpoint.path_prefix.trim_end_matches('/'))
                    .is_some_and(|tail| tail.starts_with('/')))
    })
}

fn known_header(name: &str) -> bool {
    // Fetch metadata (e.g. Sec-Fetch-Storage-Access in current Chrome/Firefox) and
    // privacy hints carry no identity; the canonical origin fetch drops them.
    name.starts_with("sec-fetch-")
        || matches!(name, "sec-gpc" | "dnt" | "origin")
        || matches!(
            name,
            "accept"
                | "accept-encoding"
                | "accept-language"
                | "connection"
                | "host"
                | "proxy-connection"
                | "user-agent"
                | "referer"
                | "upgrade-insecure-requests"
                | "priority"
                | "purpose"
                | "sec-purpose"
                | "range"
                | "if-range"
                | "cache-control"
                | "pragma"
                | "sec-ch-ua"
                | "sec-ch-ua-mobile"
                | "sec-ch-ua-platform"
                | "sec-ch-ua-platform-version"
                | "sec-ch-ua-model"
                | "sec-ch-ua-arch"
                | "sec-ch-ua-bitness"
                | "sec-ch-ua-full-version"
                | "sec-ch-ua-full-version-list"
                | "sec-ch-ua-wow64"
                | "sec-ch-ua-form-factors"
        )
}

pub(super) fn eligible<B>(request: &Request<B>, endpoint: bool) -> bool {
    if !matches!(*request.method(), Method::GET | Method::HEAD)
        || request.headers().contains_key(COOKIE)
        || request.headers().contains_key(AUTHORIZATION)
        || request.headers().contains_key(PROXY_AUTHORIZATION)
        || !request
            .headers()
            .keys()
            .all(|name| known_header(name.as_str()))
        || request_no_store(request.headers())
        || request_no_transform(request.headers())
    {
        return false;
    }
    if endpoint {
        return true;
    }
    // Range and request cache directives change reuse, never the representation key.
    let mut base = Request::new(());
    *base.method_mut() = Method::GET;
    *base.uri_mut() = request.uri().clone();
    *base.headers_mut() = request.headers().clone();
    for name in [
        RANGE,
        CACHE_CONTROL,
        PRAGMA,
        HeaderName::from_static("if-range"),
    ] {
        base.headers_mut().remove(name);
    }
    request_is_shared_cache_eligible(&base)
}

pub(super) fn origin_headers<B>(request: &Request<B>, endpoint: bool) -> Option<HeaderMap> {
    let mut copy = Request::new(());
    *copy.uri_mut() = request.uri().clone();
    *copy.headers_mut() = request.headers().clone();
    prepare_origin_request(&mut copy, !endpoint).ok()?;
    for name in [
        RANGE,
        CACHE_CONTROL,
        PRAGMA,
        HeaderName::from_static("if-range"),
    ] {
        copy.headers_mut().remove(name);
    }
    Some(copy.headers().clone())
}
// Normalize only transport-equivalent authority spelling for cache identity.
// Origin routing, Host/SNI and selector bytes continue to use the original URI.
fn canonical_cache_uri(uri: &Uri) -> String {
    let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) else {
        return uri.to_string();
    };
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return uri.to_string(),
    };
    if authority.as_str().contains('@') {
        return uri.to_string();
    }
    let host = authority.host();
    if host.is_empty() {
        return uri.to_string();
    }
    let Some(suffix) = authority.as_str().strip_prefix(host) else {
        return uri.to_string();
    };
    let port_suffix = if suffix.is_empty() {
        ""
    } else {
        let Some(port) = suffix
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok())
        else {
            return uri.to_string();
        };
        if port == default_port {
            ""
        } else {
            suffix
        }
    };
    let host = if host.starts_with('[') && host.ends_with(']') {
        host.to_owned()
    } else if host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        host.to_ascii_lowercase()
    } else {
        // Unexpected host syntax must not acquire a valid target's identity.
        return uri.to_string();
    };
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    format!("{scheme}://{host}{port_suffix}{path}")
}

pub(super) fn base_key<B>(request: &Request<B>, context: &ProxyContext, endpoint: bool) -> String {
    let mut identity = format!(
        "public-variants-v1\n{}\n{}\n{}",
        canonical_cache_uri(request.uri()),
        context.settings.compression_preset.cache_key(),
        endpoint
    );
    // CORS responses (Access-Control-Allow-Origin) belong to the requesting site.
    // Each Origin gets its own family, so no site is served another site's grant
    // and a no-cors copy never answers a CORS request. Without Origin the key is
    // unchanged, keeping existing cache entries valid.
    let origins = request.headers().get_all(ORIGIN).iter().collect::<Vec<_>>();
    if !origins.is_empty() {
        identity.push_str("\norigin");
        for value in origins {
            identity.push_str(&format!("\n{}:", value.len()));
            identity.push_str(&String::from_utf8_lossy(value.as_bytes()));
        }
    }
    // A browser asking not to be tracked never shares a copy fetched without it.
    for name in ["sec-gpc", "dnt"] {
        for value in request.headers().get_all(name) {
            identity.push_str(&format!("\n{name}\n{}:", value.len()));
            identity.push_str(&String::from_utf8_lossy(value.as_bytes()));
        }
    }
    hex::encode(Sha256::digest(identity.as_bytes()))
}
pub(super) fn key<B>(request: &Request<B>, context: &ProxyContext, endpoint: bool) -> String {
    let base = base_key(request, context, endpoint);
    let mut headers = origin_headers(request, endpoint).unwrap_or_default();
    if request.method() != Method::HEAD {
        for name in [RANGE, HeaderName::from_static("if-range")] {
            for value in request.headers().get_all(&name) {
                headers.append(name.clone(), value.clone());
            }
        }
    }
    // Cold flights include every actual origin header, with framing and absent/empty preserved.
    let mut digest = Sha256::new();
    digest.update(base);
    let mut names = headers.keys().collect::<Vec<_>>();
    names.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    for name in names {
        digest.update((name.as_str().len() as u64).to_be_bytes());
        digest.update(name.as_str());
        digest.update((headers.get_all(name).iter().count() as u64).to_be_bytes());
        for value in headers.get_all(name) {
            digest.update((value.as_bytes().len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
    }
    hex::encode(digest.finalize())
}
pub(super) async fn cached_key<B: Sync>(
    request: &Request<B>,
    context: &ProxyContext,
    endpoint: bool,
) -> Option<String> {
    let base = base_key(request, context, endpoint);
    let origin = origin_headers(request, endpoint)?;
    context.cache.hydrate_variants(&base).await;
    let candidate = context
        .cache
        .variants
        .lookup(&base, &origin, request.headers())?;
    if let Some(snapshot) = context.cache.snapshot(&candidate.key).await {
        return candidate
            .verifies(&snapshot.headers)
            .then_some(candidate.key);
    }
    let total = context.cache.fragment_total(&candidate.key).await?;
    let (start, end) = requested_range(request.headers(), total)?;
    let entry = context
        .cache
        .get_fragment(&candidate.key, start, end, true)
        .await?;
    candidate.verifies(&entry.headers).then_some(candidate.key)
}

pub(super) fn request_no_store(headers: &HeaderMap) -> bool {
    directives(headers).is_none_or(|values| values.iter().any(|v| v == "no-store"))
}
// A transformed stored representation cannot satisfy the client's no-transform
// directive either. Bypass both reuse and new transforms, retaining the original
// Cache-Control header on the noncanonical origin request.
pub(super) fn request_no_transform(headers: &HeaderMap) -> bool {
    directives(headers).is_none_or(|values| values.iter().any(|v| v == "no-transform"))
}
fn directives(headers: &HeaderMap) -> Option<Vec<String>> {
    let mut result = Vec::new();
    for value in headers.get_all(CACHE_CONTROL) {
        for item in split_http_list(value.to_str().ok()?)? {
            result.push(item.trim().to_ascii_lowercase());
        }
    }
    Some(result)
}
pub(super) fn request_requires_validation(headers: &HeaderMap) -> bool {
    directives(headers).is_none_or(|values| {
        values
            .iter()
            .any(|v| v == "no-cache" || v == "max-age=0" || v == "max-age=\"0\"")
    }) || header_contains_token(headers, PRAGMA, "no-cache")
}
pub(super) fn only_if_cached(headers: &HeaderMap) -> bool {
    directives(headers).is_some_and(|values| values.iter().any(|value| value == "only-if-cached"))
}

pub(super) fn request_allows_fresh(headers: &HeaderMap, age: u64, remaining_ttl: u64) -> bool {
    if request_requires_validation(headers) || request_no_store(headers) {
        return false;
    }
    let Some(values) = directives(headers) else {
        return false;
    };
    for value in values {
        let (name, raw) = value.split_once('=').unwrap_or((&value, ""));
        match name {
            "max-age" => {
                let Ok(limit) = raw.trim_matches('"').parse::<u64>() else {
                    return false;
                };
                if age > limit {
                    return false;
                }
            }
            "min-fresh" => {
                let Ok(limit) = raw.trim_matches('"').parse::<u64>() else {
                    return false;
                };
                if remaining_ttl < limit {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

pub(super) fn offline_allowed(
    snapshot: &crate::cache::CacheSnapshot,
    headers: &HeaderMap,
    max_stale: u64,
) -> bool {
    if snapshot.online_validation_required {
        return false;
    }
    let age = parse_single_age(&snapshot.headers)
        .unwrap_or(u64::MAX)
        .saturating_add(snapshot.age.as_secs())
        .max(parse_single_date_apparent_age(&snapshot.headers).unwrap_or(u64::MAX));
    if !request_allows_fresh(headers, age, snapshot.remaining_ttl.as_secs()) {
        return false;
    }
    let Some(policy) = stored_policy(&snapshot.headers) else {
        return false;
    };
    if policy.unsafe_to_share
        || policy.requires_validation
        || freshness_lifetime(&snapshot.headers, &policy).is_none_or(|ttl| ttl == 0)
    {
        return false;
    }
    let Some(values) = directives(headers) else {
        return false;
    };
    let mut request_max_stale = max_stale;
    for value in values {
        if let Some(raw) = value.strip_prefix("max-stale=") {
            let Ok(limit) = raw.trim_matches('"').parse::<u64>() else {
                return false;
            };
            request_max_stale = request_max_stale.min(limit);
        }
    }
    if snapshot.remaining_ttl.as_secs() > 0 {
        return true;
    }
    !policy.must_revalidate
        && policy.s_maxage.is_none()
        && snapshot.stale_for.as_secs() <= request_max_stale
}

pub(super) fn stale_error_allowed(
    snapshot: &crate::cache::CacheSnapshot,
    headers: &HeaderMap,
    bound: u64,
) -> bool {
    let Some(policy) = stored_policy(&snapshot.headers) else {
        return false;
    };
    let Some(server_limit) = policy.stale_if_error else {
        return false;
    };
    if policy.must_revalidate
        || policy.s_maxage.is_some()
        || policy.unsafe_to_share
        || policy.requires_validation
        || snapshot.remaining_ttl.as_secs() > 0
    {
        return false;
    }
    offline_allowed(snapshot, headers, bound.min(server_limit))
}

fn stored_policy(headers: &HeaderMap) -> Option<CacheControlPolicy> {
    if headers.contains_key(CACHE_CONTROL) {
        parse_cache_control(headers)
    } else {
        Some(CacheControlPolicy::default())
    }
}
fn freshness_lifetime(headers: &HeaderMap, policy: &CacheControlPolicy) -> Option<u64> {
    if let Some(seconds) = policy.s_maxage.or(policy.max_age) {
        return Some(seconds);
    }
    if policy.requires_validation {
        return Some(0);
    }
    let mut expires = headers.get_all("expires").iter();
    let value = expires.next()?;
    if expires.next().is_some() {
        return None;
    }
    let expires = httpdate::parse_http_date(value.to_str().ok()?).ok()?;
    let mut dates = headers.get_all(DATE).iter();
    let date = match dates.next() {
        Some(value) => httpdate::parse_http_date(value.to_str().ok()?).ok()?,
        None => SystemTime::now(),
    };
    if dates.next().is_some() {
        return None;
    }
    Some(expires.duration_since(date).unwrap_or_default().as_secs())
}
pub(super) fn freshness_ttl(headers: &HeaderMap, policy: &CacheControlPolicy) -> Option<Duration> {
    let seconds = freshness_lifetime(headers, policy)?;
    let remaining = seconds.saturating_sub(current_response_age(headers)?);
    Some(if policy.requires_validation {
        Duration::ZERO
    } else {
        Duration::from_secs(remaining.min(86400))
    })
}

// RFC 9111 lets a shared cache store a response with explicit freshness unless it
// is private/no-store or the request carried credentials; eligible requests never
// carry Cookie or Authorization, so `max-age` alone is enough here.
fn shareable_freshness(policy: &CacheControlPolicy) -> bool {
    policy.explicit_public
        || policy.s_maxage.is_some()
        || policy.max_age.is_some_and(|seconds| seconds > 0)
}

pub(super) fn ttl(headers: &HeaderMap, status: StatusCode, endpoint: bool) -> Option<Duration> {
    if !matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT)
        || headers.contains_key(SET_COOKIE)
        || header_values_contain(headers, CONTENT_DISPOSITION, "attachment")?
    {
        return None;
    }
    let policy = if headers.contains_key(CACHE_CONTROL) {
        parse_cache_control(headers)?
    } else if endpoint {
        CacheControlPolicy::default()
    } else {
        return None;
    };
    if policy.unsafe_to_share || (!endpoint && !shareable_freshness(&policy)) {
        return None;
    }
    for name in crate::cache::variants::schema(headers)? {
        if !known_header(&name)
            || matches!(
                name.as_str(),
                "range"
                    | "if-range"
                    | "cache-control"
                    | "pragma"
                    | "connection"
                    | "host"
                    | "proxy-connection"
            )
        {
            return None;
        }
        if !endpoint
            && !matches!(
                name.as_str(),
                "accept" | "accept-language" | "accept-encoding" | "origin"
            )
        {
            return None;
        }
    }
    crate::cache::variants::coding(headers)?;
    freshness_ttl(headers, &policy)
}
pub(super) fn head_refresh(
    snapshot: &crate::cache::CacheSnapshot,
    headers: &HeaderMap,
    endpoint: bool,
) -> Option<(HeaderMap, Duration)> {
    let etag = strong_etag(headers)?;
    strong_etag(&snapshot.headers)?;
    if etag.to_str().ok()?.starts_with("W/")
        || !etag.to_str().ok()?.starts_with('"')
        || snapshot.headers.get("etag") != Some(etag)
        || headers
            .get("last-modified")
            .is_some_and(|v| snapshot.headers.get("last-modified") != Some(v))
        || crate::cache::variants::coding(headers)?
            != crate::cache::variants::coding(&snapshot.headers)?
        || crate::cache::variants::schema(headers)?
            != crate::cache::variants::schema(&snapshot.headers)?
    {
        return None;
    }
    merge_304(snapshot, headers, endpoint)
}

pub(super) fn merge_304(
    snapshot: &crate::cache::CacheSnapshot,
    headers: &HeaderMap,
    endpoint: bool,
) -> Option<(HeaderMap, Duration)> {
    if headers.contains_key(SET_COOKIE)
        || headers.contains_key(CONTENT_ENCODING)
            && crate::cache::variants::coding(headers)
                != crate::cache::variants::coding(&snapshot.headers)
        || headers.get(CONTENT_LENGTH).is_some_and(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                != Some(snapshot.body_length)
        })
        || headers.contains_key("content-range")
    {
        return None;
    }
    if let Some(etag) = headers.get("etag") {
        if snapshot.headers.get("etag").is_some_and(|old| old != etag) {
            return None;
        }
    }
    if headers.contains_key(VARY)
        && crate::cache::variants::schema(headers)
            != crate::cache::variants::schema(&snapshot.headers)
    {
        return None;
    }
    let mut merged = snapshot.headers.clone();
    for name in headers.keys() {
        merged.remove(name);
        for value in headers.get_all(name) {
            merged.append(name.clone(), value.clone());
        }
    }
    // Without a new Age/Date a validation response would retain the old response age.
    if !headers.contains_key(AGE) {
        merged.insert(AGE, HeaderValue::from_static("0"));
    }
    if !headers.contains_key(DATE) {
        merged.insert(
            DATE,
            HeaderValue::from_str(&httpdate::fmt_http_date(SystemTime::now())).ok()?,
        );
    }
    let ttl = ttl(&merged, StatusCode::OK, endpoint)?;
    Some((merged, ttl))
}

pub(super) fn cached_range(
    mut entry: CachedEntry,
    request_headers: &HeaderMap,
) -> Result<Response<ProxyBody>, ProxyError> {
    let Some(range) = request_headers.get(RANGE) else {
        return cached_response(entry);
    };
    if entry.headers.contains_key("x-homeproxy-transformed") {
        return Err(ProxyError::Offline);
    }
    let length = entry
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or(ProxyError::Offline)?;
    if let Some(if_range) = request_headers.get("if-range") {
        let matches = request_headers.get_all("if-range").iter().count() == 1
            && if_range.to_str().ok().is_some_and(|value| {
                if value.starts_with('"') {
                    entry
                        .headers
                        .get("etag")
                        .is_some_and(|etag| etag == if_range)
                } else {
                    false
                } // Date validators are not guaranteed strong by the stored metadata.
            });
        if !matches {
            return cached_response(entry);
        }
    }
    let range = if request_headers.get_all(RANGE).iter().count() == 1 {
        range
            .to_str()
            .ok()
            .and_then(|value| value.strip_prefix("bytes="))
    } else {
        None
    };
    let parsed = range.and_then(|value| {
        if value.contains(',') {
            return None;
        }
        let (start, end) = value.split_once('-')?;
        if start.is_empty() {
            let count = end.parse::<u64>().ok()?;
            if count == 0 || length == 0 {
                return None;
            }
            Some((length.saturating_sub(count), length - 1))
        } else {
            let start = start.parse::<u64>().ok()?;
            let end = if end.is_empty() {
                length.checked_sub(1)?
            } else {
                end.parse::<u64>().ok()?.min(length.checked_sub(1)?)
            };
            (start <= end && start < length).then_some((start, end))
        }
    });
    let Some((start, end)) = parsed else {
        return Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header("content-range", format!("bytes */{length}"))
            .header(CONTENT_LENGTH, "0")
            .body(empty_body())
            .map_err(ProxyError::BuildResponse);
    };
    entry.body.range(start, end - start + 1)?;
    entry.status = StatusCode::PARTIAL_CONTENT;
    entry.headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&(end - start + 1).to_string()).map_err(|_| ProxyError::Offline)?,
    );
    entry.headers.insert(
        "content-range",
        HeaderValue::from_str(&format!("bytes {start}-{end}/{length}"))
            .map_err(|_| ProxyError::Offline)?,
    );
    entry
        .headers
        .insert("accept-ranges", HeaderValue::from_static("bytes"));
    cached_response(entry)
}

pub(super) fn request_reason<B>(request: &Request<B>, endpoint: bool) -> &'static str {
    if request.headers().contains_key(COOKIE) {
        "request-cookie"
    } else if request.headers().contains_key(AUTHORIZATION)
        || request.headers().contains_key(PROXY_AUTHORIZATION)
    {
        "request-authorization"
    } else if request_no_store(request.headers()) {
        "request-no-store"
    } else if request_no_transform(request.headers()) {
        "request-no-transform"
    } else if !request
        .headers()
        .keys()
        .all(|name| known_header(name.as_str()))
    {
        "request-unknown-header"
    } else if !matches!(*request.method(), Method::GET | Method::HEAD) {
        "request-method"
    } else if !endpoint
        && request.uri().query().is_some()
        && !browser_static_subresource(request.headers())
    {
        "request-query"
    } else if !endpoint {
        "request-navigation"
    } else {
        "request-ineligible"
    }
}
pub(super) fn response_reason(
    headers: &HeaderMap,
    status: StatusCode,
    endpoint: bool,
) -> &'static str {
    if headers.contains_key(SET_COOKIE) {
        return "response-set-cookie";
    }
    if !matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT) {
        return "response-status";
    }
    if let Some(policy) = parse_cache_control(headers) {
        if policy.unsafe_to_share {
            return if directives(headers).is_some_and(|values| {
                values
                    .iter()
                    .any(|v| v.split('=').next() == Some("no-store"))
            }) {
                "response-no-store"
            } else {
                "response-private"
            };
        }
    } else if headers.contains_key(CACHE_CONTROL) {
        return "response-invalid-cache-control";
    }
    if crate::cache::variants::schema(headers).is_none_or(|names| {
        names.iter().any(|name| {
            !known_header(name)
                || matches!(
                    name.as_str(),
                    "range"
                        | "if-range"
                        | "cache-control"
                        | "pragma"
                        | "connection"
                        | "host"
                        | "proxy-connection"
                )
                || !endpoint
                    && !matches!(
                        name.as_str(),
                        "accept" | "accept-language" | "accept-encoding" | "origin"
                    )
        })
    }) {
        "response-vary"
    } else if crate::cache::variants::coding(headers).is_none() {
        "response-content-coding"
    } else if !endpoint && !parse_cache_control(headers).is_some_and(|p| shareable_freshness(&p)) {
        "response-not-public"
    } else {
        "response-vary-or-freshness"
    }
}

pub(super) fn requested_range(headers: &HeaderMap, length: u64) -> Option<(u64, u64)> {
    if headers.contains_key("if-range") || headers.get_all(RANGE).iter().count() != 1 {
        return None;
    }
    let value = headers.get(RANGE)?.to_str().ok()?.strip_prefix("bytes=")?;
    if value.contains(',') || length == 0 {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    if start.is_empty() {
        let count = end.parse::<u64>().ok()?;
        (count > 0).then_some((length.saturating_sub(count), length - 1))
    } else {
        let start = start.parse::<u64>().ok()?;
        let end = if end.is_empty() {
            length - 1
        } else {
            end.parse::<u64>().ok()?.min(length - 1)
        };
        (start <= end && start < length).then_some((start, end))
    }
}

fn strong_etag(headers: &HeaderMap) -> Option<&HeaderValue> {
    if headers.get_all("etag").iter().count() != 1 {
        return None;
    }
    let value = headers.get("etag")?;
    let etag = value.to_str().ok()?;
    (etag.starts_with('"')
        && etag.ends_with('"')
        && etag.len() >= 2
        && !etag[1..etag.len() - 1]
            .bytes()
            .any(|v| v == b'"' || v < 0x21 || v == 0x7f))
    .then_some(value)
}
pub(super) fn fragment_eligible(headers: &HeaderMap) -> bool {
    strong_etag(headers).is_some()
        && headers.get_all("content-range").iter().count() == 1
        && headers.get_all(CONTENT_LENGTH).iter().count() == 1
}

#[cfg(test)]
mod cache_uri_tests {
    use super::*;

    #[test]
    fn canonical_cache_uri_changes_only_dns_case_and_scheme_default_port() {
        for (input, expected) in [
            (
                "http://EXAMPLE.test:80/a%2Fb?b=2&a=1",
                "http://example.test/a%2Fb?b=2&a=1",
            ),
            (
                "https://EXAMPLE.test:443/a/../B//?x=%2f",
                "https://example.test/a/../B//?x=%2f",
            ),
            (
                "https://EXAMPLE.test:08443/a",
                "https://example.test:08443/a",
            ),
            ("https://EXAMPLE.test:80/a", "https://example.test:80/a"),
            ("http://EXAMPLE.test:443/a", "http://example.test:443/a"),
            ("https://EXAMPLE.test./a", "https://example.test./a"),
            ("https://[2001:DB8::1]:443/a", "https://[2001:DB8::1]/a"),
            ("http://[2001:DB8::1]:8080/a", "http://[2001:DB8::1]:8080/a"),
        ] {
            let uri: Uri = input.parse().unwrap();
            let original = uri.to_string();
            assert_eq!(canonical_cache_uri(&uri), expected);
            assert_eq!(
                uri.to_string(),
                original,
                "cache identity must not mutate routing URI"
            );
        }
    }

    #[test]
    fn unexpected_cache_uri_keeps_original_identity() {
        for input in [
            "/A%2fb?b=2&a=1",
            "EXAMPLE.test:443",
            "ftp://EXAMPLE.test:80/a",
            "https://user@EXAMPLE.test:443/a",
            "https://EXAMPLE.test:65536/a",
            "https://EXAMPLE.test:invalid/a",
        ] {
            let uri: Uri = input.parse().unwrap();
            assert_eq!(canonical_cache_uri(&uri), uri.to_string());
        }
    }
}
