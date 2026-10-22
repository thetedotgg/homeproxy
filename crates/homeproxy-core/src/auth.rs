use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use http::{header::PROXY_AUTHORIZATION, Method, Request, Uri};
use md5::Md5;
use rand::random;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const REALM: &str = "HomeProxy";
const NONCE_LIFETIME: Duration = Duration::from_secs(5 * 60);
const MAX_REPLAY_NONCES: usize = 1_024;
const MAX_CLIENT_NONCES_PER_NONCE: usize = 256;
const NONCE_KEY_BYTES: usize = 32;
const NONCE_RANDOM_BYTES: usize = 16;
const NONCE_AUTHORITY_BYTES: usize = 32;
const NONCE_MAC_BYTES: usize = 32;
const NONCE_PAYLOAD_BYTES: usize = 8 + NONCE_RANDOM_BYTES + 1 + NONCE_AUTHORITY_BYTES;
const NONCE_BYTES: usize = NONCE_PAYLOAD_BYTES + NONCE_MAC_BYTES;
const NONCE_COUNT_WINDOW_BITS: u32 = u64::BITS;

pub struct DigestAuth {
    nonce_key: [u8; NONCE_KEY_BYTES],
    state: Mutex<AuthState>,
}

#[derive(Default)]
struct AuthState {
    nonces: HashMap<String, NonceState>,
}

struct NonceState {
    expires_at: u64,
    count_windows: HashMap<String, NonceCountWindow>,
}

#[derive(Default)]
struct NonceCountWindow {
    highest: u32,
    seen: u64,
}

impl NonceCountWindow {
    fn accept(&mut self, count: u32) -> bool {
        if count > self.highest {
            let advance = count - self.highest;
            self.seen = if advance >= NONCE_COUNT_WINDOW_BITS {
                0
            } else {
                self.seen << advance
            };
            self.highest = count;
            self.seen |= 1;
            return true;
        }

        let age = self.highest - count;
        if age >= NONCE_COUNT_WINDOW_BITS {
            return false;
        }
        let count_bit = 1_u64 << age;
        if self.seen & count_bit != 0 {
            return false;
        }
        self.seen |= count_bit;
        true
    }
}

struct VerifiedNonce {
    expires_at: u64,
    challenge_authority: Option<[u8; NONCE_AUTHORITY_BYTES]>,
}

impl Default for DigestAuth {
    fn default() -> Self {
        Self {
            nonce_key: random::<[u8; NONCE_KEY_BYTES]>(),
            state: Mutex::new(AuthState::default()),
        }
    }
}

impl DigestAuth {
    pub fn challenge(&self, method: &Method, request_uri: &str) -> String {
        let issued_at = unix_timestamp();
        let random = random::<[u8; NONCE_RANDOM_BYTES]>();
        let challenge_authority = request_authority(method, request_uri);
        let mut nonce = Vec::with_capacity(NONCE_BYTES);
        nonce.extend_from_slice(&issued_at.to_be_bytes());
        nonce.extend_from_slice(&random);
        nonce.push(u8::from(challenge_authority.is_some()));
        nonce.extend_from_slice(&authority_fingerprint(challenge_authority.as_deref()));
        let mac = self.nonce_authenticator(&nonce).finalize().into_bytes();
        nonce.extend_from_slice(&mac);
        let nonce = hex::encode(nonce);
        format!(
            "Digest realm=\"{REALM}\", nonce=\"{nonce}\", algorithm=MD5, qop=\"auth\", charset=UTF-8"
        )
    }

    /// Resolve the principal only after digest verification (including replay protection).
    pub fn authenticate<B>(
        &self,
        request: &Request<B>,
        settings: &crate::config::Settings,
    ) -> Option<String> {
        let value = request.headers().get(PROXY_AUTHORIZATION)?.to_str().ok()?;
        let parameters = parse_digest(value)?;
        let username = parameters.get("username")?;
        let password = if username == &settings.proxy_username {
            &settings.proxy_password
        } else {
            &settings
                .device_profiles
                .iter()
                .find(|p| &p.username == username)?
                .password
        };
        self.verify_parameters(
            request.method(),
            &request.uri().to_string(),
            username,
            password,
            &parameters,
        )
        .then(|| username.clone())
    }

    fn verify_parameters(
        &self,
        method: &Method,
        request_uri: &str,
        username: &str,
        password: &str,
        parameters: &HashMap<String, String>,
    ) -> bool {
        let required = |key: &str| parameters.get(key).map(String::as_str);
        let (
            Some(received_username),
            Some(realm),
            Some(nonce),
            Some(uri),
            Some(response),
            Some(qop),
            Some(nonce_count),
            Some(client_nonce),
        ) = (
            required("username"),
            required("realm"),
            required("nonce"),
            required("uri"),
            required("response"),
            required("qop"),
            required("nc"),
            required("cnonce"),
        )
        else {
            return false;
        };
        let algorithm = parameters
            .get("algorithm")
            .map(String::as_str)
            .unwrap_or("MD5");
        let (response_length, digest): (usize, fn(&[u8]) -> String) =
            if algorithm.eq_ignore_ascii_case("MD5") {
                (32, md5_hex)
            } else if algorithm.eq_ignore_ascii_case("SHA-256") {
                (64, sha256_hex)
            } else {
                return false;
            };
        let Some(uri_match) = digest_uri_match(method, request_uri, uri) else {
            return false;
        };
        if received_username != username
            || realm != REALM
            || !qop.eq_ignore_ascii_case("auth")
            || response.len() != response_length
            || nonce_count.len() != 8
            || client_nonce.is_empty()
            || client_nonce.len() > 128
        {
            return false;
        }
        let Ok(count) = u32::from_str_radix(nonce_count, 16) else {
            return false;
        };
        if count == 0 {
            return false;
        }
        let Some(verified_nonce) = self.verify_nonce(nonce) else {
            return false;
        };
        if uri_match == DigestUriMatch::OriginForm
            && !nonce_authority_matches(
                verified_nonce.challenge_authority.as_ref(),
                method,
                request_uri,
            )
        {
            return false;
        }

        let ha1 = digest(format!("{username}:{REALM}:{password}").as_bytes());
        let ha2 = digest(format!("{method}:{uri}").as_bytes());
        let expected =
            digest(format!("{ha1}:{nonce}:{nonce_count}:{client_nonce}:auth:{ha2}").as_bytes());
        let Ok(received) = hex::decode(response) else {
            return false;
        };
        let Ok(expected) = hex::decode(expected) else {
            return false;
        };
        if received.ct_eq(&expected).unwrap_u8() != 1 {
            return false;
        }

        let replay_key = format!("{username}\0{client_nonce}");
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let now = unix_timestamp();
        if verified_nonce.expires_at < now {
            return false;
        }
        state
            .nonces
            .retain(|_, nonce_state| nonce_state.expires_at >= now);
        if !state.nonces.contains_key(nonce) && state.nonces.len() >= MAX_REPLAY_NONCES {
            return false;
        }
        let nonce_state = state
            .nonces
            .entry(nonce.to_string())
            .or_insert_with(|| NonceState {
                expires_at: verified_nonce.expires_at,
                count_windows: HashMap::new(),
            });
        if !nonce_state.count_windows.contains_key(&replay_key)
            && nonce_state.count_windows.len() >= MAX_CLIENT_NONCES_PER_NONCE
        {
            return false;
        }
        nonce_state
            .count_windows
            .entry(replay_key)
            .or_default()
            .accept(count)
    }

    fn verify_nonce(&self, nonce: &str) -> Option<VerifiedNonce> {
        if nonce.len() != NONCE_BYTES * 2
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return None;
        }
        let decoded = hex::decode(nonce).ok()?;
        let issued_at = u64::from_be_bytes(decoded[..8].try_into().ok()?);
        let authority_present = decoded[8 + NONCE_RANDOM_BYTES];
        if authority_present > 1 {
            return None;
        }
        let authority_start = 8 + NONCE_RANDOM_BYTES + 1;
        let authority_end = authority_start + NONCE_AUTHORITY_BYTES;
        let challenge_authority = (authority_present == 1).then(|| {
            decoded[authority_start..authority_end]
                .try_into()
                .expect("nonce authority fingerprint has a fixed length")
        });
        let (payload, received_mac) = decoded.split_at(NONCE_PAYLOAD_BYTES);
        self.nonce_authenticator(payload)
            .verify_slice(received_mac)
            .ok()?;

        let now = unix_timestamp();
        if issued_at > now || now - issued_at > NONCE_LIFETIME.as_secs() {
            return None;
        }
        Some(VerifiedNonce {
            expires_at: issued_at.saturating_add(NONCE_LIFETIME.as_secs()),
            challenge_authority,
        })
    }

    fn nonce_authenticator(&self, payload: &[u8]) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.nonce_key)
            .expect("HMAC accepts keys of any length");
        mac.update(b"HomeProxy Digest nonce v2\0");
        mac.update(payload);
        mac
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DigestUriMatch {
    Exact,
    OriginForm,
}

fn digest_uri_match(
    method: &Method,
    request_uri: &str,
    digest_uri: &str,
) -> Option<DigestUriMatch> {
    if digest_uri == request_uri {
        return Some(DigestUriMatch::Exact);
    }
    if method == Method::CONNECT {
        return None;
    }
    (request_uri
        .parse::<Uri>()
        .ok()
        .filter(|uri| uri.scheme_str() == Some("http"))
        .and_then(|uri| uri.path_and_query().map(|path| path.as_str().to_string()))
        .unwrap_or_else(|| "/".to_string())
        == digest_uri)
        .then_some(DigestUriMatch::OriginForm)
}

fn request_authority(method: &Method, request_uri: &str) -> Option<String> {
    let authority = if method == Method::CONNECT {
        request_uri.parse::<http::uri::Authority>().ok()?
    } else {
        let uri = request_uri.parse::<Uri>().ok()?;
        uri.authority()?.clone()
    };
    Some(authority.as_str().to_ascii_lowercase())
}

fn authority_fingerprint(authority: Option<&str>) -> [u8; NONCE_AUTHORITY_BYTES] {
    let mut digest = Sha256::new();
    digest.update(b"HomeProxy Digest authority v1\0");
    match authority {
        Some(authority) => {
            digest.update([1]);
            digest.update(authority.as_bytes());
        }
        None => digest.update([0]),
    }
    digest.finalize().into()
}

fn nonce_authority_matches(
    challenge_authority: Option<&[u8; NONCE_AUTHORITY_BYTES]>,
    method: &Method,
    request_uri: &str,
) -> bool {
    let (Some(challenge_authority), Some(request_authority)) =
        (challenge_authority, request_authority(method, request_uri))
    else {
        return false;
    };
    challenge_authority
        .ct_eq(&authority_fingerprint(Some(&request_authority)))
        .unwrap_u8()
        == 1
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn md5_hex(bytes: &[u8]) -> String {
    hex::encode(Md5::digest(bytes))
}

fn parse_digest(value: &str) -> Option<HashMap<String, String>> {
    if value.len() > 8 * 1024 {
        return None;
    }
    let parameters = value.strip_prefix("Digest ")?;
    let mut fields = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in parameters.char_indices() {
        match character {
            '\\' if quoted => escaped = !escaped,
            '"' if !escaped => quoted = !quoted,
            ',' if !quoted => {
                fields.push(&parameters[start..index]);
                start = index + 1;
                escaped = false;
            }
            _ => escaped = false,
        }
    }
    if quoted {
        return None;
    }
    fields.push(&parameters[start..]);

    let mut parsed = HashMap::new();
    for field in fields {
        let (name, raw_value) = field.trim().split_once('=')?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || parsed.contains_key(&name) {
            return None;
        }
        let raw_value = raw_value.trim();
        let value = if raw_value.starts_with('"') {
            unquote(raw_value)?
        } else {
            raw_value.to_string()
        };
        parsed.insert(name, value);
    }
    Some(parsed)
}

fn unquote(value: &str) -> Option<String> {
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    let mut output = String::with_capacity(inner.len());
    let mut escaped = false;
    for character in inner.chars() {
        if escaped {
            output.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            output.push(character);
        }
    }
    (!escaped).then_some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce_from_challenge(challenge: &str) -> &str {
        challenge
            .split("nonce=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
    }

    fn sha256_parameters(
        method: &Method,
        uri: &str,
        nonce: &str,
        username: &str,
        password: &str,
        nonce_count: &str,
        client_nonce: &str,
    ) -> HashMap<String, String> {
        let ha1 = sha256_hex(format!("{username}:{REALM}:{password}").as_bytes());
        let ha2 = sha256_hex(format!("{method}:{uri}").as_bytes());
        let response =
            sha256_hex(format!("{ha1}:{nonce}:{nonce_count}:{client_nonce}:auth:{ha2}").as_bytes());
        parse_digest(&format!(
            "Digest username=\"{username}\", realm=\"{REALM}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\", algorithm=SHA-256, qop=auth, nc={nonce_count}, cnonce=\"{client_nonce}\""
        ))
        .unwrap()
    }

    #[test]
    fn parses_quoted_commas_without_accepting_duplicates() {
        let parsed =
            parse_digest("Digest username=\"domov\", realm=\"Klidna, sit\", nonce=abc, qop=auth")
                .unwrap();
        assert_eq!(parsed["realm"], "Klidna, sit");
        assert!(parse_digest("Digest nonce=a, nonce=b").is_none());
    }

    #[test]
    fn verifies_sha256_and_rejects_replay() {
        let auth = DigestAuth::default();
        let uri = "example.com:443";
        let challenge = auth.challenge(&Method::CONNECT, uri);
        let nonce = challenge
            .split("nonce=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let username = "domov";
        let password = "0123456789abcdef";
        let nc = "00000001";
        let cnonce = "abcdef";
        let ha1 = sha256_hex(format!("{username}:{REALM}:{password}").as_bytes());
        let ha2 = sha256_hex(format!("CONNECT:{uri}").as_bytes());
        let response = sha256_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes());
        let parameters = parse_digest(&format!(
            "Digest username=\"{username}\", realm=\"{REALM}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\", algorithm=SHA-256, qop=auth, nc={nc}, cnonce=\"{cnonce}\""
        ))
        .unwrap();
        assert!(auth.verify_parameters(&Method::CONNECT, uri, username, password, &parameters));
        assert!(!auth.verify_parameters(&Method::CONNECT, uri, username, password, &parameters));
    }

    #[test]
    fn verifies_md5_used_by_windows_sspi_clients() {
        let auth = DigestAuth::default();
        let uri = "http://example.com/";
        let challenge = auth.challenge(&Method::GET, uri);
        let nonce = challenge
            .split("nonce=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let username = "domov";
        let password = "0123456789abcdef";
        let nc = "00000001";
        let cnonce = "abcdef";
        let ha1 = md5_hex(format!("{username}:{REALM}:{password}").as_bytes());
        let ha2 = md5_hex(format!("GET:{uri}").as_bytes());
        let response = md5_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes());
        let parameters = parse_digest(&format!(
            "Digest username=\"{username}\", realm=\"{REALM}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\", algorithm=MD5, qop=auth, nc={nc}, cnonce=\"{cnonce}\""
        ))
        .unwrap();
        assert!(auth.verify_parameters(&Method::GET, uri, username, password, &parameters));
    }

    #[test]
    fn verifies_windows_proxy_origin_form_for_an_absolute_request() {
        let auth = DigestAuth::default();
        let absolute_uri = "http://example.com/";
        let challenge = auth.challenge(&Method::GET, absolute_uri);
        let nonce = challenge
            .split("nonce=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let username = "domov";
        let password = "0123456789abcdef";
        let digest_uri = "/";
        let nc = "00000001";
        let cnonce = "abcdef";
        let ha1 = md5_hex(format!("{username}:{REALM}:{password}").as_bytes());
        let ha2 = md5_hex(format!("GET:{digest_uri}").as_bytes());
        let response = md5_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes());
        let parameters = parse_digest(&format!(
            "Digest username=\"{username}\", realm=\"{REALM}\", nonce=\"{nonce}\", uri=\"{digest_uri}\", response=\"{response}\", algorithm=MD5, qop=auth, nc={nc}, cnonce=\"{cnonce}\""
        ))
        .unwrap();
        assert!(!auth.verify_parameters(
            &Method::GET,
            "http://different.example/",
            username,
            password,
            &parameters
        ));
        assert!(auth.verify_parameters(
            &Method::GET,
            absolute_uri,
            username,
            password,
            &parameters
        ));
    }

    #[test]
    fn reuses_nonce_for_exact_uris_across_hosts_and_connect() {
        let auth = DigestAuth::default();
        let challenge = auth.challenge(&Method::GET, "http://first.example/one");
        let nonce = nonce_from_challenge(&challenge);
        let username = "domov";
        let password = "0123456789abcdef";
        let client_nonce = "proxy-wide";

        for (method, uri, count) in [
            (Method::GET, "http://first.example/one", 1),
            (Method::GET, "http://second.example/two?x=1", 2),
            (Method::CONNECT, "third.example:443", 3),
        ] {
            let nonce_count = format!("{count:08x}");
            let parameters = sha256_parameters(
                &method,
                uri,
                nonce,
                username,
                password,
                &nonce_count,
                client_nonce,
            );
            assert!(auth.verify_parameters(&method, uri, username, password, &parameters));
        }
    }

    #[test]
    fn origin_form_nonce_reuse_is_bound_to_the_challenge_authority() {
        let auth = DigestAuth::default();
        let challenge = auth.challenge(&Method::GET, "http://example.com/first");
        let nonce = nonce_from_challenge(&challenge);
        let username = "domov";
        let password = "0123456789abcdef";
        let client_nonce = "windows-sspi";

        let first = sha256_parameters(
            &Method::GET,
            "/first",
            nonce,
            username,
            password,
            "00000001",
            client_nonce,
        );
        assert!(auth.verify_parameters(
            &Method::GET,
            "http://example.com/first",
            username,
            password,
            &first,
        ));

        let second = sha256_parameters(
            &Method::GET,
            "/second?x=1",
            nonce,
            username,
            password,
            "00000002",
            client_nonce,
        );
        assert!(!auth.verify_parameters(
            &Method::GET,
            "http://different.example/second?x=1",
            username,
            password,
            &second,
        ));
        assert!(auth.verify_parameters(
            &Method::GET,
            "http://example.com/second?x=1",
            username,
            password,
            &second,
        ));
    }

    #[test]
    fn accepts_out_of_order_unique_nonce_counts_within_the_window() {
        let auth = DigestAuth::default();
        let uri = "http://example.com/";
        let challenge = auth.challenge(&Method::GET, uri);
        let nonce = nonce_from_challenge(&challenge);
        let username = "domov";
        let password = "0123456789abcdef";
        let client_nonce = "parallel-client";
        let second = sha256_parameters(
            &Method::GET,
            uri,
            nonce,
            username,
            password,
            "00000002",
            client_nonce,
        );
        let first = sha256_parameters(
            &Method::GET,
            uri,
            nonce,
            username,
            password,
            "00000001",
            client_nonce,
        );

        assert!(auth.verify_parameters(&Method::GET, uri, username, password, &second));
        assert!(auth.verify_parameters(&Method::GET, uri, username, password, &first));
        assert!(!auth.verify_parameters(&Method::GET, uri, username, password, &first));
    }

    #[test]
    fn one_nonce_remains_serviceable_beyond_replay_nonce_capacity() {
        let auth = DigestAuth::default();
        let uri = "http://example.com/";
        let challenge = auth.challenge(&Method::GET, uri);
        let nonce = nonce_from_challenge(&challenge);
        let username = "domov";
        let password = "0123456789abcdef";
        let client_nonce = "long-lived-client";

        for count in 1..=(MAX_REPLAY_NONCES + 1) {
            let nonce_count = format!("{count:08x}");
            let parameters = sha256_parameters(
                &Method::GET,
                uri,
                nonce,
                username,
                password,
                &nonce_count,
                client_nonce,
            );
            assert!(auth.verify_parameters(&Method::GET, uri, username, password, &parameters,));
        }
        assert_eq!(auth.state.lock().unwrap().nonces.len(), 1);
    }

    #[test]
    fn unauthenticated_challenges_do_not_invalidate_an_existing_nonce() {
        let auth = DigestAuth::default();
        let uri = "http://example.com/";
        let challenge = auth.challenge(&Method::GET, uri);
        let nonce = nonce_from_challenge(&challenge);

        for _ in 0..=MAX_REPLAY_NONCES {
            auth.challenge(&Method::GET, "http://example.com/");
        }
        assert!(auth.state.lock().unwrap().nonces.is_empty());

        let username = "domov";
        let password = "0123456789abcdef";
        let nc = "00000001";
        let cnonce = "first-client";
        let parameters =
            sha256_parameters(&Method::GET, uri, nonce, username, password, nc, cnonce);

        assert!(auth.verify_parameters(&Method::GET, uri, username, password, &parameters));
    }

    #[test]
    fn replay_capacity_fails_closed_without_evicting_live_nonces() {
        let auth = DigestAuth::default();
        let username = "domov";
        let password = "0123456789abcdef";
        let client_nonce = "client";
        let mut first = None;

        for index in 0..MAX_REPLAY_NONCES {
            let uri = format!("http://example.com/{index}");
            let challenge = auth.challenge(&Method::GET, &uri);
            let nonce = nonce_from_challenge(&challenge).to_string();
            let parameters = sha256_parameters(
                &Method::GET,
                &uri,
                &nonce,
                username,
                password,
                "00000001",
                client_nonce,
            );
            assert!(auth.verify_parameters(&Method::GET, &uri, username, password, &parameters));
            if first.is_none() {
                first = Some((uri, nonce));
            }
        }

        let overflow_uri = "http://example.com/overflow";
        let challenge = auth.challenge(&Method::GET, overflow_uri);
        let overflow_nonce = nonce_from_challenge(&challenge);
        let overflow_parameters = sha256_parameters(
            &Method::GET,
            overflow_uri,
            overflow_nonce,
            username,
            password,
            "00000001",
            client_nonce,
        );
        assert!(!auth.verify_parameters(
            &Method::GET,
            overflow_uri,
            username,
            password,
            &overflow_parameters
        ));
        assert_eq!(auth.state.lock().unwrap().nonces.len(), MAX_REPLAY_NONCES);

        let (first_uri, first_nonce) = first.unwrap();
        let next_parameters = sha256_parameters(
            &Method::GET,
            &first_uri,
            &first_nonce,
            username,
            password,
            "00000002",
            client_nonce,
        );
        assert!(auth.verify_parameters(
            &Method::GET,
            &first_uri,
            username,
            password,
            &next_parameters
        ));
    }
}

/// SOCKS credential comparison hashes both inputs to fixed-length digests before comparison.
/// Returns a principal only after validating both username and secret.
pub(crate) fn authenticate_credentials(
    username: &[u8],
    password: &[u8],
    settings: &crate::config::Settings,
) -> Option<String> {
    fn equal(a: &[u8], b: &[u8]) -> bool {
        let a = Sha256::digest(a);
        let b = Sha256::digest(b);
        bool::from(a.ct_eq(&b))
    }
    let mut authenticated = None;
    let candidates = std::iter::once((&settings.proxy_username, &settings.proxy_password)).chain(
        settings
            .device_profiles
            .iter()
            .map(|p| (&p.username, &p.password)),
    );
    for (candidate, secret) in candidates {
        let valid = equal(username, candidate.as_bytes()) & equal(password, secret.as_bytes());
        if valid {
            authenticated = Some(candidate.clone());
        }
    }
    authenticated
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    fn settings() -> crate::config::Settings {
        crate::config::Settings { device_profiles: vec![serde_json::from_value(serde_json::json!({"id":"phone","name":"Phone","username":"phone_user","password":"0123456789abcdef"})).unwrap()], ..Default::default() }
    }
    #[test]
    fn socks_credentials_return_only_verified_principal() {
        let settings = settings();
        assert_eq!(
            authenticate_credentials(b"phone_user", b"0123456789abcdef", &settings).as_deref(),
            Some("phone_user")
        );
        assert!(authenticate_credentials(b"phone_user", b"0123456789abcdeg", &settings).is_none());
        assert!(authenticate_credentials(b"phone", b"0123456789abcdef", &settings).is_none());
        assert!(authenticate_credentials(
            b"unknown",
            settings.proxy_password.as_bytes(),
            &settings
        )
        .is_none());
        assert_eq!(
            authenticate_credentials(
                settings.proxy_username.as_bytes(),
                settings.proxy_password.as_bytes(),
                &settings
            )
            .as_deref(),
            Some(settings.proxy_username.as_str())
        );
    }
    #[test]
    fn digest_resolves_profile_after_signature_and_replay_checks() {
        let settings = settings();
        let auth = DigestAuth::default();
        let uri = "http://example.com/";
        let challenge = auth.challenge(&Method::GET, uri);
        let nonce = parse_digest(&challenge).unwrap()["nonce"].clone();
        let username = "phone_user";
        let ha1 = md5_hex(format!("{username}:{REALM}:0123456789abcdef").as_bytes());
        let ha2 = md5_hex(format!("GET:{uri}").as_bytes());
        let response = md5_hex(format!("{ha1}:{nonce}:00000001:test:auth:{ha2}").as_bytes());
        let value=format!("Digest username=\"{username}\",realm=\"{REALM}\",nonce=\"{nonce}\",uri=\"{uri}\",response=\"{response}\",qop=auth,nc=00000001,cnonce=\"test\"");
        let request = Request::builder()
            .uri(uri)
            .header(PROXY_AUTHORIZATION, value)
            .body(())
            .unwrap();
        assert_eq!(
            auth.authenticate(&request, &settings).as_deref(),
            Some(username)
        );
        assert!(auth.authenticate(&request, &settings).is_none());
        let unverified = Request::builder()
            .uri(uri)
            .header(PROXY_AUTHORIZATION, "Digest username=\"phone_user\"")
            .body(())
            .unwrap();
        assert!(auth.authenticate(&unverified, &settings).is_none());
    }
}
