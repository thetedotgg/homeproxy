//! Static HTTPS scope and compatibility policy shared by CONNECT and offline readiness.
//! Inspection admission says nothing about whether an origin response is public/cacheable.
use crate::config::{policy_host_matches, HttpsInspectionScope, HttpsMode, Settings};

pub(crate) fn host_is_inspected(settings: &Settings, host: &str) -> bool {
    let all_supported = settings.https_inspection_scope == HttpsInspectionScope::AllSupportedHosts;
    settings.https_mode == HttpsMode::Inspect
        && settings.https_client_trust_acknowledged
        && (all_supported
            || settings
                .https_inspect_hosts
                .iter()
                .any(|rule| policy_host_matches(rule, host)))
        // The broad scope must not break Google sign-in, attestation, Play and image
        // hosts that YouTube/Play apps reach beside the video domains. The domain list
        // is hidden in this scope, so only the selected scope can opt such hosts in.
        && !(all_supported && host_matches_google_companion(host))
        && !settings
            .https_bypass_hosts
            .iter()
            .any(|rule| policy_host_matches(rule, host))
        && !host_matches_inspection_bypass(host)
        && !host_matches_video_tunnel(host)
        && !host_matches_pinned_update_service(host)
}

pub(crate) fn normalized_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

pub(crate) fn host_matches_inspection_bypass(host: &str) -> bool {
    const BASE_DOMAINS: &[&str] = &[
        "whatsapp.com",
        "whatsapp.net",
        "messenger.com",
        "facebook.com",
        "facebook.net",
        "fb.com",
        "fb.me",
        "fbcdn.net",
        "fbsbx.com",
        "m.me",
        "telegram.org",
        "telegram.me",
        "t.me",
        "tdesktop.com",
        "telesco.pe",
        "signal.org",
        "signal.group",
        "signal.me",
        "signal.art",
        "signalusers.org",
        "whispersystems.org",
    ];
    let host = normalized_host(host);
    BASE_DOMAINS.iter().any(|base| {
        host == *base
            || host
                .strip_suffix(base)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

// TV clients may not trust a user-installed CA and may never retry a rejected TLS
// connection. These video endpoints stay end-to-end TLS from their first request.
pub(crate) fn host_matches_video_tunnel(host: &str) -> bool {
    let host = normalized_host(host);
    [
        "youtube.com",
        "googlevideo.com",
        "ytimg.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
    ]
    .iter()
    .any(|base| {
        host == *base
            || host
                .strip_suffix(base)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

// Android TV/Play/YouTube clients reach Google account, attestation, API and image
// hosts beside the video domains; they usually reject a user-installed CA there too.
pub(crate) fn host_matches_google_companion(host: &str) -> bool {
    let host = normalized_host(host);
    [
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "ggpht.com",
        "googleusercontent.com",
        "youtu.be",
        "youtube-nocookie.com",
        "youtubekids.com",
        // Play/YouTube app assets and updates, Android connectivity checks.
        "gvt1.com",
        "gvt2.com",
        "gvt3.com",
        "android.com",
        // In-app ads when the ad filter is off; failing ad requests can stall playback.
        "doubleclick.net",
        "googleadservices.com",
        "googlesyndication.com",
        // App telemetry; a failing SDK request should not hold the app back.
        "google-analytics.com",
        "googletagmanager.com",
        "app-measurement.com",
        "crashlytics.com",
    ]
    .iter()
    .any(|base| {
        host == *base
            || host
                .strip_suffix(base)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

// Microsoft requires end-to-end TLS for these certificate-pinned cloud services.
// Payload endpoints and HTTP Range downloads retain their existing policies.
// https://learn.microsoft.com/en-us/windows/deployment/do/delivery-optimization-proxy
pub(crate) fn host_matches_pinned_update_service(host: &str) -> bool {
    let host = normalized_host(host);
    let base = "do.dsp.mp.microsoft.com";
    host == base
        || host
            .strip_suffix(base)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_hosts_keep_exact_and_label_bounded_wildcards() {
        let mut settings = Settings {
            https_mode: HttpsMode::Inspect,
            https_client_trust_acknowledged: true,
            https_inspect_hosts: vec!["example.com".into(), "*.assets.example".into()],
            https_bypass_hosts: vec!["private.assets.example".into(), "*.excluded.example".into()],
            ..Settings::default()
        };
        for host in [
            "EXAMPLE.com.",
            "img.assets.example",
            "nested.img.assets.example",
        ] {
            assert!(host_is_inspected(&settings, host), "{host}");
        }
        for host in [
            "unlisted.example",
            "sub.example.com",
            "assets.example",
            "notassets.example",
            "assets.example.attacker",
            "private.assets.example",
        ] {
            assert!(!host_is_inspected(&settings, host), "{host}");
        }
        settings.https_inspect_hosts.clear();
        assert!(!host_is_inspected(&settings, "unlisted.example"));
        settings.https_inspection_scope = HttpsInspectionScope::AllSupportedHosts;
        for host in [
            "unlisted.example",
            "assets.example",
            "notassets.example",
            "youtube.com.attacker",
            "notwhatsapp.com",
            "do.dsp.mp.microsoft.com.attacker",
            "google.com.attacker",
            "notgoogleapis.com",
            "ggpht.com.example",
            "android.com.example",
            "notdoubleclick.net",
        ] {
            assert!(host_is_inspected(&settings, host), "{host}");
        }
        for host in [
            "private.assets.example",
            "a.excluded.example",
            "web.whatsapp.com",
            "CHAT.signal.org.",
            "youtube.com",
            "r.googlevideo.com",
            "i.ytimg.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "do.dsp.mp.microsoft.com",
            "geo.do.dsp.mp.microsoft.com",
            "accounts.google.com",
            "www.google.com",
            "oauth2.googleapis.com",
            "jnn-pa.googleapis.com",
            "play.googleapis.com",
            "www.gstatic.com",
            "yt3.ggpht.com",
            "yt3.googleusercontent.com",
            "youtu.be",
            "www.youtube-nocookie.com",
            "www.youtubekids.com",
            "redirector.gvt1.com",
            "beacons.gvt2.com",
            "connectivitycheck.android.com",
            "googleads.g.doubleclick.net",
            "www.googleadservices.com",
            "pagead2.googlesyndication.com",
            "www.google-analytics.com",
            "app-measurement.com",
            "settings.crashlytics.com",
        ] {
            assert!(!host_is_inspected(&settings, host), "{host}");
        }
        // A stale list hidden in the broad scope cannot re-enable Google inspection;
        // the selected scope still honours an explicit choice.
        settings.https_inspect_hosts = vec!["*.gstatic.com".into()];
        assert!(!host_is_inspected(&settings, "fonts.gstatic.com"));
        assert!(!host_is_inspected(&settings, "yt3.ggpht.com"));
        settings.https_inspection_scope = HttpsInspectionScope::SelectedHosts;
        assert!(host_is_inspected(&settings, "fonts.gstatic.com"));
        assert!(!host_is_inspected(&settings, "yt3.ggpht.com"));
        settings.https_inspection_scope = HttpsInspectionScope::AllSupportedHosts;
        settings.https_inspect_hosts.clear();
        settings.https_client_trust_acknowledged = false;
        assert!(!host_is_inspected(&settings, "unlisted.example"));
        settings.https_client_trust_acknowledged = true;
        settings.https_mode = HttpsMode::Tunnel;
        assert!(!host_is_inspected(&settings, "unlisted.example"));
    }
}
