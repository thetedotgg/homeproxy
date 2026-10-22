use std::{net::IpAddr, str::FromStr};

use crate::config::AdblockMode;

const MILD_HOSTS: &[&str] = &[
    "adservice.google.com",
    "adsrvr.org",
    "advertising.com",
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "scorecardresearch.com",
    // Curated service endpoints, reviewed 2026-09-20; updated with app releases.
    // Keep vendor portals, shared CDNs and browser-only filter modifiers out.
    // https://raw.githubusercontent.com/prebid/Prebid.js/master/modules/appnexusBidAdapter.js
    "ib.adnxs.com",
    "ib.adnxs-simple.com",
    // https://raw.githubusercontent.com/prebid/Prebid.js/master/modules/rubiconBidAdapter.js
    "fastlane.rubiconproject.com",
    "prebid-server.rubiconproject.com",
    // https://raw.githubusercontent.com/prebid/Prebid.js/master/modules/pubmaticBidAdapter.js
    "hbopenbid.pubmatic.com",
    "ads.pubmatic.com",
    "image8.pubmatic.com",
    // https://raw.githubusercontent.com/prebid/Prebid.js/master/modules/openxBidAdapter.js
    "rtb.openx.net",
    "u.openx.net",
    // https://raw.githubusercontent.com/prebid/Prebid.js/master/modules/ixBidAdapter.js
    "htlb.casalemedia.com",
    "dsum.casalemedia.com",
    // https://raw.githubusercontent.com/prebid/Prebid.js/master/modules/smartadserverBidAdapter.js
    "prg.smartadserver.com",
    // https://raw.githubusercontent.com/prebid/Prebid.js/master/modules/tripleliftBidAdapter.js
    "tlx.3lift.com",
    "eb2.3lift.com",
    // https://raw.githubusercontent.com/prebid/Prebid.js/master/modules/sovrnBidAdapter.js
    "ap.lijit.com",
    "ce.lijit.com",
    // https://raw.githubusercontent.com/prebid/Prebid.js/master/modules/yieldmoBidAdapter.js
    "ads.yieldmo.com",
    // https://raw.githubusercontent.com/prebid/Prebid.js/master/modules/sonobiBidAdapter.js
    "apex.go.sonobi.com",
    // https://partner.seznam.cz/napoveda/seznam-partner-program/postup-nasazeni-reklamy/
    "ssp.seznam.cz",
    "c-ko.seznam.cz",
];

const STRICT_HOSTS: &[&str] = &[
    "app-measurement.com",
    "facebook.net",
    "google-analytics.com",
    "googletagmanager.com",
    "hotjar.com",
    "segment.io",
    // Curated service endpoints, reviewed 2026-09-20; updated with app releases.
    // Keep vendor portals, shared CDNs and browser-only filter modifiers out.
    // https://amplitude.com/docs/apis/analytics/http-v2
    "api2.amplitude.com",
    "api.eu.amplitude.com",
    // https://developer.fullstory.com/browser/fullcapture/configure-capture/
    "rs.fullstory.com",
    "edge.fullstory.com",
    // https://raw.githubusercontent.com/mixpanel/mixpanel-js/master/src/mixpanel-core.js
    "api-js.mixpanel.com",
    "cdn.mxpnl.com",
    // https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-csp
    "clarity.ms",
    // https://api-docs.mouseflow.com/
    "cdn.mouseflow.com",
    // https://napoveda.sklik.cz/merici-skripty/retargetingovy-kod/
    "c.seznam.cz",
];

pub fn is_blocked_host(host: &str, mode: AdblockMode) -> bool {
    let host = normalize_host(host);
    match mode {
        AdblockMode::Off => false,
        AdblockMode::Mild => matches_any_suffix(&host, MILD_HOSTS),
        AdblockMode::Strict => {
            matches_any_suffix(&host, MILD_HOSTS) || matches_any_suffix(&host, STRICT_HOSTS)
        }
    }
}

pub fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn matches_any_suffix(host: &str, rules: &[&str]) -> bool {
    rules.iter().any(|rule| {
        host == *rule
            || host
                .strip_suffix(rule)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

pub fn destination_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || octets[0] == 0
                || octets[0] >= 224
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && matches!(octets[1], 18 | 19))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0))
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4() {
                return destination_is_public(IpAddr::V4(ipv4));
            }
            let segments = ip.segments();
            let is_6to4 = segments[0] == 0x2002;
            let is_teredo = segments[0] == 0x2001 && segments[1] == 0;
            let is_nat64_well_known = segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0];
            let is_nat64_local_use = segments[..3] == [0x0064, 0xff9b, 1];
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || is_6to4
                || is_teredo
                || is_nat64_well_known
                || is_nat64_local_use)
        }
    }
}

pub fn host_is_intrinsically_private(host: &str) -> bool {
    let normalized = normalize_host(host);
    if normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized.ends_with(".local")
        || normalized.ends_with(".home.arpa")
        || normalized.ends_with(".internal")
    {
        return true;
    }
    IpAddr::from_str(&normalized)
        .map(|ip| !destination_is_public(ip))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_rules_require_a_hostname_boundary() {
        assert!(is_blocked_host("cdn.doubleclick.net", AdblockMode::Mild));
        assert!(is_blocked_host("DOUBLECLICK.NET.", AdblockMode::Mild));
        assert!(!is_blocked_host("notdoubleclick.net", AdblockMode::Mild));
        assert!(!is_blocked_host("example.com", AdblockMode::Strict));
    }

    #[test]
    fn expanded_ads_and_trackers_keep_modes_and_hostname_boundaries() {
        for (host, minimum) in [
            ("hbopenbid.pubmatic.com", AdblockMode::Mild),
            ("ssp.seznam.cz", AdblockMode::Mild),
            ("c-ko.seznam.cz", AdblockMode::Mild),
            ("api2.amplitude.com", AdblockMode::Strict),
            ("rs.fullstory.com", AdblockMode::Strict),
            ("c.seznam.cz", AdblockMode::Strict),
        ] {
            assert!(!is_blocked_host(host, AdblockMode::Off));
            assert!(is_blocked_host(host, AdblockMode::Strict));
            assert_eq!(
                is_blocked_host(host, AdblockMode::Mild),
                minimum == AdblockMode::Mild
            );
            assert!(is_blocked_host(
                &format!("CDN.{}.", host.to_uppercase()),
                minimum
            ));
            assert!(!is_blocked_host(&format!("not{host}"), AdblockMode::Strict));
            assert!(!is_blocked_host(
                &format!("{host}.example"),
                AdblockMode::Strict
            ));
        }
        for host in [
            "pubmatic.com",
            "account.pubmatic.com",
            "rubiconproject.com",
            "openx.net",
            "privacy.criteo.com",
            "amazonaws.com",
            "cloudfront.net",
            "googleapis.com",
            "www.seznam.cz",
            "login.szn.cz",
            "email.seznam.cz",
            "youtube.com",
            "youtubei.googleapis.com",
            "googlevideo.com",
            "web.whatsapp.com",
            "signal.org",
            "app.amplitude.com",
            "app.fullstory.com",
            "mixpanel.com",
        ] {
            assert!(!is_blocked_host(host, AdblockMode::Strict), "{host}");
        }
    }

    #[test]
    fn private_and_metadata_targets_are_rejected() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "::1",
            "fe80::1",
            "fd00::1",
        ] {
            assert!(!destination_is_public(ip.parse().unwrap()), "{ip}");
        }
        assert!(destination_is_public("93.184.216.34".parse().unwrap()));
        assert!(destination_is_public(
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
        ));
    }

    #[test]
    fn ipv4_embedded_ipv6_uses_ipv4_policy() {
        for ip in [
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "::ffff:192.168.1.1",
            "::192.168.1.1",
            "::ffff:169.254.169.254",
            "::169.254.169.254",
        ] {
            assert!(!destination_is_public(ip.parse().unwrap()), "{ip}");
        }

        for ip in ["::ffff:93.184.216.34", "::93.184.216.34"] {
            assert!(destination_is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn ipv6_transition_prefixes_are_rejected() {
        let decisions = [
            "2002:7f00:1::",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "64:ff9b::7f00:1",
            "64:ff9b:1::7f00:1",
        ]
        .map(|ip| destination_is_public(ip.parse().unwrap()));

        assert_eq!(decisions, [false; 4]);
    }
}
