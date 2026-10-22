//! A public, read-only bootstrap on the already configured LAN HTTP socket.
//! Only public certificate data is exposed; no authentication/trust state is changed.
use super::*;
use crate::tls_inspection::CertificateFormat;

const MAX_SETUP_TARGET: usize = 1024;
const MAX_SETUP_QUERY: usize = 96;
const MAX_SETUP_BODY: usize = 32 * 1024;
const SETUP_PATH: &str = "/homeproxy/setup";
const CERT_PATH: &str = "/homeproxy/ca.cer";
const PROFILE_PATH: &str = "/homeproxy/ca.mobileconfig";

// Recognize escaped and traversal spellings as reserved too, so they cannot fall
// through to forwarding/authentication. We never use the decoded path to serve data.
fn reserved_path(path: &str) -> bool {
    if path == "/homeproxy" || path.starts_with("/homeproxy/") {
        return true;
    }
    // Streaming comparison avoids allocation and still recognizes a namespace
    // after a long prefix. The HTTP parser's header limit bounds total work.
    let namespace = b"homeproxy";
    let mut segment_length = 0usize;
    let mut segment_matches = true;
    let mut bytes = path.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        let byte = if byte == b'%' {
            let Some((a, b)) = bytes.next().zip(bytes.next()) else {
                return path.contains("homeproxy");
            };
            let hex_digit = |c: u8| (c as char).to_digit(16);
            let Some((a, b)) = hex_digit(a).zip(hex_digit(b)) else {
                return path.contains("homeproxy");
            };
            (a * 16 + b) as u8
        } else {
            byte
        };
        if matches!(byte, b'/' | b'\\') {
            if segment_matches && segment_length == namespace.len() {
                return true;
            }
            segment_length = 0;
            segment_matches = true;
        } else {
            segment_matches &= namespace.get(segment_length).copied() == Some(byte);
            segment_length = segment_length.saturating_add(1);
        }
    }
    segment_matches && segment_length == namespace.len()
}

fn query(query: Option<&str>) -> Option<(&str, &str)> {
    let query = query?;
    if query.len() > MAX_SETUP_QUERY || query.is_empty() {
        return None;
    }
    let mut lang = None;
    let mut fingerprint = None;
    for field in query.split('&') {
        let (key, value) = field.split_once('=')?;
        match key {
            "lang" if lang.is_none() && matches!(value, "cs" | "en") => lang = Some(value),
            "fp" if fingerprint.is_none()
                && value.len() == 64
                && value
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) =>
            {
                fingerprint = Some(value);
            }
            _ => return None,
        }
    }
    Some((lang.unwrap_or("cs"), fingerprint?))
}

fn local_response<B>(
    request: &Request<B>,
    status: StatusCode,
    mime: &'static str,
    body: Bytes,
    filename: Option<&'static str>,
) -> Response<ProxyBody> {
    let length = body.len();
    let mut response = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, mime)
        .header(CONTENT_LENGTH, length)
        .header(CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .header("x-frame-options", "DENY")
        .header("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        .header(CONNECTION, "close");
    if status == StatusCode::METHOD_NOT_ALLOWED {
        response = response.header("allow", "GET, HEAD");
    }
    if let Some(filename) = filename {
        response = response.header(CONTENT_DISPOSITION, filename);
    }
    response
        .body(if request.method() == Method::HEAD {
            empty_body()
        } else {
            full_body(body)
        })
        .unwrap_or_else(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Local response unavailable.",
            )
        })
}

// Browsers omit HTTP's default port. Accept that one canonical spelling only;
// every non-default port, IP alias and userinfo spelling must still be explicit.
fn matches_listener_authority(value: &str, address: SocketAddr) -> bool {
    let explicit = address.to_string();
    value == explicit || (address.port() == 80 && explicit.strip_suffix(":80") == Some(value))
}

pub(super) fn response<B>(
    request: &Request<B>,
    context: &ProxyContext,
) -> Option<Response<ProxyBody>> {
    let absolute_target = request.uri().scheme().is_some() || request.uri().authority().is_some();
    let local_authority = context.listener_address.is_some_and(|address| {
        request.uri().authority().is_some_and(|authority| {
            // Userinfo cannot make a local absolute target public. It is rejected
            // below, while third-party absolute URLs retain the ordinary proxy path.
            authority
                .as_str()
                .rsplit('@')
                .next()
                .is_some_and(|value| matches_listener_authority(value, address))
        })
    });
    if absolute_target && !local_authority {
        return None;
    }
    let local_connect = request.method() == Method::CONNECT && local_authority;
    if !reserved_path(request.uri().path()) && !local_connect {
        return None;
    }
    let error = |status, message: &'static str| {
        Some(local_response(
            request,
            status,
            "text/plain; charset=utf-8",
            Bytes::from_static(message.as_bytes()),
            None,
        ))
    };
    if request.uri().to_string().len() > MAX_SETUP_TARGET
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
    {
        return error(
            StatusCode::BAD_REQUEST,
            "Use the original local setup link before configuring the proxy.",
        );
    }
    let Some(address) = context.listener_address else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "LAN setup is unavailable.");
    };
    let mut hosts = request.headers().get_all(HOST).iter();
    if !hosts
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| matches_listener_authority(value, address))
        || hosts.next().is_some()
    {
        return error(StatusCode::BAD_REQUEST, "Invalid local Host.");
    }
    if request.headers().contains_key("upgrade")
        || request
            .headers()
            .get_all(CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|v| v.trim().eq_ignore_ascii_case("upgrade"))
    {
        return error(
            StatusCode::BAD_REQUEST,
            "Upgrades are unavailable on local setup.",
        );
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "Local setup supports GET and HEAD only.",
        );
    }
    if !matches!(request.uri().path(), SETUP_PATH | CERT_PATH | PROFILE_PATH) {
        return error(StatusCode::NOT_FOUND, "Unknown local setup resource.");
    }
    let Some((lang, expected_fingerprint)) = query(request.uri().query()) else {
        return error(
            StatusCode::BAD_REQUEST,
            "Invalid setup query. Open the current link from HomeProxy.",
        );
    };
    let selected_listener = match address.ip() {
        IpAddr::V4(ip) => {
            crate::config::is_private_lan_ip(ip)
                && context
                    .settings
                    .selected_listen_ips()
                    .is_ok_and(|ips| ips.contains(&ip))
        }
        IpAddr::V6(_) => false,
    };
    if !context.settings.lan_enabled || !selected_listener {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Enable the selected LAN listener in HomeProxy first.",
        );
    }
    let Ok(certificate) = context.tls_inspection.try_root_certificate_der() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Prepare the certificate in HomeProxy first.",
        );
    };
    let fingerprint = hex::encode(Sha256::digest(certificate.as_ref()));
    if fingerprint != expected_fingerprint {
        return error(
            StatusCode::CONFLICT,
            "The certificate has changed. Scan the current link from HomeProxy.",
        );
    }
    let (body, mime, filename) = match request.uri().path() {
        CERT_PATH => (
            Bytes::copy_from_slice(certificate.as_ref()),
            "application/pkix-cert",
            Some("attachment; filename=HomeProxy-CA.cer"),
        ),
        PROFILE_PATH => {
            // Reuse the authority's public PEM export, including its existing base64 encoder.
            let Ok(pem) = context
                .tls_inspection
                .export_certificate(CertificateFormat::Pem)
            else {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Certificate export unavailable.",
                );
            };
            let encoded = pem
                .certificate
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>();
            (
                Bytes::from(mobileconfig(certificate.as_ref(), &encoded)),
                "application/x-apple-aspen-config",
                Some("attachment; filename=HomeProxy-CA.mobileconfig"),
            )
        }
        _ => (
            Bytes::from(guide(lang, &fingerprint, certificate.as_ref(), address)),
            "text/html; charset=utf-8",
            None,
        ),
    };
    if body.len() > MAX_SETUP_BODY {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Local setup resource is too large.",
        );
    }
    Some(local_response(
        request,
        StatusCode::OK,
        mime,
        body,
        filename,
    ))
}

fn profile_uuid(der: &[u8], namespace: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(namespace);
    hash.update(der);
    let mut bytes = hash.finalize();
    // Deterministic UUID with RFC 9562 version 8 and RFC variant bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(&bytes[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn mobileconfig(der: &[u8], encoded: &str) -> String {
    let top = profile_uuid(der, b"homeproxy.profile.root-only.v1");
    let root = profile_uuid(der, b"homeproxy.payload.root-only.v1");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>local.homeproxy.ca.{top}</string>
<key>PayloadUUID</key><string>{top}</string>
<key>PayloadDisplayName</key><string>HomeProxy CA</string>
<key>PayloadDescription</key><string>HomeProxy public root certificate only. Verify its SHA-256 against your desktop before trusting it.</string>
<key>PayloadContent</key><array><dict>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>local.homeproxy.ca.root.{root}</string>
<key>PayloadUUID</key><string>{root}</string>
<key>PayloadDisplayName</key><string>HomeProxy Local HTTPS Inspection CA</string>
<key>PayloadCertificateFileName</key><string>HomeProxy-CA.cer</string>
<key>PayloadContent</key><data>{encoded}</data>
</dict></array></dict></plist>"#
    )
}

// No Host, credentials, profile names or settings snapshots are interpolated.
// All variable text is a validated language, digest or numeric socket endpoint.
fn guide(lang: &str, fingerprint: &str, der: &[u8], address: SocketAddr) -> String {
    let cs = lang == "cs";
    let choose = |cs: &'static str, en: &'static str| if lang == "cs" { cs } else { en };
    let display_fingerprint = crate::tls_inspection::certificate_fingerprint(der);
    let query = format!("lang={lang}&amp;fp={fingerprint}");
    let other = if cs { "en" } else { "cs" };
    let title = choose(
        "Připojte zařízení k HomeProxy",
        "Connect your device to HomeProxy",
    );
    let intro = choose("Začněte na své důvěryhodné domácí Wi-Fi. Tento odkaz otevřete ještě před nastavením proxy. Počítač s HomeProxy musí zůstat zapnutý.", "Start on your trusted home Wi-Fi. Open this link before configuring the proxy. Keep the HomeProxy computer running.");
    let download_title = choose(
        "1. Stáhněte a ověřte certifikát",
        "1. Download and verify the certificate",
    );
    let download_label = choose("Stáhnout certifikát .cer", "Download certificate .cer");
    let apple_label = choose("Apple: stáhnout profil CA", "Apple: download CA profile");
    let verify_title = choose(
        "Jak ověřit pravost certifikátu",
        "How to verify the certificate",
    );
    let verify_short = choose("Potvrďte jen certifikát z vašeho HomeProxy. Před instalací porovnejte SHA-256 staženého souboru s aplikací na počítači.", "Trust only the certificate from your HomeProxy. Before installation, compare the downloaded file's SHA-256 with the desktop app.");
    let verify = choose("Před instalací porovnejte SHA-256 skutečně staženého certifikátu s otiskem v aplikaci HomeProxy na počítači. Použijte podrobnosti certifikátu v systému, pokud SHA-256 zobrazují. Otisk této HTTP stránky sám pravost nedokazuje: útočník v síti může změnit stránku i soubor. Pokud otisk nemůžete ověřit, přeneste veřejný certifikát důvěryhodnou cestou přímo z počítače.", "Before installation, compare the SHA-256 of the actual downloaded certificate with HomeProxy on your desktop. Use your OS certificate details if they display SHA-256. This HTTP page's fingerprint alone does not prove authenticity: a network attacker could replace both the page and file. If you cannot verify the fingerprint, transfer the public certificate directly from the desktop using a trusted method.");
    let trust = choose("Tato CA umožní vašemu HomeProxy číst HTTPS provoz vybraný pro kontrolu. Instalujte ji jen na vlastní zařízení a až po ověření. Stažení není instalace ani potvrzení důvěry.", "This CA lets your HomeProxy read HTTPS traffic selected for inspection. Install it only on your own device after verification. Downloading does not install it or confirm trust.");
    let install_title = choose(
        "2. Nainstalujte CA v systému",
        "2. Install the CA in your OS",
    );
    let platform_hint = choose(
        "Vyberte zařízení. Názvy nabídek se mohou podle verze systému nebo výrobce lišit.",
        "Choose your device. Menu names vary by OS version and manufacturer.",
    );
    let android = choose("V Nastavení vyhledejte „certifikát CA“ nebo instalaci certifikátu v zabezpečení / šifrování a přihlašovacích údajích. Zvolte Certifikát CA a soubor HomeProxy-CA.cer (nikoli certifikát klienta pro Wi-Fi). Systém může požadovat zámek obrazovky a zobrazit upozornění na kontrolu provozu. Ne každá aplikace důvěřuje uživatelským CA. Pokud je instalace zakázaná správcem nebo chybí, HTTPS kontrolu pro toto zařízení nepoužívejte.", "In Settings, search for “CA certificate” or certificate installation under security / encryption and credentials. Choose CA certificate and HomeProxy-CA.cer (not a Wi-Fi client certificate). Your OS may require a screen lock and explain traffic inspection. Some apps do not trust user CAs. If installation is unavailable or restricted by an administrator, do not use HTTPS inspection for this device.");
    let windows = choose("Po ověření otevřete HomeProxy-CA.cer → Nainstalovat certifikát → Aktuální uživatel → Všechny certifikáty umístit v následujícím úložišti → Důvěryhodné kořenové certifikační autority. Instalaci potvrďte jen pro ověřenou CA. Některé prohlížeče mají vlastní úložiště důvěry.", "After verification, open HomeProxy-CA.cer → Install Certificate → Current User → Place all certificates in the following store → Trusted Root Certification Authorities. Confirm installation only for the verified CA. Some browsers maintain their own trust store.");
    let windows_hash = choose(
        "Windows: ověření SHA-256 souboru",
        "Windows: check the file's SHA-256",
    );
    let windows_hash_text = choose("Běžná položka „Thumbprint“ v dialogu Windows může být SHA-1, proto ji neporovnávejte se SHA-256. V terminálu otevřeném ve složce se staženým souborem spusťte následující příkaz a výsledek porovnejte s aplikací na počítači:", "The standard Windows certificate dialog's “Thumbprint” may be SHA-1; do not compare it with SHA-256. In a terminal opened in the downloaded file's folder, run this command and compare its result with the desktop app:");
    let ios = choose("V Safari stáhněte profil CA. V Nastavení otevřete stažený profil (případně Obecné → VPN a správa zařízení), zkontrolujte jeho jediný certifikát a po ověření jej nainstalujte. Pak Obecné → Informace → Důvěra certifikátů: povolte úplnou důvěru pro tuto ověřenou HomeProxy CA. Profil obsahuje pouze veřejný kořenový certifikát; nenastavuje Wi-Fi, VPN, MDM ani proxy.", "Download the CA profile in Safari. In Settings, open the downloaded profile (or General → VPN & Device Management), inspect its single certificate and install it after verification. Then General → About → Certificate Trust Settings: enable full trust for this verified HomeProxy CA. The profile contains only the public root certificate; it configures no Wi-Fi, VPN, MDM or proxy.");
    let mac = choose("Po ověření otevřete .cer v Klíčence, přidejte jej do přihlašovací klíčenky a u tohoto certifikátu nastavte důvěru pro SSL. Podle verze macOS může instalace profilu vyžadovat potvrzení v nastavení správy zařízení. Instalujte jen jednu variantu: .cer nebo profil CA.", "After verification, open the .cer in Keychain Access, add it to your login keychain and configure SSL trust for that certificate. Depending on macOS version, profile installation may require confirmation in device management settings. Install one variant: .cer or the CA profile.");
    let linux = choose("Po ověření importujte certifikát do úložiště důvěry použitého prohlížečem nebo distribucí. Postup se liší podle distribuce a prohlížeče; pro jediné zařízení stačí příslušné úložiště. PEM variantu můžete exportovat z aplikace na počítači, pokud ji systém vyžaduje.", "After verification, import the certificate into the trust store used by your browser or distribution. The procedure varies by distribution and browser; use the relevant store for this device. Export PEM from the desktop app if your system requires it.");
    let other_title = choose("Jiné zařízení / TV", "Other device / TV");
    let other_text = choose("Televize a některé aplikace neumí nainstalovat vlastní CA nebo ruční proxy. Nenuťte instalaci ani neobcházejte varování certifikátu. Na nepodporovaném zařízení ponechte HTTPS v tunelu bez kontroly; nastavení příslušné výjimky proveďte v aplikaci na počítači.", "TVs and some apps cannot install a custom CA or use a manual proxy. Do not force installation or bypass certificate warnings. Keep HTTPS as a tunnel without inspection on unsupported devices; configure the relevant exception in the desktop app.");
    let proxy_title = choose(
        "3. Nastavte ruční HTTP proxy",
        "3. Configure the manual HTTP proxy",
    );
    let proxy_text = choose("Teprve po stažení, ověření a instalaci certifikátu otevřete nastavení proxy pro tuto Wi-Fi nebo systém. Zadejte adresu a port níže. Použijte je i pro HTTPS proxy, pokud má systém samostatnou volbu. Vyžádá-li si zařízení přihlášení, uživatelské jméno a přístupový klíč najdete v aplikaci HomeProxy na počítači.", "After downloading, verifying and installing the certificate, open the proxy settings for this Wi-Fi network or your OS. Enter the address and port below. Use them for HTTPS proxy too if your OS provides a separate field. If your device asks for authentication, find the username and access key in HomeProxy on your desktop.");
    let test_title = choose(
        "4. Ověřte skutečné připojení",
        "4. Check the actual connection",
    );
    let test_text = choose("Otevřete běžný veřejný HTTPS web a v aplikaci na počítači ověřte provoz tohoto zařízení. Při chybě certifikátu se zastavte a zkontrolujte instalaci a důvěru; varování neobcházejte. Tato stránka nepotvrzuje správnou instalaci ani funkční proxy.", "Open a normal public HTTPS website and check this device's traffic in the desktop app. If a certificate error appears, stop and check installation and trust; do not bypass the warning. This page does not confirm installation or a working proxy.");
    let host_label = choose("Adresa", "Address");
    let port_label = choose("Port", "Port");
    let ip = address.ip();
    let port = address.port();
    let css = r#":root{color-scheme:dark;font-family:"Segoe UI Variable Display","Segoe UI",Inter,sans-serif;background:#0c1018;color:#edf2fc}*{box-sizing:border-box}body{margin:0}main{max-width:760px;margin:auto;padding:28px 20px 48px}header{display:flex;align-items:center;justify-content:space-between;gap:12px}.brand{font-weight:800;letter-spacing:-.03em;color:#ffd364}a{color:#ffd364;text-underline-offset:4px}a:focus-visible,summary:focus-visible{outline:3px solid #ffd364;outline-offset:4px}h1{font-size:clamp(1.85rem,6vw,2.7rem);line-height:1.12;letter-spacing:-.04em;margin:36px 0 16px}h2{font-size:1.2rem;margin:0 0 14px;line-height:1.4}p{line-height:1.65;color:#bfcadb;margin:12px 0}section{background:#151b26;border:1px solid #293346;border-radius:16px;margin:20px 0;padding:22px}nav{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}nav a{padding:10px 12px;border:1px solid #3c4961;border-radius:10px;font-size:.9rem}.button{display:block;text-align:center;background:#ffd364;color:#141820;font-weight:750;text-decoration:none;padding:14px 16px;border-radius:10px;margin:16px 0;line-height:1.4}.secondary{background:transparent;color:#ffd364;border:1px solid #8c7540}.fingerprint{display:block;overflow-wrap:anywhere;padding:14px;border:1px solid #3c4961;border-radius:10px;font: .82rem/1.6 ui-monospace,Consolas,monospace;color:#edf2fc}details{border-top:1px solid #303c50;padding:16px 0;scroll-margin-top:16px}summary{cursor:pointer;font-weight:650;line-height:1.5;min-height:28px}dl{display:grid;grid-template-columns:auto 1fr;gap:12px}dt{color:#bfcadb}dd{margin:0;font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere}code{overflow-wrap:anywhere}footer{font-size:.85rem;color:#aebbd0}strong{color:#edf2fc}@media(max-width:420px){main{padding:20px 16px 36px}section{padding:18px}nav a{font-size:.85rem}}"#;
    format!(
        r##"<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{title} · HomeProxy</title><style>{css}</style></head><body><main>
<header><span class="brand">HomeProxy</span><a href="{SETUP_PATH}?lang={other}&amp;fp={fingerprint}" lang="{other}">{other}</a></header>
<h1>{title}</h1><p>{intro}</p>
<section><h2>{download_title}</h2><a class="button" href="{CERT_PATH}?{query}">{download_label}</a><p>{verify_short}</p><p>{trust}</p><details><summary>{verify_title}</summary><p>{verify}</p><span class="fingerprint">SHA-256<br>{display_fingerprint}</span></details></section>
<section><h2>{install_title}</h2><p>{platform_hint}</p><nav aria-label="Platform"><a href="#android">Android</a><a href="#windows">Windows</a><a href="#ios">iPhone / iPad</a><a href="#mac">macOS</a><a href="#linux">Linux</a><a href="#other">{other_title}</a></nav>
<details id="android" open><summary>Android</summary><p>{android}</p></details>
<details id="windows" open><summary>Windows</summary><p>{windows}</p><details><summary>{windows_hash}</summary><p>{windows_hash_text}</p><code>certutil -hashfile HomeProxy-CA.cer SHA256</code></details></details>
<details id="ios"><summary>iPhone / iPad</summary><a class="button secondary" href="{PROFILE_PATH}?{query}">{apple_label}</a><p>{ios}</p></details><details id="mac"><summary>macOS</summary><p>{mac}</p></details><details id="linux"><summary>Linux</summary><p>{linux}</p></details><details id="other"><summary>{other_title}</summary><p>{other_text}</p></details></section>
<section><h2>{proxy_title}</h2><p>{proxy_text}</p><dl><dt>{host_label}</dt><dd>{ip}</dd><dt>{port_label}</dt><dd>{port}</dd></dl></section>
<section><h2>{test_title}</h2><p>{test_text}</p></section><footer>HomeProxy · {address}</footer>
</main></body></html>"##
    )
}

#[cfg(test)]
#[path = "device_setup_tests.rs"]
mod tests;
