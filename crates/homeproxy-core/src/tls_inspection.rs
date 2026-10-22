use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(not(unix))]
use tempfile::NamedTempFile;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};
use zeroize::Zeroize;

pub(crate) const AUTHORITY_RECORD_FILE: &str = "https-inspection-authority-v1.json";
const AUTHORITY_RECORD_VERSION: u8 = 1;
const MAX_AUTHORITY_RECORD_BYTES: u64 = 128 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 32 * 1024;
const MAX_PROTECTED_KEY_BYTES: usize = 32 * 1024;
const MAX_LEAF_CONFIGS: usize = 256;
const LEAF_LIFETIME_DAYS: i64 = 30;
// Renew well before expiry: a long-running daemon otherwise keeps serving one leaf
// per host until clients reject it as expired.
const LEAF_RENEW_BEFORE_DAYS: i64 = 7;
const CA_COMMON_NAME: &str = "HomeProxy Local HTTPS Inspection CA";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateFormat {
    Pem,
    Der,
}

/// Public authority certificate only. The private key is never part of an export.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportedCertificate {
    pub format: CertificateFormat,
    /// `pem` for PEM text, `hex` for DER bytes carried through JSON.
    pub encoding: String,
    pub certificate: String,
    /// Uppercase, colon-separated SHA-256 of the DER certificate.
    pub sha256_fingerprint: String,
    pub subject: String,
}

/// Authority state for status reports. Being prepared is neither Inspect nor client trust.
pub(crate) struct AuthorityState {
    pub(crate) prepared: bool,
    pub(crate) active: bool,
    pub(crate) sha256_fingerprint: Option<String>,
    pub(crate) error: Option<String>,
}

/// Clones share one provider, so an activated authority is visible to every holder.
#[derive(Clone)]
pub(crate) struct TlsInspection {
    provider: Arc<AuthorityProvider>,
}

/// Nothing is read or created until an explicit prepare or an Inspect activation.
struct AuthorityProvider {
    record_path: PathBuf,
    /// `None` uses the platform roots; tests supply fixed roots.
    fixed_roots: Option<RootCertStore>,
    active: OnceLock<Arc<TlsInspectionInner>>,
    prepared: OnceLock<CertificateDer<'static>>,
    transition: Mutex<()>,
}

struct TlsInspectionInner {
    issuer: Issuer<'static, KeyPair>,
    ca_certificate: CertificateDer<'static>,
    upstream_config: Arc<ClientConfig>,
    leaf_configs: Mutex<HashMap<String, CachedLeaf>>,
}

struct CachedLeaf {
    config: Arc<ServerConfig>,
    issued_at: OffsetDateTime,
    renew_after: OffsetDateTime,
}

impl CachedLeaf {
    // A clock stepped back before issuance would make clients see "not yet valid".
    fn is_current(&self, now: OffsetDateTime) -> bool {
        self.issued_at <= now && now < self.renew_after
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorityRecord {
    version: u8,
    certificate_der_hex: String,
    protected_private_key_hex: String,
}

impl TlsInspection {
    /// Eager authority with platform roots; production engines use [`TlsInspection::lazy`].
    #[cfg(test)]
    pub(crate) fn load_or_create(record_path: PathBuf) -> Result<Self, TlsInspectionError> {
        let inspection = Self::lazy(record_path);
        inspection.activate(true)?;
        Ok(inspection)
    }

    /// Lazy provider: construction performs no I/O and never creates an authority.
    pub(crate) fn lazy(record_path: PathBuf) -> Self {
        Self::lazy_with_roots(record_path, None)
    }

    fn lazy_with_roots(record_path: PathBuf, fixed_roots: Option<RootCertStore>) -> Self {
        Self {
            provider: Arc::new(AuthorityProvider {
                record_path,
                fixed_roots,
                active: OnceLock::new(),
                prepared: OnceLock::new(),
                transition: Mutex::new(()),
            }),
        }
    }

    fn available(&self) -> Result<&Arc<TlsInspectionInner>, TlsInspectionError> {
        self.provider
            .active
            .get()
            .ok_or(TlsInspectionError::InspectionUnavailable)
    }

    pub(crate) fn is_active(&self) -> bool {
        self.available().is_ok()
    }

    /// Loads the authority for live inspection. Without `create`, a missing authority fails
    /// closed with `NotPrepared` instead of being generated implicitly.
    pub(crate) fn activate(&self, create: bool) -> Result<(), TlsInspectionError> {
        let provider = &self.provider;
        if provider.active.get().is_some() {
            return Ok(());
        }
        let _transition = provider
            .transition
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if provider.active.get().is_some() {
            return Ok(());
        }
        let inner = build_inspection(&provider.record_path, provider.fixed_roots.clone(), create)?;
        let _ = provider.prepared.set(inner.ca_certificate.clone());
        let _ = provider.active.set(Arc::new(inner));
        Ok(())
    }

    /// Explicitly creates (or validates an existing) authority. Does not activate inspection.
    pub(crate) fn prepare(&self) -> Result<CertificateDer<'static>, TlsInspectionError> {
        let provider = &self.provider;
        if let Some(inner) = provider.active.get() {
            return Ok(inner.ca_certificate.clone());
        }
        let _transition = provider
            .transition
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (certificate, key) = load_or_create_authority(&provider.record_path)?;
        validate_authority(&certificate, &key)?;
        drop(key);
        let _ = provider.prepared.set(certificate.clone());
        Ok(certificate)
    }

    /// The validated public certificate of an existing authority; never creates one.
    fn prepared_certificate(&self) -> Result<Option<CertificateDer<'static>>, TlsInspectionError> {
        let provider = &self.provider;
        if let Some(inner) = provider.active.get() {
            return Ok(Some(inner.ca_certificate.clone()));
        }
        if let Some(certificate) = provider.prepared.get() {
            return Ok(Some(certificate.clone()));
        }
        let _transition = provider
            .transition
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((certificate, key)) = load_authority(&provider.record_path)? else {
            return Ok(None);
        };
        validate_authority(&certificate, &key)?;
        drop(key);
        let _ = provider.prepared.set(certificate.clone());
        Ok(Some(certificate))
    }

    pub(crate) fn authority_state(&self) -> AuthorityState {
        let active = self.is_active();
        match self.prepared_certificate() {
            Ok(certificate) => AuthorityState {
                prepared: certificate.is_some(),
                active,
                sha256_fingerprint: certificate
                    .map(|certificate| certificate_fingerprint(certificate.as_ref())),
                error: None,
            },
            Err(error) => AuthorityState {
                prepared: false,
                active,
                sha256_fingerprint: None,
                error: Some(error.to_string()),
            },
        }
    }

    /// Exports the public certificate of a prepared authority, never its key.
    pub(crate) fn export_certificate(
        &self,
        format: CertificateFormat,
    ) -> Result<ExportedCertificate, TlsInspectionError> {
        let certificate = self
            .prepared_certificate()?
            .ok_or(TlsInspectionError::NotPrepared)?;
        Ok(export_certificate(certificate.as_ref(), format))
    }

    pub(crate) fn try_root_certificate_der(
        &self,
    ) -> Result<CertificateDer<'static>, TlsInspectionError> {
        self.prepared_certificate()?
            .ok_or(TlsInspectionError::InspectionUnavailable)
    }

    #[cfg(test)]
    pub(crate) fn root_certificate_der(&self) -> CertificateDer<'static> {
        self.try_root_certificate_der().unwrap()
    }

    pub(crate) fn install_current_user_root(&self) -> Result<(), TlsInspectionError> {
        install_current_user_root(self.available()?.ca_certificate.as_ref())
    }

    #[cfg(test)]
    pub(crate) fn acceptor_for_host(
        &self,
        host: &str,
    ) -> Result<tokio_rustls::TlsAcceptor, TlsInspectionError> {
        Ok(tokio_rustls::TlsAcceptor::from(
            self.server_config_for_host(host)?,
        ))
    }

    pub(crate) fn server_config_for_host(
        &self,
        host: &str,
    ) -> Result<Arc<ServerConfig>, TlsInspectionError> {
        self.server_config_for_host_at(host, OffsetDateTime::now_utc())
    }

    fn server_config_for_host_at(
        &self,
        host: &str,
        now: OffsetDateTime,
    ) -> Result<Arc<ServerConfig>, TlsInspectionError> {
        let inner = self.available()?;
        let cache_key = host.to_ascii_lowercase();
        if cache_key.is_empty() || cache_key.len() > 255 {
            return Err(TlsInspectionError::InvalidHost);
        }
        if let Some(config) = inner
            .leaf_configs
            .lock()
            .map_err(|_| TlsInspectionError::LeafCache)?
            .get(&cache_key)
            .filter(|leaf| leaf.is_current(now))
            .map(|leaf| leaf.config.clone())
        {
            return Ok(config);
        }

        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(LEAF_LIFETIME_DAYS);
        let certificate = params.signed_by(&leaf_key, &inner.issuer)?;
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate.der().clone()], private_key)?,
        );

        let mut configs = inner
            .leaf_configs
            .lock()
            .map_err(|_| TlsInspectionError::LeafCache)?;
        if let Some(current) = configs.get(&cache_key).filter(|leaf| leaf.is_current(now)) {
            // A parallel handshake already stored a fresh leaf; keep one per host.
            return Ok(current.config.clone());
        }
        if !configs.contains_key(&cache_key) && configs.len() >= MAX_LEAF_CONFIGS {
            configs.clear();
        }
        configs.insert(
            cache_key,
            CachedLeaf {
                config: config.clone(),
                issued_at: now,
                renew_after: now + Duration::days(LEAF_LIFETIME_DAYS - LEAF_RENEW_BEFORE_DAYS),
            },
        );
        Ok(config)
    }

    pub(crate) async fn connect_upstream(
        &self,
        host: &str,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>, TlsInspectionError> {
        let inner = self.available()?;
        let server_name =
            ServerName::try_from(host.to_string()).map_err(|_| TlsInspectionError::InvalidHost)?;
        TlsConnector::from(inner.upstream_config.clone())
            .connect(server_name, stream)
            .await
            .map_err(TlsInspectionError::UpstreamHandshake)
    }

    #[cfg(test)]
    pub(crate) fn for_tests(
        record_path: PathBuf,
        roots: RootCertStore,
    ) -> Result<Self, TlsInspectionError> {
        let inspection = Self::lazy_for_tests(record_path, roots);
        inspection.activate(true)?;
        Ok(inspection)
    }

    #[cfg(test)]
    pub(crate) fn lazy_for_tests(record_path: PathBuf, roots: RootCertStore) -> Self {
        Self::lazy_with_roots(record_path, Some(roots))
    }
}

/// Upstream validation never trusts the inspection authority itself.
fn build_inspection(
    record_path: &Path,
    fixed_roots: Option<RootCertStore>,
    create: bool,
) -> Result<TlsInspectionInner, TlsInspectionError> {
    let (ca_certificate, ca_key) = if create {
        load_or_create_authority(record_path)?
    } else {
        load_authority(record_path)?.ok_or(TlsInspectionError::NotPrepared)?
    };
    let ca_public_key = validate_authority(&ca_certificate, &ca_key)?;
    let roots = match fixed_roots {
        Some(roots) => exclude_authority(roots, &ca_public_key),
        None => {
            let native = rustls_native_certs::load_native_certs();
            let mut roots = RootCertStore::empty();
            for certificate in native.certs {
                add_upstream_root(&mut roots, certificate, &ca_public_key);
            }
            if roots.is_empty() {
                return Err(TlsInspectionError::NoNativeRoots);
            }
            roots
        }
    };
    from_authority(ca_certificate, ca_key, roots)
}

fn exclude_authority(mut roots: RootCertStore, inspection_public_key: &[u8]) -> RootCertStore {
    roots
        .roots
        .retain(|root| root.subject_public_key_info.as_ref() != inspection_public_key);
    roots
}

fn from_authority(
    ca_certificate: CertificateDer<'static>,
    ca_key: KeyPair,
    roots: RootCertStore,
) -> Result<TlsInspectionInner, TlsInspectionError> {
    let issuer = Issuer::new(ca_parameters(), ca_key);
    let mut validation_roots = RootCertStore::empty();
    validation_roots
        .add(ca_certificate.clone())
        .map_err(TlsInspectionError::InvalidCaCertificate)?;
    let upstream_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsInspectionInner {
        issuer,
        ca_certificate,
        upstream_config: Arc::new(upstream_config),
        leaf_configs: Mutex::new(HashMap::new()),
    })
}

pub(crate) fn certificate_fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn export_certificate(der: &[u8], format: CertificateFormat) -> ExportedCertificate {
    let (encoding, certificate) = match format {
        CertificateFormat::Pem => ("pem", pem_certificate(der)),
        CertificateFormat::Der => ("hex", hex::encode(der)),
    };
    ExportedCertificate {
        format,
        encoding: encoding.into(),
        certificate,
        sha256_fingerprint: certificate_fingerprint(der),
        subject: CA_COMMON_NAME.into(),
    }
}

fn pem_certificate(der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(der.len().div_ceil(3) * 4);
    for chunk in der.chunks(3) {
        let triple = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        let symbol = |shift: u32| char::from(ALPHABET[((triple >> shift) & 63) as usize]);
        encoded.push(symbol(18));
        encoded.push(symbol(12));
        encoded.push(if chunk.len() > 1 { symbol(6) } else { '=' });
        encoded.push(if chunk.len() > 2 { symbol(0) } else { '=' });
    }
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn validate_authority(
    certificate: &CertificateDer<'static>,
    key: &KeyPair,
) -> Result<Vec<u8>, TlsInspectionError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(certificate.clone())
        .map_err(TlsInspectionError::InvalidCaCertificate)?;
    let certificate_public_key = roots
        .roots
        .first()
        .ok_or(TlsInspectionError::InvalidRecord)?
        .subject_public_key_info
        .as_ref();
    let key_public_key = key.subject_public_key_info();
    if certificate_public_key != der_sequence_contents(&key_public_key)? {
        return Err(TlsInspectionError::InvalidRecord);
    }
    Ok(certificate_public_key.to_vec())
}

fn der_sequence_contents(der: &[u8]) -> Result<&[u8], TlsInspectionError> {
    if der.first() != Some(&0x30) {
        return Err(TlsInspectionError::InvalidRecord);
    }
    let first_length = *der.get(1).ok_or(TlsInspectionError::InvalidRecord)?;
    let (header_length, content_length) = if first_length & 0x80 == 0 {
        (2usize, usize::from(first_length))
    } else {
        let length_bytes = usize::from(first_length & 0x7f);
        if length_bytes == 0 || length_bytes > std::mem::size_of::<usize>() {
            return Err(TlsInspectionError::InvalidRecord);
        }
        let length_slice = der
            .get(2..2 + length_bytes)
            .ok_or(TlsInspectionError::InvalidRecord)?;
        if length_slice.first() == Some(&0) {
            return Err(TlsInspectionError::InvalidRecord);
        }
        let content_length = length_slice.iter().try_fold(0usize, |length, byte| {
            length.checked_mul(256)?.checked_add(usize::from(*byte))
        });
        (
            2 + length_bytes,
            content_length.ok_or(TlsInspectionError::InvalidRecord)?,
        )
    };
    let end = header_length
        .checked_add(content_length)
        .ok_or(TlsInspectionError::InvalidRecord)?;
    if end != der.len() {
        return Err(TlsInspectionError::InvalidRecord);
    }
    der.get(header_length..end)
        .ok_or(TlsInspectionError::InvalidRecord)
}

fn add_upstream_root(
    roots: &mut RootCertStore,
    certificate: CertificateDer<'static>,
    inspection_public_key: &[u8],
) -> bool {
    let mut parsed = RootCertStore::empty();
    if parsed.add(certificate).is_err()
        || parsed.roots[0].subject_public_key_info.as_ref() == inspection_public_key
    {
        return false;
    }
    roots.roots.push(parsed.roots.remove(0));
    true
}

fn ca_parameters() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.use_authority_key_identifier_extension = true;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(3650);
    params
}

/// `Ok(None)` only when the record (or its directory) does not exist.
fn load_authority(
    record_path: &Path,
) -> Result<Option<(CertificateDer<'static>, KeyPair)>, TlsInspectionError> {
    let Some(mut bytes) = read_record(record_path)? else {
        return Ok(None);
    };
    let record = serde_json::from_slice::<AuthorityRecord>(&bytes);
    bytes.zeroize();
    let mut record = record?;
    let authority = decode_record(&record);
    record.protected_private_key_hex.zeroize();
    authority.map(Some)
}

fn decode_record(
    record: &AuthorityRecord,
) -> Result<(CertificateDer<'static>, KeyPair), TlsInspectionError> {
    if record.version != AUTHORITY_RECORD_VERSION {
        return Err(TlsInspectionError::InvalidRecord);
    }
    let certificate = hex::decode(&record.certificate_der_hex)?;
    let mut protected_key = hex::decode(&record.protected_private_key_hex)?;
    if certificate.is_empty()
        || certificate.len() > MAX_CERTIFICATE_BYTES
        || protected_key.is_empty()
        || protected_key.len() > MAX_PROTECTED_KEY_BYTES
    {
        protected_key.zeroize();
        return Err(TlsInspectionError::InvalidRecord);
    }
    let private_key = unprotect_key_material(&protected_key);
    protected_key.zeroize();
    let mut private_key = private_key?;
    let key_pair = KeyPair::try_from(private_key.as_slice());
    private_key.zeroize();
    Ok((CertificateDer::from(certificate), key_pair?))
}

fn load_or_create_authority(
    record_path: &Path,
) -> Result<(CertificateDer<'static>, KeyPair), TlsInspectionError> {
    if let Some(authority) = load_authority(record_path)? {
        return Ok(authority);
    }
    let key_pair = KeyPair::generate()?;
    let certificate = ca_parameters().self_signed(&key_pair)?.der().clone();
    let mut private_key = key_pair.serialize_der();
    let protected_key = protect_key_material(&private_key);
    private_key.zeroize();
    let mut protected_key = protected_key?;
    let mut record = AuthorityRecord {
        version: AUTHORITY_RECORD_VERSION,
        certificate_der_hex: hex::encode(certificate.as_ref()),
        protected_private_key_hex: hex::encode(&protected_key),
    };
    protected_key.zeroize();
    let bytes = serde_json::to_vec_pretty(&record);
    record.protected_private_key_hex.zeroize();
    let mut bytes = bytes?;
    let written = write_record(record_path, &bytes);
    bytes.zeroize();
    written?;
    // Read back through the same checks; a concurrent creator's record wins.
    load_authority(record_path)?.ok_or(TlsInspectionError::InvalidRecord)
}

/// No-clobber publication of a fully written and synced record.
#[cfg(not(unix))]
fn persist_new(temporary: NamedTempFile, record_path: &Path) -> Result<(), TlsInspectionError> {
    match temporary.persist_noclobber(record_path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(TlsInspectionError::Io(error.error)),
    }
}

#[cfg(not(unix))]
fn read_record(record_path: &Path) -> Result<Option<Vec<u8>>, TlsInspectionError> {
    match std::fs::metadata(record_path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.len() > MAX_AUTHORITY_RECORD_BYTES {
                return Err(TlsInspectionError::InvalidRecord);
            }
            Ok(Some(std::fs::read(record_path)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(TlsInspectionError::Io(error)),
    }
}

#[cfg(not(unix))]
fn write_record(record_path: &Path, bytes: &[u8]) -> Result<(), TlsInspectionError> {
    use std::io::Write;
    let parent = record_path
        .parent()
        .ok_or(TlsInspectionError::InvalidRecord)?;
    std::fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    persist_new(temporary, record_path)
}

#[cfg(unix)]
use private_storage::{read_record, write_record};

/// The private key is only file-permission protected on Unix, so the record must stay in an
/// owner-only directory as an owner-only, single-link regular file of the effective user.
/// Every check is made on the open descriptor, not on a path that could be swapped.
#[cfg(unix)]
mod private_storage {
    use std::{
        ffi::CString,
        fs::{self, DirBuilder, File, OpenOptions},
        io::{self, Read, Write},
        os::unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            io::{AsRawFd, FromRawFd},
        },
        path::Path,
    };

    use zeroize::Zeroize;

    use super::{TlsInspectionError, MAX_AUTHORITY_RECORD_BYTES};

    const DIRECTORY_MODE: u32 = 0o700;
    const RECORD_MODE: u32 = 0o600;

    fn effective_uid() -> u32 {
        // SAFETY: geteuid has no arguments or preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    fn split(record_path: &Path) -> Result<(&Path, CString), TlsInspectionError> {
        let parent = record_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(TlsInspectionError::InvalidRecord)?;
        let name = record_path
            .file_name()
            .ok_or(TlsInspectionError::InvalidRecord)?;
        let name = CString::new(name.as_bytes()).map_err(|_| TlsInspectionError::InvalidRecord)?;
        Ok((parent, name))
    }

    fn link_error(error: io::Error, reason: &'static str) -> TlsInspectionError {
        match error.raw_os_error() {
            Some(code) if code == libc::ELOOP || code == libc::EMLINK || code == libc::ENOTDIR => {
                TlsInspectionError::UnsafeStorage(reason)
            }
            _ => TlsInspectionError::Io(error),
        }
    }

    fn open_private_directory(parent: &Path) -> Result<Option<File>, TlsInspectionError> {
        let directory = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)
        {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(link_error(
                    error,
                    "adresář certifikátu nesmí být symbolický odkaz",
                ))
            }
        };
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != effective_uid()
            || metadata.mode() & 0o777 != DIRECTORY_MODE
        {
            return Err(TlsInspectionError::UnsafeStorage(
                "adresář certifikátu musí patřit uživateli služby a mít oprávnění 0700",
            ));
        }
        Ok(Some(directory))
    }

    fn check_record(metadata: &fs::Metadata) -> Result<(), TlsInspectionError> {
        let reason = if !metadata.file_type().is_file() {
            "záznam certifikátu musí být běžný soubor"
        } else if metadata.uid() != effective_uid() {
            "záznam certifikátu musí patřit uživateli služby"
        } else if metadata.nlink() != 1 {
            "záznam certifikátu nesmí mít další pevné odkazy"
        } else if metadata.mode() & 0o777 != RECORD_MODE {
            "záznam certifikátu musí mít oprávnění 0600"
        } else if metadata.len() > MAX_AUTHORITY_RECORD_BYTES {
            return Err(TlsInspectionError::InvalidRecord);
        } else {
            return Ok(());
        };
        Err(TlsInspectionError::UnsafeStorage(reason))
    }

    pub(super) fn read_record(record_path: &Path) -> Result<Option<Vec<u8>>, TlsInspectionError> {
        let (parent, name) = split(record_path)?;
        let Some(directory) = open_private_directory(parent)? else {
            return Ok(None);
        };
        // O_NONBLOCK keeps a planted FIFO from blocking before the type check.
        // SAFETY: `name` is NUL-terminated and `directory` stays open for the call.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NOCTTY
                    | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(link_error(
                error,
                "záznam certifikátu nesmí být symbolický odkaz",
            ));
        }
        // SAFETY: openat returned a new descriptor owned by nothing else.
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata()?;
        check_record(&metadata)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        let read = (&file)
            .take(MAX_AUTHORITY_RECORD_BYTES + 1)
            .read_to_end(&mut bytes);
        if let Err(error) = read {
            bytes.zeroize();
            return Err(TlsInspectionError::Io(error));
        }
        if bytes.len() as u64 != metadata.len() {
            bytes.zeroize();
            return Err(TlsInspectionError::InvalidRecord);
        }
        Ok(Some(bytes))
    }

    pub(super) fn write_record(record_path: &Path, bytes: &[u8]) -> Result<(), TlsInspectionError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);
        let (parent, target) = split(record_path)?;
        DirBuilder::new()
            .recursive(true)
            .mode(DIRECTORY_MODE)
            .create(parent)?;
        let directory = open_private_directory(parent)?.ok_or(TlsInspectionError::InvalidRecord)?;
        // All creation and publication use the checked directory descriptor. A concurrent
        // rename or replacement of the path cannot redirect private-key writes elsewhere.
        let (name, mut temporary) = loop {
            let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
            let name =
                CString::new(format!(".homeproxy-ca-{}-{sequence}", std::process::id())).unwrap();
            // SAFETY: directory and NUL-terminated name live throughout openat.
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    RECORD_MODE,
                )
            };
            if descriptor >= 0 {
                // SAFETY: openat returned a newly owned descriptor.
                break (name, unsafe { File::from_raw_fd(descriptor) });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(TlsInspectionError::Io(error));
            }
            if sequence > 1_000_000 {
                return Err(TlsInspectionError::InvalidRecord);
            }
        };
        struct Cleanup<'a>(&'a File, &'a CString);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                // SAFETY: directory descriptor and name remain alive for the call.
                unsafe {
                    libc::unlinkat(self.0.as_raw_fd(), self.1.as_ptr(), 0);
                }
            }
        }
        let cleanup = Cleanup(&directory, &name);
        check_record(&temporary.metadata()?)?;
        temporary.write_all(bytes)?;
        temporary.sync_all()?;
        // Linux renameat2 publishes without clobber and without an intermediate hard link,
        // so concurrent readers always see the required nlink=1.
        // SAFETY: names and checked directory descriptor remain alive throughout the call.
        #[cfg(target_os = "linux")]
        let linked = unsafe {
            libc::renameat2(
                directory.as_raw_fd(),
                name.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(not(target_os = "linux"))]
        let linked = unsafe {
            libc::linkat(
                directory.as_raw_fd(),
                name.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
                0,
            )
        };
        if linked < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(TlsInspectionError::Io(error));
            }
        }
        drop(cleanup);
        directory.sync_all()?;
        Ok(())
    }
}

#[cfg(not(windows))]
fn protect_key_material(bytes: &[u8]) -> Result<Vec<u8>, TlsInspectionError> {
    Ok(bytes.to_vec())
}

#[cfg(not(windows))]
fn unprotect_key_material(bytes: &[u8]) -> Result<Vec<u8>, TlsInspectionError> {
    Ok(bytes.to_vec())
}

#[cfg(windows)]
fn protect_key_material(bytes: &[u8]) -> Result<Vec<u8>, TlsInspectionError> {
    use std::{ptr::null, slice};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(|_| TlsInspectionError::InvalidRecord)?,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let succeeded = unsafe {
        CryptProtectData(
            &input,
            null(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if succeeded == 0 {
        return Err(TlsInspectionError::Windows(std::io::Error::last_os_error()));
    }
    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            unsafe {
                LocalFree(output.pbData.cast());
            }
        }
        return Err(TlsInspectionError::InvalidRecord);
    }
    let protected =
        unsafe { slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(protected)
}

#[cfg(windows)]
fn unprotect_key_material(bytes: &[u8]) -> Result<Vec<u8>, TlsInspectionError> {
    use std::{
        ptr::{null, null_mut},
        slice,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(|_| TlsInspectionError::InvalidRecord)?,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let succeeded = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if succeeded == 0 {
        return Err(TlsInspectionError::Windows(std::io::Error::last_os_error()));
    }
    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            unsafe {
                LocalFree(output.pbData.cast());
            }
        }
        return Err(TlsInspectionError::InvalidRecord);
    }
    let private_key =
        unsafe { slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(private_key)
}

/// Only Windows has a current-user installer; elsewhere nothing is ever added to a trust store.
#[cfg(not(windows))]
fn install_current_user_root(_certificate: &[u8]) -> Result<(), TlsInspectionError> {
    Err(TlsInspectionError::TrustStoreUnsupported)
}

#[cfg(windows)]
fn install_current_user_root(certificate: &[u8]) -> Result<(), TlsInspectionError> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Cryptography::{
        CertAddEncodedCertificateToStore, CertCloseStore, CertOpenSystemStoreW,
        CERT_STORE_ADD_REPLACE_EXISTING, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    let certificate_length =
        u32::try_from(certificate.len()).map_err(|_| TlsInspectionError::InvalidRecord)?;
    let store_name = "ROOT\0".encode_utf16().collect::<Vec<_>>();
    let store = unsafe { CertOpenSystemStoreW(0, store_name.as_ptr()) };
    if store.is_null() {
        return Err(TlsInspectionError::Windows(std::io::Error::last_os_error()));
    }
    let added = unsafe {
        CertAddEncodedCertificateToStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            certificate.as_ptr(),
            certificate_length,
            CERT_STORE_ADD_REPLACE_EXISTING,
            null_mut(),
        )
    };
    let add_error = (added == 0).then(std::io::Error::last_os_error);
    let closed = unsafe { CertCloseStore(store, 0) };
    if let Some(error) = add_error {
        return Err(TlsInspectionError::Windows(error));
    }
    if closed == 0 {
        return Err(TlsInspectionError::Windows(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum TlsInspectionError {
    #[error("HTTPS certifikát HomeProxy nelze přečíst nebo uložit: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTPS certifikát HomeProxy má neplatný záznam.")]
    InvalidRecord,
    #[error("HTTPS certifikát HomeProxy má neplatné kódování: {0}")]
    Decode(#[from] hex::FromHexError),
    #[error("HTTPS certifikát HomeProxy nelze vytvořit: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("HTTPS konfiguraci HomeProxy nelze vytvořit: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Kořenový HTTPS certifikát HomeProxy není platný: {0}")]
    InvalidCaCertificate(rustls::Error),
    #[error("V systému není dostupný žádný platný důvěryhodný kořenový certifikát.")]
    NoNativeRoots,
    #[error("HTTPS inspekce není v této službě dostupná.")]
    InspectionUnavailable,
    #[error("HTTPS certifikát HomeProxy ještě není připraven. Nejdřív jej výslovně připravte (homeproxy tls prepare).")]
    NotPrepared,
    #[error("Úložiště HTTPS certifikátu HomeProxy není bezpečné: {0}.")]
    UnsafeStorage(&'static str),
    #[error("Automatická instalace kořenového certifikátu není na této platformě podporována. Exportujte veřejný certifikát a důvěru nastavte ručně na klientech.")]
    TrustStoreUnsupported,
    #[error("HTTPS hostitel není platný.")]
    InvalidHost,
    #[error("Cache HTTPS certifikátů HomeProxy není dostupná.")]
    LeafCache,
    #[error("HTTPS certifikát cílového webu není důvěryhodný: {0}")]
    UpstreamHandshake(std::io::Error),
    #[error("Windows nemohl bezpečně připravit HTTPS certifikát HomeProxy: {0}")]
    Windows(std::io::Error),
    #[error("HTTPS certifikát HomeProxy nelze serializovat: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use std::fs;

    fn private_test_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        set_mode(directory.path(), 0o700);
        directory
    }
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[test]
    fn cached_leaf_is_reissued_before_it_expires_on_a_long_running_daemon() {
        let directory = private_test_directory();
        let inspection = TlsInspection::for_tests(
            directory.path().join("inspection-authority.json"),
            RootCertStore::empty(),
        )
        .unwrap();
        let cached = |inspection: &TlsInspection| {
            let inner = inspection.available().unwrap();
            let configs = inner.leaf_configs.lock().unwrap();
            let leaf = &configs["example.com"];
            (leaf.config.clone(), leaf.renew_after)
        };
        let start = OffsetDateTime::now_utc();
        inspection
            .server_config_for_host_at("example.com", start)
            .unwrap();
        let (first, renew_after) = cached(&inspection);
        assert_eq!(
            renew_after,
            start + Duration::days(LEAF_LIFETIME_DAYS - LEAF_RENEW_BEFORE_DAYS)
        );

        inspection
            .server_config_for_host_at("EXAMPLE.com", renew_after - Duration::seconds(1))
            .unwrap();
        assert!(Arc::ptr_eq(&first, &cached(&inspection).0));

        inspection
            .server_config_for_host_at("example.com", renew_after)
            .unwrap();
        let (second, next_renewal) = cached(&inspection);
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(
            next_renewal,
            renew_after + Duration::days(LEAF_LIFETIME_DAYS - LEAF_RENEW_BEFORE_DAYS)
        );
        // A clock stepped back before issuance reissues instead of serving a leaf
        // that clients would treat as not yet valid.
        inspection
            .server_config_for_host_at("example.com", renew_after - Duration::days(2))
            .unwrap();
        assert!(!Arc::ptr_eq(&second, &cached(&inspection).0));
        assert_eq!(
            inspection
                .available()
                .unwrap()
                .leaf_configs
                .lock()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn renewing_one_host_in_a_full_leaf_cache_keeps_the_other_hosts() {
        let directory = private_test_directory();
        let inspection = TlsInspection::for_tests(
            directory.path().join("inspection-authority.json"),
            RootCertStore::empty(),
        )
        .unwrap();
        let start = OffsetDateTime::now_utc();
        for index in 0..MAX_LEAF_CONFIGS {
            inspection
                .server_config_for_host_at(&format!("host-{index}.example"), start)
                .unwrap();
        }
        let renewal = start + Duration::days(LEAF_LIFETIME_DAYS - LEAF_RENEW_BEFORE_DAYS);
        inspection
            .server_config_for_host_at("host-0.example", renewal)
            .unwrap();
        let inner = inspection.available().unwrap();
        let configs = inner.leaf_configs.lock().unwrap();
        assert_eq!(configs.len(), MAX_LEAF_CONFIGS);
        assert_eq!(
            configs["host-0.example"].renew_after,
            renewal + Duration::days(LEAF_LIFETIME_DAYS - LEAF_RENEW_BEFORE_DAYS)
        );
    }

    #[tokio::test]
    async fn persisted_authority_reuses_a_trusted_root_and_issues_working_leafs() {
        let directory = private_test_directory();
        let record = directory.path().join("inspection-authority.json");
        let first = TlsInspection::for_tests(record.clone(), RootCertStore::empty()).unwrap();
        let first_root = first.root_certificate_der();
        drop(first);

        let second = TlsInspection::for_tests(record, RootCertStore::empty()).unwrap();
        assert_eq!(second.root_certificate_der(), first_root);

        let acceptor = second.acceptor_for_host("example.com").unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(first_root).unwrap();
        let client = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let (client_io, server_io) = duplex(16 * 1024);
        let server = tokio::spawn(async move {
            let mut stream = acceptor.accept(server_io).await.unwrap();
            let mut ping = [0u8; 4];
            stream.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut client_stream = client
            .connect(ServerName::try_from("example.com").unwrap(), client_io)
            .await
            .unwrap();
        client_stream.write_all(b"ping").await.unwrap();
        let mut pong = [0u8; 4];
        client_stream.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        server.await.unwrap();
    }

    #[test]
    fn corrupted_authority_record_fails_closed() {
        let directory = private_test_directory();
        let record = directory.path().join("inspection-authority.json");
        fs::write(&record, b"not-json").unwrap();
        #[cfg(unix)]
        set_mode(&record, 0o600);
        assert!(matches!(
            TlsInspection::for_tests(record.clone(), RootCertStore::empty()),
            Err(TlsInspectionError::Json(_))
        ));
        assert_eq!(fs::read(&record).unwrap(), b"not-json");
    }

    #[test]
    fn lazy_provider_creates_nothing_until_an_explicit_prepare() {
        let directory = private_test_directory();
        let record = directory.path().join("config").join(AUTHORITY_RECORD_FILE);
        let inspection = TlsInspection::lazy_for_tests(record.clone(), RootCertStore::empty());

        let state = inspection.authority_state();
        assert!(!state.prepared && !state.active && state.error.is_none());
        assert!(matches!(
            inspection.export_certificate(CertificateFormat::Pem),
            Err(TlsInspectionError::NotPrepared)
        ));
        assert!(matches!(
            inspection.activate(false),
            Err(TlsInspectionError::NotPrepared)
        ));
        assert!(matches!(
            inspection.try_root_certificate_der(),
            Err(TlsInspectionError::InspectionUnavailable)
        ));
        assert!(!record.exists());
        assert!(!record.parent().unwrap().exists());

        let certificate = inspection.prepare().unwrap();
        assert!(record.exists());
        let state = inspection.authority_state();
        assert!(state.prepared);
        // Preparing never activates inspection by itself.
        assert!(!state.active && !inspection.is_active());
        assert_eq!(
            state.sha256_fingerprint.as_deref(),
            Some(certificate_fingerprint(certificate.as_ref()).as_str())
        );

        // A restarted provider reuses the persisted authority instead of replacing it.
        let restarted = TlsInspection::lazy_for_tests(record, RootCertStore::empty());
        restarted.activate(false).unwrap();
        assert!(restarted.is_active());
        assert_eq!(restarted.root_certificate_der(), certificate);
    }

    #[test]
    fn export_contains_only_the_public_certificate_and_its_fingerprint() {
        let directory = private_test_directory();
        let record = directory.path().join(AUTHORITY_RECORD_FILE);
        let inspection = TlsInspection::lazy_for_tests(record.clone(), RootCertStore::empty());
        let certificate = inspection.prepare().unwrap();
        let saved: AuthorityRecord = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
        let expected_fingerprint = Sha256::digest(certificate.as_ref())
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(expected_fingerprint.len(), 32 * 3 - 1);

        let der = inspection
            .export_certificate(CertificateFormat::Der)
            .unwrap();
        assert_eq!(der.format, CertificateFormat::Der);
        assert_eq!(der.encoding, "hex");
        assert_eq!(hex::decode(&der.certificate).unwrap(), certificate.as_ref());
        assert_eq!(der.sha256_fingerprint, expected_fingerprint);

        let pem = inspection
            .export_certificate(CertificateFormat::Pem)
            .unwrap();
        assert_eq!(pem.encoding, "pem");
        assert_eq!(pem.sha256_fingerprint, expected_fingerprint);
        assert!(pem.certificate.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.certificate.ends_with("\n-----END CERTIFICATE-----\n"));
        let body = pem
            .certificate
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<_>>();
        assert!(body.iter().all(|line| line.len() <= 64));
        assert_eq!(decode_base64(&body.concat()), certificate.as_ref());

        for exported in [&der, &pem] {
            let json = serde_json::to_string(exported).unwrap();
            assert!(!json.contains(&saved.protected_private_key_hex));
            assert!(!json.contains("PRIVATE"));
        }
    }

    #[test]
    fn pem_encoding_matches_base64_padding_vectors() {
        for (input, expected) in [(&b"Man"[..], "TWFu"), (b"Ma", "TWE="), (b"M", "TQ==")] {
            let pem = pem_certificate(input);
            assert_eq!(pem.lines().nth(1), Some(expected));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_preparation_publishes_one_private_authority_without_clobbering() {
        let directory = private_test_directory();
        let record = directory.path().join("private").join(AUTHORITY_RECORD_FILE);
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let record = record.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    TlsInspection::lazy_for_tests(record, RootCertStore::empty())
                        .prepare()
                        .unwrap()
                })
            })
            .collect();
        let certificates: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(certificates
            .iter()
            .all(|certificate| certificate == &certificates[0]));
        assert_eq!(fs::read_dir(record.parent().unwrap()).unwrap().count(), 1);
        reload(&record).unwrap();
    }

    #[test]
    fn upstream_roots_never_include_the_inspection_authority() {
        let directory = private_test_directory();
        let record = directory.path().join(AUTHORITY_RECORD_FILE);
        let first = TlsInspection::for_tests(record.clone(), RootCertStore::empty()).unwrap();
        let own_root = first.root_certificate_der();
        let mut supplied = RootCertStore::empty();
        supplied.add(own_root.clone()).unwrap();
        let public_key = supplied.roots[0].subject_public_key_info.as_ref().to_vec();

        assert!(exclude_authority(supplied.clone(), &public_key).is_empty());
        // Supplying the authority as a custom root still yields a working, reused inspector.
        let reloaded = TlsInspection::for_tests(record, supplied).unwrap();
        assert_eq!(reloaded.root_certificate_der(), own_root);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_trust_installation_is_an_explicit_failure() {
        let directory = private_test_directory();
        let inspection = TlsInspection::for_tests(
            directory.path().join(AUTHORITY_RECORD_FILE),
            RootCertStore::empty(),
        )
        .unwrap();
        assert!(matches!(
            inspection.install_current_user_root(),
            Err(TlsInspectionError::TrustStoreUnsupported)
        ));
    }

    #[cfg(unix)]
    fn set_mode(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn prepared_record() -> (tempfile::TempDir, PathBuf, CertificateDer<'static>) {
        let directory = private_test_directory();
        let record = directory.path().join("state").join(AUTHORITY_RECORD_FILE);
        let certificate = TlsInspection::lazy_for_tests(record.clone(), RootCertStore::empty())
            .prepare()
            .unwrap();
        (directory, record, certificate)
    }

    #[cfg(unix)]
    fn reload(record: &std::path::Path) -> Result<(), TlsInspectionError> {
        let inspection =
            TlsInspection::lazy_for_tests(record.to_path_buf(), RootCertStore::empty());
        inspection.export_certificate(CertificateFormat::Der)?;
        inspection.activate(false)
    }

    #[cfg(unix)]
    #[test]
    fn unix_record_is_private_and_survives_restart() {
        use std::os::unix::fs::MetadataExt;
        let (_directory, record, certificate) = prepared_record();
        assert_eq!(mode_of(record.parent().unwrap()), 0o700);
        assert_eq!(mode_of(&record), 0o600);
        assert_eq!(fs::metadata(&record).unwrap().nlink(), 1);
        // Only the record itself is left behind; the temporary file was renamed.
        assert_eq!(fs::read_dir(record.parent().unwrap()).unwrap().count(), 1);
        reload(&record).unwrap();
        let restarted = TlsInspection::lazy_for_tests(record, RootCertStore::empty());
        assert_eq!(restarted.prepare().unwrap(), certificate);
    }

    #[cfg(unix)]
    #[test]
    fn unix_record_with_group_or_world_access_is_rejected() {
        for mode in [0o644, 0o640, 0o604, 0o400] {
            let (_directory, record, _) = prepared_record();
            set_mode(&record, mode);
            assert!(
                matches!(reload(&record), Err(TlsInspectionError::UnsafeStorage(_))),
                "{mode:o}"
            );
            // A rejected record is never replaced by a new authority.
            assert!(matches!(
                TlsInspection::lazy_for_tests(record.clone(), RootCertStore::empty()).prepare(),
                Err(TlsInspectionError::UnsafeStorage(_))
            ));
            assert_eq!(mode_of(&record), mode);
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_shared_directory_is_rejected_before_creating_a_record() {
        let directory = private_test_directory();
        let shared = directory.path().join("shared");
        fs::create_dir(&shared).unwrap();
        set_mode(&shared, 0o755);
        let record = shared.join(AUTHORITY_RECORD_FILE);
        assert!(matches!(
            TlsInspection::lazy_for_tests(record.clone(), RootCertStore::empty()).prepare(),
            Err(TlsInspectionError::UnsafeStorage(_))
        ));
        assert!(!record.exists());
        assert_eq!(fs::read_dir(&shared).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn unix_symlinked_record_or_directory_is_rejected() {
        let (directory, record, _) = prepared_record();
        let moved = directory.path().join("moved.json");
        fs::rename(&record, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &record).unwrap();
        assert!(matches!(
            reload(&record),
            Err(TlsInspectionError::UnsafeStorage(_))
        ));
        assert!(matches!(
            TlsInspection::lazy_for_tests(record.clone(), RootCertStore::empty()).prepare(),
            Err(TlsInspectionError::UnsafeStorage(_))
        ));
        assert!(fs::symlink_metadata(&record)
            .unwrap()
            .file_type()
            .is_symlink());

        let linked_directory = directory.path().join("linked-state");
        std::os::unix::fs::symlink(record.parent().unwrap(), &linked_directory).unwrap();
        fs::remove_file(&record).unwrap();
        fs::rename(&moved, &record).unwrap();
        assert!(matches!(
            reload(&linked_directory.join(AUTHORITY_RECORD_FILE)),
            Err(TlsInspectionError::UnsafeStorage(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_hardlinked_record_is_rejected() {
        let (directory, record, _) = prepared_record();
        let alias = directory.path().join("alias.json");
        fs::hard_link(&record, &alias).unwrap();
        assert!(matches!(
            reload(&record),
            Err(TlsInspectionError::UnsafeStorage(_))
        ));
        fs::remove_file(&alias).unwrap();
        reload(&record).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_non_regular_record_is_rejected_without_blocking() {
        let directory = private_test_directory();
        let record = directory.path().join(AUTHORITY_RECORD_FILE);
        fs::create_dir(&record).unwrap();
        set_mode(&record, 0o600);
        assert!(reload(&record).is_err());
        assert!(
            TlsInspection::lazy_for_tests(record, RootCertStore::empty())
                .prepare()
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_fifo_record_is_rejected_without_reading_or_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt;
        let directory = private_test_directory();
        let record = directory.path().join(AUTHORITY_RECORD_FILE);
        let path = std::ffi::CString::new(record.as_os_str().as_bytes()).unwrap();
        // SAFETY: NUL-terminated path points into this isolated owned temporary directory.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            reload(&record),
            Err(TlsInspectionError::UnsafeStorage(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn oversized_authority_record_is_rejected_before_parsing_or_replacement() {
        let directory = private_test_directory();
        let record = directory.path().join(AUTHORITY_RECORD_FILE);
        fs::write(&record, vec![b'x'; MAX_AUTHORITY_RECORD_BYTES as usize + 1]).unwrap();
        set_mode(&record, 0o600);
        assert!(matches!(
            reload(&record),
            Err(TlsInspectionError::InvalidRecord)
        ));
        assert_eq!(
            fs::metadata(&record).unwrap().len(),
            MAX_AUTHORITY_RECORD_BYTES + 1
        );
    }

    fn decode_base64(text: &str) -> Vec<u8> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = 0u32;
        let mut count = 0;
        let mut output = Vec::new();
        for byte in text.bytes().filter(|byte| *byte != b'=') {
            let value = ALPHABET.iter().position(|symbol| *symbol == byte).unwrap() as u32;
            bits = (bits << 6) | value;
            count += 6;
            if count >= 8 {
                count -= 8;
                output.push((bits >> count) as u8);
                bits &= (1 << count) - 1;
            }
        }
        output
    }

    #[test]
    fn authority_record_rejects_a_certificate_and_key_mismatch() {
        let directory = private_test_directory();
        let first_record = directory.path().join("first.json");
        let second_record = directory.path().join("second.json");
        TlsInspection::for_tests(first_record.clone(), RootCertStore::empty()).unwrap();
        TlsInspection::for_tests(second_record.clone(), RootCertStore::empty()).unwrap();

        let mut first: AuthorityRecord =
            serde_json::from_slice(&fs::read(&first_record).unwrap()).unwrap();
        let second: AuthorityRecord =
            serde_json::from_slice(&fs::read(&second_record).unwrap()).unwrap();
        first.protected_private_key_hex = second.protected_private_key_hex;
        fs::write(&first_record, serde_json::to_vec(&first).unwrap()).unwrap();

        assert!(matches!(
            TlsInspection::for_tests(first_record, RootCertStore::empty()),
            Err(TlsInspectionError::InvalidRecord)
        ));
    }

    #[test]
    fn inspection_authority_is_never_an_upstream_trust_anchor() {
        let directory = private_test_directory();
        let inspection = TlsInspection::for_tests(
            directory.path().join("inspection.json"),
            RootCertStore::empty(),
        )
        .unwrap();
        let root = inspection.root_certificate_der();
        let public_key = {
            let mut parsed = RootCertStore::empty();
            parsed.add(root.clone()).unwrap();
            parsed.roots[0].subject_public_key_info.as_ref().to_vec()
        };
        let mut upstream = RootCertStore::empty();

        assert!(!add_upstream_root(&mut upstream, root, &public_key));
        assert!(upstream.is_empty());
    }
}
