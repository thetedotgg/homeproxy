//! Versioned local control protocol. No desktop or proxy-engine dependency.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fmt, io,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u16 = 1;
pub const MAX_FRAME: usize = 256 * 1024;
pub const MAX_RESPONSE_FRAME: usize = 32 * 1024 * 1024;
pub const SYSTEM_SOCKET: &str = "/run/homeproxy/control.sock";
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Status,
    /// Explicit privileged UI request; ordinary status never includes credentials.
    DesktopSnapshot,
    /// Private, allowlisted diagnostic report, independent of normal engine mutations.
    ExportDiagnostics,
    /// Local listener supervision status; this is not a WAN connectivity test.
    DiagnosticsStatus,
    Start,
    Stop,
    ApplySettings {
        settings: Value,
        expected_revision: String,
    },
    ConfigureLan {
        settings: Value,
        listen_ip: String,
        cache_enabled: bool,
        expected_revision: String,
    },
    ConfigPatch {
        patch: Value,
    },
    ConfigCheck,
    Credentials,
    RotatePassword,
    SetDeviceAllowed {
        ip: String,
        allowed: bool,
    },
    ClearCache,
    OfflinePreparationStatus,
    PrepareOffline {
        request: Value,
    },
    CancelOfflinePreparation {
        id: String,
    },
    ReleaseOfflinePin {
        key: String,
    },
    ClearActivity,
    /// Reset the displayed transfer pair and return the canonical stats snapshot.
    ResetTransferStats,
    /// Authority capability, preparation, Inspect and trust-declaration state.
    TlsStatus,
    /// Explicitly creates the private authority; never enables Inspect or declares trust.
    PrepareCa,
    /// Public certificate and SHA-256 fingerprint only; the private key never leaves the daemon.
    ExportCa {
        format: CertificateFormat,
    },
    UsageHistory,
    FilterFeeds,
    ImportFilterFeed {
        feed: Value,
        expected_revision: String,
    },
    RemoveFilterFeed {
        id: String,
        expected_revision: String,
    },
    ExportUsageHistory {
        format: HistoryFormat,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateFormat {
    Pem,
    Der,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HistoryFormat {
    Json,
    Csv,
}

#[derive(Serialize)]
pub struct Request {
    pub version: u16,
    pub command: Command,
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRequest {
            version: u16,
            command: Value,
        }
        let wire = WireRequest::deserialize(deserializer)?;
        let command: Command =
            serde_json::from_value(wire.command.clone()).map_err(serde::de::Error::custom)?;
        // Serde internally tagged unit variants accept extra fields even with
        // deny_unknown_fields. Enforce the exact command shape at the wire boundary.
        let canonical = serde_json::to_value(&command).map_err(serde::de::Error::custom)?;
        if canonical != wire.command {
            return Err(serde::de::Error::custom("Unexpected command fields"));
        }
        Ok(Self {
            version: wire.version,
            command,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u16,
    pub result: Result<Value, ControlError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlError {
    pub code: String,
    pub message: String,
}

impl ControlError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}
impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for ControlError {}

pub fn default_socket() -> PathBuf {
    std::env::var_os("HOMEPROXY_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| SYSTEM_SOCKET.into())
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    read_frame_limited(reader, MAX_FRAME).await
}

async fn read_frame_limited<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let size = reader.read_u32().await? as usize;
    if size == 0 || size > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid control frame length",
        ));
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &impl Serialize,
) -> io::Result<()> {
    write_frame_limited(writer, value, MAX_FRAME).await
}

pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &Response,
) -> io::Result<()> {
    write_frame_limited(writer, value, MAX_RESPONSE_FRAME).await
}

async fn write_frame_limited<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &impl Serialize,
    limit: usize,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Control frame exceeds size limit",
        ));
    }
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await
}

#[cfg(target_os = "linux")]
pub async fn call(socket: &Path, command: Command) -> Result<Value, ControlError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use tokio::net::UnixStream;
    let operation = async {
        let metadata = std::fs::symlink_metadata(socket).map_err(connection_error)?;
        if !metadata.file_type().is_socket() {
            return Err(ControlError::new(
                "unsafe_socket",
                "Control endpoint is not a Unix socket",
            ));
        }
        // SAFETY: geteuid has no arguments and cannot fail.
        let uid = unsafe { libc::geteuid() };
        if socket != Path::new(SYSTEM_SOCKET) && metadata.uid() != uid {
            return Err(ControlError::new(
                "unsafe_socket",
                "Custom socket must belong to the current user",
            ));
        }
        let parent = socket
            .parent()
            .ok_or_else(|| ControlError::new("unsafe_socket", "Missing socket directory"))?;
        let directory = std::fs::symlink_metadata(parent).map_err(connection_error)?;
        if !directory.is_dir()
            || directory.file_type().is_symlink()
            || directory.uid() != metadata.uid()
            || directory.mode() & 0o022 != 0
        {
            return Err(ControlError::new(
                "unsafe_socket",
                "Control directory has an unsafe owner or permissions",
            ));
        }
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(connection_error)?;
        let peer = stream.peer_cred().map_err(connection_error)?;
        if peer.uid() != metadata.uid() {
            return Err(ControlError::new(
                "unsafe_socket",
                "Daemon identity does not match socket owner",
            ));
        }
        write_frame(
            &mut stream,
            &Request {
                version: VERSION,
                command,
            },
        )
        .await
        .map_err(connection_error)?;
        let bytes = read_frame_limited(&mut stream, MAX_RESPONSE_FRAME)
            .await
            .map_err(connection_error)?;
        let response: Response = serde_json::from_slice(&bytes).map_err(|_| {
            ControlError::new("invalid_response", "Daemon returned an invalid response")
        })?;
        if response.version != VERSION {
            return Err(ControlError::new(
                "version_mismatch",
                "CLI and daemon protocol versions differ",
            ));
        }
        response.result
    };
    tokio::time::timeout(CALL_TIMEOUT, operation)
        .await
        .map_err(|_| {
            ControlError::new(
                "timeout",
                "Daemon request timed out; check status before retrying a change",
            )
        })?
}

#[cfg(not(target_os = "linux"))]
pub async fn call(_socket: &Path, _command: Command) -> Result<Value, ControlError> {
    Err(ControlError::new(
        "unsupported_platform",
        "The service client currently supports Linux",
    ))
}

#[cfg(target_os = "linux")]
fn connection_error(error: io::Error) -> ControlError {
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => ControlError::new("unavailable", "HomeProxy service is not running at this socket. Check --socket or systemctl status homeproxy."),
        io::ErrorKind::PermissionDenied => ControlError::new("permission_denied", "No access to HomeProxy service. Ask an administrator for homeproxy-admin group membership and sign in again."),
        _ => ControlError::new("transport", error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transfer_reset_has_an_exact_wire_shape() {
        let request = serde_json::to_value(Request {
            version: VERSION,
            command: Command::ResetTransferStats,
        })
        .unwrap();
        assert_eq!(
            request,
            serde_json::json!({"version": VERSION, "command": {"method":"reset_transfer_stats"}})
        );
        assert!(serde_json::from_value::<Request>(request).is_ok());
        for invalid in [
            serde_json::json!({"version": VERSION, "command": {"method":"reset_transfer_stats", "scope":"all"}}),
            serde_json::json!({"version": VERSION, "command": {"method":"reset_transfer_stats", "expected_revision":"a:1"}}),
        ] {
            assert!(serde_json::from_value::<Request>(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn history_exports_use_response_bound_without_widening_request_bound() {
        let response = Response {
            version: VERSION,
            result: Ok(serde_json::json!({"content":"x".repeat(MAX_FRAME + 1)})),
        };
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let (written, bytes) = tokio::join!(
            write_response(&mut writer, &response),
            read_frame_limited(&mut reader, MAX_RESPONSE_FRAME)
        );
        written.unwrap();
        let bytes = bytes.unwrap();
        assert!(bytes.len() > MAX_FRAME);
        let parsed: Response = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.result.is_ok());
        let oversized = ((MAX_RESPONSE_FRAME + 1) as u32).to_be_bytes();
        assert_eq!(
            read_frame_limited(&mut &oversized[..], MAX_RESPONSE_FRAME)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[tokio::test]
    async fn rejects_oversized_frame_before_reading_payload() {
        let bytes = ((MAX_FRAME + 1) as u32).to_be_bytes();
        assert_eq!(
            read_frame(&mut &bytes[..]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[tokio::test]
    async fn rejects_truncated_frame() {
        assert!(read_frame(&mut &[0, 0, 0, 4, 1][..]).await.is_err());
    }
    #[test]
    fn rejects_unknown_commands_and_fields() {
        assert!(serde_json::from_str::<Request>(
            r#"{"version":1,"command":{"method":"start","shell":"bad"}}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<Request>(r#"{"version":1,"command":{"method":"execute"}}"#)
                .is_err()
        );
    }
    #[test]
    fn tls_commands_have_an_exact_wire_shape() {
        for method in ["tls_status", "prepare_ca"] {
            let request = format!(r#"{{"version":1,"command":{{"method":"{method}"}}}}"#);
            assert!(serde_json::from_str::<Request>(&request).is_ok());
            let extra =
                format!(r#"{{"version":1,"command":{{"method":"{method}","path":"/tmp/ca"}}}}"#);
            assert!(serde_json::from_str::<Request>(&extra).is_err());
        }
        for format in ["pem", "der"] {
            let request = format!(
                r#"{{"version":1,"command":{{"method":"export_ca","format":"{format}"}}}}"#
            );
            assert!(serde_json::from_str::<Request>(&request).is_ok());
        }
        for invalid in [
            r#"{"version":1,"command":{"method":"export_ca"}}"#,
            r#"{"version":1,"command":{"method":"export_ca","format":"key"}}"#,
            r#"{"version":1,"command":{"method":"export_ca","format":"PEM"}}"#,
            r#"{"version":1,"command":{"method":"export_ca","format":"pem","includeKey":true}}"#,
        ] {
            assert!(
                serde_json::from_str::<Request>(invalid).is_err(),
                "{invalid}"
            );
        }
    }
}
