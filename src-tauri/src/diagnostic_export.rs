//! Native diagnostic artifacts. No user-controlled destination, logs, or raw errors.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Value};
use tauri::Manager;

const MAX_REPORT_BYTES: usize = 24 * 1024 * 1024;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn export_error(code: &str) -> String {
    format!("HOMEPROXY_DIAGNOSTICS:{code}")
}

fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn report(source: Result<Value, String>, now: u64) -> (Value, bool) {
    // The engine owns the allowlist. A failed/invalid response must never include
    // its error text, because that may contain credentials, URLs, or filesystem paths.
    let (mut value, partial) = match source {
        Ok(Value::Object(object))
            if object.get("schemaVersion").and_then(Value::as_u64) == Some(1)
                && object.get("current").is_some_and(Value::is_object) =>
        {
            (Value::Object(object), false)
        }
        _ => (json!({"errorCode": "diagnostics_unavailable"}), true),
    };
    value["guiVersion"] = json!(env!("CARGO_PKG_VERSION"));
    value["exportedAtUnixMs"] = json!(now);
    value["platform"] = json!(std::env::consts::OS);
    value["partial"] = json!(partial);
    (value, partial)
}

struct BoundedBuffer(Vec<u8>);
impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_REPORT_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("report_too_large"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encoded_report(value: &Value) -> Result<Vec<u8>, String> {
    let mut output = BoundedBuffer(Vec::new());
    serde_json::to_writer_pretty(&mut output, value)
        .map_err(|_| export_error("report_too_large"))?;
    output
        .write_all(b"\n")
        .map_err(|_| export_error("report_too_large"))?;
    Ok(output.0)
}

fn save_at(downloads: &Path, source: Result<Value, String>, now: u64) -> Result<Value, String> {
    let destination = PinnedDownloads::open(downloads)?;
    let (value, partial) = report(source, now);
    let bytes = encoded_report(&value)?;
    save_bytes(
        &destination,
        &bytes,
        partial,
        now,
        SEQUENCE.fetch_add(1, Ordering::Relaxed),
    )
}

struct PinnedDownloads {
    display: PathBuf,
    handle: File,
    #[cfg(windows)]
    _ancestors: Vec<File>,
}

impl PinnedDownloads {
    fn open(downloads: &Path) -> Result<Self, String> {
        // Fresh desktops may not have opened Downloads yet. Create only this native
        // configured directory, without following a substituted final symlink.
        if !downloads.exists() {
            let directory = fs::DirBuilder::new();
            #[cfg(unix)]
            let directory = {
                use std::os::unix::fs::DirBuilderExt;
                let mut directory = directory;
                directory.mode(0o700);
                directory
            };
            directory
                .create(downloads)
                .map_err(|_| export_error("downloads_unavailable"))?;
        }
        let metadata =
            fs::symlink_metadata(downloads).map_err(|_| export_error("downloads_unavailable"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(export_error("downloads_unavailable"));
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let handle = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(downloads)
                .map_err(|_| export_error("downloads_unavailable"))?;
            let pinned = Self {
                display: downloads.into(),
                handle,
            };
            if !pinned.unchanged() {
                return Err(export_error("downloads_unavailable"));
            }
            Ok(pinned)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            if !downloads.is_absolute() {
                return Err(export_error("downloads_unavailable"));
            }
            // Rust's default shares DELETE. Remove it and pin every path component,
            // preventing rename/delete substitution during path-based file creation.
            let mut handles = Vec::new();
            for ancestor in downloads
                .ancestors()
                .filter(|p| !p.as_os_str().is_empty())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                let handle = OpenOptions::new()
                    .access_mode(0)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(ancestor)
                    .map_err(|_| export_error("downloads_unavailable"))?;
                let metadata = handle
                    .metadata()
                    .map_err(|_| export_error("downloads_unavailable"))?;
                if !metadata.is_dir()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(export_error("downloads_unavailable"));
                }
                handles.push(handle);
            }
            let handle = handles
                .pop()
                .ok_or_else(|| export_error("downloads_unavailable"))?;
            Ok(Self {
                display: downloads.into(),
                handle,
                _ancestors: handles,
            })
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        Err(export_error("downloads_unavailable"))
    }

    fn write_path(&self, name: &str) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", self.handle.as_raw_fd())).join(name)
        }
        #[cfg(not(target_os = "linux"))]
        self.display.join(name)
    }

    fn unchanged(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let Ok(current) = fs::symlink_metadata(&self.display) else {
                return false;
            };
            let Ok(pinned) = self.handle.metadata() else {
                return false;
            };
            current.is_dir()
                && !current.file_type().is_symlink()
                && current.dev() == pinned.dev()
                && current.ino() == pinned.ino()
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.handle
                .metadata()
                .is_ok_and(|metadata| metadata.is_dir())
        }
    }
}

fn save_bytes(
    downloads: &PinnedDownloads,
    bytes: &[u8],
    partial: bool,
    now: u64,
    sequence: u64,
) -> Result<Value, String> {
    for attempt in 0..128u32 {
        let name = format!(
            "HomeProxy-diagnostika-{now}-{}-{sequence}-{attempt}.json",
            std::process::id()
        );
        let path = downloads.write_path(&name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(export_error("write_failed")),
        };
        if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
            // Best effort: never advertise an incomplete write as a saved report.
            let _ = fs::remove_file(&path);
            return Err(export_error("write_failed"));
        }
        if !downloads.unchanged() {
            let _ = fs::remove_file(&path);
            return Err(export_error("downloads_unavailable"));
        }
        return Ok(
            json!({"path": downloads.display.join(&name).to_string_lossy(), "fileName": name, "partial": partial}),
        );
    }
    Err(export_error("write_failed"))
}

pub async fn save(app: tauri::AppHandle, source: Result<Value, String>) -> Result<Value, String> {
    let downloads = app
        .path()
        .download_dir()
        .map_err(|_| export_error("downloads_unavailable"))?;
    tauri::async_runtime::spawn_blocking(move || save_at(&downloads, source, timestamp_ms()))
        .await
        .map_err(|_| export_error("write_failed"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "homeproxy-diagnostic-export-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn repeated_exports_save_distinct_actual_json_files_with_private_permissions() {
        let root = Temp::new();
        let first = save_at(
            &root.0,
            Ok(json!({"schemaVersion":1,"current":{},"recoveryCount": 3})),
            123,
        )
        .unwrap();
        let second = save_at(
            &root.0,
            Ok(json!({"schemaVersion":1,"current":{},"recoveryCount": 4})),
            123,
        )
        .unwrap();
        assert_ne!(first["path"], second["path"]);
        for result in [first, second] {
            let path = Path::new(result["path"].as_str().unwrap());
            assert_eq!(path.parent(), Some(root.0.as_path()));
            let saved: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(saved["guiVersion"], env!("CARGO_PKG_VERSION"));
            assert_eq!(saved["partial"], false);
            assert_eq!(result["partial"], false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn failed_source_is_a_clearly_partial_allowlisted_report_without_error_details() {
        let root = Temp::new();
        let result = save_at(&root.0, Err("HOMEPROXY_SERVICE:timeout:https://user:secret@private.example/path?token=abc PRIVATE KEY /home/client".into()), 456).unwrap();
        assert_eq!(result["partial"], true);
        let bytes = fs::read(result["path"].as_str().unwrap()).unwrap();
        let saved: Value = serde_json::from_slice(&bytes).unwrap();
        let object = saved.as_object().unwrap();
        assert_eq!(object.len(), 5);
        assert_eq!(saved["errorCode"], "diagnostics_unavailable");
        assert_eq!(saved["partial"], true);
        assert_eq!(saved["exportedAtUnixMs"], 456);
        assert!(!String::from_utf8(bytes).unwrap().contains("secret"));
        assert!(report(Ok(Value::Null), 456).1);
        assert!(report(Ok(json!({"settings":{"proxyPassword":"secret"}})), 456).1);
    }

    #[test]
    fn oversized_report_and_missing_destination_never_claim_success() {
        let root = Temp::new();
        assert!(save_at(
            &root.0,
            Ok(json!({"schemaVersion":1,"current":{},"oversize": "x".repeat(MAX_REPORT_BYTES)})),
            0
        )
        .unwrap_err()
        .ends_with("report_too_large"));
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
        let error = save_at(
            &root.0.join("missing-parent").join("Downloads"),
            Ok(json!({})),
            0,
        )
        .unwrap_err();
        assert_eq!(error, "HOMEPROXY_DIAGNOSTICS:downloads_unavailable");
    }

    #[test]
    fn first_export_creates_the_configured_downloads_directory() {
        let root = Temp::new();
        let downloads = root.0.join("Downloads");
        let result = save_at(&downloads, Ok(json!({"schemaVersion":1,"current":{}})), 0).unwrap();
        assert!(Path::new(result["path"].as_str().unwrap()).is_file());
        assert_eq!(result["partial"], false);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_downloads_is_rejected_and_create_new_cannot_clobber_a_file_or_symlink() {
        use std::os::unix::fs::symlink;
        let root = Temp::new();
        let downloads_link = root.0.join("downloads-link");
        symlink(&root.0, &downloads_link).unwrap();
        assert!(save_at(&downloads_link, Ok(json!({})), 0).is_err());
        let target = root.0.join("keep.json");
        fs::write(&target, b"keep").unwrap();
        let first_name = format!("HomeProxy-diagnostika-0-{}-42-0.json", std::process::id());
        let second_name = format!("HomeProxy-diagnostika-0-{}-42-1.json", std::process::id());
        symlink(&target, root.0.join(first_name)).unwrap();
        let existing = root.0.join(second_name);
        fs::write(&existing, b"existing").unwrap();
        let pinned = PinnedDownloads::open(&root.0).unwrap();
        let result = save_bytes(&pinned, b"{}\n", false, 0, 42).unwrap();
        assert!(result["fileName"].as_str().unwrap().ends_with("-42-2.json"));
        assert_eq!(fs::read(result["path"].as_str().unwrap()).unwrap(), b"{}\n");
        assert_eq!(fs::read(existing).unwrap(), b"existing");
        assert_eq!(fs::read(target).unwrap(), b"keep");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn directory_substitution_after_validation_cannot_redirect_the_export() {
        use std::os::unix::fs::symlink;
        let root = Temp::new();
        let downloads = root.0.join("Downloads");
        let replacement = root.0.join("elsewhere");
        let original = root.0.join("original");
        fs::create_dir(&downloads).unwrap();
        fs::create_dir(&replacement).unwrap();
        let pinned = PinnedDownloads::open(&downloads).unwrap();
        fs::rename(&downloads, &original).unwrap();
        symlink(&replacement, &downloads).unwrap();
        let error = save_bytes(&pinned, b"private report\n", false, 0, 17).unwrap_err();
        assert_eq!(error, "HOMEPROXY_DIAGNOSTICS:downloads_unavailable");
        assert_eq!(fs::read_dir(&replacement).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
    }
}
