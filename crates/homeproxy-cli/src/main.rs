use clap::{ArgGroup, Args, Parser, Subcommand};
use homeproxy_control::{
    call, default_socket, CertificateFormat, Command, ControlError, HistoryFormat, MAX_FRAME,
};
use serde_json::{json, Map, Value};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::Ipv4Addr,
    path::PathBuf,
    process::ExitCode,
};

/// Manage the local HomeProxy service.
#[derive(Parser)]
#[command(name = "homeproxy", version, about, arg_required_else_help = true, color = clap::ColorChoice::Never)]
struct Cli {
    /// Unix socket of the service (also HOMEPROXY_SOCKET).
    #[arg(long, global = true, env = "HOMEPROXY_SOCKET")]
    socket: Option<PathBuf>,
    /// Machine-readable JSON result or error.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Local supervision and private, allowlisted incident report.
    Diagnostics {
        #[command(subcommand)]
        action: DiagnosticsAction,
    },
    Filter {
        #[command(subcommand)]
        action: FilterAction,
    },
    History {
        #[command(subcommand)]
        action: HistoryAction,
    },
    Tls {
        #[command(subcommand)]
        action: TlsAction,
    },
    Status,
    Start,
    Stop,
    Doctor,
    Devices {
        #[command(subcommand)]
        action: DevicesAction,
    },
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    Credentials {
        #[command(subcommand)]
        action: CredentialsAction,
    },
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    Activity {
        #[command(subcommand)]
        action: ActivityAction,
    },
}

#[derive(Subcommand)]
enum DiagnosticsAction {
    Status,
    /// Print the current diagnostic report and retained incidents as JSON.
    Export,
}

#[derive(Subcommand)]
enum TlsAction {
    Status,
    /// Explicitly prepare the private authority without enabling Inspect or installing trust.
    Prepare,
    /// Export only the public certificate. Existing output files are never overwritten.
    Export {
        #[arg(long, value_parser = ["pem", "der"], default_value = "pem")]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum HistoryAction {
    Status,
    Export {
        #[arg(long, value_parser = ["json", "csv"], default_value = "json")]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum FilterAction {
    List,
    /// Import a trusted hosts/domain-only file; replaces an existing feed with the same name.
    Import {
        #[arg(long)]
        name: String,
        #[arg(long)]
        file: PathBuf,
    },
    Remove {
        id: String,
    },
}

#[derive(Subcommand)]
enum DevicesAction {
    List,
    Allow { ip: Ipv4Addr },
    Deny { ip: Ipv4Addr },
}

#[derive(Subcommand)]
enum ConfigAction {
    Show,
    Check,
    Set { key: String, json_value: String },
    Apply(ApplyArgs),
}

#[derive(Args)]
#[command(group(ArgGroup::new("input").required(true).args(["file", "stdin"])))]
struct ApplyArgs {
    /// JSON patch file; '-' reads standard input.
    #[arg(long)]
    file: Option<PathBuf>,
    /// Read a JSON patch from standard input.
    #[arg(long)]
    stdin: bool,
}

#[derive(Subcommand)]
enum CredentialsAction {
    Show,
    Rotate,
}
#[derive(Subcommand)]
enum CacheAction {
    /// Disk usage, applied limits and measurement/maintenance state.
    Status,
    Clear,
    /// Preparation jobs, disk pin quota and current offline availability.
    Prepared,
    /// Read {urls,budgetMib,pin} from a private JSON file ('-' reads stdin).
    Prepare {
        #[arg(long)]
        file: PathBuf,
    },
    Cancel {
        id: String,
    },
    Unpin {
        key: String,
    },
}
#[derive(Subcommand)]
enum ActivityAction {
    Clear,
}

#[derive(Debug)]
struct CliError {
    code: String,
    message: String,
    exit: u8,
}

impl CliError {
    fn input(message: impl Into<String>) -> Self {
        Self {
            code: "invalid_input".into(),
            message: message.into(),
            exit: 2,
        }
    }
    fn degraded(message: impl Into<String>) -> Self {
        Self {
            code: "degraded".into(),
            message: message.into(),
            exit: 6,
        }
    }
}

impl From<ControlError> for CliError {
    fn from(error: ControlError) -> Self {
        let exit = match error.code.as_str() {
            "unavailable" => 3,
            "permission_denied" => 4,
            "invalid_input"
            | "invalid_config"
            | "invalid_ip"
            | "inspection_unsupported"
            | "operation_failed"
            | "listener_in_use"
            | "listener_access_denied"
            | "listener_address_unavailable"
            | "listener_start_failed"
            | "stop_persistence"
            | "conflict" => 5,
            _ => 7,
        };
        Self {
            code: error.code,
            message: error.message,
            exit,
        }
    }
}

fn parse_patch(key: &str, json_value: &str) -> Result<Value, CliError> {
    if key
        .replace(['_', '-'], "")
        .eq_ignore_ascii_case("proxyPassword")
    {
        return Err(CliError::input("Set proxyPassword through `config apply --file PATH` or `config apply --stdin`, never through command arguments"));
    }
    if key.is_empty() || key.contains('.') {
        return Err(CliError::input(
            "KEY must be one top-level camelCase settings field",
        ));
    }
    let value = serde_json::from_str(json_value)
        .map_err(|error| CliError::input(format!("JSON_VALUE is invalid JSON: {error}")))?;
    if contains_password(&value) {
        return Err(CliError::input("Set profile or upstream passwords through `config apply --file PATH` or `config apply --stdin`, never through command arguments"));
    }
    let mut patch = Map::new();
    patch.insert(key.to_owned(), value);
    Ok(Value::Object(patch))
}

fn contains_password(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            matches!(key.as_str(), "password" | "proxyPassword") || contains_password(value)
        }),
        Value::Array(items) => items.iter().any(contains_password),
        _ => false,
    }
}

fn read_patch(args: &ApplyArgs) -> Result<Value, CliError> {
    let input: Box<dyn Read> = if args.stdin
        || args
            .file
            .as_ref()
            .is_some_and(|path| path == std::path::Path::new("-"))
    {
        Box::new(io::stdin())
    } else {
        let path = args
            .file
            .as_ref()
            .ok_or_else(|| CliError::input("Specify --file PATH or --stdin"))?;
        Box::new(
            File::open(path)
                .map_err(|error| CliError::input(format!("Cannot open patch file: {error}")))?,
        )
    };
    let mut bytes = Vec::new();
    input
        .take((MAX_FRAME + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| CliError::input(format!("Cannot read patch: {error}")))?;
    if bytes.len() > MAX_FRAME {
        return Err(CliError::input(format!(
            "Patch exceeds the {MAX_FRAME}-byte control limit"
        )));
    }
    let patch: Value = serde_json::from_slice(&bytes)
        .map_err(|error| CliError::input(format!("Patch is invalid JSON: {error}")))?;
    if !patch.is_object() {
        return Err(CliError::input(
            "Patch must be a JSON object of settings fields",
        ));
    }
    Ok(patch)
}

fn remove_secrets(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|key, _| {
                !matches!(
                    key.as_str(),
                    "proxyPassword" | "proxy_password" | "password"
                )
            });
            for child in map.values_mut() {
                remove_secrets(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                remove_secrets(item);
            }
        }
        _ => {}
    }
}

fn status_health(snapshot: &Value) -> Result<&'static str, CliError> {
    let running = snapshot
        .get("running")
        .and_then(Value::as_bool)
        .ok_or_else(|| CliError::degraded("Service returned no running state"))?;
    let enabled = snapshot
        .pointer("/settings/enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| CliError::degraded("Service returned no enabled setting"))?;
    if let Some(error) = snapshot.get("lastError").and_then(Value::as_str) {
        return Err(CliError::degraded(format!("Service reports: {error}")));
    }
    if snapshot
        .get("listenerError")
        .is_some_and(|value| !value.is_null())
    {
        return Err(CliError::degraded(
            "Service reports a listener error; inspect status and service logs",
        ));
    }
    if enabled && !running {
        return Err(CliError::degraded(
            "Proxy is enabled but not running; check service logs and listener settings",
        ));
    }
    if !enabled && running {
        return Err(CliError::degraded(
            "Proxy is running despite the saved disabled setting",
        ));
    }
    if let Some(error) = snapshot
        .pointer("/stats/listenerRuntimeError")
        .and_then(Value::as_str)
    {
        return Err(CliError::degraded(format!(
            "Proxy listener reports: {error}"
        )));
    }
    if snapshot
        .pointer("/usageHistory/healthy")
        .and_then(Value::as_bool)
        == Some(false)
    {
        let error = snapshot
            .pointer("/usageHistory/error")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        return Err(CliError::degraded(format!(
            "Usage history is unhealthy; quota profiles are blocked: {error}"
        )));
    }
    let stats = &snapshot["stats"];
    let global_limit = stats["connectionLimit"].as_u64().unwrap_or(0);
    let active = stats["activeConnections"].as_u64().unwrap_or(0);
    if global_limit > 0 && active >= global_limit {
        return Err(CliError::degraded("Proxy has no free connection slots"));
    }
    let peer_limit = stats["connectionLimitPerPeer"].as_u64().unwrap_or(0);
    if peer_limit > 0 {
        let mut counts = std::collections::HashMap::new();
        if let Some(connections) = stats["liveConnections"].as_array() {
            for connection in connections {
                if let Some(peer) = connection["peerIp"].as_str() {
                    let count = counts.entry(peer).or_insert(0u64);
                    *count += 1;
                    if *count >= peer_limit {
                        return Err(CliError::degraded(
                            "A proxy client has no free connection slots",
                        ));
                    }
                }
            }
        }
    }
    Ok(if running {
        "running"
    } else {
        "intentionally stopped"
    })
}

async fn execute(cli: &Cli) -> Result<Value, CliError> {
    let socket = cli.socket.clone().unwrap_or_else(default_socket);
    let command = match &cli.command {
        Action::Diagnostics {
            action: DiagnosticsAction::Status,
        } => Command::DiagnosticsStatus,
        Action::Diagnostics {
            action: DiagnosticsAction::Export,
        } => Command::ExportDiagnostics,
        Action::Filter {
            action: FilterAction::List,
        } => Command::FilterFeeds,
        Action::Filter {
            action: FilterAction::Import { name, file },
        } => {
            let mut text = String::new();
            File::open(file)
                .map_err(|error| CliError::input(format!("Cannot read filter file: {error}")))?
                .take(homeproxy_core::MAX_FILTER_FILE_BYTES as u64 + 1)
                .read_to_string(&mut text)
                .map_err(|error| {
                    CliError::input(format!("Filter file must contain valid UTF-8: {error}"))
                })?;
            let feed = homeproxy_core::FilterFeed::parse(name, &text)
                .map_err(|error| CliError::input(error.to_string()))?;
            let status = call(&socket, Command::Status).await?;
            Command::ImportFilterFeed {
                feed: serde_json::to_value(feed)
                    .map_err(|error| CliError::input(error.to_string()))?,
                expected_revision: status_revision(&status)?,
            }
        }
        Action::Filter {
            action: FilterAction::Remove { id },
        } => {
            let status = call(&socket, Command::Status).await?;
            Command::RemoveFilterFeed {
                id: id.clone(),
                expected_revision: status_revision(&status)?,
            }
        }
        Action::History {
            action: HistoryAction::Status,
        } => Command::UsageHistory,
        Action::History {
            action: HistoryAction::Export { format, .. },
        } => Command::ExportUsageHistory {
            format: if format == "csv" {
                HistoryFormat::Csv
            } else {
                HistoryFormat::Json
            },
        },
        Action::Tls {
            action: TlsAction::Status,
        } => Command::TlsStatus,
        Action::Tls {
            action: TlsAction::Prepare,
        } => Command::PrepareCa,
        Action::Tls {
            action: TlsAction::Export { format, .. },
        } => Command::ExportCa {
            format: if format == "der" {
                CertificateFormat::Der
            } else {
                CertificateFormat::Pem
            },
        },
        Action::Status
        | Action::Doctor
        | Action::Devices {
            action: DevicesAction::List,
        }
        | Action::Config {
            action: ConfigAction::Show,
        }
        | Action::Cache {
            action: CacheAction::Status,
        } => Command::Status,
        Action::Start => Command::Start,
        Action::Stop => Command::Stop,
        Action::Devices {
            action: DevicesAction::Allow { ip },
        } => Command::SetDeviceAllowed {
            ip: ip.to_string(),
            allowed: true,
        },
        Action::Devices {
            action: DevicesAction::Deny { ip },
        } => Command::SetDeviceAllowed {
            ip: ip.to_string(),
            allowed: false,
        },
        Action::Config {
            action: ConfigAction::Check,
        } => Command::ConfigCheck,
        Action::Config {
            action: ConfigAction::Set { key, json_value },
        } => Command::ConfigPatch {
            patch: parse_patch(key, json_value)?,
        },
        Action::Config {
            action: ConfigAction::Apply(args),
        } => Command::ConfigPatch {
            patch: read_patch(args)?,
        },
        Action::Credentials {
            action: CredentialsAction::Show,
        } => Command::Credentials,
        Action::Credentials {
            action: CredentialsAction::Rotate,
        } => Command::RotatePassword,
        Action::Cache {
            action: CacheAction::Clear,
        } => Command::ClearCache,
        Action::Cache {
            action: CacheAction::Prepared,
        } => Command::OfflinePreparationStatus,
        Action::Cache {
            action: CacheAction::Prepare { file },
        } => {
            let mut bytes = Vec::new();
            if file.as_os_str() == "-" {
                std::io::stdin()
                    .take(256 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| CliError::input("Cannot read preparation request"))?;
            } else {
                std::fs::File::open(file)
                    .map_err(|_| CliError::input("Cannot open preparation request"))?
                    .take(256 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| CliError::input("Cannot read preparation request"))?;
            }
            if bytes.len() > 256 * 1024 {
                return Err(CliError::input("Preparation request is too large"));
            }
            let request: Value = serde_json::from_slice(&bytes)
                .map_err(|_| CliError::input("Preparation request must be valid JSON"))?;
            Command::PrepareOffline { request }
        }
        Action::Cache {
            action: CacheAction::Cancel { id },
        } => Command::CancelOfflinePreparation { id: id.clone() },
        Action::Cache {
            action: CacheAction::Unpin { key },
        } => Command::ReleaseOfflinePin { key: key.clone() },
        Action::Activity {
            action: ActivityAction::Clear,
        } => Command::ClearActivity,
    };
    let mut response = call(&socket, command).await?;
    if !matches!(
        cli.command,
        Action::Credentials {
            action: CredentialsAction::Show
        }
    ) {
        remove_secrets(&mut response);
    }
    match &cli.command {
        Action::History {
            action: HistoryAction::Export {
                output: Some(path), ..
            },
        } => {
            let content = response
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::degraded("Service returned no history export"))?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path).map_err(|error| {
                CliError::input(format!("Cannot create history output: {error}"))
            })?;
            file.write_all(content.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| {
                    CliError::input(format!("Cannot write history output: {error}"))
                })?;
            Ok(json!({"output":path,"bytes":content.len()}))
        }
        Action::Tls {
            action: TlsAction::Export {
                output: Some(path), ..
            },
        } => {
            let bytes = exported_certificate_bytes(&response)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|error| {
                    CliError::input(format!("Cannot create certificate output: {error}"))
                })?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| {
                    CliError::input(format!("Cannot write certificate output: {error}"))
                })?;
            Ok(
                json!({"output":path,"sha256Fingerprint":response.get("sha256Fingerprint"),"bytes":bytes.len()}),
            )
        }
        Action::Doctor => {
            let state = status_health(&response)?;
            Ok(json!({"health": "ok", "state": state, "revision": response.get("revision")}))
        }
        Action::Config {
            action: ConfigAction::Show,
        } => response
            .get("settings")
            .cloned()
            .ok_or_else(|| CliError::degraded("Service returned no settings")),
        Action::Devices {
            action: DevicesAction::List,
        } => Ok(json!({
            "clients": response.pointer("/stats/clients").cloned().unwrap_or_else(|| json!([])),
            "deniedClientIps": response.pointer("/settings/deniedClientIps").cloned().unwrap_or_else(|| json!([])),
            "deviceLimits": response.pointer("/settings/deviceLimits").cloned().unwrap_or_else(|| json!([]))
        })),
        Action::Cache {
            action: CacheAction::Status,
        } => cache_summary(&response),
        _ => Ok(response),
    }
}

fn status_revision(value: &Value) -> Result<String, CliError> {
    value
        .get("revision")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CliError::degraded("Service returned no revision; use a matching daemon version")
        })
}

fn exported_certificate_bytes(value: &Value) -> Result<Vec<u8>, CliError> {
    let certificate = value
        .get("certificate")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::degraded("Service returned no public certificate"))?;
    match value.get("encoding").and_then(Value::as_str) {
        Some("pem") if certificate.starts_with("-----BEGIN CERTIFICATE-----\n") => {
            Ok(certificate.as_bytes().to_vec())
        }
        Some("hex") => {
            if certificate.len() % 2 != 0 {
                return Err(CliError::degraded("Invalid DER certificate encoding"));
            }
            certificate
                .as_bytes()
                .chunks(2)
                .map(|pair| {
                    let high = (pair[0] as char).to_digit(16);
                    let low = (pair[1] as char).to_digit(16);
                    high.zip(low)
                        .map(|(h, l)| ((h << 4) | l) as u8)
                        .ok_or_else(|| CliError::degraded("Invalid DER certificate encoding"))
                })
                .collect()
        }
        _ => Err(CliError::degraded("Unsupported certificate encoding")),
    }
}

fn cache_summary(snapshot: &Value) -> Result<Value, CliError> {
    let usage = snapshot
        .get("cache")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            CliError::degraded("Service returned no cache usage; use a matching daemon version")
        })?;
    let settings = snapshot
        .get("settings")
        .ok_or_else(|| CliError::degraded("Service returned no settings"))?;
    Ok(json!({
        "usage": usage,
        "limits": {
            "cacheEnabled": settings.get("cacheEnabled"),
            "cacheLimitGib": settings.get("cacheLimitGib"),
            "cacheMaxObjectMib": settings.get("cacheMaxObjectMib"),
            "responseBufferLimitMib": settings.get("responseBufferLimitMib"),
            "responseBufferBudgetMib": settings.get("responseBufferBudgetMib")
        },
        "units": {"GiB": 1073741824_u64, "MiB": 1048576_u64},
        "storage": "disk",
        "bufferScope": "Temporary collected HTTP response bodies; not a persistent RAM cache or total process memory"
    }))
}

fn show_result(cli: &Cli, value: &Value) {
    if cli.json {
        println!("{}", json!({"ok": true, "result": value}));
        return;
    }
    match &cli.command {
        Action::Diagnostics { .. } => println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".into())
        ),
        Action::Cache {
            action:
                CacheAction::Prepared
                | CacheAction::Prepare { .. }
                | CacheAction::Cancel { .. }
                | CacheAction::Unpin { .. },
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".into())
            );
        }
        Action::Status | Action::Start | Action::Stop => {
            let running = value
                .get("running")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            println!("Proxy: {}", if running { "running" } else { "stopped" });
            if let Some(error) = value.get("lastError").and_then(Value::as_str) {
                println!("Issue: {error}");
            }
            if let Some(addresses) = value.get("proxyAddresses").and_then(Value::as_array) {
                for address in addresses {
                    if let Some(address) = address.as_str() {
                        println!("HTTP proxy: {address}");
                    }
                }
            }
        }
        Action::Filter { .. } | Action::Tls { .. } | Action::History { .. } => println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        ),
        Action::Doctor => println!(
            "HomeProxy service: healthy ({})",
            value["state"].as_str().unwrap_or("unknown")
        ),
        Action::Config {
            action: ConfigAction::Check,
        } => println!("Configuration is valid"),
        Action::Config {
            action: ConfigAction::Show,
        }
        | Action::Devices {
            action: DevicesAction::List,
        }
        | Action::Credentials {
            action: CredentialsAction::Show,
        }
        | Action::Cache {
            action: CacheAction::Status,
        } => println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        ),
        Action::Config {
            action: ConfigAction::Set { .. } | ConfigAction::Apply(_),
        } => println!("Configuration updated"),
        Action::Devices {
            action: DevicesAction::Allow { ip },
        } => println!("Device {ip} allowed"),
        Action::Devices {
            action: DevicesAction::Deny { ip },
        } => println!("Device {ip} denied"),
        Action::Credentials {
            action: CredentialsAction::Rotate,
        } => println!("Proxy password rotated; use `homeproxy credentials show` to view it"),
        Action::Cache {
            action: CacheAction::Clear,
        } => println!("Cache cleared"),
        Action::Activity {
            action: ActivityAction::Clear,
        } => println!("Activity cleared"),
    }
}

fn show_error(json_output: bool, error: &CliError) {
    if json_output {
        println!(
            "{}",
            json!({"ok": false, "error": {"code": error.code, "message": error.message}})
        );
    } else {
        eprintln!("HomeProxy: {}", error.message);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error) => {
            let exit = error.exit_code();
            if exit == 0 {
                let _ = error.print();
                return ExitCode::SUCCESS;
            }
            let json_output = args.iter().any(|arg| arg == "--json");
            show_error(json_output, &CliError::input(error.to_string()));
            return ExitCode::from(2);
        }
    };
    match execute(&cli).await {
        Ok(value) => {
            show_result(&cli, &value);
            ExitCode::SUCCESS
        }
        Err(error) => {
            show_error(cli.json, &error);
            ExitCode::from(error.exit)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tls_export_decodes_public_der_and_rejects_malformed_wire_encoding() {
        assert_eq!(
            exported_certificate_bytes(&json!({"certificate":"3002ff00","encoding":"hex"}))
                .unwrap(),
            vec![0x30, 2, 255, 0]
        );
        for value in [
            json!({"certificate":"0","encoding":"hex"}),
            json!({"certificate":"GG","encoding":"hex"}),
            json!({"certificate":"private","encoding":"pem"}),
            json!({"encoding":"hex"}),
        ] {
            assert!(exported_certificate_bytes(&value).is_err());
        }
        for arguments in [
            vec!["homeproxy", "tls", "status"],
            vec!["homeproxy", "tls", "prepare"],
            vec![
                "homeproxy",
                "tls",
                "export",
                "--format",
                "der",
                "--output",
                "root.der",
            ],
            vec!["homeproxy", "history", "export", "--format", "csv"],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
        assert!(Cli::try_parse_from(["homeproxy", "tls", "export", "--format", "key"]).is_err());
    }
    #[test]
    fn cache_status_preserves_unknown_usage_and_never_includes_credentials() {
        assert!(cache_summary(&json!({"settings": {}})).is_err());
        let summary = cache_summary(&json!({
            "settings": {"cacheEnabled": true,"cacheLimitGib":20,"cacheMaxObjectMib":32,
                "responseBufferLimitMib":0,"responseBufferBudgetMib":0,"proxyPassword":"secret"},
            "cache": {"usedBytes":123,"entryCount":1,"usageIsCurrent":false,
                "pendingMaintenance":true,"measurementError":null}
        }))
        .unwrap();
        assert_eq!(summary["usage"]["usedBytes"], 123);
        assert_eq!(summary["usage"]["usageIsCurrent"], false);
        assert_eq!(summary["limits"]["cacheMaxObjectMib"], 32);
        assert!(!summary.to_string().contains("secret"));
    }

    #[test]
    fn rejects_password_on_command_line_but_accepts_other_json() {
        assert!(parse_patch("proxyPassword", r#""secret""#).is_err());
        assert!(parse_patch("proxy_password", r#""secret""#).is_err());
        assert!(parse_patch("deviceProfiles", r#"[{"password":"secret"}]"#).is_err());
        assert!(parse_patch("upstreamProxies", r#"[{"password":"secret"}]"#).is_err());
        assert_eq!(
            parse_patch("cacheEnabled", "true").unwrap(),
            json!({"cacheEnabled": true})
        );
    }
    #[test]
    fn ordinary_output_recursively_redacts_password() {
        let mut value = json!({"settings": {"proxyPassword": "secret", "nested": [{"password": "other"}], "proxyUsername": "domov"}});
        remove_secrets(&mut value);
        assert_eq!(
            value,
            json!({"settings": {"nested": [{}], "proxyUsername": "domov"}})
        );
    }
    #[test]
    fn doctor_distinguishes_stopped_from_degraded() {
        assert_eq!(
            status_health(
                &json!({"running": false, "settings": {"enabled": false}, "lastError": null})
            )
            .unwrap(),
            "intentionally stopped"
        );
        assert_eq!(
            status_health(
                &json!({"running": true, "settings": {"enabled": true}, "lastError": null})
            )
            .unwrap(),
            "running"
        );
        assert_eq!(
            status_health(
                &json!({"running": false, "settings": {"enabled": true}, "lastError": null})
            )
            .unwrap_err()
            .exit,
            6
        );
        assert_eq!(status_health(&json!({"running": false, "settings": {"enabled": false}, "lastError": "Inspect unavailable"})).unwrap_err().exit, 6);
    }

    #[test]
    fn doctor_detects_current_capacity_and_accept_errors_without_sticky_history() {
        assert_eq!(
            status_health(&json!({"running":false,"settings":{"enabled":false},
            "lastError":null,"stats":{"listenerRuntimeError":null,"listenerRuntimeErrors":2,
                "activeConnections":0,"connectionLimit":256,"connectionLimitPerPeer":128,
                "liveConnections":[]}}))
            .unwrap(),
            "intentionally stopped"
        );
        let base = json!({"running":true,"settings":{"enabled":true},"lastError":null,
            "stats":{"activeConnections":1,"connectionLimit":256,"connectionLimitPerPeer":128,
                "liveConnections":[{"peerIp":"192.0.2.1"}], "listenerRuntimeError":null,
                "rejectedConnections":300,"idleConnectionsClosed":128,"listenerRuntimeErrors":3,
                "keepaliveConfigurationFailures":1}});
        assert_eq!(status_health(&base).unwrap(), "running");
        let mut global = base.clone();
        global["stats"]["activeConnections"] = json!(256);
        assert_eq!(status_health(&global).unwrap_err().exit, 6);
        let mut peer = base.clone();
        peer["stats"]["liveConnections"] = json!(vec![json!({"peerIp":"192.0.2.1"}); 128]);
        assert_eq!(status_health(&peer).unwrap_err().exit, 6);
        peer["stats"]["liveConnections"] = json!(vec![json!({"peerIp":"192.0.2.1"}); 127]);
        assert!(status_health(&peer).is_ok());
        let mut history = base.clone();
        history["usageHistory"] = json!({"healthy": true});
        assert!(status_health(&history).is_ok());
        history["usageHistory"] = json!({"healthy": false, "error": "disk full"});
        let error = status_health(&history).unwrap_err();
        assert_eq!(error.exit, 6);
        assert!(error.message.contains("disk full"), "{}", error.message);
        let mut listener = base;
        listener["stats"]["listenerRuntimeError"] = json!("resource temporarily unavailable");
        assert_eq!(status_health(&listener).unwrap_err().exit, 6);
    }
    #[test]
    fn supports_global_options_and_nested_commands() {
        let cli = Cli::try_parse_from([
            "homeproxy",
            "config",
            "set",
            "cacheEnabled",
            "true",
            "--json",
        ])
        .unwrap();
        assert!(cli.json);
        assert!(matches!(
            cli.command,
            Action::Config {
                action: ConfigAction::Set { .. }
            }
        ));
    }
}
