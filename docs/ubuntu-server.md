# HomeProxy on Ubuntu Server

This package contains `homeproxyd` and the small `homeproxy` CLI. It does not need a desktop or Node.js. The system service runs as the unprivileged `homeproxy` user, with private state in `/var/lib/homeproxy`, cache in `/var/cache/homeproxy`, and a local control socket at `/run/homeproxy/control.sock`. The service starts after installation with the proxy disabled; no firewall rules or certificate trust stores are changed.

## Try it without installing

Build the two Rust binaries with `cargo build --locked --offline -p homeproxy-service -p homeproxy-cli`. In one terminal, create a private profile and run the daemon in the foreground:

```sh
profile=$(mktemp -d)
chmod 700 "$profile"
printf 'Profile: %s\n' "$profile"
cargo run --locked --offline -p homeproxy-service -- --foreground --state-dir "$profile/state" --cache-dir "$profile/cache" --socket "$profile/run/control.sock"
```

In another terminal, use the printed profile path:

```sh
export HOMEPROXY_SOCKET=/path/from/first/terminal/run/control.sock
cargo run --locked --offline -p homeproxy-cli -- status
cargo run --locked --offline -p homeproxy-cli -- doctor
```

Only your account can access this development socket. The daemon stays in the foreground; Ctrl+C stops its process without changing the saved desire to run. Keep the profile path if you want to reuse its settings.

## Install the server package

Run `scripts/build-linux.sh` to build an offline release `.deb` in `target/linux-package/`. `scripts/build-linux.sh --debug` builds a faster debug package for testing. Building does not install or start anything. On the target Ubuntu machine, an administrator installs the resulting package and grants local management access:

```sh
sudo apt install ./target/linux-package/homeproxy_VERSION_ARCH.deb
sudo usermod -aG homeproxy-admin "$USER"
```

Sign out and back in for the new group membership to apply. Check it with `id -nG`, then use `homeproxy status` and `homeproxy doctor`. The socket is local and group restricted; SSH plus the CLI is the supported remote administration path. Avoid forwarding the socket to untrusted users. `sudo systemctl status homeproxy` and `sudo journalctl -u homeproxy -b` show service startup and runtime errors.

## Configure and start

`homeproxy config show` prints the saved settings without the proxy password. `homeproxy credentials show` is the explicit command that reveals the current username and password; use it only in a private terminal. `homeproxy credentials rotate` changes the password. `homeproxy config check` validates the saved configuration. Use `homeproxy --json status` for a JSON result.

The default proxy is disabled and bound only to loopback until LAN is explicitly configured. Choose a private IPv4 address actually assigned to the Ubuntu host; `homeproxy --json status` lists `availableAddresses` to help identify it. For example:

```sh
homeproxy config apply --stdin <<'JSON'
{"lanEnabled":true,"listenIp":"192.168.1.20","cacheEnabled":true}
JSON
homeproxy config check
homeproxy start
homeproxy doctor
homeproxy status
```

If `listenIps` already contains addresses, it takes precedence over `listenIp`; include `"listenIps":[]` in the same patch when switching to the single-address setting. The group-restricted control socket protects administration, but any local account can use the loopback proxy without credentials; shared Ubuntu hosts with untrusted local users still need a separate access-control design before release.

Configure each client to use the reported HTTP proxy address and port, and its credentials if authentication is enabled. Opening the host firewall, router setup, or client proxy setup is a separate explicit administrative choice. This is an explicit proxy: devices that do not use it are unaffected. Tunnel mode carries HTTPS but cannot inspect, compress, or cache its encrypted content. SOCKS5 always carries raw tunnels.

To cache or compress supported HTTPS sites, the headless service can use HTTPS Inspect with a private authority stored under `/var/lib/homeproxy`; it never installs that authority into any trust store. Preparing the authority does not enable Inspect:

```sh
homeproxy tls prepare
homeproxy tls export --format pem --output HomeProxy-CA.pem
homeproxy tls status
```

Compare the SHA-256 fingerprint and install trust in the certificate on each of your own clients (`--format der` exports DER). Then acknowledge client trust and choose the scope in one patch, either every supported site or a list of exact domains (`*.example.org` for subdomains):

```sh
homeproxy config apply --stdin <<'JSON'
{"httpsMode":"inspect","httpsClientTrustAcknowledged":true,"httpsInspectionScope":"allSupportedHosts","cacheEnabled":true}
JSON
```

For selected domains use `"httpsInspectionScope":"selectedHosts","httpsInspectHosts":["example.org"]`; an empty list is rejected. Saving restarts active connections. Inspect can read signed-in pages on hosts in scope; only eligible public responses are cached or compressed. Built-in video/Google exceptions and remembered client TLS failures stay tunnelled. `homeproxy --json status` reports `stats.cacheBypassReasons`, and `scripts/homeproxy-healthcheck.py` lists the most frequent ones. See [HTTPS cache and offline mode](https-offline.md) and [why HTTPS is not cached](cache-and-images.md#proč-se-https-necachuje).

Useful commands include `homeproxy devices list`, `homeproxy devices deny 192.168.1.50`, `homeproxy devices allow 192.168.1.50`, `homeproxy cache clear`, `homeproxy activity clear`, and `homeproxy stop`. `homeproxy config set cacheEnabled true` accepts JSON values for one ordinary setting. Password changes through configuration are accepted only from `config apply --file PATH` or `config apply --stdin`, never an argument visible in process listings. Input patches have the control protocol size limit.

CLI exit codes: `0` success; `2` CLI usage or local input error; `3` service unavailable; `4` permission denied; `5` rejected change or configuration conflict; `6` service degraded (`doctor`); `7` transport, protocol, or unexpected service error. With `--json`, normal results are `{"ok":true,"result":...}` and errors are `{"ok":false,"error":{"code":"...","message":"..."}}`.

Listener failures use JSON error codes `listener_in_use`, `listener_access_denied`, `listener_address_unavailable`, or `listener_start_failed` (all exit `5`), replacing generic `operation_failed` for these failures. A rejected live change returns its error even when rollback restores a healthy service; `doctor` then reports the current running service as healthy.

The package restarts an enabled or already running service during upgrade, following Debian service policy; a disabled inactive service or an administrator mask is preserved. Reinstalling an enabled service starts it again. To keep it off across upgrades and boot, use `systemctl disable --now homeproxy`; `homeproxy stop` separately preserves the proxy's disabled setting. Removing or purging the package leaves `/var/lib/homeproxy` and `/var/cache/homeproxy` intact for recovery or reinstallation. Back up the private state directory before migration to another machine; it contains configuration and credentials. Use normal filesystem permissions for backups.

Package lifecycle (installation, systemd identity, reboot, upgrade and reinstallation) is tested in disposable Ubuntu virtual machines. GNOME/Wayland sessions and individual phone, TV and app combinations are not covered by those tests; please report problems through GitHub issues.

## Ubuntu Desktop package

Cache controls now include disk capacity (1–1024 GiB), maximum object (1–1024 MiB), and temporary response buffers (0–8 MiB per body, 0–512 MiB shared). Defaults stay 8 GiB / 1024 MiB / 8 MiB / 64 MiB with cache disabled. `homeproxy cache status` shows usage and applied limits; `homeproxy --json cache status` preserves measurement and maintenance states. These buffers are not a persistent RAM cache or a total process-memory limit. Changing limits restarts proxy listeners and can interrupt transfers. See [cache controls and protocol limits](cache-controls.md) for exact fields, validation, persistence and the SmartTube / Google Play explanation.

Build the matching server `.deb` first with `scripts/build-linux.sh`, then run `scripts/build-linux-desktop.sh`. The desktop wrapper uses the local Tauri CLI and offline Cargo dependencies; it produces `target/linux-package/homeproxy-desktop_VERSION_ARCH.deb` and verifies that the package requires exactly the matching `homeproxy` server version. Install both packages together on Ubuntu Desktop. The application menu entry is **Homeproxy Desktop**; the window remains **HomeProxy**. Closing the window does not stop the system service.

The desktop bundle uses the host's WebKitGTK and GTK libraries. A built `.deb` confirms packaging but not rendering or interaction under GNOME/Wayland; test those on a real Ubuntu Desktop session before release. The server package remains usable on its own without these desktop libraries.

The circular-arrow button in the desktop traffic summary resets only the sent and received totals after confirmation. Existing transfers continue, and rates, savings, history, quotas and settings are preserved. The period survives closing the window and stopping/starting the proxy; restarting the daemon starts a new period. Server and desktop version 1.2.6 must be updated together for this command.
