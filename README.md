# HomeProxy

**A calm home proxy for the whole household.** HomeProxy runs on one computer at home and lets phones, laptops and TVs on the same network browse through it: ads are blocked, eligible public content is cached and images can be compressed, so the household uses less data. You see what each device does and can limit or block it.

HomeProxy is free and open source. [Čeština](README.cs.md) · [Website](https://homeproxy.thetasigma.io)

## Download

| Platform | Download |
|---|---|
| Windows 10/11 (x64) | [HomeProxy-Setup-x64.exe](https://github.com/thetedotgg/homeproxy/releases/latest/download/HomeProxy-Setup-x64.exe) |
| Ubuntu 22.04 or newer (amd64) | [HomeProxy-Ubuntu-amd64.tar.gz](https://github.com/thetedotgg/homeproxy/releases/latest/download/HomeProxy-Ubuntu-amd64.tar.gz) |

All files and SHA-256 checksums are on the [latest release](https://github.com/thetedotgg/homeproxy/releases/latest) page.

**Windows:** run the installer. It is not code-signed yet, so SmartScreen may show *Windows protected your PC*; choose **More info → Run anyway** only if the file came from the release page above.

**Ubuntu:** extract the archive and run the installer from a terminal, then sign out and back in:

```sh
tar -xzf HomeProxy-Ubuntu-amd64.tar.gz
cd HomeProxy-Ubuntu-amd64
./install.sh
```

The installer verifies the checksums and installs two packages: the `homeproxy` system service and the `homeproxy-desktop` app. The service keeps running when the window is closed.

## Connect your devices

Open HomeProxy, start the proxy for your home network and follow the **Getting started** guide. It shows the address, port, user name and access key to enter in the device's proxy settings (on phones and TVs under Wi-Fi), and a QR code for installing the HomeProxy certificate if you turn on HTTPS inspection. Sign-in is required by default, and you can block any device from the app.

The computer running HomeProxy must stay on and awake. Video streaming does not get cheaper, and pages behind a sign-in (such as online banking), cookies and private responses are never cached.

## What it does

- **Ad blocking** with three levels: Off, Mild and Strict.
- **Public cache** for content that is safe to share (2, 8 or 20 GB); private, signed-in and `no-store` responses are never stored.
- **Image compression** to save mobile or metered data.
- **Traffic overview** with today's savings and per-device activity.
- **Device limits**: block a device, set quotas and time rules.
- **Optional HTTPS inspection** for sites you choose. It stays off until you prepare the HomeProxy certificate and trust it on each device; chat and call apps and YouTube always use an encrypted tunnel, and you can add other sites, such as your bank, as exceptions.
- **Offline preparation** of selected public pages and files.
- **Diagnostics and automatic recovery** without a terminal.

Nothing is sent anywhere: HomeProxy has no telemetry, account or cloud service.

## Documentation

- [Ubuntu service and CLI](docs/ubuntu-server.md)
- [Connecting devices with a QR code](docs/device-certificate-setup.md) (Czech)
- [HTTPS cache and offline mode](docs/https-offline.md) (Czech)
- [Cache and image savings](docs/cache-and-images.md) (Czech)
- [Cache limits and protocol scope](docs/cache-controls.md) (Czech)
- [Long-running connections](docs/connection-resilience.md) (Czech)
- [Diagnostics and recovery](docs/diagnostics-and-recovery.md) (Czech)
- [Releasing](docs/releasing.md)

## Build from source

HomeProxy is a Rust workspace (`crates/`) with a Tauri 2 desktop app (`src-tauri/`) and a TypeScript UI (`src/`). You need Rust stable, Node.js 22 and, on Linux, the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

```sh
npm ci
cargo fetch --locked
npm test && cargo test --workspace --locked
bash scripts/build-linux.sh          # server .deb in target/linux-package/
bash scripts/build-linux-desktop.sh  # desktop .deb, requires the server .deb
```

On Windows, `npm run tauri -- build --bundles nsis` builds the installer. See [CONTRIBUTING.md](CONTRIBUTING.md) before sending changes.

## Support the project

HomeProxy is free. If it saves you data or hassle, you can support its development: see the [website](https://homeproxy.thetasigma.io/en/#support).

## Security and license

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). HomeProxy is licensed under the [GNU General Public License v3.0 or later](LICENSE).
