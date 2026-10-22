# Contributing to HomeProxy

Thank you for helping. Bug reports, translations (Czech and English) and focused pull requests are welcome.

## Before you start

- For larger changes, open an issue first so we can agree on the approach.
- Keep the privacy rules intact: proxy authentication stays on by default, private and signed-in responses are never cached, and HTTPS inspection requires explicit trust on each device.
- User-visible text lives in `src/i18n.ts` and must be updated in both languages.

## Development

Requirements: Rust stable, Node.js 22, and on Linux the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

```sh
npm ci
cargo fetch --locked
npm run dev                 # UI only, in a browser
npm run tauri -- dev        # desktop app
```

On Ubuntu the desktop controls a separate daemon. To run one in a private, temporary profile without installing anything, follow [Try it without installing](docs/ubuntu-server.md#try-it-without-installing).

## Checks

Run these before opening a pull request; CI runs the same set:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
npm test
npm run build
```

Add a regression test for every bug fix. Tests that need network access, a virtual machine or a real desktop session are opt-in; do not run them against someone else's network.

## Pull requests

Describe what changed and how you tested it. By contributing you agree that your contribution is licensed under the project's [GPL-3.0-or-later](LICENSE) license.
