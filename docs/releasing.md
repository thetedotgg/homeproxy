# Vydání HomeProxy / Releasing HomeProxy

Vydání staví GitHub Actions workflow [`release.yml`](../.github/workflows/release.yml).
Odkazy `https://github.com/<owner>/<repo>/releases/latest/download/<název>` fungují
díky stabilním názvům souborů.

| Soubor | Obsah |
|---|---|
| `HomeProxy-Setup-x64.exe` | Windows NSIS instalátor (bez podpisu, pokud chybí secret níže) |
| `HomeProxy-Ubuntu-amd64.tar.gz` | složka `HomeProxy-Ubuntu-amd64/`: oba `.deb`, `install.sh`, `SHA256SUMS` |
| `HomeProxy_<verze>_x64-setup.exe`, `homeproxy_<verze>_amd64.deb`, `homeproxy-desktop_<verze>_amd64.deb` | verzované kopie |
| `SHA256SUMS.txt` | SHA-256 všech výše uvedených souborů |

Tělo vydání se generuje ze šablony [`.github/release-notes.md`](../.github/release-notes.md).

## Postup

1. Zvyš verzi společně v `Cargo.toml` (`workspace.package.version`), `Cargo.lock`,
   `package.json`, `package-lock.json`, `src-tauri/tauri.conf.json` a závislost
   `homeproxy (= <verze>)` v `src-tauri/tauri.linux.conf.json`. Kontrola:
   `bash scripts/package-release-assets.sh check-version`.
2. Lokální gate (hostované Actions mohou být blokované): `cargo fmt --all --check`,
   `cargo clippy --workspace --all-targets --locked -- -D warnings`,
   `cargo test --workspace --locked`, `npm test`, `npm run build`,
   `bash scripts/test-linux-package-scripts.sh`, `bash scripts/test-linux-install-bundle.sh`.
3. Volitelně zkušební běh: **Actions → Release → Run workflow** na `main` vytvoří
   nebo aktualizuje **koncept** (draft) `v<verze>`; z jiné větve, nebo když tag už ukazuje
   jinam, workflow skončí chybou. Zveřejněné vydání se nikdy nepřepisuje.
4. Po merge do `main` vytvoř a pushni tag na commit v `main`:
   `git tag -a v<verze> -m "HomeProxy <verze>" && git push origin v<verze>`.
   Workflow ověří, že tag odpovídá verzi ve všech manifestech a leží na `origin/main`,
   postaví Ubuntu (na `ubuntu-22.04`, glibc ≤ 2.35) i Windows (`windows-latest`) a vydání
   zveřejní jako **latest** (verze s `-` jako prerelease).

Lokální sestavení Ubuntu assetů stejně jako v CI:

```sh
npm ci && cargo fetch --locked
bash scripts/build-linux.sh && bash scripts/build-linux-desktop.sh
bash scripts/package-release-assets.sh linux          # -> target/release-assets/
```

## Veřejné repo / Public repository

Vývoj, interní QA podklady a agentní instrukce zůstávají v soukromém
`thetedotgg/homeproxy-private`. Veřejné `thetedotgg/homeproxy` dostává jen
proskenovaný export (`scripts/public-export-exclude.txt`). Po merge do soukromého `main`:

```sh
git clone https://github.com/thetedotgg/homeproxy.git ~/.cache/homeproxy-public-clone   # jednou
bash scripts/sync-public-repo.sh --deny-patterns <soubor mimo repo> ~/.cache/homeproxy-public-clone
git -C ~/.cache/homeproxy-public-clone push origin main
```

Tag vydání se vytváří ve veřejném repu na synchronizovaném commitu. Příspěvky z veřejných PR
se přenášejí do soukromého repa jako patch (`gh pr diff <n> | git apply`) a vrací se dalším syncem.

## Jednorázové nastavení repozitáře / One-time repository setup

- **Settings → Environments → `release`**: povinný reviewer a omezení na tagy `v*`
  a větev `main`. V tomto prostředí běží Windows build (volitelný podpis) i publikace.
- **Settings → Rules → Rulesets**: chraň tagy `v*` (zákaz smazání a přepsání) a zapni
  **Immutable releases**, pokud je dostupné.
- **Settings → Code security → Private vulnerability reporting**: zapnout (viz `SECURITY.md`).

## Podpis Windows / Windows signing

Bez secretu `HOMEPROXY_TAURI_SIGNING_CONFIG` (ulož ho jako secret prostředí `release`) vzniká nepodepsaný instalátor a CI ověří,
že je `NotSigned`. Pokud vlastník uloží autorizovaný Tauri signing config (JSON) do
tohoto secretu, build ho použije a ověří podpis podle `scripts/windows-signing-policy.json`;
s prázdnou politikou build záměrně selže.

## Ověření stažených souborů / Verifying downloads

```sh
sha256sum --check --ignore-missing SHA256SUMS.txt
gh attestation verify HomeProxy-Setup-x64.exe --repo <owner>/<repo>   # jen u veřejného repa
```

Release builds run without caches, pin third-party actions to commit SHAs and grant
`contents: write` only to the publish job. The workflow never installs anything on
client machines; publishing a release is not a deployment to any device.
