# HomeProxy website

Static product page for **homeproxy.thetasigma.io**: `/cs/` and `/en/` are rendered
from one template (`src/page.mjs`) and two dictionaries (`src/i18n/{cs,en}.mjs`).
No client framework; one CSS file, one small progressive JS file (< 5 kB), self-hosted
Inter subset. Served by unprivileged nginx with a strict CSP.

## Layout

| Path | Purpose |
|---|---|
| `site.json` | Single config: URLs, downloads, author, license, donate buttons |
| `src/page.mjs`, `src/icons.mjs` | Template, icon sprite, hero diagram |
| `src/i18n/cs.mjs`, `src/i18n/en.mjs` | Copy; same shape is enforced by the build |
| `src/styles.css`, `src/site.js` | Stylesheet and progressive enhancement |
| `src/screens/*.png` | App screenshots, 2360×1520 (`{cs,en}-{home,guide,settings,devices}`) |
| `src/generated/screens/` | AVIF/WebP variants (640/1180/1760 px) + `manifest.json` |
| `src/og/og-{cs,en}.png` | Open Graph images 1200×630 |
| `src/fonts/` | Inter Variable subset (Latin + Czech/Slovak, wght 400–700), OFL-1.1 |
| `src/icons/` | Favicons copied from `assets/app-icon.svg` and `src-tauri/icons/` |
| `scripts/build.mjs` | Dependency-free build into `dist/` |
| `nginx/` | Runtime config and security headers |

## Commands

Node 22+. The build itself needs no `npm install`.

```sh
cd website
node scripts/build.mjs               # preview build; placeholders allowed, prints warnings
node scripts/build.mjs --production  # fails while any placeholder would ship
npm run check                        # syntax + node:test suite
npm run preview                      # dist/ on http://127.0.0.1:4338 (approximates nginx)
```

Dev-time asset steps (outputs are committed, so Docker never runs them):

```sh
npm ci                                # installs sharp (devDependency) for the two steps below
npm run images                        # after replacing src/screens/*.png
npm run og                            # after changing hero copy; needs Chromium (CHROME_BIN or Playwright cache)
uv run scripts/subset-fonts.py <@fontsource-variable/inter 5.3.0>/files   # only if glyph coverage changes
```

`build.mjs` refuses to run when a screenshot no longer matches its generated variants.

## Placeholders and the production gate

`--production` (and therefore the Docker image by default) fails while:

- `donate.enabled` is `true` and `donate.url` is `null` (a dashed placeholder box is shown in preview).
  Set the URL, or set `"enabled": false` to drop the section and the FAQ mention.
- `license.name` / `license.url` are `null` — the page says the project is open source.
- any screenshot is still a generated placeholder.

Extra donate buttons (`donate.more`, e.g. GitHub Sponsors, Ko-fi) appear once their `url`
is set; `locales` limits them to `cs` and/or `en`. `donate.czechQr` (CZ page only) shows a
QR payment image from `image` with the `account` number; it needs both.

## Language routing

`/` returns `302` to `/cs/` or `/en/` with `Vary: Accept-Language, Cookie` and `no-store`:
a `lang=cs|en` cookie wins (set by the language switch, `SameSite=Lax`, `Secure` on HTTPS,
one year); otherwise the first `cs`/`sk`/`en` tag in `Accept-Language` decides (`cs`/`sk` → Czech),
falling back to English. The switch is a normal link and works without JS. Pages carry
`hreflang`, `x-default` (English) and self-canonical URLs; `sitemap.xml` lists both.

## Docker

```sh
cd website
docker build -t homeproxy-website .                               # production (fails on placeholders)
docker build --build-arg SITE_MODE=preview -t homeproxy-website:preview .   # local QA only
docker run --rm --read-only --tmpfs /tmp --cap-drop ALL -p 8088:8080 homeproxy-website:preview
curl -sI -H 'Host: homeproxy.thetasigma.io' -H 'Accept-Language: cs' http://127.0.0.1:8088/
```

Pass `--build-arg SOURCE_COMMIT=<full sha>` to stamp `/version.json` and the OCI label.
Base images are pinned by digest (same as thete.gg). The container runs as `nginx` on
port 8080; `/healthz` returns `{"status":"ok"}` for the health check.

Headers: CSP `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'none';
form-action 'none'; frame-ancestors 'none'` (no inline scripts or styles, no CDNs, no
analytics), `nosniff`, `DENY` framing, referrer and permissions policy. Hashed assets under
`/assets/` are `immutable` for a year; HTML revalidates. `X-Robots-Tag` is `index, follow`
only for `homeproxy.thetasigma.io`; every other host (previews, IPs) gets `noindex`.

## Deploying on Coolify (not done yet)

1. New resource → the HomeProxy GitHub repository → build pack **Dockerfile**,
   base directory **`website/`**, Dockerfile `Dockerfile`, exposed port **8080**.
2. Domain **https://homeproxy.thetasigma.io**; health check path `/healthz`.
3. Optional build arg `SOURCE_COMMIT` = the deployed commit SHA.
4. Production builds fail until donate (or `"enabled": false`) and license are set in `site.json`.

DNS (Cloudflare zone `thetasigma.io`): one record `homeproxy` pointing to the Coolify host
(`A` to the server IP or `CNAME` to its hostname, as the existing thetasigma.io records do),
proxied, SSL mode Full (strict) with the origin certificate Coolify/Traefik serves.
Cloudflare terminates HTTPS and HTTP/2/3; the `Secure` cookie flag and HSTS depend on that.

## Measured (local Docker, 2026-10-22)

Lighthouse 12.8 mobile (simulated slow 4G, 4× CPU): Performance 100, Accessibility 100,
SEO 92 → 100 when `connect-src` allows Lighthouse's own `robots.txt` fetch (the strict CSP
blocks only that audit, not crawlers). Best Practices 79 locally because the test origin is
plain HTTP/1.1; it is expected to rise behind Cloudflare HTTPS, not verified.
First view (HTML + CSS + JS + fonts, gzip): ~46 kB Czech, ~41 kB English.
