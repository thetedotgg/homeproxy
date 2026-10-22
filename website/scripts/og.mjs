// Dev-time: renders the 1200x630 Open Graph images (src/og/og-{cs,en}.png)
// with headless Chromium and the site's own fonts, CSS and diagram.
// Needs `sharp` (devDependency) and Chromium: set CHROME_BIN, or a Playwright
// Chromium in ~/.cache/ms-playwright is used.
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import sharp from 'sharp';
import { brandMark, diagram } from '../src/icons.mjs';
import { esc } from './lib/render.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));

function findChrome() {
  if (process.env.CHROME_BIN) return process.env.CHROME_BIN;
  const base = path.join(os.homedir(), '.cache/ms-playwright');
  const dirs = existsSync(base) ? readdirSync(base).filter(d => /^chromium-\d+$/.test(d)).sort((a, b) => Number(b.split('-')[1]) - Number(a.split('-')[1])) : [];
  for (const dir of dirs) {
    const bin = path.join(base, dir, 'chrome-linux64/chrome');
    if (existsSync(bin)) return bin;
  }
  throw new Error('Chromium not found. Set CHROME_BIN.');
}

const site = JSON.parse(await readFile(path.join(root, 'site.json'), 'utf8'));
const chrome = findChrome();
const tmp = await mkdtemp(path.join(os.tmpdir(), 'homeproxy-og-'));
const fontUrl = name => pathToFileURL(path.join(root, 'src/fonts', name)).href;
const css = (await readFile(path.join(root, 'src/styles.css'), 'utf8')).replaceAll('{{FONT_LATIN}}', fontUrl('inter-latin.woff2')).replaceAll('{{FONT_CZECH}}', fontUrl('inter-czech.woff2'));
await writeFile(path.join(tmp, 'styles.css'), css);
await writeFile(path.join(tmp, 'og.css'), `
html, body { width: 1200px; height: 630px; overflow: hidden; }
body { min-width: 0; }
.og { position: relative; display: grid; grid-template-columns: 640px 1fr; align-items: center; gap: 40px; height: 630px; padding: 0 72px; background: radial-gradient(520px 420px at 900px 320px, rgb(240 180 41 / 10%), transparent 70%), var(--ground); border-bottom: 6px solid var(--amber); }
.og-brand { display: flex; align-items: center; gap: 16px; font-size: 30px; font-weight: 650; letter-spacing: -0.01em; }
.og-brand .brand-mark { width: 52px; height: 52px; }
.og h1 { margin-top: 40px; font-size: 68px; line-height: 1.04; font-weight: 650; letter-spacing: -0.035em; }
.og p { margin-top: 28px; color: var(--ink-2); font-size: 26px; }
.og .diagram { width: 470px; }
.pk-ad { opacity: 1; transform: translate(-37px, 26px); }
`);

await mkdir(path.join(root, 'src/og'), { recursive: true });
for (const code of site.locales) {
  const t = (await import(pathToFileURL(path.join(root, `src/i18n/${code}.mjs`)).href)).default;
  const page = `<!doctype html><html lang="${code}"><head><meta charset="utf-8"><link rel="stylesheet" href="styles.css"><link rel="stylesheet" href="og.css"></head>
<body><div class="og"><div><div class="og-brand">${brandMark()}<span>HomeProxy</span></div><h1>${esc(t.hero.title)}</h1><p>${esc(t.hero.eyebrow)}</p></div>
<div class="is-paused">${diagram(t.hero.diagram, t.hero.diagramLabel)}</div></div></body></html>`;
  const htmlFile = path.join(tmp, `og-${code}.html`);
  await writeFile(htmlFile, page);
  const shot = path.join(tmp, `og-${code}.png`);
  execFileSync(chrome, ['--headless=new', '--no-sandbox', '--disable-gpu', '--hide-scrollbars', '--force-device-scale-factor=1', '--force-prefers-reduced-motion', '--window-size=1200,630', '--virtual-time-budget=2000', `--screenshot=${shot}`, pathToFileURL(htmlFile).href], { stdio: 'ignore' });
  const target = path.join(root, `src/og/og-${code}.png`);
  await sharp(shot).resize(1200, 630).png({ palette: true, quality: 90, compressionLevel: 9, effort: 10 }).toFile(target);
  console.log(`og: ${path.relative(root, target)}`);
}
await rm(tmp, { recursive: true, force: true });
