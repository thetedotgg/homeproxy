// Dev-time image step (needs the `sharp` devDependency): placeholder screens,
// AVIF/WebP variants and favicons. Outputs are committed, so the Docker build
// and scripts/build.mjs stay dependency-free.
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, readdir, rm, writeFile, copyFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const root = fileURLToPath(new URL('../', import.meta.url));
const repo = path.resolve(root, '..');
const screensDir = path.join(root, 'src/screens');
const outDir = path.join(root, 'src/generated/screens');
const manifestPath = path.join(outDir, 'manifest.json');
const placeholderList = path.join(screensDir, 'placeholders.json');

export const LOCALES = ['cs', 'en'];
export const SCREENS = ['home', 'devices', 'guide', 'settings'];
export const SOURCE = { width: 2360, height: 1520 };
export const WIDTHS = [640, 1180, 1760];

const sha256 = buffer => createHash('sha256').update(buffer).digest('hex');
const readJson = async (file, fallback) => (existsSync(file) ? JSON.parse(await readFile(file, 'utf8')) : fallback);

function placeholderSvg(locale, screen) {
  const label = {
    cs: { home: 'Domov', devices: 'Zařízení', guide: 'Průvodce', settings: 'Nastavení', note: 'Dočasný náhled – čeká na skutečný snímek aplikace' },
    en: { home: 'Home', devices: 'Devices', guide: 'Guide', settings: 'Settings', note: 'Temporary placeholder – waiting for a real app screenshot' },
  }[locale];
  const { width: w, height: h } = SOURCE;
  const rows = Array.from({ length: 5 }, (_, i) => `<rect x="560" y="${520 + i * 150}" width="${1520 - i * 140}" height="96" rx="20" fill="#1b1e23"/>`).join('');
  return Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
  <rect width="${w}" height="${h}" fill="#0b0c0e"/>
  <rect width="${w}" height="120" fill="#16181c"/>
  <rect x="0" y="120" width="440" height="${h - 120}" fill="#121417"/>
  <rect x="64" y="40" width="40" height="40" rx="10" fill="#f0b429"/>
  <rect x="560" y="220" width="760" height="170" rx="24" fill="#1b1e23" stroke="#2a2d33" stroke-width="4"/>
  ${rows}
  <rect x="40" y="40" width="${w - 80}" height="${h - 80}" rx="36" fill="none" stroke="#3a3e46" stroke-width="6" stroke-dasharray="28 22"/>
  <text x="${w / 2}" y="${h / 2 - 40}" text-anchor="middle" font-family="sans-serif" font-size="120" font-weight="700" fill="#ece7dc">${label[screen]}</text>
  <text x="${w / 2}" y="${h / 2 + 70}" text-anchor="middle" font-family="sans-serif" font-size="56" fill="#8b9099">${label.note}</text>
</svg>`);
}

async function ensurePlaceholders() {
  await mkdir(screensDir, { recursive: true });
  const known = new Set(await readJson(placeholderList, []));
  let created = false;
  for (const locale of LOCALES) {
    for (const screen of SCREENS) {
      const file = path.join(screensDir, `${locale}-${screen}.png`);
      if (existsSync(file)) continue; // never overwrite a real screenshot
      const png = await sharp(placeholderSvg(locale, screen)).png({ palette: true, compressionLevel: 9 }).toBuffer();
      await writeFile(file, png);
      known.add(sha256(png));
      created = true;
      console.log(`placeholder: ${path.relative(root, file)}`);
    }
  }
  if (created) await writeFile(placeholderList, `${JSON.stringify([...known].sort(), null, 2)}\n`);
  return known;
}

async function variants(placeholders) {
  await mkdir(outDir, { recursive: true });
  const previous = await readJson(manifestPath, { items: {} });
  const items = {};
  for (const locale of LOCALES) {
    for (const screen of SCREENS) {
      const name = `${locale}-${screen}`;
      const buffer = await readFile(path.join(screensDir, `${name}.png`));
      const hash = sha256(buffer);
      const meta = await sharp(buffer).metadata();
      if (meta.width !== SOURCE.width || meta.height !== SOURCE.height) {
        throw new Error(`${name}.png must be ${SOURCE.width}x${SOURCE.height}, got ${meta.width}x${meta.height}.`);
      }
      const files = { avif: {}, webp: {} };
      for (const width of WIDTHS) {
        files.avif[width] = `${name}-${width}.avif`;
        files.webp[width] = `${name}-${width}.webp`;
      }
      const old = previous.items?.[name];
      const fresh = old?.sha256 === hash && Object.values(files).every(set => Object.values(set).every(f => existsSync(path.join(outDir, f))));
      if (!fresh) {
        for (const width of WIDTHS) {
          const resized = sharp(buffer).resize({ width, kernel: 'lanczos3' });
          // UI screenshots: keep text crisp (no chroma subsampling for WebP, high-ish AVIF quality).
          await resized.clone().webp({ quality: 82, smartSubsample: true, effort: 6 }).toFile(path.join(outDir, files.webp[width]));
          await resized.clone().avif({ quality: 58, effort: 6, chromaSubsampling: '4:4:4' }).toFile(path.join(outDir, files.avif[width]));
        }
        console.log(`variants: ${name}`);
      }
      items[name] = { sha256: hash, width: SOURCE.width, height: SOURCE.height, placeholder: placeholders.has(hash), files };
    }
  }
  const keep = new Set(Object.values(items).flatMap(item => Object.values(item.files).flatMap(Object.values)));
  for (const file of await readdir(outDir)) {
    if (file !== 'manifest.json' && !keep.has(file)) await rm(path.join(outDir, file));
  }
  await writeFile(manifestPath, `${JSON.stringify({ version: 1, widths: WIDTHS, items }, null, 2)}\n`);
}

async function icons() {
  const iconDir = path.join(root, 'src/icons');
  await mkdir(iconDir, { recursive: true });
  const svg = path.join(repo, 'assets/app-icon.svg');
  const png = path.join(repo, 'src-tauri/icons/icon.png');
  const ico = path.join(repo, 'src-tauri/icons/icon.ico');
  if (![svg, png, ico].every(existsSync)) {
    console.log('icons: repo sources not found, keeping committed copies');
    return;
  }
  await copyFile(svg, path.join(iconDir, 'favicon.svg'));
  await copyFile(ico, path.join(iconDir, 'favicon.ico'));
  await sharp(png).resize(180, 180).flatten({ background: '#0b0c0e' }).png({ compressionLevel: 9 }).toFile(path.join(iconDir, 'apple-touch-icon.png'));
  console.log('icons: favicon.svg, favicon.ico, apple-touch-icon.png');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const placeholders = await ensurePlaceholders();
  await variants(placeholders);
  await icons();
}
