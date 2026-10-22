// Static build for homeproxy.thetasigma.io. Node 22+, no npm dependencies.
//   node scripts/build.mjs               preview build (placeholders allowed, with warnings)
//   node scripts/build.mjs --production  fails while any placeholder would ship
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync, constants } from 'node:zlib';
import { czechNbsp, safeHref } from './lib/render.mjs';

const JS_BUDGET = 5 * 1024;
const COMMIT_RE = /^(?:[a-f0-9]{40}|unreleased)$/;

const hash = buffer => createHash('sha256').update(buffer).digest('hex');

/** Same keys, array lengths and value types in every locale. */
export function compareShape(a, b, at = 'dict') {
  const problems = [];
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return [`${at}: array vs non-array`];
    if (a.length !== b.length) problems.push(`${at}: ${a.length} vs ${b.length} items`);
    for (let i = 0; i < Math.min(a.length, b.length); i++) problems.push(...compareShape(a[i], b[i], `${at}[${i}]`));
    return problems;
  }
  if (a && typeof a === 'object') {
    if (!b || typeof b !== 'object') return [`${at}: object vs ${typeof b}`];
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const key of keys) {
      if (!(key in a) || !(key in b)) problems.push(`${at}.${key}: missing in one locale`);
      else problems.push(...compareShape(a[key], b[key], `${at}.${key}`));
    }
    return problems;
  }
  if (typeof a !== typeof b) problems.push(`${at}: ${typeof a} vs ${typeof b}`);
  // Language-independent identifiers must match exactly.
  if (/\.(id|icon|tone)$/.test(at) && a !== b) problems.push(`${at}: "${a}" vs "${b}"`);
  return problems;
}

/** Structural checks on rendered HTML; returns a list of problems. */
export function checkHtml(page, name) {
  const problems = [];
  const ids = [...page.matchAll(/\sid="([^"]+)"/g)].map(m => m[1]);
  const seen = new Set();
  for (const id of ids) {
    if (seen.has(id)) problems.push(`${name}: duplicate id "${id}"`);
    seen.add(id);
  }
  for (const [, target] of page.matchAll(/href="#([^"]*)"/g)) {
    if (!seen.has(target)) problems.push(`${name}: link to missing #${target}`);
  }
  for (const [, ref] of page.matchAll(/aria-labelledby="([^"]+)"/g)) {
    for (const id of ref.split(/\s+/)) if (!seen.has(id)) problems.push(`${name}: aria-labelledby missing #${id}`);
  }
  if (/\{\{|\}\}/.test(page)) problems.push(`${name}: unresolved template braces`);
  if (/\{(?:license|repo|account)\}/.test(page)) problems.push(`${name}: unresolved copy variable`);
  if (/\sstyle=/i.test(page) || /<style[\s>]/i.test(page)) problems.push(`${name}: inline style (blocked by CSP)`);
  for (const [tag] of page.matchAll(/<script\b[^>]*>/gi)) if (!/\ssrc="/.test(tag)) problems.push(`${name}: inline script (blocked by CSP)`);
  for (const [tag] of page.matchAll(/<img\b[^>]*>/gi)) {
    if (!/\salt="/.test(tag)) problems.push(`${name}: img without alt`);
    if (!/\swidth="\d+"/.test(tag) || !/\sheight="\d+"/.test(tag)) problems.push(`${name}: img without width/height`);
  }
  if (!/^<!doctype html>\n<html lang="[a-z]{2}">/.test(page)) problems.push(`${name}: missing doctype/lang`);
  return problems;
}

async function loadDicts(root, locales) {
  const dicts = {};
  for (const code of locales) {
    const url = pathToFileURL(path.join(root, `src/i18n/${code}.mjs`));
    dicts[code] = (await import(`${url.href}?v=${Date.now()}`)).default;
  }
  return dicts;
}

function validateSite(site) {
  for (const key of ['siteUrl', 'repo', 'releases', 'issues']) safeHref(site[key]);
  safeHref(site.downloads.windows.url);
  safeHref(site.downloads.ubuntu.url);
  safeHref(site.author.url);
  if (new URL(site.siteUrl).pathname !== '/' || site.siteUrl.endsWith('/')) throw new Error('siteUrl must be an origin without a trailing slash.');
  if (!site.locales.includes(site.defaultLocale)) throw new Error('defaultLocale must be one of locales.');
  if (site.license.url) safeHref(site.license.url);
  if (site.donate.url) safeHref(site.donate.url);
  for (const extra of site.donate.more ?? []) if (extra.url) safeHref(extra.url);
}

export async function build({ root, out, production = false, commit = 'unreleased', log = console.log, site: siteOverride }) {
  if (!COMMIT_RE.test(commit)) throw new Error('SOURCE_COMMIT must be a full Git SHA or "unreleased".');
  const site = siteOverride ?? JSON.parse(await readFile(path.join(root, 'site.json'), 'utf8'));
  validateSite(site);
  const dicts = await loadDicts(root, site.locales);
  const [first, ...rest] = site.locales;
  const shape = rest.flatMap(code => compareShape(dicts[first], dicts[code], `${first}↔${code}`));
  if (shape.length) throw new Error(`Dictionaries differ:\n  ${shape.join('\n  ')}`);

  const warnings = [];
  const blockers = [];
  const placeholderIssue = message => (production ? blockers : warnings).push(message);

  if (site.donate.enabled && !site.donate.url) placeholderIssue('donate.url is null: the support section shows a placeholder box. Set the URL or "enabled": false.');
  const unusedExtras = (site.donate.more ?? []).filter(extra => !extra.url).map(extra => extra.id);
  if (site.donate.enabled && unusedExtras.length) log(`info: optional donate buttons without URL are hidden: ${unusedExtras.join(', ')}`);
  if (!site.license.name || !site.license.url) placeholderIssue('license.name/url is null: the page says "open source" but shows a license placeholder. Set the project license.');

  // Screens: committed variants must match the current source PNGs.
  const manifest = JSON.parse(await readFile(path.join(root, 'src/generated/screens/manifest.json'), 'utf8'));
  for (const code of site.locales) {
    for (const item of dicts[code].screens.items) {
      const name = `${code}-${item.id}`;
      const entry = manifest.items[name];
      if (!entry) throw new Error(`Missing screen variants for ${name}. Run: npm run images`);
      const source = path.join(root, `src/screens/${name}.png`);
      if (existsSync(source) && hash(await readFile(source)) !== entry.sha256) throw new Error(`${name}.png changed since its variants were generated. Run: npm run images`);
      if (entry.placeholder) placeholderIssue(`${name}: screenshot is still a placeholder.`);
    }
  }

  await rm(out, { recursive: true, force: true });
  await mkdir(path.join(out, 'assets'), { recursive: true });
  const put = async (base, ext, buffer) => {
    const url = `/assets/${base}.${hash(buffer).slice(0, 12)}.${ext}`;
    await writeFile(path.join(out, url), buffer);
    return url;
  };

  const assets = { fonts: {}, og: {}, screens: {} };
  assets.fonts.latin = await put('inter-latin', 'woff2', await readFile(path.join(root, 'src/fonts/inter-latin.woff2')));
  assets.fonts.czech = await put('inter-czech', 'woff2', await readFile(path.join(root, 'src/fonts/inter-czech.woff2')));
  await writeFile(path.join(out, 'assets/inter-OFL.txt'), await readFile(path.join(root, 'src/fonts/OFL.txt')));
  const css = (await readFile(path.join(root, 'src/styles.css'), 'utf8')).replaceAll('{{FONT_LATIN}}', assets.fonts.latin).replaceAll('{{FONT_CZECH}}', assets.fonts.czech);
  if (/\{\{/.test(css)) throw new Error('Unresolved CSS placeholder.');
  assets.css = await put('styles', 'css', Buffer.from(css));
  const js = await readFile(path.join(root, 'src/site.js'));
  if (js.length > JS_BUDGET) throw new Error(`site.js is ${js.length} B, budget is ${JS_BUDGET} B.`);
  assets.js = await put('site', 'js', js);
  assets.faviconSvg = await put('favicon', 'svg', await readFile(path.join(root, 'src/icons/favicon.svg')));
  for (const code of site.locales) {
    const og = path.join(root, `src/og/og-${code}.png`);
    if (!existsSync(og)) throw new Error(`Missing ${path.relative(root, og)}. Run: npm run og`);
    assets.og[code] = await put(`og-${code}`, 'png', await readFile(og));
  }
  const screenDir = path.join(root, 'src/generated/screens');
  for (const [name, entry] of Object.entries(manifest.items)) {
    const files = { avif: {}, webp: {} };
    for (const format of ['avif', 'webp']) {
      for (const [width, file] of Object.entries(entry.files[format])) {
        files[format][width] = await put(file.replace(/\.(avif|webp)$/, ''), format, await readFile(path.join(screenDir, file)));
      }
    }
    assets.screens[name] = { ...entry, files };
  }
  const qr = site.donate.czechQr;
  if (site.donate.enabled && qr?.enabled) {
    const file = path.join(root, qr.image);
    if (!existsSync(file) || !qr.account) throw new Error('donate.czechQr is enabled but the image or account is missing.');
    const buffer = await readFile(file);
    const ext = path.extname(file).slice(1).toLowerCase();
    if (!['png', 'svg', 'webp'].includes(ext)) throw new Error('donate.czechQr.image must be PNG, SVG or WebP.');
    const size = ext === 'png' ? { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) } : { width: 240, height: 240 };
    assets.donateQr = { url: await put('qr-platba', ext, buffer), ...size };
  }

  const { renderPage, renderNotFound } = await import(`${pathToFileURL(path.join(root, 'src/page.mjs')).href}?v=${Date.now()}`);
  const state = { donateVisible: Boolean(site.donate.enabled) };
  const problems = [];
  const pages = {};
  for (const lang of site.locales) {
    const rendered = renderPage({ t: dicts[lang], lang, site, assets, state, page: { dicts } });
    const page = lang === 'cs' ? czechNbsp(rendered) : rendered;
    problems.push(...checkHtml(page, `/${lang}/`));
    await mkdir(path.join(out, lang), { recursive: true });
    await writeFile(path.join(out, lang, 'index.html'), page);
    pages[lang] = page;
  }
  const notFound = renderNotFound({ dicts, site, assets });
  problems.push(...checkHtml(notFound, '/404.html'));
  await writeFile(path.join(out, '404.html'), notFound);
  if (problems.length) throw new Error(`HTML checks failed:\n  ${problems.join('\n  ')}`);

  const alternates = site.locales.map(code => `    <xhtml:link rel="alternate" hreflang="${code}" href="${site.siteUrl}/${code}/"/>`).join('\n');
  const urls = site.locales.map(code => `  <url>\n    <loc>${site.siteUrl}/${code}/</loc>\n${alternates}\n    <xhtml:link rel="alternate" hreflang="x-default" href="${site.siteUrl}/${site.defaultLocale}/"/>\n  </url>`).join('\n');
  await writeFile(path.join(out, 'sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n${urls}\n</urlset>\n`);
  await writeFile(path.join(out, 'robots.txt'), `User-agent: *\nAllow: /\n\nSitemap: ${site.siteUrl}/sitemap.xml\n`);
  await writeFile(path.join(out, 'version.json'), `${JSON.stringify({ commit, mode: production ? 'production' : 'preview' })}\n`);
  await writeFile(path.join(out, 'favicon.ico'), await readFile(path.join(root, 'src/icons/favicon.ico')));
  await writeFile(path.join(out, 'apple-touch-icon.png'), await readFile(path.join(root, 'src/icons/apple-touch-icon.png')));

  // Precompressed copies for nginx gzip_static.
  const sizes = {};
  const walk = async dir => (await readdir(dir, { withFileTypes: true })).flatMap(entry => (entry.isDirectory() ? [] : [path.join(dir, entry.name)]));
  const files = [...(await walk(out)), ...(await walk(path.join(out, 'assets'))), ...(await Promise.all(site.locales.map(code => walk(path.join(out, code))))).flat()];
  for (const file of files) {
    const body = await readFile(file);
    const rel = `/${path.relative(out, file).split(path.sep).join('/')}`;
    let gz = body.length;
    if (/\.(html|css|js|svg|xml|txt|json|ico)$/.test(file) && body.length > 512) {
      const compressed = gzipSync(body, { level: constants.Z_BEST_COMPRESSION });
      if (compressed.length < body.length) {
        await writeFile(`${file}.gz`, compressed);
        gz = compressed.length;
      }
    }
    sizes[rel] = { raw: body.length, gz };
  }

  const firstView = lang => {
    const fonts = lang === 'cs' ? [assets.fonts.latin, assets.fonts.czech] : [assets.fonts.latin];
    return [`/${lang}/index.html`, assets.css, assets.js, ...fonts].reduce((sum, file) => sum + sizes[file].gz, 0);
  };
  const report = {
    mode: production ? 'production' : 'preview',
    html: Object.fromEntries(site.locales.map(code => [code, sizes[`/${code}/index.html`]])),
    css: sizes[assets.css],
    js: sizes[assets.js],
    fonts: { latin: sizes[assets.fonts.latin].raw, czech: sizes[assets.fonts.czech].raw },
    firstViewTransfer: Object.fromEntries(site.locales.map(code => [code, firstView(code)])),
    placeholders: Object.fromEntries(site.locales.map(code => [code, (pages[code].match(/data-placeholder/g) || []).length])),
    warnings,
    blockers,
  };
  if (blockers.length) {
    const error = new Error(`Production build refused:\n  - ${blockers.join('\n  - ')}`);
    error.report = report;
    throw error;
  }
  return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const args = process.argv.slice(2);
  const production = args.includes('--production');
  const outArg = args.find(arg => arg.startsWith('--out='));
  const out = outArg ? path.resolve(outArg.slice(6)) : path.join(root, 'dist');
  try {
    const report = await build({ root, out, production, commit: process.env.SOURCE_COMMIT || 'unreleased' });
    for (const warning of report.warnings) console.warn(`warning: ${warning}`);
    const kb = n => `${(n / 1024).toFixed(1)} kB`;
    console.log(`Built ${report.mode} site in ${path.relative(process.cwd(), out) || out}`);
    for (const [code, size] of Object.entries(report.html)) console.log(`  /${code}/  html ${kb(size.raw)} (${kb(size.gz)} gz) · first view ${kb(report.firstViewTransfer[code])} gz · placeholders ${report.placeholders[code]}`);
    console.log(`  css ${kb(report.css.raw)} (${kb(report.css.gz)} gz) · js ${kb(report.js.raw)} (${kb(report.js.gz)} gz) · fonts ${kb(report.fonts.latin)} + ${kb(report.fonts.czech)}`);
    if (report.warnings.length) console.warn(`${report.warnings.length} warning(s): this build is not production-ready.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

