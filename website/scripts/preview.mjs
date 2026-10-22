// Local preview of dist/ without Docker. Mirrors the nginx essentials: the "/"
// language redirect, CSP and security headers (parsed from nginx config).
// It is a dev aid, not a replacement for testing the Docker image.
import { createServer } from 'node:http';
import { existsSync } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = path.join(root, 'dist');
const port = Number(process.env.PORT || 4338);
const headerConf = await readFile(path.join(root, 'nginx/security-headers.conf'), 'utf8');
const fixed = [...headerConf.matchAll(/^add_header ([\w-]+) "([^"]+)" always;$/gm)].map(([, name, value]) => [name, value]);
const types = { html: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8', js: 'application/javascript; charset=utf-8', woff2: 'font/woff2', avif: 'image/avif', webp: 'image/webp', png: 'image/png', svg: 'image/svg+xml', ico: 'image/x-icon', xml: 'application/xml', txt: 'text/plain; charset=utf-8', json: 'application/json' };

export function pickLanguage(cookie = '', acceptLanguage = '') {
  const chosen = /(?:^|;\s*)lang=(cs|en)(?:;|$)/.exec(cookie);
  if (chosen) return chosen[1];
  const tag = /^(?:[^,]*,)*?\s*(cs|sk|en)(?:[-_;,\s]|$)/i.exec(acceptLanguage);
  return tag && /^(cs|sk)$/i.test(tag[1]) ? 'cs' : 'en';
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (!existsSync(dist)) throw new Error('Run npm run build first.');
  createServer(async (req, res) => {
    for (const [name, value] of fixed) res.setHeader(name, value);
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/') {
      res.writeHead(302, { Location: `/${pickLanguage(req.headers.cookie, req.headers['accept-language'])}/`, Vary: 'Accept-Language, Cookie', 'Cache-Control': 'no-store' });
      return res.end();
    }
    let file = path.join(dist, path.normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, ''));
    if (!file.startsWith(dist)) file = path.join(dist, '404.html');
    if (existsSync(file) && (await stat(file)).isDirectory()) file = path.join(file, 'index.html');
    const found = existsSync(file) && !file.endsWith('.gz');
    const target = found ? file : path.join(dist, '404.html');
    res.writeHead(found ? 200 : 404, { 'Content-Type': types[path.extname(target).slice(1)] || 'application/octet-stream', 'Cache-Control': found && url.pathname.startsWith('/assets/') ? 'public, max-age=31536000, immutable' : 'no-cache' });
    res.end(await readFile(target));
  }).listen(port, '127.0.0.1', () => console.log(`Preview on http://127.0.0.1:${port}/`));
}
