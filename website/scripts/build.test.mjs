import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build, checkHtml, compareShape } from './build.mjs';
import { czechNbsp, inline } from './lib/render.mjs';
import { pickLanguage } from './preview.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const site = JSON.parse(await readFile(path.join(root, 'site.json'), 'utf8'));
const temp = await mkdtemp(path.join(os.tmpdir(), 'homeproxy-site-test-'));
after(() => rm(temp, { recursive: true, force: true }));
const quiet = () => {};

// Fixtures do not depend on what site.json currently has configured.
const placeholder = structuredClone(site);
placeholder.donate.enabled = true;
placeholder.donate.url = null;
placeholder.license = { name: null, url: null };
const ready = structuredClone(site);
ready.donate.url = 'https://example.org/donate';
ready.license = { name: 'MIT', url: 'https://github.com/thetedotgg/homeproxy/blob/main/LICENSE' };

test('preview build renders both locales from one template with SEO links', async () => {
  const out = path.join(temp, 'preview');
  const report = await build({ root, out, log: quiet, site: placeholder });
  for (const lang of ['cs', 'en']) {
    const page = await readFile(path.join(out, lang, 'index.html'), 'utf8');
    assert.match(page, new RegExp(`<html lang="${lang}">`));
    assert.match(page, new RegExp(`<link rel="canonical" href="https://homeproxy.thetasigma.io/${lang}/">`));
    assert.match(page, /hreflang="x-default" href="https:\/\/homeproxy.thetasigma.io\/en\/"/);
    assert.match(page, /og:image" content="https:\/\/homeproxy.thetasigma.io\/assets\/og-/);
    assert.match(page, /releases\/latest\/download\/HomeProxy-Setup-x64.exe/);
    assert.match(page, /releases\/latest\/download\/HomeProxy-Ubuntu-amd64.tar.gz/);
    assert.deepEqual(checkHtml(page, lang), []);
  }
  assert.ok(report.js.raw < 5 * 1024, 'JS budget');
  assert.ok(report.firstViewTransfer.cs < 150 * 1024, 'first view budget');
  assert.equal(report.warnings.length, 2, 'donate + license placeholders are reported');
  assert.match(await readFile(path.join(out, 'sitemap.xml'), 'utf8'), /hreflang="cs"/);
});

test('production build refuses placeholders', async () => {
  await assert.rejects(build({ root, out: path.join(temp, 'refused'), production: true, log: quiet, site: placeholder }), /donate\.url is null[\s\S]*license/);
});

test('production build passes once donate and license are configured', async () => {
  const out = path.join(temp, 'production');
  const report = await build({ root, out, production: true, log: quiet, site: ready });
  assert.equal(report.blockers.length, 0);
  const page = await readFile(path.join(out, 'cs', 'index.html'), 'utf8');
  assert.doesNotMatch(page, /data-placeholder/);
  assert.match(page, /href="https:\/\/example.org\/donate"/);
  assert.match(page, /licencí MIT/);
});

test('donate section can be switched off for production', async () => {
  const off = structuredClone(ready);
  off.donate.enabled = false;
  off.donate.url = null;
  const out = path.join(temp, 'no-donate');
  await build({ root, out, production: true, log: quiet, site: off });
  const page = await readFile(path.join(out, 'en', 'index.html'), 'utf8');
  assert.doesNotMatch(page, /id="support"/);
  assert.doesNotMatch(page, /href="#support"/);
});

test('extra donate buttons render only with a URL and for their locales', async () => {
  const more = structuredClone(ready);
  more.donate.more = [
    { id: 'github-sponsors', url: 'https://github.com/sponsors/thetedotgg', label: { cs: 'GitHub Sponsors', en: 'GitHub Sponsors' }, locales: ['cs', 'en'] },
    { id: 'ko-fi', url: 'https://ko-fi.com/example', label: { cs: 'Ko-fi', en: 'Ko-fi' }, locales: ['en'] },
    { id: 'unset', url: null, label: { cs: 'UnsetButtonCs', en: 'UnsetButtonEn' } },
  ];
  const out = path.join(temp, 'more');
  await build({ root, out, production: true, log: quiet, site: more });
  const cs = await readFile(path.join(out, 'cs', 'index.html'), 'utf8');
  const en = await readFile(path.join(out, 'en', 'index.html'), 'utf8');
  assert.match(cs, /github.com\/sponsors/);
  assert.doesNotMatch(cs, /ko-fi/);
  assert.match(en, /ko-fi.com\/example/);
  assert.doesNotMatch(en, /UnsetButtonEn/);
});

test('copy markup escapes HTML and only allows https or in-page links', () => {
  assert.equal(String(inline('<b>x</b> **y** `z`')), '&lt;b&gt;x&lt;/b&gt; <strong>y</strong> <code>z</code>');
  assert.equal(String(inline('[a](#faq)')), '<a href="#faq">a</a>');
  assert.throws(() => inline('[a](javascript:alert(1))'));
  assert.throws(() => inline('[a](http://example.org)'));
  assert.throws(() => inline('{nope}'));
});

test('dictionary shape check reports missing keys and mismatched ids', () => {
  assert.deepEqual(compareShape({ a: 1, b: [{ id: 'x' }] }, { a: 2, b: [{ id: 'x' }] }), []);
  assert.equal(compareShape({ a: 1 }, {}).length, 1);
  assert.equal(compareShape({ b: [{ id: 'x' }] }, { b: [{ id: 'y' }] }).length, 1);
});

test('HTML checks catch CSP and id problems', () => {
  const base = '<!doctype html>\n<html lang="en">';
  assert.equal(checkHtml(`${base}<p id="a"></p><p id="a"></p>`, 't').length, 1);
  assert.equal(checkHtml(`${base}<p style="x"></p>`, 't').length, 1);
  assert.equal(checkHtml(`${base}<script>1</script>`, 't').length, 1);
  assert.equal(checkHtml(`${base}<a href="#missing">x</a>`, 't').length, 1);
});

test('preview server language choice mirrors the nginx rules', () => {
  assert.equal(pickLanguage('', 'cs-CZ,cs;q=0.9'), 'cs');
  assert.equal(pickLanguage('', 'sk'), 'cs');
  assert.equal(pickLanguage('', 'en-US,cs;q=0.5'), 'en');
  assert.equal(pickLanguage('', 'de-DE,cs;q=0.8'), 'cs');
  assert.equal(pickLanguage('', 'de'), 'en');
  assert.equal(pickLanguage('', ''), 'en');
  assert.equal(pickLanguage('lang=en', 'cs'), 'en');
  assert.equal(pickLanguage('a=1; lang=cs', 'en'), 'cs');
  assert.equal(pickLanguage('lang=xx', 'cs'), 'cs');
});

test('license label is localized in FAQ and footer, falling back to the SPDX name', async () => {
  const labelled = structuredClone(ready);
  labelled.license = { name: 'GPL-3.0-or-later', url: 'https://github.com/thetedotgg/homeproxy/blob/main/LICENSE', label: { cs: 'GNU GPL 3.0 nebo novější', en: 'GNU GPL 3.0 or later' } };
  const out = path.join(temp, 'license');
  await build({ root, out, production: true, log: quiet, site: labelled });
  const cs = await readFile(path.join(out, 'cs', 'index.html'), 'utf8');
  const en = await readFile(path.join(out, 'en', 'index.html'), 'utf8');
  assert.match(cs, /licencí GNU GPL 3\.0 nebo novější/);
  assert.match(cs, />Licence GNU GPL 3\.0 nebo novější</);
  assert.match(en, /licensed under the GNU GPL 3\.0 or later/);
  assert.match(en, />License: GNU GPL 3\.0 or later</);
  assert.doesNotMatch(cs + en, /GPL-3\.0-or-later</);
});

test('Czech non-breaking spaces touch text only, never tags, attributes or code', () => {
  const input = '<p title="a b" class="k x">Jdi k domu a v klidu <a href="#a b">s námi</a> <code>a b</code> i</p>';
  assert.equal(czechNbsp(input), '<p title="a b" class="k x">Jdi k domu a v klidu <a href="#a b">s námi</a> <code>a b</code> i</p>');
});
