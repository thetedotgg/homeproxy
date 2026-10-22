// The single page template. Both /cs/ and /en/ are rendered from here with
// their dictionary; nothing language-specific lives in this file.
import { html, inline, safeHref } from '../scripts/lib/render.mjs';
import { brandMark, diagram, icon, sprite } from './icons.mjs';

function placeholder(text, className = '') {
  return html`<span class="placeholder ${className}" data-placeholder>${text}</span>`;
}

function head({ t, lang, site, assets, page }) {
  const other = site.locales.filter(code => code !== lang);
  const url = `${site.siteUrl}/${lang}/`;
  const og = `${site.siteUrl}${assets.og[lang]}`;
  return html`<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${t.meta.title}</title>
<meta name="description" content="${t.meta.description}">
<link rel="canonical" href="${url}">
${site.locales.map(code => html`<link rel="alternate" hreflang="${code}" href="${site.siteUrl}/${code}/">\n`)}<link rel="alternate" hreflang="x-default" href="${site.siteUrl}/${site.defaultLocale}/">
<meta name="theme-color" content="#0b0c0e">
<meta name="color-scheme" content="dark">
<link rel="preload" href="${assets.fonts.latin}" as="font" type="font/woff2" crossorigin>
${lang === 'cs' ? html`<link rel="preload" href="${assets.fonts.czech}" as="font" type="font/woff2" crossorigin>\n` : ''}<link rel="stylesheet" href="${assets.css}">
<script src="${assets.js}" defer></script>
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" href="${assets.faviconSvg}" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta property="og:type" content="website">
<meta property="og:site_name" content="HomeProxy">
<meta property="og:title" content="${t.meta.title}">
<meta property="og:description" content="${t.meta.description}">
<meta property="og:url" content="${url}">
<meta property="og:locale" content="${t.meta.locale}">
${other.map(code => html`<meta property="og:locale:alternate" content="${page.dicts[code].meta.locale}">\n`)}<meta property="og:image" content="${og}">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="${t.meta.ogAlt}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${t.meta.title}">
<meta name="twitter:description" content="${t.meta.description}">
<meta name="twitter:image" content="${og}">
<meta name="twitter:image:alt" content="${t.meta.ogAlt}">
</head>`;
}

function header({ t, lang, site }) {
  const target = site.locales.find(code => code !== lang);
  const links = ['screens', 'features', 'how', 'download', 'faq'];
  return html`<a class="skip-link" href="#main">${t.nav.skip}</a>
<header class="site-header">
  <div class="wrap header-row">
    <a class="brand" href="/${lang}/" aria-label="${t.nav.home}">${brandMark()}<span>HomeProxy</span></a>
    <nav class="site-nav" aria-label="${t.nav.label}">
      <ul>${links.map(id => html`<li><a href="#${id}">${t.nav[id]}</a></li>`)}</ul>
    </nav>
    <div class="header-tools">
      <a class="lang-switch" href="/${target}/" hreflang="${target}" lang="${target}" data-lang="${target}" title="${t.nav.switchLabel}">${t.nav.switchText}</a>
      <a class="icon-link" href="${safeHref(site.repo)}" aria-label="${t.nav.githubLabel}">${icon('github')}</a>
    </div>
  </div>
</header>`;
}

function hero({ t, site }) {
  const h = t.hero;
  return html`<section class="hero" aria-labelledby="hero-title">
  <div class="wrap hero-grid">
    <div class="hero-copy">
      <p class="hero-eyebrow">${h.eyebrow}</p>
      <h1 id="hero-title" class="hero-claim">${h.title}</h1>
      <p class="hero-lead">${h.lead}</p>
      <p class="cta-mobile">${h.mobileNote} <a href="#download">${h.mobileLink}</a></p>
      <div class="cta" role="group" aria-label="${h.ctaLabel}">
        <a class="btn btn-os btn-windows" href="${safeHref(site.downloads.windows.url)}" data-os-button="windows">${icon('windows')}<span>${h.windows}</span></a>
        <a class="btn btn-os btn-ubuntu" href="${safeHref(site.downloads.ubuntu.url)}" data-os-button="ubuntu">${icon('ubuntu')}<span>${h.ubuntu}</span></a>
      </div>
      <p class="cta-note" data-note data-note-windows="${h.noteWindows}" data-note-ubuntu="${h.noteUbuntu}" data-note-linux="${h.noteLinux}" data-note-mac="${h.noteMac}">${h.noteDefault}</p>
      <p class="hero-source"><a href="${safeHref(site.repo)}">${icon('github')}<span>${h.source}</span></a></p>
    </div>
    <div class="hero-art">${diagram(h.diagram, h.diagramLabel)}</div>
  </div>
</section>`;
}

function picture(item, shot) {
  const srcset = format => Object.entries(shot.files[format]).map(([width, url]) => `${url} ${width}w`).join(', ');
  const sizes = '(min-width: 72rem) 54rem, (min-width: 48rem) 80vw, 88vw';
  const fallback = shot.files.webp[1180];
  return html`<picture>
          <source type="image/avif" srcset="${srcset('avif')}" sizes="${sizes}">
          <img src="${fallback}" srcset="${srcset('webp')}" sizes="${sizes}" width="${shot.width / 2}" height="${shot.height / 2}" alt="${item.alt}" loading="lazy" decoding="async">
        </picture>`;
}

function screens({ t, lang, assets }) {
  const s = t.screens;
  return html`<section class="section screens" id="screens" aria-labelledby="screens-title">
  <div class="wrap">
    <div class="section-head">
      <h2 id="screens-title">${s.title}</h2>
      <p>${s.lead}</p>
    </div>
  </div>
  <div class="gallery" data-gallery>
    <div class="wrap gallery-bar">
      <nav class="gallery-tabs" aria-label="${s.tabsLabel}">
        <ul>${s.items.map((item, index) => html`<li><a href="#screen-${item.id}" data-tab="${index}">${item.title}</a></li>`)}</ul>
      </nav>
      <div class="gallery-controls" data-controls hidden>
        <button type="button" class="icon-button" data-prev aria-label="${s.previous}">${icon('prev')}</button>
        <button type="button" class="icon-button" data-next aria-label="${s.next}">${icon('next')}</button>
      </div>
    </div>
    <ul class="gallery-track" data-track tabindex="0" aria-label="${s.listLabel}">
      ${s.items.map(item => html`<li class="shot" id="screen-${item.id}">
        <figure>
          <a class="shot-frame" href="${assets.screens[`${lang}-${item.id}`].files.webp[1760]}">
        ${picture(item, assets.screens[`${lang}-${item.id}`])}
          </a>
          <figcaption><strong>${item.title}</strong> ${item.text}</figcaption>
        </figure>
      </li>`)}
    </ul>
  </div>
</section>`;
}

function features({ t }) {
  const f = t.features;
  return html`<section class="section features" id="features" aria-labelledby="features-title">
  <div class="wrap">
    <div class="section-head">
      <h2 id="features-title">${f.title}</h2>
      <p>${f.lead}</p>
    </div>
    <div class="feature-groups">
      ${f.groups.map((group, g) => html`<section class="feature-group" aria-labelledby="feature-group-${g + 1}">
        <h3 class="group-title" id="feature-group-${g + 1}">${group.title}</h3>
        <ul class="feature-list">
          ${group.items.map(item => html`<li class="feature tone-${item.tone}">
            <span class="feature-icon">${icon(item.icon)}</span>
            <div>
              <h4>${item.title}</h4>
              <p>${item.text}</p>
              ${item.presets ? html`<ul class="presets" aria-label="${f.presetsLabel}">${item.presets.map(p => html`<li>${p}</li>`)}</ul>` : ''}
            </div>
          </li>`)}
        </ul>
      </section>`)}
    </div>
  </div>
</section>`;
}

function how({ t }) {
  const h = t.how;
  return html`<section class="section how" id="how" aria-labelledby="how-title">
  <div class="wrap">
    <div class="section-head">
      <h2 id="how-title">${h.title}</h2>
      <p>${h.lead}</p>
    </div>
    <ol class="steps" role="list">
      ${h.steps.map(step => html`<li class="step">
        <span class="step-icon">${icon(step.icon)}</span>
        <h3>${step.title}</h3>
        <p>${step.text}</p>
      </li>`)}
    </ol>
  </div>
</section>`;
}

function downloadCard(os, copy, download, t) {
  return html`<article class="dl-card" data-os-card="${os}" aria-labelledby="dl-${os}">
        <div class="dl-head">
          <span class="dl-logo">${icon(os)}</span>
          <div>
            <h3 id="dl-${os}">${copy.title}</h3>
            <p class="dl-req">${copy.req}</p>
          </div>
          <p class="dl-rec">${t.download.recommended}</p>
        </div>
        <a class="btn btn-os btn-${os} btn-block" href="${safeHref(download.url)}" data-os-button="${os}">${icon('download')}<span>${copy.button}</span></a>
        <p class="dl-file">${download.file}</p>
        <ol class="dl-steps" aria-label="${t.download.stepsLabel}">
          ${copy.steps.map(step => html`<li>${inline(step)}</li>`)}
        </ol>
      </article>`;
}

function download({ t, site }) {
  const d = t.download;
  return html`<section class="section download" id="download" aria-labelledby="download-title">
  <div class="wrap">
    <div class="section-head">
      <h2 id="download-title">${d.title}</h2>
      <p>${d.lead}</p>
    </div>
    <div class="dl-grid">
      ${downloadCard('windows', d.windows, site.downloads.windows, t)}
      ${downloadCard('ubuntu', d.ubuntu, site.downloads.ubuntu, t)}
    </div>
    <div class="dl-more">
      <details class="verify" id="verify">
        <summary>${d.verifyTitle}${icon('chevron', 'icon chevron')}</summary>
        <div class="verify-body">
          <p>${d.verifyText}</p>
          <dl>
            <dt>${d.verifyWindows}</dt>
            <dd><code>Get-FileHash .\\${site.downloads.windows.file}</code></dd>
            <dt>${d.verifyUbuntu}</dt>
            <dd><code>sha256sum ${site.downloads.ubuntu.file}</code></dd>
          </dl>
        </div>
      </details>
      <p class="all-files"><a href="${safeHref(site.releases)}">${d.allFiles}</a></p>
    </div>
  </div>
</section>`;
}

const licenseLabel = (site, lang) => site.license.label?.[lang] ?? site.license.name;

function faq({ t, lang, site, state }) {
  const vars = { repo: site.repo, license: site.license.name ? licenseLabel(site, lang) : '{license}' };
  const answer = item => {
    if (item.id === 'open-source' && !site.license.name) {
      const [before, after] = item.a.split('{license}');
      return html`${inline(before, vars)}${placeholder(t.footer.licensePlaceholder)}${inline(after, vars)}`;
    }
    const donate = item.donate && state.donateVisible ? html` ${inline(item.donate)}` : '';
    return html`${inline(item.a, vars)}${donate}`;
  };
  return html`<section class="section faq" id="faq" aria-labelledby="faq-title">
  <div class="wrap faq-grid">
    <div class="section-head">
      <h2 id="faq-title">${t.faq.title}</h2>
    </div>
    <div class="faq-list">
      ${t.faq.items.map(item => html`<details class="faq-item" id="faq-${item.id}">
        <summary>${item.q}${icon('chevron', 'icon chevron')}</summary>
        <p>${answer(item)}</p>
      </details>`)}
    </div>
  </div>
</section>`;
}

function support({ t, lang, site, assets }) {
  const donate = site.donate;
  if (!donate.enabled) return '';
  const s = t.support;
  const buttons = [];
  if (donate.url) buttons.push(html`<a class="btn btn-primary" href="${safeHref(donate.url)}">${donate.label[lang]}</a>`);
  for (const extra of donate.more ?? []) {
    if (extra.url && (extra.locales ?? site.locales).includes(lang)) buttons.push(html`<a class="btn" href="${safeHref(extra.url)}">${extra.label[lang]}</a>`);
  }
  const qr = donate.czechQr?.enabled && lang === 'cs' && assets.donateQr
    ? html`<figure class="donate-qr">
        <img src="${assets.donateQr.url}" width="${assets.donateQr.width}" height="${assets.donateQr.height}" alt="${s.qrAlt.replace('{account}', donate.czechQr.account)}" loading="lazy" decoding="async">
        <figcaption><strong>${s.qrTitle}</strong> ${s.qrText}<br>${s.account}: <span class="nowrap">${donate.czechQr.account}</span></figcaption>
      </figure>`
    : '';
  return html`<section class="section support" id="support" aria-labelledby="support-title">
  <div class="wrap">
    <div class="support-panel">
      <div>
        <h2 id="support-title">${s.title}</h2>
        <p>${s.text}</p>
      </div>
      <div class="support-actions">
        ${buttons.length ? html`<div class="support-buttons">${buttons}</div>` : placeholder(s.placeholder, 'placeholder-block')}
        ${qr}
      </div>
    </div>
  </div>
</section>`;
}

function footer({ t, lang, site }) {
  const f = t.footer;
  const license = site.license.name
    ? html`<li><a href="${safeHref(site.license.url)}">${f.license.replace('{license}', licenseLabel(site, lang))}</a></li>`
    : html`<li>${placeholder(f.licensePlaceholder)}</li>`;
  return html`<footer class="site-footer">
  <div class="wrap footer-grid">
    <div class="footer-brand">
      <a class="brand" href="/${lang}/" aria-label="${t.nav.home}">${brandMark()}<span>HomeProxy</span></a>
      <p>${f.tagline}</p>
    </div>
    <ul class="footer-links">
      <li><a href="${safeHref(site.repo)}">${f.source}</a></li>
      <li><a href="${safeHref(site.releases)}">${f.releases}</a></li>
      <li><a href="${safeHref(site.issues)}">${f.issues}</a></li>
      ${license}
    </ul>
    <p class="footer-author">${f.author} <a href="${safeHref(site.author.url)}">${site.author.name}</a></p>
    <p class="footer-privacy">${f.privacy}</p>
  </div>
</footer>`;
}

export function renderPage(ctx) {
  const { lang } = ctx;
  const body = [hero(ctx), screens(ctx), features(ctx), how(ctx), download(ctx), faq(ctx), support(ctx)];
  return `<!doctype html>
<html lang="${lang}">
${head(ctx)}
<body>
${sprite()}
${header(ctx)}
<main id="main" tabindex="-1">
${body.join('\n')}
</main>
${footer(ctx)}
</body>
</html>
`;
}

export function renderNotFound({ dicts, site, assets }) {
  const blocks = site.locales.map(code => {
    const n = dicts[code].notFound;
    return html`<section lang="${code}" class="nf-block"><h${code === site.defaultLocale ? '1' : '2'} class="nf-title">${n.title}</h${code === site.defaultLocale ? '1' : '2'}><p>${n.text}</p><p><a class="btn" href="/${code}/">${n.home}</a></p></section>`;
  });
  return `<!doctype html>
<html lang="${site.defaultLocale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>404 · HomeProxy</title>
<meta name="robots" content="noindex">
<meta name="theme-color" content="#0b0c0e">
<link rel="stylesheet" href="${assets.css}">
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" href="${assets.faviconSvg}" type="image/svg+xml">
</head>
<body>
<main id="main" class="wrap not-found">
${brandMark('brand-mark nf-mark')}
${blocks.join('\n')}
</main>
</body>
</html>
`;
}
