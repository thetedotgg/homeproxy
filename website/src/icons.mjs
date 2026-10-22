// Inline SVG: icon sprite, brand mark and the hero diagram. Presentation
// attributes only (no style attributes), so the strict CSP stays intact.
import { html, raw } from '../scripts/lib/render.mjs';

const ICONS = {
  ads: '<rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M7.5 15.5 9.8 9h.4l2.3 6.5M8.3 13.5h3.4M14.5 9v6.5h1.2a2.6 2.6 0 0 0 0-5.2h-1.2"/><path d="m3.5 3.5 17 17"/>',
  cache: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v6c0 1.66 3.13 3 7 3s7-1.34 7-3V6"/><path d="M5 12v6c0 1.66 3.13 3 7 3s7-1.34 7-3v-6"/>',
  image: '<rect x="3" y="4" width="18" height="16" rx="2.5"/><circle cx="9" cy="9.5" r="1.75"/><path d="m4 18 5.5-5.5 3.5 3.5 2.5-2.5L20 18"/>',
  saved: '<path d="M4.5 17a7.5 7.5 0 1 1 15 0"/><path d="m12 17 3.5-4.5"/><path d="M3 20h18"/>',
  traffic: '<path d="M3 20h18"/><path d="M6.5 16v-4M11 16V6M15.5 16v-6M20 16V9"/>',
  devices: '<rect x="2.5" y="5" width="13" height="9.5" rx="1.5"/><path d="M1.5 18h15"/><rect x="18" y="8" width="4.5" height="11" rx="1.2"/>',
  key: '<circle cx="8" cy="15" r="4.5"/><path d="m11.2 11.8 8.3-8.3M16.5 6.5l2.5 2.5M14 9l2 2"/>',
  lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/><path d="M12 14.5v2"/>',
  power: '<path d="M12 3v8"/><path d="M6.3 6.8a8 8 0 1 0 11.4 0"/>',
  heal: '<path d="M20 12a8 8 0 1 1-2.6-5.9"/><path d="M20.5 4v4.5H16"/><path d="m8.5 12.3 2.4 2.4 4.6-4.8"/>',
  qr: '<rect x="3" y="3" width="7" height="7" rx="1.2"/><rect x="14" y="3" width="7" height="7" rx="1.2"/><rect x="3" y="14" width="7" height="7" rx="1.2"/><path d="M14 14h3v3h-3zM20.5 14v.01M14 20.5h.01M17.5 20.5h3v-3"/>',
  offline: '<path d="M12 3v11"/><path d="m7.5 9.5 4.5 4.5 4.5-4.5"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/>',
  computer: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  download: '<path d="M12 4v11"/><path d="m7 10.5 5 5 5-5"/><path d="M5 20h14"/>',
  chevron: '<path d="m6 9 6 6 6-6"/>',
  prev: '<path d="m14.5 6-6 6 6 6"/>',
  next: '<path d="m9.5 6 6 6-6 6"/>',
  windows: '<path fill="currentColor" stroke="none" d="M3 5.6 10.4 4.6v7H3zM11.6 4.4 21 3v8.6h-9.4zM3 12.8h7.4v7L3 18.8zM11.6 12.8H21V21l-9.4-1.3z"/>',
  ubuntu: '<circle cx="12" cy="12" r="6" stroke-width="2.2"/><g fill="currentColor" stroke="#0b0c0e" stroke-width="2"><circle cx="19.5" cy="12" r="3"/><circle cx="8.25" cy="18.5" r="3"/><circle cx="8.25" cy="5.5" r="3"/></g>',
  github: '<path fill="currentColor" stroke="none" d="M12 2.5a9.7 9.7 0 0 0-3.07 18.9c.49.09.66-.21.66-.47v-1.66c-2.7.59-3.27-1.3-3.27-1.3-.44-1.12-1.08-1.42-1.08-1.42-.88-.6.07-.59.07-.59.97.07 1.49 1 1.49 1 .87 1.48 2.27 1.05 2.83.8.09-.63.34-1.05.62-1.3-2.15-.24-4.42-1.08-4.42-4.8 0-1.06.38-1.93 1-2.6-.1-.25-.44-1.24.09-2.58 0 0 .82-.26 2.67 1a9.2 9.2 0 0 1 4.86 0c1.85-1.26 2.67-1 2.67-1 .53 1.34.2 2.33.1 2.58.62.67 1 1.54 1 2.6 0 3.73-2.28 4.55-4.44 4.79.35.3.66.89.66 1.8v2.67c0 .26.18.57.67.47A9.7 9.7 0 0 0 12 2.5Z"/>',
};

export function sprite() {
  const symbols = Object.entries(ICONS).map(([id, body]) => `<symbol id="i-${id}" viewBox="0 0 24 24">${body}</symbol>`).join('');
  return raw(`<svg class="sprite" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><defs>${symbols}</defs></svg>`);
}

export function icon(id, className = 'icon') {
  if (!ICONS[id]) throw new Error(`Unknown icon ${id}`);
  return raw(`<svg class="${className}" aria-hidden="true" focusable="false" width="24" height="24"><use href="#i-${id}"/></svg>`);
}

/** The app icon (assets/app-icon.svg) drawn inline for the header and footer. */
export function brandMark(className = 'brand-mark') {
  return raw(`<svg class="${className}" aria-hidden="true" focusable="false" viewBox="0 0 512 512" width="28" height="28"><rect width="512" height="512" rx="112" fill="#16181c"/><path d="M102 249 256 126l154 123v153a30 30 0 0 1-30 30H132a30 30 0 0 1-30-30Z" fill="#1b1e23" stroke="#f0b429" stroke-width="28" stroke-linejoin="round"/><path d="M172 293c48-43 120-43 168 0M208 337c27-23 69-23 96 0" fill="none" stroke="#7dd3fc" stroke-width="26" stroke-linecap="round"/><circle cx="256" cy="380" r="17" fill="#f0b429"/></svg>`);
}

/**
 * Household diagram: three devices reach the internet through the computer
 * running HomeProxy; an ad is stopped at the house. viewBox 420 x 340.
 */
export function diagram(d, label) {
  const device = (cy, glyph, text) => html`
    <g class="dg-device">
      <rect x="10" y="${cy - 28}" width="84" height="56" rx="12" class="dg-box"/>
      ${raw(glyph)}
      <text x="52" y="${cy + 48}" text-anchor="middle" class="dg-label">${text}</text>
    </g>`;
  const tv = `<g class="dg-glyph"><rect x="33" y="50" width="38" height="24" rx="3"/><path d="M45 80h14M52 74v6"/></g>`;
  const laptop = `<g class="dg-glyph"><rect x="35" y="156" width="34" height="21" rx="2.5"/><path d="M28 182h48"/></g>`;
  const phone = `<g class="dg-glyph"><rect x="43" y="259" width="18" height="33" rx="4"/><path d="M49.5 286h5"/></g>`;
  return html`<svg class="diagram" data-animate viewBox="0 0 420 340" width="420" height="340" role="img" aria-labelledby="diagram-title">
    <title id="diagram-title">${label}</title>
    <g class="dg-lines">
      <path d="M94 64 150 178M94 170l56 26M94 276l56-62"/>
      <path d="m266 147 84-59"/>
    </g>
    ${device(64, tv, d.tv)}
    ${device(170, laptop, d.laptop)}
    ${device(276, phone, d.phone)}
    <g transform="translate(107.2 53) scale(.42)">
      <path d="M102 249 256 126l154 123v153a30 30 0 0 1-30 30H132a30 30 0 0 1-30-30Z" fill="#1b1e23" stroke="#f0b429" stroke-width="10" stroke-linejoin="round"/>
      <path d="M172 293c48-43 120-43 168 0M208 337c27-23 69-23 96 0" fill="none" stroke="#7dd3fc" stroke-width="18" stroke-linecap="round"/>
      <circle class="dg-pulse" cx="256" cy="380" r="17" fill="#f0b429"/>
    </g>
    <text x="214.7" y="262" text-anchor="middle" class="dg-hub">HomeProxy</text>
    <text x="214.7" y="280" text-anchor="middle" class="dg-label">${d.hub}</text>
    <g class="dg-globe">
      <circle cx="372" cy="70" r="24"/>
      <ellipse cx="372" cy="70" rx="10" ry="24"/>
      <path d="M348 70h48M352 58h40M352 82h40"/>
    </g>
    <text x="372" y="116" text-anchor="middle" class="dg-label">${d.internet}</text>
    <circle class="dg-ring" cx="276" cy="140" r="9"/>
    <text x="292" y="166" class="dg-blocked">${d.blocked}</text>
    <g class="dg-packets">
      <circle class="pk pk-tv" cx="94" cy="64" r="4"/>
      <circle class="pk pk-laptop" cx="94" cy="170" r="4"/>
      <circle class="pk pk-phone" cx="94" cy="276" r="4"/>
      <circle class="pk pk-out" cx="266" cy="147" r="4"/>
      <circle class="pk pk-ad" cx="350" cy="88" r="4.5"/>
    </g>
  </svg>`;
}
