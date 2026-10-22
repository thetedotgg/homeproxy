// Tiny, dependency-free HTML templating with escaping by default.
export class Raw {
  constructor(value) {
    this.value = String(value);
  }
  toString() {
    return this.value;
  }
}

export const raw = value => new Raw(value);

const ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = value => String(value).replace(/[&<>"']/g, char => ENTITIES[char]);

function flatten(value) {
  if (value === null || value === undefined || value === false) return '';
  if (Array.isArray(value)) return value.map(flatten).join('');
  if (value instanceof Raw) return value.value;
  return esc(value);
}

/** Tagged template: interpolations are escaped unless wrapped in raw()/html``. */
export function html(strings, ...values) {
  let out = strings[0];
  values.forEach((value, index) => {
    out += flatten(value) + strings[index + 1];
  });
  return raw(out);
}

export function safeHref(value) {
  if (typeof value !== 'string') throw new Error(`Link must be a string, got ${value}`);
  if (/^#[a-z0-9-]+$/.test(value) || /^\/(?:[a-z0-9-]+\/)*$/.test(value)) return value;
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error(`Links must be HTTPS without credentials: ${value}`);
  return url.href;
}

/**
 * Czech typography: a non-breaking space after one-letter prepositions and
 * conjunctions (k s v z o u a i). Only text between tags is touched, so
 * attributes, URLs and markup stay intact; <code>/<script> content is skipped.
 */
export function czechNbsp(page) {
  let skip = 0;
  return page.split(/(<[^>]+>)/).map(part => {
    if (part.startsWith('<')) {
      if (/^<(code|script|pre)\b/i.test(part)) skip++;
      else if (/^<\/(code|script|pre)>/i.test(part)) skip = Math.max(0, skip - 1);
      return part;
    }
    if (skip) return part;
    return part.replace(/(?<=^|[\s\u00a0(„“–])([kKsSvVzZoOuUaAiI]) (?=[^\s])/g, '$1\u00a0');
  }).join('');
}

/**
 * Inline copy markup used by the dictionaries: **bold**, `code`, [label](href).
 * Text is escaped first, so dictionary strings can never inject HTML.
 */
export function inline(text, vars = {}) {
  const filled = String(text).replace(/\{([a-zA-Z]+)\}/g, (match, key) => {
    if (!(key in vars)) throw new Error(`Unknown copy variable ${match} in "${text}"`);
    return vars[key];
  });
  let out = esc(filled);
  out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (match, label, href) => {
    const decoded = href.replace(/&amp;/g, '&');
    return `<a href="${esc(safeHref(decoded))}">${label}</a>`;
  });
  return raw(out);
}
