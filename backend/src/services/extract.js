// Regex-based artifact extractor (working-copy only, never mutates original).
// Extracts: urls, domains, emails, ipv4, hashes, timestamps. Preserves source location.
const URL_RE = /https?:\/\/[^\s"'<>,]+/gi;
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const HASH_RE = /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g;
const ISO_TS_RE = /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?Z?\b/g;

function domainOf(url) { try { return new URL(url).hostname.toLowerCase(); } catch { return ''; } }
function normUrl(u) {
  try {
    const x = new URL(u);
    return (x.protocol + '//' + x.hostname.toLowerCase() + x.pathname.replace(/\/$/, '') + x.search).toLowerCase();
  } catch { return String(u).toLowerCase(); }
}

function extractFromText(text, srcLabel) {
  const out = [];
  const push = (type, value, normalized, extra = {}) =>
    out.push({ type, value, normalized_value: normalized || String(value).toLowerCase(), source_location: srcLabel, ...extra });
  for (const m of (text.match(URL_RE) || [])) {
    push('url', m, normUrl(m));
    const d = domainOf(m);
    if (d) push('domain', d, d);
  }
  for (const m of (text.match(EMAIL_RE) || [])) push('email', m, m.toLowerCase());
  for (const m of (text.match(IPV4_RE) || [])) push('ip', m, m);
  for (const m of (text.match(HASH_RE) || [])) push('hash', m, m.toLowerCase());
  for (const m of (text.match(ISO_TS_RE) || [])) {
    const d = new Date(m);
    push('timestamp', m, m, { parsed_utc: isNaN(d) ? null : d.toISOString() });
  }
  return out;
}

module.exports = { extractFromText, domainOf, normUrl };
