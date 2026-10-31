import { parse as parseDomain } from 'tldts';
import punycode from 'punycode/punycode.js';

export const MAX_URL_LENGTH = 8192;

export interface ParsedUrl {
  ok: true;
  input: string;
  /** Normalised href without the fragment. */
  href: string;
  scheme: 'http' | 'https';
  /** ASCII (punycode) hostname, lowercase, no brackets for IPv6. */
  host: string;
  /** Unicode rendering of the hostname. */
  unicodeHost: string;
  port: string;
  path: string;
  query: string;
  hasUserInfo: boolean;
  userInfo: string;
  isIp: boolean;
  ipVersion: 4 | 6 | null;
  /** The raw authority used a non-dotted-decimal IP form (hex, octal, integer). */
  ipObfuscated: boolean;
  /** eTLD+1, e.g. `sbi.co.in`. Null for IPs and bare suffixes. */
  registrableDomain: string | null;
  /** Registrable domain without the suffix, e.g. `sbi`. */
  domainLabel: string | null;
  publicSuffix: string | null;
  /** Subdomain part, e.g. `www` or `sbi.co.in.login`. */
  subdomain: string;
  /** Scheme was missing from the input and `http://` was assumed (manual scans). */
  assumedScheme: boolean;
  isPrivateOrLocal: boolean;
  usesPunycode: boolean;
  /** Hostname ends in a suffix from the Public Suffix List (false for made-up TLDs). */
  knownSuffix: boolean;
}

export interface UrlParseError {
  ok: false;
  input: string;
  reason: 'empty' | 'too_long' | 'invalid' | 'unsupported_scheme';
  scheme?: string;
  message: string;
}

export type UrlParseResult = ParsedUrl | UrlParseError;

// Registries restricted to vetted registrants (used to avoid false positives, never as proof of safety).
// `bank.in` is reserved by RBI/IDRBT for regulated Indian banks.
const RESTRICTED_SECOND_LEVEL = ['bank.in', 'gov.in', 'nic.in', 'mil.in', 'ac.in', 'edu.in', 'res.in'];

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = new RegExp('[\u0000-\u001f\u007f\u200b-\u200f\u2028\u2029\ufeff]', 'g');

export function parseUrl(raw: string, opts: { allowSchemeless?: boolean } = {}): UrlParseResult {
  const input = typeof raw === 'string' ? raw : '';
  const trimmed = input.replace(CONTROL_CHARS, '').trim();
  if (!trimmed) return { ok: false, input, reason: 'empty', message: 'No URL provided.' };
  if (trimmed.length > MAX_URL_LENGTH) {
    return { ok: false, input, reason: 'too_long', message: `URL exceeds ${MAX_URL_LENGTH} characters.` };
  }

  let candidate = trimmed;
  let assumedScheme = false;
  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(candidate);
  const looksLikeHostPort = /^[^/:?#]+:\d+(?:[/?#]|$)/.test(candidate);
  if (!schemeMatch || looksLikeHostPort) {
    if (!opts.allowSchemeless) {
      return { ok: false, input, reason: 'invalid', message: 'URL has no scheme.' };
    }
    candidate = `http://${candidate.replace(/^\/\//, '')}`;
    assumedScheme = true;
  } else {
    const scheme = schemeMatch[1]!.toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      return {
        ok: false,
        input,
        reason: 'unsupported_scheme',
        scheme,
        message: `The "${scheme}:" scheme is not a website address PhishShield can analyse.`,
      };
    }
  }

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return { ok: false, input, reason: 'invalid', message: 'This is not a valid URL.' };
  }
  if (!url.hostname) return { ok: false, input, reason: 'invalid', message: 'URL has no host.' };

  const scheme = url.protocol === 'https:' ? 'https' : 'http';
  let host = url.hostname.toLowerCase();
  let ipVersion: 4 | 6 | null = null;
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
    ipVersion = 6;
  } else if (isIPv4(host)) {
    ipVersion = 4;
  }
  // Trailing dot (FQDN form) is equivalent; strip it so suffix matching works.
  host = host.replace(/\.$/, '');
  const isIp = ipVersion !== null;

  const rawAuthority = extractRawHost(candidate);
  const ipObfuscated = ipVersion === 4 && rawAuthority !== null && rawAuthority.replace(/\.$/, '') !== host;

  let registrableDomain: string | null = null;
  let domainLabel: string | null = null;
  let publicSuffix: string | null = null;
  let subdomain = '';
  let knownSuffix = isIp;
  if (!isIp) {
    const info = parseDomain(host, { allowPrivateDomains: true });
    knownSuffix = Boolean(info.isIcann || info.isPrivate);
    registrableDomain = info.domain ?? null;
    domainLabel = info.domainWithoutSuffix ?? null;
    publicSuffix = info.publicSuffix ?? null;
    subdomain = info.subdomain ?? '';
    // Ensure restricted Indian registries are treated as public suffixes even if the bundled PSL lags.
    const restricted = RESTRICTED_SECOND_LEVEL.find((s) => host === s || host.endsWith(`.${s}`));
    if (restricted && publicSuffix !== restricted && host !== restricted) {
      const labels = host.slice(0, -(restricted.length + 1)).split('.');
      domainLabel = labels.pop() ?? null;
      publicSuffix = restricted;
      registrableDomain = domainLabel ? `${domainLabel}.${restricted}` : null;
      subdomain = labels.join('.');
    }
  }

  const usesPunycode = host.split('.').some((l) => l.startsWith('xn--'));
  let unicodeHost = host;
  if (usesPunycode) {
    try {
      unicodeHost = punycode.toUnicode(host);
    } catch {
      unicodeHost = host;
    }
  }

  url.hash = '';
  const href = url.href;

  return {
    ok: true,
    input,
    href,
    scheme,
    host,
    unicodeHost,
    port: url.port,
    path: url.pathname,
    query: url.search,
    hasUserInfo: Boolean(url.username || url.password),
    userInfo: decodeSafe(url.username + (url.password ? `:${url.password}` : '')),
    isIp,
    ipVersion,
    ipObfuscated,
    registrableDomain,
    domainLabel,
    publicSuffix,
    subdomain,
    assumedScheme,
    isPrivateOrLocal: isPrivateOrLocalHost(host, ipVersion),
    usesPunycode,
    knownSuffix,
  };
}

/** URL used for remote reputation lookups: no fragment, no query string (may hold tokens/PII). */
export function lookupUrl(p: ParsedUrl, includeQuery = false): string {
  const port = p.port ? `:${p.port}` : '';
  const host = p.ipVersion === 6 ? `[${p.host}]` : p.host;
  return `${p.scheme}://${host}${port}${p.path}${includeQuery ? p.query : ''}`;
}

/** Cache key for a URL. Fragment-insensitive; query-sensitive. */
export function cacheKey(p: ParsedUrl): string {
  return lookupUrl(p, true);
}

export function isIPv4(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  return parts.every((x) => /^\d{1,3}$/.test(x) && Number(x) <= 255);
}

export function isPrivateOrLocalHost(host: string, ipVersion: 4 | 6 | null = null): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (/\.(local|internal|lan|home|corp|intranet|home\.arpa)$/.test(h)) return true;
  const v = ipVersion ?? (isIPv4(h) ? 4 : h.includes(':') ? 6 : null);
  if (v === null && !h.includes('.')) return true; // single-label intranet names
  if (v === 4) {
    const [a, b] = h.split('.').map(Number) as [number, number, number, number];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local incl. cloud metadata 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast / reserved
    return false;
  }
  if (v === 6) {
    const x = h.replace(/^\[|\]$/g, '');
    if (x === '::' || x === '::1') return true;
    if (/^f[cd][0-9a-f]{2}:/.test(x)) return true; // unique local fc00::/7
    if (/^fe[89ab][0-9a-f]:/.test(x)) return true; // link-local fe80::/10
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(x);
    if (mapped) return isPrivateOrLocalHost(mapped[1]!, 4);
    return false;
  }
  return false;
}

function extractRawHost(candidate: string): string | null {
  const m = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]*)/.exec(candidate);
  if (!m) return null;
  let authority = m[1]!;
  const at = authority.lastIndexOf('@');
  if (at >= 0) authority = authority.slice(at + 1);
  if (authority.startsWith('[')) return authority.slice(1, authority.indexOf(']')).toLowerCase();
  return authority.replace(/:\d*$/, '').toLowerCase();
}

function decodeSafe(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
