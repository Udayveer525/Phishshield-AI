import { getDomain } from 'tldts';
import { z } from 'zod';
import { isPrivateOrLocalHost } from '../../engine/url.js';
import type { DomainInfo } from '../../shared/types.js';
import { RateLimiter, TtlCache, isTimeoutError, readTextLimited, type FetchLike } from '../util.js';

/**
 * Domain registration dates via RDAP (RFC 9082/9083), the JSON successor to WHOIS.
 *
 * 1. The IANA bootstrap file (RFC 9224) maps each TLD to its registry's RDAP base URL.
 * 2. We query `${base}domain/${registrableDomain}` and read the "registration" event.
 *
 * SSRF controls: the bootstrap URL is fixed; registry base URLs must be https on a public hostname;
 * redirects are followed manually (max 2) under the same rules; responses are size-capped.
 * Privacy: only the registrable domain (e.g. "example.co.in") is sent, to that TLD's registry.
 */
export const IANA_RDAP_BOOTSTRAP = 'https://data.iana.org/rdap/dns.json';
const MAX_BOOTSTRAP_BYTES = 2 * 1024 * 1024;
const MAX_RDAP_BYTES = 512 * 1024;

const Bootstrap = z.object({
  services: z.array(z.tuple([z.array(z.string()), z.array(z.string())])),
});

const RdapDomain = z
  .object({
    ldhName: z.string().optional(),
    events: z.array(z.object({ eventAction: z.string(), eventDate: z.string() }).passthrough()).optional(),
    entities: z.array(z.object({ roles: z.array(z.string()).optional(), vcardArray: z.unknown().optional() }).passthrough()).optional(),
  })
  .passthrough();

export interface RdapOptions {
  enabled: boolean;
  fetchImpl?: FetchLike;
  now?: () => number;
  timeoutMs?: number;
}

export interface RdapClient {
  readonly id: 'rdap';
  readonly name: string;
  isConfigured(): boolean;
  lookup(host: string): Promise<DomainInfo | undefined>;
  describe(): Record<string, unknown>;
}

export function parseBootstrap(raw: unknown): Map<string, string> {
  const map = new Map<string, string>();
  for (const [tlds, urls] of Bootstrap.parse(raw).services) {
    const https = urls.find((u) => isSafeBase(u));
    if (!https) continue;
    for (const tld of tlds) map.set(tld.toLowerCase(), https.endsWith('/') ? https : `${https}/`);
  }
  return map;
}

export function isSafeBase(u: string): boolean {
  try {
    const url = new URL(u);
    if (url.protocol !== 'https:' || url.username || url.password || url.port) return false;
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (/^[\d.]+$/.test(host) || host.includes(':') || !host.includes('.')) return false;
    return !isPrivateOrLocalHost(host);
  } catch {
    return false;
  }
}

/** Extract the facts we use from an RDAP domain object. */
export function parseRdapDomain(raw: unknown, domain: string, checkedAt: number): DomainInfo {
  const r = RdapDomain.safeParse(raw);
  if (!r.success) return { domain, status: 'error', source: 'rdap', checkedAt, message: 'Unexpected RDAP response.' };
  const ev = (action: string) => {
    const e = r.data.events?.find((x) => x.eventAction.toLowerCase() === action);
    const t = e ? Date.parse(e.eventDate) : NaN;
    return Number.isFinite(t) ? t : undefined;
  };
  const registrarEntity = r.data.entities?.find((e) => e.roles?.includes('registrar'));
  const registrar = vcardName(registrarEntity?.vcardArray);
  const registeredAt = ev('registration');
  return {
    domain,
    status: 'found',
    ...(registeredAt ? { registeredAt } : {}),
    ...(ev('expiration') ? { expiresAt: ev('expiration') } : {}),
    ...(registrar ? { registrar: registrar.slice(0, 120) } : {}),
    source: 'rdap',
    checkedAt,
    ...(registeredAt ? {} : { message: 'The registry did not publish a registration date.' }),
  };
}

function vcardName(v: unknown): string | undefined {
  // jCard: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"], ...]]
  if (!Array.isArray(v) || !Array.isArray(v[1])) return undefined;
  for (const prop of v[1] as unknown[]) {
    if (Array.isArray(prop) && prop[0] === 'fn' && typeof prop[3] === 'string') return prop[3];
  }
  return undefined;
}

export function createRdapClient(opts: RdapOptions): RdapClient {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const now = opts.now ?? Date.now;
  const timeoutMs = opts.timeoutMs ?? 3500;
  const cache = new TtlCache<DomainInfo>(20_000, now);
  const perRegistry = new RateLimiter(30, 30, now);
  let bootstrap: Map<string, string> | null = null;
  let bootstrapAt = 0;
  let bootstrapLoading: Promise<void> | null = null;
  let lastError: string | undefined;

  async function loadBootstrap(): Promise<void> {
    if (bootstrap && now() - bootstrapAt < 24 * 3600_000) return;
    if (bootstrapLoading) return bootstrapLoading;
    bootstrapLoading = (async () => {
      try {
        const res = await fetchImpl(IANA_RDAP_BOOTSTRAP, { signal: AbortSignal.timeout(10_000), redirect: 'error', headers: { accept: 'application/json' } });
        if (!res.ok) throw new Error(`bootstrap HTTP ${res.status}`);
        bootstrap = parseBootstrap(JSON.parse(await readTextLimited(res, MAX_BOOTSTRAP_BYTES)));
        bootstrapAt = now();
      } catch (err) {
        lastError = isTimeoutError(err) ? 'bootstrap timeout' : err instanceof Error ? err.message : 'bootstrap failed';
      } finally {
        bootstrapLoading = null;
      }
    })();
    return bootstrapLoading;
  }

  async function fetchRdap(url: string, hops = 0): Promise<Response> {
    const res = await fetchImpl(url, { headers: { accept: 'application/rdap+json, application/json' }, signal: AbortSignal.timeout(timeoutMs), redirect: 'manual' });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc || hops >= 2) throw new Error('too many redirects');
      const next = new URL(loc, url).toString();
      if (!isSafeBase(next)) throw new Error('unsafe redirect');
      return fetchRdap(next, hops + 1);
    }
    return res;
  }

  return {
    id: 'rdap',
    name: 'Domain registration (RDAP)',
    isConfigured: () => opts.enabled,
    describe: () => ({ configured: opts.enabled, mode: 'registry RDAP via IANA bootstrap', tlds: bootstrap?.size ?? 0, cached: cache.size, lastError }),

    async lookup(host: string): Promise<DomainInfo | undefined> {
      if (!opts.enabled) return undefined;
      // RDAP is per ICANN registrable domain: "user.github.io" is looked up as "github.io".
      const domain = getDomain(host, { allowPrivateDomains: false })?.toLowerCase();
      const checkedAt = now();
      if (!domain || !/^[a-z0-9.-]+$/.test(domain)) return undefined;
      const hit = cache.get(domain);
      if (hit) return hit;
      await loadBootstrap();
      if (!bootstrap) return { domain, status: 'error', source: 'rdap', checkedAt, message: 'RDAP directory unavailable.' };
      const tld = domain.slice(domain.lastIndexOf('.') + 1);
      const base = bootstrap.get(tld);
      if (!base) {
        const out: DomainInfo = { domain, status: 'unsupported', source: 'rdap', checkedAt, message: `The .${tld} registry does not offer RDAP.` };
        cache.set(domain, out, 24 * 3600_000);
        return out;
      }
      const registryHost = new URL(base).hostname;
      if (perRegistry.take(registryHost) > 0) return { domain, status: 'error', source: 'rdap', checkedAt, message: 'Registry lookup budget reached; try again shortly.' };
      try {
        const res = await fetchRdap(`${base}domain/${encodeURIComponent(domain)}`);
        if (res.status === 404) {
          const out: DomainInfo = { domain, status: 'not_found', source: 'rdap', checkedAt, message: 'The registry has no record of this domain.' };
          cache.set(domain, out, 3600_000);
          return out;
        }
        if (!res.ok) return { domain, status: 'error', source: 'rdap', checkedAt, message: `Registry answered HTTP ${res.status}.` };
        const out = parseRdapDomain(JSON.parse(await readTextLimited(res, MAX_RDAP_BYTES)), domain, checkedAt);
        if (out.status === 'found') cache.set(domain, out, 24 * 3600_000);
        lastError = undefined;
        return out;
      } catch (err) {
        lastError = isTimeoutError(err) ? 'timeout' : err instanceof Error ? err.message : 'failed';
        return { domain, status: isTimeoutError(err) ? 'timeout' : 'error', source: 'rdap', checkedAt, message: isTimeoutError(err) ? 'Registry did not respond in time.' : 'Registry lookup failed.' };
      }
    },
  };
}
