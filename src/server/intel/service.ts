import { getDomain } from 'tldts';
import { lookupUrl, parseUrl } from '../../engine/url.js';
import type { DomainInfo, ReputationSummary } from '../../shared/types.js';
import { RateLimiter, TtlCache } from '../util.js';
import type { BreachCatalog } from './hibp.js';
import type { RdapClient } from './rdap.js';
import type { IntelProvider, ProviderResult } from './types.js';

export interface IntelService {
  /** `deep` also runs on-demand providers (quota-limited, e.g. VirusTotal); used for manual scans. */
  check(url: string, opts?: { deep?: boolean }): Promise<ReputationSummary>;
  providers(): Array<{ id: string; name: string; configured: boolean; details: Record<string, unknown> }>;
}

export interface IntelServiceOptions {
  now?: () => number;
  providerCallsPerMinute?: number;
  rdap?: RdapClient;
  breaches?: BreachCatalog;
  /** Longest the reputation response waits for RDAP; a slower lookup still completes and is cached. */
  domainDeadlineMs?: number;
}

const isOnDemand = (p: IntelProvider) => (p as { onDemand?: boolean }).onDemand === true;

export function createIntelService(providers: IntelProvider[], opts: IntelServiceOptions = {}): IntelService {
  const now = opts.now ?? Date.now;
  const cache = new TtlCache<ProviderResult>(20_000, now);
  // Global per-provider budget protects upstream quotas regardless of client count.
  const budget = new RateLimiter(opts.providerCallsPerMinute ?? 120, opts.providerCallsPerMinute ?? 120, now);

  return {
    providers: () =>
      [...providers, ...(opts.rdap ? [opts.rdap] : []), ...(opts.breaches ? [opts.breaches] : [])].map((p) => ({
        id: p.id,
        name: p.name,
        configured: p.isConfigured(),
        details: { ...p.describe(), ...('onDemand' in p && p.onDemand ? { onDemand: true } : {}) },
      })),

    async check(rawUrl: string, checkOpts: { deep?: boolean } = {}): Promise<ReputationSummary> {
      const parsed = parseUrl(rawUrl);
      if (!parsed.ok) return { status: 'skipped', findings: [], note: parsed.message };
      if (parsed.isPrivateOrLocal) return { status: 'skipped', findings: [], note: 'Private and local addresses are never sent to reputation providers.' };

      // Query strings can contain tokens or personal data; they are not forwarded.
      const url = lookupUrl(parsed);
      const icannDomain = parsed.isIp ? null : (getDomain(parsed.host, { allowPrivateDomains: false }) ?? null);
      const enrich = enrichment(parsed.host, icannDomain);
      const configured = providers.filter((p) => p.isConfigured() && (checkOpts.deep || !isOnDemand(p)));
      const deferred = providers
        .filter((p) => p.isConfigured() && !checkOpts.deep && isOnDemand(p))
        .map<ProviderResult>((p) => ({ providerId: p.id, providerName: p.name, status: 'skipped', checkedAt: now(), message: 'Checked on manual scans only (free-tier quota).' }));
      const unconfigured = providers
        .filter((p) => !p.isConfigured())
        .map<ProviderResult>((p) => ({ providerId: p.id, providerName: p.name, status: 'unconfigured', checkedAt: now() }));
      if (!configured.length) return { status: 'not_configured', findings: [...deferred, ...unconfigured], ...(await enrich) };

      const results = await Promise.all(
        configured.map(async (p): Promise<ProviderResult> => {
          const key = `${p.id}|${url}`;
          const hit = cache.get(key);
          if (hit) return { ...hit, fromCache: true };
          if (budget.take(p.id) > 0) {
            return { providerId: p.id, providerName: p.name, status: 'error', checkedAt: now(), message: 'Server-side provider budget exhausted; try again shortly.' };
          }
          let r: ProviderResult;
          try {
            r = await p.check(url);
          } catch {
            r = { providerId: p.id, providerName: p.name, status: 'error', checkedAt: now(), message: 'Provider failed unexpectedly.' };
          }
          if (r.status === 'match' || r.status === 'no_match') cache.set(key, r, (r.cacheTtlSec ?? 300) * 1000);
          return r;
        }),
      );

      const answered = results.filter((r) => r.status === 'match' || r.status === 'no_match').length;
      // On-demand providers that were not asked do not make the result "partial".
      const status = answered === results.length ? 'checked' : answered === 0 ? 'unavailable' : 'partial';
      // Strip internal cache hints from the wire format.
      const findings = [...results, ...deferred, ...unconfigured].map(({ cacheTtlSec: _ttl, ...f }) => f);
      return { status, findings, ...(await enrich) };
    },
  };

  /** Domain registration (RDAP) and breach history (HIBP), keyed by the ICANN registrable domain. */
  async function enrichment(host: string, domain: string | null): Promise<Pick<ReputationSummary, 'domain' | 'breaches'>> {
    if (!domain) return {};
    const breaches = opts.breaches?.lookup(domain);
    let info: DomainInfo | undefined;
    if (opts.rdap?.isConfigured()) {
      const deadline = opts.domainDeadlineMs ?? 2500;
      const pending = opts.rdap.lookup(host).catch(() => undefined);
      info = await Promise.race([
        pending,
        new Promise<DomainInfo>((resolve) => {
          const t = setTimeout(() => resolve({ domain, status: 'timeout', source: 'rdap', checkedAt: now(), message: 'Registry is slow; the result will be ready on the next check.' }), deadline);
          void pending.finally(() => clearTimeout(t));
        }),
      ]);
    }
    return { ...(info ? { domain: info } : {}), ...(breaches ? { breaches } : {}) };
  }
}
