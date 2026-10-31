import { z } from 'zod';
import type { BreachRecord } from '../../shared/types.js';
import { BodyTooLargeError, isTimeoutError, readTextLimited, type FetchLike } from '../util.js';

/**
 * Have I Been Pwned public breach catalogue (GET /api/v3/breaches, no key required).
 * Docs: https://haveibeenpwned.com/API/v3#AllBreaches
 *
 * The server downloads the whole catalogue (~1,000 breaches) once a day and indexes it by domain,
 * so the sites a user visits are never sent to HIBP. Breach data is licensed CC BY 4.0: every UI
 * that shows it links back to haveibeenpwned.com.
 *
 * A breach is context ("this company leaked customer data; expect targeted scams"), never a
 * phishing signal: the real site of a breached company is still the real site.
 */
export const HIBP_BREACHES_URL = 'https://haveibeenpwned.com/api/v3/breaches';
const MAX_BYTES = 20 * 1024 * 1024;
const MAX_PER_DOMAIN = 5;

const Breach = z
  .object({
    Name: z.string(),
    Title: z.string(),
    Domain: z.string(),
    BreachDate: z.string(),
    PwnCount: z.number(),
    DataClasses: z.array(z.string()),
    IsVerified: z.boolean(),
    IsFabricated: z.boolean().optional(),
    IsSpamList: z.boolean().optional(),
    IsRetired: z.boolean().optional(),
  })
  .passthrough();

export interface BreachCatalogOptions {
  enabled: boolean;
  userAgent: string;
  fetchImpl?: FetchLike;
  now?: () => number;
  timeoutMs?: number;
  refreshMs?: number;
}

export interface BreachCatalog {
  readonly id: 'hibp_breaches';
  readonly name: string;
  isConfigured(): boolean;
  lookup(registrableDomain: string): BreachRecord[] | undefined;
  refresh(): Promise<void>;
  start(): () => void;
  describe(): Record<string, unknown>;
}

export function indexBreaches(raw: unknown): Map<string, BreachRecord[]> {
  const list = z.array(z.unknown()).parse(raw);
  const index = new Map<string, BreachRecord[]>();
  for (const item of list) {
    const b = Breach.safeParse(item);
    if (!b.success) continue;
    const d = b.data;
    // Fabricated breaches, spam lists and retired entries are not evidence about the company.
    if (d.IsFabricated || d.IsSpamList || d.IsRetired) continue;
    const domain = d.Domain.trim().toLowerCase();
    if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) continue;
    const rec: BreachRecord = {
      name: d.Name.slice(0, 100),
      title: d.Title.slice(0, 120),
      domain,
      breachDate: /^\d{4}-\d{2}-\d{2}$/.test(d.BreachDate) ? d.BreachDate : '',
      pwnCount: Math.max(0, Math.floor(d.PwnCount)),
      dataClasses: d.DataClasses.slice(0, 20).map((c) => c.slice(0, 60)),
      isVerified: d.IsVerified,
    };
    const list = index.get(domain) ?? [];
    list.push(rec);
    index.set(domain, list);
  }
  for (const list of index.values()) {
    list.sort((a, b) => b.breachDate.localeCompare(a.breachDate));
    list.splice(MAX_PER_DOMAIN);
  }
  return index;
}

export function createBreachCatalog(opts: BreachCatalogOptions): BreachCatalog {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const now = opts.now ?? Date.now;
  let index: Map<string, BreachRecord[]> | null = null;
  let count = 0;
  let fetchedAt: number | undefined;
  let lastError: string | undefined;
  let inflight: Promise<void> | null = null;

  async function refresh(): Promise<void> {
    if (!opts.enabled) return;
    if (inflight) return inflight;
    inflight = (async () => {
      try {
        // HIBP returns 403 without a descriptive User-Agent.
        const res = await fetchImpl(HIBP_BREACHES_URL, {
          headers: { 'user-agent': opts.userAgent, accept: 'application/json' },
          signal: AbortSignal.timeout(opts.timeoutMs ?? 20_000),
          redirect: 'error',
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const parsed = indexBreaches(JSON.parse(await readTextLimited(res, MAX_BYTES)));
        if (!parsed.size) throw new Error('catalogue was empty');
        index = parsed;
        count = [...parsed.values()].reduce((a, l) => a + l.length, 0);
        fetchedAt = now();
        lastError = undefined;
      } catch (err) {
        lastError = isTimeoutError(err) ? 'timeout' : err instanceof BodyTooLargeError ? 'catalogue too large' : err instanceof Error ? err.message : 'unknown error';
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  return {
    id: 'hibp_breaches',
    name: 'Have I Been Pwned (breach catalogue)',
    isConfigured: () => opts.enabled,
    lookup(domain) {
      if (!opts.enabled || !index) return undefined;
      return index.get(domain.toLowerCase()) ?? [];
    },
    refresh,
    start() {
      void refresh();
      const timer = setInterval(() => void refresh(), Math.max(60 * 60_000, opts.refreshMs ?? 24 * 60 * 60_000));
      timer.unref?.();
      return () => clearInterval(timer);
    },
    describe: () => ({
      configured: opts.enabled,
      mode: 'downloaded daily, matched locally',
      entries: count,
      domains: index?.size ?? 0,
      fetchedAt: fetchedAt ? new Date(fetchedAt).toISOString() : null,
      license: 'CC BY 4.0, haveibeenpwned.com',
      lastError,
    }),
  };
}
