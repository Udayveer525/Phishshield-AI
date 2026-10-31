import { BRANDS } from '../../engine/brands.js';
import { FREE_HOSTING_SUFFIXES, URL_SHORTENERS, hostMatchesSuffix } from '../../engine/lists.js';
import { parseUrl } from '../../engine/url.js';
import { BodyTooLargeError, isTimeoutError, readTextLimited, type FetchLike } from '../util.js';
import type { IntelProvider, ProviderResult } from './types.js';

/**
 * OpenPhish Community Feed: a plain-text list of active phishing URLs, updated every 12 hours.
 * Terms: free for non-commercial use only (https://openphish.com/terms.html).
 * The server downloads the feed from a fixed, allow-listed URL and matches locally, so the
 * user's URLs are never sent to OpenPhish.
 */
export const OPENPHISH_FEED_URLS = [
  'https://openphish.com/feed.txt',
  'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt',
] as const;

const FEED_HOSTS = new Set(OPENPHISH_FEED_URLS.map((u) => new URL(u).hostname));
const MAX_FEED_BYTES = 10 * 1024 * 1024;
const STALE_AFTER_MS = 36 * 60 * 60 * 1000;

export interface OpenPhishOptions {
  enabled: boolean;
  feedUrl?: string;
  refreshMs?: number;
  timeoutMs?: number;
  fetchImpl?: FetchLike;
  now?: () => number;
}

export interface FeedIndex {
  urls: Set<string>;
  hosts: Set<string>;
  count: number;
}

/** Key used for matching: lowercase host + path without trailing slash. Query/fragment ignored. */
export function feedKey(raw: string): { key: string; host: string } | null {
  const p = parseUrl(raw);
  if (!p.ok) return null;
  const path = p.path.replace(/\/+$/, '') || '';
  return { key: `${p.host}${p.port ? `:${p.port}` : ''}${path}`, host: p.host };
}

export function parseFeed(text: string): FeedIndex {
  const urls = new Set<string>();
  const hosts = new Set<string>();
  let count = 0;
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const k = feedKey(t);
    if (!k) continue;
    urls.add(k.key);
    hosts.add(k.host);
    count++;
    if (count > 500_000) break;
  }
  return { urls, hosts, count };
}

/** Hosts shared by many unrelated users, where a single listed URL says nothing about the rest. */
function isSharedHost(host: string): boolean {
  const p = parseUrl(`https://${host}/`);
  if (!p.ok) return true;
  if (hostMatchesSuffix(host, FREE_HOSTING_SUFFIXES) && p.subdomain === '') return true;
  if (URL_SHORTENERS.has(host) || (p.registrableDomain && URL_SHORTENERS.has(p.registrableDomain))) return true;
  return BRANDS.some((b) => p.registrableDomain && b.domains.includes(p.registrableDomain));
}

export function matchFeed(index: FeedIndex, url: string): ProviderResult['matchType'] | null {
  const k = feedKey(url);
  if (!k) return null;
  if (index.urls.has(k.key)) return 'exact_url';
  // Parent paths: a listed kit directory covers the pages beneath it.
  const pathPart = k.key.slice(k.host.length);
  const segments = pathPart.split('/').filter(Boolean);
  for (let i = segments.length - 1; i >= 1; i--) {
    if (index.urls.has(`${k.host}/${segments.slice(0, i).join('/')}`)) return 'url_prefix';
  }
  if (index.hosts.has(k.host) && !isSharedHost(k.host)) return 'host';
  return null;
}

export function createOpenPhishProvider(opts: OpenPhishOptions): IntelProvider & { refresh(): Promise<void>; start(): () => void } {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const now = opts.now ?? Date.now;
  const feedUrl = opts.feedUrl ?? OPENPHISH_FEED_URLS[0];
  if (!(OPENPHISH_FEED_URLS as readonly string[]).includes(feedUrl)) {
    throw new Error(`OPENPHISH_FEED_URL must be one of: ${OPENPHISH_FEED_URLS.join(', ')}`);
  }
  const base = { providerId: 'openphish', providerName: 'OpenPhish Community Feed' } as const;
  let index: FeedIndex | null = null;
  let fetchedAt: number | undefined;
  let lastError: string | undefined;
  let inflight: Promise<void> | null = null;

  async function refresh(): Promise<void> {
    if (!opts.enabled) return;
    if (inflight) return inflight;
    inflight = (async () => {
      try {
        const res = await fetchImpl(feedUrl, { signal: AbortSignal.timeout(opts.timeoutMs ?? 20_000), redirect: 'follow' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        // Redirects may only stay on the allow-listed feed hosts.
        const finalHost = res.url ? new URL(res.url).hostname : new URL(feedUrl).hostname;
        if (!FEED_HOSTS.has(finalHost)) throw new Error(`feed redirected to unexpected host ${finalHost}`);
        const type = res.headers.get('content-type') ?? '';
        if (type && !/^text\/plain\b/i.test(type)) throw new Error(`unexpected content-type ${type}`);
        const text = await readTextLimited(res, MAX_FEED_BYTES);
        const parsed = parseFeed(text);
        if (parsed.count === 0) throw new Error('feed was empty');
        index = parsed;
        fetchedAt = now();
        lastError = undefined;
      } catch (err) {
        lastError = isTimeoutError(err) ? 'timeout' : err instanceof BodyTooLargeError ? 'feed too large' : err instanceof Error ? err.message : 'unknown error';
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  }

  return {
    id: base.providerId,
    name: base.providerName,
    isConfigured: () => opts.enabled,
    describe: () => ({
      configured: opts.enabled,
      feedUrl,
      entries: index?.count ?? 0,
      fetchedAt: fetchedAt ? new Date(fetchedAt).toISOString() : null,
      stale: fetchedAt ? now() - fetchedAt > STALE_AFTER_MS : null,
      lastError,
    }),
    refresh,
    start() {
      void refresh();
      const timer = setInterval(() => void refresh(), Math.max(60 * 60_000, opts.refreshMs ?? 12 * 60 * 60_000));
      timer.unref?.();
      return () => clearInterval(timer);
    },
    async check(url: string): Promise<ProviderResult> {
      const checkedAt = now();
      if (!opts.enabled) return { ...base, status: 'unconfigured', checkedAt, message: 'OpenPhish feed is disabled on the server.' };
      if (!index || !fetchedAt) {
        return { ...base, status: 'error', checkedAt, message: lastError ? `Feed unavailable (${lastError}).` : 'Feed not downloaded yet.' };
      }
      const stale = now() - fetchedAt > STALE_AFTER_MS;
      const matchType = matchFeed(index, url);
      const extra = { checkedAt, datasetUpdatedAt: fetchedAt, ...(stale ? { message: 'Feed snapshot is older than 36 hours.' } : {}) };
      if (!matchType) return { ...base, status: 'no_match', ...extra, cacheTtlSec: 600 };
      return { ...base, status: 'match', matchType, threatTypes: ['PHISHING'], ...extra, cacheTtlSec: 1800 };
    },
  };
}
