import { z } from 'zod';
import { isTimeoutError, type FetchLike } from '../util.js';
import type { IntelProvider, ProviderResult } from './types.js';

/**
 * Google Safe Browsing v4 Lookup API (threatMatches:find).
 * Docs: https://developers.google.com/safe-browsing/v4/lookup-api
 * Usage: the Safe Browsing APIs are for non-commercial use; commercial products must use
 * Google Cloud Web Risk instead. The API key stays on the server.
 */
export const GSB_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

const GsbResponse = z.object({
  matches: z
    .array(
      z.object({
        threatType: z.string(),
        platformType: z.string().optional(),
        threatEntryType: z.string().optional(),
        threat: z.object({ url: z.string() }),
        cacheDuration: z.string().optional(),
      }),
    )
    .optional(),
});

export interface SafeBrowsingOptions {
  apiKey?: string;
  timeoutMs?: number;
  fetchImpl?: FetchLike;
  clientVersion?: string;
  now?: () => number;
}

export function createSafeBrowsingProvider(opts: SafeBrowsingOptions): IntelProvider {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 4000;
  const now = opts.now ?? Date.now;
  const base = { providerId: 'google_safe_browsing', providerName: 'Google Safe Browsing' } as const;
  let lastError: string | undefined;

  return {
    id: base.providerId,
    name: base.providerName,
    isConfigured: () => Boolean(opts.apiKey),
    describe: () => ({ configured: Boolean(opts.apiKey), api: 'v4 Lookup (threatMatches:find)', lastError }),
    async check(url: string): Promise<ProviderResult> {
      const checkedAt = now();
      if (!opts.apiKey) return { ...base, status: 'unconfigured', checkedAt, message: 'GSB_API_KEY is not set on the server.' };

      const body = {
        client: { clientId: 'phishshield-ai', clientVersion: opts.clientVersion ?? '0.1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      };

      let res: Response;
      try {
        res = await fetchImpl(`${GSB_ENDPOINT}?key=${encodeURIComponent(opts.apiKey)}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(timeoutMs),
          redirect: 'error',
        });
      } catch (err) {
        if (isTimeoutError(err)) {
          lastError = 'timeout';
          return { ...base, status: 'timeout', checkedAt, message: `No response within ${timeoutMs} ms.` };
        }
        lastError = 'network error';
        return { ...base, status: 'error', checkedAt, message: 'Network error contacting Safe Browsing.' };
      }

      if (!res.ok) {
        lastError = `HTTP ${res.status}`;
        const message =
          res.status === 429 ? 'Safe Browsing quota exceeded.' : res.status === 400 || res.status === 403 ? 'Safe Browsing rejected the request (check the API key).' : `Safe Browsing returned HTTP ${res.status}.`;
        return { ...base, status: 'error', checkedAt, message };
      }

      let json: unknown;
      try {
        json = await res.json();
      } catch {
        lastError = 'malformed response';
        return { ...base, status: 'error', checkedAt, message: 'Malformed response from Safe Browsing.' };
      }
      const parsed = GsbResponse.safeParse(json);
      if (!parsed.success) {
        lastError = 'unexpected response shape';
        return { ...base, status: 'error', checkedAt, message: 'Unexpected response from Safe Browsing.' };
      }
      lastError = undefined;
      const matches = parsed.data.matches ?? [];
      if (!matches.length) return { ...base, status: 'no_match', checkedAt, cacheTtlSec: 300 };
      const ttl = Math.max(...matches.map((m) => parseDuration(m.cacheDuration) ?? 300));
      return {
        ...base,
        status: 'match',
        matchType: 'exact_url',
        threatTypes: [...new Set(matches.map((m) => m.threatType))],
        checkedAt,
        cacheTtlSec: ttl,
      };
    },
  };
}

/** Parse protobuf Duration strings such as "300s" or "300.000s". */
export function parseDuration(d?: string): number | undefined {
  if (!d) return undefined;
  const m = /^(\d+(?:\.\d+)?)s$/.exec(d.trim());
  return m ? Math.min(86_400, Math.round(Number(m[1]))) : undefined;
}
