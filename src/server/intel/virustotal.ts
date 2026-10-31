import { z } from 'zod';
import { MULTI_ENGINE_CONFIRM } from '../../engine/aggregate.js';
import type { EngineDetections } from '../../shared/types.js';
import { RateLimiter, TtlCache, isTimeoutError, readTextLimited, type FetchLike } from '../util.js';
import type { IntelProvider, ProviderResult } from './types.js';

/**
 * VirusTotal API v3, lookup only. Docs: https://docs.virustotal.com/reference/overview
 *
 *  - GET /files/{sha256}   report for a file hash
 *  - GET /urls/{id}        report for a URL, id = unpadded base64url of the URL
 *
 * PhishShield NEVER uploads files or submits URLs for scanning: anything submitted to VirusTotal
 * is shared with its security partners and premium customers. Only hashes and already-public
 * URLs (without query strings) are looked up.
 *
 * Public API limits: 4 lookups/minute, 500/day, non-commercial use only. Because of that quota the
 * provider is "on demand": it runs for manual scans and file checks, not on every page load.
 */
export const VT_API = 'https://www.virustotal.com/api/v3';

const Stats = z
  .object({
    malicious: z.number().int().min(0).default(0),
    suspicious: z.number().int().min(0).default(0),
    harmless: z.number().int().min(0).default(0),
    undetected: z.number().int().min(0).default(0),
    timeout: z.number().int().min(0).default(0),
    'type-unsupported': z.number().int().min(0).default(0),
    failure: z.number().int().min(0).default(0),
  })
  .partial()
  .passthrough();

const VtObject = z.object({
  data: z.object({
    id: z.string(),
    type: z.string(),
    attributes: z
      .object({
        last_analysis_stats: Stats.optional(),
        last_analysis_date: z.number().optional(),
        first_submission_date: z.number().optional(),
        times_submitted: z.number().optional(),
        reputation: z.number().optional(),
        meaningful_name: z.string().optional(),
        type_description: z.string().optional(),
        type_tag: z.string().optional(),
        size: z.number().optional(),
        title: z.string().optional(),
        categories: z.record(z.string(), z.string()).optional(),
        total_votes: z.object({ harmless: z.number(), malicious: z.number() }).partial().optional(),
        popular_threat_classification: z
          .object({ suggested_threat_label: z.string().optional(), popular_threat_category: z.array(z.object({ value: z.string() }).passthrough()).optional() })
          .passthrough()
          .optional(),
      })
      .passthrough(),
  }),
});

/** File facts returned alongside the finding by POST /v1/file. All optional; all from VirusTotal. */
export interface VtFileInfo {
  meaningfulName?: string;
  typeDescription?: string;
  size?: number;
  firstSeen?: number;
  lastAnalysis?: number;
  timesSubmitted?: number;
  communityVotes?: { harmless: number; malicious: number };
  label?: string;
  permalink: string;
}

export interface VirusTotalOptions {
  apiKey?: string;
  timeoutMs?: number;
  fetchImpl?: FetchLike;
  now?: () => number;
  perMinute?: number;
  perDay?: number;
}

export interface VirusTotalClient extends IntelProvider {
  readonly onDemand: true;
  lookupFile(sha256: string): Promise<{ finding: ProviderResult; file?: VtFileInfo }>;
}

/** VirusTotal URL identifier: base64url of the URL without padding. */
export function vtUrlId(url: string): string {
  return Buffer.from(url, 'utf8').toString('base64url');
}

export function detectionsFrom(stats: z.infer<typeof Stats> | undefined): EngineDetections | undefined {
  if (!stats) return undefined;
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const harmless = stats.harmless ?? 0;
  const undetected = stats.undetected ?? 0;
  return { malicious, suspicious, harmless, undetected, total: malicious + suspicious + harmless + undetected };
}

export function createVirusTotalProvider(opts: VirusTotalOptions): VirusTotalClient {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const now = opts.now ?? Date.now;
  const timeoutMs = opts.timeoutMs ?? 6000;
  const base = { providerId: 'virustotal', providerName: 'VirusTotal' } as const;
  const minute = new RateLimiter(opts.perMinute ?? 4, opts.perMinute ?? 4, now);
  const perDay = opts.perDay ?? 500;
  let day = { start: now(), used: 0 };
  const fileCache = new TtlCache<{ finding: ProviderResult; file?: VtFileInfo }>(2000, now);
  let lastError: string | undefined;

  function quota(): string | null {
    if (now() - day.start > 86_400_000) day = { start: now(), used: 0 };
    if (day.used >= perDay) return 'VirusTotal daily quota reached (free tier: 500 lookups/day).';
    if (minute.take('vt') > 0) return 'VirusTotal rate limit reached (free tier: 4 lookups/minute). Try again in a minute.';
    day.used++;
    return null;
  }

  async function get(path: string): Promise<{ status: number; body: unknown } | { failure: ProviderResult['status']; message: string }> {
    let res: Response;
    try {
      res = await fetchImpl(`${VT_API}${path}`, {
        headers: { 'x-apikey': opts.apiKey!, accept: 'application/json' },
        signal: AbortSignal.timeout(timeoutMs),
        redirect: 'error',
      });
    } catch (err) {
      lastError = isTimeoutError(err) ? 'timeout' : 'network error';
      return isTimeoutError(err) ? { failure: 'timeout', message: `VirusTotal did not respond within ${timeoutMs} ms.` } : { failure: 'error', message: 'Could not reach VirusTotal.' };
    }
    let body: unknown = null;
    try {
      body = JSON.parse(await readTextLimited(res, 2 * 1024 * 1024));
    } catch {
      /* non-JSON error page */
    }
    return { status: res.status, body };
  }

  function failureFor(status: number, body: unknown): { status: ProviderResult['status']; message: string } {
    const code = z.object({ error: z.object({ code: z.string() }) }).safeParse(body).data?.error.code;
    lastError = code ?? `HTTP ${status}`;
    if (status === 401 || status === 403) return { status: 'error', message: 'VirusTotal rejected the server API key.' };
    if (status === 429) return { status: 'error', message: 'VirusTotal quota exceeded. Try again later.' };
    if (status === 504 || code === 'DeadlineExceededError') return { status: 'timeout', message: 'VirusTotal timed out.' };
    return { status: 'error', message: `VirusTotal error (${code ?? status}).` };
  }

  function toFinding(parsed: z.infer<typeof VtObject>, checkedAt: number): ProviderResult {
    const a = parsed.data.attributes;
    const detections = detectionsFrom(a.last_analysis_stats);
    const confirmed = !!detections && detections.malicious >= MULTI_ENGINE_CONFIRM;
    const label = a.popular_threat_classification?.suggested_threat_label;
    return {
      ...base,
      status: confirmed ? 'match' : 'no_match',
      ...(confirmed ? { matchType: 'exact_url' as const, threatTypes: label ? [label] : ['MALICIOUS'] } : {}),
      checkedAt,
      ...(a.last_analysis_date ? { datasetUpdatedAt: a.last_analysis_date * 1000 } : {}),
      ...(detections ? { detections } : {}),
      cacheTtlSec: confirmed ? 6 * 3600 : 1800,
    };
  }

  return {
    id: base.providerId,
    name: base.providerName,
    onDemand: true,
    isConfigured: () => Boolean(opts.apiKey),
    describe: () => ({ configured: Boolean(opts.apiKey), mode: 'on demand (manual scans and file hashes)', usedToday: day.used, dailyQuota: perDay, lastError }),

    async check(url: string): Promise<ProviderResult> {
      const checkedAt = now();
      if (!opts.apiKey) return { ...base, status: 'unconfigured', checkedAt, message: 'VT_API_KEY is not set on the server.' };
      const q = quota();
      if (q) return { ...base, status: 'error', checkedAt, message: q };
      const r = await get(`/urls/${vtUrlId(url)}`);
      if ('failure' in r) return { ...base, status: r.failure, checkedAt, message: r.message };
      if (r.status === 404) return { ...base, status: 'no_match', checkedAt, message: 'VirusTotal has no report for this address.', cacheTtlSec: 900 };
      if (r.status !== 200) return { ...base, checkedAt, ...failureFor(r.status, r.body) };
      const parsed = VtObject.safeParse(r.body);
      if (!parsed.success) return { ...base, status: 'error', checkedAt, message: 'Unexpected response from VirusTotal.' };
      lastError = undefined;
      return toFinding(parsed.data, checkedAt);
    },

    async lookupFile(sha256: string) {
      const checkedAt = now();
      const hash = sha256.toLowerCase();
      const permalink = `https://www.virustotal.com/gui/file/${hash}`;
      if (!/^[a-f0-9]{64}$/.test(hash)) return { finding: { ...base, status: 'error', checkedAt, message: 'Invalid SHA-256.' } };
      if (!opts.apiKey) return { finding: { ...base, status: 'unconfigured', checkedAt, message: 'VT_API_KEY is not set on the server.' } };
      const hit = fileCache.get(hash);
      if (hit) return { ...hit, finding: { ...hit.finding, fromCache: true } };
      const q = quota();
      if (q) return { finding: { ...base, status: 'error', checkedAt, message: q } };
      const r = await get(`/files/${hash}`);
      if ('failure' in r) return { finding: { ...base, status: r.failure, checkedAt, message: r.message } };
      if (r.status === 404) {
        const out = { finding: { ...base, status: 'no_match' as const, checkedAt, message: 'VirusTotal has never seen this file.' } };
        fileCache.set(hash, out, 15 * 60_000);
        return out;
      }
      if (r.status !== 200) return { finding: { ...base, checkedAt, ...failureFor(r.status, r.body) } };
      const parsed = VtObject.safeParse(r.body);
      if (!parsed.success) return { finding: { ...base, status: 'error', checkedAt, message: 'Unexpected response from VirusTotal.' } };
      lastError = undefined;
      const a = parsed.data.data.attributes;
      const finding = toFinding(parsed.data, checkedAt);
      const file: VtFileInfo = {
        permalink,
        ...(a.meaningful_name ? { meaningfulName: a.meaningful_name.slice(0, 200) } : {}),
        ...(a.type_description ? { typeDescription: a.type_description.slice(0, 100) } : {}),
        ...(a.size !== undefined ? { size: a.size } : {}),
        ...(a.first_submission_date ? { firstSeen: a.first_submission_date * 1000 } : {}),
        ...(a.last_analysis_date ? { lastAnalysis: a.last_analysis_date * 1000 } : {}),
        ...(a.times_submitted !== undefined ? { timesSubmitted: a.times_submitted } : {}),
        ...(a.total_votes ? { communityVotes: { harmless: a.total_votes.harmless ?? 0, malicious: a.total_votes.malicious ?? 0 } } : {}),
        ...(a.popular_threat_classification?.suggested_threat_label ? { label: a.popular_threat_classification.suggested_threat_label.slice(0, 100) } : {}),
      };
      const out = { finding, file };
      fileCache.set(hash, out, (finding.cacheTtlSec ?? 1800) * 1000);
      return out;
    },
  };
}
