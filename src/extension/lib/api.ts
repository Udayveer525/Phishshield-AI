import type { AiAnalysis, FormSummary, ReputationFinding, ReputationSummary } from '../../shared/types.js';

export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: 'not_configured' | 'timeout' | 'network' | 'http' | 'rate_limited' | 'invalid'; message: string };

export const TIMEOUTS = { health: 4000, reputation: 6000, reputationDeep: 14000, analyze: 45000, file: 12000 } as const;

async function call<T>(base: string, path: string, init: RequestInit, timeoutMs: number, validate: (x: unknown) => x is T): Promise<ApiResult<T>> {
  if (!base) return { ok: false, error: 'not_configured', message: 'No PhishShield API is configured (local-only mode).' };
  let res: Response;
  try {
    res = await fetch(`${base}${path}`, { ...init, signal: AbortSignal.timeout(timeoutMs), credentials: 'omit', cache: 'no-store', redirect: 'error' });
  } catch (err) {
    if (err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
      return { ok: false, error: 'timeout', message: `The PhishShield API did not respond within ${Math.round(timeoutMs / 1000)}s.` };
    }
    return { ok: false, error: 'network', message: 'Could not reach the PhishShield API.' };
  }
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    /* handled below */
  }
  if (res.status === 429) return { ok: false, error: 'rate_limited', message: 'Too many requests. Please wait a moment.' };
  if (!res.ok) {
    const msg = body && typeof body === 'object' && 'message' in body && typeof body.message === 'string' ? body.message : `HTTP ${res.status}`;
    return { ok: false, error: 'http', message: msg.slice(0, 200) };
  }
  if (!validate(body)) return { ok: false, error: 'invalid', message: 'Unexpected response from the PhishShield API.' };
  return { ok: true, data: body };
}

const isObj = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x);

const REPUTATION_STATUSES = ['checked', 'partial', 'unavailable', 'not_configured', 'skipped'];
const PROVIDER_STATUSES = ['match', 'no_match', 'error', 'timeout', 'unconfigured', 'skipped'];

export function isReputationSummary(x: unknown): x is ReputationSummary {
  return (
    isObj(x) &&
    typeof x.status === 'string' &&
    REPUTATION_STATUSES.includes(x.status) &&
    Array.isArray(x.findings) &&
    x.findings.length <= 10 &&
    x.findings.every(isFinding) &&
    (x.domain === undefined || (isObj(x.domain) && typeof x.domain.domain === 'string' && typeof x.domain.status === 'string')) &&
    (x.breaches === undefined || (Array.isArray(x.breaches) && x.breaches.length <= 10 && x.breaches.every((b) => isObj(b) && typeof b.title === 'string' && typeof b.pwnCount === 'number')))
  );
}

function isFinding(f: unknown): f is ReputationFinding {
  return (
    isObj(f) &&
    typeof f.providerId === 'string' &&
    typeof f.providerName === 'string' &&
    typeof f.status === 'string' &&
    PROVIDER_STATUSES.includes(f.status) &&
    typeof f.checkedAt === 'number' &&
    (f.detections === undefined || (isObj(f.detections) && ['malicious', 'suspicious', 'harmless', 'undetected', 'total'].every((k) => typeof (f.detections as Record<string, unknown>)[k] === 'number')))
  );
}

export interface FileLookup {
  finding: ReputationFinding;
  file?: {
    meaningfulName?: string;
    typeDescription?: string;
    size?: number;
    firstSeen?: number;
    lastAnalysis?: number;
    timesSubmitted?: number;
    communityVotes?: { harmless: number; malicious: number };
    label?: string;
    permalink: string;
  };
}
const isFileLookup = (x: unknown): x is FileLookup => isObj(x) && isFinding(x.finding) && (x.file === undefined || (isObj(x.file) && typeof x.file.permalink === 'string' && x.file.permalink.startsWith('https://www.virustotal.com/')));

const AI_STATUSES = ['ok', 'unavailable', 'error', 'refused', 'timeout', 'rate_limited'];
export function isAiAnalysis(x: unknown): x is AiAnalysis {
  if (!isObj(x) || typeof x.status !== 'string' || !AI_STATUSES.includes(x.status)) return false;
  if (x.status !== 'ok') return true;
  return (
    (x.concern === 'low' || x.concern === 'medium' || x.concern === 'high') &&
    Array.isArray(x.tactics) &&
    x.tactics.every((t) => isObj(t) && typeof t.tactic === 'string' && typeof t.explanation === 'string' && typeof t.evidenceQuote === 'string' && typeof t.grounded === 'boolean')
  );
}

export interface Health {
  service: string;
  version: string;
  providers: Array<{ id: string; name: string; configured: boolean; onDemand?: boolean; entries?: number; fetchedAt?: string | null; lastError?: string }>;
  ai: { configured: boolean; provider: string | null; model: string | null };
  features?: { fileReputation?: boolean };
}
const isHealth = (x: unknown): x is Health => isObj(x) && x.service === 'phishshield-api' && Array.isArray(x.providers) && isObj(x.ai);

const json = (body: unknown): RequestInit => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

export const api = {
  health: (base: string) => call(base, '/v1/health', { method: 'GET' }, TIMEOUTS.health, isHealth),
  reputation: (base: string, url: string, deep = false) =>
    call(base, '/v1/reputation', json(deep ? { url, deep } : { url }), deep ? TIMEOUTS.reputationDeep : TIMEOUTS.reputation, isReputationSummary),
  /** Hash-only file lookup: the file itself never leaves the device. */
  file: (base: string, sha256: string) => call(base, '/v1/file', json({ sha256 }), TIMEOUTS.file, isFileLookup),
  analyze: (
    base: string,
    body: { kind: 'page' | 'message'; url?: string; title?: string; text: string; forms?: Partial<FormSummary>; localFindings?: string[] },
  ) => call(base, '/v1/analyze', json(body), TIMEOUTS.analyze, isAiAnalysis),
};
