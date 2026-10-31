import type { DownloadAssessment } from '../../engine/download.js';
import type { ReputationSummary, RiskAssessment, Verdict } from '../../shared/types.js';

/**
 * Ephemeral state kept in chrome.storage.session (memory only, cleared when the browser closes).
 * Nothing here is written to disk; no browsing history is kept beyond the open tabs.
 */

export interface TabState {
  url: string;
  assessment: RiskAssessment;
  reputationPending: boolean;
  redirectedFrom?: string;
  updatedAt: number;
}

const REP_TTL_CLEAN_MS = 30 * 60_000;
const REP_TTL_MATCH_MS = 60 * 60_000;
const REP_TTL_FAILURE_MS = 60_000;
const MAX_REP_ENTRIES = 400;

async function sha256(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

export async function getTabState(tabId: number): Promise<TabState | undefined> {
  const key = `tab:${tabId}`;
  const r = await chrome.storage.session.get(key);
  return r[key] as TabState | undefined;
}

export async function setTabState(tabId: number, state: TabState): Promise<void> {
  await chrome.storage.session.set({ [`tab:${tabId}`]: state });
}

export async function clearTabState(tabId: number, includeSafe = false): Promise<void> {
  await chrome.storage.session.remove(includeSafe ? [`tab:${tabId}`, `safe:${tabId}`] : `tab:${tabId}`);
}

interface RepEntry {
  summary: ReputationSummary;
  expires: number;
}

/** Reputation cache keyed by a hash of the lookup URL, so raw URLs are not used as keys. */
export async function getCachedReputation(lookupUrl: string): Promise<ReputationSummary | undefined> {
  const key = `rep:${await sha256(lookupUrl)}`;
  const r = await chrome.storage.session.get(key);
  const e = r[key] as RepEntry | undefined;
  if (!e) return undefined;
  if (e.expires < Date.now()) {
    await chrome.storage.session.remove(key);
    return undefined;
  }
  return e.summary;
}

export async function setCachedReputation(lookupUrl: string, summary: ReputationSummary): Promise<void> {
  const hasMatch = summary.findings.some((f) => f.status === 'match');
  const ttl = hasMatch ? REP_TTL_MATCH_MS : summary.status === 'checked' ? REP_TTL_CLEAN_MS : REP_TTL_FAILURE_MS;
  const key = `rep:${await sha256(lookupUrl)}`;
  await chrome.storage.session.set({ [key]: { summary, expires: Date.now() + ttl } satisfies RepEntry });
  void pruneReputation();
}

async function pruneReputation(): Promise<void> {
  const all = await chrome.storage.session.get(null);
  const entries = Object.entries(all).filter(([k]) => k.startsWith('rep:')) as Array<[string, RepEntry]>;
  const now = Date.now();
  const expired = entries.filter(([, e]) => e.expires < now).map(([k]) => k);
  const live = entries.filter(([, e]) => e.expires >= now).sort((a, b) => a[1].expires - b[1].expires);
  const overflow = live.slice(0, Math.max(0, live.length - MAX_REP_ENTRIES)).map(([k]) => k);
  if (expired.length || overflow.length) await chrome.storage.session.remove([...expired, ...overflow]);
}

/** Temporary "continue anyway" bypass for a host, chosen by the user on the warning page. */
export async function addBypass(host: string, minutes = 30): Promise<void> {
  await chrome.storage.session.set({ [`bypass:${host}`]: Date.now() + minutes * 60_000 });
}

export async function isBypassed(host: string): Promise<boolean> {
  const key = `bypass:${host}`;
  const r = await chrome.storage.session.get(key);
  return typeof r[key] === 'number' && (r[key] as number) > Date.now();
}

export async function stashWarning(assessment: RiskAssessment, committed: boolean): Promise<string> {
  const id = crypto.randomUUID();
  await chrome.storage.session.set({ [`warn:${id}`]: { assessment, committed, createdAt: Date.now() } });
  return id;
}

export async function readWarning(id: string): Promise<{ assessment: RiskAssessment; committed: boolean } | undefined> {
  const key = `warn:${id}`;
  const r = await chrome.storage.session.get(key);
  return r[key] as { assessment: RiskAssessment; committed: boolean } | undefined;
}

/** Last page in this tab that did not trigger a warning, used by "Go back to safety". Session-only. */
export async function setLastSafeUrl(tabId: number, url: string): Promise<void> {
  await chrome.storage.session.set({ [`safe:${tabId}`]: url });
}

export async function takeLastSafeUrl(tabId: number): Promise<string | undefined> {
  const key = `safe:${tabId}`;
  const r = await chrome.storage.session.get(key);
  return typeof r[key] === 'string' ? (r[key] as string) : undefined;
}

/** Download Guard decisions for this browser session (file name and host only, never full URLs). */
export interface DownloadRecord {
  id: number;
  filename: string;
  host: string;
  verdict: Verdict;
  score: number;
  headline: string;
  intervened: boolean;
  /** What happened: still waiting on the user, kept, cancelled or deleted. */
  outcome: 'pending' | 'kept' | 'cancelled' | 'deleted' | 'allowed';
  at: number;
}

const MAX_DOWNLOAD_RECORDS = 25;

export async function saveDownload(record: DownloadRecord, assessment: DownloadAssessment): Promise<void> {
  const list = (await listDownloads()).filter((r) => r.id !== record.id);
  list.unshift(record);
  const removed = list.splice(MAX_DOWNLOAD_RECORDS);
  await chrome.storage.session.set({ downloads: list, [`dl:${record.id}`]: assessment });
  if (removed.length) await chrome.storage.session.remove(removed.map((r) => `dl:${r.id}`));
}

export async function listDownloads(): Promise<DownloadRecord[]> {
  const { downloads } = await chrome.storage.session.get('downloads');
  return Array.isArray(downloads) ? (downloads as DownloadRecord[]) : [];
}

export async function getDownload(id: number): Promise<{ record: DownloadRecord; assessment: DownloadAssessment } | undefined> {
  const record = (await listDownloads()).find((r) => r.id === id);
  const key = `dl:${id}`;
  const assessment = (await chrome.storage.session.get(key))[key] as DownloadAssessment | undefined;
  return record && assessment ? { record, assessment } : undefined;
}

export async function setDownloadOutcome(id: number, outcome: DownloadRecord['outcome']): Promise<void> {
  const list = await listDownloads();
  const r = list.find((x) => x.id === id);
  if (!r) return;
  r.outcome = outcome;
  await chrome.storage.session.set({ downloads: list });
}
