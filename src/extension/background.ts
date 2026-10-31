import { assessDownload } from '../engine/download.js';
import { assess, findMentionedBrands, isOfficialFor, lookupUrl, parseUrl } from '../engine/index.js';
import type { ReputationSummary, RiskAssessment, Verdict } from '../shared/types.js';
import { api, TIMEOUTS } from './lib/api.js';
import type { BgRequest, BgResponse, DownloadAction, DownloadView, GuardInfo } from './lib/messages.js';
import { getSettings, getTrustedDomains, setTrusted, type Settings } from './lib/settings.js';
import {
  addBypass,
  clearTabState,
  getCachedReputation,
  getDownload,
  getTabState,
  isBypassed,
  listDownloads,
  saveDownload,
  setCachedReputation,
  setDownloadOutcome,
  setLastSafeUrl,
  setTabState,
  stashWarning,
  takeLastSafeUrl,
} from './lib/state.js';

/**
 * Background service worker.
 *  - Runs local URL checks for every top-level navigation (no network).
 *  - Optionally asks the configured PhishShield API for reputation (URL without query string).
 *  - Shows a full-page warning for high-risk verdicts, and a toolbar badge otherwise.
 *  - Download Guard: pauses risky downloads and asks the user (file name, source and type only).
 *  - Keeps the static ad / malvertising rulesets in line with settings.
 * It never reads page content automatically and never submits forms or redirects silently.
 */

const BADGE: Record<Verdict, { text: string; color: string }> = {
  no_known_threats: { text: '', color: '#0E7490' },
  suspicious: { text: '!', color: '#B45309' },
  likely_phishing: { text: '!!', color: '#C2410C' },
  confirmed_malicious: { text: 'X', color: '#B91C1C' },
  inconclusive: { text: '?', color: '#475569' },
};

const pendingInitialUrl = new Map<number, string>();
/** A scan still marked pending after this long was interrupted (e.g. the service worker was stopped mid-lookup). */
const STALE_PENDING_MS = TIMEOUTS.reputation + 4000;

function isWebUrl(url: string): boolean {
  return /^https?:\/\//i.test(url);
}

function warnsFor(verdict: Verdict, settings: Settings): boolean {
  if (settings.protectionLevel === 'off') return false;
  if (verdict === 'confirmed_malicious') return true;
  return settings.protectionLevel === 'likely' && verdict === 'likely_phishing';
}

async function setBadge(tabId: number, verdict: Verdict | null): Promise<void> {
  try {
    const b = verdict ? BADGE[verdict] : { text: '', color: '#0E7490' };
    await chrome.action.setBadgeText({ tabId, text: b.text });
    if (b.text) await chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
    const title = verdict ? `PhishShield AI: ${verdict.replace(/_/g, ' ')}` : 'PhishShield AI';
    await chrome.action.setTitle({ tabId, title });
  } catch {
    /* tab may have closed */
  }
}

async function fetchReputation(url: string, settings: Settings, deep = false): Promise<ReputationSummary> {
  const parsed = parseUrl(url);
  if (!parsed.ok) return { status: 'skipped', findings: [] };
  if (parsed.isPrivateOrLocal) return { status: 'skipped', findings: [], note: 'Local addresses are not sent for reputation checks.' };
  if (!settings.apiBaseUrl) return { status: 'not_configured', findings: [], note: 'Local-only mode: no PhishShield API configured.' };
  if (!settings.autoReputation) return { status: 'skipped', findings: [], note: 'Automatic reputation checks are turned off in settings.' };
  const key = lookupUrl(parsed);
  // Deep results (with on-demand providers such as VirusTotal) are cached separately.
  const cacheKey = deep ? `deep|${key}` : key;
  const cached = await getCachedReputation(cacheKey);
  if (cached) return cached;
  const r = await api.reputation(settings.apiBaseUrl, key, deep);
  const summary: ReputationSummary = r.ok ? r.data : { status: 'unavailable', findings: [], note: r.message };
  await setCachedReputation(cacheKey, summary);
  return summary;
}

async function showWarning(tabId: number, assessment: RiskAssessment, committed: boolean): Promise<void> {
  const id = await stashWarning(assessment, committed);
  await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`warning/warning.html#${id}`) });
}

async function scanTab(tabId: number, url: string, opts: { redirectedFrom?: string; allowWarning: boolean }): Promise<RiskAssessment> {
  const [settings, trustedDomains] = await Promise.all([getSettings(), getTrustedDomains()]);
  const local = assess(url, { trustedDomains });
  await setTabState(tabId, { url, assessment: local, reputationPending: true, redirectedFrom: opts.redirectedFrom, updatedAt: Date.now() });
  await setBadge(tabId, local.verdict);

  const reputation = await fetchReputation(url, settings);
  const full = assess(url, { trustedDomains, reputation });
  if (opts.redirectedFrom) {
    full.signals.push({
      id: 'nav.redirected',
      source: 'local_url',
      category: 'informational',
      strength: 'contextual',
      weight: 0,
      title: 'Arrived via redirect',
      detail: `You were redirected here from ${opts.redirectedFrom}. PhishShield checked the final destination.`,
    });
  }

  // The user may have navigated away while reputation was loading.
  const current = await getTabState(tabId);
  if (!current || current.url !== url) return full;
  await setTabState(tabId, { url, assessment: full, reputationPending: false, redirectedFrom: opts.redirectedFrom, updatedAt: Date.now() });
  await setBadge(tabId, full.verdict);

  const host = parseUrl(url);
  if (opts.allowWarning && warnsFor(full.verdict, settings) && host.ok && !(await isBypassed(host.host))) {
    await showWarning(tabId, full, true);
  } else if (!warnsFor(full.verdict, settings)) {
    await setLastSafeUrl(tabId, url);
  }
  return full;
}

// ---- Navigation listeners ------------------------------------------------------

chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId !== 0 || !isWebUrl(d.url)) return;
  pendingInitialUrl.set(d.tabId, d.url);
  void (async () => {
    const settings = await getSettings();
    if (settings.protectionLevel === 'off') return;
    const p = parseUrl(d.url);
    if (!p.ok || (await isBypassed(p.host))) return;
    // Fast path: local checks plus any cached reputation, before the page loads.
    const cached = await getCachedReputation(lookupUrl(p));
    const reputation = cached ?? (settings.apiBaseUrl && settings.autoReputation && !p.isPrivateOrLocal ? { status: 'pending' as const, findings: [] } : undefined);
    const a = assess(d.url, { trustedDomains: await getTrustedDomains(), reputation });
    if (warnsFor(a.verdict, settings)) await showWarning(d.tabId, a, false);
  })();
});

chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return;
  if (!isWebUrl(d.url)) {
    void clearTabState(d.tabId);
    void setBadge(d.tabId, null);
    return;
  }
  const initial = pendingInitialUrl.get(d.tabId);
  pendingInitialUrl.delete(d.tabId);
  let redirectedFrom: string | undefined;
  if (initial && d.transitionQualifiers.includes('server_redirect')) {
    const a = parseUrl(initial);
    const b = parseUrl(d.url);
    if (a.ok && b.ok && a.host !== b.host) redirectedFrom = a.host;
  }
  void scanTab(d.tabId, d.url, { redirectedFrom, allowWarning: true });
});

chrome.webNavigation.onHistoryStateUpdated.addListener((d) => {
  if (d.frameId !== 0 || !isWebUrl(d.url)) return;
  void scanTab(d.tabId, d.url, { allowWarning: true });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  pendingInitialUrl.delete(tabId);
  void clearTabState(tabId, true);
});

// ---- Credential Guard registration (optional host permission) -----------------

const GUARD_ID = 'phishshield-guard';
const ALL_SITES = ['https://*/*', 'http://*/*'];

async function syncGuard(): Promise<void> {
  const settings = await getSettings();
  const granted = await chrome.permissions.contains({ origins: ALL_SITES });
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [GUARD_ID] });
  if (settings.credentialGuard && granted) {
    if (!existing.length) {
      await chrome.scripting.registerContentScripts([
        { id: GUARD_ID, matches: ALL_SITES, js: ['content/guard.js'], runAt: 'document_idle', allFrames: false, persistAcrossSessions: true },
      ]);
    }
  } else if (existing.length) {
    await chrome.scripting.unregisterContentScripts({ ids: [GUARD_ID] });
  }
}

chrome.runtime.onInstalled.addListener(() => void syncGuard().then(syncRulesets));
chrome.runtime.onStartup.addListener(() => void syncGuard().then(syncRulesets));
chrome.permissions.onRemoved.addListener(() => void syncGuard());

async function guardCheck(sender: chrome.runtime.MessageSender, title: string): Promise<GuardInfo> {
  const url = sender.tab?.url ?? sender.url ?? '';
  const p = parseUrl(url);
  if (!p.ok) return { warn: false, host: '' };
  const state = sender.tab?.id !== undefined ? await getTabState(sender.tab.id) : undefined;
  const a = state && state.url === url ? state.assessment : assess(url, { trustedDomains: await getTrustedDomains() });
  if (['suspicious', 'likely_phishing', 'confirmed_malicious'].includes(a.verdict)) {
    return { warn: true, verdict: a.verdict, host: p.unicodeHost, reason: a.headline };
  }
  if ((await getTrustedDomains()).includes(p.registrableDomain ?? '')) return { warn: false, host: p.unicodeHost };
  // Page title claims a brand that this domain does not belong to.
  const brand = findMentionedBrands(title.slice(0, 200), '').find((b) => !isOfficialFor(b, p.registrableDomain, p.publicSuffix));
  if (brand) {
    return {
      warn: true,
      host: p.unicodeHost,
      reason: `This page calls itself "${brand.name}" but is not on an official ${brand.name} domain.`,
      officialHint: brand.domains.slice(0, 2).join(' or '),
    };
  }
  return { warn: false, host: p.unicodeHost };
}

// ---- Network blocking (static declarativeNetRequest rulesets) ------------------

async function syncRulesets(): Promise<void> {
  const s = await getSettings();
  const enableRulesetIds: string[] = [];
  const disableRulesetIds: string[] = [];
  (s.blockMalvertising ? enableRulesetIds : disableRulesetIds).push('malvertising');
  (s.blockAds ? enableRulesetIds : disableRulesetIds).push('ads');
  try {
    await chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds, disableRulesetIds });
  } catch (e) {
    console.warn('[phishshield] could not update rulesets', e);
  }
}

// ---- Download Guard -------------------------------------------------------------

const guardedDownloads = new Set<number>();

async function guardDownload(item: chrome.downloads.DownloadItem, reason: 'created' | 'danger'): Promise<void> {
  const settings = await getSettings();
  if (!settings.downloadGuard || item.byExtensionId === chrome.runtime.id) return;
  if (reason === 'created' && guardedDownloads.has(item.id)) return;
  const a = assessDownload(
    { filename: item.filename, url: item.url, finalUrl: item.finalUrl, referrer: item.referrer, mime: item.mime, fileSize: item.fileSize, danger: item.danger },
    { trustedDomains: await getTrustedDomains() },
  );
  if (!a.filename) return;
  await saveDownload(
    { id: item.id, filename: a.filename, host: a.sourceHost || a.referrerHost, verdict: a.verdict, score: a.score, headline: a.headline, intervened: a.intervene, outcome: a.intervene ? 'pending' : 'allowed', at: Date.now() },
    a,
  );
  if (!a.intervene || guardedDownloads.has(item.id)) return;
  guardedDownloads.add(item.id);
  try {
    await chrome.downloads.pause(item.id);
  } catch {
    /* already complete or not pausable: the page offers to delete it instead */
  }
  await chrome.tabs.create({ url: chrome.runtime.getURL(`download/download.html#${item.id}`), active: true });
}

// Risky downloads are paused before suggest() releases the file name, so the pause lands as early as
// possible. Files whose bytes have all arrived (tiny files) can't be paused; the Download Guard page
// then offers to delete them. The name is never changed, and a 3 s cap stops a slow check from holding
// a download.
chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    suggest();
  };
  setTimeout(release, 3000);
  void guardDownload(item, 'created').finally(release);
  return true;
});

chrome.downloads.onChanged.addListener((delta) => {
  // Re-check when Chrome attaches a Safe Browsing danger verdict after the download started.
  const danger = delta.danger?.current;
  if (!danger || danger === 'safe' || danger === 'accepted') return;
  void chrome.downloads.search({ id: delta.id }).then(([item]) => item && guardDownload(item, 'danger'));
});

async function downloadView(id: number): Promise<DownloadView | undefined> {
  const saved = await getDownload(id);
  if (!saved) return undefined;
  const [item] = await chrome.downloads.search({ id });
  return {
    ...saved,
    ...(item ? { live: { state: item.state, paused: item.paused, exists: item.exists, bytesReceived: item.bytesReceived, totalBytes: item.totalBytes, url: item.finalUrl || item.url } } : {}),
  };
}

async function downloadAction(id: number, action: DownloadAction): Promise<void> {
  const [item] = await chrome.downloads.search({ id });
  if (!item) return;
  if (action === 'resume') {
    if (item.state === 'in_progress' && item.paused) await chrome.downloads.resume(id);
    await setDownloadOutcome(id, 'kept');
  } else if (action === 'cancel') {
    if (item.state === 'in_progress') await chrome.downloads.cancel(id);
    await setDownloadOutcome(id, 'cancelled');
  } else if (action === 'delete') {
    // Only ever the file this download created, and only when the user clicks "Delete file".
    if (item.state === 'in_progress') await chrome.downloads.cancel(id);
    else if (item.state === 'complete' && item.exists) await chrome.downloads.removeFile(id);
    await setDownloadOutcome(id, 'deleted');
  } else if (action === 'show' && item.state === 'complete' && item.exists) {
    chrome.downloads.show(id);
  }
}

// ---- Messages -------------------------------------------------------------------

chrome.runtime.onMessage.addListener((msg: BgRequest, sender, sendResponse: (r: BgResponse) => void) => {
  const fromExtensionPage = sender.id === chrome.runtime.id && !sender.tab?.url?.match(/^https?:/);
  const fromOwnContentScript = sender.id === chrome.runtime.id && !!sender.tab;
  void (async (): Promise<BgResponse> => {
    switch (msg?.type) {
      case 'guard-check':
        if (!fromOwnContentScript) return { ok: false, error: 'forbidden' };
        return { ok: true, guard: await guardCheck(sender, String(msg.title ?? '')) };
      case 'get-tab-state': {
        if (!fromExtensionPage) return { ok: false, error: 'forbidden' };
        const state = await getTabState(msg.tabId);
        const stale = state?.reputationPending && Date.now() - state.updatedAt > STALE_PENDING_MS;
        if (state && !stale && (!msg.url || state.url === msg.url)) return { ok: true, state };
        if (msg.url && isWebUrl(msg.url)) {
          await scanTab(msg.tabId, msg.url, { allowWarning: false });
          return { ok: true, state: await getTabState(msg.tabId) };
        }
        return { ok: true };
      }
      case 'rescan-tab':
        if (!fromExtensionPage) return { ok: false, error: 'forbidden' };
        await scanTab(msg.tabId, msg.url, { allowWarning: false });
        return { ok: true, state: await getTabState(msg.tabId) };
      case 'scan-url': {
        if (!fromExtensionPage) return { ok: false, error: 'forbidden' };
        const settings = await getSettings();
        const trustedDomains = await getTrustedDomains();
        const local = assess(msg.url, { allowSchemeless: true, trustedDomains });
        if (!local.url) return { ok: true, assessment: local };
        const reputation = settings.apiBaseUrl ? await fetchReputation(local.url, { ...settings, autoReputation: true }, msg.deep === true) : undefined;
        return { ok: true, assessment: assess(msg.url, { allowSchemeless: true, trustedDomains, reputation }) };
      }
      case 'set-content-assessment': {
        if (!fromExtensionPage) return { ok: false, error: 'forbidden' };
        const state = await getTabState(msg.tabId);
        if (state && state.url === msg.assessment.url) {
          await setTabState(msg.tabId, { ...state, assessment: msg.assessment, updatedAt: Date.now() });
          await setBadge(msg.tabId, msg.assessment.verdict);
        }
        return { ok: true };
      }
      case 'bypass-and-continue': {
        if (!fromExtensionPage) return { ok: false, error: 'forbidden' };
        const p = parseUrl(msg.url);
        if (!p.ok) return { ok: false, error: 'invalid url' };
        await addBypass(p.host);
        if (msg.trust && p.registrableDomain) await setTrusted(p.registrableDomain, true);
        await chrome.tabs.update(msg.tabId, { url: p.href });
        return { ok: true };
      }
      case 'go-back-safe': {
        if (!fromExtensionPage) return { ok: false, error: 'forbidden' };
        const safe = await takeLastSafeUrl(msg.tabId);
        await chrome.tabs.update(msg.tabId, { url: safe ?? 'chrome://newtab/' });
        return { ok: true };
      }
      case 'settings-changed':
        if (!fromExtensionPage) return { ok: false, error: 'forbidden' };
        await syncGuard();
        await syncRulesets();
        return { ok: true };
      case 'list-downloads':
        if (!fromExtensionPage) return { ok: false, error: 'forbidden' };
        return { ok: true, downloads: await listDownloads() };
      case 'get-download': {
        if (!fromExtensionPage) return { ok: false, error: 'forbidden' };
        const view = await downloadView(msg.id);
        return view ? { ok: true, download: view } : { ok: false, error: 'not found' };
      }
      case 'download-action':
        if (!fromExtensionPage) return { ok: false, error: 'forbidden' };
        await downloadAction(msg.id, msg.action);
        return { ok: true, download: await downloadView(msg.id) };
      default:
        return { ok: false, error: 'unknown message' };
    }
  })()
    .then(sendResponse)
    .catch((e: unknown) => sendResponse({ ok: false, error: e instanceof Error ? e.message : 'error' }));
  return true;
});
