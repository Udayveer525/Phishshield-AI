import { analyzeText, assess, assessUpi, computeScore, decideVerdict, extractUpiLinks, extractUrls, lookupUrl, parseUrl, type UpiAssessment } from '../../engine/index.js';
import { analyzeQrPayload, type QrAnalysis } from '../../engine/qr.js';
import { redactSensitive } from '../../shared/redact.js';
import type { AiAnalysis, PageSnapshot, RiskAssessment, Verdict } from '../../shared/types.js';
import { extractPageSnapshot } from '../content/extract.js';
import { api, type Health } from '../lib/api.js';
import { decodeQrFromDataUrl } from '../lib/qr-decode.js';
import { sendBg } from '../lib/messages.js';
import { getSettings, getTrustedDomains, saveSettings, setTrusted, type Settings } from '../lib/settings.js';
import { append, clear, el, icon } from '../ui/dom.js';
import { VERDICT_LABEL, t, type Lang } from '../ui/i18n.js';
import { aiBlock, renderAssessment, speak } from '../ui/render.js';
import { renderQr, renderUpi } from '../ui/render-tools.js';

type TabKey = 'site' | 'scan' | 'message' | 'tools';

const state = {
  lang: 'en' as Lang,
  settings: null as Settings | null,
  active: 'site' as TabKey,
  health: undefined as Health | null | undefined,
  tab: null as { id: number; url: string } | null,
  site: null as RiskAssessment | null,
  repPending: false,
  snapshot: null as PageSnapshot | null,
  aiPending: false,
  busy: '' as string,
  error: '' as string,
  trusted: [] as string[],
  scan: { input: '', result: null as RiskAssessment | null, busy: false },
  message: {
    input: '',
    busy: false,
    links: [] as RiskAssessment[],
    textVerdict: null as Verdict | null,
    textSignals: [] as ReturnType<typeof analyzeText>,
    ai: null as AiAnalysis | null,
    aiPending: false,
    done: false,
    upi: [] as UpiAssessment[],
  },
  tools: { qrBusy: false, qr: null as QrAnalysis | null, qrError: '' },
  /** Requests blocked on the current tab by the static rulesets (null = unknown). */
  blocked: null as { malvertising: number; ads: number } | null,
};

const root = document.getElementById('app')!;

// ---------------------------------------------------------------------------------------------
// Rendering

function render(): void {
  const lang = state.lang;
  document.documentElement.lang = lang === 'hi' ? 'hi' : 'en';
  clear(root);

  const header = el(
    'header',
    { class: 'top' },
    el('div', { class: 'brand' }, el('span', { class: 'brand-mark' }, icon('shield', 18)), el('span', { class: 'brand-name' }, 'PhishShield'), el('span', { class: 'brand-ai' }, 'AI')),
    el(
      'div',
      { class: 'top-actions' },
      el('button', { class: 'icon-btn lang-btn', title: 'Language / भाषा', onclick: toggleLang, 'aria-label': 'Switch language' }, lang === 'en' ? 'हिं' : 'EN'),
      el('button', { class: 'icon-btn', title: 'Settings', 'aria-label': 'Settings', onclick: () => chrome.runtime.openOptionsPage() }, icon('settings', 17)),
    ),
  );

  const tabs: Array<[TabKey, string, string]> = [
    ['site', t('tab_site', lang), 'globe'],
    ['scan', t('tab_scan', lang), 'search'],
    ['message', t('tab_message', lang), 'message'],
    ['tools', t('tab_tools', lang), 'tools'],
  ];
  const nav = el(
    'nav',
    { class: 'tabs', role: 'tablist' },
    ...tabs.map(([k, label, ic]) =>
      el(
        'button',
        { class: `tab${state.active === k ? ' active' : ''}`, role: 'tab', 'aria-selected': state.active === k ? 'true' : 'false', onclick: () => switchTab(k) },
        icon(ic, 15),
        el('span', {}, label),
      ),
    ),
  );

  const banner =
    state.health === null && state.settings?.apiBaseUrl
      ? el('div', { class: 'banner off' }, icon('info', 14), ' ', t('api_offline', lang))
      : !state.settings?.apiBaseUrl
        ? el('div', { class: 'banner off' }, icon('info', 14), ' ', 'Local-only mode (no server configured).')
        : null;

  const main = el('main', { class: 'panel', role: 'tabpanel' });
  if (state.active === 'site') renderSite(main);
  if (state.active === 'scan') renderScan(main);
  if (state.active === 'message') renderMessage(main);
  if (state.active === 'tools') renderTools(main);

  const footer = el('footer', { class: 'foot' }, el('a', { href: 'https://cybercrime.gov.in/', target: '_blank', rel: 'noopener noreferrer' }, t('report', lang)));
  append(root, header, nav, banner, main, footer);
}

function errorBox(msg: string): HTMLElement {
  return el('div', { class: 'error', role: 'alert' }, icon('alert', 16), el('span', {}, msg));
}

function skeleton(label: string): HTMLElement {
  return el('div', { class: 'skeleton', 'aria-busy': 'true' }, el('div', { class: 'sk sk-head' }), el('div', { class: 'sk sk-line' }), el('div', { class: 'sk sk-line short' }), el('p', { class: 'muted small center' }, label));
}

function renderSite(main: HTMLElement): void {
  const lang = state.lang;
  if (!state.tab) {
    append(main, el('div', { class: 'empty' }, icon('shield', 30), el('p', {}, t('not_web', lang))));
    return;
  }
  if (!state.site) {
    append(main, skeleton(t('loading', lang)));
    return;
  }
  const a = state.site;
  append(main, renderAssessment(a, { lang, reputationPending: state.repPending, aiPending: state.aiPending }));

  if (state.error) append(main, errorBox(state.error));

  const isTrusted = !!a.registrableDomain && state.trusted.includes(a.registrableDomain);
  const actions = el(
    'div',
    { class: 'actions' },
    el(
      'button',
      { class: 'btn', onclick: analyzePage, disabled: !!state.busy, title: t('analyze_page_hint', lang) },
      icon('search', 15),
      state.busy === 'page' ? t('loading', lang) : t('analyze_page', lang),
    ),
    el(
      'button',
      { class: 'btn primary', onclick: deepAi, disabled: !!state.busy || state.aiPending, title: t('deep_ai_hint', lang) },
      icon('cpu', 15),
      state.aiPending ? t('loading', lang) : t('deep_ai', lang),
    ),
  );
  const secondary = el(
    'div',
    { class: 'actions secondary' },
    el('button', { class: 'link-btn', onclick: () => speak(a, lang) }, icon('volume', 14), t('listen', lang)),
    el('button', { class: 'link-btn', onclick: rescan }, icon('refresh', 14), t('rescan', lang)),
    a.verdict !== 'confirmed_malicious' && a.registrableDomain
      ? el('button', { class: 'link-btn', onclick: () => toggleTrust(a.registrableDomain!, !isTrusted) }, icon('shield', 14), isTrusted ? t('untrust_site', lang) : t('trust_site', lang))
      : null,
  );
  append(main, actions, el('p', { class: 'hint small muted' }, `${t('analyze_page_hint', lang)}. ${t('deep_ai_hint', lang)}.`), secondary);
  const b = state.blocked;
  if (b && b.malvertising + b.ads > 0) {
    append(
      main,
      el(
        'p',
        { class: 'note small' },
        icon('ban', 14),
        ` Blocked on this page: ${[b.malvertising ? `${b.malvertising} scam-ad request${b.malvertising === 1 ? '' : 's'}` : '', b.ads ? `${b.ads} ad/tracker request${b.ads === 1 ? '' : 's'}` : ''].filter(Boolean).join(', ')}.`,
      ),
    );
  }
}

function renderScan(main: HTMLElement): void {
  const lang = state.lang;
  const input = el('input', {
    class: 'input',
    type: 'text',
    inputmode: 'url',
    autocomplete: 'off',
    spellcheck: 'false',
    placeholder: t('scan_placeholder', lang),
    value: state.scan.input,
    'aria-label': t('tab_scan', lang),
    oninput: (e: Event) => (state.scan.input = (e.target as HTMLInputElement).value),
    onkeydown: (e: Event) => (e as KeyboardEvent).key === 'Enter' && void scanUrl(),
  });
  append(
    main,
    el('div', { class: 'row' }, input, el('button', { class: 'btn primary', onclick: scanUrl, disabled: state.scan.busy }, state.scan.busy ? '…' : t('scan', lang))),
    el('p', { class: 'hint small muted' }, t('scan_note', lang)),
  );
  if (state.scan.busy) append(main, skeleton(t('loading', lang)));
  else if (state.scan.result) append(main, renderAssessment(state.scan.result, { lang }));
  queueMicrotask(() => input.focus());
}

function verdictPill(v: Verdict, lang: Lang): HTMLElement {
  return el('span', { class: `pill v-${v}` }, VERDICT_LABEL[v][lang]);
}

function worst(verdicts: Verdict[]): Verdict {
  const order: Verdict[] = ['confirmed_malicious', 'likely_phishing', 'suspicious', 'inconclusive', 'no_known_threats'];
  return order.find((v) => verdicts.includes(v)) ?? 'no_known_threats';
}

function renderMessage(main: HTMLElement): void {
  const lang = state.lang;
  const m = state.message;
  const ta = el('textarea', {
    class: 'input area',
    rows: 5,
    placeholder: t('message_placeholder', lang),
    'aria-label': t('tab_message', lang),
    oninput: (e: Event) => (m.input = (e.target as HTMLTextAreaElement).value),
  });
  ta.value = m.input;
  append(
    main,
    ta,
    el(
      'div',
      { class: 'actions' },
      el('button', { class: 'btn primary', onclick: checkMessage, disabled: m.busy }, icon('search', 15), m.busy ? t('loading', lang) : t('check_message', lang)),
      el('button', { class: 'btn', onclick: explainMessage, disabled: m.aiPending || !m.input.trim() }, icon('cpu', 15), m.aiPending ? t('loading', lang) : t('explain_ai', lang)),
    ),
  );
  if (m.busy) {
    append(main, skeleton(t('loading', lang)));
    return;
  }
  if (!m.done) return;

  const overall = worst([m.textVerdict ?? 'no_known_threats', ...m.links.map((l) => l.verdict), ...m.upi.map((u) => u.verdict)]);
  append(
    main,
    el('div', { class: `verdict v-${overall}` }, el('div', { class: 'verdict-icon' }, icon(overall === 'no_known_threats' ? 'shield-dot' : 'shield-alert', 24)), el('div', { class: 'verdict-text' }, el('div', { class: 'verdict-label' }, VERDICT_LABEL[overall][lang]), el('div', { class: 'verdict-host' }, `${m.links.length} link(s) · ${m.textSignals.length} tactic(s)`))),
    el(
      'section',
      { class: 'block' },
      el('h3', {}, t('message_tactics', lang)),
      m.textSignals.length
        ? el('ul', { class: 'findings' }, ...m.textSignals.map((s) => el('li', { class: `finding s-${s.strength}` }, el('div', { class: 'finding-head' }, el('span', { class: 'finding-title' }, s.title)), el('div', { class: 'finding-detail' }, s.detail), ...(s.evidence ?? []).slice(0, 1).map((e) => el('blockquote', {}, e)))))
        : el('p', { class: 'muted small' }, t('no_findings', lang)),
    ),
    el(
      'section',
      { class: 'block' },
      el('h3', {}, t('links_found', lang)),
      m.links.length
        ? el(
            'div',
            { class: 'links' },
            ...m.links.map((l) =>
              el(
                'details',
                { class: 'link-item' },
                el('summary', {}, verdictPill(l.verdict, lang), el('span', { class: 'mono link-host' }, l.displayHost || l.input)),
                renderAssessment(l, { lang, compact: true }),
              ),
            ),
          )
        : el('p', { class: 'muted small' }, t('no_links', lang)),
    ),
  );
  if (m.upi.length) {
    append(main, el('section', { class: 'block' }, el('h3', {}, t('upi_found', lang)), ...m.upi.map((u) => renderUpi(u))));
  }
  if (m.ai) {
    const block = aiBlock(m.ai, lang);
    append(main, block ?? errorBox(m.ai.message ?? 'AI analysis unavailable.'));
  }
}

function renderTools(main: HTMLElement): void {
  const lang = state.lang;
  const tl = state.tools;
  const s = state.settings;
  const center = (hash: string) => () => void chrome.tabs.create({ url: chrome.runtime.getURL(`center/center.html#${hash}`) });
  const shield = (label: string, on: boolean, key: 'blockMalvertising' | 'blockAds', count?: number) =>
    el(
      'label',
      { class: 'tool-toggle' },
      el('span', {}, el('span', { class: 'strong' }, label), count ? el('span', { class: 'muted small' }, ` · ${count} blocked here`) : null),
      el('input', {
        type: 'checkbox',
        class: 'switch',
        checked: on,
        'aria-label': label,
        onchange: async (e: Event) => {
          state.settings = await saveSettings({ [key]: (e.target as HTMLInputElement).checked });
          await sendBg({ type: 'settings-changed' }).catch(() => undefined);
          render();
        },
      }),
    );

  append(
    main,
    el(
      'section',
      { class: 'block tool-first' },
      el('button', { class: 'btn primary wide', onclick: scanScreenQr, disabled: tl.qrBusy }, icon('qr', 16), tl.qrBusy ? t('loading', lang) : t('scan_qr_screen', lang)),
      el('p', { class: 'hint small muted' }, t('scan_qr_hint', lang)),
      tl.qrError ? errorBox(tl.qrError) : null,
      tl.qr ? renderQr(tl.qr, lang) : null,
    ),
    el(
      'section',
      { class: 'block' },
      el('h3', {}, 'Security Center'),
      el(
        'div',
        { class: 'tool-grid' },
        el('button', { class: 'tool', onclick: center('file') }, icon('file', 18), el('span', {}, 'Scan a file'), el('span', { class: 'muted small' }, 'APK, ZIP, PDF, Office')),
        el('button', { class: 'tool', onclick: center('qr') }, icon('qr', 18), el('span', {}, 'QR / UPI image'), el('span', { class: 'muted small' }, 'from a photo or screenshot')),
        el('button', { class: 'tool', onclick: center('password') }, icon('key', 18), el('span', {}, 'Password leak check'), el('span', { class: 'muted small' }, 'k-anonymity, never sent')),
        el('button', { class: 'tool', onclick: center('downloads') }, icon('download', 18), el('span', {}, 'Downloads'), el('span', { class: 'muted small' }, s?.downloadGuard ? 'Download Guard on' : 'Download Guard off')),
      ),
    ),
    el(
      'section',
      { class: 'block' },
      el('h3', {}, 'Shields'),
      shield('Scam-ad shield', !!s?.blockMalvertising, 'blockMalvertising', state.blocked?.malvertising),
      shield('Block ads & trackers', !!s?.blockAds, 'blockAds', state.blocked?.ads),
    ),
  );
}

async function scanScreenQr(): Promise<void> {
  const tl = state.tools;
  Object.assign(tl, { qrBusy: true, qrError: '', qr: null });
  render();
  try {
    // activeTab (granted by opening the popup) allows one screenshot of the visible tab. It is decoded here and discarded.
    const shot = await chrome.tabs.captureVisibleTab({ format: 'png' });
    const data = await decodeQrFromDataUrl(shot);
    if (!data) tl.qrError = 'No QR code found on the visible part of the page. Scroll it fully into view, or use the Security Center with a screenshot.';
    else tl.qr = analyzeQrPayload(data, { trustedDomains: state.trusted });
  } catch {
    tl.qrError = 'This page cannot be captured (browser pages and the Web Store are protected).';
  }
  tl.qrBusy = false;
  render();
}

async function loadBlocked(): Promise<void> {
  if (!state.tab) return;
  try {
    const { rulesMatchedInfo } = await chrome.declarativeNetRequest.getMatchedRules({ tabId: state.tab.id });
    state.blocked = {
      malvertising: rulesMatchedInfo.filter((r) => r.rule.rulesetId === 'malvertising').length,
      ads: rulesMatchedInfo.filter((r) => r.rule.rulesetId === 'ads').length,
    };
    render();
  } catch {
    state.blocked = null; // quota reached or no access to this tab
  }
}

// ---------------------------------------------------------------------------------------------
// Actions

function switchTab(k: TabKey): void {
  state.active = k;
  render();
}

async function toggleLang(): Promise<void> {
  state.lang = state.lang === 'en' ? 'hi' : 'en';
  state.settings = await saveSettings({ language: state.lang });
  render();
}

async function toggleTrust(domain: string, trust: boolean): Promise<void> {
  state.trusted = await setTrusted(domain, trust);
  await rescan();
}

async function loadSite(): Promise<void> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url || !/^https?:/i.test(tab.url)) {
    state.tab = null;
    render();
    return;
  }
  state.tab = { id: tab.id, url: tab.url };
  void loadBlocked();
  await refreshSiteState();
}

async function refreshSiteState(force = false): Promise<void> {
  if (!state.tab) return;
  const res = await sendBg(force ? { type: 'rescan-tab', tabId: state.tab.id, url: state.tab.url } : { type: 'get-tab-state', tabId: state.tab.id, url: state.tab.url });
  if (res.ok && res.state) {
    // Keep page-content and AI layers the user already ran in this popup.
    state.site = state.snapshot || state.site?.ai ? reassess(res.state.assessment.reputation) : res.state.assessment;
    state.repPending = res.state.reputationPending;
  } else if (!state.site) {
    state.site = assess(state.tab.url, { trustedDomains: state.trusted });
  }
  render();
  if (state.repPending) setTimeout(() => void refreshSiteState(), 700);
}

function reassess(reputation = state.site?.reputation): RiskAssessment {
  return assess(state.tab!.url, { reputation, page: state.snapshot ?? undefined, ai: state.site?.ai, trustedDomains: state.trusted });
}

async function rescan(): Promise<void> {
  state.error = '';
  await refreshSiteState(true);
}

async function captureSnapshot(): Promise<PageSnapshot | null> {
  if (!state.tab) return null;
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId: state.tab.id }, func: extractPageSnapshot, args: [8000] });
    const snap = res?.result as PageSnapshot | undefined;
    if (!snap || typeof snap.text !== 'string') throw new Error('no result');
    if (snap.url !== state.tab.url) state.tab.url = snap.url; // SPA navigation since popup opened
    return snap;
  } catch {
    state.error = t('page_protected', state.lang);
    return null;
  }
}

async function analyzePage(): Promise<void> {
  state.busy = 'page';
  state.error = '';
  render();
  const snap = await captureSnapshot();
  state.busy = '';
  if (snap) {
    state.snapshot = snap;
    state.site = reassess();
    void sendBg({ type: 'set-content-assessment', tabId: state.tab!.id, assessment: state.site });
  }
  render();
}

function confirmRemote(): Promise<boolean> {
  if (state.settings?.aiConsentRemembered) return Promise.resolve(true);
  const lang = state.lang;
  return new Promise((resolve) => {
    const remember = el('input', { type: 'checkbox', id: 'remember' });
    const close = (v: boolean) => {
      dialog.close();
      dialog.remove();
      if (v && remember.checked) void saveSettings({ aiConsentRemembered: true }).then((s) => (state.settings = s));
      resolve(v);
    };
    const dialog = el(
      'dialog',
      { class: 'dialog', 'aria-labelledby': 'dlg-title' },
      el('h2', { id: 'dlg-title' }, icon('lock', 16), ' ', t('consent_title', lang)),
      el('p', { class: 'small' }, t('consent_body', lang).replace('{provider}', state.health?.ai.provider ?? t('ai_provider_generic', lang))),
      el('label', { class: 'check small' }, remember, ' ', t('consent_remember', lang)),
      el('div', { class: 'actions' }, el('button', { class: 'btn', onclick: () => close(false) }, t('cancel', lang)), el('button', { class: 'btn primary', onclick: () => close(true) }, t('send', lang))),
    );
    dialog.addEventListener('cancel', () => close(false));
    document.body.append(dialog);
    dialog.showModal();
  });
}

async function deepAi(): Promise<void> {
  if (!state.tab || !state.site) return;
  const base = state.settings?.apiBaseUrl ?? '';
  if (!base) {
    state.site = { ...state.site, ai: { status: 'unavailable', message: 'No PhishShield server configured.' } };
    render();
    return;
  }
  if (!(await confirmRemote())) return;
  if (!state.snapshot) {
    const snap = await captureSnapshot();
    if (!snap) return render();
    state.snapshot = snap;
  }
  state.aiPending = true;
  state.error = '';
  state.site = reassess();
  render();
  const parsed = parseUrl(state.tab.url);
  const snap = state.snapshot;
  const res = await api.analyze(base, {
    kind: 'page',
    url: parsed.ok ? lookupUrl(parsed) : undefined,
    title: redactSensitive(snap.title),
    text: redactSensitive(snap.text),
    forms: snap.forms,
    localFindings: state.site.signals.filter((s) => s.weight > 0 && s.source !== 'ai').slice(0, 15).map((s) => s.title),
  });
  state.aiPending = false;
  const ai: AiAnalysis = res.ok ? res.data : { status: res.error === 'timeout' ? 'timeout' : res.error === 'rate_limited' ? 'rate_limited' : 'error', message: res.message };
  state.site = assess(state.tab.url, { reputation: state.site.reputation, page: snap, ai, trustedDomains: state.trusted });
  if (ai.status !== 'ok') state.error = ai.message ?? 'AI analysis failed. Local results are still valid.';
  void sendBg({ type: 'set-content-assessment', tabId: state.tab.id, assessment: state.site });
  render();
}

async function scanUrl(): Promise<void> {
  const input = state.scan.input.trim();
  if (!input) return;
  state.scan.busy = true;
  render();
  const res = await sendBg({ type: 'scan-url', url: input, deep: true });
  state.scan.busy = false;
  state.scan.result = res.ok && res.assessment ? res.assessment : assess(input, { allowSchemeless: true, trustedDomains: state.trusted });
  render();
}

async function checkMessage(): Promise<void> {
  const m = state.message;
  if (!m.input.trim()) return;
  m.busy = true;
  m.ai = null;
  render();
  m.textSignals = analyzeText(m.input);
  m.textVerdict = decideVerdict(computeScore(m.textSignals), { reputationMatch: false });
  m.upi = extractUpiLinks(m.input).map((u) => assessUpi(u)).filter((u): u is UpiAssessment => !!u);
  const urls = extractUrls(m.input, 6);
  const results = await Promise.all(urls.map((u) => sendBg({ type: 'scan-url', url: u })));
  m.links = results.map((r, i) => (r.ok && r.assessment ? r.assessment : assess(urls[i]!, { trustedDomains: state.trusted })));
  m.busy = false;
  m.done = true;
  render();
}

async function explainMessage(): Promise<void> {
  const m = state.message;
  const base = state.settings?.apiBaseUrl ?? '';
  if (!m.input.trim()) return;
  if (!m.done) await checkMessage();
  if (!base) {
    m.ai = { status: 'unavailable', message: 'No PhishShield server configured.' };
    return render();
  }
  if (!(await confirmRemote())) return;
  m.aiPending = true;
  render();
  const res = await api.analyze(base, {
    kind: 'message',
    text: redactSensitive(m.input).slice(0, 8000),
    localFindings: [...m.textSignals.map((s) => s.title), ...m.links.map((l) => `${l.displayHost}: ${l.verdict}`)].slice(0, 20),
  });
  m.aiPending = false;
  m.ai = res.ok ? res.data : { status: 'error', message: res.message };
  render();
}

// ---------------------------------------------------------------------------------------------

async function init(): Promise<void> {
  state.settings = await getSettings();
  state.lang = state.settings.language;
  state.trusted = await getTrustedDomains();
  render();
  void loadSite();
  if (state.settings.apiBaseUrl) {
    void api.health(state.settings.apiBaseUrl).then((h) => {
      state.health = h.ok ? h.data : null;
      render();
    });
  }
}

void init();
