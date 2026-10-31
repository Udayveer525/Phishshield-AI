import { describeAge, domainAgeDays, humanizeTactic } from '../../engine/index.js';
import type { AiAnalysis, BreachRecord, DomainInfo, ReputationFinding, RiskAssessment, Signal, SignalSource } from '../../shared/types.js';
import { el, icon, timeAgo } from './dom.js';
import { VERDICT_ACTION_HI, VERDICT_ICON, VERDICT_LABEL, t, type Lang } from './i18n.js';

export interface RenderOpts {
  lang: Lang;
  reputationPending?: boolean;
  aiPending?: boolean;
  compact?: boolean;
}

const SOURCE_LABEL: Record<SignalSource, string> = {
  local_url: 'Local · URL',
  local_content: 'Local · Page',
  local_file: 'Local · File',
  reputation: 'Reputation',
  registry: 'Registry · RDAP',
  ai: 'AI',
};

export function verdictHeader(a: RiskAssessment, lang: Lang): HTMLElement {
  return el(
    'div',
    { class: `verdict v-${a.verdict}` },
    el('div', { class: 'verdict-icon' }, icon(VERDICT_ICON[a.verdict], 26)),
    el(
      'div',
      { class: 'verdict-text' },
      el('div', { class: 'verdict-label' }, VERDICT_LABEL[a.verdict][lang]),
      el('div', { class: 'verdict-host', title: a.url || a.input }, a.displayHost || a.input.slice(0, 80) || '—'),
      a.displayHost && a.displayHost !== a.host ? el('div', { class: 'verdict-puny mono' }, a.host) : null,
    ),
  );
}

export function scoreMeter(a: RiskAssessment, lang: Lang): HTMLElement {
  const pct = Math.max(0, Math.min(100, a.score));
  return el(
    'div',
    { class: 'meter', title: t('score_note', lang) },
    el('div', { class: 'meter-row' }, el('span', { class: 'meter-label' }, t('risk_score', lang)), el('span', { class: 'meter-value' }, `${pct}`, el('span', { class: 'muted' }, ' / 100'))),
    el('div', { class: `meter-track v-${a.verdict}`, role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': pct, 'aria-label': t('risk_score', lang) }, el('div', { class: 'meter-fill', style: `width:${pct}%` })),
    el('div', { class: 'meter-note' }, t('score_note', lang)),
  );
}

function signalItem(s: Signal): HTMLElement {
  return el(
    'li',
    { class: `finding s-${s.strength}` },
    el('div', { class: 'finding-head' }, el('span', { class: 'finding-title' }, s.title), el('span', { class: `chip src-${s.source}` }, SOURCE_LABEL[s.source])),
    el('div', { class: 'finding-detail' }, s.detail),
  );
}

export function topFindings(a: RiskAssessment, lang: Lang, max = 4): HTMLElement {
  const counted = a.signals.filter((s) => s.weight > 0 && s.category !== 'informational');
  const notes = a.signals.filter((s) => s.id === 'url.official_domain' || s.id === 'nav.redirected');
  return el(
    'section',
    { class: 'block' },
    el('h3', {}, t('why', lang)),
    counted.length ? el('ul', { class: 'findings' }, ...counted.slice(0, max).map(signalItem)) : el('p', { class: 'muted small' }, t('no_findings', lang)),
    ...notes.map((n) => el('p', { class: 'note small' }, icon('info', 14), ' ', n.detail)),
  );
}

export function actionBox(a: RiskAssessment, lang: Lang): HTMLElement {
  return el(
    'div',
    { class: `action v-${a.verdict}` },
    el('div', { class: 'action-title' }, t('what_to_do', lang)),
    el('div', {}, lang === 'hi' ? VERDICT_ACTION_HI[a.verdict] : a.recommendedAction),
  );
}

function providerStatusText(f: ReputationFinding): { text: string; cls: string } {
  const d = f.detections;
  switch (f.status) {
    case 'match':
      if (d) return { text: `${d.malicious}/${d.total} engines: malicious`, cls: 'bad' };
      return { text: f.matchType === 'host' ? 'Host listed (other pages)' : `Listed: ${(f.threatTypes ?? ['malicious']).join(', ').toLowerCase().replace(/_/g, ' ')}`, cls: 'bad' };
    case 'no_match':
      if (d) return d.malicious + d.suspicious > 0 ? { text: `${d.malicious + d.suspicious}/${d.total} engines flag it`, cls: 'warn' } : { text: `0/${d.total} engines flag it`, cls: 'ok' };
      if (f.message && /no report|never seen/i.test(f.message)) return { text: 'No report yet', cls: 'off' };
      return { text: 'Not listed', cls: 'ok' };
    case 'timeout':
      return { text: 'Timed out', cls: 'warn' };
    case 'error':
      return { text: f.message ? `Unavailable: ${f.message}` : 'Unavailable', cls: 'warn' };
    case 'unconfigured':
      return { text: 'Not configured', cls: 'off' };
    default:
      return { text: f.message && f.message.length < 60 ? f.message : 'Skipped', cls: 'off' };
  }
}

/** Status line for the RDAP registration lookup. */
export function domainStatusText(info: DomainInfo | undefined): { text: string; cls: string } | null {
  if (!info) return null;
  if (info.status === 'found') {
    const days = domainAgeDays(info);
    if (days === null) return { text: 'Registration date not published', cls: 'off' };
    return { text: `Registered ${new Date(info.registeredAt!).toISOString().slice(0, 10)} (${describeAge(days)})`, cls: days < 30 ? 'bad' : days < 90 ? 'warn' : 'ok' };
  }
  if (info.status === 'not_found') return { text: 'Registry has no record', cls: 'warn' };
  if (info.status === 'unsupported') return { text: info.message ?? 'Registry has no RDAP service', cls: 'off' };
  return { text: info.status === 'timeout' ? 'Registry slow, try again' : 'Registry lookup failed', cls: 'warn' };
}

/** Public breaches of this organisation (HIBP). Context for the user, never a phishing verdict. */
export function breachBlock(breaches: BreachRecord[] | undefined, domain: string | null): HTMLElement | null {
  if (!breaches?.length) return null;
  return el(
    'section',
    { class: 'block breaches' },
    el('h3', {}, 'Breach history'),
    el('p', { class: 'small' }, `${domain ?? 'This organisation'} has had ${breaches.length === 1 ? 'a data breach' : `${breaches.length} data breaches`}. This does not mean this page is fake, but scammers use leaked details to make calls and messages look real.`),
    el(
      'ul',
      { class: 'findings' },
      ...breaches.slice(0, 3).map((b) =>
        el(
          'li',
          { class: 'finding' },
          el('div', { class: 'finding-head' }, el('span', { class: 'finding-title' }, b.title), el('span', { class: 'muted small' }, b.breachDate.slice(0, 7))),
          el('div', { class: 'finding-detail' }, `${b.pwnCount.toLocaleString('en-IN')} accounts · ${b.dataClasses.slice(0, 5).join(', ')}${b.isVerified ? '' : ' · unverified'}`),
        ),
      ),
    ),
    el('p', { class: 'meta small muted' }, 'Source: ', el('a', { href: 'https://haveibeenpwned.com/', target: '_blank', rel: 'noopener noreferrer' }, 'Have I Been Pwned'), ' (CC BY 4.0)'),
  );
}

function aiStatusText(ai: AiAnalysis | undefined, pending: boolean): { text: string; cls: string } {
  if (pending) return { text: 'Analysing…', cls: 'pending' };
  if (!ai) return { text: 'Not run (on demand)', cls: 'off' };
  switch (ai.status) {
    case 'ok':
      return { text: `Done · concern: ${ai.concern}`, cls: ai.concern === 'high' ? 'bad' : ai.concern === 'medium' ? 'warn' : 'ok' };
    case 'unavailable':
      return { text: 'Not configured on server', cls: 'off' };
    case 'refused':
      return { text: 'Model declined', cls: 'warn' };
    case 'timeout':
      return { text: 'Timed out', cls: 'warn' };
    case 'rate_limited':
      return { text: 'Rate limited, try later', cls: 'warn' };
    default:
      return { text: ai.message ?? 'Failed', cls: 'warn' };
  }
}

export function sourcesPanel(a: RiskAssessment, opts: RenderOpts): HTMLElement {
  const lang = opts.lang;
  const localCount = a.signals.filter((s) => (s.source === 'local_url' || s.source === 'local_content') && s.weight > 0).length;
  const localText = `${a.layers.localContent ? 'URL + page content' : 'URL rules'} · ${localCount} finding${localCount === 1 ? '' : 's'}`;

  const repRows: HTMLElement[] = [];
  if (opts.reputationPending) {
    repRows.push(el('div', { class: 'src-sub' }, el('span', {}, 'Providers'), el('span', { class: 'st pending' }, 'Checking…')));
  } else if (a.reputation.findings.length) {
    for (const f of a.reputation.findings) {
      const st = providerStatusText(f);
      repRows.push(
        el(
          'div',
          { class: 'src-sub', title: f.datasetUpdatedAt ? `Dataset updated ${new Date(f.datasetUpdatedAt).toLocaleString()}` : `Checked ${new Date(f.checkedAt).toLocaleString()}` },
          el('span', {}, f.providerName),
          el('span', { class: `st ${st.cls}` }, st.text, f.fromCache ? ' (cached)' : ''),
        ),
      );
    }
  } else {
    const label =
      a.reputation.status === 'not_configured'
        ? 'Not configured (local-only mode)'
        : a.reputation.status === 'skipped'
          ? a.reputation.note ?? 'Skipped'
          : a.reputation.status === 'pending'
            ? 'Not finished'
          : a.reputation.note ?? 'Unavailable';
    repRows.push(el('div', { class: 'src-sub' }, el('span', {}, 'Providers'), el('span', { class: `st ${a.reputation.status === 'unavailable' ? 'warn' : 'off'}` }, label)));
  }

  const ai = aiStatusText(a.ai, !!opts.aiPending);
  const reg = domainStatusText(a.reputation.domain);
  return el(
    'section',
    { class: 'block sources' },
    el('h3', {}, t('sources', lang)),
    el(
      'div',
      { class: 'src' },
      el('div', { class: 'src-head' }, icon('list', 16), el('span', {}, t('src_local', lang)), el('span', { class: 'st ok' }, localText)),
      el('div', { class: 'src-desc' }, t('local_desc', lang)),
    ),
    el('div', { class: 'src' }, el('div', { class: 'src-head' }, icon('database', 16), el('span', {}, t('src_reputation', lang))), ...repRows),
    reg
      ? el(
          'div',
          { class: 'src', title: a.reputation.domain?.registrar ? `Registrar: ${a.reputation.domain.registrar}` : '' },
          el('div', { class: 'src-head' }, icon('calendar', 16), el('span', {}, t('src_registry', lang)), el('span', { class: `st ${reg.cls}` }, reg.text)),
        )
      : null,
    el('div', { class: 'src' }, el('div', { class: 'src-head' }, icon('cpu', 16), el('span', {}, t('src_ai', lang)), el('span', { class: `st ${ai.cls}` }, ai.text))),
  );
}

export function aiBlock(ai: AiAnalysis, lang: Lang): HTMLElement | null {
  if (ai.status !== 'ok') return null;
  const summary = lang === 'hi' ? ai.summaryHi || ai.summaryEn : ai.summaryEn;
  return el(
    'section',
    { class: 'block ai' },
    el('div', { class: 'ai-label' }, icon('cpu', 14), ' ', t('ai_label', lang)),
    summary ? el('p', { class: 'ai-summary' }, summary) : null,
    ai.injectionAttemptDetected ? el('p', { class: 'note warn small' }, icon('alert', 14), ' The page contains text that tries to instruct AI tools. It was treated as evidence, not as instructions.') : null,
    ai.tactics?.length
      ? el(
          'ul',
          { class: 'tactics' },
          ...ai.tactics.map((x) =>
            el(
              'li',
              {},
              el('div', { class: 'finding-head' }, el('span', { class: 'finding-title' }, humanizeTactic(x.tactic)), el('span', { class: `chip ${x.grounded ? 'grounded' : 'ungrounded'}` }, x.grounded ? 'quoted from page' : 'unverified quote')),
              el('div', { class: 'finding-detail' }, x.explanation),
              x.evidenceQuote ? el('blockquote', {}, x.evidenceQuote) : null,
            ),
          ),
        )
      : null,
    ai.advice?.length ? el('ul', { class: 'advice' }, ...ai.advice.map((x) => el('li', {}, x))) : null,
    el('div', { class: 'meta small muted' }, `${ai.provider ?? 'AI'} · ${ai.model ?? ''}${ai.analyzedAt ? ` · ${timeAgo(ai.analyzedAt, lang)}` : ''}`),
  );
}

export function evidenceDetails(a: RiskAssessment, lang: Lang): HTMLElement {
  const groups: Array<[string, Signal[]]> = [
    ['Reputation', a.signals.filter((s) => s.source === 'reputation')],
    ['Local · URL', a.signals.filter((s) => s.source === 'local_url')],
    ['Local · Page content', a.signals.filter((s) => s.source === 'local_content')],
    ['Registry · RDAP', a.signals.filter((s) => s.source === 'registry')],
    ['AI (capped, cannot confirm)', a.signals.filter((s) => s.source === 'ai')],
  ];
  return el(
    'details',
    { class: 'evidence' },
    el('summary', {}, icon('chevron', 14, 'chev'), ' ', t('evidence', lang)),
    ...groups
      .filter(([, list]) => list.length)
      .map(([name, list]) =>
        el(
          'div',
          { class: 'ev-group' },
          el('div', { class: 'ev-group-title' }, name),
          ...list.map((s) =>
            el(
              'div',
              { class: 'ev' },
              el('div', { class: 'ev-head' }, el('code', {}, s.id), el('span', { class: 'muted' }, ` ${s.strength} · weight ${s.weight.toFixed(2)}`)),
              ...(s.evidence ?? []).map((e) => el('div', { class: 'ev-line mono' }, e)),
            ),
          ),
        ),
      ),
    el('div', { class: 'ev-group' }, el('div', { class: 'ev-group-title' }, t('limitations', lang)), el('ul', { class: 'limits' }, ...a.limitations.map((l) => el('li', {}, l)))),
    el(
      'div',
      { class: 'ev-group' },
      el('div', { class: 'ev-line mono' }, `url: ${a.url || a.input}`),
      a.registrableDomain ? el('div', { class: 'ev-line mono' }, `registrable domain: ${a.registrableDomain}`) : null,
      a.reputation.domain?.registrar ? el('div', { class: 'ev-line mono' }, `registrar: ${a.reputation.domain.registrar}`) : null,
      el('div', { class: 'ev-line mono' }, `verdict: ${a.verdict} · severity: ${a.severity} · score: ${a.score}`),
      el('div', { class: 'ev-line mono' }, `engine ${a.engineVersion} · ${new Date(a.analyzedAt).toLocaleString()}`),
    ),
  );
}

export function renderAssessment(a: RiskAssessment, opts: RenderOpts): HTMLElement {
  const lang = opts.lang;
  return el(
    'div',
    { class: 'assessment' },
    verdictHeader(a, lang),
    a.verdict !== 'inconclusive' || a.score > 0 ? scoreMeter(a, lang) : null,
    a.verdict !== 'no_known_threats' && a.headline ? el('p', { class: 'headline' }, a.headline) : null,
    actionBox(a, lang),
    topFindings(a, lang, opts.compact ? 3 : 4),
    a.ai ? aiBlock(a.ai, lang) : null,
    opts.compact ? null : sourcesPanel(a, opts),
    opts.compact ? null : breachBlock(a.reputation.breaches, a.registrableDomain),
    evidenceDetails(a, lang),
  );
}

/** Read the verdict aloud (useful for elderly users). Uses the browser's built-in speech engine; nothing is sent anywhere. */
export function speak(a: RiskAssessment, lang: Lang): void {
  if (!('speechSynthesis' in window)) return;
  window.speechSynthesis.cancel();
  const parts = [VERDICT_LABEL[a.verdict][lang], lang === 'hi' ? VERDICT_ACTION_HI[a.verdict] : a.recommendedAction];
  if (a.ai?.status === 'ok') parts.push((lang === 'hi' ? a.ai.summaryHi : a.ai.summaryEn) ?? '');
  const u = new SpeechSynthesisUtterance(parts.filter(Boolean).join('. '));
  u.lang = lang === 'hi' ? 'hi-IN' : 'en-IN';
  const voice = window.speechSynthesis.getVoices().find((v) => v.lang === u.lang) ?? window.speechSynthesis.getVoices().find((v) => v.lang.startsWith(lang));
  if (voice) u.voice = voice;
  u.rate = 0.95;
  window.speechSynthesis.speak(u);
}
