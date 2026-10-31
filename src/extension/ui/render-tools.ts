import type { FileAssessment } from '../../engine/file.js';
import type { QrAnalysis } from '../../engine/qr.js';
import type { UpiAssessment } from '../../engine/upi.js';
import type { Signal, Verdict } from '../../shared/types.js';
import type { FileLookup } from '../lib/api.js';
import { el, icon } from './dom.js';
import { VERDICT_ICON, type Lang } from './i18n.js';
import { renderAssessment } from './render.js';

/** Renderers for the Security Center and popup tools. Every string is set as text, never HTML. */

const FILE_LABEL: Record<Verdict, string> = {
  confirmed_malicious: 'Known malware',
  likely_phishing: 'Likely dangerous',
  suspicious: 'Risky file',
  no_known_threats: 'No known threats found',
  inconclusive: 'Could not fully check',
};

const UPI_LABEL: Record<Verdict, string> = {
  confirmed_malicious: 'Known scam',
  likely_phishing: 'Likely UPI scam',
  suspicious: 'Suspicious payment request',
  no_known_threats: 'Payment request',
  inconclusive: 'Could not fully check',
};

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

const inr = (n: number) => `₹${n.toLocaleString('en-IN', { maximumFractionDigits: 2 })}`;

function header(verdict: Verdict, label: string, sub: string, iconName?: string): HTMLElement {
  return el(
    'div',
    { class: `verdict v-${verdict}` },
    el('div', { class: 'verdict-icon' }, icon(iconName ?? VERDICT_ICON[verdict], 26)),
    el('div', { class: 'verdict-text' }, el('div', { class: 'verdict-label' }, label), el('div', { class: 'verdict-host', title: sub }, sub)),
  );
}

function meter(verdict: Verdict, score: number): HTMLElement {
  const pct = Math.max(0, Math.min(100, score));
  return el(
    'div',
    { class: 'meter' },
    el('div', { class: 'meter-row' }, el('span', { class: 'meter-label' }, 'Risk score'), el('span', { class: 'meter-value' }, `${pct}`, el('span', { class: 'muted' }, ' / 100'))),
    el('div', { class: `meter-track v-${verdict}`, role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': pct, 'aria-label': 'Risk score' }, el('div', { class: 'meter-fill', style: `width:${pct}%` })),
    el('div', { class: 'meter-note' }, 'Heuristic score, not a probability'),
  );
}

function findings(signals: Signal[], empty: string, max = 8): HTMLElement {
  const counted = signals.filter((s) => s.weight > 0);
  return el(
    'section',
    { class: 'block' },
    el('h3', {}, 'Why'),
    counted.length
      ? el(
          'ul',
          { class: 'findings' },
          ...counted.slice(0, max).map((s) =>
            el(
              'li',
              { class: `finding s-${s.strength}` },
              el('div', { class: 'finding-head' }, el('span', { class: 'finding-title' }, s.title), el('span', { class: `chip src-${s.source}` }, s.source === 'reputation' ? 'VirusTotal' : 'Local')),
              el('div', { class: 'finding-detail' }, s.detail),
              ...(s.evidence ?? []).slice(0, 3).map((e) => el('div', { class: 'ev-line mono small' }, e)),
            ),
          ),
        )
      : el('p', { class: 'muted small' }, empty),
  );
}

function facts(rows: Array<[string, string | Node | null | undefined]>): HTMLElement {
  return el(
    'dl',
    { class: 'facts' },
    ...rows.filter(([, v]) => v !== null && v !== undefined && v !== '').flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v as string | Node)]),
  );
}

function limits(list: string[]): HTMLElement {
  return el('section', { class: 'block' }, el('h3', {}, 'Limitations'), el('ul', { class: 'limits' }, ...list.map((l) => el('li', {}, l))));
}

export function renderFileAssessment(a: FileAssessment, opts: { vt?: FileLookup | null; vtPending?: boolean; embedded?: Array<{ url: string; verdict: Verdict; host: string }> } = {}): HTMLElement {
  const r = a.report;
  const vt = opts.vt;
  const d = vt?.finding.detections;
  const vtRow = opts.vtPending
    ? el('span', { class: 'st pending' }, 'Looking up…')
    : !vt
      ? el('span', { class: 'st off' }, 'Not checked')
      : vt.finding.status === 'match' || d
        ? el(
            'span',
            {},
            el('span', { class: `st ${vt.finding.status === 'match' ? 'bad' : d && d.malicious + d.suspicious > 0 ? 'warn' : 'ok'}` }, d ? `${d.malicious} of ${d.total} engines flag it` : 'Listed'),
            vt.file?.label ? el('span', { class: 'muted small' }, ` · ${vt.file.label}`) : null,
          )
        : el('span', { class: `st ${vt.finding.status === 'no_match' ? 'off' : 'warn'}` }, vt.finding.message ?? vt.finding.status);

  return el(
    'div',
    { class: 'assessment' },
    header(a.verdict, FILE_LABEL[a.verdict], r.name, 'file'),
    meter(a.verdict, a.score),
    a.verdict !== 'no_known_threats' ? el('p', { class: 'headline' }, a.headline) : null,
    el('div', { class: `action v-${a.verdict}` }, el('div', { class: 'action-title' }, 'What to do'), el('div', {}, a.recommendedAction)),
    findings(a.signals, 'No warning signs were found in the checks that ran.'),
    el(
      'section',
      { class: 'block' },
      el('h3', {}, 'File details'),
      facts([
        ['Real type', r.kindLabel],
        ['Extension', r.extension ? `.${r.extension}` : '(none)'],
        ['Size', fmtBytes(r.size)],
        ['SHA-256', a.sha256 ? el('code', { class: 'hash' }, a.sha256) : null],
        ['VirusTotal', vtRow],
        ['First seen', vt?.file?.firstSeen ? new Date(vt.file.firstSeen).toLocaleDateString() : null],
        ['Known as', vt?.file?.meaningfulName ?? null],
        ['App permissions', r.apkPermissions ? (r.apkPermissions.length ? r.apkPermissions.join(', ') : 'none of the high-risk ones') : null],
        ['Archive', r.zip ? `${r.zip.entries} entries${r.zip.encrypted ? `, ${r.zip.encrypted} encrypted` : ''}${r.zip.truncated ? ' (list truncated)' : ''}` : null],
        ['Signature', r.pe ? (r.pe.signed ? 'Has a digital signature (not verified)' : 'Not signed') : null],
      ]),
      vt?.file?.permalink ? el('a', { class: 'small', href: vt.file.permalink, target: '_blank', rel: 'noopener noreferrer' }, icon('external', 12), ' Open the VirusTotal report') : null,
    ),
    opts.embedded?.length
      ? el(
          'section',
          { class: 'block' },
          el('h3', {}, 'Links inside the file'),
          el('ul', { class: 'linklist' }, ...opts.embedded.map((e) => el('li', {}, el('span', { class: `pill v-${e.verdict}` }, e.verdict.replace(/_/g, ' ')), el('span', { class: 'mono' }, e.host || e.url)))),
        )
      : null,
    limits(a.limitations),
  );
}

export function renderUpi(u: UpiAssessment): HTMLElement {
  const p = u.payment;
  return el(
    'div',
    { class: 'assessment' },
    header(u.verdict, UPI_LABEL[u.verdict], p.payeeVpa || 'No UPI ID', 'qr'),
    el(
      'div',
      { class: `upi-send v-${u.verdict}` },
      el('div', { class: 'upi-kicker' }, p.kind === 'mandate' ? 'This sets up an AUTO-DEBIT' : 'Scanning this QR SENDS money'),
      el('div', { class: 'upi-amount' }, p.amount !== null ? inr(p.amount) : 'Amount: you choose'),
      el('div', { class: 'upi-to' }, 'to ', el('strong', {}, p.payeeName || 'an unnamed payee'), ' ', el('span', { class: 'mono' }, p.payeeVpa)),
      el('p', { class: 'small' }, 'You never scan a QR code or enter your UPI PIN to receive money.'),
    ),
    meter(u.verdict, u.score),
    el('div', { class: `action v-${u.verdict}` }, el('div', { class: 'action-title' }, 'What to do'), el('div', {}, u.recommendedAction)),
    findings(u.signals, 'No scam patterns found in this payment request. Still check the name your UPI app shows.'),
    el(
      'section',
      { class: 'block' },
      el('h3', {}, 'Payment details'),
      facts([
        ['Type', p.kind === 'mandate' ? 'Recurring mandate' : 'One-time payment'],
        ['Payee name', p.payeeName || '(not given)'],
        ['UPI ID', p.payeeVpa || '(missing)'],
        ['Handle', p.handle ? `@${p.handle}${p.handleKnown ? '' : ' (unfamiliar)'}` : null],
        ['Note', p.note || null],
        ['Merchant code', p.merchantCode || null],
        ['App link', p.scheme !== 'upi' ? `${p.scheme}://` : null],
      ]),
    ),
    limits(u.limitations),
  );
}

export function renderQr(q: QrAnalysis, lang: Lang): HTMLElement {
  const raw = el('details', { class: 'evidence' }, el('summary', {}, icon('chevron', 14, 'chev'), ' What the QR code contains'), el('div', { class: 'ev-group' }, el('div', { class: 'ev-line mono' }, q.raw)));
  switch (q.type) {
    case 'upi':
      return el('div', {}, renderUpi(q.upi), raw);
    case 'url':
      return el('div', {}, el('p', { class: 'note small' }, icon('info', 14), ' This QR code opens a website. PhishShield checked it without opening it.'), renderAssessment(q.url, { lang, compact: true }), raw);
    case 'wifi':
      return el(
        'div',
        { class: 'assessment' },
        header('no_known_threats', 'Wi-Fi network', q.ssid || '(hidden)', 'qr'),
        el('p', { class: 'note small' }, icon('info', 14), ` Joins the network “${q.ssid}” (${q.security}). Only join networks you recognise; public networks can watch unencrypted traffic.`),
      );
    case 'contact':
      return el('div', { class: 'assessment' }, header('no_known_threats', q.summary, q.raw.slice(0, 60), 'qr'), raw);
    default: {
      const v: Verdict = q.signals.some((s) => s.strength === 'strong') ? 'likely_phishing' : q.signals.length ? 'suspicious' : 'no_known_threats';
      return el('div', {}, el('div', { class: 'assessment' }, header(v, v === 'no_known_threats' ? 'Plain text' : 'Text with scam tactics', `${q.raw.length} characters`, 'qr'), findings(q.signals, 'No scam tactics found in the text.')), raw);
    }
  }
}
