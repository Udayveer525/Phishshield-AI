import { MAX_INSPECT_BYTES, assessFile, inspectFile, sha256Hex, type FileAssessment } from '../../engine/file.js';
import { assess } from '../../engine/index.js';
import { analyzeQrPayload, type QrAnalysis } from '../../engine/qr.js';
import { checkPwnedPassword, type PwnedResult } from '../../shared/pwned.js';
import type { Verdict } from '../../shared/types.js';
import { api, type FileLookup } from '../lib/api.js';
import { sendBg } from '../lib/messages.js';
import { decodeQrFromBlob } from '../lib/qr-decode.js';
import { getSettings, getTrustedDomains, type Settings } from '../lib/settings.js';
import type { DownloadRecord } from '../lib/state.js';
import { append, clear, el, icon, timeAgo } from '../ui/dom.js';
import { VERDICT_LABEL, type Lang } from '../ui/i18n.js';
import { renderFileAssessment, renderQr } from '../ui/render-tools.js';

/**
 * Security Center: tools that need more room than the popup (and a file picker, which would close
 * the popup). Everything here runs on the device; the only network calls are the optional SHA-256
 * lookup via the user's PhishShield server and the k-anonymity password range query to HIBP.
 */

type Section = 'file' | 'qr' | 'password' | 'downloads';

const app = document.getElementById('app')!;
const state = {
  section: (['file', 'qr', 'password', 'downloads'].includes(location.hash.slice(1)) ? location.hash.slice(1) : 'file') as Section,
  settings: null as Settings | null,
  lang: 'en' as Lang,
  file: { busy: '', result: null as FileAssessment | null, vt: null as FileLookup | null, vtPending: false, embedded: [] as Array<{ url: string; verdict: Verdict; host: string }>, error: '' },
  qr: { busy: false, result: null as QrAnalysis | null, error: '', text: '' },
  pw: { busy: false, result: null as PwnedResult | null },
  downloads: [] as DownloadRecord[],
};

// ---------------------------------------------------------------------------------------------

function render(): void {
  clear(app);
  const nav: Array<[Section, string, string]> = [
    ['file', 'Scan a file', 'file'],
    ['qr', 'QR & UPI', 'qr'],
    ['password', 'Password check', 'key'],
    ['downloads', 'Downloads', 'download'],
  ];
  append(
    app,
    el(
      'header',
      { class: 'c-top' },
      el(
        'div',
        { class: 'c-top-in' },
        el('div', { class: 'c-brand' }, el('span', { class: 'mark' }, icon('shield', 17)), 'PhishShield', el('span', { class: 'sub' }, 'Security Center')),
        el(
          'nav',
          { class: 'c-nav', 'aria-label': 'Tools' },
          ...nav.map(([k, label, ic]) => el('button', { class: state.section === k ? 'active' : '', 'aria-current': state.section === k ? 'page' : undefined, onclick: () => go(k) }, icon(ic, 15), label)),
        ),
      ),
    ),
  );
  const main = el('main', { class: 'c-main' });
  if (state.section === 'file') renderFile(main);
  if (state.section === 'qr') renderQrSection(main);
  if (state.section === 'password') renderPassword(main);
  if (state.section === 'downloads') renderDownloads(main);
  append(app, main);
}

function go(s: Section): void {
  state.section = s;
  history.replaceState(null, '', `#${s}`);
  render();
  if (s === 'downloads') void loadDownloads();
}

function dropZone(opts: { accept: string; label: string; hint: string; onFile: (f: File) => void; id: string }): HTMLElement {
  const input = el('input', { type: 'file', accept: opts.accept, id: opts.id, 'aria-label': opts.label });
  input.addEventListener('change', () => input.files?.[0] && opts.onFile(input.files[0]));
  const zone = el('label', { class: 'drop', for: opts.id }, icon('upload', 26), el('span', { class: 'big' }, opts.label), el('span', { class: 'small muted' }, opts.hint), input);
  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('over');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('over');
    const f = e.dataTransfer?.files?.[0];
    if (f) opts.onFile(f);
  });
  return zone;
}

function resultCard(content: Node | null, busy: string, emptyIcon: string, emptyText: string): HTMLElement {
  return el(
    'section',
    { class: 'c-card c-result', 'aria-live': 'polite' },
    busy ? el('div', { class: 'skeleton', 'aria-busy': 'true' }, el('div', { class: 'sk sk-head' }), el('div', { class: 'sk sk-line' }), el('div', { class: 'sk sk-line short' }), el('p', { class: 'muted small center' }, busy)) : content ?? el('div', { class: 'empty' }, icon(emptyIcon, 30), el('p', {}, emptyText)),
  );
}

// ---- Files -------------------------------------------------------------------------------------

function renderFile(main: HTMLElement): void {
  const f = state.file;
  const hashOn = !!state.settings?.fileHashLookup && !!state.settings.apiBaseUrl;
  append(
    main,
    el('div', { class: 'c-intro' }, el('h1', {}, 'Scan a file before you open it'), el('p', {}, 'Checks what the file really is, whether it hides a program, macros, scripts or risky Android permissions, and (optionally) whether antivirus engines already know it. The file is read on this device and never uploaded.')),
    el(
      'div',
      { class: 'c-grid' },
      el(
        'section',
        { class: 'c-card' },
        el('h2', {}, icon('file', 16), 'Choose a file'),
        el('p', {}, 'APKs from WhatsApp, e-mail attachments, “invoice” ZIPs, PDFs, Office files, installers.'),
        dropZone({ accept: '*/*', label: 'Drop a file here or click to choose', hint: `Up to ${Math.round(MAX_INSPECT_BYTES / 1048576)} MB is inspected`, onFile: (file) => void scanFile(file), id: 'file-in' }),
        el(
          'div',
          { class: 'privacy-line' },
          icon('lock', 14),
          el(
            'span',
            {},
            hashOn
              ? 'Only the file’s SHA-256 fingerprint is sent to your PhishShield server for a VirusTotal lookup. The file itself never leaves your device. (Change in settings.)'
              : 'Fingerprint lookups are off or no server is configured, so only local checks run.',
          ),
        ),
        f.error ? el('div', { class: 'error', role: 'alert' }, icon('alert', 16), el('span', {}, f.error)) : null,
      ),
      resultCard(f.result ? renderFileAssessment(f.result, { vt: f.vt, vtPending: f.vtPending, embedded: f.embedded }) : null, f.busy, 'file', 'Results appear here.'),
    ),
  );
}

async function scanFile(file: File): Promise<void> {
  const f = state.file;
  Object.assign(f, { busy: `Reading ${file.name}…`, result: null, vt: null, vtPending: false, embedded: [], error: '' });
  render();
  try {
    const slice = file.size > MAX_INSPECT_BYTES ? file.slice(0, MAX_INSPECT_BYTES) : file;
    const bytes = new Uint8Array(await slice.arrayBuffer());
    f.busy = 'Inspecting…';
    render();
    const report = await inspectFile(bytes, file.name, { declaredSize: file.size });
    // Hash of the inspected bytes; only equals the file hash when the whole file was read.
    const sha = file.size <= MAX_INSPECT_BYTES ? await sha256Hex(bytes) : undefined;
    f.result = assessFile(report, { sha256: sha });
    f.busy = '';
    const trusted = await getTrustedDomains();
    f.embedded = report.embeddedUrls.slice(0, 10).map((u) => {
      const a = assess(u, { trustedDomains: trusted });
      return { url: u, verdict: a.verdict, host: a.displayHost };
    });
    render();
    const s = state.settings;
    if (sha && s?.fileHashLookup && s.apiBaseUrl) {
      f.vtPending = true;
      render();
      const r = await api.file(s.apiBaseUrl, sha);
      f.vtPending = false;
      f.vt = r.ok ? r.data : { finding: { providerId: 'virustotal', providerName: 'VirusTotal', status: 'error', checkedAt: Date.now(), message: r.message } };
      f.result = assessFile(report, { sha256: sha, reputation: f.vt.finding });
      render();
    }
  } catch (e) {
    f.busy = '';
    f.error = `Could not read the file: ${e instanceof Error ? e.message : 'unknown error'}`;
    render();
  }
}

// ---- QR / UPI ----------------------------------------------------------------------------------

function renderQrSection(main: HTMLElement): void {
  const q = state.qr;
  const text = el('input', { class: 'input', type: 'text', placeholder: 'or paste a UPI link / QR text, e.g. upi://pay?pa=…', value: q.text, 'aria-label': 'QR text or UPI link', spellcheck: 'false', autocomplete: 'off' });
  text.addEventListener('input', () => (q.text = text.value));
  text.addEventListener('keydown', (e) => e.key === 'Enter' && analyzeText());
  append(
    main,
    el('div', { class: 'c-intro' }, el('h1', {}, 'Check a QR code before you scan it with a payment app'), el('p', {}, 'Decodes the QR code on this device and explains what it really does. Most UPI QR scams promise you money: scanning a UPI QR and entering your PIN always SENDS money.')),
    el(
      'div',
      { class: 'c-grid' },
      el(
        'section',
        { class: 'c-card' },
        el('h2', {}, icon('qr', 16), 'QR code image'),
        el('p', {}, 'A screenshot or photo of the QR code. You can also paste an image (Ctrl+V) anywhere on this page.'),
        dropZone({ accept: 'image/*', label: 'Drop an image or click to choose', hint: 'PNG, JPG, WebP', onFile: (file) => void decodeImage(file), id: 'qr-in' }),
        el('div', { class: 'row' }, text, el('button', { class: 'btn primary', onclick: analyzeText }, 'Check')),
        el('div', { class: 'privacy-line' }, icon('lock', 14), el('span', {}, 'Decoded locally. Nothing is uploaded. Website links in a QR code are checked with the same rules as “Scan link”.')),
        q.error ? el('div', { class: 'error', role: 'alert' }, icon('alert', 16), el('span', {}, q.error)) : null,
      ),
      resultCard(q.result ? renderQr(q.result, state.lang) : null, q.busy ? 'Decoding…' : '', 'qr', 'Results appear here.'),
    ),
  );
}

async function decodeImage(file: Blob): Promise<void> {
  const q = state.qr;
  Object.assign(q, { busy: true, error: '', result: null });
  render();
  try {
    const data = await decodeQrFromBlob(file);
    q.busy = false;
    if (!data) q.error = 'No QR code found. Try a sharper image, or crop it so the QR code fills most of the picture.';
    else q.result = analyzeQrPayload(data, { trustedDomains: await getTrustedDomains() });
  } catch {
    q.busy = false;
    q.error = 'That file could not be read as an image.';
  }
  render();
}

async function analyzeText(): Promise<void> {
  const q = state.qr;
  if (!q.text.trim()) return;
  q.error = '';
  q.result = analyzeQrPayload(q.text, { trustedDomains: await getTrustedDomains() });
  render();
}

document.addEventListener('paste', (e) => {
  const item = [...(e.clipboardData?.items ?? [])].find((i) => i.type.startsWith('image/'));
  const blob = item?.getAsFile();
  if (!blob) return;
  e.preventDefault();
  if (state.section !== 'qr') go('qr');
  void decodeImage(blob);
});

// ---- Passwords ---------------------------------------------------------------------------------

function renderPassword(main: HTMLElement): void {
  const p = state.pw;
  const input = el('input', { class: 'input', type: 'password', autocomplete: 'off', placeholder: 'Type a password to check', 'aria-label': 'Password to check', spellcheck: 'false' });
  const submit = () => {
    const v = input.value;
    input.value = '';
    void checkPassword(v);
  };
  input.addEventListener('keydown', (e) => e.key === 'Enter' && submit());
  let result: HTMLElement | null = null;
  if (p.result && p.result.ok) {
    result =
      p.result.count > 0
        ? el(
            'div',
            { class: 'pw-result bad', role: 'status' },
            el('div', { class: 'big' }, `Found in ${p.result.count.toLocaleString('en-IN')} leaked password lists`),
            el('p', {}, 'Criminals try these passwords first. Stop using it everywhere, starting with e-mail, banking and UPI apps, and turn on two-step verification.'),
          )
        : el(
            'div',
            { class: 'pw-result ok', role: 'status' },
            el('div', { class: 'big' }, 'Not found in known breaches'),
            el('p', {}, 'That is good, but not proof the password is strong. Use a different password for every important account.'),
          );
  } else if (p.result && !p.result.ok) {
    result = el('div', { class: 'error', role: 'alert' }, icon('alert', 16), el('span', {}, p.result.message));
  }
  append(
    main,
    el('div', { class: 'c-intro' }, el('h1', {}, 'Has this password leaked?'), el('p', {}, 'Checks the password against more than a billion passwords exposed in data breaches, using Have I Been Pwned’s k-anonymity service. The password never leaves this page.')),
    el(
      'div',
      { class: 'c-grid' },
      el(
        'section',
        { class: 'c-card' },
        el('h2', {}, icon('key', 16), 'Check a password'),
        el('div', { class: 'row' }, input, el('button', { class: 'btn primary', onclick: submit, disabled: p.busy }, p.busy ? 'Checking…' : 'Check')),
        result,
        el(
          'div',
          { class: 'privacy-line' },
          icon('lock', 14),
          el('span', {}, p.result && p.result.ok ? `Only “${p.result.prefix}” (the first 5 of 40 characters of the password’s SHA-1 hash) was sent.` : 'Checked only when you press Check, never while you type. Nothing is stored.'),
        ),
      ),
      el(
        'section',
        { class: 'c-card' },
        el('h2', {}, icon('info', 16), 'How the check works'),
        el(
          'ol',
          { class: 'steps' },
          el('li', {}, 'Your browser computes the SHA-1 hash of the password, e.g. 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.'),
          el('li', {}, 'Only the first 5 characters (5BAA6) go to api.pwnedpasswords.com, directly from your browser (not through the PhishShield server).'),
          el('li', {}, 'The service returns every hash ending that starts with those 5 characters (usually well over a thousand), padded with fake zero-count rows so the response size reveals nothing.'),
          el('li', {}, 'Your browser looks for the remaining 35 characters in that list. The match happens here.'),
        ),
        el('p', { class: 'attrib' }, 'Pwned Passwords by ', el('a', { href: 'https://haveibeenpwned.com/Passwords', target: '_blank', rel: 'noopener noreferrer' }, 'Have I Been Pwned'), '.'),
      ),
    ),
  );
}

async function checkPassword(pw: string): Promise<void> {
  if (!pw) return;
  state.pw = { busy: true, result: null };
  render();
  const result = await checkPwnedPassword(pw);
  state.pw = { busy: false, result };
  render();
}

// ---- Downloads ---------------------------------------------------------------------------------

function renderDownloads(main: HTMLElement): void {
  const list = state.downloads;
  append(
    main,
    el('div', { class: 'c-intro' }, el('h1', {}, 'Downloads checked this session'), el('p', {}, 'Download Guard looks at every download’s name, source and type. Risky ones are paused until you decide. This list is kept in memory only and clears when the browser closes.')),
    el(
      'section',
      { class: 'c-card', style: 'margin-top:18px' },
      el('h2', {}, icon('download', 16), state.settings?.downloadGuard ? 'Download Guard is on' : 'Download Guard is off (turn it on in settings)'),
      list.length
        ? el(
            'ul',
            { class: 'dl-list' },
            ...list.map((r) =>
              el(
                'li',
                { class: `v-${r.verdict}` },
                el('span', { class: `pill v-${r.verdict}` }, VERDICT_LABEL[r.verdict].en),
                el('div', { class: 'grow' }, el('div', { class: 'name' }, r.filename), el('div', { class: 'meta' }, `${r.host || 'unknown source'} · ${timeAgo(r.at)} · ${r.intervened ? `paused, ${r.outcome}` : 'allowed'}`)),
                r.intervened ? el('a', { class: 'link-btn', href: chrome.runtime.getURL(`download/download.html#${r.id}`), target: '_blank' }, 'Details') : null,
              ),
            ),
          )
        : el('p', { class: 'muted small', style: 'margin-top:10px' }, 'No downloads yet in this session.'),
    ),
  );
}

async function loadDownloads(): Promise<void> {
  const r = await sendBg({ type: 'list-downloads' });
  state.downloads = r.ok ? (r.downloads ?? []) : [];
  if (state.section === 'downloads') render();
}

// ---------------------------------------------------------------------------------------------

async function init(): Promise<void> {
  state.settings = await getSettings();
  state.lang = state.settings.language;
  render();
  if (state.section === 'downloads') void loadDownloads();
}

void init();
