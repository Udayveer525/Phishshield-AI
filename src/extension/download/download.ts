import type { DownloadAction, DownloadView } from '../lib/messages.js';
import { sendBg } from '../lib/messages.js';
import { append, clear, el, icon } from '../ui/dom.js';
import { VERDICT_ICON, VERDICT_LABEL } from '../ui/i18n.js';

/** Download Guard decision page: opened by the background when a risky download is paused. */

const app = document.getElementById('app')!;
const id = Number(location.hash.slice(1));
let view: DownloadView | undefined;
let busy = false;

const CLASS_LABEL: Record<string, string> = {
  android_app: 'Android app (APK)',
  program: 'Program',
  script: 'Script',
  shortcut: 'Windows shortcut',
  disk_image: 'Disk image',
  macro_document: 'Macro-enabled document',
  java: 'Java program',
  archive: 'Archive',
  document: 'Document',
  other: 'File',
};

function fmtSize(n: number): string {
  if (!n || n < 0) return 'unknown size';
  return n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1048576).toFixed(1)} MB`;
}

const KICKER: Partial<Record<string, string>> = { cancelled: 'Download cancelled', deleted: 'File deleted', kept: 'File kept' };

function statusText(v: DownloadView): { text: string; done: boolean } {
  const outcome = v.record.outcome;
  if (outcome === 'deleted') return { text: 'Deleted. The file was removed from your computer.', done: true };
  if (outcome === 'cancelled') return { text: 'Cancelled. The file was not saved.', done: true };
  if (outcome === 'kept') return { text: 'You chose to keep this file. Only open it if you trust where it came from.', done: true };
  const live = v.live;
  if (!live || !live.exists) return { text: 'The download is no longer available.', done: true };
  if (live.state === 'in_progress' && live.paused) return { text: `Paused at ${fmtSize(live.bytesReceived)}${live.totalBytes > 0 ? ` of ${fmtSize(live.totalBytes)}` : ''}. Nothing has been opened.`, done: false };
  if (live.state === 'complete') return { text: 'This file finished downloading before it could be paused. It has not been opened. You can delete it now.', done: false };
  if (live.state === 'interrupted') return { text: 'The download was interrupted.', done: true };
  return { text: 'Downloading…', done: false };
}

function render(): void {
  clear(app);
  if (!view) {
    append(app, el('div', { class: 'w-brand' }, icon('shield', 20), 'PhishShield AI'), el('p', {}, 'This download is no longer tracked (the browser may have been restarted). Check your downloads list.'));
    return;
  }
  const a = view.assessment;
  const live = view.live;
  document.body.className = `warning-page v-${a.verdict}`;
  const st = statusText(view);
  const complete = live?.state === 'complete' && live.exists;
  const pending = view.record.outcome === 'pending' && !st.done;
  const reasons = a.signals.filter((s) => s.weight > 0).slice(0, 5);

  const understand = el('input', { type: 'checkbox', id: 'understand' });
  const keepBtn = el('button', { class: 'btn', disabled: true, onclick: () => act('resume') }, complete ? 'Keep the file' : 'Continue download (not recommended)');
  understand.addEventListener('change', () => (keepBtn.disabled = !understand.checked || busy));

  append(
    app,
    el('div', { class: 'w-brand' }, icon('shield', 20), 'PhishShield AI · Download Guard'),
    el(
      'div',
      { class: 'w-head' },
      el('div', { class: 'w-icon' }, icon(VERDICT_ICON[a.verdict], 34)),
      el(
        'div',
        {},
        el('div', { class: 'w-kicker' }, `${KICKER[view.record.outcome] ?? (complete ? 'Download finished' : 'Download paused')} · ${VERDICT_LABEL[a.verdict].en}`),
        el('h1', { class: 'w-title' }, a.verdict === 'likely_phishing' ? 'This download is likely dangerous' : 'Check this download before opening it'),
        el(
          'div',
          { class: 'd-file' },
          el('div', { class: 'row' }, el('span', { class: 'k' }, 'File'), el('span', { class: 'v' }, a.filename)),
          el('div', { class: 'row' }, el('span', { class: 'k' }, 'Type'), el('span', { class: 'v' }, CLASS_LABEL[a.fileClass] ?? 'File')),
          a.sourceHost ? el('div', { class: 'row' }, el('span', { class: 'k' }, 'From'), el('span', { class: 'v' }, a.sourceHost)) : null,
          a.referrerHost && a.referrerHost !== a.sourceHost ? el('div', { class: 'row' }, el('span', { class: 'k' }, 'Started on'), el('span', { class: 'v' }, a.referrerHost)) : null,
        ),
      ),
    ),
    el('ul', { class: 'w-reasons' }, ...reasons.map((s) => el('li', {}, el('div', { class: 't' }, s.title), el('div', { class: 'd' }, s.detail)))),
    el('div', { class: `d-status${st.done ? ' done' : ''}` }, st.text),
    pending
      ? el(
          'div',
          { class: 'w-buttons' },
          el('button', { class: 'btn danger', autofocus: true, disabled: busy, onclick: () => act(complete ? 'delete' : 'cancel') }, icon('ban', 16), complete ? 'Delete file' : 'Cancel download'),
          el('button', { class: 'link-btn', onclick: openCenter }, icon('file', 14), 'Inspect the file in the Security Center'),
        )
      : el('div', { class: 'w-buttons' }, el('button', { class: 'btn', onclick: () => window.close() }, 'Close this tab'), complete && view.record.outcome === 'kept' ? el('button', { class: 'link-btn', onclick: () => act('show') }, 'Show in folder') : null),
    pending
      ? el(
          'div',
          { class: 'w-proceed' },
          el('p', {}, 'If you trust the sender and were expecting this file, you can keep it. PhishShield never opens or runs downloads.'),
          el('label', {}, understand, ' I understand the risk'),
          keepBtn,
        )
      : null,
    el('p', { class: 'w-sources' }, ...a.limitations.map((l) => el('span', {}, l, ' '))),
  );
}

async function act(action: DownloadAction): Promise<void> {
  busy = true;
  render();
  const r = await sendBg({ type: 'download-action', id, action });
  busy = false;
  if (r.ok && r.download) view = r.download;
  render();
}

function openCenter(): void {
  void chrome.tabs.create({ url: chrome.runtime.getURL('center/center.html#file') });
}

async function init(): Promise<void> {
  const r = Number.isInteger(id) ? await sendBg({ type: 'get-download', id }) : null;
  view = r?.ok ? r.download : undefined;
  render();
}

void init();
