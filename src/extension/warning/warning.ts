import type { RiskAssessment } from '../../shared/types.js';
import { sendBg } from '../lib/messages.js';
import { getSettings, saveSettings } from '../lib/settings.js';
import { readWarning } from '../lib/state.js';
import { append, clear, el, icon } from '../ui/dom.js';
import { VERDICT_ACTION_HI, VERDICT_ICON, VERDICT_LABEL, type Lang } from '../ui/i18n.js';
import { evidenceDetails, speak } from '../ui/render.js';

const app = document.getElementById('app')!;

const TEXT = {
  kicker: { en: 'PhishShield stopped this page', hi: 'PhishShield ने यह पेज रोका' },
  title_confirmed: { en: 'This site is on a known phishing / malware list', hi: 'यह साइट ज्ञात फ़िशिंग / मैलवेयर सूची में है' },
  title_likely: { en: 'This site is likely trying to trick you', hi: 'यह साइट शायद आपको धोखा देने की कोशिश कर रही है' },
  back: { en: 'Go back to safety', hi: 'सुरक्षित पेज पर लौटें' },
  evidence: { en: 'Evidence', hi: 'साक्ष्य' },
  proceed_note: {
    en: 'If you are sure this is a mistake, you can continue. PhishShield will not warn again for this site for 30 minutes.',
    hi: 'अगर आपको यकीन है कि यह गलती है, तो आगे बढ़ सकते हैं। PhishShield 30 मिनट तक इस साइट पर फिर चेतावनी नहीं देगा।',
  },
  understand: { en: 'I understand the risk', hi: 'मैं जोखिम समझता/समझती हूँ' },
  proceed: { en: 'Continue to site (not recommended)', hi: 'साइट पर जाएँ (अनुशंसित नहीं)' },
  trust: { en: 'This is a mistake: trust this site', hi: 'यह गलती है: इस साइट पर भरोसा करें' },
  listen: { en: 'Listen', hi: 'सुनें' },
  missing: { en: 'This warning has expired. Go back and reload the page to check it again.', hi: 'यह चेतावनी समाप्त हो गई है। पेज दोबारा लोड करके जाँचें।' },
} as const;

let lang: Lang = 'en';
let data: { assessment: RiskAssessment; committed: boolean } | undefined;

async function tabId(): Promise<number | undefined> {
  return (await chrome.tabs.getCurrent())?.id;
}

function render(): void {
  clear(app);
  const tr = (k: keyof typeof TEXT) => TEXT[k][lang];
  const langBtn = el('button', { class: 'btn w-lang', onclick: toggleLang }, lang === 'en' ? 'हिंदी' : 'English');

  if (!data) {
    append(app, el('div', { class: 'w-brand' }, icon('shield', 20), 'PhishShield AI'), el('p', {}, tr('missing')), langBtn);
    return;
  }
  const a = data.assessment;
  const confirmed = a.verdict === 'confirmed_malicious';
  document.body.className = `warning-page v-${a.verdict}`;

  const reasons = a.signals.filter((s) => s.weight > 0 && s.category !== 'informational').slice(0, 4);
  const understand = el('input', { type: 'checkbox', id: 'understand' });
  const proceedBtn = el('button', { class: 'btn', disabled: confirmed, onclick: () => proceed(false) }, tr('proceed'));
  understand.addEventListener('change', () => (proceedBtn.disabled = !understand.checked));

  append(
    app,
    langBtn,
    el('div', { class: 'w-brand' }, icon('shield', 20), 'PhishShield AI'),
    el(
      'div',
      { class: 'w-head' },
      el('div', { class: 'w-icon' }, icon(VERDICT_ICON[a.verdict], 34)),
      el(
        'div',
        {},
        el('div', { class: 'w-kicker' }, `${tr('kicker')} · ${VERDICT_LABEL[a.verdict][lang]}`),
        el('h1', { class: 'w-title' }, confirmed ? tr('title_confirmed') : tr('title_likely')),
        el('div', { class: 'w-host' }, a.displayHost || a.host),
        a.displayHost !== a.host ? el('div', { class: 'w-puny' }, `Actual address (punycode): ${a.host}`) : null,
      ),
    ),
    el('ul', { class: 'w-reasons' }, ...reasons.map((s) => el('li', {}, el('div', { class: 't' }, s.title), el('div', { class: 'd' }, s.detail)))),
    el('p', { class: 'w-action' }, lang === 'hi' ? VERDICT_ACTION_HI[a.verdict] : a.recommendedAction),
    el(
      'div',
      { class: 'w-buttons' },
      el('button', { class: 'btn primary', onclick: goBack, autofocus: true }, icon('back', 16), tr('back')),
      el('button', { class: 'link-btn', onclick: () => speak(a, lang) }, icon('volume', 14), tr('listen')),
    ),
    el(
      'p',
      { class: 'w-sources' },
      a.reputation.findings.length
        ? `Reputation: ${a.reputation.findings.map((f) => `${f.providerName} (${f.status.replace('_', ' ')})`).join(', ')}. `
        : a.reputation.status === 'unavailable'
          ? 'Reputation lists could not be reached, so this warning is based on local checks only. '
          : a.reputation.status === 'pending'
            ? 'Shown before reputation lists finished checking, based on local checks. '
            : a.reputation.status === 'not_configured'
            ? 'Reputation lists are not configured (local-only mode). '
            : 'Reputation lists were not consulted for this decision. ',
      `Risk score ${a.score}/100 (heuristic, not a probability).`,
    ),
    evidenceDetails(a, lang),
    el(
      'div',
      { class: 'w-proceed' },
      el('p', {}, tr('proceed_note')),
      el('label', {}, understand, tr('understand')),
      el('div', { class: 'w-buttons' }, proceedBtn, !confirmed ? el('button', { class: 'link-btn', onclick: () => proceed(true) }, tr('trust')) : null),
    ),
  );
  if (!confirmed) proceedBtn.disabled = true;
}

async function goBack(): Promise<void> {
  const id = await tabId();
  if (id !== undefined) await sendBg({ type: 'go-back-safe', tabId: id });
}

async function proceed(trust: boolean): Promise<void> {
  const id = await tabId();
  if (id === undefined || !data) return;
  await sendBg({ type: 'bypass-and-continue', tabId: id, url: data.assessment.url, trust });
}

async function toggleLang(): Promise<void> {
  lang = lang === 'en' ? 'hi' : 'en';
  await saveSettings({ language: lang });
  render();
}

async function init(): Promise<void> {
  lang = (await getSettings()).language;
  const id = location.hash.slice(1);
  data = /^[0-9a-f-]{36}$/.test(id) ? await readWarning(id) : undefined;
  render();
}

void init();
