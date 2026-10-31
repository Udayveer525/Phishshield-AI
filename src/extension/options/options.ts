import { api } from '../lib/api.js';
import { sendBg } from '../lib/messages.js';
import { getSettings, getTrustedDomains, normalizeApiBase, saveSettings, setTrusted, type ProtectionLevel, type Settings } from '../lib/settings.js';
import { append, clear, el, icon } from '../ui/dom.js';

const app = document.getElementById('app')!;
const ALL_SITES = ['https://*/*', 'http://*/*'];
let settings: Settings;
let trusted: string[] = [];
let status: { text: string; ok: boolean; lines: string[] } | null = null;

function setting(label: string, desc: string, control: Node): HTMLElement {
  return el('div', { class: 'setting' }, el('div', {}, el('div', { class: 'lbl' }, label), el('div', { class: 'desc' }, desc)), el('div', { class: 'ctl' }, control));
}

function toggle(checked: boolean, onChange: (v: boolean) => void, label: string): HTMLInputElement {
  const i = el('input', { type: 'checkbox', class: 'switch', 'aria-label': label });
  i.checked = checked;
  i.addEventListener('change', () => onChange(i.checked));
  return i;
}

async function update(patch: Partial<Settings>): Promise<void> {
  settings = await saveSettings(patch);
  await sendBg({ type: 'settings-changed' }).catch(() => undefined);
  render();
}

async function testConnection(): Promise<void> {
  status = { text: 'Testing…', ok: true, lines: [] };
  render();
  const r = await api.health(settings.apiBaseUrl);
  if (!r.ok) {
    status = { text: r.message, ok: false, lines: [] };
  } else {
    status = {
      text: `Connected to PhishShield API ${r.data.version}`,
      ok: true,
      lines: [
        ...r.data.providers.map(
          (p) =>
            `${p.name}: ${p.configured ? 'configured' : 'not configured'}${p.onDemand ? ' · manual scans + file hashes only' : ''}${p.entries !== undefined ? ` · ${p.entries} entries` : ''}${p.lastError ? ` · last error: ${p.lastError}` : ''}`,
        ),
        `AI analysis: ${r.data.ai.configured ? `${r.data.ai.provider} (${r.data.ai.model})` : 'not configured'}`,
      ],
    };
  }
  render();
}

// Broad host access is optional: requested when the user turns on a feature that needs it (Credential
// Guard or ad-space hiding) and given back once neither is on.
async function setSiteAccessFeature(key: 'credentialGuard' | 'hideAdSpaces', on: boolean): Promise<void> {
  if (on && !(await chrome.permissions.request({ origins: ALL_SITES }))) return render();
  await update({ [key]: on });
  if (!settings.credentialGuard && !settings.hideAdSpaces) await chrome.permissions.remove({ origins: ALL_SITES }).catch(() => false);
}

function render(): void {
  clear(app);
  const apiInput = el('input', { class: 'input', type: 'url', value: settings.apiBaseUrl, placeholder: 'http://localhost:8787', 'aria-label': 'API base URL' });
  apiInput.addEventListener('change', () => {
    const v = normalizeApiBase(apiInput.value);
    if (apiInput.value.trim() && !v) {
      status = { text: 'Use https://… (or http://localhost for local development).', ok: false, lines: [] };
      render();
      return;
    }
    void update({ apiBaseUrl: v });
  });

  const level = el(
    'select',
    { class: 'input', 'aria-label': 'Protection level' },
    el('option', { value: 'likely', selected: settings.protectionLevel === 'likely' }, 'Known threats + likely phishing'),
    el('option', { value: 'confirmed', selected: settings.protectionLevel === 'confirmed' }, 'Known threats only'),
    el('option', { value: 'off', selected: settings.protectionLevel === 'off' }, 'Never (badge only)'),
  );
  level.addEventListener('change', () => void update({ protectionLevel: level.value as ProtectionLevel }));

  const lang = el('select', { class: 'input', 'aria-label': 'Language' }, el('option', { value: 'en', selected: settings.language === 'en' }, 'English'), el('option', { value: 'hi', selected: settings.language === 'hi' }, 'हिंदी (Hindi)'));
  lang.addEventListener('change', () => void update({ language: lang.value as 'en' | 'hi' }));

  append(
    app,
    el('div', { class: 'opt-head' }, el('div', { class: 'mark' }, icon('shield', 20)), el('h1', {}, 'PhishShield AI settings')),

    el(
      'section',
      { class: 'card' },
      el('h2', {}, 'Protection'),
      el('p', {}, 'Local URL checks run for every page you open, entirely on your device. A full-page warning appears only for high-risk results; lower-risk findings show as a badge on the toolbar icon.'),
      setting('Full-page warnings', 'Which results interrupt navigation with a warning page. You can always go back or continue.', level),
      setting(
        'Credential Guard',
        'Warn when you start typing a password, OTP, PIN or card number on a risky page. Needs permission to run on all sites (requested only when you turn this on). It never reads what you type.',
        toggle(settings.credentialGuard, (v) => void setSiteAccessFeature('credentialGuard', v), 'Credential Guard'),
      ),
      setting('Language', 'Interface and spoken explanations.', lang),
    ),

    el(
      'section',
      { class: 'card' },
      el('h2', {}, 'Downloads and ads'),
      el('p', {}, 'These run on your device. Download Guard looks only at the file name, where it came from and its type; it never opens files.'),
      setting(
        'Download Guard',
        'Pause risky downloads (Android apps from websites, scripts, shortcuts, programs disguised as documents, files built inside a web page) and ask before keeping them.',
        toggle(settings.downloadGuard, (v) => void update({ downloadGuard: v }), 'Download Guard'),
      ),
      setting(
        'Scam-ad shield',
        'Block pop-under and push-notification ad networks that are commonly used to redirect people to fake prize, tech-support and loan pages. Applies only to third-party requests.',
        toggle(settings.blockMalvertising, (v) => void update({ blockMalvertising: v }), 'Scam-ad shield'),
      ),
      setting(
        'Block ads and trackers',
        'Also block mainstream advertising and tracking networks (Google ads, Amazon ads, Taboola, Outbrain, Criteo: about 80 networks in all). Off by default because some sites break or ask you to disable ad blockers. Ads served by the site itself (for example YouTube video ads) cannot be blocked this way.',
        toggle(settings.blockAds, (v) => void update({ blockAds: v }), 'Block ads and trackers'),
      ),
      settings.blockAds
        ? setting(
            'Hide empty ad spaces',
            'Blocked ads can leave empty boxes behind. This adds a small style sheet to pages that collapses known ad containers. Needs permission to run on all sites (requested now, removed when you turn this off). It reads nothing on the page.',
            toggle(settings.hideAdSpaces, (v) => void setSiteAccessFeature('hideAdSpaces', v), 'Hide empty ad spaces'),
          )
        : null,
      setting(
        'File fingerprint lookups',
        'When you scan a file in the Security Center, send its SHA-256 fingerprint (not the file) to your server, which looks it up on VirusTotal.',
        toggle(settings.fileHashLookup, (v) => void update({ fileHashLookup: v }), 'File fingerprint lookups'),
      ),
    ),

    el(
      'section',
      { class: 'card' },
      el('h2', {}, 'PhishShield server (optional)'),
      el('p', {}, 'Reputation lists (Google Safe Browsing, OpenPhish) and AI analysis run through a small server you control, so API keys never ship inside the extension. Without it, PhishShield works in local-only mode.'),
      setting('Server URL', 'Leave empty for local-only mode.', el('div', { class: 'ctl' }, apiInput, el('button', { class: 'btn', onclick: testConnection, disabled: !settings.apiBaseUrl }, 'Test'))),
      status ? el('div', { class: `status ${status.ok ? 'ok' : 'bad'}` }, status.text, ...status.lines.map((l) => el('div', { class: 'prov' }, l))) : null,
      setting(
        'Automatic reputation checks',
        'Send the address of each site you visit (without query string or fragment) to your server for reputation lookups. Private/local addresses are never sent. Results are cached in memory for up to an hour.',
        toggle(settings.autoReputation, (v) => void update({ autoReputation: v }), 'Automatic reputation checks'),
      ),
      setting(
        'Skip the AI privacy prompt',
        'When off, PhishShield asks before every remote AI analysis.',
        toggle(settings.aiConsentRemembered, (v) => void update({ aiConsentRemembered: v }), 'Skip AI prompt'),
      ),
    ),

    el(
      'section',
      { class: 'card' },
      el('h2', {}, 'Sites you trust'),
      el('p', {}, 'Heuristic warnings are muted for these domains. Matches on reputation lists still apply.'),
      trusted.length
        ? el(
            'ul',
            { class: 'trusted' },
            ...trusted.map((d) =>
              el(
                'li',
                {},
                d,
                el(
                  'button',
                  {
                    class: 'link-btn',
                    onclick: async () => {
                      trusted = await setTrusted(d, false);
                      render();
                    },
                  },
                  'Remove',
                ),
              ),
            ),
          )
        : el('p', { class: 'muted small' }, 'None yet.'),
    ),

    el(
      'section',
      { class: 'card privacy' },
      el('h2', {}, 'Privacy notice'),
      el(
        'ul',
        {},
        el('li', {}, 'No accounts, analytics or tracking. PhishShield does not keep a browsing history; per-tab results live in memory and are cleared when the browser closes.'),
        el('li', {}, 'Page content is read only when you click “Analyze page”, and only visible text plus counts of form-field types. Values you type into forms are never read.'),
        el('li', {}, 'Remote AI analysis happens only after you confirm. Before sending, e-mail addresses, phone, card, Aadhaar, PAN and long account numbers are redacted. Your PhishShield server forwards the excerpt to the AI provider it is configured with (Groq by default; see “Test” above) and does not store or log it. The provider processes it under its own API data policy.'),
        el('li', {}, 'Reputation checks send the page address without its query string to your server, which queries Google Safe Browsing (if configured) and matches it against a locally downloaded copy of the OpenPhish feed. Breach history comes from a locally downloaded copy of Have I Been Pwned’s public breach list, so no lookup is sent for it. VirusTotal is asked only for links you scan manually.'),
        el('li', {}, 'For domain age, your server sends only the site’s registered domain (for example “example.co.in”) to that domain’s official registry (RDAP). Turn this off on the server with RDAP_ENABLED=false.'),
        el('li', {}, 'File scanning happens on your device. Only the file’s SHA-256 fingerprint is ever sent (if enabled); files are never uploaded. Password checks send only the first 5 characters of the password’s SHA-1 hash, directly to Have I Been Pwned (k-anonymity).'),
        el('li', {}, 'AI findings are labelled as model-generated and can never mark a site as confirmed malicious. “No known threats” is never a guarantee of safety.'),
      ),
    ),
  );
}

async function init(): Promise<void> {
  settings = await getSettings();
  trusted = await getTrustedDomains();
  // Keep the toggle honest if the user revoked the permission in browser settings.
  if ((settings.credentialGuard || settings.hideAdSpaces) && !(await chrome.permissions.contains({ origins: ALL_SITES }))) settings = await saveSettings({ credentialGuard: false, hideAdSpaces: false });
  render();
}

void init();
