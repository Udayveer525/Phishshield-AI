export type ProtectionLevel = 'likely' | 'confirmed' | 'off';
export type UiLanguage = 'en' | 'hi';

export interface Settings {
  /** Base URL of the optional PhishShield API (reputation + AI). Empty = local-only mode. */
  apiBaseUrl: string;
  /** Automatically check visited sites against reputation providers via the API. */
  autoReputation: boolean;
  /** Which verdicts show a full-page warning before the site loads. */
  protectionLevel: ProtectionLevel;
  /** Warn when typing passwords/OTPs on risky pages (needs optional site access). */
  credentialGuard: boolean;
  language: UiLanguage;
  /** User confirmed the remote-AI privacy notice and asked not to be asked again. */
  aiConsentRemembered: boolean;
  /** Pause risky downloads (APKs, scripts, disguised programs) and ask first. */
  downloadGuard: boolean;
  /** Block pop-under / push-spam ad networks often used for scam redirects. */
  blockMalvertising: boolean;
  /** Block mainstream ad and tracking networks (off by default: can break some sites). */
  blockAds: boolean;
  /** Look up file fingerprints (SHA-256) on VirusTotal via the server when scanning files. */
  fileHashLookup: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  apiBaseUrl: 'http://localhost:8787',
  autoReputation: true,
  protectionLevel: 'likely',
  credentialGuard: false,
  language: 'en',
  aiConsentRemembered: false,
  downloadGuard: true,
  blockMalvertising: true,
  blockAds: false,
  fileHashLookup: true,
};

export async function getSettings(): Promise<Settings> {
  try {
    const { settings } = await chrome.storage.local.get('settings');
    return { ...DEFAULT_SETTINGS, ...(settings as Partial<Settings> | undefined) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const next = { ...(await getSettings()), ...patch };
  next.apiBaseUrl = normalizeApiBase(next.apiBaseUrl);
  await chrome.storage.local.set({ settings: next });
  return next;
}

export function normalizeApiBase(raw: string): string {
  const t = raw.trim().replace(/\/+$/, '');
  if (!t) return '';
  try {
    const u = new URL(t);
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname))) return '';
    return `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
  } catch {
    return '';
  }
}

/** Registrable domains the user explicitly trusts (false-positive overrides). Stored locally only. */
export async function getTrustedDomains(): Promise<string[]> {
  try {
    const { trustedDomains } = await chrome.storage.local.get('trustedDomains');
    return Array.isArray(trustedDomains) ? (trustedDomains as string[]) : [];
  } catch {
    return [];
  }
}

export async function setTrusted(domain: string, trusted: boolean): Promise<string[]> {
  const list = new Set(await getTrustedDomains());
  if (trusted) list.add(domain);
  else list.delete(domain);
  const out = [...list].sort().slice(0, 500);
  await chrome.storage.local.set({ trustedDomains: out });
  return out;
}
