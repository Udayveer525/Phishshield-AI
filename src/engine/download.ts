import type { Severity, Signal, SignalCategory, SignalStrength, Verdict } from '../shared/types.js';
import { computeScore, decideVerdict, rankSignals, severityFor } from './aggregate.js';
import { DISK_IMAGE_EXT, EXECUTABLE_EXT, MACRO_OFFICE_EXT, RUNNABLE_EXT, SCRIPT_EXT, SHORTCUT_EXT, fileExtension, fileNameSignals, lureWords } from './file.js';
import { assess } from './index.js';

/**
 * Download Guard: judge a download from its metadata (name, source URL, page it came from, MIME
 * type, Chrome's own danger flag) before the user opens it. The file's bytes are not read here;
 * the Security Center can inspect the saved file on request.
 */

export interface DownloadMeta {
  filename: string;
  url: string;
  finalUrl?: string;
  referrer?: string;
  mime?: string;
  fileSize?: number;
  /** chrome.downloads DangerType. */
  danger?: string;
}

export type DownloadClass = 'android_app' | 'program' | 'script' | 'shortcut' | 'disk_image' | 'macro_document' | 'java' | 'archive' | 'document' | 'other';

export interface DownloadAssessment {
  filename: string;
  extension: string;
  fileClass: DownloadClass;
  sourceHost: string;
  referrerHost: string;
  verdict: Verdict;
  severity: Severity;
  /** Heuristic 0-100 risk score. Not a probability. */
  score: number;
  headline: string;
  signals: Signal[];
  /** True when Download Guard should pause the download and ask the user. */
  intervene: boolean;
  limitations: string[];
}

const ARCHIVE_EXT = new Set(['zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'cab', 'arj', 'ace', 'lzh', 'xz', 'bz2']);
const DOC_EXT = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'txt', 'csv', 'rtf', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'mp3', 'mp4']);

const APK_MIME = 'application/vnd.android.package-archive';
const PROGRAM_MIME = /^application\/(x-msdownload|x-msdos-program|x-ms-installer|x-msi|vnd\.microsoft\.portable-executable|x-executable|x-dosexec|java-archive|x-sh|x-bat)/i;

/** Chrome danger types worth repeating to the user (Chrome may also block these itself). */
const CHROME_DANGER: Record<string, string> = {
  file: 'Chrome considers this file type dangerous.',
  url: 'Google Safe Browsing reports the download address as malicious.',
  content: 'Google Safe Browsing reports this file as malicious.',
  uncommon: 'Chrome says this file is not commonly downloaded.',
  host: 'Chrome reports this site distributes harmful files.',
  unwanted: 'Chrome reports this file as unwanted software.',
  accountCompromise: 'Chrome reports this file can steal account details.',
};

export function classifyExtension(ext: string, mime = ''): DownloadClass {
  if (ext === 'apk' || ext === 'xapk' || ext === 'apks' || mime === APK_MIME) return 'android_app';
  if (EXECUTABLE_EXT.has(ext)) return 'program';
  if (SCRIPT_EXT.has(ext)) return 'script';
  if (SHORTCUT_EXT.has(ext)) return 'shortcut';
  if (DISK_IMAGE_EXT.has(ext)) return 'disk_image';
  if (MACRO_OFFICE_EXT.has(ext)) return 'macro_document';
  if (ext === 'jar') return 'java';
  if (ARCHIVE_EXT.has(ext)) return 'archive';
  if (DOC_EXT.has(ext)) return 'document';
  if (PROGRAM_MIME.test(mime)) return 'program';
  return 'other';
}

function sig(id: string, category: SignalCategory, strength: SignalStrength, weight: number, title: string, detail: string, evidence?: string[]): Signal {
  return { id, source: 'local_file', category, strength, weight, title, detail, ...(evidence?.length ? { evidence } : {}) };
}

function hostOf(u?: string): string {
  if (!u) return '';
  try {
    return new URL(u).hostname;
  } catch {
    return '';
  }
}

export function assessDownload(d: DownloadMeta, opts: { trustedDomains?: string[] } = {}): DownloadAssessment {
  const base = (d.filename.split(/[\\/]/).pop() ?? d.filename).slice(0, 255);
  const ext = fileExtension(base);
  const mime = (d.mime ?? '').toLowerCase();
  const fileClass = classifyExtension(ext, mime);
  const source = d.finalUrl || d.url;
  const scheme = source.slice(0, source.indexOf(':') + 1).toLowerCase();
  const sourceHost = hostOf(source);
  const referrerHost = hostOf(d.referrer);
  const runnable = RUNNABLE_EXT.has(ext) || fileClass === 'android_app' || fileClass === 'program' || fileClass === 'disk_image' || fileClass === 'macro_document';
  const signals: Signal[] = [...fileNameSignals(base)];
  const limitations = ['Download Guard checks the file name, where it came from and its type. It does not open the file. Use the Security Center to inspect the saved file.'];

  // --- What kind of file ------------------------------------------------------------------------
  const lure = lureWords(base);
  if (fileClass === 'android_app') {
    signals.push(sig('download.apk', 'infrastructure', 'moderate', 0.25, 'Android app from a website', 'Real banks, RTO, electricity boards and government schemes never ask you to install an app from a link or file. Use the Play Store.'));
    if (lure.length) signals.push(sig('download.apk_lure', 'impersonation', 'strong', 0.55, `App named like a ${lure[0]} app`, 'Fake "KYC", "RTO challan", "electricity bill" and "invitation" APKs steal OTPs and empty bank accounts.', [`name: ${base}`]));
  } else if (fileClass === 'program' || fileClass === 'java') {
    signals.push(sig('download.program', 'infrastructure', 'weak', 0.12, 'Program file', 'This file runs code on your computer.'));
    if (lure.length) signals.push(sig('download.program_lure', 'impersonation', 'moderate', 0.35, `Program named like a ${lure[0]} document`, 'Bills, invitations, challans and KYC forms are documents, never programs.', [`name: ${base}`]));
  } else if (fileClass === 'script') {
    signals.push(sig('download.script', 'evasion', 'moderate', 0.35, `Script file (.${ext})`, 'Scripts run commands the moment you open them. Websites rarely have a good reason to give you one.'));
  } else if (fileClass === 'shortcut') {
    signals.push(sig('download.shortcut', 'evasion', 'moderate', 0.4, 'Windows shortcut file', 'Downloaded .lnk files are almost always used to run hidden commands.'));
  } else if (fileClass === 'disk_image') {
    signals.push(sig('download.disk_image', 'evasion', 'moderate', 0.25, 'Disk image (ISO/IMG)', 'Used to deliver malware because files inside can skip Windows security warnings.'));
  } else if (fileClass === 'macro_document') {
    signals.push(sig('download.macro_document', 'evasion', 'moderate', 0.25, `Macro-enabled document (.${ext})`, 'Never click "Enable content" in a downloaded document.'));
  }

  // --- MIME disagrees with the name ------------------------------------------------------------
  if (mime === APK_MIME && ext !== 'apk') {
    signals.push(sig('download.mime_mismatch', 'obfuscation', 'strong', 0.5, `Named .${ext || '(none)'} but the server says it is an Android app`, 'The file is an APK disguised with another name.', [`mime: ${mime}`]));
  } else if (PROGRAM_MIME.test(mime) && DOC_EXT.has(ext)) {
    signals.push(sig('download.mime_mismatch', 'obfuscation', 'strong', 0.5, `Named .${ext} but the server says it is a program`, 'A program disguised as a document.', [`mime: ${mime}`]));
  }

  // --- Where it came from ------------------------------------------------------------------------
  if (scheme === 'blob:' || scheme === 'data:') {
    signals.push(sig('download.built_in_page', 'evasion', runnable ? 'strong' : 'weak', runnable ? 0.45 : 0.1, 'File was assembled inside the web page', `The page created this file itself (${scheme} link) instead of downloading it from a server. For programs this is a known trick ("HTML smuggling") to get past security scanners.`, [`source: ${scheme}…`]));
  }
  const pages = [...new Set([source, d.referrer].filter((u): u is string => !!u && /^https?:/i.test(u)))];
  for (const [i, u] of pages.entries()) {
    const a = assess(u, { trustedDomains: opts.trustedDomains });
    if (a.verdict === 'suspicious' || a.verdict === 'likely_phishing') {
      const which = u === d.referrer && i > 0 ? 'page' : 'address';
      signals.push(sig(`download.source_${which}`, 'infrastructure', a.verdict === 'likely_phishing' ? 'strong' : 'moderate', a.verdict === 'likely_phishing' ? 0.45 : 0.25, `Download ${which === 'page' ? 'started from a' : 'comes from a'} ${a.verdict === 'likely_phishing' ? 'likely phishing' : 'suspicious'} site`, `${a.displayHost}: ${a.headline}`, a.signals.filter((s) => s.weight > 0).slice(0, 3).map((s) => s.title)));
    }
  }
  if (/^http:/i.test(source) && runnable) {
    signals.push(sig('download.insecure', 'infrastructure', 'contextual', 0.08, 'Downloaded over plain HTTP', 'The file could have been swapped in transit.', [`source: ${sourceHost}`]));
  }

  // --- Chrome's own verdict ---------------------------------------------------------------------
  const danger = d.danger && d.danger !== 'safe' && d.danger !== 'accepted' ? d.danger : '';
  if (danger) {
    const sb = danger === 'url' || danger === 'content' || danger === 'host' || danger === 'accountCompromise';
    signals.push(sig(`download.chrome_${danger}`, sb ? 'threat_intel' : 'infrastructure', sb ? 'strong' : 'weak', sb ? 0.5 : 0.1, 'Chrome flagged this download', CHROME_DANGER[danger] ?? `Chrome danger type: ${danger}.`, [`danger: ${danger}`]));
  }

  const trusted = (opts.trustedDomains ?? []).some((t) => sourceHost === t || sourceHost.endsWith(`.${t}`));
  const effective = trusted ? signals.map((s) => (s.category === 'threat_intel' ? s : { ...s, weight: 0 })) : signals;
  if (trusted) limitations.push(`You trust ${sourceHost}, so file-type warnings are muted.`);

  const breakdown = computeScore(effective);
  const verdict = decideVerdict(breakdown, { reputationMatch: false });
  const ranked = rankSignals(effective);
  const top = ranked.find((s) => s.weight > 0);
  const prefix: Record<Verdict, string> = {
    confirmed_malicious: 'Known malicious download',
    likely_phishing: 'Likely dangerous download',
    suspicious: 'Risky download',
    no_known_threats: 'No warning signs',
    inconclusive: 'Could not check',
  };
  return {
    filename: base,
    extension: ext,
    fileClass,
    sourceHost,
    referrerHost,
    verdict,
    severity: severityFor(verdict, breakdown.score),
    score: breakdown.score,
    headline: verdict !== 'no_known_threats' && top ? `${prefix[verdict]}: ${top.title}` : prefix[verdict],
    signals: ranked,
    // Pause anything likely dangerous, and any runnable file that is at least suspicious.
    intervene: verdict === 'likely_phishing' || (verdict === 'suspicious' && runnable),
    limitations,
  };
}
