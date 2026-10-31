import type { ReputationFinding, Severity, Signal, SignalCategory, SignalStrength, Verdict } from '../shared/types.js';
import { computeScore, decideVerdict, minorityDetectionSignal, rankSignals, severityFor } from './aggregate.js';

/**
 * Static file triage. Reads bytes only; nothing is ever executed, opened or uploaded.
 *
 * It answers "what is this file really, and does it look like the kind of file used in scams?"
 * It is not an antivirus: it cannot tell a clean installer from a trojan with the same shape.
 * Hash reputation (VirusTotal) is a separate, optional layer.
 */

export const MAX_INSPECT_BYTES = 256 * 1024 * 1024;
const MAX_ZIP_ENTRIES = 20_000;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const TEXT_SCAN_BYTES = 4 * 1024 * 1024;

export type FileKind =
  | 'windows_executable'
  | 'linux_executable'
  | 'mac_executable'
  | 'android_app'
  | 'java_archive'
  | 'office_document'
  | 'office_legacy'
  | 'zip'
  | 'rar'
  | '7z'
  | 'gzip'
  | 'pdf'
  | 'html'
  | 'disk_image'
  | 'shortcut'
  | 'script'
  | 'image'
  | 'text'
  | 'unknown';

export const KIND_LABEL: Record<FileKind, string> = {
  windows_executable: 'Windows program (PE)',
  linux_executable: 'Linux program (ELF)',
  mac_executable: 'macOS program (Mach-O)',
  android_app: 'Android app (APK)',
  java_archive: 'Java archive (JAR)',
  office_document: 'Office document',
  office_legacy: 'Legacy Office / installer (OLE)',
  zip: 'ZIP archive',
  rar: 'RAR archive',
  '7z': '7-Zip archive',
  gzip: 'GZIP archive',
  pdf: 'PDF document',
  html: 'HTML page',
  disk_image: 'Disk image (ISO)',
  shortcut: 'Windows shortcut (LNK)',
  script: 'Script',
  image: 'Image',
  text: 'Text',
  unknown: 'Unknown type',
};

export interface ZipEntry {
  name: string;
  compressedSize: number;
  size: number;
  encrypted: boolean;
  method: number;
  /** Offset of the local file header. */
  offset: number;
}

export interface FileReport {
  name: string;
  size: number;
  extension: string;
  kind: FileKind;
  kindLabel: string;
  signals: Signal[];
  /** Links found inside PDFs / HTML files, for checking with the URL engine. */
  embeddedUrls: string[];
  /** Android permissions found in an APK's manifest. */
  apkPermissions?: string[];
  zip?: { entries: number; encrypted: number; executables: string[]; truncated: boolean };
  pe?: { signed: boolean; is64: boolean };
  limitations: string[];
}

// ------------------------------------------------------------------------------------------------
// Extension classes

export const EXECUTABLE_EXT = new Set(['exe', 'scr', 'com', 'pif', 'cpl', 'msi', 'msix', 'msp', 'appx', 'appxbundle', 'dll', 'sys', 'gadget', 'application']);
export const SCRIPT_EXT = new Set(['bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'sct', 'reg', 'scf', 'inf', 'url', 'xll', 'iqy', 'slk']);
export const SHORTCUT_EXT = new Set(['lnk']);
export const DISK_IMAGE_EXT = new Set(['iso', 'img', 'vhd', 'vhdx']);
export const MACRO_OFFICE_EXT = new Set(['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm']);
const OFFICE_EXT = new Set(['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'odt', 'ods', 'odp', ...MACRO_OFFICE_EXT]);
const DOCUMENT_EXT = new Set([...OFFICE_EXT, 'pdf', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'mp3', 'mp4', 'mov', 'avi', 'wav', 'csv', 'zip', 'rar']);
const IMAGE_EXT = new Set(['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp']);
/** Extensions that run code when opened on a typical Windows / Android device. */
export const RUNNABLE_EXT = new Set([...EXECUTABLE_EXT, ...SCRIPT_EXT, ...SHORTCUT_EXT, 'apk', 'xapk', 'apks', 'jar']);

/** Bidi controls that can make "invoice\u202efdp.exe" render as "invoiceexe.pdf". */
const BIDI_CONTROLS = /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/;

/** File-name words used in Indian APK / malware campaigns (fake bank, challan, invitation, bill apps). */
const LURE_WORDS: Array<[RegExp, string]> = [
  [/\b(sbi|yono|hdfc|icici|axis|kotak|pnb|canara|bob|baroda|indusind|idfc|federal|union\s?bank|bank)\b/i, 'bank'],
  [/\b(paytm|phonepe|phone\s?pe|gpay|google\s?pay|bhim|upi|amazon\s?pay|cred)\b/i, 'payments app'],
  [/\b(kyc|e-?kyc|aadhaa?r|pan\s?card|pan|update|verify|verification|reactivat\w*|blocked)\b/i, 'KYC / verification'],
  [/\b(rto|e-?challan|challan|parivahan|traffic|fastag|vahan)\b/i, 'traffic challan'],
  [/\b(pm[\s_-]?kisan|kisan|yojana|subsidy|ration|gas\s?subsidy)\b/i, 'government scheme'],
  [/\b(electricity|bijli|power\s?bill|light\s?bill|bill\s?update|mseb|bescom|tneb)\b/i, 'electricity bill'],
  [/\b(wedding|shaadi|shadi|invitation|invite|card)\b/i, 'invitation'],
  [/\b(reward|points|cashback|refund|prize|lottery|gift|bonus|loan|income\s?tax|itr)\b/i, 'reward / refund'],
  [/\b(customer\s?care|support|helpdesk|courier|delivery|india\s?post|fedex|dtdc|bluedart)\b/i, 'support / delivery'],
];

// ------------------------------------------------------------------------------------------------
// Helpers

export function fileExtension(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? name;
  const i = base.lastIndexOf('.');
  return i > 0 ? base.slice(i + 1).toLowerCase().replace(/[^a-z0-9]/g, '') : '';
}

function startsWith(b: Uint8Array, sig: number[], at = 0): boolean {
  if (b.length < at + sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[at + i] !== sig[i]) return false;
  return true;
}

const u16 = (b: Uint8Array, o: number) => (o + 2 <= b.length ? b[o]! | (b[o + 1]! << 8) : 0);
const u32 = (b: Uint8Array, o: number) => (o + 4 <= b.length ? (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0 : 0);

/** Latin-1 view of bytes, enough for scanning ASCII markers in PDFs and HTML. */
function latin1(b: Uint8Array, max = TEXT_SCAN_BYTES): string {
  const n = Math.min(b.length, max);
  let out = '';
  for (let i = 0; i < n; i += 0x8000) out += String.fromCharCode(...b.subarray(i, Math.min(n, i + 0x8000)));
  return out;
}

function sig(id: string, category: SignalCategory, strength: SignalStrength, weight: number, title: string, detail: string, evidence?: string[]): Signal {
  return { id, source: 'local_file', category, strength, weight, title, detail, ...(evidence?.length ? { evidence } : {}) };
}

// ------------------------------------------------------------------------------------------------
// Type detection

export function detectKind(b: Uint8Array, ext = ''): FileKind {
  if (startsWith(b, [0x4d, 0x5a])) return 'windows_executable';
  if (startsWith(b, [0x7f, 0x45, 0x4c, 0x46])) return 'linux_executable';
  if ([[0xfe, 0xed, 0xfa, 0xce], [0xfe, 0xed, 0xfa, 0xcf], [0xce, 0xfa, 0xed, 0xfe], [0xcf, 0xfa, 0xed, 0xfe]].some((m) => startsWith(b, m))) return 'mac_executable';
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06])) return 'zip';
  if (startsWith(b, [0x25, 0x50, 0x44, 0x46, 0x2d])) return 'pdf';
  if (startsWith(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return 'office_legacy';
  if (startsWith(b, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) return 'rar';
  if (startsWith(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
  if (startsWith(b, [0x1f, 0x8b])) return 'gzip';
  if (startsWith(b, [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return 'shortcut';
  if (startsWith(b, [0x43, 0x44, 0x30, 0x30, 0x31], 0x8001) || startsWith(b, [0x43, 0x44, 0x30, 0x30, 0x31], 0x9001)) return 'disk_image';
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47]) || startsWith(b, [0xff, 0xd8, 0xff]) || startsWith(b, [0x47, 0x49, 0x46, 0x38])) return 'image';
  if (startsWith(b, [0x52, 0x49, 0x46, 0x46]) && startsWith(b, [0x57, 0x45, 0x42, 0x50], 8)) return 'image';
  const head = latin1(b.subarray(0, 1024)).replace(/^\ufeff|^\xef\xbb\xbf/, '').trimStart().toLowerCase();
  if (head.startsWith('#!')) return 'script';
  if (/^(<!doctype html|<html|<head|<body|<script|<meta|<form|<iframe|<svg[^>]*onload)/.test(head)) return 'html';
  if (SCRIPT_EXT.has(ext)) return 'script';
  if (ext === 'html' || ext === 'htm' || ext === 'shtml' || ext === 'xhtml' || ext === 'svg') return /<[a-z!]/.test(head) ? 'html' : 'text';
  return isMostlyText(b) ? 'text' : 'unknown';
}

function isMostlyText(b: Uint8Array): boolean {
  const n = Math.min(b.length, 2048);
  if (!n) return false;
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const c = b[i]!;
    if (c === 0) return false;
    if (c < 9 || (c > 13 && c < 32)) bad++;
  }
  return bad / n < 0.02;
}

/** Which extensions are consistent with a detected kind. Empty set means "any". */
const EXPECTED_EXT: Partial<Record<FileKind, string[]>> = {
  windows_executable: [...EXECUTABLE_EXT, 'efi', 'ocx', 'ax', 'mui', 'node', 'bin'],
  pdf: ['pdf', 'ai'],
  image: [...IMAGE_EXT, 'jfif', 'ico'],
  shortcut: ['lnk'],
  disk_image: [...DISK_IMAGE_EXT],
};

// ------------------------------------------------------------------------------------------------
// ZIP central directory

export function readZipEntries(b: Uint8Array): { entries: ZipEntry[]; truncated: boolean } | null {
  // End of central directory record: last 22 bytes + up to 64 KB comment.
  const min = Math.max(0, b.length - 22 - 0xffff);
  let eocd = -1;
  for (let i = b.length - 22; i >= min; i--) {
    if (b[i] === 0x50 && b[i + 1] === 0x4b && b[i + 2] === 0x05 && b[i + 3] === 0x06) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return null;
  let count = u16(b, eocd + 10);
  let cdOffset = u32(b, eocd + 16);
  // ZIP64: the real values live in the ZIP64 EOCD record.
  if (cdOffset === 0xffffffff || count === 0xffff) {
    const loc = eocd - 20;
    if (loc >= 0 && u32(b, loc) === 0x07064b50) {
      const z64 = Number(new DataView(b.buffer, b.byteOffset).getBigUint64(loc + 8, true));
      if (z64 + 56 <= b.length && u32(b, z64) === 0x06064b50) {
        count = Number(new DataView(b.buffer, b.byteOffset).getBigUint64(z64 + 32, true));
        cdOffset = Number(new DataView(b.buffer, b.byteOffset).getBigUint64(z64 + 48, true));
      }
    }
  }
  const entries: ZipEntry[] = [];
  let p = cdOffset;
  const decoder = new TextDecoder();
  while (entries.length < Math.min(count, MAX_ZIP_ENTRIES) && p + 46 <= b.length && u32(b, p) === 0x02014b50) {
    const flags = u16(b, p + 8);
    const method = u16(b, p + 10);
    const compressedSize = u32(b, p + 20);
    const size = u32(b, p + 24);
    const nameLen = u16(b, p + 28);
    const extraLen = u16(b, p + 30);
    const commentLen = u16(b, p + 32);
    const offset = u32(b, p + 42);
    const name = decoder.decode(b.subarray(p + 46, p + 46 + nameLen));
    entries.push({ name, compressedSize, size, encrypted: (flags & 1) === 1, method, offset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return { entries, truncated: count > entries.length };
}

/** Decompress one ZIP entry (stored or deflate). Returns null if unsupported or too large. */
export async function readZipEntry(b: Uint8Array, e: ZipEntry, maxBytes = MAX_MANIFEST_BYTES): Promise<Uint8Array | null> {
  if (e.encrypted || e.size > maxBytes || e.compressedSize > maxBytes || u32(b, e.offset) !== 0x04034b50) return null;
  const start = e.offset + 30 + u16(b, e.offset + 26) + u16(b, e.offset + 28);
  const data = b.subarray(start, start + e.compressedSize);
  if (e.method === 0) return data;
  if (e.method !== 8 || typeof DecompressionStream === 'undefined') return null;
  try {
    const stream = new Blob([data as Uint8Array<ArrayBuffer>]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    const out = new Uint8Array(await new Response(stream).arrayBuffer());
    return out.length <= maxBytes ? out : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------------------------------------
// Android

/** High-risk permissions typical of Indian banking trojans and SIM-binding / OTP-stealing apps. */
export const APK_PERMISSIONS: Array<{ perm: string; strength: SignalStrength; weight: number; what: string }> = [
  { perm: 'RECEIVE_SMS', strength: 'strong', weight: 0.45, what: 'read incoming SMS, including bank OTPs' },
  { perm: 'READ_SMS', strength: 'strong', weight: 0.45, what: 'read your SMS inbox, including bank OTPs' },
  { perm: 'SEND_SMS', strength: 'moderate', weight: 0.3, what: 'send SMS from your number (used to register UPI on your SIM)' },
  { perm: 'BIND_ACCESSIBILITY_SERVICE', strength: 'strong', weight: 0.4, what: 'control your screen and read what you type' },
  { perm: 'BIND_NOTIFICATION_LISTENER_SERVICE', strength: 'moderate', weight: 0.3, what: 'read all notifications, including OTPs' },
  { perm: 'SYSTEM_ALERT_WINDOW', strength: 'moderate', weight: 0.2, what: 'draw fake screens over your banking apps' },
  { perm: 'REQUEST_INSTALL_PACKAGES', strength: 'moderate', weight: 0.2, what: 'install more apps' },
  { perm: 'BIND_DEVICE_ADMIN', strength: 'moderate', weight: 0.3, what: 'resist uninstall and lock your phone' },
  { perm: 'READ_CALL_LOG', strength: 'weak', weight: 0.1, what: 'read your call history' },
  { perm: 'CALL_PHONE', strength: 'weak', weight: 0.1, what: 'place calls (used for call-forwarding codes)' },
  { perm: 'PROCESS_OUTGOING_CALLS', strength: 'weak', weight: 0.12, what: 'intercept outgoing calls' },
  { perm: 'READ_CONTACTS', strength: 'weak', weight: 0.08, what: 'read your contacts (used to spread to friends)' },
  { perm: 'QUERY_ALL_PACKAGES', strength: 'weak', weight: 0.08, what: 'see which banking apps you have' },
];

function utf16le(s: string): Uint8Array {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) out[i * 2] = s.charCodeAt(i);
  return out;
}

function indexOfBytes(hay: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

/** Find permission names in a compiled (binary XML) AndroidManifest.xml. Strings are UTF-16LE or UTF-8. */
export function apkPermissionsFrom(manifest: Uint8Array): string[] {
  const found = new Set<string>();
  const ascii = latin1(manifest);
  for (const { perm } of APK_PERMISSIONS) {
    const full = `android.permission.${perm}`;
    if (ascii.includes(full) || indexOfBytes(manifest, utf16le(full)) >= 0) found.add(perm);
  }
  return [...found];
}

// ------------------------------------------------------------------------------------------------
// Windows PE

export function peInfo(b: Uint8Array): { signed: boolean; is64: boolean } | null {
  const lfanew = u32(b, 0x3c);
  if (lfanew <= 0 || lfanew > b.length - 24 || u32(b, lfanew) !== 0x00004550) return null;
  const opt = lfanew + 24;
  const magic = u16(b, opt);
  const is64 = magic === 0x20b;
  if (magic !== 0x10b && !is64) return null;
  const dirs = opt + (is64 ? 112 : 96);
  const numDirs = u32(b, opt + (is64 ? 108 : 92));
  if (numDirs < 5) return { signed: false, is64 };
  // Data directory #4 = certificate table (Authenticode). Presence only; validity is not checked.
  const certSize = u32(b, dirs + 4 * 8 + 4);
  return { signed: certSize > 0, is64 };
}

// ------------------------------------------------------------------------------------------------
// PDF / HTML markers

const URL_RE = /https?:\/\/[^\s"'<>()\\\]]{4,300}/gi;

function extractLinks(text: string, max = 15): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(URL_RE)) {
    out.add(m[0].replace(/[.,;)]+$/, ''));
    if (out.size >= max) break;
  }
  return [...out];
}

function pdfSignals(text: string): { signals: Signal[]; urls: string[] } {
  const signals: Signal[] = [];
  const js = /\/(JavaScript|JS)\b/.test(text);
  const auto = /\/(OpenAction|AA)\b/.test(text);
  if (js) signals.push(sig('file.pdf_javascript', 'evasion', auto ? 'strong' : 'moderate', auto ? 0.45 : 0.3, auto ? 'PDF runs JavaScript when opened' : 'PDF contains JavaScript', 'Normal documents such as bills and statements do not need scripts. Scripts in PDFs are used to exploit readers or redirect you.', ['/JavaScript', ...(auto ? ['/OpenAction or /AA (runs automatically)'] : [])]));
  if (/\/Launch\b/.test(text)) signals.push(sig('file.pdf_launch', 'evasion', 'strong', 0.5, 'PDF tries to launch a program', 'The /Launch action asks the PDF reader to run another file or command.', ['/Launch']));
  if (/\/EmbeddedFile\b/.test(text)) signals.push(sig('file.pdf_embedded', 'evasion', 'weak', 0.15, 'PDF has a file hidden inside it', 'Embedded files can carry malware past e-mail filters.', ['/EmbeddedFile']));
  if (/\/(AcroForm|XFA)\b/.test(text) && /\/SubmitForm\b/.test(text)) signals.push(sig('file.pdf_submit_form', 'credential_harvest', 'moderate', 0.25, 'PDF form sends what you type to the internet', 'The PDF contains a form with a submit action. Do not type passwords or card details into a PDF.', ['/SubmitForm']));
  const uris = [...text.matchAll(/\/URI\s*\(([^)]{4,400})\)/g)].map((m) => m[1]!.replace(/\\(.)/g, '$1'));
  const urls = [...new Set([...uris.filter((u) => /^https?:/i.test(u)), ...extractLinks(text, 10)])].slice(0, 15);
  return { signals, urls };
}

function htmlSignals(text: string): { signals: Signal[]; urls: string[] } {
  const t = text.slice(0, 2_000_000);
  const signals: Signal[] = [];
  const password = /<input[^>]+type\s*=\s*["']?password/i.test(t);
  const form = /<form\b/i.test(t);
  const smuggle = /(msSaveOrOpenBlob|new\s+Blob\s*\(|URL\.createObjectURL|download\s*=)/.test(t) && /(atob\s*\(|base64|fromCharCode)/i.test(t);
  const obfuscated = /(eval\s*\(\s*(atob|unescape|decodeURIComponent)|document\.write\s*\(\s*(atob|unescape))/i.test(t);
  const autoRedirect = /(http-equiv\s*=\s*["']?refresh|window\.location(\.href)?\s*=|location\.replace\s*\()/i.test(t);
  if (password) signals.push(sig('file.html_login_form', 'credential_harvest', 'strong', 0.5, 'Attachment is a login page', 'This file is a web page with a password box that opens from your computer instead of the real website. Saved HTML login pages are a common way to steal passwords.', ['<input type=password>']));
  else if (form) signals.push(sig('file.html_form', 'credential_harvest', 'moderate', 0.2, 'Attachment contains a form', 'A local web page that asks you to type something and sends it to the internet.', ['<form>']));
  if (smuggle) signals.push(sig('file.html_smuggling', 'evasion', 'strong', 0.5, 'Builds a hidden download (HTML smuggling)', 'The page decodes data in your browser and saves it as a file. This is used to get malware past e-mail and network filters.', ['Blob / createObjectURL with base64 decoding']));
  if (obfuscated) signals.push(sig('file.html_obfuscated', 'evasion', 'moderate', 0.3, 'Hidden (obfuscated) script', 'The page decodes and runs scrambled code, which hides what it really does.', ['eval/document.write of decoded data']));
  if (autoRedirect) signals.push(sig('file.html_redirect', 'evasion', 'weak', 0.12, 'Redirects you to another site', 'Opening the file immediately sends you to a website.', []));
  const actions = [...t.matchAll(/<form[^>]+action\s*=\s*["']?(https?:\/\/[^"'\s>]+)/gi)].map((m) => m[1]!);
  return { signals, urls: [...new Set([...actions, ...extractLinks(t, 12)])].slice(0, 15) };
}

/** Deceptive file-name tricks. Name-only, so it also runs on downloads before any bytes are read. */
export function fileNameSignals(name: string): Signal[] {
  const signals: Signal[] = [];
  if (BIDI_CONTROLS.test(name)) {
    signals.push(sig('file.rtlo_name', 'obfuscation', 'strong', 0.6, 'File name uses hidden text-direction characters', 'Invisible Unicode controls make the name display a fake extension (e.g. "invoice\u202efdp.exe" shows as "invoiceexe.pdf"). This is only done to deceive.', [`name: ${JSON.stringify(name)}`]));
  }
  const parts = (name.split(/[\\/]/).pop() ?? name).toLowerCase().split('.');
  if (parts.length >= 3) {
    const last = parts[parts.length - 1]!.trim();
    const prev = parts[parts.length - 2]!.trim();
    if (RUNNABLE_EXT.has(last) && DOCUMENT_EXT.has(prev)) {
      signals.push(sig('file.double_extension', 'obfuscation', 'strong', 0.55, `Disguised as .${prev} but is .${last}`, `The file pretends to be a ${prev.toUpperCase()} document, but it is a program that runs when opened.`, [`name: ${name}`]));
    }
  }
  if (/\s{5,}\.\w+$/.test(name) || /\.(pdf|docx?|jpe?g)\s{3,}/i.test(name)) {
    signals.push(sig('file.padded_name', 'obfuscation', 'moderate', 0.3, 'File name padded with spaces', 'Long runs of spaces push the real extension out of view.', [`name: ${JSON.stringify(name)}`]));
  }
  return signals;
}

/** Which scam lure themes a file name uses ("SBI KYC", "RTO challan", "wedding invitation"...). */
export function lureWords(name: string): string[] {
  return LURE_WORDS.filter(([re]) => re.test(name.replace(/[_.\-+]/g, ' '))).map(([, label]) => label);
}

// ------------------------------------------------------------------------------------------------
// Main entry

export async function inspectFile(bytes: Uint8Array, name: string, opts: { declaredSize?: number } = {}): Promise<FileReport> {
  const ext = fileExtension(name);
  const size = opts.declaredSize ?? bytes.length;
  const truncatedRead = bytes.length < size;
  let kind = detectKind(bytes, ext);
  const signals: Signal[] = [];
  const limitations: string[] = [
    'Static check only: PhishShield never opens or runs the file. A clean result is not proof the file is safe; malware can look like a normal program.',
  ];
  if (truncatedRead) limitations.push(`Only the first ${Math.round(bytes.length / 1048576)} MB were inspected.`);
  const report: FileReport = { name, size, extension: ext, kind, kindLabel: KIND_LABEL[kind], signals, embeddedUrls: [], limitations };

  signals.push(...fileNameSignals(name));

  // --- Content vs. extension ----------------------------------------------------------------------
  const expected = EXPECTED_EXT[kind];
  if (expected && ext && !expected.includes(ext)) {
    const disguisedProgram = kind === 'windows_executable' || kind === 'shortcut';
    signals.push(sig('file.type_mismatch', 'obfuscation', disguisedProgram ? 'strong' : 'moderate', disguisedProgram ? 0.6 : 0.25, `Named .${ext} but is really a ${KIND_LABEL[kind]}`, disguisedProgram ? 'The file is a program disguised with a harmless-looking extension.' : 'The file content does not match its extension.', [`extension: .${ext}`, `content: ${KIND_LABEL[kind]}`]));
  }
  if (kind === 'linux_executable' || kind === 'mac_executable') {
    signals.push(sig('file.native_program', 'infrastructure', 'weak', 0.1, `${KIND_LABEL[kind]}`, 'A program file. Only run programs from publishers you trust.'));
  }

  // --- Container formats -------------------------------------------------------------------------
  if (kind === 'zip') {
    const zip = readZipEntries(bytes);
    if (zip) {
      const names = new Set(zip.entries.map((e) => e.name));
      const isApk = names.has('AndroidManifest.xml') && [...names].some((n) => /^classes\d*\.dex$/.test(n));
      const isJar = !isApk && names.has('META-INF/MANIFEST.MF') && [...names].some((n) => n.endsWith('.class'));
      const isOffice = names.has('[Content_Types].xml') && [...names].some((n) => /^(word|xl|ppt)\//.test(n));
      kind = isApk ? 'android_app' : isJar ? 'java_archive' : isOffice ? 'office_document' : 'zip';
      report.kind = kind;
      report.kindLabel = KIND_LABEL[kind];
      const executables = zip.entries
        .map((e) => e.name)
        .filter((n) => !n.endsWith('/') && RUNNABLE_EXT.has(fileExtension(n)) && !(isApk || isJar))
        .slice(0, 10);
      const encrypted = zip.entries.filter((e) => e.encrypted).length;
      report.zip = { entries: zip.entries.length, encrypted, executables, truncated: zip.truncated };

      if (kind === 'zip') {
        if (executables.length) {
          signals.push(sig('file.zip_contains_program', 'evasion', encrypted ? 'strong' : 'moderate', encrypted ? 0.5 : 0.35, 'Archive contains a program or script', 'Malware is often sent zipped so e-mail and chat scanners do not see it.', executables.map((n) => `inside: ${n}`)));
        }
        if (encrypted) {
          signals.push(sig('file.zip_encrypted', 'evasion', 'moderate', 0.25, 'Password-protected archive', 'Password-protected archives cannot be scanned by security tools. Scammers send the password in the same message for that reason.', [`${encrypted} encrypted entr${encrypted === 1 ? 'y' : 'ies'}`]));
        }
        const nested = zip.entries.filter((e) => /\.(zip|rar|7z|iso|img)$/i.test(e.name)).map((e) => e.name);
        if (nested.length && zip.entries.length <= 3) {
          signals.push(sig('file.zip_nested', 'evasion', 'weak', 0.12, 'Archive inside an archive', 'Nesting archives is a common trick to slip past scanners.', nested.slice(0, 3).map((n) => `inside: ${n}`)));
        }
        const total = zip.entries.reduce((a, e) => a + e.size, 0);
        const packed = zip.entries.reduce((a, e) => a + e.compressedSize, 0);
        if (total > 1_000_000_000 && packed > 0 && total / packed > 100) {
          signals.push(sig('file.zip_bomb', 'evasion', 'moderate', 0.3, 'Archive expands to an enormous size', 'The archive is built to expand far beyond its size, which can freeze scanners or your device.', [`packed ${packed} bytes → ${total} bytes`]));
        }
      }

      if (kind === 'office_document' && [...names].some((n) => /^(word|xl|ppt)\/vbaProject\.bin$/.test(n))) {
        signals.push(sig('file.office_macros', 'evasion', 'strong', 0.45, 'Document contains macros', 'Macros are programs inside the document. Scam documents ask you to "Enable content" so the macro can install malware.', ['vbaProject.bin']));
      }
      if (kind === 'office_document' && [...names].some((n) => /externalLink|oleObject/i.test(n))) {
        signals.push(sig('file.office_external', 'evasion', 'weak', 0.12, 'Document loads external or embedded objects', 'Embedded OLE objects and external links can fetch or run content when opened.', []));
      }

      if (kind === 'android_app') {
        const manifest = zip.entries.find((e) => e.name === 'AndroidManifest.xml')!;
        const data = await readZipEntry(bytes, manifest);
        if (data) {
          const perms = apkPermissionsFrom(data);
          report.apkPermissions = perms;
          for (const p of APK_PERMISSIONS.filter((x) => perms.includes(x.perm))) {
            signals.push(sig(`file.apk_perm.${p.perm.toLowerCase()}`, 'credential_harvest', p.strength, p.weight, `App can ${p.what}`, `The app requests android.permission.${p.perm}.`, [`android.permission.${p.perm}`]));
          }
        } else {
          limitations.push('The APK manifest could not be read, so app permissions were not checked.');
        }
      }
    } else {
      limitations.push('The archive directory could not be read (damaged or incomplete file).');
    }
  }

  // --- Kind-based risk ------------------------------------------------------------------------------
  const lure = lureWords(name);
  if (kind === 'android_app' || ext === 'apk' || ext === 'xapk' || ext === 'apks') {
    signals.push(sig('file.apk_sideload', 'infrastructure', 'moderate', 0.25, 'Android app from outside the Play Store', 'Banks, RTO, electricity boards and government schemes never send apps as files over WhatsApp, SMS or e-mail. Install apps only from the Play Store.'));
    if (lure.length) {
      signals.push(sig('file.apk_lure_name', 'impersonation', 'strong', 0.55, `App named like a ${lure[0]} app`, 'Fake "bank KYC", "RTO challan", "electricity bill" and "wedding invitation" APKs are a leading cause of account takeovers in India. They read your OTPs and empty your account.', [`name: ${name}`, `lure: ${lure.join(', ')}`]));
    }
  } else if (kind === 'windows_executable' || EXECUTABLE_EXT.has(ext)) {
    const pe = kind === 'windows_executable' ? peInfo(bytes) : null;
    if (pe) report.pe = pe;
    signals.push(sig('file.windows_program', 'infrastructure', 'weak', 0.12, 'Windows program', 'This file runs code on your computer. Only run programs downloaded from the publisher’s official site.'));
    if (pe && !pe.signed) signals.push(sig('file.unsigned', 'infrastructure', 'weak', 0.12, 'Not digitally signed', 'Most legitimate installers are signed by their publisher. (PhishShield only checks that a signature exists, not that it is valid.)', ['no Authenticode certificate table']));
    if (lure.length) signals.push(sig('file.program_lure_name', 'impersonation', 'moderate', 0.35, `Program named like a ${lure[0]} document`, 'Bills, invitations, challans and KYC forms are documents, never programs.', [`name: ${name}`]));
  } else if (kind === 'shortcut' || SHORTCUT_EXT.has(ext)) {
    signals.push(sig('file.shortcut', 'evasion', 'moderate', 0.4, 'Windows shortcut file', 'Shortcut (.lnk) files can run hidden commands. They are almost never sent legitimately.'));
  } else if (kind === 'script' || SCRIPT_EXT.has(ext)) {
    signals.push(sig('file.script', 'evasion', 'moderate', 0.35, `Script file (.${ext || 'sh'})`, 'Scripts run commands on your computer as soon as you open them. Regular documents are never sent as scripts.'));
  } else if (kind === 'disk_image' || DISK_IMAGE_EXT.has(ext)) {
    signals.push(sig('file.disk_image', 'evasion', 'moderate', 0.25, 'Disk image', 'ISO/IMG files are used to deliver malware because files inside them can skip Windows security warnings.'));
  } else if (kind === 'java_archive' || ext === 'jar') {
    signals.push(sig('file.jar', 'infrastructure', 'moderate', 0.25, 'Java program', 'JAR files run code on your computer and are a common malware format.'));
  } else if (MACRO_OFFICE_EXT.has(ext)) {
    signals.push(sig('file.macro_extension', 'evasion', 'moderate', 0.25, `Macro-enabled document (.${ext})`, 'This document type is allowed to contain macros. Never click "Enable content".'));
  }

  // --- Document internals ---------------------------------------------------------------------------
  if (kind === 'pdf') {
    const { signals: s, urls } = pdfSignals(latin1(bytes));
    signals.push(...s);
    report.embeddedUrls = urls;
    if (/\/(ObjStm|FlateDecode)\b/.test(latin1(bytes.subarray(0, 1_000_000)))) limitations.push('Compressed PDF streams were not unpacked; scripts hidden inside them may be missed.');
  }
  if (kind === 'html') {
    const { signals: s, urls } = htmlSignals(new TextDecoder().decode(bytes.subarray(0, TEXT_SCAN_BYTES)));
    signals.push(...s);
    report.embeddedUrls = urls;
  }
  if (kind === 'office_legacy' && /(_VBA_PROJECT|VBA\b|Macros)/.test(latin1(bytes))) {
    signals.push(sig('file.office_macros', 'evasion', 'strong', 0.45, 'Document contains macros', 'Macros are programs inside the document. Scam documents ask you to "Enable content" so the macro can install malware.', ['VBA project stream']));
  }

  if (size === 0) limitations.push('The file is empty.');
  report.signals = dedupe(signals);
  return report;
}

function dedupe(signals: Signal[]): Signal[] {
  const seen = new Set<string>();
  return signals.filter((s) => (seen.has(s.id) ? false : (seen.add(s.id), true)));
}

/** SHA-256 of the bytes, lower-case hex. Uses WebCrypto (browser and Node). */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>);
  return [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

// ------------------------------------------------------------------------------------------------
// Verdict

export interface FileAssessment {
  report: FileReport;
  sha256?: string;
  verdict: Verdict;
  severity: Severity;
  /** Heuristic 0-100 risk score. Not a probability. */
  score: number;
  headline: string;
  recommendedAction: string;
  signals: Signal[];
  reputation?: ReputationFinding;
  limitations: string[];
}

const FILE_ACTIONS: Record<Verdict, string> = {
  confirmed_malicious: 'Delete this file without opening it. If you already opened or installed it, disconnect from the internet, uninstall it, change your banking passwords from another device and call your bank (or 1930).',
  likely_phishing: 'Do not open or install this file. Delete it, and ask the sender through a different channel whether they really sent it.',
  suspicious: 'Be careful. Only open this file if you were expecting it from someone you trust, and never enable macros or install apps from files.',
  no_known_threats: 'No known threats were found, but that is not a guarantee. Only open files you were expecting from people you trust.',
  inconclusive: 'PhishShield could not fully check this file. Treat it with caution.',
};

const FILE_PREFIX: Record<Verdict, string> = {
  confirmed_malicious: 'Known malicious file',
  likely_phishing: 'Likely dangerous file',
  suspicious: 'Suspicious file',
  no_known_threats: 'No known threats found',
  inconclusive: 'Could not fully check',
};

export function assessFile(report: FileReport, opts: { sha256?: string; reputation?: ReputationFinding } = {}): FileAssessment {
  const rep = opts.reputation;
  const signals = [...report.signals];
  const limitations = [...report.limitations];
  const confirmed = rep?.status === 'match';
  if (confirmed) {
    signals.unshift({
      id: `intel.${rep.providerId}`,
      source: 'reputation',
      category: 'threat_intel',
      strength: 'strong',
      weight: 1,
      title: rep.detections ? `${rep.detections.malicious} of ${rep.detections.total} security vendors flag this file as malicious` : `Listed by ${rep.providerName}`,
      detail: `${rep.providerName} has seen this exact file (same SHA-256) and multiple antivirus engines identify it as malware.`,
      evidence: [`provider: ${rep.providerName}`, ...(opts.sha256 ? [`sha256: ${opts.sha256}`] : []), ...(rep.threatTypes?.length ? [`labels: ${rep.threatTypes.join(', ')}`] : [])],
    });
  } else if (rep) {
    const minority = minorityDetectionSignal(rep, 'file');
    if (minority) signals.unshift(minority);
    if (rep.status === 'no_match' && !rep.detections) limitations.push(`${rep.providerName} has never seen this file. New or targeted files are often unknown, so this is not a clean bill of health.`);
    if (rep.status === 'error' || rep.status === 'timeout') limitations.push(`${rep.providerName} lookup failed: ${rep.message ?? rep.status}.`);
    if (rep.status === 'unconfigured') limitations.push('Hash reputation is not configured on the server (set VT_API_KEY).');
  } else {
    limitations.push('Hash reputation was not checked.');
  }
  const breakdown = computeScore(signals);
  const verdict = decideVerdict(breakdown, { reputationMatch: confirmed });
  const score = confirmed ? 100 : breakdown.score;
  const ranked = rankSignals(signals);
  const top = ranked.find((s) => s.weight > 0);
  if (verdict === 'no_known_threats') limitations.push('“No known threats” is not proof the file is safe.');
  return {
    report,
    sha256: opts.sha256,
    verdict,
    severity: severityFor(verdict, score),
    score,
    headline: verdict !== 'no_known_threats' && top ? `${FILE_PREFIX[verdict]}: ${top.title}` : FILE_PREFIX[verdict],
    recommendedAction: FILE_ACTIONS[verdict],
    signals: ranked,
    reputation: rep,
    limitations: [...new Set(limitations)],
  };
}

