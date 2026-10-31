import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyzeQrPayload } from '../src/engine/qr.js';
import { assessFile, inspectFile } from '../src/engine/file.js';

// The harmless sample files in demo/ are used in docs/DEMO.md. These tests keep the demo honest:
// if a rule changes, the demo script's expected results must change with it.

const load = (name: string) => new Uint8Array(readFileSync(`demo/files/${name}`));
const assess = async (name: string) => assessFile(await inspectFile(load(name), name));

describe('demo files', () => {
  it('fake KYC APK is likely dangerous because of its name and SMS permissions', async () => {
    const a = await assess('SBI_YONO_KYC_Update.apk');
    expect(a.verdict).toBe('likely_phishing');
    expect(a.report.apkPermissions).toEqual(expect.arrayContaining(['RECEIVE_SMS', 'READ_SMS', 'BIND_ACCESSIBILITY_SERVICE']));
  });

  it('HTML attachment is a likely-dangerous login page with a phishing link inside', async () => {
    const a = await assess('Secure_Message_HDFC.html');
    expect(a.verdict).toBe('likely_phishing');
    expect(a.report.embeddedUrls).toContain('http://hdfc-netbanking-verify.top/login');
  });

  it('PDF with auto-run JavaScript is flagged and its link extracted', async () => {
    const a = await assess('Electricity_Bill_Disconnection.pdf');
    expect(['suspicious', 'likely_phishing']).toContain(a.verdict);
    expect(a.report.embeddedUrls).toContain('http://bescom-bill-update.xyz/pay');
  });

  it('macro document is at least suspicious', async () => {
    expect(['suspicious', 'likely_phishing']).toContain((await assess('Salary_Revision_2026.docm')).verdict);
  });

  it('a plain text file shows no known threats', async () => {
    expect((await assess('normal_notes.txt')).verdict).toBe('no_known_threats');
  });
});

describe('demo QR payloads', () => {
  // Same strings encoded in demo/qr/*.png.
  const verdictOf = (raw: string) => {
    const q = analyzeQrPayload(raw);
    return q.type === 'upi' ? q.upi.verdict : q.type === 'url' ? q.url.verdict : null;
  };

  it('classifies the four demo QR codes', () => {
    expect(verdictOf('upi://pay?pa=9876543210@ybl&pn=Refund%20Desk&am=4999&cu=INR&tn=Scan%20to%20receive%20your%20cashback%20refund')).toBe('likely_phishing');
    expect(verdictOf('upi://pay?pa=sbi.kyc.helpdesk@axl&pn=SBI%20KYC%20Department&am=10&cu=INR&tn=KYC%20verification%20fee')).not.toBe('no_known_threats');
    expect(verdictOf('upi://pay?pa=sharmakirana@okaxis&pn=Sharma%20Kirana&am=120&cu=INR&tn=Groceries')).toBe('no_known_threats');
    expect(verdictOf('http://sbi-kyc-update.xyz/login')).toBe('likely_phishing');
  });
});
