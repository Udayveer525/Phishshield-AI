import { describe, expect, it } from 'vitest';
import { assess, assessUpi, domainAgeSignals, extractUpiLinks, parseUpi } from '../src/engine/index.js';
import { analyzeQrPayload } from '../src/engine/qr.js';
import type { DomainInfo } from '../src/shared/types.js';

const ids = (r: { signals: Array<{ id: string }> }) => r.signals.map((s) => s.id);

describe('UPI links', () => {
  it('parses NPCI pay links and app variants', () => {
    const p = parseUpi('upi://pay?pa=ramesh.kumar@okaxis&pn=Ramesh%20Kumar&am=250.00&cu=INR&tn=Dinner')!;
    expect(p).toMatchObject({ kind: 'pay', payeeVpa: 'ramesh.kumar@okaxis', payeeName: 'Ramesh Kumar', amount: 250, currency: 'INR', note: 'Dinner', handle: 'okaxis', handleKnown: true, vpaValid: true });
    expect(parseUpi('tez://upi/pay?pa=a@oksbi')?.payeeVpa).toBe('a@oksbi');
    expect(parseUpi('phonepe://pay?pa=a@ybl')?.handle).toBe('ybl');
    expect(parseUpi('upi://mandate?pa=x@icici&am=999')?.kind).toBe('mandate');
    expect(parseUpi('https://example.com')).toBeNull();
  });

  it('always explains that scanning sends money', () => {
    const a = assessUpi('upi://pay?pa=shop@ybl&pn=Sharma%20Kirana&am=120')!;
    expect(a.whatHappens).toMatch(/SEND ₹120 .*Sharma Kirana/);
    expect(a.whatHappens).toMatch(/never need to scan a QR or enter your PIN to receive money/);
    expect(a.verdict).toBe('no_known_threats');
  });

  it('flags "scan to receive refund / prize" QRs as likely scams', () => {
    const a = assessUpi('upi://pay?pa=9876543210@ybl&pn=Refund%20Desk&am=4999&tn=Scan%20to%20receive%20your%20cashback%20refund')!;
    expect(ids(a)).toContain('upi.receive_lure');
    expect(a.verdict).toBe('likely_phishing');
    expect(a.recommendedAction).toMatch(/Do not pay/);
  });

  it('flags brand names on personal UPI IDs', () => {
    const a = assessUpi('upi://pay?pa=9123456780@ybl&pn=State%20Bank%20of%20India&tn=KYC%20verification%20fee&am=10')!;
    expect(ids(a)).toEqual(expect.arrayContaining(['upi.brand_personal_vpa', 'upi.fee_or_kyc']));
    expect(['suspicious', 'likely_phishing']).toContain(a.verdict);
  });

  it('only flags bills when paid to personal IDs', () => {
    expect(ids(assessUpi('upi://pay?pa=9123456780@ybl&pn=RTO%20Office&tn=e-challan%20fine')!)).toContain('upi.bill_personal_vpa');
    expect(ids(assessUpi('upi://pay?pa=bescom.billdesk@hdfcbank&pn=BESCOM&mc=4900&tn=electricity%20bill')!)).not.toContain('upi.bill_personal_vpa');
  });

  it('flags mandates and malformed payees', () => {
    expect(ids(assessUpi('upi://mandate?pa=x@icici&pn=Netflix&am=649')!)).toContain('upi.mandate');
    expect(ids(assessUpi('upi://pay?pn=Someone&am=5')!)).toContain('upi.invalid_vpa');
    expect(ids(assessUpi('upi://pay?pa=ab@weirdpsp')!)).toContain('upi.unknown_handle');
  });

  it('does not treat ordinary words as lures', () => {
    for (const note of ['Groceries', 'Rent October', 'Credit card bill', 'Birthday gift for Riya']) {
      expect(assessUpi(`upi://pay?pa=a.b@okhdfcbank&pn=Anita&tn=${encodeURIComponent(note)}`)!.verdict).toBe('no_known_threats');
    }
  });

  it('finds UPI links in messages', () => {
    expect(extractUpiLinks('Get ₹5000 now: upi://pay?pa=x@ybl&am=1. Thanks')).toEqual(['upi://pay?pa=x@ybl&am=1']);
  });
});

describe('QR payload routing', () => {
  it('routes UPI, URLs, Wi-Fi, contacts and text', () => {
    expect(analyzeQrPayload('upi://pay?pa=a@ybl').type).toBe('upi');
    const url = analyzeQrPayload('http://sbi-kyc-update.xyz/login');
    expect(url.type).toBe('url');
    if (url.type === 'url') expect(['suspicious', 'likely_phishing']).toContain(url.url.verdict);
    expect(analyzeQrPayload('example.com/menu').type).toBe('url');
    const wifi = analyzeQrPayload('WIFI:T:WPA;S:Cafe\\;Guest;P:secret;;');
    expect(wifi).toMatchObject({ type: 'wifi', ssid: 'Cafe;Guest', security: 'WPA' });
    expect(analyzeQrPayload('BEGIN:VCARD\nFN:A\nEND:VCARD').type).toBe('contact');
    const text = analyzeQrPayload('Your KYC is pending, share the OTP sent to your mobile');
    expect(text.type).toBe('text');
    if (text.type === 'text') expect(text.signals.length).toBeGreaterThan(0);
  });
});

describe('domain age', () => {
  const now = Date.UTC(2026, 9, 31);
  const info = (daysOld: number): DomainInfo => ({ domain: 'x.com', status: 'found', registeredAt: now - daysOld * 86_400_000, source: 'rdap', checkedAt: now });

  it('scores brand-new domains, but never enough to warn on their own', () => {
    const [s] = domainAgeSignals(info(2), now);
    expect(s).toMatchObject({ id: 'registry.domain_days_old', source: 'registry', strength: 'moderate' });
    const alone = assess('https://plain-example-shop.com/', { reputation: { status: 'checked', findings: [], domain: info(2) }, now });
    expect(alone.verdict).toBe('no_known_threats');
    expect(alone.signals.some((x) => x.id === 'registry.domain_days_old')).toBe(true);
  });

  it('adds weight to other warning signs', () => {
    const base = assess('http://sbi-rewards-kyc.com/login', { now });
    const young = assess('http://sbi-rewards-kyc.com/login', { reputation: { status: 'checked', findings: [], domain: info(3) }, now });
    expect(young.score).toBeGreaterThan(base.score);
  });

  it('treats old domains as information only and ignores bad data', () => {
    const [old] = domainAgeSignals(info(4000), now);
    expect(old).toMatchObject({ weight: 0, category: 'informational' });
    expect(old!.title).toMatch(/10 years ago/);
    expect(domainAgeSignals({ ...info(1), registeredAt: now + 10 * 86_400_000 }, now)).toEqual([]);
    expect(domainAgeSignals({ domain: 'x.io', status: 'unsupported', source: 'rdap', checkedAt: now }, now)).toEqual([]);
  });

  it('is muted for trusted domains', () => {
    const a = assess('https://plain-example-shop.com/', { reputation: { status: 'checked', findings: [], domain: info(1) }, trustedDomains: ['plain-example-shop.com'], now });
    expect(a.signals.find((x) => x.id === 'registry.domain_days_old')!.weight).toBe(0);
  });
});
