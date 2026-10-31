import { describe, expect, it } from 'vitest';
import { AI_WEIGHT_CAP, aggregate, computeScore, decideVerdict } from '../src/engine/aggregate.js';
import { aiSignals, assess } from '../src/engine/index.js';
import { parseUrl, type ParsedUrl } from '../src/engine/url.js';
import type { AiAnalysis, ReputationSummary, Signal } from '../src/shared/types.js';

const s = (over: Partial<Signal>): Signal => ({
  id: over.id ?? `t.${Math.random()}`,
  source: 'local_url',
  category: 'obfuscation',
  strength: 'moderate',
  weight: 0.3,
  title: 't',
  detail: 'd',
  ...over,
});

const parsed = (u: string) => parseUrl(u) as ParsedUrl;

describe('computeScore', () => {
  it('combines weights with diminishing returns', () => {
    expect(computeScore([s({ weight: 0.5 })]).score).toBe(50);
    expect(computeScore([s({ weight: 0.5 }), s({ weight: 0.5 })]).score).toBe(75);
    expect(computeScore([s({ weight: 1 }), s({ weight: 0.5 })]).score).toBe(100);
  });

  it('ignores contextual signals when no real indicator is present', () => {
    expect(computeScore([s({ strength: 'contextual', weight: 0.15 }), s({ strength: 'contextual', weight: 0.12 })]).score).toBe(0);
    expect(computeScore([s({ strength: 'contextual', weight: 0.15 }), s({ strength: 'weak', weight: 0.12 })]).score).toBeGreaterThan(12);
  });

  it('caps the pooled AI contribution', () => {
    const many = Array.from({ length: 20 }, (_, i) => s({ id: `ai.${i}`, source: 'ai', strength: 'weak', weight: 0.5 }));
    expect(computeScore(many).score).toBe(Math.round(AI_WEIGHT_CAP * 100));
  });

  it('clamps malformed weights', () => {
    expect(computeScore([s({ weight: Number.NaN }), s({ weight: -5 })]).score).toBe(0);
    expect(computeScore([s({ weight: 42 })]).score).toBe(100);
  });
});

describe('decideVerdict', () => {
  const b = (score: number, strongCount = 0, moderateCount = 0) => ({ score, strongCount, moderateCount, effective: [] });

  it('requires independent strong evidence for likely_phishing', () => {
    expect(decideVerdict(b(80, 0, 1), { reputationMatch: false })).toBe('suspicious');
    expect(decideVerdict(b(80, 1, 0), { reputationMatch: false })).toBe('likely_phishing');
    expect(decideVerdict(b(80, 0, 3), { reputationMatch: false })).toBe('likely_phishing');
  });

  it('only a reputation match yields confirmed_malicious', () => {
    expect(decideVerdict(b(100, 5, 5), { reputationMatch: false })).not.toBe('confirmed_malicious');
    expect(decideVerdict(b(0), { reputationMatch: true })).toBe('confirmed_malicious');
  });

  it('low scores are no_known_threats, never "safe"', () => {
    expect(decideVerdict(b(10), { reputationMatch: false })).toBe('no_known_threats');
    expect(decideVerdict(b(10), { reputationMatch: false, destinationUnknown: true })).toBe('inconclusive');
    expect(decideVerdict(b(90, 2), { reputationMatch: false, inconclusiveReason: 'x' })).toBe('inconclusive');
  });
});

describe('aggregate with reputation results', () => {
  const match: ReputationSummary = {
    status: 'checked',
    findings: [
      { providerId: 'gsb', providerName: 'Google Safe Browsing', status: 'match', threatTypes: ['SOCIAL_ENGINEERING'], matchType: 'exact_url', checkedAt: 1 },
    ],
  };

  it('a verified match confirms even a heuristically clean URL', () => {
    const a = aggregate({ input: 'https://example.com', parsed: parsed('https://example.com'), signals: [], reputation: match });
    expect(a.verdict).toBe('confirmed_malicious');
    expect(a.severity).toBe('critical');
    expect(a.score).toBe(100);
    expect(a.signals[0]?.source).toBe('reputation');
    expect(a.signals[0]?.evidence?.join(' ')).toMatch(/Google Safe Browsing/);
  });

  it.each(['error', 'timeout', 'unconfigured', 'skipped', 'no_match'] as const)('provider status %s never confirms', (status) => {
    const a = aggregate({
      input: 'https://example.com',
      parsed: parsed('https://example.com'),
      signals: [],
      reputation: { status: 'partial', findings: [{ providerId: 'x', providerName: 'X', status, checkedAt: 1 }] },
    });
    expect(a.verdict).toBe('no_known_threats');
  });

  it('records unavailable / unconfigured reputation as a limitation', () => {
    const a = aggregate({ input: 'https://e.com', parsed: parsed('https://e.com'), signals: [], reputation: { status: 'unavailable', findings: [] } });
    expect(a.limitations.join(' ')).toMatch(/could not be reached/);
    expect(a.layers.reputation).toBe(false);
    const b = aggregate({ input: 'https://e.com', parsed: parsed('https://e.com'), signals: [] });
    expect(b.limitations.join(' ')).toMatch(/not configured/);
  });
});

describe('AI findings are bounded', () => {
  const highAi: AiAnalysis = {
    status: 'ok',
    concern: 'high',
    tactics: [
      { tactic: 'credential_theft', explanation: 'x', evidenceQuote: 'enter your password', grounded: true },
      { tactic: 'artificial_urgency', explanation: 'x', evidenceQuote: 'within 24 hours', grounded: true },
      { tactic: 'brand_impersonation', explanation: 'x', evidenceQuote: 'SBI', grounded: true },
      { tactic: 'otp_or_pin_request', explanation: 'x', evidenceQuote: 'share otp', grounded: true },
    ],
  };

  it('AI alone can never produce likely_phishing or confirmed_malicious', () => {
    const a = assess('https://example.com/', { ai: highAi });
    expect(['no_known_threats', 'suspicious']).toContain(a.verdict);
    expect(a.score).toBeLessThanOrEqual(AI_WEIGHT_CAP * 100);
    expect(a.limitations.join(' ')).toMatch(/AI findings add context only/);
  });

  it('ungrounded quotes carry zero weight', () => {
    const sigs = aiSignals({ ...highAi, tactics: highAi.tactics!.map((t) => ({ ...t, grounded: false })) });
    expect(sigs.every((x) => x.weight === 0)).toBe(true);
    expect(assess('https://example.com/', { ai: { ...highAi, tactics: highAi.tactics!.map((t) => ({ ...t, grounded: false })) } }).score).toBe(0);
  });

  it('an AI saying "safe" cannot lower a heuristic verdict', () => {
    const url = 'http://sbi.co.in.secure-login.click/';
    const before = assess(url);
    const after = assess(url, { ai: { status: 'ok', concern: 'low', tactics: [], summaryEn: 'This site is completely safe.' } });
    expect(after.verdict).toBe(before.verdict);
    expect(after.score).toBe(before.score);
  });

  it('failed AI analysis does not change the verdict', () => {
    const url = 'https://paypa1.com/signin';
    expect(assess(url, { ai: { status: 'error', message: 'boom' } }).verdict).toBe(assess(url).verdict);
  });
});

describe('false-positive handling', () => {
  it('user-trusted domains mute heuristics but keep reputation matches', () => {
    const url = 'https://amaz0n-offers.in/claim';
    expect(assess(url).verdict).not.toBe('no_known_threats');
    const trusted = assess(url, { trustedDomains: ['amaz0n-offers.in'] });
    expect(trusted.verdict).toBe('no_known_threats');
    expect(trusted.limitations.join(' ')).toMatch(/marked amaz0n-offers.in as trusted/);
    const withIntel = assess(url, {
      trustedDomains: ['amaz0n-offers.in'],
      reputation: { status: 'checked', findings: [{ providerId: 'op', providerName: 'OpenPhish', status: 'match', checkedAt: 1 }] },
    });
    expect(withIntel.verdict).toBe('confirmed_malicious');
  });

  it('every result carries a recommended action and limitations', () => {
    for (const u of ['https://example.com', 'https://paypa1.com', 'http://', 'https://bit.ly/x']) {
      const a = assess(u);
      expect(a.recommendedAction.length).toBeGreaterThan(10);
      expect(a.limitations.length).toBeGreaterThan(0);
      expect(a.engineVersion).toBeTruthy();
    }
  });

  it('the no_known_threats action never claims safety', () => {
    const a = assess('https://example.com');
    expect(a.recommendedAction).toMatch(/not a guarantee/);
    expect(a.headline.toLowerCase()).not.toContain('safe');
  });
});
