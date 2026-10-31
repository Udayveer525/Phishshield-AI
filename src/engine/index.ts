import type { AiAnalysis, PageSnapshot, ReputationSummary, RiskAssessment, Signal } from '../shared/types.js';
import { aggregate } from './aggregate.js';
import { analyzePage } from './content.js';
import { domainAgeSignals } from './domain-age.js';
import { parseUrl } from './url.js';
import { analyzeUrl } from './url-rules.js';

export * from './aggregate.js';
export * from './content.js';
export * from './url.js';
export * from './url-rules.js';
export * from './domain-age.js';
export * from './upi.js';
export * from './file.js';
export { BRANDS, officialBrandFor, isOfficialFor } from './brands.js';

export interface AssessOptions {
  /** Manual scans accept "example.com" without a scheme. */
  allowSchemeless?: boolean;
  reputation?: ReputationSummary;
  page?: PageSnapshot;
  ai?: AiAnalysis;
  /** Registrable domains the user explicitly trusts. Suppresses heuristics, never reputation. */
  trustedDomains?: string[];
  now?: number;
}

/** Full assessment for a URL from whichever layers are available. Pure and synchronous. */
export function assess(input: string, opts: AssessOptions = {}): RiskAssessment {
  const parsed = parseUrl(input, { allowSchemeless: opts.allowSchemeless });
  if (!parsed.ok) {
    const dangerousScheme = parsed.reason === 'unsupported_scheme' && (parsed.scheme === 'javascript' || parsed.scheme === 'data' || parsed.scheme === 'vbscript');
    const signals: Signal[] = dangerousScheme
      ? [
          {
            id: 'url.script_or_data_scheme',
            source: 'local_url',
            category: 'obfuscation',
            strength: 'strong',
            weight: 0.5,
            title: `"${parsed.scheme}:" link`,
            detail:
              parsed.scheme === 'data'
                ? 'data: links can contain an entire fake web page with no real web address behind it.'
                : 'This link runs code instead of opening a website.',
          },
        ]
      : [];
    return aggregate({
      input,
      parsed: null,
      signals,
      reputation: { status: 'skipped', findings: [] },
      inconclusiveReason: dangerousScheme ? undefined : parsed.message,
      limitations: [parsed.message],
      now: opts.now,
    });
  }

  const urlResult = analyzeUrl(parsed);
  let signals: Signal[] = [...urlResult.signals];
  const limitations = [...urlResult.limitations];

  if (opts.page) {
    const content = analyzePage(opts.page, parsed);
    signals.push(...content.signals);
    limitations.push(...content.limitations);
    if (!content.signals.length) limitations.push('Page content was analysed; no scam tactics were detected in the visible text.');
  }
  if (opts.ai?.status === 'ok') signals.push(...aiSignals(opts.ai));
  signals.push(...domainAgeSignals(opts.reputation?.domain, opts.now));

  const trusted = !!parsed.registrableDomain && (opts.trustedDomains ?? []).includes(parsed.registrableDomain);
  if (trusted) {
    signals = signals.map((s) => (s.source === 'reputation' ? s : { ...s, weight: 0 }));
    limitations.push(`You marked ${parsed.registrableDomain} as trusted, so heuristic warnings are muted. Reputation matches still apply.`);
  }

  const onlyShortener =
    urlResult.isShortener && !signals.some((s) => s.id !== 'url.shortener' && s.strength !== 'contextual' && s.weight > 0);

  return aggregate({
    input,
    parsed,
    signals,
    reputation: opts.reputation,
    ai: opts.ai,
    limitations,
    destinationUnknown: onlyShortener,
    now: opts.now,
  });
}

/**
 * Convert AI findings into low-weight signals. Only quotes that were found verbatim in the
 * submitted content count; ungrounded claims are shown but carry zero weight.
 */
export function aiSignals(ai: AiAnalysis): Signal[] {
  if (ai.status !== 'ok' || !ai.tactics?.length) return [];
  const base = ai.concern === 'high' ? 0.12 : ai.concern === 'medium' ? 0.08 : 0.04;
  return ai.tactics.map((t, i) => ({
    id: `ai.${t.tactic}.${i}`,
    source: 'ai' as const,
    category: t.tactic === 'prompt_injection' ? ('evasion' as const) : ('social_engineering' as const),
    strength: 'weak' as const,
    weight: t.grounded ? base : 0,
    title: `AI: ${humanizeTactic(t.tactic)}`,
    detail: t.explanation,
    evidence: [`${t.grounded ? 'quote' : 'unverified quote (not found in page)'}: “${t.evidenceQuote}”`],
  }));
}

export function humanizeTactic(t: string): string {
  const s = t.replace(/_/g, ' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

const URL_IN_TEXT =
  /\b(?:https?:\/\/[^\s<>"'()]+|(?:www\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.(?:[a-z]{2,24}|xn--[a-z0-9-]{2,30})(?:\/[^\s<>"'()]*)?)/gi;

/** Extract links from pasted SMS / WhatsApp / e-mail text (including bare domains). */
export function extractUrls(text: string, max = 10): string[] {
  const out = new Set<string>();
  for (const m of text.slice(0, 10_000).matchAll(URL_IN_TEXT)) {
    let u = m[0].replace(/[.,;:!?)\]]+$/, '');
    if (/^\d+(\.\d+)*$/.test(u)) continue; // plain numbers like 2.5
    if (!/[a-z]/i.test(u.split('/')[0]!)) continue;
    // Skip e-mail addresses.
    const before = text[(m.index ?? 0) - 1];
    if (before === '@') continue;
    if (!/^https?:\/\//i.test(u)) u = `http://${u}`;
    const p = parseUrl(u);
    if (p.ok && p.registrableDomain && p.knownSuffix) out.add(u);
    if (out.size >= max) break;
  }
  return [...out];
}
