import { z } from 'zod';
import { AI_TACTICS, type AiAnalysis, type AiTacticFinding } from '../../shared/types.js';

/**
 * Schema the model is asked to produce (structured output). Kept free of length constraints so
 * it maps cleanly onto JSON Schema; limits are enforced afterwards by `validateAnalysis`.
 */
export const ModelAnalysisSchema = z.object({
  concern: z.enum(['low', 'medium', 'high']),
  summary_en: z.string(),
  summary_hi: z.string(),
  impersonated_brand: z.string().nullable(),
  tactics: z.array(
    z.object({
      tactic: z.enum(AI_TACTICS),
      evidence_quote: z.string(),
      explanation: z.string(),
    }),
  ),
  advice: z.array(z.string()),
  injection_attempt_detected: z.boolean(),
});
export type ModelAnalysis = z.infer<typeof ModelAnalysisSchema>;

const MAX_TACTICS = 8;

function clip(s: string, n: number): string {
  const t = s.replace(/\s+/g, ' ').trim();
  return t.length > n ? `${t.slice(0, n - 1)}…` : t;
}

function norm(s: string): string {
  return s.normalize('NFKC').toLowerCase().replace(/[“”"'‘’`]/g, '').replace(/\s+/g, ' ').trim();
}

/**
 * Validate model output at the trust boundary. Anything malformed is rejected outright; valid
 * output is clipped, de-duplicated, and every evidence quote is checked against the submitted
 * content so ungrounded claims can be shown as such and carry no weight.
 */
export function validateAnalysis(
  raw: unknown,
  sourceText: string,
  meta: { provider: string; model: string; now?: number },
): AiAnalysis {
  const parsed = ModelAnalysisSchema.safeParse(raw);
  if (!parsed.success) {
    return { status: 'error', provider: meta.provider, model: meta.model, message: 'The AI response did not match the expected format and was discarded.' };
  }
  const d = parsed.data;
  const haystack = norm(sourceText);
  const seen = new Set<string>();
  const tactics: AiTacticFinding[] = [];
  for (const t of d.tactics) {
    const quote = clip(t.evidence_quote, 200);
    const key = `${t.tactic}|${norm(quote)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const q = norm(quote.replace(/…$/, ''));
    tactics.push({
      tactic: t.tactic,
      evidenceQuote: quote,
      explanation: clip(t.explanation, 300),
      grounded: q.length >= 4 && haystack.includes(q),
    });
    if (tactics.length >= MAX_TACTICS) break;
  }
  return {
    status: 'ok',
    provider: meta.provider,
    model: meta.model,
    concern: d.concern,
    summaryEn: clip(d.summary_en, 600),
    summaryHi: clip(d.summary_hi, 800),
    impersonatedBrand: d.impersonated_brand ? clip(d.impersonated_brand, 80) : null,
    tactics,
    advice: d.advice.slice(0, 4).map((a) => clip(a, 200)),
    injectionAttemptDetected: d.injection_attempt_detected || tactics.some((t) => t.tactic === 'prompt_injection'),
    analyzedAt: meta.now ?? Date.now(),
  };
}
