import type { AiAnalysis } from '../../shared/types.js';
import { ANALYSIS_SYSTEM_PROMPT, buildAnalysisPrompt, type AnalysisPromptInput } from './prompt.js';
import { ModelAnalysisSchema, validateAnalysis } from './schema.js';
import type { ModelClient } from './types.js';

export interface AiService {
  readonly configured: boolean;
  readonly provider: string | null;
  readonly model: string | null;
  analyze(input: AnalysisPromptInput): Promise<AiAnalysis>;
}

/** Provider-independent AI analysis: prompt building, validation and graceful degradation. */
export function createAiService(client: ModelClient | null, now: () => number = Date.now): AiService {
  return {
    configured: Boolean(client),
    provider: client?.provider ?? null,
    model: client?.model ?? null,

    async analyze(input) {
      if (!client) return { status: 'unavailable', message: 'AI analysis is not configured on the server (no AI provider API key set).' };
      const { user, groundingText } = buildAnalysisPrompt(input, client.maxInputChars);
      const out = await client.generate({ task: 'analysis', system: ANALYSIS_SYSTEM_PROMPT, user, schema: ModelAnalysisSchema });
      if (out.kind !== 'ok') {
        const status = out.kind === 'refused' ? 'refused' : out.kind === 'timeout' ? 'timeout' : out.kind === 'rate_limited' ? 'rate_limited' : 'error';
        return { status, provider: client.provider, model: client.model, message: out.message };
      }
      return validateAnalysis(out.output, groundingText, { provider: client.provider, model: out.model, now: now() });
    },
  };
}
