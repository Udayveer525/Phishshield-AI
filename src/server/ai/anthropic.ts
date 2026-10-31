import Anthropic from '@anthropic-ai/sdk';
import { betaZodOutputFormat } from '@anthropic-ai/sdk/helpers/beta/zod';
import type { ModelClient, ModelOutcome } from './types.js';

/** Optional alternative provider: Anthropic Claude via the official SDK with structured outputs. */

export const DEFAULT_ANTHROPIC_MODEL = 'claude-opus-5-5';

const MAX_TOKENS = { analysis: 6000 } as const;

export interface AnthropicOptions {
  apiKey?: string;
  model?: string;
  timeoutMs: number;
  /** Server-side fallback on overload ("default" routing). Disable if your account rejects it. */
  fallbacks: boolean;
}

export function createAnthropicClient(opts: AnthropicOptions): ModelClient | null {
  if (!opts.apiKey) return null;
  const model = opts.model || DEFAULT_ANTHROPIC_MODEL;
  const client = new Anthropic({ apiKey: opts.apiKey, maxRetries: 1, timeout: opts.timeoutMs });

  async function generate({ task, system, user, schema }: Parameters<ModelClient['generate']>[0]): Promise<ModelOutcome> {
    const request = (withFallbacks: boolean) =>
      client.beta.messages.parse({
        model,
        max_tokens: MAX_TOKENS[task],
        system,
        messages: [{ role: 'user', content: user }],
        // Classification-style task: low effort keeps latency acceptable for an interactive popup.
        output_config: { effort: 'low', format: betaZodOutputFormat(schema) },
        ...(withFallbacks ? { betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default' as const } : {}),
      });
    try {
      let response;
      try {
        response = await request(opts.fallbacks);
      } catch (err) {
        // If the account does not accept the fallback beta, retry once without it.
        if (opts.fallbacks && err instanceof Anthropic.BadRequestError && /fallback/i.test(err.message)) {
          response = await request(false);
        } else {
          throw err;
        }
      }
      if (response.stop_reason === 'refusal') return { kind: 'refused', message: 'The AI model declined to analyse this content.' };
      if (response.stop_reason === 'max_tokens') return { kind: 'truncated', message: 'The AI response was cut off.' };
      if (response.parsed_output === null || response.parsed_output === undefined) return { kind: 'error', message: 'The AI response could not be parsed.' };
      return { kind: 'ok', output: response.parsed_output, model: response.model };
    } catch (err) {
      if (err instanceof Anthropic.RateLimitError) return { kind: 'rate_limited', message: 'AI provider rate limit reached. Try again shortly.' };
      if (err instanceof Anthropic.APIConnectionTimeoutError) return { kind: 'timeout', message: `AI analysis timed out after ${opts.timeoutMs} ms.` };
      if (err instanceof Anthropic.AuthenticationError) return { kind: 'error', message: 'The AI provider rejected the server credentials.' };
      if (err instanceof Anthropic.APIError) return { kind: 'error', message: `AI provider error (${err.status ?? 'network'}).` };
      return { kind: 'error', message: 'AI analysis failed.' };
    }
  }

  return { provider: 'Anthropic Claude', model, maxInputChars: 8000, generate };
}
