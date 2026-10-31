import { z } from 'zod';
import { isTimeoutError, readTextLimited, type FetchLike } from '../util.js';
import type { ModelClient, ModelOutcome, StructuredRequest } from './types.js';

/**
 * Groq chat-completions client (OpenAI-compatible API).
 * Docs: https://console.groq.com/docs/structured-outputs, /docs/reasoning, /docs/rate-limits
 *
 * - Models that support strict JSON Schema output use `response_format: json_schema, strict: true`,
 *   so the reply is constrained to our schema. Other models fall back to JSON object mode with the
 *   schema described in the system prompt. Either way the reply is validated again here.
 * - gpt-oss models are reasoning models: reasoning effort is kept low and reasoning text is not returned.
 */

export const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
export const DEFAULT_GROQ_MODEL = 'openai/gpt-oss-120b';

const STRICT_SCHEMA_MODELS = new Set(['openai/gpt-oss-20b', 'openai/gpt-oss-120b', 'qwen/qwen3.8-27b', 'meta-models/muse-spark-open']);
const isGptOss = (model: string) => model.startsWith('openai/gpt-oss');

// The free tier allows ~8K tokens per minute on gpt-oss models, so keep each request well under that.
const TASK_SETTINGS = {
  analysis: { maxTokens: 2048, temperature: 0.2 },
} as const;
const MAX_INPUT_CHARS = 6000;
const MAX_RESPONSE_BYTES = 256 * 1024;

const ChatCompletion = z.object({
  model: z.string(),
  choices: z
    .array(
      z.object({
        finish_reason: z.string().nullable(),
        message: z.object({ content: z.string().nullable().optional() }),
      }),
    )
    .min(1),
});

export interface GroqOptions {
  apiKey?: string;
  model?: string;
  timeoutMs: number;
  fetchImpl?: FetchLike;
}

/** JSON Schema for `response_format`. zod's output mode already marks every field required and objects closed, as strict mode needs. */
export function toResponseSchema(schema: z.ZodType): Record<string, unknown> {
  const { $schema: _drop, ...rest } = z.toJSONSchema(schema) as Record<string, unknown>;
  return rest;
}

export function createGroqClient(opts: GroqOptions): ModelClient | null {
  if (!opts.apiKey) return null;
  const apiKey = opts.apiKey;
  const model = opts.model || DEFAULT_GROQ_MODEL;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const strict = STRICT_SCHEMA_MODELS.has(model);

  function buildBody(req: StructuredRequest, reasoningParams: boolean): Record<string, unknown> {
    const settings = TASK_SETTINGS[req.task];
    const jsonSchema = toResponseSchema(req.schema);
    return {
      model,
      messages: [
        {
          role: 'system',
          content: strict ? req.system : `${req.system}\n\nRespond with a single JSON object that matches this JSON Schema exactly:\n${JSON.stringify(jsonSchema)}`,
        },
        { role: 'user', content: req.user },
      ],
      max_completion_tokens: settings.maxTokens,
      temperature: settings.temperature,
      response_format: strict
        ? { type: 'json_schema', json_schema: { name: `phishshield_${req.task}`, strict: true, schema: jsonSchema } }
        : { type: 'json_object' },
      ...(reasoningParams && isGptOss(model) ? { reasoning_effort: 'low', include_reasoning: false } : {}),
    };
  }

  async function send(req: StructuredRequest, reasoningParams: boolean): Promise<{ res: Response; text: string } | ModelOutcome> {
    try {
      const res = await fetchImpl(GROQ_API_URL, {
        method: 'POST',
        headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(buildBody(req, reasoningParams)),
        signal: AbortSignal.timeout(opts.timeoutMs),
        redirect: 'error',
      });
      return { res, text: await readTextLimited(res, MAX_RESPONSE_BYTES) };
    } catch (err) {
      if (isTimeoutError(err)) return { kind: 'timeout', message: `AI analysis timed out after ${opts.timeoutMs} ms.` };
      return { kind: 'error', message: 'Could not reach the AI provider.' };
    }
  }

  async function generate(req: StructuredRequest): Promise<ModelOutcome> {
    let sent = await send(req, true);
    // If a model rejects the reasoning parameters, retry once without them.
    if ('res' in sent && sent.res.status === 400 && /reasoning/i.test(providerMessage(sent.text))) sent = await send(req, false);
    if (!('res' in sent)) return sent;
    const { res, text } = sent;
    if (!res.ok) return httpFailure(res, text);

    let parsed: z.infer<typeof ChatCompletion>;
    try {
      parsed = ChatCompletion.parse(JSON.parse(text));
    } catch {
      return { kind: 'error', message: 'The AI provider sent an unexpected response.' };
    }
    const choice = parsed.choices[0]!;
    if (choice.finish_reason === 'length') return { kind: 'truncated', message: 'The AI response was cut off.' };
    const content = choice.message.content?.trim();
    if (!content) return { kind: 'error', message: 'The AI provider returned an empty response.' };

    let json: unknown;
    try {
      json = JSON.parse(content);
    } catch {
      return { kind: 'error', message: 'The AI response was not valid JSON.' };
    }
    const checked = req.schema.safeParse(json);
    if (!checked.success) return { kind: 'error', message: 'The AI response did not match the required format.' };
    return { kind: 'ok', output: checked.data, model: parsed.model };
  }

  return { provider: 'Groq', model, maxInputChars: MAX_INPUT_CHARS, generate };
}

function httpFailure(res: Response, body: string): ModelOutcome {
  const status = res.status;
  if (status === 401 || status === 403) return { kind: 'error', message: 'The AI provider rejected the server credentials.' };
  if (status === 429) {
    const wait = Number(res.headers.get('retry-after'));
    return { kind: 'rate_limited', message: `AI provider rate limit reached${Number.isFinite(wait) && wait > 0 ? `; try again in ${Math.ceil(wait)} s` : '; try again shortly'}.` };
  }
  if (status === 413) return { kind: 'error', message: 'The request was too large for the AI provider’s limits.' };
  if (status === 400 && /schema|json/i.test(providerMessage(body))) return { kind: 'error', message: 'The AI response did not match the required format.' };
  if (status === 498 || status >= 500) return { kind: 'error', message: `The AI provider is busy or unavailable (${status}). Try again shortly.` };
  return { kind: 'error', message: `AI provider error (${status}).` };
}

/** Groq errors look like {"error": {"message": "...", "type": "..."}}. Used only for classification, never shown or logged. */
function providerMessage(body: string): string {
  try {
    const m = (JSON.parse(body) as { error?: { message?: unknown } }).error?.message;
    return typeof m === 'string' ? m : '';
  } catch {
    return '';
  }
}
