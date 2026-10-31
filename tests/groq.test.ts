import { describe, expect, it } from 'vitest';
import { DEFAULT_GROQ_MODEL, GROQ_API_URL, createGroqClient, toResponseSchema } from '../src/server/ai/groq.js';
import { ModelAnalysisSchema } from '../src/server/ai/schema.js';
import { createAiService } from '../src/server/ai/service.js';
import type { StructuredRequest } from '../src/server/ai/types.js';
import { loadConfig } from '../src/server/config.js';

const KEY = 'gsk_test_key_not_real';
const source = 'Your SBI account will be blocked today. Share the OTP sent to your mobile to continue.';
const analysis = {
  concern: 'high',
  summary_en: 'The page threatens to block your account and asks for your OTP.',
  summary_hi: 'यह पेज खाता बंद करने की धमकी देकर OTP मांगता है।',
  impersonated_brand: 'State Bank of India',
  tactics: [{ tactic: 'otp_or_pin_request', evidence_quote: 'Share the OTP sent to your mobile', explanation: 'Banks never ask for OTPs.' }],
  advice: ['Never share an OTP.'],
  injection_attempt_detected: false,
};

interface Captured {
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

function fakeFetch(reply: () => Response | Promise<Response>) {
  const calls: Captured[] = [];
  const impl = async (url: string, init?: RequestInit) => {
    calls.push({ url, headers: init?.headers as Record<string, string>, body: JSON.parse(String(init?.body)) as Record<string, unknown> });
    return reply();
  };
  return { impl, calls };
}

const completion = (content: string | null, finish = 'stop', model = DEFAULT_GROQ_MODEL) =>
  new Response(JSON.stringify({ id: 'x', model, choices: [{ index: 0, finish_reason: finish, message: { role: 'assistant', content } }] }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });

const req: StructuredRequest = { task: 'analysis', system: 'SYS', user: 'USER', schema: ModelAnalysisSchema };

describe('Groq client', () => {
  it('is not created without an API key', () => {
    expect(createGroqClient({ timeoutMs: 1000 })).toBeNull();
  });

  it('sends a strict JSON-schema request with low reasoning effort for gpt-oss models', async () => {
    const f = fakeFetch(() => completion(JSON.stringify(analysis)));
    const client = createGroqClient({ apiKey: KEY, timeoutMs: 1000, fetchImpl: f.impl })!;
    expect(client.provider).toBe('Groq');
    expect(client.model).toBe('openai/gpt-oss-120b');

    const out = await client.generate(req);
    expect(out.kind).toBe('ok');
    const call = f.calls[0]!;
    expect(call.url).toBe(GROQ_API_URL);
    expect(call.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(call.body).toMatchObject({
      model: 'openai/gpt-oss-120b',
      max_completion_tokens: 2048,
      reasoning_effort: 'low',
      include_reasoning: false,
      response_format: { type: 'json_schema', json_schema: { name: 'phishshield_analysis', strict: true } },
    });
    expect(call.body.messages).toEqual([
      { role: 'system', content: 'SYS' },
      { role: 'user', content: 'USER' },
    ]);
  });

  it('produces schemas that satisfy strict mode (closed objects, every field required)', () => {
    for (const schema of [ModelAnalysisSchema]) {
      const js = toResponseSchema(schema);
      expect(js.$schema).toBeUndefined();
      const walk = (node: unknown): void => {
        if (!node || typeof node !== 'object') return;
        const n = node as Record<string, unknown>;
        if (n.type === 'object') {
          expect(n.additionalProperties).toBe(false);
          expect(new Set(n.required as string[])).toEqual(new Set(Object.keys(n.properties as object)));
        }
        Object.values(n).forEach(walk);
      };
      walk(js);
    }
  });

  it('falls back to JSON object mode with the schema in the prompt for other models', async () => {
    const f = fakeFetch(() => completion(JSON.stringify(analysis)));
    const client = createGroqClient({ apiKey: KEY, model: 'llama-3.3-70b-versatile', timeoutMs: 1000, fetchImpl: f.impl })!;
    const out = await client.generate(req);
    expect(out.kind).toBe('ok');
    const body = f.calls[0]!.body;
    expect(body.response_format).toEqual({ type: 'json_object' });
    expect(body.reasoning_effort).toBeUndefined();
    expect(body.max_completion_tokens).toBe(2048);
    expect((body.messages as Array<{ content: string }>)[0]!.content).toContain('"injection_attempt_detected"');
  });

  it('rejects output that is not JSON or does not match the schema', async () => {
    const notJson = createGroqClient({ apiKey: KEY, timeoutMs: 1000, fetchImpl: fakeFetch(() => completion('Sure! Here is the analysis…')).impl })!;
    expect(await notJson.generate(req)).toMatchObject({ kind: 'error' });
    const wrong = createGroqClient({ apiKey: KEY, timeoutMs: 1000, fetchImpl: fakeFetch(() => completion('{"concern":"catastrophic"}')).impl })!;
    expect(await wrong.generate(req)).toMatchObject({ kind: 'error', message: expect.stringMatching(/required format/) });
    const empty = createGroqClient({ apiKey: KEY, timeoutMs: 1000, fetchImpl: fakeFetch(() => completion(null)).impl })!;
    expect(await empty.generate(req)).toMatchObject({ kind: 'error' });
  });

  it('reports truncated output', async () => {
    const client = createGroqClient({ apiKey: KEY, timeoutMs: 1000, fetchImpl: fakeFetch(() => completion('{"conc', 'length')).impl })!;
    expect(await client.generate(req)).toMatchObject({ kind: 'truncated' });
  });

  it.each([
    [429, { 'retry-after': '7' }, 'rate_limited', /7 s/],
    [401, {}, 'error', /credentials/],
    [413, {}, 'error', /too large/],
    [503, {}, 'error', /busy or unavailable/],
    [498, {}, 'error', /busy or unavailable/],
  ] as const)('maps HTTP %i to %s', async (status, headers, kind, message) => {
    const reply = () => new Response(JSON.stringify({ error: { message: 'upstream detail', type: 'x' } }), { status, headers });
    const client = createGroqClient({ apiKey: KEY, timeoutMs: 1000, fetchImpl: fakeFetch(reply).impl })!;
    const out = await client.generate(req);
    expect(out).toMatchObject({ kind, message: expect.stringMatching(message) });
    expect(JSON.stringify(out)).not.toContain(KEY);
  });

  it('reports timeouts and network failures without throwing', async () => {
    const timeout = createGroqClient({
      apiKey: KEY,
      timeoutMs: 1000,
      fetchImpl: async () => {
        throw new DOMException('timed out', 'TimeoutError');
      },
    })!;
    expect(await timeout.generate(req)).toMatchObject({ kind: 'timeout' });
    const offline = createGroqClient({
      apiKey: KEY,
      timeoutMs: 1000,
      fetchImpl: async () => {
        throw new TypeError('fetch failed');
      },
    })!;
    expect(await offline.generate(req)).toMatchObject({ kind: 'error' });
  });

  it('works end to end through the AI service, including quote grounding', async () => {
    const client = createGroqClient({ apiKey: KEY, timeoutMs: 1000, fetchImpl: fakeFetch(() => completion(JSON.stringify(analysis))).impl });
    const r = await createAiService(client).analyze({ kind: 'page', text: source });
    expect(r).toMatchObject({ status: 'ok', provider: 'Groq', model: DEFAULT_GROQ_MODEL, concern: 'high' });
    expect(r.tactics?.[0]?.grounded).toBe(true);
  });
});

describe('AI provider selection', () => {
  it('prefers Groq when its key is set, and honours AI_PROVIDER', () => {
    expect(loadConfig({}).aiProvider).toBeNull();
    expect(loadConfig({ GROQ_API_KEY: 'g' }).aiProvider).toBe('groq');
    expect(loadConfig({ ANTHROPIC_API_KEY: 'a' }).aiProvider).toBe('anthropic');
    expect(loadConfig({ GROQ_API_KEY: 'g', ANTHROPIC_API_KEY: 'a' }).aiProvider).toBe('groq');
    expect(loadConfig({ GROQ_API_KEY: 'g', ANTHROPIC_API_KEY: 'a', AI_PROVIDER: 'anthropic' }).aiProvider).toBe('anthropic');
    expect(loadConfig({ GROQ_API_KEY: 'g', AI_PROVIDER: 'none' }).aiProvider).toBeNull();
  });
});

describe('Groq reasoning parameters', () => {
  it('retries once without reasoning parameters if the model rejects them', async () => {
    let n = 0;
    const f = fakeFetch(() =>
      n++ === 0
        ? new Response(JSON.stringify({ error: { message: '`include_reasoning` is not supported with this model', type: 'invalid_request_error' } }), { status: 400 })
        : completion(JSON.stringify(analysis)),
    );
    const client = createGroqClient({ apiKey: KEY, timeoutMs: 1000, fetchImpl: f.impl })!;
    expect(await client.generate(req)).toMatchObject({ kind: 'ok' });
    expect(f.calls).toHaveLength(2);
    expect(f.calls[0]!.body.include_reasoning).toBe(false);
    expect(f.calls[1]!.body.include_reasoning).toBeUndefined();
    expect(f.calls[1]!.body.reasoning_effort).toBeUndefined();
  });
});
