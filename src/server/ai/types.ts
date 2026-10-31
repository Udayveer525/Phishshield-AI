import type { z } from 'zod';

/** What the service asks a model provider for. Each provider maps `task` onto its own token/temperature settings. */
export interface StructuredRequest {
  task: 'analysis';
  system: string;
  user: string;
  /** The JSON shape the model must return. Output is re-validated against it by the provider and the service. */
  schema: z.ZodType;
}

export type ModelOutcome =
  | { kind: 'ok'; output: unknown; model: string }
  | { kind: 'refused' | 'truncated' | 'timeout' | 'rate_limited' | 'error'; message: string };

/** A configured AI provider. Implementations never throw: every failure becomes a `ModelOutcome`. */
export interface ModelClient {
  /** Human-readable provider name shown in the UI, e.g. "Groq". */
  readonly provider: string;
  readonly model: string;
  /** Upper bound on untrusted text sent per request, sized to the provider's token limits. */
  readonly maxInputChars: number;
  generate(req: StructuredRequest): Promise<ModelOutcome>;
}
