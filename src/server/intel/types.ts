import type { ReputationFinding } from '../../shared/types.js';

export interface ProviderResult extends ReputationFinding {
  /** How long this result may be cached, in seconds. */
  cacheTtlSec?: number;
}

/**
 * A URL reputation provider. Implementations must:
 *  - never fabricate results: on any failure return status `error` / `timeout`;
 *  - only contact their fixed, documented endpoint (no user-controlled destinations);
 *  - enforce their own timeout.
 */
export interface IntelProvider {
  readonly id: string;
  readonly name: string;
  isConfigured(): boolean;
  /** `url` is already normalised (no fragment) and validated as public http(s). */
  check(url: string): Promise<ProviderResult>;
  /** Extra status for the health endpoint. */
  describe(): Record<string, unknown>;
}
