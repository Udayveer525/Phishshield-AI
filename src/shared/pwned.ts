/**
 * Pwned Passwords k-anonymity check (https://haveibeenpwned.com/API/v3#PwnedPasswords).
 *
 * 1. SHA-1 the password locally.
 * 2. Send only the first 5 hex characters to api.pwnedpasswords.com/range/{prefix}.
 * 3. The service returns every suffix that shares that prefix (~800-1,000 lines with padding);
 *    the match happens here. Neither HIBP nor PhishShield ever sees the password or its full hash.
 *
 * "Add-Padding: true" makes every response a similar size so the prefix can't be guessed from the
 * response length; padded rows have a count of 0 and are ignored.
 */
export const PWNED_RANGE_URL = 'https://api.pwnedpasswords.com/range/';

export async function sha1Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/** Parse "SUFFIX:COUNT" lines and return the count for `suffix` (0 when absent or padding). */
export function countForSuffix(body: string, suffix: string): number {
  const want = suffix.toUpperCase();
  for (const line of body.split(/\r?\n/)) {
    const [s, c] = line.trim().split(':');
    if (s?.toUpperCase() === want) {
      const n = Number(c);
      return Number.isFinite(n) && n > 0 ? n : 0;
    }
  }
  return 0;
}

export type PwnedResult = { ok: true; count: number; prefix: string } | { ok: false; message: string };

export async function checkPwnedPassword(password: string, fetchImpl: typeof fetch = fetch): Promise<PwnedResult> {
  if (!password) return { ok: false, message: 'Enter a password to check.' };
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const get = (padding: boolean) =>
    fetchImpl(`${PWNED_RANGE_URL}${prefix}`, {
      headers: padding ? { 'Add-Padding': 'true' } : {},
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: AbortSignal.timeout(8000),
    });
  let res: Response;
  try {
    res = await get(true);
  } catch {
    // If the padding header is blocked (CORS preflight), fall back to the plain request.
    try {
      res = await get(false);
    } catch {
      return { ok: false, message: 'Could not reach Have I Been Pwned. Check your connection.' };
    }
  }
  if (!res.ok) return { ok: false, message: `Have I Been Pwned answered HTTP ${res.status}.` };
  const body = await res.text();
  return { ok: true, count: countForSuffix(body, suffix), prefix };
}
