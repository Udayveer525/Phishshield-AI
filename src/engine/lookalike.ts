/**
 * Lookalike / homoglyph helpers. Deliberately small and deterministic: a curated subset of
 * Unicode confusables (Cyrillic, Greek, fullwidth, common Latin variants) and ASCII
 * substitutions used in typosquats.
 */

const UNICODE_CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a', в: 'b', е: 'e', ё: 'e', к: 'k', м: 'm', н: 'h', о: 'o', р: 'p', с: 'c', т: 't', у: 'y', х: 'x',
  ѕ: 's', і: 'i', ї: 'i', ј: 'j', ԁ: 'd', ɡ: 'g', һ: 'h', ӏ: 'l', ԛ: 'q', ԝ: 'w', ү: 'y', ҽ: 'e', ո: 'n',
  // Greek
  α: 'a', β: 'b', ε: 'e', η: 'n', ι: 'i', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't', υ: 'u', χ: 'x', ϲ: 'c',
  // Latin variants / IPA
  ı: 'i', ł: 'l', ɩ: 'i', ɑ: 'a', ɵ: 'o', ƅ: 'b', ɢ: 'g', ʜ: 'h', ʟ: 'l', ɴ: 'n', ʀ: 'r', ꜱ: 's', ᴠ: 'v', ᴡ: 'w',
  à: 'a', á: 'a', â: 'a', ã: 'a', ä: 'a', å: 'a', ā: 'a', ç: 'c', è: 'e', é: 'e', ê: 'e', ë: 'e', ē: 'e',
  ì: 'i', í: 'i', î: 'i', ï: 'i', ñ: 'n', ò: 'o', ó: 'o', ô: 'o', õ: 'o', ö: 'o', ø: 'o', ō: 'o',
  ù: 'u', ú: 'u', û: 'u', ü: 'u', ý: 'y', ÿ: 'y', ś: 's', š: 's', ž: 'z', ż: 'z', ğ: 'g', ș: 's', ț: 't',
};

const ASCII_SUBSTITUTIONS: Array<[RegExp, string]> = [
  [/0/g, 'o'],
  [/1/g, 'l'],
  [/3/g, 'e'],
  [/4/g, 'a'],
  [/5/g, 's'],
  [/7/g, 't'],
  [/8/g, 'b'],
  [/9/g, 'g'],
  [/rn/g, 'm'],
  [/vv/g, 'w'],
];

/** Map a label to a "skeleton" so visually similar strings compare equal. */
export function skeleton(label: string): string {
  let out = '';
  for (const ch of label.normalize('NFKC').toLowerCase()) {
    out += UNICODE_CONFUSABLES[ch] ?? ch;
  }
  for (const [re, rep] of ASCII_SUBSTITUTIONS) out = out.replace(re, rep);
  // Treat l/i/1 as interchangeable (they collapse to the same glyph in many fonts).
  return out.replace(/[il|]/g, 'l');
}

export type Script = 'latin' | 'cyrillic' | 'greek' | 'devanagari' | 'other' | 'common';

export function scriptOf(ch: string): Script {
  const cp = ch.codePointAt(0) ?? 0;
  if ((cp >= 0x30 && cp <= 0x39) || ch === '-' || ch === '.') return 'common';
  if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a) || (cp >= 0xc0 && cp <= 0x24f) || (cp >= 0x1e00 && cp <= 0x1eff)) return 'latin';
  if (cp >= 0x250 && cp <= 0x2af) return 'latin'; // IPA extensions
  if (cp >= 0x1d00 && cp <= 0x1d7f) return 'latin'; // phonetic extensions (small caps)
  if (cp >= 0xa720 && cp <= 0xa7ff) return 'latin';
  if (cp >= 0x400 && cp <= 0x52f) return 'cyrillic';
  if (cp >= 0x370 && cp <= 0x3ff) return 'greek';
  if (cp >= 0x900 && cp <= 0x97f) return 'devanagari';
  return 'other';
}

/** Distinct non-common scripts used in a label. */
export function scriptsIn(label: string): Set<Script> {
  const s = new Set<Script>();
  for (const ch of label) {
    const sc = scriptOf(ch);
    if (sc !== 'common') s.add(sc);
  }
  return s;
}

/** Optimal string alignment (restricted Damerau-Levenshtein) distance with early exit. */
export function editDistance(a: string, b: string, max = 3): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const n = a.length;
  const m = b.length;
  let prev2: number[] = [];
  let prev: number[] = Array.from({ length: m + 1 }, (_, j) => j);
  for (let i = 1; i <= n; i++) {
    const cur: number[] = [i];
    let rowMin = i;
    for (let j = 1; j <= m; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, prev2[j - 2]! + 1);
      }
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    prev2 = prev;
    prev = cur;
  }
  return prev[m]!;
}
