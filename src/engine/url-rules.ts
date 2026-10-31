import punycode from 'punycode/punycode.js';
import type { Signal } from '../shared/types.js';
import { BRANDS, type Brand, isOfficialFor, isRestrictedRegistryFor, officialBrandFor } from './brands.js';
import {
  ABUSED_TLDS,
  BRAND_SHORTENERS,
  DYNAMIC_DNS_SUFFIXES,
  FREE_HOSTING_SUFFIXES,
  REDIRECT_PARAMS,
  SENSITIVE_URL_WORDS,
  TUNNEL_SUFFIXES,
  URL_SHORTENERS,
  hostMatchesSuffix,
} from './lists.js';
import { editDistance, scriptsIn, skeleton } from './lookalike.js';
import type { ParsedUrl } from './url.js';

export interface BrandMatch {
  brand: Brand;
  how: 'embedded_official_domain' | 'homoglyph' | 'substitution' | 'lookalike' | 'brand_in_subdomain' | 'brand_in_domain' | 'brand_in_path';
}

export interface UrlRuleResult {
  signals: Signal[];
  brandMatch?: BrandMatch;
  officialBrand?: Brand;
  isShortener: boolean;
  limitations: string[];
}

const SENSITIVE = new Set(SENSITIVE_URL_WORDS);

function sig(s: Omit<Signal, 'source'>): Signal {
  return { source: 'local_url', ...s };
}

function tokensOf(s: string): string[] {
  return s.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
}

function sensitiveWordsIn(tokens: string[]): string[] {
  const found = new Set<string>();
  for (const t of tokens) {
    if (SENSITIVE.has(t)) found.add(t);
    else {
      // Compound labels such as "kycupdate" or "securelogin".
      for (const w of ['login', 'signin', 'verify', 'kyc', 'update', 'secure', 'account', 'banking', 'refund', 'reward', 'unlock', 'suspend', 'otp', 'wallet', 'password', 'support', 'helpdesk']) {
        if (t.length > w.length && t.includes(w)) found.add(w);
      }
    }
  }
  return [...found];
}

export function analyzeUrl(p: ParsedUrl): UrlRuleResult {
  const signals: Signal[] = [];
  const limitations: string[] = [];
  const host = p.host;
  const officialBrand = p.isIp ? undefined : officialBrandFor(p.registrableDomain, p.publicSuffix);

  if (p.isPrivateOrLocal) {
    limitations.push('This is a local or private-network address. Remote reputation checks are not performed for it.');
  }

  let userInfoBrand: BrandMatch | undefined;
  // ---- '@' userinfo trick -------------------------------------------------
  if (p.hasUserInfo) {
    const looksLikeHost = /[a-z0-9-]+\.[a-z]{2,}/i.test(p.userInfo) || BRANDS.some((b) => tokensOf(p.userInfo).some((t) => b.tokens.includes(t)));
    const imitated = BRANDS.find((b) => b.domains.some((d) => p.userInfo.toLowerCase().includes(d)) || tokensOf(p.userInfo).some((t) => b.tokens.includes(t)));
    if (imitated && !isOfficialFor(imitated, p.registrableDomain, p.publicSuffix)) userInfoBrand = { brand: imitated, how: 'embedded_official_domain' };
    signals.push(
      sig({
        id: 'url.userinfo_trick',
        category: 'obfuscation',
        strength: looksLikeHost ? 'strong' : 'moderate',
        weight: looksLikeHost ? (userInfoBrand ? 0.65 : 0.55) : 0.25,
        title: looksLikeHost ? "Deceptive '@' in the address" : 'Credentials embedded in the address',
        detail: looksLikeHost
          ? `Browsers ignore everything before '@'. This link appears to point to "${p.userInfo}" but actually opens ${host}.`
          : 'The address contains a username/password section, which is rarely used by legitimate websites.',
        evidence: [`userinfo: ${p.userInfo}`, `actual host: ${host}`],
      }),
    );
  }

  // ---- IP address hosts ---------------------------------------------------
  if (p.isIp && !p.isPrivateOrLocal) {
    signals.push(
      sig({
        id: 'url.ip_host',
        category: 'infrastructure',
        strength: 'moderate',
        weight: 0.3,
        title: 'Website uses a raw IP address',
        detail: 'Legitimate banks, shops and services use domain names. Raw IP addresses are common in short-lived phishing setups.',
        evidence: [`host: ${host}`],
      }),
    );
    if (p.ipObfuscated) {
      signals.push(
        sig({
          id: 'url.ip_obfuscated',
          category: 'obfuscation',
          strength: 'strong',
          weight: 0.45,
          title: 'IP address written in a disguised form',
          detail: 'The address uses an integer, hex or octal IP notation that browsers silently convert. This is a known evasion trick.',
          evidence: [`input: ${p.input.slice(0, 200)}`, `resolves to: ${host}`],
        }),
      );
    }
  }

  // ---- Encoded hostname ---------------------------------------------------
  const rawAuthority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(p.input.trim())?.[1] ?? '';
  if (/%[0-9a-f]{2}/i.test(rawAuthority)) {
    signals.push(
      sig({
        id: 'url.encoded_host',
        category: 'obfuscation',
        strength: 'moderate',
        weight: 0.35,
        title: 'Hostname is percent-encoded',
        detail: 'Encoding the website name hides where the link really goes. Legitimate links do not need this.',
        evidence: [`raw authority: ${rawAuthority.slice(0, 200)}`, `decoded host: ${host}`],
      }),
    );
  }

  // ---- IDN / punycode -----------------------------------------------------
  let idnBrand: BrandMatch | undefined;
  if (p.usesPunycode) {
    const unicodeLabels = p.unicodeHost.split('.');
    const mixed = unicodeLabels.filter((l) => scriptsIn(l).size > 1);
    const regLabel = p.domainLabel ? (p.unicodeHost.split('.').at(-(p.registrableDomain?.split('.').length ?? 2)) ?? '') : '';
    for (const brand of BRANDS) {
      if (isOfficialFor(brand, p.registrableDomain, p.publicSuffix)) continue;
      const sk = skeleton(regLabel);
      const hit = [...brand.tokens, ...brand.fuzzyTokens, ...brand.domains.map((d) => d.split('.')[0]!)].some(
        (t) => t.length >= 3 && sk === skeleton(t),
      );
      if (hit) {
        idnBrand = { brand, how: 'homoglyph' };
        break;
      }
    }
    if (idnBrand) {
      signals.push(
        sig({
          id: 'url.idn_homoglyph',
          category: 'impersonation',
          strength: 'strong',
          weight: 0.65,
          title: `Lookalike characters imitate ${idnBrand.brand.name}`,
          detail: `"${p.unicodeHost}" uses non-Latin characters that look like "${idnBrand.brand.domains[0]}". It is a different website.`,
          evidence: [`punycode: ${host}`, `displayed as: ${p.unicodeHost}`],
        }),
      );
    } else if (mixed.length) {
      signals.push(
        sig({
          id: 'url.idn_mixed_script',
          category: 'obfuscation',
          strength: 'strong',
          weight: 0.5,
          title: 'Domain mixes alphabets',
          detail: 'Part of the domain mixes characters from different alphabets (e.g. Latin and Cyrillic), a common way to imitate familiar names.',
          evidence: [`punycode: ${host}`, `displayed as: ${p.unicodeHost}`, ...mixed.map((l) => `mixed label: ${l}`)],
        }),
      );
    } else {
      signals.push(
        sig({
          id: 'url.idn',
          category: 'informational',
          strength: 'contextual',
          weight: 0.05,
          title: 'Internationalised domain name',
          detail: `This domain uses non-ASCII characters and is shown as "${p.unicodeHost}". That is normal for many languages; check that it is the site you expect.`,
          evidence: [`punycode: ${host}`],
        }),
      );
    }
  }

  // ---- Brand impersonation ------------------------------------------------
  let brandMatch: BrandMatch | undefined = idnBrand ?? userInfoBrand;
  const subTokens = tokensOf(p.subdomain);
  const domTokens = p.domainLabel ? tokensOf(p.domainLabel) : [];
  const pathTokens = tokensOf(decodeLoose(p.path));
  const hostSensitive = sensitiveWordsIn([...subTokens, ...domTokens]);
  const pathSensitive = sensitiveWordsIn(pathTokens);

  if (!brandMatch && !p.isIp) {
    for (const brand of BRANDS) {
      if (isOfficialFor(brand, p.registrableDomain, p.publicSuffix)) continue;
      if (isRestrictedRegistryFor(brand.category, p.registrableDomain)) continue;

      // a) official domain embedded in a longer hostname: sbi.co.in.kyc-verify.xyz / paypal.com-login.net
      // The imitation must start before the real registrable domain (so paypal.com.au is not flagged).
      const prefixEnd = host.length - (p.registrableDomain?.length ?? 0);
      const embedded = brand.domains.find((d) => {
        const forms = [`${d}.`, `${d}-`, `${d.replace(/\./g, '-')}-`, `${d.replace(/\./g, '-')}.`];
        return forms.some((f) => {
          const i = host.indexOf(f);
          return i >= 0 && i < prefixEnd && (i === 0 || host[i - 1] === '.' || host[i - 1] === '-');
        });
      });
      if (embedded) {
        brandMatch = { brand, how: 'embedded_official_domain' };
        signals.push(
          sig({
            id: 'url.embedded_official_domain',
            category: 'impersonation',
            strength: 'strong',
            weight: 0.6,
            title: `Fake ${brand.name} address`,
            detail: `The address starts with "${embedded}" to look official, but the website actually belongs to ${p.registrableDomain ?? host}.`,
            evidence: [`host: ${host}`, `real registrable domain: ${p.registrableDomain}`, `imitated: ${embedded}`],
          }),
        );
        break;
      }

      // b) lookalike / character substitution in the registrable label
      if (p.domainLabel) {
        const parts = [p.domainLabel, ...domTokens];
        const targets = new Set([...brand.fuzzyTokens, ...brand.domains.map((d) => d.split('.')[0]!)].filter((t) => t.length >= 4));
        let found: { part: string; target: string; dist: number } | undefined;
        for (const part of parts) {
          if (part.length < 4) continue;
          for (const target of targets) {
            if (part === target) continue;
            const skPart = skeleton(part);
            const skTarget = skeleton(target);
            // Character substitution (0→o, 1→l, Cyrillic…) for any target; edit distance only for
            // longer names, where a 1-2 letter difference is unlikely to be a different real word.
            const dist = skPart === skTarget ? 0 : editDistance(part, target, 2);
            const limit = target.length >= 9 ? 2 : target.length >= 6 ? 1 : 0;
            if (dist <= limit && !(dist > 0 && part.includes(target))) {
              found = { part, target, dist };
              break;
            }
          }
          if (found) break;
        }
        if (found) {
          const substitution = found.dist === 0;
          brandMatch = { brand, how: substitution ? 'substitution' : 'lookalike' };
          signals.push(
            sig({
              id: substitution ? 'url.char_substitution' : 'url.lookalike_domain',
              category: 'impersonation',
              strength: 'strong',
              weight: substitution ? 0.6 : 0.5,
              title: substitution ? `Look-alike spelling of ${brand.name}` : `Domain resembles ${brand.name}`,
              detail: substitution
                ? `"${found.part}" swaps characters (like 0 for o or 1 for l) to imitate "${found.target}".`
                : `"${found.part}" is one or two letters away from "${found.target}", a common typosquatting technique.`,
              evidence: [`domain: ${p.registrableDomain}`, `imitates: ${found.target}`, `official: ${brand.domains.slice(0, 3).join(', ')}`],
            }),
          );
          break;
        }
      }

      // c) brand name inside the unofficial registrable domain
      const inDomain = domTokens.some((t) => brand.tokens.includes(t)) || brand.fuzzyTokens.some((t) => (p.domainLabel ?? '').includes(t));
      if (inDomain) {
        brandMatch = { brand, how: 'brand_in_domain' };
        const officialLabels = brand.domains.map((d) => d.split('.')[0]);
        const regional = !!p.domainLabel && officialLabels.includes(p.domainLabel) && isCountryVariant(p.publicSuffix);
        if (regional) {
          signals.push(
            sig({
              id: 'url.brand_regional_variant',
              category: 'impersonation',
              strength: 'weak',
              weight: 0.12,
              title: `${brand.name} name with a different country ending`,
              detail: `${p.registrableDomain} is not on PhishShield's list of ${brand.name} domains. It may be a regional site; check the address carefully.`,
              evidence: [`domain: ${p.registrableDomain}`, `known official: ${brand.domains.slice(0, 3).join(', ')}`],
            }),
          );
          break;
        }
        const combo = sensitiveWordsIn(domTokens.length > 1 ? domTokens : [p.domainLabel ?? '']).filter((w) => !brand.tokens.includes(w));
        signals.push(
          sig({
            id: combo.length ? 'url.brand_keyword_domain' : 'url.brand_in_domain',
            category: 'impersonation',
            strength: combo.length ? 'strong' : 'moderate',
            weight: combo.length ? 0.55 : 0.25,
            title: combo.length ? `Unofficial "${brand.name}" domain with action words` : `Uses the name ${brand.name} in an unofficial domain`,
            detail: combo.length
              ? `${p.registrableDomain} combines "${brand.name}" with "${combo.join('", "')}". ${brand.name}'s official sites are ${brand.domains.slice(0, 2).join(' and ')}.`
              : `${p.registrableDomain} is not one of ${brand.name}'s known official domains (${brand.domains.slice(0, 2).join(', ')}). It could be a fan site, reseller or impostor.`,
            evidence: [`domain: ${p.registrableDomain}`, ...(combo.length ? [`keywords: ${combo.join(', ')}`] : [])],
          }),
        );
        break;
      }

      // d) brand name in subdomain of an unrelated domain
      if (subTokens.some((t) => brand.tokens.includes(t)) || brand.fuzzyTokens.some((t) => p.subdomain.includes(t))) {
        brandMatch = { brand, how: 'brand_in_subdomain' };
        const combo = hostSensitive.filter((w) => !brand.tokens.includes(w));
        signals.push(
          sig({
            id: 'url.brand_in_subdomain',
            category: 'impersonation',
            strength: combo.length ? 'strong' : 'moderate',
            weight: combo.length ? 0.5 : 0.35,
            title: `"${brand.name}" used as a subdomain`,
            detail: `The address begins with a ${brand.name}-like name, but the actual website is ${p.registrableDomain ?? host}.`,
            evidence: [`subdomain: ${p.subdomain}`, `registrable domain: ${p.registrableDomain}`],
          }),
        );
        break;
      }
    }
  }

  // e) brand in path on an unrelated domain, combined with sensitive words
  if (!brandMatch && !officialBrand && pathSensitive.length) {
    const brand = BRANDS.find((b) => pathTokens.some((t) => b.tokens.includes(t) || b.fuzzyTokens.includes(t)));
    if (brand) {
      brandMatch = { brand, how: 'brand_in_path' };
      const throwawayHost = p.isIp || !!hostMatchesSuffix(host, [...FREE_HOSTING_SUFFIXES, ...TUNNEL_SUFFIXES, ...DYNAMIC_DNS_SUFFIXES]);
      signals.push(
        sig({
          id: 'url.brand_in_path',
          category: 'impersonation',
          strength: throwawayHost ? 'strong' : 'weak',
          weight: throwawayHost ? 0.4 : 0.15,
          title: `Mentions ${brand.name} in the page path`,
          detail: `The link path references ${brand.name} with words like "${pathSensitive.slice(0, 3).join('", "')}" on a website that is not ${brand.name}'s.`,
          evidence: [`path: ${p.path.slice(0, 200)}`],
        }),
      );
    }
  }

  if (officialBrand) {
    signals.push(
      sig({
        id: 'url.official_domain',
        category: 'informational',
        strength: 'contextual',
        weight: 0,
        title: `Known official domain of ${officialBrand.name}`,
        detail: `${p.registrableDomain ?? p.publicSuffix} is on PhishShield's built-in list of ${officialBrand.name} domains. This lowers impersonation risk but does not prove the page is safe.`,
      }),
    );
  }

  // ---- Hosting infrastructure ----------------------------------------------
  const tunnel = hostMatchesSuffix(host, TUNNEL_SUFFIXES);
  const dyn = hostMatchesSuffix(host, DYNAMIC_DNS_SUFFIXES);
  const freeHost = hostMatchesSuffix(host, FREE_HOSTING_SUFFIXES);
  if (tunnel) {
    signals.push(
      sig({
        id: 'url.tunnel_host',
        category: 'infrastructure',
        strength: 'moderate',
        weight: 0.25,
        title: 'Temporary tunnel address',
        detail: `${tunnel} exposes someone's own computer to the internet. Real banks and stores never use these.`,
        evidence: [`host: ${host}`],
      }),
    );
  } else if (dyn) {
    signals.push(
      sig({
        id: 'url.dynamic_dns',
        category: 'infrastructure',
        strength: 'weak',
        weight: 0.18,
        title: 'Free dynamic-DNS address',
        detail: `${dyn} provides free changing addresses. It has legitimate uses but is also popular with attackers.`,
        evidence: [`host: ${host}`],
      }),
    );
  } else if (freeHost && !officialBrand) {
    signals.push(
      sig({
        id: 'url.free_hosting',
        category: 'infrastructure',
        strength: brandMatch ? 'strong' : 'contextual',
        weight: brandMatch ? 0.4 : 0.08,
        title: 'Hosted on a free website builder',
        detail: `Anyone can publish a site on ${freeHost}${brandMatch ? `, so a ${brandMatch.brand.name}-branded page here is unlikely to be official` : ''}.`,
        evidence: [`host: ${host}`],
      }),
    );
  }

  // ---- Shorteners -----------------------------------------------------------
  const isShortener = !!p.registrableDomain && (URL_SHORTENERS.has(host) || URL_SHORTENERS.has(p.registrableDomain));
  if (isShortener) {
    const firstParty = BRAND_SHORTENERS.has(host) || BRAND_SHORTENERS.has(p.registrableDomain ?? '');
    signals.push(
      sig({
        id: 'url.shortener',
        category: 'obfuscation',
        strength: 'contextual',
        weight: firstParty ? 0 : 0.1,
        title: 'Shortened link hides its destination',
        detail: firstParty
          ? `${host} is a brand-owned short-link service. The final destination is checked after the redirect.`
          : `${host} is a link shortener. PhishShield checks the final page after the redirect; a manual scan cannot see the destination.`,
        evidence: [`shortener: ${host}`],
      }),
    );
    limitations.push('Shortened link: the destination is unknown until the browser follows the redirect.');
  }

  // ---- Structure ----------------------------------------------------------
  const tld = p.publicSuffix?.split('.').at(-1);
  if (tld && ABUSED_TLDS.has(tld) && !officialBrand) {
    signals.push(
      sig({
        id: 'url.abused_tld',
        category: 'infrastructure',
        strength: 'weak',
        weight: 0.12,
        title: `".${tld}" domain ending`,
        detail: `Cheap ".${tld}" domains are frequently used in scams. Many legitimate sites use it too, so this only matters with other warning signs.`,
        evidence: [`public suffix: ${p.publicSuffix}`],
      }),
    );
  }

  const subLabels = p.subdomain ? p.subdomain.split('.') : [];
  const tldLike = subLabels.filter((l, i) => ['com', 'net', 'org', 'gov', 'co'].includes(l) || (l === 'www' && i > 0));
  if (tldLike.length && !brandMatch) {
    signals.push(
      sig({
        id: 'url.tld_in_subdomain',
        category: 'obfuscation',
        strength: 'moderate',
        weight: 0.3,
        title: 'Address imitates a different domain',
        detail: `The address contains "${tldLike.join('", "')}" in the middle, making it look like another website. The real site is ${p.registrableDomain}.`,
        evidence: [`subdomain: ${p.subdomain}`],
      }),
    );
  }
  if (subLabels.length >= 4) {
    signals.push(
      sig({
        id: 'url.deep_subdomains',
        category: 'obfuscation',
        strength: 'weak',
        weight: 0.12,
        title: 'Unusually many subdomains',
        detail: 'Long chains of subdomains push the real domain out of view, especially on mobile screens.',
        evidence: [`${subLabels.length} subdomain levels: ${p.subdomain.slice(0, 120)}`],
      }),
    );
  }
  // Count hyphens in the readable label: punycode ("xn--…") adds its own.
  let readableLabel = p.domainLabel;
  try {
    if (readableLabel?.startsWith('xn--')) readableLabel = punycode.toUnicode(readableLabel);
  } catch {
    /* keep the ASCII form */
  }
  if (readableLabel && (readableLabel.match(/-/g)?.length ?? 0) >= 3 && !officialBrand) {
    signals.push(
      sig({
        id: 'url.many_hyphens',
        category: 'obfuscation',
        strength: 'weak',
        weight: 0.1,
        title: 'Many hyphens in the domain',
        detail: 'Domains strung together from several words with hyphens are common in throwaway scam sites.',
        evidence: [`domain: ${p.registrableDomain}`],
      }),
    );
  }
  if (p.domainLabel && !p.domainLabel.startsWith('xn--') && looksRandom(p.domainLabel) && !officialBrand) {
    signals.push(
      sig({
        id: 'url.random_label',
        category: 'infrastructure',
        strength: 'weak',
        weight: 0.1,
        title: 'Random-looking domain name',
        detail: 'The domain looks machine-generated, which is typical of disposable infrastructure.',
        evidence: [`domain label: ${p.domainLabel}`],
      }),
    );
  }

  // ---- Encodings in path / query ---------------------------------------------
  const pathAndQuery = p.path + p.query;
  if (/%25[0-9a-f]{2}/i.test(pathAndQuery)) {
    signals.push(
      sig({
        id: 'url.double_encoding',
        category: 'obfuscation',
        strength: 'moderate',
        weight: 0.2,
        title: 'Double-encoded characters',
        detail: 'Parts of the link are encoded twice, a technique used to slip past security filters.',
        evidence: [pathAndQuery.match(/%25[0-9a-f]{2}/gi)!.slice(0, 5).join(' ')],
      }),
    );
  }
  const encodedCount = pathAndQuery.match(/%[0-9a-f]{2}/gi)?.length ?? 0;
  if (encodedCount >= 12 && encodedCount * 3 > pathAndQuery.length * 0.3) {
    signals.push(
      sig({
        id: 'url.heavy_encoding',
        category: 'obfuscation',
        strength: 'weak',
        weight: 0.12,
        title: 'Heavily encoded link',
        detail: 'Much of the link is percent-encoded, which can hide its real content.',
        evidence: [`${encodedCount} encoded sequences`],
      }),
    );
  }
  if (/%(2f|5c|40)/i.test(p.path) || p.input.includes('\\')) {
    signals.push(
      sig({
        id: 'url.encoded_separators',
        category: 'obfuscation',
        strength: 'weak',
        weight: 0.1,
        title: 'Encoded slashes or "@" in the path',
        detail: 'Encoded path separators are sometimes used to confuse link previews and filters.',
        evidence: [p.path.slice(0, 160)],
      }),
    );
  }
  const embeddedRedirect = findEmbeddedUrl(p.query);
  if (embeddedRedirect) {
    signals.push(
      sig({
        id: 'url.embedded_redirect',
        category: 'obfuscation',
        strength: 'weak',
        weight: 0.1,
        title: 'Link carries another web address',
        detail: `A "${embeddedRedirect.param}" parameter points to ${embeddedRedirect.host}. Open redirects can bounce you from a trusted site to a malicious one.`,
        evidence: [`${embeddedRedirect.param}=${embeddedRedirect.value.slice(0, 160)}`],
      }),
    );
  }

  // ---- Contextual-only indicators ---------------------------------------------
  const sensitive = [...new Set([...hostSensitive, ...pathSensitive])];
  if (sensitive.length && !officialBrand) {
    signals.push(
      sig({
        id: 'url.sensitive_words',
        category: 'credential_harvest',
        strength: 'contextual',
        weight: 0.15,
        title: 'Login / account words in the link',
        detail: `The link contains "${sensitive.slice(0, 4).join('", "')}". Harmless on its own, but common in phishing links.`,
        evidence: [`matched: ${sensitive.join(', ')}`],
      }),
    );
  }
  if (p.scheme === 'http' && !p.isPrivateOrLocal) {
    signals.push(
      sig({
        id: 'url.no_https',
        category: 'infrastructure',
        strength: 'contextual',
        weight: sensitive.length || brandMatch ? 0.12 : 0.04,
        title: 'Connection is not encrypted (HTTP)',
        detail: 'Information sent to this page can be read in transit. Many harmless sites still use HTTP, so this only matters together with other signs.',
      }),
    );
  }
  if (p.port && !['80', '443', '8080', '8443'].includes(p.port) && !p.isPrivateOrLocal) {
    signals.push(
      sig({
        id: 'url.unusual_port',
        category: 'infrastructure',
        strength: 'weak',
        weight: 0.1,
        title: `Unusual port :${p.port}`,
        detail: 'Public websites almost always use standard ports.',
      }),
    );
  }
  if (p.href.length > 200) {
    signals.push(
      sig({
        id: 'url.long',
        category: 'informational',
        strength: 'contextual',
        weight: 0.03,
        title: 'Very long link',
        detail: 'Long links are normal for many sites; they only matter combined with other warning signs.',
        evidence: [`${p.href.length} characters`],
      }),
    );
  }

  return { signals, brandMatch, officialBrand, isShortener, limitations };
}

function decodeLoose(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function findEmbeddedUrl(query: string): { param: string; value: string; host: string } | undefined {
  if (!query) return undefined;
  const params = new URLSearchParams(query);
  for (const [k, v] of params) {
    if (!REDIRECT_PARAMS.includes(k.toLowerCase())) continue;
    const m = /^(?:https?:)?\/\/([^/?#:]+)/i.exec(v.trim());
    if (m) return { param: k, value: v, host: m[1]!.toLowerCase() };
  }
  return undefined;
}

const GENERIC_SLD = new Set(['com', 'co', 'net', 'org', 'gov', 'edu', 'ac']);
function isCountryVariant(suffix: string | null): boolean {
  if (!suffix) return false;
  const parts = suffix.split('.');
  if (parts.length === 1) return parts[0]!.length === 2;
  return parts.length === 2 && GENERIC_SLD.has(parts[0]!) && parts[1]!.length === 2;
}

export function looksRandom(label: string): boolean {
  const l = label.toLowerCase().replace(/-/g, '');
  if (l.length < 10) return false;
  const digits = (l.match(/\d/g) ?? []).length;
  if (digits / l.length > 0.3 && /[a-z]/.test(l)) return true;
  if (/[bcdfghjklmnpqrstvwxz]{6,}/.test(l)) return true;
  const vowels = (l.match(/[aeiou]/g) ?? []).length;
  return l.length >= 14 && vowels / l.length < 0.15;
}
