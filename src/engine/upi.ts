import type { Severity, Signal, SignalCategory, SignalStrength, Verdict } from '../shared/types.js';
import { computeScore, decideVerdict, rankSignals, severityFor } from './aggregate.js';
import { BRANDS } from './brands.js';

/**
 * UPI payment-link / QR analysis (NPCI "upi://pay" deep links and the app-specific variants).
 *
 * The single most important fact for users: scanning a UPI QR code and entering your PIN always
 * SENDS money. You never scan a QR or enter a PIN to receive money. "Scan to receive your refund /
 * prize / cashback" is the core of most UPI QR fraud in India.
 */

export interface UpiPayment {
  /** 'pay' = one-time payment; 'mandate' = recurring / auto-debit authorisation. */
  kind: 'pay' | 'mandate';
  scheme: string;
  payeeVpa: string;
  payeeName: string;
  /** Amount in rupees as written in the link, if fixed. */
  amount: number | null;
  currency: string;
  note: string;
  merchantCode: string;
  transactionRef: string;
  /** Text after the "@", e.g. "okaxis". */
  handle: string;
  handleKnown: boolean;
  vpaValid: boolean;
  /** Raw parameters (for the evidence panel). */
  params: Record<string, string>;
}

export interface UpiAssessment {
  payment: UpiPayment;
  verdict: Verdict;
  severity: Severity;
  /** Heuristic 0-100 risk score. Not a probability. */
  score: number;
  /** One-line plain statement of what will happen if the user proceeds. */
  whatHappens: string;
  headline: string;
  recommendedAction: string;
  signals: Signal[];
  limitations: string[];
}

const UPI_PREFIX = /^(?:upi|tez|gpay|phonepe|paytmmp|paytm|bhim|credpay|mobikwik|amazonpay|whatsapp):\/\/(?:upi\/)?(pay|mandate|collect)\b/i;

/** Common UPI handles (PSP suffixes). Not exhaustive: an unknown handle is only contextual. */
export const KNOWN_UPI_HANDLES = new Set([
  'upi', 'okaxis', 'oksbi', 'okhdfcbank', 'okicici', 'ybl', 'ibl', 'axl', 'apl', 'yapl', 'rapl', 'paytm', 'ptyes', 'ptaxis', 'pthdfc', 'ptsbi',
  'axisbank', 'axisb', 'icici', 'hdfcbank', 'hdfcbankjd', 'sbi', 'kotak', 'kmbl', 'indus', 'federal', 'fbl', 'idfcbank', 'idfcfirst', 'pnb', 'barodampay',
  'unionbank', 'uboi', 'cnrb', 'canarabank', 'boi', 'mahb', 'centralbank', 'cbin', 'iob', 'indianbank', 'idbi', 'aubank', 'rbl', 'yesbank', 'yesbankltd',
  'freecharge', 'ikwik', 'mobikwik', 'jupiteraxis', 'waicici', 'waaxis', 'wahdfcbank', 'wasbi', 'amazonpay', 'amazon', 'superyes', 'naviaxis', 'slc', 'abfspay',
  'airtel', 'jio', 'postbank', 'equitas', 'dbs', 'hsbc', 'sc', 'citi', 'kbl', 'karurvysyabank', 'tjsb', 'dlb', 'jkb', 'pockets', 'timecosmos', 'fam', 'pingpay', 'axisbiz',
]);

const VPA_RE = /^[a-z0-9][a-z0-9._-]{1,255}@[a-z][a-z0-9.]{1,63}$/i;

export function isUpiLink(text: string): boolean {
  return UPI_PREFIX.test(text.trim());
}

export function parseUpi(raw: string): UpiPayment | null {
  const text = raw.trim();
  const m = UPI_PREFIX.exec(text);
  if (!m) return null;
  const q = text.indexOf('?');
  const params: Record<string, string> = {};
  if (q >= 0) {
    for (const part of text.slice(q + 1).split('&')) {
      const eq = part.indexOf('=');
      const k = (eq >= 0 ? part.slice(0, eq) : part).trim().toLowerCase();
      if (!k || k in params) continue;
      let v = eq >= 0 ? part.slice(eq + 1) : '';
      try {
        v = decodeURIComponent(v.replace(/\+/g, ' '));
      } catch {
        /* keep raw */
      }
      params[k] = v.slice(0, 300);
    }
  }
  const payeeVpa = (params.pa ?? '').trim();
  const handle = payeeVpa.includes('@') ? payeeVpa.split('@').pop()!.toLowerCase() : '';
  const amt = params.am ? Number(params.am) : NaN;
  return {
    kind: m[1]!.toLowerCase() === 'mandate' ? 'mandate' : 'pay',
    scheme: text.slice(0, text.indexOf(':')).toLowerCase(),
    payeeVpa,
    payeeName: (params.pn ?? '').trim(),
    amount: Number.isFinite(amt) && amt > 0 ? amt : null,
    currency: (params.cu ?? 'INR').toUpperCase(),
    note: (params.tn ?? params.purpose ?? '').trim(),
    merchantCode: (params.mc ?? '').trim(),
    transactionRef: (params.tr ?? params.tid ?? '').trim(),
    handle,
    handleKnown: KNOWN_UPI_HANDLES.has(handle),
    vpaValid: VPA_RE.test(payeeVpa),
    params,
  };
}

const RECEIVE_LURE = /\b(receive|recieve|claim|refund|cash\s?back|prize|lottery|lucky\s+draw|winner|won|reward|bonus|reimburse\w*|subsidy|scholarship|payment\s+received|money\s+received|paisa\s+milega|paise\s+milenge|paise\s+wapas|refund\s+milega)\b|पैसे\s*(?:मिलेंगे|वापस)|रिफंड|इनाम|कैशबैक/i;
const KYC_LURE = /\b(kyc|verify|verification|activate|activation|unblock|reactivat\w*|police|court|arrest|customs|cyber\s?cell|registration\s+fee|processing\s+fee|security\s+deposit|token\s+amount|task\s+fee)\b/i;
/** Bills and fines are paid by UPI legitimately, but through merchant accounts, not personal IDs. */
const BILL_LURE = /\b(challan|e-?challan|electricity|bijli|light\s+bill|fine|penalty|fastag)\b/i;

function sig(id: string, category: SignalCategory, strength: SignalStrength, weight: number, title: string, detail: string, evidence?: string[]): Signal {
  return { id, source: 'local_content', category, strength, weight, title, detail, ...(evidence?.length ? { evidence } : {}) };
}

/** Does the payee name claim to be a known organisation? */
function brandClaimed(name: string): string | null {
  const n = ` ${name.toLowerCase().replace(/[^a-z0-9\p{Script=Devanagari} ]+/gu, ' ')} `;
  for (const b of BRANDS) {
    for (const nm of b.names) {
      if (nm.length >= 3 && n.includes(` ${nm.toLowerCase()} `)) return b.name;
    }
  }
  if (/\b(rbi|reserve bank|income tax|customs|cyber cell|police|npci|trai|government|govt|sarkar|electricity board)\b/i.test(name)) return name;
  return null;
}

const inr = (n: number) => `₹${n.toLocaleString('en-IN', { maximumFractionDigits: 2 })}`;

export function assessUpi(raw: string): UpiAssessment | null {
  const p = parseUpi(raw);
  if (!p) return null;
  const signals: Signal[] = [];
  const limitations = ['PhishShield cannot see who owns a UPI ID. Check the name your UPI app shows before entering your PIN.'];
  const text = `${p.payeeName} ${p.note}`;
  const who = p.payeeName ? `${p.payeeName} (${p.payeeVpa || 'no UPI ID'})` : p.payeeVpa || 'an unknown payee';
  const whatHappens =
    p.kind === 'mandate'
      ? `This sets up a recurring auto-debit from your account to ${who}${p.amount ? ` of up to ${inr(p.amount)}` : ''}.`
      : `Scanning this and entering your UPI PIN will SEND ${p.amount ? inr(p.amount) : 'money'} from your account to ${who}. You never need to scan a QR or enter your PIN to receive money.`;

  if (RECEIVE_LURE.test(text)) {
    signals.push(sig('upi.receive_lure', 'payment_fraud', 'strong', 0.6, 'Says you will receive money, but this QR takes money', 'Refund, prize, cashback or "receive payment" QR codes are the most common UPI scam. A UPI PIN is only ever needed to pay.', [`note: ${p.note || '—'}`, `payee name: ${p.payeeName || '—'}`]));
  }
  const brand = brandClaimed(p.payeeName);
  const localPart = p.payeeVpa.split('@')[0] ?? '';
  const personalLooking = /^\d{10}$/.test(localPart) || (!p.merchantCode && ['ybl', 'ibl', 'axl', 'okaxis', 'oksbi', 'okhdfcbank', 'okicici', 'paytm', 'apl', 'upi'].includes(p.handle));
  if (KYC_LURE.test(text)) {
    signals.push(sig('upi.fee_or_kyc', 'social_engineering', 'moderate', 0.3, 'Payment for KYC, verification or "fees"', 'Banks do not collect KYC or verification fees over UPI, and police, courts and customs never collect money through UPI QR codes.', [`note: ${p.note || '—'}`]));
  } else if (BILL_LURE.test(text) && personalLooking) {
    signals.push(sig('upi.bill_personal_vpa', 'payment_fraud', 'moderate', 0.3, 'Bill or fine paid to a personal UPI ID', 'Electricity boards, RTO challans and FASTag are paid through registered merchant accounts or official apps, never to a personal UPI ID.', [`note: ${p.note || '—'}`, `UPI ID: ${p.payeeVpa}`]));
  }
  if (brand && personalLooking) {
    signals.push(sig('upi.brand_personal_vpa', 'impersonation', 'moderate', 0.35, `Payee claims to be ${brand} but uses a personal UPI ID`, 'Organisations collect payments through registered merchant accounts, not personal phone-number or app UPI IDs.', [`payee name: ${p.payeeName}`, `UPI ID: ${p.payeeVpa}`]));
  }
  if (p.kind === 'mandate') {
    signals.push(sig('upi.mandate', 'payment_fraud', 'moderate', 0.3, 'Sets up an auto-debit (UPI mandate)', 'A mandate lets the payee take money again later. Only approve mandates for subscriptions you started yourself.', [`scheme: ${p.scheme}://mandate`]));
  }
  if (!p.vpaValid) {
    signals.push(sig('upi.invalid_vpa', 'obfuscation', 'moderate', 0.25, 'Malformed UPI ID', 'The payee address is missing or not a valid UPI ID.', [`pa: ${p.payeeVpa || '(missing)'}`]));
  } else if (!p.handleKnown) {
    signals.push(sig('upi.unknown_handle', 'infrastructure', 'contextual', 0.06, `Unfamiliar UPI handle “@${p.handle}”`, 'Not in PhishShield’s list of common UPI handles. That is often fine; check the name your UPI app shows.', [`handle: @${p.handle}`]));
  }
  if (p.amount !== null && p.amount >= 10_000 && !p.merchantCode) {
    signals.push(sig('upi.large_amount', 'payment_fraud', 'contextual', 0.08, `Large fixed amount: ${inr(p.amount)}`, 'Large pre-filled amounts to non-merchant UPI IDs deserve extra checking.', [`am: ${p.params.am}`]));
  }
  if (p.currency !== 'INR') {
    signals.push(sig('upi.currency', 'obfuscation', 'weak', 0.1, `Unusual currency “${p.currency}”`, 'UPI payments are in Indian rupees.', [`cu: ${p.currency}`]));
  }

  const breakdown = computeScore(signals);
  const verdict = decideVerdict(breakdown, { reputationMatch: false });
  const ranked = rankSignals(signals);
  const top = ranked.find((s) => s.weight > 0);
  const prefix: Record<Verdict, string> = {
    confirmed_malicious: 'Known scam',
    likely_phishing: 'Likely UPI scam',
    suspicious: 'Suspicious payment request',
    no_known_threats: 'Payment request',
    inconclusive: 'Could not fully check',
  };
  return {
    payment: p,
    verdict,
    severity: severityFor(verdict, breakdown.score),
    score: breakdown.score,
    whatHappens,
    headline: verdict !== 'no_known_threats' && top ? `${prefix[verdict]}: ${top.title}` : prefix[verdict],
    recommendedAction:
      verdict === 'likely_phishing' || verdict === 'suspicious'
        ? 'Do not pay. If someone promised you money, they are trying to take it. Report the number at cybercrime.gov.in or call 1930.'
        : 'Only continue if you meant to pay this person or shop. Check the name shown in your UPI app before entering your PIN.',
    signals: ranked,
    limitations,
  };
}

/** Find UPI deep links in pasted text (SMS, WhatsApp, e-mail). */
export function extractUpiLinks(text: string, max = 5): string[] {
  const re = /\b(?:upi|tez|gpay|phonepe|paytmmp|paytm|bhim):\/\/[^\s<>"']+/gi;
  return [...new Set([...text.slice(0, 10_000).matchAll(re)].map((m) => m[0].replace(/[.,;)]+$/, '')))].slice(0, max);
}
