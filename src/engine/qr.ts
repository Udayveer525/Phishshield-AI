import type { RiskAssessment, Signal } from '../shared/types.js';
import { analyzeText, assess, type AssessOptions } from './index.js';
import { assessUpi, isUpiLink, type UpiAssessment } from './upi.js';

/**
 * What a decoded QR code contains, and what PhishShield thinks about it. Imported directly by the
 * extension (not re-exported from engine/index) to keep the module graph acyclic.
 */
export type QrAnalysis =
  | { type: 'upi'; raw: string; upi: UpiAssessment }
  | { type: 'url'; raw: string; url: RiskAssessment }
  | { type: 'wifi'; raw: string; ssid: string; security: string }
  | { type: 'contact'; raw: string; summary: string }
  | { type: 'text'; raw: string; signals: Signal[] };

const MAX_QR_TEXT = 4096;

export function analyzeQrPayload(raw: string, opts: AssessOptions = {}): QrAnalysis {
  const text = raw.slice(0, MAX_QR_TEXT).trim();
  if (isUpiLink(text)) {
    const upi = assessUpi(text);
    if (upi) return { type: 'upi', raw: text, upi };
  }
  if (/^https?:\/\//i.test(text) || /^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/\S*)?$/i.test(text)) {
    return { type: 'url', raw: text, url: assess(text, { ...opts, allowSchemeless: true }) };
  }
  if (/^WIFI:/i.test(text)) {
    const field = (k: string) => new RegExp(`(?:^WIFI:|;)${k}:((?:\\\\.|[^;])*)`, 'i').exec(text)?.[1]?.replace(/\\(.)/g, '$1') ?? '';
    return { type: 'wifi', raw: text, ssid: field('S'), security: field('T') || 'open' };
  }
  if (/^(?:BEGIN:VCARD|MECARD:|tel:|sms:|smsto:|mailto:|geo:)/i.test(text)) {
    const kind = text.split(/[:;]/)[0]!.toUpperCase();
    return { type: 'contact', raw: text, summary: kind === 'BEGIN' ? 'Contact card (vCard)' : `${kind.toLowerCase()} link` };
  }
  return { type: 'text', raw: text, signals: analyzeText(text) };
}
