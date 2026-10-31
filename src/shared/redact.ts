/** Redact likely personal data before text leaves the device or is sent to a model. */
export function redactSensitive(text: string): string {
  return text
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[email]')
    .replace(/\b[A-Z]{5}\d{4}[A-Z]\b/g, '[pan]')
    .replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}(?:[\s-]?\d{4})?\b/g, '[number]')
    .replace(/(?<![\d₹.,])\d{8,}(?![\d])/g, '[number]')
    .replace(/(?:\+91[\s-]?)?\b[6-9]\d{4}[\s-]?\d{5}\b/g, '[phone]');
}
