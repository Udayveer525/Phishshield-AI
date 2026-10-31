import type { PageSnapshot } from '../../shared/types.js';

/**
 * Injected on demand (user clicked "Analyze page") via chrome.scripting.executeScript({ func }).
 * Must be fully self-contained: it is serialised and run in the page, so it cannot use imports
 * or outer variables.
 *
 * Privacy contract:
 *  - Reads visible text nodes only. Never reads `.value` of inputs, textareas, selects or
 *    contenteditable regions, so typed passwords, OTPs and form data are never collected.
 *  - Reports form fields as counts by type and form targets as hostnames only.
 */
export function extractPageSnapshot(maxChars: number): PageSnapshot {
  const SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'TEXTAREA', 'INPUT', 'SELECT', 'OPTION', 'SVG', 'CANVAS', 'IFRAME', 'OBJECT']);
  const visibility = new WeakMap<Element, boolean>();

  function visible(el: Element | null): boolean {
    if (!el) return true;
    const cached = visibility.get(el);
    if (cached !== undefined) return cached;
    let v = true;
    if (SKIP.has(el.tagName) || (el as HTMLElement).isContentEditable) v = false;
    else if (typeof (el as HTMLElement).checkVisibility === 'function') v = (el as HTMLElement).checkVisibility({ opacityProperty: true, visibilityProperty: true });
    visibility.set(el, v);
    return v;
  }

  const parts: string[] = [];
  let length = 0;
  let truncated = false;
  const walker = document.createTreeWalker(document.body ?? document.documentElement, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const parent = node.parentElement;
    if (!parent || !visible(parent)) continue;
    if (parent.closest('[contenteditable=""], [contenteditable="true"], textarea, input, select')) continue;
    const t = (node.nodeValue ?? '').replace(/\s+/g, ' ').trim();
    if (!t) continue;
    parts.push(t);
    length += t.length + 1;
    if (length > maxChars) {
      truncated = true;
      break;
    }
  }
  const text = parts.join(' ').slice(0, maxChars);

  const inputs = Array.from(document.querySelectorAll('input, select, textarea')) as Array<HTMLInputElement>;
  const attrs = (el: Element) =>
    ['name', 'id', 'placeholder', 'autocomplete', 'aria-label', 'inputmode']
      .map((a) => el.getAttribute(a) ?? '')
      .join(' ')
      .toLowerCase();
  let passwordFields = 0;
  let otpFields = 0;
  let cardFields = 0;
  let identityFields = 0;
  let pinFields = 0;
  for (const el of inputs) {
    const type = (el.getAttribute('type') ?? 'text').toLowerCase();
    if (['hidden', 'submit', 'button', 'image', 'reset', 'checkbox', 'radio'].includes(type)) continue;
    const a = attrs(el);
    if (/\b(upi.?pin|m-?pin|atm.?pin|card.?pin|\bpin\b)/.test(a)) pinFields++;
    else if (type === 'password') passwordFields++;
    else if (/one-time-code|\botp\b|one.?time|verification.?code/.test(a)) otpFields++;
    else if (/cc-number|cc-csc|cc-exp|card.?(no|num)|\bcvv\b|\bcvc\b|expiry/.test(a)) cardFields++;
    else if (/aadha?ar|\bpan\b|pan.?card|pan.?no/.test(a)) identityFields++;
  }

  const actionHosts = new Set<string>();
  for (const f of Array.from(document.forms)) {
    try {
      const action = f.getAttribute('action');
      if (action) actionHosts.add(new URL(action, location.href).hostname);
    } catch {
      /* ignore malformed actions */
    }
  }

  const meta = document.querySelector('meta[name="description"]')?.getAttribute('content') ?? '';
  return {
    url: location.href,
    title: (document.title ?? '').slice(0, 300),
    metaDescription: meta.slice(0, 300),
    text,
    truncated,
    forms: {
      formCount: document.forms.length,
      passwordFields,
      otpFields,
      cardFields,
      identityFields,
      pinFields,
      actionHosts: [...actionHosts].slice(0, 10),
    },
  };
}
