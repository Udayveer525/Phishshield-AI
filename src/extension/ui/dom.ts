/** Tiny DOM builder. All text goes through textContent; untrusted strings are never parsed as HTML. */

type Child = Node | string | number | null | undefined | false;
type Attrs = Record<string, string | number | boolean | EventListener | undefined | null>;

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'class') node.className = String(v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  append(node, ...children);
  return node;
}

export function append(parent: Node, ...children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    parent.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
  }
}

export function clear(node: Node): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

const SVG_NS = 'http://www.w3.org/2000/svg';

// Stroke icons (24px grid). Drawn for PhishShield; deliberately no "check mark = safe" icon.
const ICONS: Record<string, string[]> = {
  shield: ['M12 2.5 19.5 5.5V11c0 4.6-3.1 8.6-7.5 10.5C7.6 19.6 4.5 15.6 4.5 11V5.5Z'],
  'shield-alert': ['M12 2.5 19.5 5.5V11c0 4.6-3.1 8.6-7.5 10.5C7.6 19.6 4.5 15.6 4.5 11V5.5Z', 'M12 8v4.5', 'M12 15.6v.1'],
  'shield-x': ['M12 2.5 19.5 5.5V11c0 4.6-3.1 8.6-7.5 10.5C7.6 19.6 4.5 15.6 4.5 11V5.5Z', 'm9.5 9.5 5 5', 'm14.5 9.5-5 5'],
  'shield-q': ['M12 2.5 19.5 5.5V11c0 4.6-3.1 8.6-7.5 10.5C7.6 19.6 4.5 15.6 4.5 11V5.5Z', 'M10 9.5a2 2 0 1 1 2.8 1.8c-.5.3-.8.7-.8 1.2v.5', 'M12 15.6v.1'],
  'shield-dot': ['M12 2.5 19.5 5.5V11c0 4.6-3.1 8.6-7.5 10.5C7.6 19.6 4.5 15.6 4.5 11V5.5Z', 'M12 11.5v.1'],
  alert: ['M10.3 3.9 2.6 17.5A2 2 0 0 0 4.3 20.5h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z', 'M12 9v4', 'M12 16.8v.1'],
  search: ['M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14Z', 'm20 20-4-4'],
  message: ['M4 5h16v11H8l-4 4Z'],
  mask: ['M3 6c3 1.5 6 1.5 9 0 3 1.5 6 1.5 9 0v5c0 5-4 8-9 8s-9-3-9-8Z', 'M7.5 11.5c1 .7 2 .7 3 0', 'M13.5 11.5c1 .7 2 .7 3 0'],
  globe: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z', 'M3 12h18', 'M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3Z'],
  cpu: ['M7 7h10v10H7Z', 'M10 3v4', 'M14 3v4', 'M10 17v4', 'M14 17v4', 'M3 10h4', 'M3 14h4', 'M17 10h4', 'M17 14h4'],
  database: ['M12 3c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3Z', 'M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6', 'M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3'],
  list: ['M9 6h11', 'M9 12h11', 'M9 18h11', 'M4.5 6h.1', 'M4.5 12h.1', 'M4.5 18h.1'],
  volume: ['M4 9h4l5-4v14l-5-4H4Z', 'M16.5 8.5a5 5 0 0 1 0 7', 'M19 6a8.5 8.5 0 0 1 0 12'],
  settings: ['M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z', 'M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.6 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.6-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z'],
  copy: ['M9 9h11v11H9Z', 'M5 15H4V4h11v1'],
  chevron: ['m9 6 6 6-6 6'],
  external: ['M14 4h6v6', 'M20 4 11 13', 'M18 14v6H4V6h6'],
  back: ['M15 6 9 12l6 6'],
  info: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z', 'M12 11v5', 'M12 7.8v.1'],
  refresh: ['M20 11a8 8 0 0 0-14.6-4.5L4 8', 'M4 4v4h4', 'M4 13a8 8 0 0 0 14.6 4.5L20 16', 'M20 20v-4h-4'],
  lock: ['M6 11h12v9H6Z', 'M8.5 11V8a3.5 3.5 0 0 1 7 0v3'],
  download: ['M12 4v11', 'm7.5 10.5 4.5 4.5 4.5-4.5', 'M5 20h14'],
  file: ['M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z', 'M14 3v5h5'],
  qr: ['M4 4h6v6H4Z', 'M14 4h6v6h-6Z', 'M4 14h6v6H4Z', 'M14 14h2v2h-2Z', 'M18 14h2', 'M14 18h2', 'M18 18h2v2'],
  key: ['M8 15a4 4 0 1 1 3.5-6', 'M11.5 9H21', 'M17 9v3', 'M20 9v2'],
  tools: ['M14.7 6.3a4 4 0 0 0-5.4 5.2L4 16.8V20h3.2l5.3-5.3a4 4 0 0 0 5.2-5.4l-2.3 2.3-2.4-.6-.6-2.4Z'],
  ban: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z', 'm5.6 5.6 12.8 12.8'],
  calendar: ['M4 6h16v14H4Z', 'M4 10h16', 'M8 3v4', 'M16 3v4'],
  upload: ['M12 16V5', 'm7.5 9.5 4.5-4.5 4.5 4.5', 'M5 20h14'],
  camera: ['M4 8h3l2-2.5h6L17 8h3v11H4Z', 'M12 10.5a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z'],
};

export function icon(name: keyof typeof ICONS | string, size = 18, cls = ''): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  if (cls) svg.setAttribute('class', cls);
  for (const d of ICONS[name] ?? ICONS.info!) {
    const p = document.createElementNS(SVG_NS, 'path');
    p.setAttribute('d', d);
    svg.appendChild(p);
  }
  return svg;
}

export function timeAgo(ts: number, lang: 'en' | 'hi' = 'en'): string {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return lang === 'hi' ? 'अभी' : 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return lang === 'hi' ? `${m} मिनट पहले` : `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return lang === 'hi' ? `${h} घंटे पहले` : `${h} h ago`;
  return new Date(ts).toLocaleDateString();
}
