import type { BgResponse } from '../lib/messages.js';

/**
 * Credential Guard (opt-in). When the user focuses a password, OTP, PIN or card field, ask the
 * background worker whether this page is risky and, if so, show an inline banner.
 * It never reads what the user types and never blocks or submits anything.
 */
(() => {
  const SENSITIVE = /password|one-time-code|\botp\b|one.?time|verification.?code|\bpin\b|upi.?pin|mpin|cvv|cvc|cc-number|card.?(no|num)|aadha?ar/i;
  let shown = false;
  let checking = false;

  function isSensitive(el: EventTarget | null): el is HTMLInputElement {
    if (!(el instanceof HTMLInputElement)) return false;
    if (el.type === 'password') return true;
    const a = ['name', 'id', 'placeholder', 'autocomplete', 'aria-label'].map((x) => el.getAttribute(x) ?? '').join(' ');
    return SENSITIVE.test(a);
  }

  function showBanner(reason: string, host: string, officialHint?: string): void {
    shown = true;
    const hostEl = document.createElement('phishshield-guard');
    const root = hostEl.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = `
      .box{position:fixed;z-index:2147483647;left:50%;bottom:20px;transform:translateX(-50%);max-width:min(560px,calc(100vw - 32px));
        background:#1C1917;color:#FAFAF9;border-left:4px solid #F97316;border-radius:10px;padding:14px 16px;
        font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;box-shadow:0 10px 30px rgba(0,0,0,.35)}
      .t{font-weight:650;margin:0 0 4px}.r{margin:0 0 10px;color:#E7E5E4}.h{color:#FDBA74}
      .row{display:flex;gap:8px;flex-wrap:wrap}
      button{font:inherit;border-radius:7px;padding:6px 12px;cursor:pointer;border:1px solid #57534E;background:#292524;color:#FAFAF9}
      button.p{background:#F97316;border-color:#F97316;color:#1C1917;font-weight:650}
      button:focus-visible{outline:2px solid #FDBA74;outline-offset:2px}`;
    const box = document.createElement('div');
    box.className = 'box';
    box.setAttribute('role', 'alert');
    const t = document.createElement('p');
    t.className = 't';
    t.textContent = `PhishShield: think before you type on ${host}`;
    const r = document.createElement('p');
    r.className = 'r';
    r.textContent = reason;
    if (officialHint) {
      const h = document.createElement('span');
      h.className = 'h';
      h.textContent = ` Official site: ${officialHint}.`;
      r.append(h);
    }
    const row = document.createElement('div');
    row.className = 'row';
    const leave = document.createElement('button');
    leave.className = 'p';
    leave.textContent = 'Leave this page';
    leave.addEventListener('click', () => history.back());
    const dismiss = document.createElement('button');
    dismiss.textContent = 'Dismiss';
    dismiss.addEventListener('click', () => hostEl.remove());
    row.append(leave, dismiss);
    box.append(t, r, row);
    root.append(style, box);
    document.documentElement.append(hostEl);
  }

  document.addEventListener(
    'focusin',
    (e) => {
      if (shown || checking || !isSensitive(e.target)) return;
      checking = true;
      chrome.runtime
        .sendMessage({ type: 'guard-check', title: document.title })
        .then((res: BgResponse) => {
          if (res?.ok && res.guard?.warn) showBanner(res.guard.reason ?? 'This page shows signs of phishing.', res.guard.host, res.guard.officialHint);
        })
        .catch(() => undefined)
        .finally(() => {
          checking = false;
        });
    },
    true,
  );
})();
