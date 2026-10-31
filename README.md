# PhishShield AI

A Manifest V3 browser extension that protects people in India from the scams they actually meet:

- phishing sites;
- **UPI "receive money" QR codes**;
- **fake KYC / e-challan APKs**;
- booby-trapped attachments;
- scam-ad redirects;
- leaked passwords.

It explains every verdict in plain English and Hindi, and it works offline. Reputation lists, VirusTotal, domain age, breach history and AI explanations are optional extras, served by a small API server you run yourself, so no API key ever ships inside the extension.

There are no accounts, no analytics and no browsing history.

| Read next | For |
| --- | --- |
| [docs/LECTURE.md](docs/LECTURE.md) | **Start here.** The whole product explained from zero: scams, security basics, every feature and setting, how we built it, judge Q&A |
| [docs/FEATURES.md](docs/FEATURES.md) | **Every feature, how it works and its limits**, plus the competitive edge |
| [docs/DEMO.md](docs/DEMO.md) | The 7-minute stage demo, with harmless sample files in [`demo/`](demo), and judge Q&A |
| [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) | Stack, architecture, and how to turn on AI |
| [docs/research/VIRUSTOTAL.md](docs/research/VIRUSTOTAL.md) | How VirusTotal works behind the scenes, and what we adopted |
| [docs/research/HAVEIBEENPWNED.md](docs/research/HAVEIBEENPWNED.md) | How Have I Been Pwned and k-anonymity work, and what we adopted |

---

## What it does

### Protection while you browse

| Feature | How |
| --- | --- |
| **Automatic URL protection** | Every top-level navigation is checked on-device against deterministic rules, catching: deceptive subdomains (`sbi.co.in.secure-login.click`), look-alike spellings (`paypa1.com`), punycode/IDN homoglyphs (`xn--pypal-4ve.com` → `pаypal.com`), raw and obfuscated IP hosts, `user@host` tricks, shorteners, encoding abuse, free hosting combined with brand names, and brand-keyword domains (`hdfcbank-kyc-update.in`). |
| **Threat intel (optional)** | Google Safe Browsing v4 and the OpenPhish feed (a local copy), queried through the server. **VirusTotal** is used for manual scans only, because of its free-tier quota. Every finding names its provider and freshness. |
| **Domain age (RDAP)** | Asks the domain's **official registry** when it was registered. Only the registrable domain is sent. A domain registered days ago adds weight; it never flags a site on its own. |
| **Breach history (HIBP)** | "This company had a data breach in 2021: names, phones, addresses leaked." Shown as context to explain convincing scam calls. It is never a risk signal. |
| **Warnings** | A full-page interstitial appears only for `likely_phishing` and `confirmed_malicious`. Lower verdicts show only a toolbar badge. |
| **Scam-ad shield** (on) / **ad and tracker blocking** (off) / **hide empty ad spaces** (opt-in) | Chrome's `declarativeNetRequest` blocks pop-under, push and redirect ad networks used for prize, tech-support and loan scams. Optionally it also blocks about 80 mainstream ad and tracking networks, and collapses the empty boxes left behind. Third-party sub-resources only. |
| **Download Guard** | Pauses risky downloads before they finish: APKs from websites (especially with KYC, challan or invitation names), programs disguised as documents, scripts, shortcuts, and files built inside the page (HTML smuggling). You choose Cancel or Keep. |
| **Credential Guard** (opt-in) | Warns when you focus a password, OTP, PIN or card field on a risky page. It never reads what you type. |

### Tools you use on demand

| Feature | How |
| --- | --- |
| **Scan a QR code on screen** | Popup → Tools. Decodes the QR code visible in the tab, on-device. UPI codes show exactly **who gets how much money**, and flag "scan to receive" refund scams, fake KYC fees, brand names on personal UPI IDs, and autopay mandates. |
| **Scan a file** | Security Center. Static, on-device inspection of APK, ZIP, Office, PDF, HTML and EXE files: real type vs. extension, hidden programs, OTP-stealing Android permissions, macros, auto-run PDF JavaScript, login-page attachments, embedded links. The file is **never uploaded and never opened**; only its SHA-256 is optionally looked up on VirusTotal. |
| **Password leak check** | Security Center. Have I Been Pwned's k-anonymity range API: only 5 characters of the SHA-1 hash leave the browser. |
| **Check message** | Paste an SMS, WhatsApp or e-mail text. It finds scam tactics (English, Hindi, Hinglish), checks every link, and assesses any `upi://` links. |
| **Analyze page / Deep AI analysis** | Local content rules, then an optional LLM explanation (Groq by default, or Claude) of a redacted excerpt, after you confirm. |

### Verdicts

There are five verdicts:

- `no_known_threats`
- `suspicious`
- `likely_phishing`
- `confirmed_malicious`
- `inconclusive`

Each comes with a 0–100 score that is explicitly *not* a probability, plus reasons, evidence, sources, a recommended action and what was *not* checked. **"Confirmed" comes only from verified intel**: an exact match on a reputation list, or at least 3 VirusTotal engines. **No result ever says "safe".**

---

## Quick start

Requires Node.js ≥ 22.9 and Chrome/Edge ≥ 120.

```bash
npm install
```

```bash
npm run build
```

This writes the unpacked extension to `dist/extension/` and the API server to `dist/server/index.js`.

### Load the extension

1. Open `chrome://extensions`, turn on **Developer mode**, and choose **Load unpacked** → `dist/extension`.
2. Pin PhishShield. It works immediately in **local-only mode**.

### Run the API server (optional)

```bash
cp .env.example .env
```

Every key in `.env` is optional:

| Key | Enables | Where to get it |
| --- | --- | --- |
| `GROQ_API_KEY` | AI explanations | Free at https://console.groq.com/keys |
| `GSB_API_KEY` | Google Safe Browsing | Google Cloud console |
| `VT_API_KEY` | VirusTotal lookups (manual scans and file hashes) | Free account at virustotal.com → API key |

These need no key and are on by default: the OpenPhish feed, RDAP domain age and the HIBP breach catalogue.

```bash
npm run server
```

The server listens on `http://127.0.0.1:8787`, which is the extension's default. In **Settings**, click **Test** to see which providers are configured. For anything beyond local development, put the server behind HTTPS and set `ALLOWED_ORIGINS=chrome-extension://<your-extension-id>`.

### Checks

```bash
npm run check
```

This runs typecheck, lint, tests and the production build. The build also fails if anything that looks like an API key (Groq, Anthropic, Google, VirusTotal) ends up in the extension bundle.

---

## How the verdict is decided

```
 URL ─────► local URL rules ─────────┐
 page ────► local content rules ─────┤
 file ────► local file inspector ────┤      score = 1 − Π(1 − wᵢ)   (0–100, not a probability)
 QR/UPI ──► local UPI rules ─────────┼──► aggregate ──► verdict + severity + evidence + limitations
 server ──► reputation lists / VT ───┤
 server ──► domain age (RDAP) ───────┤
 server ──► AI (on demand) ──────────┘   (AI pooled, capped at 0.30)
```

- **Signals.** Each rule emits a signal with a weight, a strength (`strong` / `moderate` / `weak` / `contextual`), a human-readable explanation and raw evidence.
- **Contextual signals never stand alone.** These include HTTP, long URLs, login-ish words, shorteners, unusual TLDs and a domain 1–3 months old. They count only when a real indicator is also present.
- **Thresholds:** `suspicious` at 30 or above, `likely_phishing` at 60 or above. `likely_phishing` also requires at least one strong or three moderate non-AI signals.
- **`confirmed_malicious` comes only from verified threat intel.** Heuristics, domain age and AI can never produce it.
  - **Reputation lists:** an exact-URL or URL-prefix match confirms. A host-level match only adds a strong signal.
  - **VirusTotal:** at least 3 engines saying `malicious` confirms. 1–2 engines is a minority-detection signal.
- **AI can raise concern but never lower it,** and never adds more than 0.30 of weight. A finding counts only if its quote appears in the page.
- **A lack of findings is reported as "No known threats", never as "safe".** Every result lists what was not checked.

---

## Permissions and why

| Permission | Why it is needed |
| --- | --- |
| `webNavigation` | See top-level navigations so URLs can be checked before and as pages load. Chrome shows this as "Read your browsing history". PhishShield does **not** keep a history: per-tab results live in `chrome.storage.session` (memory only). |
| `storage` | Settings, the trusted-site list, per-tab state and reputation cache (keys are SHA-256 hashes of URLs), and recent Download Guard decisions (session only). |
| `activeTab` + `scripting` | Read the current page's visible text **only when you click "Analyze page"**; capture the visible tab once when you click **Scan a QR code on this screen**; show the per-tab "blocked" count. |
| `downloads` | **Download Guard**: notice new downloads, pause risky ones, and cancel or delete only when you click. Chrome shows "Manage your downloads". |
| `declarativeNetRequest` | **Scam-ad shield** and **ad/tracker blocking**, applied by Chrome itself. The extension never sees your requests. Chrome shows "Block content on any page". |
| `optional_host_permissions: https://*/*, http://*/*` | **Only for Credential Guard**: requested when you turn it on, removed when you turn it off. |

There are no `<all_urls>` content scripts by default, and no `cookies`, `history`, `tabCapture` or `declarativeNetRequestFeedback` permissions. A test pins the exact permission list.

Extension pages use a strict CSP (`script-src 'self'; object-src 'self'; base-uri 'none'`). All UI is built with DOM APIs, and ESLint forbids `innerHTML` / `outerHTML` / `insertAdjacentHTML`.

---

## Privacy notice

- **No accounts, analytics or tracking.** No browsing history is kept.
- **Local by default.** URL rules, page analysis, file inspection, QR decoding, UPI analysis, Download Guard and ad blocking all run on your device.
- **Reputation checks** (if a server is configured and the setting is on) send the page address **without query string or fragment** to *your* server.
  - The server queries Google Safe Browsing (if configured) and matches against a local copy of the OpenPhish feed.
  - **VirusTotal is asked only for links you scan by hand.**
  - Private, local and link-local addresses (`localhost`, `10.x`, `192.168.x`, `169.254.169.254`, `.local`, …) are never sent anywhere.
- **Domain age:** the server sends only the **registrable domain** (for example `example.co.in`) to that domain's official RDAP registry. Disable with `RDAP_ENABLED=false`.
- **Breach history** comes from a local copy of HIBP's public breach list, downloaded daily. No per-site lookup is sent to HIBP.
- **Files are never uploaded.** Only the file's SHA-256 fingerprint is sent, and only if "File fingerprint lookups" is on, to your server, which looks it up on VirusTotal.
- **Password checks** send only the first 5 characters of the password's SHA-1 hash, **directly** to Have I Been Pwned (k-anonymity). Our server never sees them.
- **QR screen scans** capture the visible tab once, decode it in the popup, and discard the image.
- **AI analysis happens only after you confirm** in a dialog that says what will be sent.
  - E-mails, phone numbers, card numbers, Aadhaar, PAN and long digit runs are redacted on-device first.
  - The server logs only method, path, status and timing, and never request bodies.
  - The AI provider (Groq by default) processes the excerpt under its own API data policy.
- **Form values, passwords and tokens are never read** from web pages.

---

## Security design

- **Secrets stay on the server.** The extension knows only the server URL. The build aborts if a key-like string appears in `dist/extension`.
- **The server never visits user-supplied URLs.** That removes the SSRF / DNS-rebinding / redirect-abuse surface. Its outbound requests go only to fixed API endpoints:
  - Safe Browsing;
  - the two official OpenPhish feed URLs;
  - VirusTotal;
  - `haveibeenpwned.com/api/v3/breaches`;
  - the IANA RDAP bootstrap and the registry servers it lists.

  Each registry base must be `https://` on a public hostname. Redirects are followed manually (at most 2) and re-validated, with a 3.5 s timeout.
- **Lookup, never submit.** VirusTotal is only asked about hashes and URL IDs it already knows. PhishShield never uploads files or asks VT to fetch a URL.
- **Trust boundaries are validated:**
  - strict zod schemas (unknown keys rejected);
  - a 48 KB body limit and `Content-Type` enforcement;
  - per-IP rate limits (reputation 60/min, file 10/min, analyze 6/min, health 30/min);
  - local VirusTotal quota limiting (4/min, 500/day) and per-registry RDAP limits;
  - a cap of 4 concurrent AI calls;
  - CORS restricted to extension origins, plus security headers.

  Every provider response is schema-validated.
- **Prompt-injection defences:**
  - untrusted text is stripped of control characters and fake delimiter tags;
  - it is wrapped in `<untrusted_content>`;
  - output is forced into a JSON schema;
  - quotes must be verbatim from the source;
  - instructions aimed at AI are themselves detected as a scam signal.

  Even a fully hijacked model can neither lower a verdict nor confirm one.
- **The extension never executes downloaded or uploaded content.** File inspection is byte-level parsing only. Download Guard reads metadata only. Delete and cancel run only when you click.
- **Message routing checks the sender.** Only extension pages can request scans, bypasses or download actions.

---

## Providers and terms

| Provider | Status | Terms |
| --- | --- | --- |
| **Google Safe Browsing v4 Lookup** | Implemented; needs `GSB_API_KEY` | Non-commercial only; commercial products must use Google Web Risk |
| **OpenPhish Community Feed** | On by default; downloaded every 12 h, flagged stale after 36 h | Free for non-commercial use |
| **VirusTotal API v3** | Implemented; needs `VT_API_KEY`. On demand only, lookup only. | Public API: 4/min, 500/day, **non-commercial only** |
| **RDAP** (IANA bootstrap → registries) | On by default; no key | Public registry data |
| **Have I Been Pwned** breach catalogue | On by default; downloaded daily | **CC BY 4.0**: attributed in the UI |
| **Pwned Passwords** (k-anonymity) | Called directly by the Security Center | Free, no key, no attribution required |
| **Groq** / **Anthropic** | AI explanations | Provider API terms |

Unconfigured providers are reported as **not configured**, never silently treated as clean. Failures, timeouts and partial results are reported as such. Nothing in the UI is mocked.

---

## Testing

There are 356 tests (`npm test`) covering:

- URL parsing and look-alike detection, plus about 70 legitimate Indian banking, payment, government and delivery URLs that must not be flagged.
- Aggregation rules: contextual-only signals, AI cap, confirmation only from verified intel, VirusTotal minority detections.
- Content rules in English, Hindi and Hinglish, including negation and injection detection.
- **File inspector:** type detection; RTLO and double extensions; ZIP/ZIP64 and encrypted entries; APK permissions from compressed manifests; macros; PDF JavaScript; HTML smuggling; Authenticode.
- **UPI and QR:** receive-money lures, KYC fees, brand names on personal UPI IDs, mandates, invalid VPAs, QR payload routing.
- **Download Guard:** lure APKs, MIME mismatches, `blob:` downloads, trusted sources, and ordinary downloads that must pass.
- **Ad-blocking rulesets:** valid rules, third-party only, never `main_frame`, disjoint lists, default states, and the exact permission list.
- **Intel adapters:** Safe Browsing, OpenPhish, VirusTotal (detections, 404, quota, key errors), HIBP (filtering, indexing), RDAP (bootstrap, unsafe bases, redirects, timeouts).
- **Pwned Passwords:** only the prefix is sent, padding rows are ignored, the fallback works.
- **Demo files:** the sample files in `demo/` produce the results that [docs/DEMO.md](docs/DEMO.md) promises.
- AI output validation, and the HTTP layer (CORS, body limits, schemas, rate limits).

**Also verified by hand** (31 Oct 2026), in a browser preview with a chrome.* stub and a live server:

- QR decoding of real QR images;
- the file scan flow;
- the live Pwned Passwords call (padding works through CORS);
- the Download Guard pause and cancel flow;
- shield toggles;
- live RDAP (`adobe.com`, `dominos.co.in`, `example.com`) and live HIBP breach data;
- a live OpenPhish match.

VirusTotal was verified only with mocked responses, because no `VT_API_KEY` was configured.

**No accuracy figure is claimed.** The rules have not been measured against a representative, labelled dataset.

## Limitations

- **Heuristics can be evaded.** A phishing page with no brand cues, or one on a compromised legitimate site, gets past them. Reputation lists catch some of these, and only after they're reported.
- **The interstitial is not a hard block.** A fast page may start loading first.
- **Ad blocking uses a curated list** of 111 network domains (29 scam-ad and 82 ad/tracker), not EasyList. Ads that a site serves from its own domain, such as YouTube video ads, can't be blocked at the network level.
- **File inspection is static**, with a 256 MB cap and no sandbox.
- **Download Guard uses metadata only.**
- **UPI checks can't see who owns a UPI ID.**
- **Domain age is "unsupported"** for TLDs without RDAP.
- **Link-shortener destinations are not expanded.**
- **Chromium only** (Chrome/Edge ≥ 120).
- **Partly tested in real Chrome.** Tested on 31 Oct 2026: the extension talks to the server, Download Guard pauses and cancels a 3 MB APK, and the ad rules block listed networks on a real news site. A later change (1 Nov 2026) makes **Cancel** also remove a download that finished before it could be paused — so very small files (a few KB, which Chrome can't pause) no longer stay on disk — and adds a content script that collapses the site's own wrapper and "Advertisement" caption around a blocked ad slot. That collapser was verified by simulation in a browser preview; it, the download change, the warning page, the popup and the QR screen capture have not yet been re-confirmed in real Chrome. Rebuild, reload the extension, and run the [demo script](docs/DEMO.md) once before presenting.

## Project layout

```
src/engine/      Pure TypeScript risk engine (URL, content, UPI/QR, file inspector, download, domain age, aggregation)
src/shared/      Types, redaction, Pwned Passwords client
src/extension/   MV3 extension: background worker, popup, warning page, Security Center, Download Guard page,
                 options, content scripts, ad-blocking rulesets
src/server/      Optional Node API: Safe Browsing, OpenPhish, VirusTotal, RDAP, HIBP, AI providers, HTTP app
tests/           Vitest suites
demo/            Harmless sample QR codes and files, and site/ — the local "Test Range" demo page
docs/            Features, demo, architecture, and VirusTotal / HIBP research
scripts/build.mjs       esbuild bundling, icon generation, secret scan
scripts/demo-server.py  serves the Test Range and the slow demo download on 127.0.0.1:8098
```

If you see a scam in India, report it at **cybercrime.gov.in** or call **1930**.
