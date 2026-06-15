# AI Intruder Pro — Proxy, Intercept, Scanner & Agent (v3)

A Chrome/Edge extension that works like an AI-augmented Burp Suite, living *inside* the browser.
Capture and **intercept** traffic, run **match/replace** rules, fuzz with an **AI Intruder**,
scan the **client-side/JS**, do **multi-session IDOR** testing, and turn loose a constrained
**AI testing agent** — all analyzed with the DeepSeek API.

> ⚠️ **Authorized testing only.** Use only on systems you own or have explicit written permission
> to test. Interception, Repeater, Intruder, and the Agent send live requests. Scope enforcement
> is on by default to help prevent out-of-scope traffic.

## Headline capabilities

- **Passive capture** of full requests/responses (CDP Network domain), now stored in **IndexedDB**
  for scale (up to 5,000 entries), plus **WebSocket frame** capture.
- **Live interception + match/replace** (CDP Fetch domain): manual intercept (pause → edit →
  forward/drop, plus *Forward all*), and standing rules that rewrite request/response url/headers/
  body (string or regex). Rules and intercept turn on Fetch only while capturing.
- **AI Intruder**: `§ §` insertion points, built-in payload sets or DeepSeek-generated payloads,
  throttled concurrent firing with Stop, anomaly flags (status/length/time Δ, reflected, error
  signatures, grep), `{{OOB}}` templating for blind tests, and one-click AI triage.
- **Client-side / JS scanner**: scans the active page for DOM-XSS sinks (`innerHTML`, `eval`,
  `document.write`, `postMessage` listeners, `dangerouslySetInnerHTML`, …), mines inline +
  external JS for **secrets** and **hidden API endpoints**, and reports storage keys & cookies —
  with an optional AI review. This is the in-browser advantage a network proxy can't match.
- **Multi-session IDOR**: save identities (cookie/authorization) and replay any request as another
  user, with an automatic same-status/same-length verdict and a response diff.
- **AI Agent**: a constrained loop that plans and executes safe, **scope-enforced** probes against
  the selected request's target, asks for confirmation before any state-changing verb, and writes
  a conclusion.
- **Expanded scanner**: CORS misconfig, JWT (decode + `alg:none`), GraphQL introspection, open
  redirect, mixed content, CSP weaknesses, verb tampering, plus a broad secrets ruleset.
- **Site analysis** with cross-request correlation (IDOR/auth-inconsistency), **HAR import/export**,
  **response comparer** (word-level diff), **encoder/decoder** (URL/base64/hex/HTML/JWT/unicode),
  and an **AI-written findings report** you can download as Markdown.
- **Safety/ops**: per-request scope enforcement, outbound rate limiting, an audit log, light/dark/
  auto theme, and a service-worker keepalive.

## Install (load unpacked)

1. Unzip somewhere permanent.
2. `chrome://extensions` (or `edge://extensions`) → enable **Developer mode**.
3. **Load unpacked** → select the `ai-intruder-pro` folder.
4. Open **Settings**: add your DeepSeek key, set scope, choose theme, and review the exclude
   filter (images skipped by default) and outbound throttle.

## Quick tour

- Toolbar icon: toggle **Capture** and **Manual intercept**.
- **Analyzer** (header buttons): Intercept queue, Rules, Scan page, Sessions, Comparer, Encoder,
  Report, Site analysis, HAR.
- Per request: **Request / Response / Heuristics / AI Analysis / Intruder / AI Agent / Repeater**.

## Files

| File | Purpose |
|------|---------|
| `manifest.json` | MV3 manifest (debugger, scripting, storage, alarms) |
| `db.js` | IndexedDB backbone (entries + audit) |
| `background.js` | Capture, WebSocket, Fetch interception, rules, page-scan, messaging |
| `analyzer.js` | Heuristics, correlation, JS mining, AI prompts, agent, report, scope/rate/audit sender |
| `tools.js` | Encoders/decoders, JWT decode, word-level diff |
| `payloads.js` | Built-in Intruder payloads |
| `theme.js` | Light/dark/auto theme |
| `popup.html/.js` | Capture + intercept toggles |
| `viewer.html/.js` | Full analyzer UI and all tools |
| `intercept.html/.js` | Dedicated interception window (queue + focused editor + shortcuts) |
| `options.html/.js` | API, scope, exclude filter, rate limit, OOB, theme |

## Important notes & limits

- **Some features are browser-runtime and need live testing in Chrome.** The capture/interception
  path (CDP Fetch), the content-script page scan (`chrome.scripting`), and the agent loop are
  implemented against the documented APIs and unit-tested where logic is pure, but they cannot be
  executed outside a browser. Verify behavior on an authorized target before relying on them.
- **Manual intercept holds the page**: while ON and capturing, matching requests pause until you
  forward/drop them (like Burp). If the service worker is suspended mid-pause, a page can hang —
  toggle intercept off to release. The keepalive alarm mitigates this but the MV3 model has limits.
- Only one debugger client per tab — close DevTools on a tab you want to capture/intercept.
- Heuristics, Intruder flags, and IDOR verdicts are *leads*, not proof — confirm manually.
- Blind-vuln (OOB) detection sets up the payloads; you confirm hits on your own collaborator/OOB
  service externally.
