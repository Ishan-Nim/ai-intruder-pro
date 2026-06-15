// analyzer.js (Pro) — heuristics, DeepSeek prompts/calls, HTTP sender.

const SEC_HEADERS = {
  "content-security-policy": "Missing CSP — increases XSS impact.",
  "strict-transport-security": "Missing HSTS — downgrade to HTTP possible.",
  "x-frame-options": "Missing X-Frame-Options — possible clickjacking (check CSP frame-ancestors).",
  "x-content-type-options": "Missing nosniff — MIME sniffing risk.",
  "referrer-policy": "Missing Referrer-Policy — referrer leakage."
};

function hget(headers, name) {
  const h = (headers || []).find((x) => x.name.toLowerCase() === name.toLowerCase());
  return h ? h.value : null;
}

function heuristicScan(entry) {
  const findings = [];
  const respBody = entry.responseBody || "";
  const isHtml = /text\/html/i.test(entry.mimeType || "");

  if (isHtml) {
    for (const [h, msg] of Object.entries(SEC_HEADERS))
      if (!hget(entry.responseHeaders, h))
        findings.push({ sev: "low", title: "Missing header: " + h, detail: msg });
  }
  (entry.responseHeaders || [])
    .filter((x) => x.name.toLowerCase() === "set-cookie")
    .forEach((c) => {
      const v = c.value.toLowerCase(); const flags = [];
      if (!/;\s*httponly/.test(v)) flags.push("HttpOnly");
      if (!/;\s*secure/.test(v)) flags.push("Secure");
      if (!/;\s*samesite/.test(v)) flags.push("SameSite");
      if (flags.length) findings.push({ sev: "medium", title: "Cookie missing flags: " + flags.join(", "), detail: c.value.split(";")[0] });
    });
  try {
    const u = new URL(entry.url);
    for (const [k, val] of u.searchParams.entries())
      if (val && val.length >= 3 && respBody.includes(val))
        findings.push({ sev: "medium", title: "Reflected parameter: " + k, detail: "Value of '" + k + "' is reflected — test for XSS / injection." });
  } catch (_) {}
  ["server", "x-powered-by", "x-aspnet-version"].forEach((h) => {
    const v = hget(entry.responseHeaders, h);
    if (v) findings.push({ sev: "info", title: "Tech disclosure: " + h, detail: v });
  });
  const patterns = [
    [/-----BEGIN (RSA |EC )?PRIVATE KEY-----/, "Private key in response", "high"],
    [/AKIA[0-9A-Z]{16}/, "Possible AWS access key", "high"],
    [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/, "JWT in response", "info"],
    [/(password|passwd|secret|api[_-]?key)["']?\s*[:=]/i, "Possible secret keyword in body", "low"]
  ];
  patterns.forEach(([re, title, sev]) => { if (re.test(respBody)) findings.push({ sev, title, detail: "Pattern matched in response body." }); });
  if (/(sql syntax|mysql_fetch|ORA-\d{5}|unclosed quotation mark|psql:|SQLite3::|SQLSTATE)/i.test(respBody))
    findings.push({ sev: "high", title: "SQL error string in response", detail: "Possible SQL injection — probe input parameters." });
  if (entry.status >= 500) findings.push({ sev: "low", title: "Server error " + entry.status, detail: "May leak stack traces / internal info." });

  // CORS misconfiguration
  const acao = hget(entry.responseHeaders, "access-control-allow-origin");
  const acac = hget(entry.responseHeaders, "access-control-allow-credentials");
  if (acao === "*" && /true/i.test(acac || ""))
    findings.push({ sev: "high", title: "CORS: wildcard origin with credentials", detail: "ACAO * together with credentials=true is invalid/risky." });
  else if (acao && acao !== "*" && !/^https?:\/\/[^,]+$/i.test(acao) === false) {
    const origin = hget(entry.requestHeaders, "origin");
    if (origin && acao === origin && /true/i.test(acac || ""))
      findings.push({ sev: "medium", title: "CORS: origin reflected with credentials", detail: "ACAO reflects request Origin with credentials — test cross-origin read." });
  }

  // Mixed content
  if (/^https:/i.test(entry.url) && /(?:src|href|action)\s*=\s*["']http:\/\//i.test(respBody))
    findings.push({ sev: "low", title: "Mixed content", detail: "HTTPS page references http:// resources." });

  // CSP weaknesses
  const csp = hget(entry.responseHeaders, "content-security-policy");
  if (csp) {
    if (/unsafe-inline/i.test(csp)) findings.push({ sev: "low", title: "CSP allows unsafe-inline", detail: "script-src/style-src unsafe-inline weakens XSS protection." });
    if (/unsafe-eval/i.test(csp)) findings.push({ sev: "low", title: "CSP allows unsafe-eval", detail: "unsafe-eval permits eval-based execution." });
    if (/(^|\s)script-src[^;]*\*/i.test(csp)) findings.push({ sev: "low", title: "CSP script-src wildcard", detail: "Wildcard source in script-src." });
  }

  // GraphQL introspection
  if (/\/graphql/i.test(entry.url) && /("__schema"|"queryType"|"types":\s*\[)/.test(respBody))
    findings.push({ sev: "medium", title: "GraphQL introspection enabled", detail: "Schema introspection appears enabled — maps the full API." });

  // Open redirect candidate
  try {
    const u = new URL(entry.url);
    for (const [k, v] of u.searchParams.entries()) {
      if (/^(url|next|redirect|return|returnurl|dest|destination|continue|target|goto|r|u)$/i.test(k) && /^https?:\/\//i.test(v))
        findings.push({ sev: "medium", title: "Open-redirect candidate: " + k, detail: "Parameter '" + k + "' takes a full URL — test external redirect." });
    }
  } catch (_) {}
  if ([301, 302, 303, 307, 308].includes(entry.status)) {
    const loc = hget(entry.responseHeaders, "location");
    try { const u = new URL(entry.url); for (const v of u.searchParams.values()) { if (loc && v && loc.includes(v) && /^https?:\/\//i.test(v)) findings.push({ sev: "medium", title: "Reflected redirect Location", detail: "Redirect target derived from a parameter." }); } } catch (_) {}
  }

  // JWTs — decode and check alg
  const jwtMatch = respBody.match(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/);
  const jwtCookie = (entry.requestHeaders || []).map((h) => h.value).join(";").match(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/);
  const jwt = jwtMatch || jwtCookie;
  if (jwt) {
    try {
      const hdr = JSON.parse(atobUrl(jwt[0].split(".")[0]));
      if (/^none$/i.test(hdr.alg || "")) findings.push({ sev: "high", title: "JWT alg:none", detail: "Token header uses alg=none — signature may be bypassable." });
      else findings.push({ sev: "info", title: "JWT detected (alg=" + (hdr.alg || "?") + ")", detail: "Inspect claims/expiry; test signature stripping & key confusion." });
    } catch { findings.push({ sev: "info", title: "JWT-like token present", detail: "Inspect manually." }); }
  }

  // Verb tampering hint
  if (entry.method === "GET" && /["']?(delete|remove|drop|destroy|disable)["']?/i.test(new URL(entry.url, "http://x").pathname))
    findings.push({ sev: "low", title: "State-changing action via GET", detail: "Sensitive verb in a GET path — check CSRF / method enforcement." });

  return findings;
}

function atobUrl(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
}

const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
function topSeverity(findings) {
  return findings.reduce((m, f) => (SEV_RANK[f.sev] > SEV_RANK[m] ? f.sev : m), "info");
}

const truncate = (s, n) => { s = s || ""; return s.length > n ? s.slice(0, n) + "\n…[truncated]" : s; };

function buildRawRequest(entry) {
  let raw = `${entry.method} ${entry.url}\n`;
  (entry.requestHeaders || []).forEach((h) => (raw += `${h.name}: ${h.value}\n`));
  if (entry.requestBody) raw += `\n${truncate(entry.requestBody, 4000)}`;
  return raw;
}
function buildRawResponse(entry) {
  let raw = `HTTP ${entry.status} ${entry.statusText}\n`;
  (entry.responseHeaders || []).forEach((h) => (raw += `${h.name}: ${h.value}\n`));
  raw += `\n${truncate(entry.responseBody, 8000)}`;
  return raw;
}

function buildPrompt(entry, heuristics) {
  const h = heuristics.length ? heuristics.map((f) => `- [${f.sev}] ${f.title}: ${f.detail}`).join("\n") : "(none)";
  return `You are a senior web application penetration tester reviewing one captured HTTP transaction.

Analyze it for security vulnerabilities (XSS, SQL/NoSQL/command injection, IDOR/broken access control, auth & session flaws, CSRF, SSRF, open redirect, insecure deserialization, sensitive data exposure, misconfiguration, insecure headers/cookies).

Respond in markdown:
## Summary
One or two sentences on overall risk.
## Findings
For each: **Title** — Severity (Critical/High/Medium/Low/Info), a short evidence line, and remediation. If none: "No clear vulnerabilities identified."
## Suggested manual tests
Specific payloads/steps to confirm the most promising findings.

Only flag what the evidence supports.

=== HEURISTIC LEADS (may be false positives) ===
${h}

=== REQUEST ===
${buildRawRequest(entry)}

=== RESPONSE ===
${buildRawResponse(entry)}`;
}

// ---- cross-request correlation --------------------------------------------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LONGHEX_RE = /^[0-9a-f]{16,}$/i;
const ID_PARAM_RE = /^(id|uid|user|userid|user_id|account|acct|order|orderid|order_id|pid|product|customer|cust|invoice|doc|docid|file|fileid|key|ref|num|no|seq|record|recordid)$/i;
const SENSITIVE_RE = /(admin|account|user|profile|order|invoice|payment|delete|remove|update|edit|upload|export|download|token|password|reset|api\/|internal|config|setting)/i;

function idLike(v) {
  return /^\d{1,}$/.test(v) || UUID_RE.test(v) || LONGHEX_RE.test(v);
}
function pathPattern(pathname) {
  return pathname.split("/").map((seg) => idLike(seg) ? "{id}" : seg).join("/");
}
function isCredentialed(e) {
  return (e.requestHeaders || []).some((h) => {
    const n = h.name.toLowerCase();
    return n === "authorization" || n === "cookie" || n === "x-api-key" || n === "x-auth-token";
  });
}

function correlate(entries) {
  const eps = new Map(); // method+host+pattern -> agg
  for (const e of entries) {
    let u; try { u = new URL(e.url); } catch { continue; }
    const pat = pathPattern(u.pathname);
    const k = `${e.method} ${u.host}${pat}`;
    if (!eps.has(k)) eps.set(k, {
      method: e.method, host: u.host, pattern: pat, count: 0,
      pathIds: new Set(), idParams: new Set(), credTrue: 0, credFalse: 0,
      statuses: new Set(), sample: e.url
    });
    const a = eps.get(k);
    a.count++;
    u.pathname.split("/").forEach((seg) => { if (idLike(seg)) a.pathIds.add(seg); });
    u.searchParams.forEach((val, key) => { if (ID_PARAM_RE.test(key) || idLike(val)) a.idParams.add(key); });
    if (isCredentialed(e)) a.credTrue++; else a.credFalse++;
    a.statuses.add(e.status);
  }

  const idorCandidates = [];
  const authInconsistent = [];
  const sensitiveNoAuth = [];
  for (const a of eps.values()) {
    const distinctIds = a.pathIds.size;
    if (distinctIds >= 2 || (distinctIds >= 1 && a.idParams.size) || (a.idParams.size && a.credTrue)) {
      idorCandidates.push({
        endpoint: `${a.method} ${a.host}${a.pattern}`,
        distinctIds, idParams: [...a.idParams],
        credentialed: a.credTrue > 0, hits: a.count
      });
    }
    if (a.credTrue > 0 && a.credFalse > 0) {
      authInconsistent.push({ endpoint: `${a.method} ${a.host}${a.pattern}`, withAuth: a.credTrue, withoutAuth: a.credFalse });
    }
    if (a.credTrue === 0 && SENSITIVE_RE.test(a.pattern) && [...a.statuses].some((s) => s && s < 400)) {
      sensitiveNoAuth.push({ endpoint: `${a.method} ${a.host}${a.pattern}`, statuses: [...a.statuses] });
    }
  }

  // aggregate heuristic findings
  const tally = {};
  for (const e of entries) for (const f of heuristicScan(e)) {
    const key = f.sev + "|" + f.title.replace(/:.*/, "");
    tally[key] = (tally[key] || 0) + 1;
  }
  const findingTally = Object.entries(tally)
    .map(([k, n]) => ({ sev: k.split("|")[0], title: k.split("|")[1], count: n }))
    .sort((a, b) => b.count - a.count);

  idorCandidates.sort((a, b) => b.distinctIds - a.distinctIds || b.hits - a.hits);
  return {
    endpointCount: eps.size,
    idorCandidates: idorCandidates.slice(0, 30),
    authInconsistent: authInconsistent.slice(0, 30),
    sensitiveNoAuth: sensitiveNoAuth.slice(0, 30),
    findingTally: findingTally.slice(0, 20)
  };
}

function buildSitePrompt(entries, corr) {
  const seen = new Set(); const lines = [];
  for (const e of entries) {
    let path = e.url; try { const u = new URL(e.url); path = u.host + u.pathname; } catch {}
    const sig = e.method + " " + path;
    if (seen.has(sig)) continue; seen.add(sig);
    let params = ""; try { params = [...new URL(e.url).searchParams.keys()].join(","); } catch {}
    const finds = heuristicScan(e);
    lines.push(`${e.method} ${path} [${e.status}]${params ? " params=" + params : ""}${isCredentialed(e) ? " AUTH" : ""}${finds.length ? " flags=" + finds.length : ""}`);
    if (lines.length >= 150) break;
  }
  const idor = corr.idorCandidates.map((c) => `- ${c.endpoint} | distinct IDs=${c.distinctIds} | idParams=${c.idParams.join(",") || "-"} | credentialed=${c.credentialed}`).join("\n") || "(none detected)";
  const authI = corr.authInconsistent.map((c) => `- ${c.endpoint} | with auth=${c.withAuth} without=${c.withoutAuth}`).join("\n") || "(none detected)";
  const sens = corr.sensitiveNoAuth.map((c) => `- ${c.endpoint} | statuses=${c.statuses.join(",")}`).join("\n") || "(none detected)";
  const tally = corr.findingTally.map((f) => `- [${f.sev}] ${f.title} ×${f.count}`).join("\n") || "(none)";

  return `You are a lead penetration tester planning an engagement. Below is an inventory of captured endpoints plus automatically correlated signals across all requests.

Produce a markdown report:
## Attack surface overview
Characterize the app and tech-stack signals.
## IDOR / broken access control candidates
Assess the correlated identifier endpoints below. Which are most likely IDOR, and how to test (swap IDs across sessions/users)?
## Authentication inconsistencies
Interpret endpoints seen both with and without credentials, and sensitive endpoints with no auth.
## Cross-endpoint issues
Other patterns (info disclosure, session handling, repeated misconfig) seen across endpoints.
## Recommended test plan
Ordered, concrete next steps and payloads.

Only assert what the data supports; mark uncertain items as candidates.

=== CORRELATED: IDOR CANDIDATES (endpoints with object identifiers) ===
${idor}

=== CORRELATED: AUTH INCONSISTENCIES ===
Sometimes-authenticated endpoints:
${authI}
Sensitive endpoints with no credentials observed:
${sens}

=== CORRELATED: HEURISTIC FINDINGS TALLY ===
${tally}

=== ENDPOINT INVENTORY ===
${lines.join("\n")}`;
}

function buildPayloadGenPrompt(category, context) {
  return `You are a web security tester. Generate up to 15 effective test payloads for category "${category}".
Context (the parameter/value being fuzzed and how it appears): ${context}
Return ONLY a JSON array of strings, no commentary, no markdown fences. Tailor payloads to the context; include encoding/bypass variants where useful.`;
}

function buildTriagePrompt(template, results) {
  const rows = results.slice(0, 25).map((r) =>
    `payload=${JSON.stringify(r.payload)} status=${r.status} len=${r.length} time=${r.timeMs}ms${r.reflected ? " REFLECTED" : ""}${r.error ? " ERR:" + r.error : ""}${r.signature ? " SIG:" + r.signature : ""}`).join("\n");
  return `You are reviewing the results of an automated fuzzing (Intruder) run against one parameter.

Request template (§ marks the injection point):
${truncate(template, 1500)}

Results (payload, HTTP status, response length, time, flags):
${rows}

In markdown:
## Verdict
Is there evidence of a vulnerability? Which class?
## Strongest signals
Which payloads/responses stand out and why (length/status/time deltas, reflection, error signatures).
## Next steps
Concrete manual confirmation steps.`;
}

async function getConfig() {
  return new Promise((res) => chrome.storage.local.get(["apiKey", "model", "endpoint", "temperature"], res));
}

async function callDeepSeek(userContent, system = "You are a meticulous web security analyst. Be accurate and concise.") {
  const cfg = await getConfig();
  if (!cfg.apiKey) throw new Error("No API key set. Open 'API settings' and add your DeepSeek key.");
  const endpoint = cfg.endpoint || "https://api.deepseek.com/chat/completions";
  const resp = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + cfg.apiKey },
    body: JSON.stringify({
      model: cfg.model || "deepseek-chat",
      temperature: cfg.temperature != null ? Number(cfg.temperature) : 0.2,
      messages: [{ role: "system", content: system }, { role: "user", content: userContent }]
    })
  });
  if (!resp.ok) throw new Error(`DeepSeek API error ${resp.status}: ${(await resp.text()).slice(0, 300)}`);
  const data = await resp.json();
  return data.choices?.[0]?.message?.content || "(empty response)";
}

const analyzeWithDeepSeek = (entry, h) => callDeepSeek(buildPrompt(entry, h));
const analyzeSite = (entries, corr) => callDeepSeek(buildSitePrompt(entries, corr || correlate(entries)));
const triageIntruder = (template, results) => callDeepSeek(buildTriagePrompt(template, results));

async function generatePayloads(category, context) {
  const txt = await callDeepSeek(buildPayloadGenPrompt(category, context),
    "You output only valid JSON arrays of strings. No prose.");
  const clean = txt.replace(/```json|```/g, "").trim();
  try {
    const arr = JSON.parse(clean);
    if (Array.isArray(arr)) return arr.map(String).slice(0, 25);
  } catch (_) {}
  // fallback: split lines
  return clean.split("\n").map((s) => s.replace(/^[-*\d.\s"]+|"+$/g, "").trim()).filter(Boolean).slice(0, 25);
}

// ---- outbound guard: scope + rate limit + audit ---------------------------

let _lastSend = 0;
async function _rateGate() {
  const { rateMs = 0 } = await new Promise((r) => chrome.storage.local.get("rateMs", r));
  const wait = _lastSend + (Number(rateMs) || 0) - Date.now();
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  _lastSend = Date.now();
}
async function _scopeGuard(url) {
  const { scope = [], enforceScope = true } = await new Promise((r) => chrome.storage.local.get(["scope", "enforceScope"], r));
  if (!enforceScope || !scope.length) return;
  let host; try { host = new URL(url).host; } catch { throw new Error("Invalid URL"); }
  const ok = scope.some((p) => {
    const re = "^" + p.trim().replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$";
    try { return new RegExp(re, "i").test(host); } catch { return false; }
  });
  if (!ok) throw new Error("Blocked: " + host + " is out of scope (disable scope enforcement in Settings to override).");
}

// ---- HTTP sender (used by Repeater, Intruder, Agent; runs in viewer page) ---
async function sendHttp({ url, method, headers, body }) {
  await _scopeGuard(url);
  await _rateGate();
  const h = {};
  (headers || []).forEach(({ name, value }) => {
    if (!/^(host|content-length|connection|origin|referer|cookie)$/i.test(name)) h[name] = value;
  });
  const opts = { method: method || "GET", headers: h, credentials: "include", redirect: "manual" };
  if (body && !/^(GET|HEAD)$/i.test(method)) opts.body = body;
  const t0 = performance.now();
  const resp = await fetch(url, opts);
  const text = await resp.text();
  const respHeaders = [];
  resp.headers.forEach((v, k) => respHeaders.push({ name: k, value: v }));
  try { chrome.runtime.sendMessage({ type: "AUDIT", record: { action: "send", method, url, status: resp.status } }); } catch {}
  return {
    status: resp.status, statusText: resp.statusText,
    timeMs: Math.round(performance.now() - t0),
    length: text.length, responseHeaders: respHeaders,
    responseBody: text.length > 300 * 1024 ? text.slice(0, 300 * 1024) : text
  };
}

// ---- JS / client-side mining (pure) ----------------------------------------

const SECRET_RULES = [
  [/AKIA[0-9A-Z]{16}/g, "AWS access key id", "high"],
  [/(?:aws_secret_access_key|secret[_-]?access[_-]?key)["'\s:=]+([A-Za-z0-9/+=]{40})/gi, "AWS secret key", "high"],
  [/AIza[0-9A-Za-z_\-]{35}/g, "Google API key", "high"],
  [/ghp_[0-9A-Za-z]{36}/g, "GitHub token", "high"],
  [/xox[baprs]-[0-9A-Za-z-]{10,}/g, "Slack token", "high"],
  [/sk_live_[0-9A-Za-z]{24,}/g, "Stripe secret key", "high"],
  [/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, "Private key", "high"],
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, "JWT", "info"],
  [/(?:api[_-]?key|apikey|secret|token|password|passwd|client[_-]?secret)["'\s:=]{1,4}["']?([A-Za-z0-9_\-]{12,})/gi, "Generic secret keyword", "medium"]
];
const SINK_RULES = [
  [/\.innerHTML\s*=/g, "innerHTML assignment"],
  [/\.outerHTML\s*=/g, "outerHTML assignment"],
  [/document\.write\s*\(/g, "document.write"],
  [/\beval\s*\(/g, "eval()"],
  [/new\s+Function\s*\(/g, "new Function()"],
  [/\.insertAdjacentHTML\s*\(/g, "insertAdjacentHTML"],
  [/(?:location|location\.href|location\.assign|location\.replace)\s*=/g, "location assignment"],
  [/\.setAttribute\s*\(\s*['"]on/gi, "inline event via setAttribute"],
  [/addEventListener\s*\(\s*['"]message['"]/g, "postMessage listener (check origin)"],
  [/dangerouslySetInnerHTML/g, "React dangerouslySetInnerHTML"]
];
const ENDPOINT_RE = /["'`](\/[A-Za-z0-9_\-./]{2,}(?:\?[^"'`]*)?|https?:\/\/[A-Za-z0-9_\-.:]+\/[A-Za-z0-9_\-./?=&%]*)["'`]/g;

function mineJs(source) {
  const secrets = [];
  for (const [re, name, sev] of SECRET_RULES) {
    let m; const seen = new Set();
    while ((m = re.exec(source))) { const v = m[0].slice(0, 60); if (!seen.has(v)) { seen.add(v); secrets.push({ type: name, sev, sample: v }); } if (seen.size > 20) break; }
  }
  const sinks = [];
  for (const [re, name] of SINK_RULES) { const c = (source.match(re) || []).length; if (c) sinks.push({ type: name, count: c }); }
  const endpoints = new Set(); let m2;
  while ((m2 = ENDPOINT_RE.exec(source))) {
    const e = m2[1];
    if (/\.(png|jpg|jpeg|gif|svg|css|woff2?|ttf|ico|map)$/i.test(e)) continue;
    if (e.length < 3) continue;
    endpoints.add(e); if (endpoints.size > 400) break;
  }
  return { secrets, sinks, endpoints: [...endpoints].sort() };
}

// ---- AI agent loop (constrained) -------------------------------------------
// onStep(step) renders progress. confirmFn(action) -> boolean for state-changing verbs.
async function runAgent(seedEntry, { maxSteps = 6, onStep, confirmFn } = {}) {
  const system = `You are an authorized web penetration testing agent. You may probe ONLY the target of the seed request. ` +
    `Each turn, respond with ONE JSON object and nothing else:
{"thought":"...","action":"request"|"finish","request":{"method":"GET","url":"...","headers":[{"name":"","value":""}],"body":""},"finding":"...optional..."}
Prefer safe, idempotent requests (GET/HEAD/OPTIONS). Use the captured request as a starting point. When you have a conclusion, use action:"finish" with a markdown summary in "finding". Do not exceed the scope of the seed host.`;
  const history = [
    { role: "system", content: system },
    { role: "user", content: `Seed request:\n${buildRawRequest(seedEntry)}\n\nSeed response (truncated):\n${buildRawResponse(seedEntry)}\n\nBegin.` }
  ];
  const transcript = [];
  for (let i = 0; i < maxSteps; i++) {
    const raw = await callDeepSeek(history.map((m) => m.content).join("\n\n"), system);
    let act; try { act = JSON.parse(raw.replace(/```json|```/g, "").trim()); } catch { transcript.push({ type: "error", text: "Model returned non-JSON: " + raw.slice(0, 200) }); break; }
    history.push({ role: "assistant", content: JSON.stringify(act) });
    if (act.action === "finish" || !act.request) { transcript.push({ type: "finish", text: act.finding || act.thought || "(done)" }); onStep && onStep(transcript); break; }
    const req = act.request;
    const stateChanging = !/^(GET|HEAD|OPTIONS)$/i.test(req.method || "GET");
    if (stateChanging && confirmFn && !(await confirmFn(req))) { transcript.push({ type: "skipped", text: "User declined: " + req.method + " " + req.url }); history.push({ role: "user", content: "User declined that state-changing request. Continue with read-only tests or finish." }); onStep && onStep(transcript); continue; }
    let result;
    try { result = await sendHttp({ url: req.url, method: req.method, headers: req.headers, body: req.body }); }
    catch (e) { transcript.push({ type: "blocked", text: act.thought, req, error: e.message }); history.push({ role: "user", content: "Request error: " + e.message }); onStep && onStep(transcript); continue; }
    transcript.push({ type: "step", thought: act.thought, req, status: result.status, length: result.length });
    onStep && onStep(transcript);
    history.push({ role: "user", content: `Response: HTTP ${result.status} (${result.length} bytes)\n${result.responseBody.slice(0, 2500)}` });
  }
  return transcript;
}

// ---- report generation -----------------------------------------------------
function buildReportPrompt(corr, aiSummaries) {
  const tally = corr.findingTally.map((f) => `- [${f.sev}] ${f.title} ×${f.count}`).join("\n");
  return `Write a concise penetration-test findings report in markdown from the data below.
Sections: ## Executive summary, ## Findings (each with title, severity, affected endpoint(s), evidence, remediation), ## Recommendations.
Severities: Critical/High/Medium/Low/Info. Only include supported findings.

Heuristic tally:
${tally}

IDOR candidates: ${corr.idorCandidates.map((c) => c.endpoint).join("; ") || "none"}
Auth inconsistencies: ${corr.authInconsistent.map((c) => c.endpoint).join("; ") || "none"}
Sensitive no-auth: ${corr.sensitiveNoAuth.map((c) => c.endpoint).join("; ") || "none"}

Per-request AI notes:
${(aiSummaries || []).join("\n---\n").slice(0, 6000) || "(none)"}`;
}
const generateReport = (corr, aiSummaries) => callDeepSeek(buildReportPrompt(corr, aiSummaries), "You are a penetration tester writing a client report. Be precise.");

window.Analyzer = {
  heuristicScan, topSeverity, buildRawRequest, buildRawResponse,
  analyzeWithDeepSeek, analyzeSite, triageIntruder, generatePayloads, sendHttp,
  correlate, mineJs, runAgent, generateReport
};
