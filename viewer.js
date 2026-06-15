// viewer.js (Pro)
const $ = (id) => document.getElementById(id);
const send = (msg) => new Promise((res) => chrome.runtime.sendMessage(msg, res));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));

let entries = [];
let current = null;
const aiCache = {};        // entry.id -> rendered AI html
const aiTextCache = {};    // entry.id -> raw AI text (for report)
const findingsCache = {};  // entry.id -> findings array
let intrResults = [];
let intrTemplate = "";
let stopFlag = false;
let running = false;

// ---- utils -----------------------------------------------------------------

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function statusClass(s) { return s ? "st-" + String(s)[0] : ""; }

function findingsFor(e) {
  if (!findingsCache[e.id]) findingsCache[e.id] = Analyzer.heuristicScan(e);
  return findingsCache[e.id];
}

function miniMarkdown(md) {
  const lines = escapeHtml(md).split("\n");
  let html = "", inList = false;
  const inline = (s) => s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/`(.+?)`/g, "<code>$1</code>");
  for (let ln of lines) {
    if (/^##\s+/.test(ln)) { if (inList) { html += "</ul>"; inList = false; } html += `<h2>${inline(ln.replace(/^##\s+/, ""))}</h2>`; }
    else if (/^#\s+/.test(ln)) { if (inList) { html += "</ul>"; inList = false; } html += `<h2>${inline(ln.replace(/^#\s+/, ""))}</h2>`; }
    else if (/^\s*[-*]\s+/.test(ln)) { if (!inList) { html += "<ul>"; inList = true; } html += `<li>${inline(ln.replace(/^\s*[-*]\s+/, ""))}</li>`; }
    else { if (inList) { html += "</ul>"; inList = false; } if (ln.trim()) html += `<p>${inline(ln)}</p>`; }
  }
  if (inList) html += "</ul>";
  return html;
}

// ---- list ------------------------------------------------------------------

function renderList(filter = "") {
  const f = filter.toLowerCase();
  const rows = $("rows");
  rows.innerHTML = "";
  const shown = entries.slice().reverse().filter((e) => !f ||
    (e.url || "").toLowerCase().includes(f) ||
    (e.method || "").toLowerCase().includes(f) ||
    String(e.status || "").includes(f));
  $("listEmpty").style.display = shown.length ? "none" : "block";

  for (const e of shown) {
    const finds = findingsFor(e);
    const sev = finds.length ? Analyzer.topSeverity(finds) : "none";
    const tr = document.createElement("tr");
    if (current && current.id === e.id) tr.className = "sel";
    let path = e.url; try { const u = new URL(e.url); path = u.pathname + u.search; } catch (_) {}
    tr.innerHTML =
      `<td><span class="dotsev s-${sev}" title="${finds.length} heuristic finding(s)"></span></td>` +
      `<td class="method m-${e.method}">${e.method}</td>` +
      `<td title="${escapeHtml(e.url)}">${escapeHtml(path)}</td>` +
      `<td class="${statusClass(e.status)}">${e.status ?? "-"}</td>` +
      `<td>${escapeHtml(e.resourceType || "")}</td>`;
    tr.addEventListener("click", () => select(e));
    rows.appendChild(tr);
  }
}

function highlightReflections(e) {
  let body = escapeHtml(Analyzer.buildRawResponse(e));
  try {
    const u = new URL(e.url);
    for (const val of u.searchParams.values()) {
      if (val && val.length >= 3) {
        const safe = escapeHtml(val).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        body = body.replace(new RegExp(safe, "g"), (m) => `<mark>${m}</mark>`);
      }
    }
  } catch (_) {}
  return body;
}

function select(e) {
  current = e;
  $("curUrl").textContent = `${e.method} ${e.url}`;
  $("reqRaw").textContent = Analyzer.buildRawRequest(e);
  $("respRaw").innerHTML = highlightReflections(e);

  const finds = findingsFor(e);
  const hl = $("heurList"); hl.innerHTML = "";
  if (!finds.length) {
    hl.innerHTML = '<div class="empty">No heuristic leads. Try AI Analysis for a deeper review.</div>';
    $("heurCount").style.display = "none";
  } else {
    finds.forEach((fd) => {
      const div = document.createElement("div"); div.className = "finding";
      div.innerHTML = `<div class="t"><span class="sev ${fd.sev}">${fd.sev}</span>${escapeHtml(fd.title)}</div><div class="d">${escapeHtml(fd.detail)}</div>`;
      hl.appendChild(div);
    });
    $("heurCount").textContent = finds.length; $("heurCount").style.display = "inline-block";
  }

  $("aiResult").innerHTML = aiCache[e.id] || "";

  // seed intruder + repeater
  const raw = Analyzer.buildRawRequest(e);
  $("intrTpl").value = raw;
  $("repInput").value = raw;
  $("repResult").innerHTML = "";
  $("intrResults").innerHTML = ""; $("triageOut").innerHTML = "";
  $("triage").disabled = true;

  renderList($("search").value);
}

// ---- raw parsing -----------------------------------------------------------

function parseRaw(raw) {
  const parts = raw.split(/\n\r?\n/);
  const head = parts[0].split("\n");
  const body = parts.slice(1).join("\n\n");
  const firstLine = head[0].trim();
  const sp = firstLine.indexOf(" ");
  const method = sp === -1 ? firstLine : firstLine.slice(0, sp);
  const url = sp === -1 ? "" : firstLine.slice(sp + 1).trim();
  const headers = head.slice(1).map((h) => {
    const i = h.indexOf(":");
    return i > -1 ? { name: h.slice(0, i).trim(), value: h.slice(i + 1).trim() } : null;
  }).filter(Boolean);
  return { method, url, headers, body: body.trim() };
}

// ---- AI analysis (single) --------------------------------------------------

$("analyze").addEventListener("click", async () => {
  if (!current) return;
  const out = $("aiResult");
  out.innerHTML = '<span class="spinner"></span> Analyzing with DeepSeek…';
  try {
    const text = await Analyzer.analyzeWithDeepSeek(current, findingsFor(current));
    const html = `<div class="ai-out">${miniMarkdown(text)}</div>`;
    aiCache[current.id] = html; aiTextCache[current.id] = text; out.innerHTML = html;
  } catch (err) {
    out.innerHTML = errBox("Analysis failed", err.message);
  }
});

function errBox(title, msg) {
  return `<div class="finding"><div class="t"><span class="sev error">error</span>${escapeHtml(title)}</div><div class="d">${escapeHtml(msg)}</div></div>`;
}

// ---- Repeater --------------------------------------------------------------

$("sendRep").addEventListener("click", async () => {
  const out = $("repResult");
  out.innerHTML = '<span class="spinner"></span> Sending…';
  try {
    const r = await Analyzer.sendHttp(parseRaw($("repInput").value));
    let raw = `HTTP ${r.status} ${r.statusText}  (${r.timeMs} ms, ${r.length} bytes)\n`;
    r.responseHeaders.forEach((h) => (raw += `${h.name}: ${h.value}\n`));
    raw += `\n${r.responseBody}`;
    out.innerHTML = `<pre>${escapeHtml(raw)}</pre>`;
  } catch (err) { out.innerHTML = errBox("Send failed", err.message); }
});

// ---- Intruder --------------------------------------------------------------

function populatePayloadCats() {
  const sel = $("payloadCat");
  sel.innerHTML = "";
  for (const [k, v] of Object.entries(window.PAYLOADS)) {
    const o = document.createElement("option"); o.value = k; o.textContent = v.label; sel.appendChild(o);
  }
}

$("seedTpl").addEventListener("click", () => { if (current) $("intrTpl").value = Analyzer.buildRawRequest(current); });

$("markSel").addEventListener("click", () => {
  const ta = $("intrTpl");
  const s = ta.selectionStart, e = ta.selectionEnd;
  if (s === e) { alert("Select the text to mark as an insertion point first."); return; }
  const v = ta.value;
  ta.value = v.slice(0, s) + "§" + v.slice(s, e) + "§" + v.slice(e);
});

$("loadBuiltin").addEventListener("click", () => {
  const cat = $("payloadCat").value;
  $("payloadList").value = window.PAYLOADS[cat].list.join("\n");
});

$("genAi").addEventListener("click", async () => {
  const cat = $("payloadCat").value;
  const btn = $("genAi"); const old = btn.textContent;
  btn.disabled = true; btn.textContent = "Generating…";
  try {
    const tpl = $("intrTpl").value;
    const m = tpl.match(/§([\s\S]*?)§/);
    const ctx = `category=${cat}; injection point original value=${m ? m[1] : "(none marked)"}; request line=${tpl.split("\n")[0]}`;
    const list = await Analyzer.generatePayloads(window.PAYLOADS[cat].label, ctx);
    $("payloadList").value = list.join("\n");
  } catch (err) {
    alert("Payload generation failed: " + err.message);
  } finally { btn.disabled = false; btn.textContent = old; }
});

function flagResult(i, payload, r, baseline, grep) {
  const body = r.responseBody || "";
  const reflected = payload.length >= 3 && body.includes(payload);
  const sig = /(sql syntax|mysql_fetch|ORA-\d{5}|unclosed quotation|SQLSTATE|Traceback|Warning:|Fatal error|root:.*:0:0:)/i.exec(body);
  const grepHit = grep && body.includes(grep);
  let lenDelta = baseline ? Math.abs(r.length - baseline.length) : 0;
  const lenAnomaly = baseline && lenDelta > Math.max(50, baseline.length * 0.05);
  const statusAnomaly = baseline && r.status !== baseline.status;
  const timeSpike = baseline && r.timeMs > baseline.timeMs + 2500;
  const flags = [];
  if (statusAnomaly) flags.push("status\u0394");
  if (lenAnomaly) flags.push("len\u0394" + lenDelta);
  if (reflected) flags.push("reflected");
  if (sig) flags.push("sig");
  if (grepHit) flags.push("grep");
  if (timeSpike) flags.push("slow");
  return {
    i, payload, status: r.status, length: r.length, timeMs: r.timeMs,
    reflected, signature: sig ? sig[0].slice(0, 30) : "", flags,
    hit: flags.length > 0, snippet: body.slice(0, 6000),
    respHeaders: r.responseHeaders
  };
}

function renderIntrResults(total) {
  const done = intrResults.filter(Boolean).length;
  $("intrProgress").textContent = total ? `${done}/${total}` : "";
  const filled = intrResults.filter(Boolean).sort((a, b) => a.i - b.i);
  let html = `<table class="restab"><thead><tr><th>#</th><th>Payload</th><th>Status</th><th>Length</th><th>Time</th><th>Flags</th></tr></thead><tbody>`;
  filled.forEach((r) => {
    if (r.error) {
      html += `<tr><td>${r.i + 1}</td><td>${escapeHtml(r.payload).slice(0, 60)}</td><td colspan="4" style="color:#ff8080">err: ${escapeHtml(r.error)}</td></tr>`;
      return;
    }
    const flags = r.flags.map((f) => `<span class="flag">${escapeHtml(f)}</span>`).join("");
    html += `<tr class="${r.hit ? "hit" : ""}" data-i="${r.i}"><td>${r.i + 1}</td><td title="${escapeHtml(r.payload)}">${escapeHtml(r.payload).slice(0, 60)}</td><td class="${statusClass(r.status)}">${r.status}</td><td>${r.length}</td><td>${r.timeMs}ms</td><td>${flags}</td></tr>`;
  });
  html += "</tbody></table>";
  $("intrResults").innerHTML = html;
  $("intrResults").querySelectorAll("tr[data-i]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const r = intrResults.find((x) => x && x.i === Number(tr.dataset.i));
      if (!r) return;
      let raw = `HTTP ${r.status}  (${r.timeMs} ms, ${r.length} bytes)\nPayload: ${r.payload}\n\n`;
      (r.respHeaders || []).forEach((h) => (raw += `${h.name}: ${h.value}\n`));
      raw += "\n" + r.snippet;
      openModal("Intruder response", `<pre>${escapeHtml(raw)}</pre>`);
    });
  });
}

async function sendTemplate(text) {
  return Analyzer.sendHttp(parseRaw(text));
}

$("runIntr").addEventListener("click", async () => {
  if (running) return;
  const template = $("intrTpl").value;
  intrTemplate = template;
  if (!/§[\s\S]*?§/.test(template)) { alert("Mark at least one insertion point with § §."); return; }
  let payloads = $("payloadList").value.split("\n").map((s) => s).filter((s) => s.trim().length);
  if (!payloads.length) { alert("Add payloads (Load built-in or Generate with AI)."); return; }
  if (payloads.length > 300) { if (!confirm(payloads.length + " payloads — that's a lot of live requests. Continue?")) return; payloads = payloads.slice(0, 300); }

  const grep = $("grep").value;
  const delay = clamp(parseInt($("delay").value) || 0, 0, 10000);
  const conc = clamp(parseInt($("conc").value) || 1, 1, 10);

  running = true; stopFlag = false;
  $("runIntr").disabled = true; $("stopIntr").disabled = false; $("triage").disabled = true;
  intrResults = new Array(payloads.length).fill(null);

  const { oob = "" } = await new Promise((r) => chrome.storage.local.get("oob", r));
  if (oob) payloads = payloads.map((p) => p.split("{{OOB}}").join(oob));

  let baseline = null;
  try {
    baseline = await sendTemplate(template.replace(/§([\s\S]*?)§/g, "$1"));
  } catch (_) { /* baseline optional */ }

  let next = 0;
  async function worker() {
    while (!stopFlag) {
      const i = next++;
      if (i >= payloads.length) break;
      const p = payloads[i];
      const attack = template.replace(/§[\s\S]*?§/g, () => p);
      try {
        const r = await sendTemplate(attack);
        intrResults[i] = flagResult(i, p, r, baseline, grep);
      } catch (e) {
        intrResults[i] = { i, payload: p, error: String(e.message || e).slice(0, 80) };
      }
      renderIntrResults(payloads.length);
      if (delay) await sleep(delay);
    }
  }
  await Promise.all(Array.from({ length: conc }, worker));

  running = false;
  $("runIntr").disabled = false; $("stopIntr").disabled = true;
  $("triage").disabled = false;
  $("intrProgress").textContent += stopFlag ? " (stopped)" : " (done)";
});

$("stopIntr").addEventListener("click", () => { stopFlag = true; });

$("triage").addEventListener("click", async () => {
  const out = $("triageOut");
  out.innerHTML = '<span class="spinner"></span> Triaging results with DeepSeek…';
  try {
    const text = await Analyzer.triageIntruder(intrTemplate, intrResults.filter(Boolean));
    out.innerHTML = `<div class="ai-out">${miniMarkdown(text)}</div>`;
  } catch (err) { out.innerHTML = errBox("Triage failed", err.message); }
});

// ---- Site analysis ---------------------------------------------------------

function openModal(title, html) {
  $("modalTitle").textContent = title;
  $("modalBody").innerHTML = html;
  $("modal").classList.add("open");
}
$("modalClose").addEventListener("click", () => $("modal").classList.remove("open"));
$("modal").addEventListener("click", (e) => { if (e.target.id === "modal") $("modal").classList.remove("open"); });

function renderCorrelation(c) {
  const sev = (s) => `<span class="sev ${s}">${s}</span>`;
  const list = (arr, fn) => arr.length ? "<ul>" + arr.map(fn).join("") + "</ul>" : '<p class="url">None detected.</p>';
  return `<div class="ai-out">
    <h2>Local correlation (no AI)</h2>
    <p class="url">${c.endpointCount} distinct endpoints across captured traffic.</p>
    <h2>IDOR / object-reference candidates</h2>
    ${list(c.idorCandidates, (x) => `<li><code>${escapeHtml(x.endpoint)}</code> — ${x.distinctIds} distinct ID(s)${x.idParams.length ? ", params: " + escapeHtml(x.idParams.join(", ")) : ""}${x.credentialed ? ", credentialed" : ", no creds seen"}</li>`)}
    <h2>Auth inconsistencies</h2>
    ${list(c.authInconsistent, (x) => `<li><code>${escapeHtml(x.endpoint)}</code> — seen ${x.withAuth}× with creds, ${x.withoutAuth}× without</li>`)}
    <h2>Sensitive endpoints with no credentials</h2>
    ${list(c.sensitiveNoAuth, (x) => `<li><code>${escapeHtml(x.endpoint)}</code> — statuses ${escapeHtml(x.statuses.join(", "))}</li>`)}
    <h2>Heuristic findings tally</h2>
    ${list(c.findingTally, (f) => `<li>${sev(f.sev)} ${escapeHtml(f.title)} ×${f.count}</li>`)}
  </div>`;
}

$("siteAnalyze").addEventListener("click", async () => {
  if (!entries.length) { alert("No captured traffic to analyze."); return; }
  const corr = Analyzer.correlate(entries);
  openModal("Site analysis",
    renderCorrelation(corr) +
    '<div id="siteAi" style="margin-top:14px"><span class="spinner"></span> Correlating with DeepSeek…</div>');
  try {
    const text = await Analyzer.analyzeSite(entries, corr);
    const el = document.getElementById("siteAi");
    if (el) el.innerHTML = `<div class="ai-out"><h2 style="margin-top:0">AI correlation report</h2>${miniMarkdown(text)}</div>`;
  } catch (err) {
    const el = document.getElementById("siteAi");
    if (el) el.innerHTML = errBox("AI report failed (local correlation above still applies)", err.message);
  }
});

// ---- HAR export / import ---------------------------------------------------

$("exportHar").addEventListener("click", () => {
  const har = {
    log: {
      version: "1.2",
      creator: { name: "AI Intruder Pro", version: "2.0.0" },
      entries: entries.map((e) => ({
        startedDateTime: new Date(e.ts || Date.now()).toISOString(),
        time: 0,
        request: {
          method: e.method, url: e.url, httpVersion: "HTTP/1.1",
          headers: e.requestHeaders || [], queryString: [], cookies: [],
          headersSize: -1, bodySize: (e.requestBody || "").length,
          postData: e.requestBody ? { mimeType: "application/octet-stream", text: e.requestBody } : undefined
        },
        response: {
          status: e.status || 0, statusText: e.statusText || "", httpVersion: "HTTP/1.1",
          headers: e.responseHeaders || [], cookies: [],
          content: { size: (e.responseBody || "").length, mimeType: e.mimeType || "", text: e.responseBody || "" },
          redirectURL: "", headersSize: -1, bodySize: (e.responseBody || "").length
        },
        cache: {}, timings: { send: 0, wait: 0, receive: 0 }
      }))
    }
  };
  const blob = new Blob([JSON.stringify(har, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "ai-intruder-" + Date.now() + ".har";
  a.click();
  URL.revokeObjectURL(a.href);
});

$("importHar").addEventListener("click", () => $("harFile").click());
$("harFile").addEventListener("change", async (ev) => {
  const file = ev.target.files[0]; if (!file) return;
  try {
    const har = JSON.parse(await file.text());
    const list = (har.log?.entries || []).map((h) => ({
      id: crypto.randomUUID(), ts: Date.parse(h.startedDateTime) || Date.now(),
      url: h.request?.url, method: h.request?.method || "GET",
      requestHeaders: h.request?.headers || [], requestBody: h.request?.postData?.text || "",
      resourceType: "har", status: h.response?.status ?? null, statusText: h.response?.statusText || "",
      responseHeaders: h.response?.headers || [], mimeType: h.response?.content?.mimeType || "",
      responseBody: h.response?.content?.text || "", bodyTruncated: false
    })).filter((e) => e.url);
    if (!list.length) { alert("No entries found in HAR."); return; }
    const r = await send({ type: "ADD_ENTRIES", entries: list });
    alert("Imported " + list.length + " requests. Total: " + r.count);
    load();
  } catch (err) { alert("HAR import failed: " + err.message); }
  ev.target.value = "";
});

// ---- copy buttons ----------------------------------------------------------

$("copyReq").addEventListener("click", () => navigator.clipboard.writeText($("reqRaw").textContent));
$("copyResp").addEventListener("click", () => current && navigator.clipboard.writeText(Analyzer.buildRawResponse(current)));

// ---- tabs ------------------------------------------------------------------

document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".pane").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $("pane-" + t.dataset.pane).classList.add("active");
  });
});

// ---- toolbar ---------------------------------------------------------------

$("search").addEventListener("input", (e) => renderList(e.target.value));
$("refresh").addEventListener("click", load);
$("theme").addEventListener("click", () => {
  const next = (window.__currentTheme && window.__currentTheme() === "light") ? "dark" : "light";
  if (window.__setTheme) window.__setTheme(next);
});
$("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("clear").addEventListener("click", async () => {
  if (!confirm("Delete all captured requests?")) return;
  await send({ type: "CLEAR_ENTRIES" });
  current = null; entries = [];
  $("curUrl").textContent = "Select a request";
  $("reqRaw").textContent = ""; $("respRaw").textContent = "";
  for (const k in findingsCache) delete findingsCache[k];
  load();
});

async function load() {
  const r = await send({ type: "GET_ENTRIES" });
  const prevIds = new Set(entries.map((e) => e.id));
  entries = r.entries || [];
  // keep findings cache for known ids; new ones computed lazily
  renderList($("search").value);
}

populatePayloadCats();
load();
setInterval(() => { if (!running) load(); }, 4000);

// =====================================================================
// v3 features: intercept, rules, scan, sessions, comparer, encoder,
// report, agent
// =====================================================================

function downloadText(name, text, mime) {
  const blob = new Blob([text], { type: mime || "text/plain" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; a.click();
  URL.revokeObjectURL(a.href);
}
function rawToObj(raw) { return parseRaw(raw); }

// ---- Sessions (multi-session IDOR) ----
async function getSessions() { return (await new Promise((r) => chrome.storage.local.get("sessions", r))).sessions || []; }
async function setSessions(s) { await new Promise((r) => chrome.storage.local.set({ sessions: s }, r)); }

async function loadSessionSelect() {
  const sel = $("repSession"); if (!sel) return;
  const sessions = await getSessions();
  sel.innerHTML = '<option value="">(current browser session)</option>' +
    sessions.map((s) => `<option value="${s.id}">${escapeHtml(s.name)}</option>`).join("");
}
function applySessionToRaw(raw, session) {
  const o = parseRaw(raw);
  o.headers = o.headers.filter((h) => !/^(cookie|authorization)$/i.test(h.name));
  if (session.cookie) o.headers.push({ name: "Cookie", value: session.cookie });
  if (session.auth) o.headers.push({ name: "Authorization", value: session.auth });
  let s = `${o.method} ${o.url}\n` + o.headers.map((h) => `${h.name}: ${h.value}`).join("\n");
  if (o.body) s += `\n\n${o.body}`;
  return s;
}
$("applySession").addEventListener("click", async () => {
  const id = $("repSession").value; if (!id) return;
  const s = (await getSessions()).find((x) => x.id === id); if (!s) return;
  $("repInput").value = applySessionToRaw($("repInput").value, s);
});

$("sessionsBtn").addEventListener("click", async () => {
  const sessions = await getSessions();
  const rows = sessions.map((s) => `<tr><td>${escapeHtml(s.name)}</td><td class="url">${escapeHtml((s.cookie || "").slice(0, 40))}</td><td><button class="btn-g btn-sm" data-del="${s.id}">delete</button> <button class="btn-g btn-sm" data-cmp="${s.id}">IDOR compare current</button></td></tr>`).join("");
  openModal("Sessions / identities", `
    <p class="url">Save identities (different users) to swap into requests for IDOR / access-control testing.</p>
    <table class="restab"><thead><tr><th>Name</th><th>Cookie</th><th></th></tr></thead><tbody id="sessRows">${rows || '<tr><td colspan="3" class="url">No sessions yet.</td></tr>'}</tbody></table>
    <div class="ctl" style="margin-top:12px">
      <input id="sName" placeholder="name (e.g. userA)" style="background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:6px">
    </div>
    <textarea id="sCookie" placeholder="Cookie header value" style="min-height:50px"></textarea>
    <textarea id="sAuth" placeholder="Authorization header value (optional)" style="min-height:40px;margin-top:6px"></textarea>
    <div style="margin-top:8px"><button class="btn-o btn-sm" id="sAdd">Add session</button></div>
  `);
  $("sAdd").addEventListener("click", async () => {
    const name = $("sName").value.trim(); if (!name) return;
    const list = await getSessions();
    list.push({ id: crypto.randomUUID(), name, cookie: $("sCookie").value.trim(), auth: $("sAuth").value.trim() });
    await setSessions(list); loadSessionSelect(); $("sessionsBtn").click();
  });
  document.querySelectorAll("#sessRows [data-del]").forEach((b) => b.addEventListener("click", async () => {
    await setSessions((await getSessions()).filter((x) => x.id !== b.dataset.del)); loadSessionSelect(); $("sessionsBtn").click();
  }));
  document.querySelectorAll("#sessRows [data-cmp]").forEach((b) => b.addEventListener("click", async () => {
    if (!current) { alert("Select a request first."); return; }
    const s = (await getSessions()).find((x) => x.id === b.dataset.cmp);
    await runSessionCompare(current, s);
  }));
});

async function runSessionCompare(entry, session) {
  openModal("IDOR / session compare", '<span class="spinner"></span> Sending with both identities…');
  const baseRaw = Analyzer.buildRawRequest(entry);
  const sessRaw = applySessionToRaw(baseRaw, session);
  try {
    const [a, b] = await Promise.all([Analyzer.sendHttp(parseRaw(baseRaw)), Analyzer.sendHttp(parseRaw(sessRaw))]);
    const verdict = (a.status === b.status && Math.abs(a.length - b.length) < Math.max(30, a.length * 0.02))
      ? '<span class="sev high">possible IDOR</span> Both identities got near-identical responses — the resource may not be access-controlled.'
      : '<span class="sev info">differs</span> Responses differ — access control may be working (or the object differs).';
    openModal("IDOR / session compare", `
      <div class="ai-out"><p>${verdict}</p>
      <p class="url">Current session: HTTP ${a.status}, ${a.length} bytes — ${session.name}: HTTP ${b.status}, ${b.length} bytes.</p></div>
      <h3 style="font-size:13px">Response diff (current vs ${escapeHtml(session.name)})</h3>
      <div id="cmpDiff" style="font-family:ui-monospace,monospace;font-size:12px"></div>`);
    renderDiffInto("cmpDiff", a.responseBody.slice(0, 8000), b.responseBody.slice(0, 8000));
  } catch (err) { openModal("IDOR / session compare", errBox("Compare failed", err.message)); }
}

// ---- Match/Replace rules ----
async function getRules() { return (await new Promise((r) => chrome.storage.local.get("rules", r))).rules || []; }
async function setRules(rules) { await new Promise((r) => chrome.storage.local.set({ rules }, r)); chrome.runtime.sendMessage({ type: "RELOAD_FILTERS" }); }

$("rulesBtn").addEventListener("click", async () => {
  const rules = await getRules();
  const rows = rules.map((r) => `<tr>
    <td><input type="checkbox" data-en="${r.id}" ${r.enabled ? "checked" : ""}></td>
    <td>${escapeHtml(r.name || "")}</td><td>${r.phase}/${r.part}</td>
    <td class="url">${escapeHtml(r.find).slice(0, 24)} → ${escapeHtml(r.replace || "").slice(0, 24)}</td>
    <td><button class="btn-g btn-sm" data-del="${r.id}">delete</button></td></tr>`).join("");
  openModal("Match &amp; replace rules", `
    <p class="url">Auto-modify live traffic. Enabling any rule turns on Fetch interception while capturing.</p>
    <table class="restab"><thead><tr><th>On</th><th>Name</th><th>Phase/Part</th><th>Find → Replace</th><th></th></tr></thead>
    <tbody id="ruleRows">${rows || '<tr><td colspan="5" class="url">No rules.</td></tr>'}</tbody></table>
    <div class="ctl" style="margin-top:12px;gap:8px">
      <input id="rName" placeholder="name" style="background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:6px">
      <select id="rPhase"><option value="request">request</option><option value="response">response</option></select>
      <select id="rPart"><option value="header">header</option><option value="url">url</option><option value="body">body</option></select>
      <label><input type="checkbox" id="rRegex"> regex</label>
    </div>
    <div class="ctl"><input id="rFind" placeholder="find" style="flex:1;background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:6px">
    <input id="rRep" placeholder="replace" style="flex:1;background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:6px"></div>
    <div style="margin-top:8px"><button class="btn-o btn-sm" id="rAdd">Add rule</button></div>`);
  $("rAdd").addEventListener("click", async () => {
    const find = $("rFind").value; if (!find) return;
    const list = await getRules();
    list.push({ id: crypto.randomUUID(), enabled: true, name: $("rName").value || "rule", phase: $("rPhase").value, part: $("rPart").value, find, replace: $("rRep").value, isRegex: $("rRegex").checked });
    await setRules(list); $("rulesBtn").click();
  });
  document.querySelectorAll("#ruleRows [data-del]").forEach((b) => b.addEventListener("click", async () => { await setRules((await getRules()).filter((x) => x.id !== b.dataset.del)); $("rulesBtn").click(); }));
  document.querySelectorAll("#ruleRows [data-en]").forEach((c) => c.addEventListener("change", async () => { const list = await getRules(); const r = list.find((x) => x.id === c.dataset.en); if (r) r.enabled = c.checked; await setRules(list); }));
});

// ---- Manual intercept (opens dedicated window) ----
async function openInterceptWindow() {
  const url = chrome.runtime.getURL("intercept.html");
  const tabs = await chrome.tabs.query({ url });
  if (tabs.length) { try { await chrome.windows.update(tabs[0].windowId, { focused: true }); return; } catch {} }
  chrome.windows.create({ url, type: "popup", width: 860, height: 660 });
}
$("interceptBtn").addEventListener("click", async () => {
  const st = await send({ type: "GET_STATE" });
  if (!st.manualIntercept) await send({ type: "SET_INTERCEPT", value: true });
  openInterceptWindow();
});

// ---- Client-side / JS scan ----
$("scanBtn").addEventListener("click", async () => {
  openModal("Client-side scan", '<span class="spinner"></span> Scanning active page & mining scripts…');
  const at = await send({ type: "ACTIVE_TAB" });
  const r = await send({ type: "SCAN_PAGE", tabId: at.tabId });
  if (!r.ok) { $("modalBody").innerHTML = errBox("Scan failed", r.error + " (open the target page in the active tab first)"); return; }
  const scan = r.result;
  let sources = scan.inline || "";
  // fetch external scripts (best-effort; same host perms apply)
  for (const u of (scan.scriptUrls || []).slice(0, 40)) {
    try { const resp = await fetch(u); sources += "\n\n/* " + u + " */\n" + (await resp.text()); } catch {}
  }
  const mined = Analyzer.mineJs(sources);
  const stKeys = Object.keys(scan.localStorage || {}).concat(Object.keys(scan.sessionStorage || {}));
  const secretsHtml = mined.secrets.length ? "<ul>" + mined.secrets.map((s) => `<li><span class="sev ${s.sev}">${s.sev}</span>${escapeHtml(s.type)}: <code>${escapeHtml(s.sample)}</code></li>`).join("") + "</ul>" : '<p class="url">None found.</p>';
  const sinksHtml = mined.sinks.length ? "<ul>" + mined.sinks.map((s) => `<li>${escapeHtml(s.type)} ×${s.count}</li>`).join("") + "</ul>" : '<p class="url">None found.</p>';
  const epHtml = mined.endpoints.length ? "<ul>" + mined.endpoints.slice(0, 200).map((e) => `<li><code>${escapeHtml(e)}</code></li>`).join("") + "</ul>" : '<p class="url">None found.</p>';
  $("modalBody").innerHTML = `<div class="ai-out">
    <h2>Page: ${escapeHtml(scan.title || "")}</h2>
    <p class="url">${escapeHtml(scan.url)} — ${(scan.scriptUrls || []).length} external scripts</p>
    <h2>Secrets in JS / storage</h2>${secretsHtml}
    <h2>DOM XSS sinks</h2>${sinksHtml}
    <h2>Discovered endpoints (${mined.endpoints.length})</h2>${epHtml}
    <h2>Storage keys</h2><p class="url">${escapeHtml(stKeys.join(", ") || "none")}</p>
    <h2>Cookies (non-HttpOnly)</h2><p class="url">${escapeHtml(scan.cookies || "none")}</p>
    </div>
    <div style="margin-top:10px"><button class="btn-o btn-sm" id="scanAi">AI review of client-side findings</button><div id="scanAiOut" style="margin-top:10px"></div></div>`;
  $("scanAi").addEventListener("click", async () => {
    const out = $("scanAiOut"); out.innerHTML = '<span class="spinner"></span> Reviewing…';
    try {
      const ctx = `URL: ${scan.url}\nSinks: ${JSON.stringify(mined.sinks)}\nSecrets: ${JSON.stringify(mined.secrets.map((s) => s.type))}\nEndpoints: ${mined.endpoints.slice(0, 80).join(", ")}\nStorage keys: ${stKeys.join(", ")}`;
      const text = await Analyzer.analyzeWithDeepSeek({ method: "GET", url: scan.url, requestHeaders: [], requestBody: "", status: 200, statusText: "", responseHeaders: [], responseBody: ctx, mimeType: "text/plain" }, []);
      out.innerHTML = `<div class="ai-out">${miniMarkdown(text)}</div>`;
    } catch (e) { out.innerHTML = errBox("AI review failed", e.message); }
  });
});

// ---- Comparer ----
$("comparerBtn").addEventListener("click", () => {
  const opts = entries.slice().reverse().map((e, i) => { let p = e.url; try { p = new URL(e.url).pathname; } catch {} return `<option value="${e.id}">${escapeHtml(e.method)} ${escapeHtml(p).slice(0, 50)} [${e.status}]</option>`; }).join("");
  openModal("Response comparer", `
    <div class="ctl"><label>A</label><select id="cmpA" style="flex:1">${opts}</select></div>
    <div class="ctl"><label>B</label><select id="cmpB" style="flex:1">${opts}</select></div>
    <div class="ctl"><button class="btn-o btn-sm" id="cmpGo">Diff responses</button></div>
    <div id="cmpOut" style="font-family:ui-monospace,monospace;font-size:12px;margin-top:10px"></div>`);
  $("cmpGo").addEventListener("click", () => {
    const a = entries.find((e) => e.id === $("cmpA").value); const b = entries.find((e) => e.id === $("cmpB").value);
    if (!a || !b) return;
    renderDiffInto("cmpOut", Analyzer.buildRawResponse(a).slice(0, 12000), Analyzer.buildRawResponse(b).slice(0, 12000));
  });
});
function renderDiffInto(id, a, b) {
  const parts = window.Tools.diff(a, b);
  const html = parts.map((p) => p.t === " " ? escapeHtml(p.v) :
    p.t === "-" ? `<span style="background:#3a1414;color:#ff9a9a">${escapeHtml(p.v)}</span>` :
      `<span style="background:#143a1f;color:#9affb0">${escapeHtml(p.v)}</span>`).join("");
  document.getElementById(id).innerHTML = `<pre>${html}</pre>`;
}

// ---- Encoder / decoder ----
$("encoderBtn").addEventListener("click", () => {
  const mk = (id, label) => `<button class="btn-g btn-sm" data-op="${id}">${label}</button>`;
  openModal("Encoder / decoder", `
    <textarea id="encIn" placeholder="input" style="min-height:80px"></textarea>
    <div class="ctl" style="flex-wrap:wrap">
      ${mk("e_url", "URL enc")}${mk("d_url", "URL dec")}${mk("e_base64", "Base64 enc")}${mk("d_base64", "Base64 dec")}
      ${mk("e_hex", "Hex enc")}${mk("d_hex", "Hex dec")}${mk("e_html", "HTML enc")}${mk("d_html", "HTML dec")}
      ${mk("e_unicode", "\\u enc")}${mk("e_urlAll", "URL enc all")}${mk("d_jwt", "JWT decode")}
    </div>
    <textarea id="encOut" placeholder="output" style="min-height:120px;margin-top:8px"></textarea>`);
  document.querySelectorAll("#modalBody [data-op]").forEach((b) => b.addEventListener("click", () => {
    const [dir, fn] = b.dataset.op.split("_");
    const v = $("encIn").value;
    try { $("encOut").value = (dir === "e" ? window.Tools.enc : window.Tools.dec)[fn](v); }
    catch (e) { $("encOut").value = "[error] " + e.message; }
  }));
});

// ---- Report ----
$("reportBtn").addEventListener("click", async () => {
  if (!entries.length) { alert("No captured traffic."); return; }
  openModal("Findings report", '<span class="spinner"></span> Generating report with DeepSeek…');
  try {
    const corr = Analyzer.correlate(entries);
    const text = await Analyzer.generateReport(corr, Object.values(aiTextCache));
    $("modalBody").innerHTML = `<div style="margin-bottom:10px"><button class="btn-o btn-sm" id="dlReport">Download .md</button></div><div class="ai-out">${miniMarkdown(text)}</div>`;
    $("dlReport").addEventListener("click", () => downloadText("ai-intruder-report-" + Date.now() + ".md", text, "text/markdown"));
  } catch (err) { $("modalBody").innerHTML = errBox("Report failed", err.message); }
});

// ---- AI Agent ----
$("runAgent").addEventListener("click", async () => {
  if (!current) { alert("Select a request first."); return; }
  const out = $("agentOut");
  const steps = clamp(parseInt($("agentSteps").value) || 6, 1, 20);
  out.innerHTML = '<span class="spinner"></span> Agent running…';
  const render = (t) => {
    out.innerHTML = '<div class="ai-out">' + t.map((s) => {
      if (s.type === "step") return `<p><strong>${escapeHtml(s.req.method)} ${escapeHtml(s.req.url)}</strong> → HTTP ${s.status} (${s.length}b)<br><span class="url">${escapeHtml(s.thought || "")}</span></p>`;
      if (s.type === "finish") return `<h2>Conclusion</h2>${miniMarkdown(s.text)}`;
      if (s.type === "blocked") return `<p><span class="sev medium">blocked</span> ${escapeHtml(s.error)}</p>`;
      if (s.type === "skipped") return `<p><span class="sev info">skipped</span> ${escapeHtml(s.text)}</p>`;
      return `<p><span class="sev error">error</span> ${escapeHtml(s.text)}</p>`;
    }).join("") + '</div>';
  };
  try {
    await Analyzer.runAgent(current, {
      maxSteps: steps, onStep: render,
      confirmFn: async (req) => confirm(`Agent wants to send a state-changing request:\n\n${req.method} ${req.url}\n\nAllow?`)
    });
  } catch (err) { out.innerHTML = errBox("Agent failed", err.message); }
});

loadSessionSelect();
