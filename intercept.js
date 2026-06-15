// intercept.js — dedicated interception window.
const $ = (id) => document.getElementById(id);
const send = (msg) => new Promise((res) => chrome.runtime.sendMessage(msg, res));

let items = [];          // current held requests
let focusedRid = null;   // selected request id
let editorRid = null;    // which request the editor currently holds (to preserve edits)
let knownRids = new Set();

function parseRaw(raw) {
  const parts = raw.split(/\n\r?\n/);
  const head = parts[0].split("\n");
  const body = parts.slice(1).join("\n\n");
  const first = head[0].trim();
  const sp = first.indexOf(" ");
  const method = sp === -1 ? first : first.slice(0, sp);
  const url = sp === -1 ? "" : first.slice(sp + 1).trim();
  const headers = head.slice(1).map((h) => { const i = h.indexOf(":"); return i > -1 ? { name: h.slice(0, i).trim(), value: h.slice(i + 1).trim() } : null; }).filter(Boolean);
  return { method, url, headers, body: body.trim() };
}
function rawOf(it) {
  return `${it.request.method} ${it.request.url}\n` +
    it.request.headers.map((h) => `${h.name}: ${h.value}`).join("\n") +
    (it.request.body ? `\n\n${it.request.body}` : "");
}
const esc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

async function refreshState() {
  const st = await send({ type: "GET_STATE" });
  $("toggle").checked = !!st.manualIntercept;
  $("state").textContent = st.manualIntercept ? "ON" : "OFF";
  $("state").className = "state " + (st.manualIntercept ? "on" : "off");
  if (!st.capturing && st.manualIntercept) $("state").textContent = "ON (start capture)";
}

let busy = false;       // true while a forward/drop is in flight

async function poll() {
  if (busy) return;     // don't re-read the queue mid-action (prevents items reappearing)
  const r = await send({ type: "GET_INTERCEPT" });
  items = r.items || [];
  const rids = items.map((it) => String(it.requestId));
  // keep focus valid
  if (focusedRid && !rids.includes(focusedRid)) focusedRid = null;
  if (!focusedRid && rids.length) focusedRid = rids[0];
  renderQueue(rids);
  renderFocused();
  $("count").textContent = items.length ? items.length + " held" : "";
}

function renderQueue(rids) {
  const q = $("queue");
  // remove gone
  [...q.children].forEach((c) => { if (!rids.includes(c.dataset.rid)) c.remove(); });
  const present = new Set([...q.children].map((c) => c.dataset.rid));
  for (const it of items) {
    const rid = String(it.requestId);
    let el = q.querySelector(`[data-rid="${CSS.escape(rid)}"]`);
    if (!el) {
      el = document.createElement("div");
      el.className = "qitem" + (knownRids.size ? " new" : "");
      el.dataset.rid = rid;
      let path = it.request.url; try { const u = new URL(it.request.url); path = u.pathname + u.search; } catch {}
      el.innerHTML = `<span class="m">${esc(it.request.method)}</span> <span class="h">${esc((() => { try { return new URL(it.request.url).host; } catch { return ""; } })())}</span><span class="p">${esc(path)}</span>`;
      el.addEventListener("click", () => { focusedRid = rid; renderQueue(rids); renderFocused(); });
      q.appendChild(el);
    }
    el.classList.toggle("sel", rid === focusedRid);
  }
  knownRids = new Set(rids);
}

function renderFocused() {
  const it = items.find((x) => String(x.requestId) === focusedRid);
  if (!it) {
    $("focusView").style.display = "none";
    $("empty").style.display = "flex";
    $("empty").textContent = $("toggle").checked
      ? "Intercept is on. Waiting for a matching request…"
      : "Intercept is off. Toggle it on (with capture running) to hold requests here.";
    editorRid = null;
    return;
  }
  $("empty").style.display = "none";
  $("focusView").style.display = "flex";
  let host = ""; try { host = new URL(it.request.url).host; } catch {}
  $("reqline").innerHTML = `<span class="mm">${esc(it.request.method)}</span> ${esc(it.request.url)}`;
  // only (re)load editor when switching to a different request — preserves edits
  if (editorRid !== focusedRid) { $("editor").value = rawOf(it); editorRid = focusedRid; }
}

function setBusy(b) {
  busy = b;
  $("fwdBtn").disabled = b; $("dropBtn").disabled = b; $("forwardAll").disabled = b;
}

async function forward(rid, useEdits) {
  if (busy) return;
  const it = items.find((x) => String(x.requestId) === rid); if (!it) return;
  let request, edited = false;
  if (useEdits && rid === editorRid) {
    const o = parseRaw($("editor").value);
    request = { url: o.url, method: o.method, headers: o.headers, body: o.body };
    edited = $("editor").value.trim() !== rawOf(it).trim(); // only "edited" if actually changed
  } else { request = it.request; }
  setBusy(true);
  // remove locally and advance focus immediately (no poll yet — that's what caused the bug)
  items = items.filter((x) => String(x.requestId) !== rid);
  const remaining = items.map((x) => String(x.requestId));
  focusedRid = remaining[0] || null; editorRid = null;
  renderQueue(remaining); renderFocused();
  $("count").textContent = items.length ? items.length + " held" : "";
  try { await send({ type: "INTERCEPT_ACTION", requestId: it.requestId, action: "forward", request, edited }); }
  finally { setBusy(false); poll(); }
}

async function drop(rid) {
  if (busy) return;
  const it = items.find((x) => String(x.requestId) === rid); if (!it) return;
  setBusy(true);
  items = items.filter((x) => String(x.requestId) !== rid);
  const remaining = items.map((x) => String(x.requestId));
  focusedRid = remaining[0] || null; editorRid = null;
  renderQueue(remaining); renderFocused();
  $("count").textContent = items.length ? items.length + " held" : "";
  try { await send({ type: "INTERCEPT_ACTION", requestId: it.requestId, action: "drop" }); }
  finally { setBusy(false); poll(); }
}

function moveFocus(delta) {
  const rids = items.map((it) => String(it.requestId));
  if (!rids.length) return;
  let i = rids.indexOf(focusedRid);
  i = (i + delta + rids.length) % rids.length;
  focusedRid = rids[i]; renderQueue(rids); renderFocused();
}

// ---- events ----
$("toggle").addEventListener("change", async (e) => { await send({ type: "SET_INTERCEPT", value: e.target.checked }); refreshState(); poll(); });
$("forwardAll").addEventListener("click", async () => { if (busy) return; setBusy(true); try { await send({ type: "FORWARD_ALL" }); } finally { setBusy(false); poll(); } });
$("fwdBtn").addEventListener("click", () => focusedRid && forward(focusedRid, true));
$("dropBtn").addEventListener("click", () => focusedRid && drop(focusedRid));

document.addEventListener("keydown", (e) => {
  const inEditor = e.target && e.target.id === "editor";
  if (inEditor) {
    if (e.ctrlKey && e.key === "Enter") { e.preventDefault(); focusedRid && forward(focusedRid, true); }
    return; // don't hijack typing
  }
  if (e.key === "f" || e.key === "F") { e.preventDefault(); focusedRid && forward(focusedRid, true); }
  else if (e.key === "d" || e.key === "D") { e.preventDefault(); focusedRid && drop(focusedRid); }
  else if (e.key === "a" || e.key === "A") { e.preventDefault(); $("forwardAll").click(); }
  else if (e.key === "j" || e.key === "ArrowDown") { e.preventDefault(); moveFocus(1); }
  else if (e.key === "k" || e.key === "ArrowUp") { e.preventDefault(); moveFocus(-1); }
});

refreshState();
poll();
setInterval(poll, 700);
setInterval(refreshState, 1500);

// hold-scope controls
function loadHoldOpts() {
  chrome.storage.local.get(["interceptHoldAll", "holdPreflight"], (c) => {
    $("holdAll").checked = !!c.interceptHoldAll;
    $("holdOptions").checked = !!c.holdPreflight;
  });
}
$("holdAll").addEventListener("change", (e) => { chrome.storage.local.set({ interceptHoldAll: e.target.checked }); send({ type: "RELOAD_FILTERS" }); });
$("holdOptions").addEventListener("change", (e) => { chrome.storage.local.set({ holdPreflight: e.target.checked }); send({ type: "RELOAD_FILTERS" }); });
loadHoldOpts();
