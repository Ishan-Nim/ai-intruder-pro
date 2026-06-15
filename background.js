// background.js — AI Intruder Pro v3 capture + interception engine.
importScripts("db.js");

const DEBUG_PROTOCOL = "1.3";
const MAX_BODY_BYTES = 300 * 1024;
const MAX_ENTRIES = 5000;

const pending = new Map();      // tabId:requestId -> entry (Network capture)
const wsUrls = new Map();       // tabId:requestId -> ws url
const attached = new Set();
const interceptQueue = new Map(); // requestId -> {tabId, request, resourceType, ts}
let capturing = false;
let manualIntercept = false;
let rules = [];                 // match/replace rules
let interceptHoldAll = false;   // hold every request type vs the smart subset
let holdPreflight = false;      // hold CORS preflight OPTIONS
const HOLD_DEFAULT = new Set(["Document", "XHR", "Fetch", "WebSocket"]);

let scopeRegexes = [];
let excludeTypeSet = new Set(["Image"]);
let excludeUrlRegexes = [];
const IMG_EXT = /\.(png|jpe?g|gif|webp|svg|ico|bmp|avif|tiff?)(\?|#|$)/i;
const DEFAULT_EXCLUDE_TYPES = ["Image"];

const key = (t, r) => t + ":" + r;
const headerObjToArray = (h) => h ? Object.entries(h).map(([name, value]) => ({ name, value: String(value) })) : [];
const headerArrayToObj = (a) => { const o = {}; (a || []).forEach((h) => (o[h.name] = h.value)); return o; };

// ---- scope / exclude -------------------------------------------------------

function globToRegex(p) {
  const esc = p.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  try { return new RegExp(esc, "i"); } catch { return null; }
}
function compileScope(patterns) {
  scopeRegexes = (patterns || []).map((p) => p.trim()).filter(Boolean).map((p) => {
    const re = "^" + p.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$";
    try { return new RegExp(re, "i"); } catch { return null; }
  }).filter(Boolean);
}
function inScope(url) {
  if (!scopeRegexes.length) return true;
  try { return scopeRegexes.some((re) => re.test(new URL(url).host)); } catch { return false; }
}
function isExcluded(url, type) {
  if (type && excludeTypeSet.has(type)) return true;
  if (excludeTypeSet.has("Image")) { try { if (IMG_EXT.test(new URL(url).pathname)) return true; } catch {} }
  if (excludeUrlRegexes.some((re) => re.test(url))) return true;
  return false;
}
async function loadFilters() {
  const { scope = [], excludeTypes = DEFAULT_EXCLUDE_TYPES, excludeUrls = [], rules: r = [], manualIntercept: mi = false, interceptHoldAll: iha = false, holdPreflight: hp = false } =
    await chrome.storage.local.get(["scope", "excludeTypes", "excludeUrls", "rules", "manualIntercept", "interceptHoldAll", "holdPreflight"]);
  compileScope(scope);
  excludeTypeSet = new Set(excludeTypes);
  excludeUrlRegexes = (excludeUrls || []).map((p) => p.trim()).filter(Boolean).map(globToRegex).filter(Boolean);
  rules = (r || []).filter((x) => x.enabled);
  manualIntercept = !!mi;
  interceptHoldAll = !!iha;
  holdPreflight = !!hp;
}

// ---- storage (IndexedDB) ---------------------------------------------------

async function saveEntry(entry) {
  await IDB.put("entries", entry);
  await IDB.trim("entries", MAX_ENTRIES, "ts");
  updateBadge(await IDB.count("entries"));
}
function updateBadge(count) {
  chrome.action.setBadgeBackgroundColor({ color: manualIntercept ? "#e05252" : (capturing ? "#ff7900" : "#555") });
  chrome.action.setBadgeText({ text: count ? (count > 9999 ? "9k+" : String(count)) : "" });
}
async function audit(rec) { try { await IDB.put("audit", { id: crypto.randomUUID(), ts: Date.now(), ...rec }); await IDB.trim("audit", 2000, "ts"); } catch {} }

// ---- attach / detach -------------------------------------------------------

function needFetch() { return manualIntercept || rules.length > 0; }
function fetchPatterns() {
  const pats = [{ urlPattern: "*", requestStage: "Request" }];
  if (rules.some((r) => r.phase === "response")) pats.push({ urlPattern: "*", requestStage: "Response" });
  return pats;
}
async function attachTab(tabId, url) {
  if (attached.has(tabId)) return;
  if (url && /^(chrome|edge|about|devtools|chrome-extension|view-source):/i.test(url)) return;
  try {
    await chrome.debugger.attach({ tabId }, DEBUG_PROTOCOL);
    await chrome.debugger.sendCommand({ tabId }, "Network.enable", {});
    if (needFetch()) await chrome.debugger.sendCommand({ tabId }, "Fetch.enable", { patterns: fetchPatterns() });
    attached.add(tabId);
  } catch (e) {}
}
async function detachTab(tabId) {
  if (!attached.has(tabId)) return;
  try { await chrome.debugger.detach({ tabId }); } catch (e) {}
  attached.delete(tabId);
}
async function attachAllTabs() { const tabs = await chrome.tabs.query({}); for (const t of tabs) if (t.id != null) await attachTab(t.id, t.url); }
async function detachAllTabs() { for (const id of [...attached]) await detachTab(id); pending.clear(); }
async function reapplyFetch() {
  for (const tabId of attached) {
    try {
      if (needFetch()) await chrome.debugger.sendCommand({ tabId }, "Fetch.enable", { patterns: fetchPatterns() });
      else await chrome.debugger.sendCommand({ tabId }, "Fetch.disable", {});
    } catch {}
  }
}

// ---- capture toggle --------------------------------------------------------

async function setCapturing(on) {
  capturing = !!on;
  await chrome.storage.local.set({ capturing });
  await loadFilters();
  if (capturing) { await attachAllTabs(); chrome.alarms.create("keepalive", { periodInMinutes: 0.4 }); }
  else { await detachAllTabs(); chrome.alarms.clear("keepalive"); }
  updateBadge(await IDB.count("entries"));
}
chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name === "keepalive" && capturing) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id != null) attachTab(tab.id, tab.url);
  }
});
chrome.tabs.onUpdated.addListener((tabId, info, tab) => { if (capturing && info.status === "loading") attachTab(tabId, tab.url); });
chrome.tabs.onCreated.addListener((tab) => { if (capturing && tab.id != null) attachTab(tab.id, tab.url); });
chrome.tabs.onActivated.addListener(({ tabId }) => { if (capturing) chrome.tabs.get(tabId, (t) => t && attachTab(tabId, t.url)); });
chrome.debugger.onDetach.addListener((src) => { if (src.tabId != null) attached.delete(src.tabId); });

// ---- match/replace ---------------------------------------------------------

function applyRule(rule, str) {
  if (!str) return str;
  try {
    if (rule.isRegex) return str.replace(new RegExp(rule.find, "g"), rule.replace ?? "");
    return str.split(rule.find).join(rule.replace ?? "");
  } catch { return str; }
}
function applyRequestRules(reqObj) {
  // reqObj: { url, method, headers:{}, postData }
  let { url, method, headers, postData } = reqObj;
  let headerStr = Object.entries(headers).map(([n, v]) => `${n}: ${v}`).join("\n");
  for (const r of rules) {
    if (r.phase !== "request") continue;
    if (r.part === "url") url = applyRule(r, url);
    else if (r.part === "body") postData = applyRule(r, postData || "");
    else if (r.part === "header") headerStr = applyRule(r, headerStr);
  }
  const newHeaders = {};
  headerStr.split("\n").forEach((l) => { const i = l.indexOf(":"); if (i > -1) newHeaders[l.slice(0, i).trim()] = l.slice(i + 1).trim(); });
  return { url, method, headers: newHeaders, postData };
}
function applyResponseRules(headersArr, body) {
  let headerStr = headersArr.map((h) => `${h.name}: ${h.value}`).join("\n");
  let b = body;
  for (const r of rules) {
    if (r.phase !== "response") continue;
    if (r.part === "header") headerStr = applyRule(r, headerStr);
    else if (r.part === "body") b = applyRule(r, b);
  }
  const newHeaders = headerStr.split("\n").map((l) => { const i = l.indexOf(":"); return i > -1 ? { name: l.slice(0, i).trim(), value: l.slice(i + 1).trim() } : null; }).filter(Boolean);
  return { headers: newHeaders, body: b };
}
function toB64(str) { try { return btoa(unescape(encodeURIComponent(str))); } catch { return btoa(str); } }

// Send an EDITED intercepted request ourselves and fulfill the page's request with the
// result. This avoids Chrome's Fetch.continueRequest URL-override quirk (which re-issues
// the request and drops the edit). The SW's own fetch is NOT re-intercepted by the tab's
// Fetch domain, so there's no double-pause.
async function replayAndFulfill(item, req) {
  const tabId = item.tabId, requestId = item.requestId;
  const headers = {};
  (req.headers || []).forEach((h) => {
    const n = h.name;
    // skip forbidden/again-managed headers; cookies come from the jar via credentials:include
    if (!n.startsWith(":") && !/^(host|content-length|connection|accept-encoding|cookie)$/i.test(n)) headers[n] = h.value;
  });
  const opts = { method: req.method || "GET", headers, credentials: "include", redirect: "follow" };
  if (req.body && !/^(GET|HEAD)$/i.test(req.method)) opts.body = req.body;
  let resp, text;
  try { resp = await fetch(req.url, opts); text = await resp.text(); }
  catch (e) { try { await chrome.debugger.sendCommand({ tabId }, "Fetch.failRequest", { requestId, errorReason: "Failed" }); } catch {} return; }
  const respHeaders = [];
  resp.headers.forEach((v, k) => { if (!/^(content-encoding|content-length|transfer-encoding)$/i.test(k)) respHeaders.push({ name: k, value: String(v) }); });
  await chrome.debugger.sendCommand({ tabId }, "Fetch.fulfillRequest", {
    requestId, responseCode: resp.status || 200, responseHeaders: respHeaders, body: toB64(text)
  });
}

// ---- CDP events ------------------------------------------------------------

chrome.debugger.onEvent.addListener(async (source, method, params) => {
  const tabId = source.tabId;
  if (tabId == null) return;

  // ---- Fetch interception ----
  if (method === "Fetch.requestPaused") {
    const isResponse = params.responseStatusCode != null || params.responseErrorReason != null;
    try {
      if (!isResponse) {
        // request stage
        let mod = applyRequestRules({
          url: params.request.url, method: params.request.method,
          headers: { ...params.request.headers }, postData: params.request.postData
        });
        if (manualIntercept && inScope(mod.url) && !isExcluded(mod.url, params.resourceType)) {
          const type = params.resourceType || "";
          const isPreflight = (params.request.method || "").toUpperCase() === "OPTIONS" || type === "Preflight";
          const meaningful = interceptHoldAll || HOLD_DEFAULT.has(type);
          const hold = meaningful && !(isPreflight && !holdPreflight);
          if (hold) {
            // strip HTTP/2 pseudo-headers (:path/:authority/etc) for display — passing them
            // back would override an edited URL.
            const cleanHeaders = headerObjToArray(mod.headers).filter((h) => !h.name.startsWith(":"));
            interceptQueue.set(params.requestId, {
              tabId, requestId: params.requestId, networkId: params.networkId, resourceType: params.resourceType, ts: Date.now(),
              request: { url: mod.url, method: mod.method, headers: cleanHeaders, body: mod.postData || "" }
            });
            updateBadge(await IDB.count("entries"));
            return; // hold until user acts
          }
          // not a held type — fall through and auto-forward (with any rule edits applied)
        }
        const cmd = { requestId: params.requestId, url: mod.url, method: mod.method, headers: headerObjToArray(mod.headers) };
        if (mod.postData) cmd.postData = toB64(mod.postData);
        await chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", cmd);
      } else {
        // response stage (only when response rules exist)
        if (!rules.some((r) => r.phase === "response")) { await chrome.debugger.sendCommand({ tabId }, "Fetch.continueResponse", { requestId: params.requestId }); return; }
        let bodyRes = { body: "", base64Encoded: false };
        try { bodyRes = await chrome.debugger.sendCommand({ tabId }, "Fetch.getResponseBody", { requestId: params.requestId }); } catch {}
        let body = bodyRes.base64Encoded ? atob(bodyRes.body) : bodyRes.body;
        const out = applyResponseRules(params.responseHeaders || [], body);
        await chrome.debugger.sendCommand({ tabId }, "Fetch.fulfillRequest", {
          requestId: params.requestId, responseCode: params.responseStatusCode || 200,
          responseHeaders: out.headers, body: toB64(out.body)
        });
      }
    } catch (e) {
      try { await chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", { requestId: params.requestId }); } catch {}
    }
    return;
  }

  // ---- WebSocket ----
  if (method === "Network.webSocketCreated") { wsUrls.set(key(tabId, params.requestId), params.url); return; }
  if (method === "Network.webSocketFrameSent" || method === "Network.webSocketFrameReceived") {
    const url = wsUrls.get(key(tabId, params.requestId)) || "ws://?";
    if (!inScope(url)) return;
    const sent = method === "Network.webSocketFrameSent";
    const payload = params.response && typeof params.response.payloadData === "string" ? params.response.payloadData : "";
    await saveEntry({
      id: crypto.randomUUID(), tabId, ts: Date.now(), url,
      method: sent ? "WS\u2192" : "WS\u2190", requestHeaders: [], requestBody: sent ? payload : "",
      resourceType: "WebSocket", status: 101, statusText: "Switching Protocols",
      responseHeaders: [], mimeType: "websocket", responseBody: sent ? "" : payload, bodyTruncated: false
    });
    return;
  }

  // ---- Network capture ----
  if (method === "Network.requestWillBeSent") {
    const req = params.request || {};
    if (!inScope(req.url) || isExcluded(req.url, params.type)) return;
    pending.set(key(tabId, params.requestId), {
      id: crypto.randomUUID(), tabId, ts: Date.now(), url: req.url, method: req.method,
      requestHeaders: headerObjToArray(req.headers), requestBody: req.postData || "", hasPostData: !!req.hasPostData,
      resourceType: params.type || "", status: null, statusText: "", responseHeaders: [],
      mimeType: "", responseBody: "", bodyTruncated: false, remoteIP: ""
    });
  } else if (method === "Network.responseReceived") {
    const e = pending.get(key(tabId, params.requestId)); if (!e) return;
    const r = params.response || {};
    e.status = r.status; e.statusText = r.statusText || ""; e.responseHeaders = headerObjToArray(r.headers);
    e.mimeType = r.mimeType || ""; e.remoteIP = r.remoteIPAddress || ""; if (r.url && !e.edited) e.url = r.url;
  } else if (method === "Network.loadingFinished") {
    const k = key(tabId, params.requestId); const e = pending.get(k); if (!e) return;
    pending.delete(k);
    if (e.hasPostData && !e.requestBody) {
      try { const pd = await chrome.debugger.sendCommand({ tabId }, "Network.getRequestPostData", { requestId: params.requestId }); e.requestBody = pd.postData || ""; } catch {}
    }
    const skip = /^(image|video|audio|font)\//i.test(e.mimeType) || /(octet-stream|pdf|zip|wasm)/i.test(e.mimeType);
    if (!skip) {
      try {
        const res = await chrome.debugger.sendCommand({ tabId }, "Network.getResponseBody", { requestId: params.requestId });
        let body = res.body || ""; if (res.base64Encoded) { try { body = atob(body); } catch { body = "[base64 body]"; } }
        if (body.length > MAX_BODY_BYTES) { body = body.slice(0, MAX_BODY_BYTES); e.bodyTruncated = true; }
        e.responseBody = body;
      } catch { e.responseBody = "[body unavailable]"; }
    } else e.responseBody = "[" + e.mimeType + " body skipped]";
    await saveEntry(e);
  } else if (method === "Network.loadingFailed") {
    pending.delete(key(tabId, params.requestId));
  }
});

// ---- page scan (DOM / client-side) via scripting ---------------------------

function pageScanFn() {
  const trunc = (s, n) => (s && s.length > n ? s.slice(0, n) : s) || "";
  const scriptUrls = [...document.scripts].filter((s) => s.src).map((s) => s.src);
  const inline = [...document.scripts].filter((s) => !s.src).map((s) => s.textContent).join("\n\n");
  const store = (s) => { const o = {}; try { for (let i = 0; i < s.length; i++) { const k = s.key(i); o[k] = trunc(s.getItem(k), 300); } } catch {} return o; };
  const forms = [...document.forms].map((f) => ({
    action: f.action, method: f.method,
    inputs: [...f.elements].map((el) => ({ name: el.name, type: el.type })).filter((x) => x.name)
  }));
  return {
    url: location.href, title: document.title,
    scriptUrls, inline: trunc(inline, 400000),
    localStorage: store(localStorage), sessionStorage: store(sessionStorage),
    cookies: document.cookie, forms,
    generator: (document.querySelector('meta[name="generator"]') || {}).content || ""
  };
}

// ---- messaging -------------------------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg.type) {
      case "GET_STATE": {
        const { scope = [] } = await chrome.storage.local.get("scope");
        sendResponse({ capturing, manualIntercept, count: await IDB.count("entries"), attached: [...attached], scope, intercepting: interceptQueue.size });
        break;
      }
      case "SET_CAPTURING": await setCapturing(msg.value); sendResponse({ capturing }); break;
      case "SET_INTERCEPT":
        manualIntercept = !!msg.value; await chrome.storage.local.set({ manualIntercept });
        if (capturing) await reapplyFetch(); updateBadge(await IDB.count("entries"));
        sendResponse({ manualIntercept }); break;
      case "RELOAD_FILTERS": await loadFilters(); if (capturing) await reapplyFetch(); sendResponse({ ok: true }); break;
      case "SET_SCOPE": await chrome.storage.local.set({ scope: msg.scope || [] }); await loadFilters(); sendResponse({ ok: true }); break;
      case "GET_ENTRIES": sendResponse({ entries: await IDB.getAll("entries") }); break;
      case "ADD_ENTRIES": for (const e of (msg.entries || [])) await IDB.put("entries", e); await IDB.trim("entries", MAX_ENTRIES, "ts"); updateBadge(await IDB.count("entries")); sendResponse({ ok: true, count: await IDB.count("entries") }); break;
      case "CLEAR_ENTRIES": await IDB.clear("entries"); updateBadge(0); sendResponse({ ok: true }); break;
      case "DELETE_ENTRY": await IDB.delete("entries", msg.id); updateBadge(await IDB.count("entries")); sendResponse({ ok: true }); break;
      case "GET_INTERCEPT": sendResponse({ items: [...interceptQueue.values()] }); break;
      case "INTERCEPT_ACTION": {
        const item = interceptQueue.get(msg.requestId);
        if (item) {
          interceptQueue.delete(msg.requestId);
          try {
            if (msg.action === "drop") {
              await chrome.debugger.sendCommand({ tabId: item.tabId }, "Fetch.failRequest", { requestId: msg.requestId, errorReason: "Aborted" });
            } else if (msg.edited) {
              const req = msg.request || item.request;
              await replayAndFulfill(item, req);
              // reflect the edit in the captured history entry
              if (item.networkId != null) {
                const e = pending.get(key(item.tabId, item.networkId));
                if (e) { e.url = req.url; e.method = req.method; e.requestHeaders = (req.headers || []).filter((h) => !h.name.startsWith(":")); e.requestBody = req.body || ""; e.edited = true; }
              }
            } else {
              // unedited: pass through untouched (no URL override → no re-pause)
              await chrome.debugger.sendCommand({ tabId: item.tabId }, "Fetch.continueRequest", { requestId: msg.requestId });
            }
          } catch (e) { sendResponse({ ok: false, error: String(e) }); break; }
        }
        updateBadge(await IDB.count("entries"));
        sendResponse({ ok: true });
        break;
      }
      case "FORWARD_ALL": {
        for (const [rid, item] of [...interceptQueue.entries()]) {
          interceptQueue.delete(rid);
          try { await chrome.debugger.sendCommand({ tabId: item.tabId }, "Fetch.continueRequest", { requestId: rid }); } catch {}
        }
        sendResponse({ ok: true }); break;
      }
      case "SCAN_PAGE": {
        try {
          const tabId = msg.tabId ?? (await chrome.tabs.query({ active: true, currentWindow: true }))[0]?.id;
          const [res] = await chrome.scripting.executeScript({ target: { tabId }, func: pageScanFn });
          sendResponse({ ok: true, result: res.result });
        } catch (e) { sendResponse({ ok: false, error: String(e) }); }
        break;
      }
      case "AUDIT": await audit(msg.record || {}); sendResponse({ ok: true }); break;
      case "GET_AUDIT": sendResponse({ log: await IDB.getAll("audit") }); break;
      case "ACTIVE_TAB": { const [t] = await chrome.tabs.query({ active: true, currentWindow: true }); sendResponse({ tabId: t?.id, url: t?.url }); break; }
      default: sendResponse({ error: "unknown message" });
    }
  })();
  return true;
});

chrome.runtime.onStartup.addListener(restore);
chrome.runtime.onInstalled.addListener(restore);
async function restore() {
  await loadFilters();
  const { capturing: c } = await chrome.storage.local.get("capturing");
  if (c) await setCapturing(true);
  updateBadge(await IDB.count("entries"));
}
