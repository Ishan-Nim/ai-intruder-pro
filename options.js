const $ = (id) => document.getElementById(id);
const DEFAULT_ENDPOINT = "https://api.deepseek.com/chat/completions";

// Resource types the user can choose to skip. Documents/XHR/Fetch are never offered
// (always logged) since they're the interesting traffic.
const TYPE_OPTIONS = ["Image", "Font", "Media", "Stylesheet", "Script", "Other", "Ping"];
const DEFAULT_EXCLUDE = ["Image"];

function renderTypeChecks(selected) {
  const wrap = $("excludeTypes");
  wrap.innerHTML = "";
  TYPE_OPTIONS.forEach((t) => {
    const id = "ex_" + t;
    const label = document.createElement("label");
    label.style.cssText = "font-weight:400;margin:0;display:flex;gap:6px;align-items:center;";
    label.innerHTML = `<input type="checkbox" id="${id}" value="${t}" style="width:auto" ${selected.includes(t) ? "checked" : ""}> ${t}`;
    wrap.appendChild(label);
  });
}

chrome.storage.local.get(
  ["apiKey", "model", "endpoint", "temperature", "scope", "excludeTypes", "excludeUrls", "theme", "rateMs", "oob", "enforceScope"],
  (c) => {
    $("key").value = c.apiKey || "";
    $("model").value = c.model || "deepseek-chat";
    $("endpoint").value = c.endpoint || DEFAULT_ENDPOINT;
    $("temperature").value = c.temperature != null ? c.temperature : 0.2;
    $("scope").value = (c.scope || []).join("\n");
    $("excludeUrls").value = (c.excludeUrls || []).join("\n");
    $("theme").value = c.theme || "dark";
    $("rateMs").value = c.rateMs != null ? c.rateMs : 0;
    $("oob").value = c.oob || "";
    $("enforceScope").checked = c.enforceScope !== false;
    renderTypeChecks(c.excludeTypes || DEFAULT_EXCLUDE);
  });

$("theme").addEventListener("change", () => window.__setTheme && window.__setTheme($("theme").value));

$("save").addEventListener("click", () => {
  const scope = $("scope").value.split("\n").map((s) => s.trim()).filter(Boolean);
  const excludeUrls = $("excludeUrls").value.split("\n").map((s) => s.trim()).filter(Boolean);
  const excludeTypes = TYPE_OPTIONS.filter((t) => $("ex_" + t)?.checked);
  const theme = $("theme").value;
  chrome.storage.local.set({
    apiKey: $("key").value.trim(),
    model: $("model").value,
    endpoint: $("endpoint").value.trim() || DEFAULT_ENDPOINT,
    temperature: parseFloat($("temperature").value) || 0,
    scope, excludeUrls, excludeTypes, theme,
    rateMs: parseInt($("rateMs").value) || 0,
    oob: $("oob").value.trim(),
    enforceScope: $("enforceScope").checked
  }, () => {
    chrome.runtime.sendMessage({ type: "RELOAD_FILTERS" });
    if (window.__setTheme) window.__setTheme(theme);
    $("saved").textContent = "Saved ✓";
    setTimeout(() => ($("saved").textContent = ""), 1500);
  });
});
