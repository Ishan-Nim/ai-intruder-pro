const $ = (id) => document.getElementById(id);
const send = (msg) => new Promise((res) => chrome.runtime.sendMessage(msg, res));

async function refresh() {
  const s = await send({ type: "GET_STATE" });
  $("toggle").checked = !!s.capturing;
  $("status").textContent = s.capturing ? "On — recording" : "Off";
  $("status").className = "status " + (s.capturing ? "on" : "off");
  $("count").textContent = s.count || 0;
  $("scope").textContent = "Scope: " + ((s.scope && s.scope.length) ? s.scope.join(", ") : "all hosts");
  $("iToggle").checked = !!s.manualIntercept;
  $("iStatus").textContent = s.manualIntercept ? "On — holding requests" : "Off";
  $("iStatus").className = "status " + (s.manualIntercept ? "on" : "off");
}
$("toggle").addEventListener("change", async (e) => { await send({ type: "SET_CAPTURING", value: e.target.checked }); refresh(); });
$("iToggle").addEventListener("change", async (e) => {
  await send({ type: "SET_INTERCEPT", value: e.target.checked });
  if (e.target.checked) {
    const url = chrome.runtime.getURL("intercept.html");
    const tabs = await chrome.tabs.query({ url });
    if (tabs.length) { try { await chrome.windows.update(tabs[0].windowId, { focused: true }); } catch {} }
    else chrome.windows.create({ url, type: "popup", width: 860, height: 660 });
  }
  refresh();
});
$("open").addEventListener("click", () => chrome.tabs.create({ url: chrome.runtime.getURL("viewer.html") }));
$("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("clear").addEventListener("click", async () => { await send({ type: "CLEAR_ENTRIES" }); refresh(); });
refresh();
