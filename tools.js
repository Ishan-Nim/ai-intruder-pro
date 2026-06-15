// tools.js — encoders/decoders, JWT decode, and a word-level diff for the viewer.
(function () {
  const b64uTo = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return atob(s); };

  const enc = {
    url: (s) => encodeURIComponent(s),
    urlAll: (s) => s.replace(/[\s\S]/g, (c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")),
    base64: (s) => { try { return btoa(unescape(encodeURIComponent(s))); } catch { return btoa(s); } },
    hex: (s) => [...s].map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join(""),
    html: (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])),
    unicode: (s) => [...s].map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join("")
  };
  const dec = {
    url: (s) => { try { return decodeURIComponent(s); } catch { return s; } },
    base64: (s) => { try { return decodeURIComponent(escape(atob(s))); } catch { try { return atob(s); } catch { return "[invalid base64]"; } } },
    hex: (s) => { const t = s.replace(/[^0-9a-f]/gi, ""); let o = ""; for (let i = 0; i < t.length; i += 2) o += String.fromCharCode(parseInt(t.substr(i, 2), 16)); return o; },
    html: (s) => { const d = document.createElement("textarea"); d.innerHTML = s; return d.value; },
    jwt: (s) => {
      const p = s.trim().split(".");
      if (p.length < 2) return "[not a JWT]";
      try {
        const h = JSON.parse(b64uTo(p[0])); const b = JSON.parse(b64uTo(p[1]));
        return "HEADER:\n" + JSON.stringify(h, null, 2) + "\n\nPAYLOAD:\n" + JSON.stringify(b, null, 2) +
          "\n\nSIGNATURE: " + (p[2] || "(none)") + (/(^|)none/i.test(h.alg || "") ? "\n\n⚠ alg=none" : "");
      } catch { return "[invalid JWT]"; }
    }
  };

  // word/line diff (LCS) -> array of {t:' '|'-'|'+', v}
  function diff(a, b) {
    const A = a.split(/(\s+)/), B = b.split(/(\s+)/);
    const n = A.length, m = B.length;
    const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--)
      dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    const out = []; let i = 0, j = 0;
    while (i < n && j < m) {
      if (A[i] === B[j]) { out.push({ t: " ", v: A[i] }); i++; j++; }
      else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ t: "-", v: A[i] }); i++; }
      else { out.push({ t: "+", v: B[j] }); j++; }
    }
    while (i < n) out.push({ t: "-", v: A[i++] });
    while (j < m) out.push({ t: "+", v: B[j++] });
    return out;
  }

  window.Tools = { enc, dec, diff };
})();
