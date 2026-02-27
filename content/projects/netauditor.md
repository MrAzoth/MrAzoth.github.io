---
title: "NetAuditor"
description: "Automated network security assessment tool — nmap, ssh-audit, testssl, evidence extraction and screenshots in a single pipeline."
date: 2025-01-01
tags: ["python", "nmap", "ssh", "tls", "automation", "security-assessment"]
---

## Overview

**NetAuditor** is a Python-based automation tool designed to speed up the evidence collection phase of network security assessments. It chains together multiple well-known tools — nmap, ssh-audit, testssl.sh — into a single pipeline that runs unattended, extracts only the relevant findings, and generates ready-to-use screenshots for reports.

The goal is simple: reduce the manual overhead of running each tool separately, grepping for vulnerable ciphers, copy-pasting output into reports. Run it against a target list, come back to a structured folder with everything already filtered and rendered.

---

## Pipeline

```
nmap → ssh-audit → testssl → evidence extraction → screenshots → [report]
```

1. **nmap** — full port scan with service detection
2. **ssh-audit** — SSH cipher and algorithm analysis
3. **testssl.sh** — SSL/TLS protocol and cipher assessment
4. **Evidence extraction** — automatic filtering of vulnerabilities from raw output
5. **Screenshots** — ANSI-color-aware PNG rendering via Pillow
6. **Report mode** — consolidated audit summary across all targets

---

## Notes on the Nmap Library

The tool uses **python-nmap** rather than calling nmap via `subprocess` directly. The subprocess approach (invoking nmap and parsing its XML output manually) is generally more reliable and gives full control over the output format — and is what most production tools use.

python-nmap was chosen here to experiment with the library abstraction. The tradeoff: it requires a small manual patch to the library source before use, because the default package does not expose the `tunnel` attribute from nmap's service detection output.

**Patch required** — find the `nmap.py` file:

```bash
python3 -c "import nmap; print(nmap.__file__)"
```

In the service parsing loop, add `tunnel` initialization and extraction:

```python
name = product = version = extrainfo = conf = cpe = tunnel = ""

for dname in dport.findall("service"):
    name = dname.get("name")
    if dname.get("product"):
        product = dname.get("product")
    if dname.get("version"):
        version = dname.get("version")
    if dname.get("extrainfo"):
        extrainfo = dname.get("extrainfo")
    if dname.get("conf"):
        conf = dname.get("conf")
    if dname.get("tunnel"):
        tunnel = dname.get("tunnel")
    for dcpe in dname.findall("cpe"):
        cpe = dcpe.text
```

And add it to the result dictionary:

```python
scan_result["scan"][host][proto][port] = {
    "state": state,
    "reason": reason,
    "name": name,
    "product": product,
    "version": version,
    "extrainfo": extrainfo,
    "conf": conf,
    "cpe": cpe,
    "tunnel": tunnel,
}
```

Full details in the README.

---

## Output Structure

```
.
├── <target>_Scans/
│   ├── nmap_scan_<target>.txt
│   ├── ssh_audit_<target>_<port>.txt
│   └── ssl_scan_<target>_<port>.txt
│
├── evidence/
│   └── <target>/
│       ├── ssh_vulnerable_ciphers.txt
│       ├── ssl_vulnerable_port_<port>.txt
│       └── nmap_ssh_ports.txt
│
└── screenshots/
    └── <target>/
        ├── ssh_vulnerable_ciphers.png
        └── ssl_vulnerable_port_<port>.png
```

---

## Evidence Extraction

The extraction logic filters raw tool output down to what actually matters for a report.

**SSH** — from ssh-audit, it pulls only lines flagged as algorithms to remove or change:

```python
if any(pattern in line for pattern in [
    'kex algorithm to remove',
    'mac algorithm to remove',
    'key algorithm to remove',
    'key algorithm to change'
]):
    extracted.append(line)
```

ANSI color codes are intentionally preserved — no `.strip()` — so the rendered screenshots retain the color coding from ssh-audit's output.

**SSL/TLS** — from testssl.sh output, three sections are extracted:
- Deprecated protocols offered (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- CBC ciphers, grouped by TLS version header
- Vulnerabilities section, filtered to `VULNERABLE` lines only (BEAST, SWEET32, POODLE, etc.)

---

## Screenshots

Evidence files are rendered to PNG using **Pillow**. The renderer parses ANSI escape codes and maps them to colors, preserving the visual output of terminal tools — useful when screenshots go directly into a report without modification.

```python
ansi_colors = {
    '\033[0m':    '#ffffff',
    '\033[1;32m': '#00ff00',
    '\033[1;31m': '#ff0000',
    '\033[1;33m': '#ffff00',
    '\033[0;31m': '#ff6b6b',
    '\033[0;33m': '#ffd93d',
    '\033[0;36m': '#6bcfff',
    '\033[4m':    '#ffffff',
}
```

Output resolution: 1700×902 at 254 DPI. Font: DejaVu Sans Mono (falls back to default if not available).

---

## Report Mode

Running with `-m r` triggers `recap()`, which auto-detects all `*_Scans` directories in the current working directory and produces a consolidated `audit_report.txt` without re-running any scans.

```bash
sudo python3 NetAuditor.py -m r
```

The report summarizes:

| Section | Content |
|---|---|
| SSH | IP, port, product/version for each SSH service found |
| HTTP | IP and port for each HTTP service |
| SSL Vulnerabilities | Per-target:port — BEAST, SWEET32, POODLE, CBC obsolete |
| Weak Protocols | SSLv2, SSLv3, TLS 1.0, TLS 1.1 offered per endpoint |

Useful when scanning a batch of targets in one session and needing a quick summary before going into detail.

---

## Usage

```bash
# Single target
sudo python3 NetAuditor.py -t TARGET_IP

# Batch file
sudo python3 NetAuditor.py -f targets.txt

# Custom ports and nmap arguments
sudo python3 NetAuditor.py -t TARGET_IP -p 1-1000 -a "--min-rate 500 -sV"

# Report only (from existing scan directories)
sudo python3 NetAuditor.py -m r
```

Root is required for nmap SYN scans and service detection.

---

## Dependencies

```bash
sudo apt install -y nmap ssh-audit
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
sudo ln -s $(pwd)/testssl.sh/testssl.sh /usr/local/bin/testssl
pip3 install python-nmap Pillow --break-system-packages
```

Then apply the python-nmap patch described above.

---

> **Disclaimer:** For educational purposes and authorized security assessments only. Always obtain explicit written permission before scanning any system you do not own.
