---
title: "SMBGhost — CVE-2020-0796"
date: 2026-02-24
draft: false
---

## Overview

CVE-2020-0796, commonly known as SMBGhost (also referred to as CoronaBlue or EternalDarkness), is a pre-authentication remote code execution vulnerability in the SMBv3 (Server Message Block version 3.1.1) compression handling subsystem of the Windows TCP/IP network stack. With a CVSS score of 10.0, it affects Windows 10 versions 1903 and 1909, and the Windows Server Semi-Annual Channel releases version 1903 and 1909.

This vulnerability is wormable — it can propagate without user interaction, similar to EternalBlue (MS17-010). Unlike EternalBlue, SMBGhost targets a newer protocol version and requires no prior knowledge of the target system.

---

## Affected Versions

| OS | Build | Vulnerable |
|----|-------|-----------|
| Windows 10 1903 | 18362 | Yes |
| Windows 10 1909 | 18363 | Yes |
| Windows Server, version 1903 (SAC) | 18362 | Yes |
| Windows Server, version 1909 (SAC) | 18363 | Yes |
| Windows 10 20H1 | 19041+ | Not affected (patched in release) |
| Windows 10 1809 | 17763 | Not affected — SMBv3.1.1 compression not present |
| Windows Server 2019 LTSC | 17763 | Not affected — SMBv3.1.1 compression not present |
| Windows 10 1803 and earlier | — | Not affected |

> **Windows Server 2019 LTSC clarification:** Windows Server 2019 (LTSC, build 17763) is **NOT vulnerable**. It does not implement SMBv3.1.1 compression. The vulnerable "Windows Server 2019" entries in some early advisories refer specifically to Windows Server **Semi-Annual Channel (SAC)** releases version 1903 (build 18362) and version 1909 (build 18363) — which are entirely distinct products from Server 2019 LTSC despite the similar naming.
>
> **Windows 10 1809 note:** Build 17763 (1809) is also NOT vulnerable — SMBv3.1.1 compression capability was introduced in build 18362 (1903). Systems running 1809 will not respond to the compression negotiate context.

---

## Technical Vulnerability Analysis

### SMBv3 Compression Handling

SMBv3.1.1 introduced compression for NEGOTIATE messages. The vulnerable code path exists in `srv2.sys`, the kernel-mode SMBv3 driver. When a client sends an SMB2 `NEGOTIATE` packet with the `CompressionCapabilities` negotiate context enabled, the server processes the compressed payload in kernel mode.

The core bug is an **integer overflow** in the function responsible for decompressing the payload:

1. The `OriginalCompressedSegmentSize` field in the `SMB2_COMPRESSION_TRANSFORM_HEADER` is a 32-bit unsigned integer
2. The addition of `OriginalCompressedSegmentSize + Offset` can overflow to a small value
3. This overflow leads to an under-allocation of the buffer
4. When the decompressed data is copied into the undersized buffer, a **heap buffer overflow** occurs in kernel space

### The SMB2 Compression Transform Header

```
typedef struct _SMB2_COMPRESSION_TRANSFORM_HEADER {
    UINT32 ProtocolId;              // 0xFC534D42 ("\xfcSMB")
    UINT32 OriginalCompressedSegmentSize; // BUG: this + Offset can overflow
    UINT16 CompressionAlgorithm;
    UINT16 Flags;
    UINT32 Offset;
} SMB2_COMPRESSION_TRANSFORM_HEADER;
```

The vulnerable calculation (pseudocode from decompiled `srv2.sys`):

```c
// In the decompression handler:
ULONG decompressed_size = header->OriginalCompressedSegmentSize;
ULONG offset = header->Offset;

// This addition can overflow a 32-bit integer
ULONG alloc_size = decompressed_size + offset;  // OVERFLOW HERE

// Buffer is allocated with the (potentially small) overflowed size
void* buffer = ExAllocatePoolWithTag(NonPagedPool, alloc_size, 'SMBS');

// But the copy uses the full OriginalCompressedSegmentSize
// → heap overflow
memcpy(buffer, source, decompressed_size);  // OVERFLOW → kernel heap corruption
```

This is a **pre-auth** kernel heap overflow. An attacker sends a specially crafted compressed SMB2 NEGOTIATE packet and triggers the overflow without any credentials or session establishment.

### Why it is Wormable

- No authentication required
- Port 445 is the attack vector (SMB, widely open on internal networks)
- Kernel-mode execution (SYSTEM privileges immediately)
- No user interaction needed
- Can be triggered with a single packet

---

## Exploitation Reference

For actual exploitation PoC, refer to the public reference implementation:

- **PoC reference:** https://github.com/jamf/CVE-2020-0796-RCE-POC/blob/master/SMBleedingGhost.py

This PoC demonstrates the full kernel heap overflow exploitation path for CVE-2020-0796. Use only in authorized lab environments against vulnerable target builds (Windows 10 1903/1909, build 18362/18363 without KB4551762).

---

## Detection

### Nmap Script

```bash
# Detect SMBGhost using nmap script
nmap -p 445 --script smb2-security-mode,smb-vuln-cve-2020-0796 TARGET_IP

# More aggressive check
nmap -p 445 -sV --script "smb-vuln-*" TARGET_IP

# Scan a network range
nmap -p 445 --script smb-vuln-cve-2020-0796 192.168.1.0/24 --open
```

### Python Detection Script

```python
#!/usr/bin/env python3
"""
CVE-2020-0796 SMBGhost detection — checks for SMBv3 compression support
No crash or exploitation — safe detection only
"""
import socket
import struct
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
PORT = 445

# Crafted SMB2 NEGOTIATE with CompressionCapabilities context
# This is the detection packet — it does NOT trigger the vulnerability
SMB2_NEGOTIATE = bytes([
    # NetBIOS Session Service header
    0x00, 0x00, 0x00, 0xc0,
    # SMB2 Header
    0xfe, 0x53, 0x4d, 0x42,  # ProtocolId
    0x40, 0x00,              # StructureSize
    0x00, 0x00,              # CreditCharge
    0x00, 0x00, 0x00, 0x00,  # Status
    0x00, 0x00,              # Command: NEGOTIATE
    0x1f, 0x00,              # CreditRequest
    0x00, 0x00, 0x00, 0x00,  # Flags
    0x00, 0x00, 0x00, 0x00,  # NextCommand
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # MessageId
    0x00, 0x00, 0x00, 0x00,  # Reserved
    0x00, 0x00, 0x00, 0x00,  # TreeId
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # SessionId
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature cont
    # SMB2 NEGOTIATE body
    0x24, 0x00,              # StructureSize = 36
    0x02, 0x00,              # DialectCount = 2
    0x01, 0x00,              # SecurityMode
    0x00, 0x00,              # Reserved
    0x7f, 0x00, 0x00, 0x00,  # Capabilities
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # ClientGuid
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # ClientGuid cont
    0x00, 0x00, 0x00, 0x00,  # NegotiateContextOffset
    0x00, 0x00,              # NegotiateContextCount
    0x00, 0x00,              # Reserved2
    # Dialects: SMB2.1 + SMB3.1.1
    0x02, 0x02,              # SMB 2.0.2
    0x11, 0x03,              # SMB 3.1.1
])

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((TARGET, PORT))
    s.send(SMB2_NEGOTIATE)
    raw = s.recv(1024)
    s.close()

    if len(raw) < 4:
        print(f"[-] No response from {TARGET}:{PORT}")
        sys.exit(1)

    # Parse response
    if len(raw) > 72:
        # Check if server responded with SMB2 NEGOTIATE response
        dialect = struct.unpack('<H', raw[72:74])[0] if len(raw) > 74 else 0
        print(f"[*] Negotiated dialect: 0x{dialect:04X}")

        if dialect == 0x0311:
            print(f"[+] SMBv3.1.1 supported — check for compression support")
            # Check negotiate contexts for compression
            if b'\x03\x00' in raw:  # CompressionCapabilities context type
                print(f"[!] POTENTIALLY VULNERABLE: SMBv3 compression context present")
                print(f"    Host: {TARGET}")
                print(f"    Verify with: nmap --script smb-vuln-cve-2020-0796 {TARGET}")
            else:
                print(f"[-] SMBv3.1.1 but no compression context in response")
        else:
            print(f"[-] Server did not negotiate SMBv3.1.1")
    else:
        print(f"[-] Unexpected response length: {len(raw)}")

except Exception as e:
    print(f"[-] Error: {e}")
```

### Wireshark Filter

```
# Capture SMBGhost-related traffic
# Filter for SMB2 with compression transform header (magic 0xFC534D42)
frame[0:4] == fc:53:4d:42

# Alternative: filter on port and look for compression header
tcp.port == 445 && data[0:4] == fc:53:4d:42

# Normal SMB2 negotiate filter
tcp.port == 445 && smb2.cmd == 0

# Detection: look for NEGOTIATE with CompressionCapabilities context (type 0x0003)
smb2.negotiate_context_type == 3
```

### PowerShell Detection (from the target)

```powershell
# Check if the machine is vulnerable (run on suspected target)
Get-HotFix -Id KB4551762
# If KB4551762 is NOT listed, the machine is likely vulnerable

# Check Windows version
[System.Environment]::OSVersion.Version
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR

# Check SMB compression state
Get-SmbServerConfiguration | Select EnableSMBQuIC,DisableCompression

# If DisableCompression is False and build is 18362/18363, potentially vulnerable
```

---

## Patch Information

| Patch | KB Article | Release Date |
|-------|-----------|--------------|
| Primary fix | KB4551762 | March 12, 2020 |
| Windows 10 1903 | Build 18362.720 | March 2020 CU |
| Windows 10 1909 | Build 18363.720 | March 2020 CU |

```powershell
# Apply patch (Windows Update)
wuauclt /detectnow
wuauclt /updatenow

# Or via PowerShell
Install-Module PSWindowsUpdate
Get-WindowsUpdate -KBArticleID KB4551762 -Install

# Workaround (if patching is not immediately possible)
# Disable SMBv3 compression on SERVER side
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Type DWORD -Value 1 -Force

# Workaround on CLIENT side
Set-SmbClientConfiguration -DisableCompression $true

# Verify workaround applied
Get-SmbServerConfiguration | Select DisableCompression
```

---

## Lateral Movement Implications

SMBGhost in a corporate environment is particularly dangerous because:

1. **No credentials required** — exploitation works pre-authentication
2. **SYSTEM privileges** — immediate full OS control with no privilege escalation needed
3. **Wormable** — the exploit can be packaged to auto-propagate to all SMBv3.1.1 hosts
4. **Port 445 is open everywhere** — SMB is fundamental to Windows domain environments
5. **AV evasion** — kernel-level shellcode runs before most AV hooks

### Attack Scenario

```
1. External/Internal foothold obtained
   └─ Initial access via phishing, VPN credential, etc.

2. Network scan for vulnerable hosts
   └─ nmap -p 445 --script smb-vuln-cve-2020-0796 10.0.0.0/8

3. Exploitation
   └─ Send crafted SMB2 NEGOTIATE packet
   └─ Heap overflow in kernel → SYSTEM execution
   └─ Stage shellcode / Meterpreter in kernel context

4. Credential harvesting (SYSTEM)
   └─ Mimikatz (lsadump::sam, sekurlsa::logonpasswords)
   └─ DCSync (if DC is reached)

5. Lateral movement
   └─ Pass-the-Hash with harvested NTLM hashes
   └─ Use the same exploit against remaining vulnerable hosts
   └─ Move to DC → full domain compromise
```

---

## Relation to EternalDarkness

"EternalDarkness" is an informal name sometimes used for CVE-2020-0796, drawing a parallel to EternalBlue (CVE-2017-0144 / MS17-010):

| Property | EternalBlue (MS17-010) | SMBGhost (CVE-2020-0796) |
|----------|----------------------|--------------------------|
| Protocol | SMBv1 | SMBv3.1.1 |
| Bug class | Integer overflow → pool overflow | Integer overflow → heap overflow |
| Pre-auth | Yes | Yes |
| Wormable | Yes | Yes |
| CVSS | 9.3 | 10.0 |
| Affected OS | XP, Vista, 7, Server 2003-2008 R2 | Win 10 1903/1909; Server SAC 1903/1909 (NOT Server 2019 LTSC) |
| Used by | WannaCry, NotPetya, EternalBlue Metasploit | PoC exploits, targeted attacks |
| Patch | MS17-010 | KB4551762 |

Key difference: SMBGhost requires the **compression feature** (only in SMBv3.1.1), whereas EternalBlue exploited **SMBv1** which had even broader deployment.

---

## Hardening and Detection

### Network-Level Mitigations

```bash
# Block SMB at perimeter firewall — CRITICAL
# Port 445 (TCP/UDP) and 139 (TCP) should NEVER be exposed to the internet

# Windows Firewall (PowerShell) — block inbound SMB from untrusted networks
New-NetFirewallRule -DisplayName "Block SMB Inbound" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block -Enabled True

# For domain environments: restrict SMB to specific subnets
New-NetFirewallRule -DisplayName "Allow SMB from Domain Only" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress "10.0.0.0/8,192.168.0.0/16" -Action Allow
```

### Detection Rules

```yaml
# Sigma rule for SMBGhost exploitation attempt
title: SMBGhost CVE-2020-0796 Exploitation Attempt
id: smb-ghost-detect
status: experimental
description: Detects suspicious SMB connections that may indicate CVE-2020-0796 exploitation
logsource:
  category: network
  product: windows
detection:
  selection:
    dst_port: 445
    network_protocol: tcp
  condition: selection
level: low

---

# Snort rule
# alert tcp any any -> any 445 (msg:"CVE-2020-0796 SMBGhost Compression Header"; content:"|fc 53 4d 42|"; offset:4; depth:4; sid:9000796; rev:1;)
```

### Summary

- CVE-2020-0796 is a kernel-level pre-auth RCE with CVSS 10.0
- Affects Windows 10 1903/1909 and Windows Server SAC versions 1903/1909 (NOT Server 2019 LTSC)
- Root cause is integer overflow in SMBv3.1.1 compression decompression
- Fix: KB4551762 (March 2020) or disable compression as a workaround
- High lateral movement potential in corporate Windows environments
- Never expose port 445 to untrusted networks


---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.