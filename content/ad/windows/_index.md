---
title: "AD — From Windows"
description: "Active Directory attacks from a Windows foothold."
---

Attacking Active Directory from Windows means you already have a foothold — a domain-joined machine, a shell, or stolen credentials. The toolset includes **PowerView**, **Rubeus**, **Mimikatz**, **SharpHound**, **Certify**, **Seatbelt**, and PowerShell AD cmdlets.

Windows-based attacks are often faster and stealthier — you operate from within the domain, with access to Kerberos natively, and can leverage LOLBAS (Living Off the Land Binaries and Scripts) to reduce tool footprint.

---

| Topic | File |
|---|---|
| Enumeration & Discovery | [enumeration](/ad/windows/enumeration/) |
| Kerberos Attacks | [kerberos-attacks](/ad/windows/kerberos-attacks/) |
| Credential Attacks | [credential-attacks](/ad/windows/credential-attacks/) |
| Delegation Attacks | [delegation-attacks](/ad/windows/delegation-attacks/) |
| Lateral Movement | [lateral-movement](/ad/windows/lateral-movement/) |
| Domain & Forest Trusts | [domain-trusts](/ad/windows/domain-trusts/) |
| Persistence | [persistence](/ad/windows/persistence/) |

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
