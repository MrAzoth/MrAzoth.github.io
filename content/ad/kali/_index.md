---
title: "AD — From Kali / Linux"
description: "Active Directory attacks from a Linux/Kali attacker machine."
---

Attacking Active Directory from Linux means operating remotely — typically with no domain-joined machine. The toolset revolves around **Impacket**, **NetExec (nxc)**, **BloodHound-python**, **Certipy**, **Kerbrute**, and **Responder**.

The main constraint is that you cannot run Windows-native tools directly — but nearly every critical attack has a Python/Linux equivalent.

---

| Topic | File |
|---|---|
| Enumeration & Discovery | [enumeration](/ad/kali/enumeration/) |
| Kerberos Attacks | [kerberos-attacks](/ad/kali/kerberos-attacks/) |
| Credential Attacks & Relay | [credential-attacks](/ad/kali/credential-attacks/) |
| Delegation Attacks | [delegation-attacks](/ad/kali/delegation-attacks/) |
| Lateral Movement | [lateral-movement](/ad/kali/lateral-movement/) |
| Domain & Forest Trusts | [domain-trusts](/ad/kali/domain-trusts/) |
| Persistence | [persistence](/ad/kali/persistence/) |

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.
