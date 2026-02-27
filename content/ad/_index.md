---
title: "Active Directory"
description: "Active Directory attack techniques — enumeration, exploitation, persistence."
---

Active Directory (AD) remains one of the most targeted environments in enterprise networks. This section covers offensive AD techniques from initial enumeration to full domain compromise, organized by attacker platform.

The same attack often looks very different depending on whether you are operating from a **Linux/Kali** machine (remote, unauthenticated or with stolen credentials) or from a **Windows** foothold (on-domain, local admin, or higher privileges). Understanding both perspectives is essential for both red teamers and defenders.

---

| Section | Description |
|---|---|
| **[From Kali / Linux](/ad/kali/)** | Remote enumeration and exploitation using Impacket, BloodHound, NetExec, Certipy and other Linux-native tools |
| **[From Windows](/ad/windows/)** | On-host attacks using PowerView, Rubeus, Mimikatz, SharpHound, and living-off-the-land techniques |

---

> **Disclaimer:** For educational purposes only. Unauthorized access to computer systems is illegal.

---

## Further Reading

These notes are personal field references. For broader coverage, authoritative community resources:

| Resource | Description |
|---|---|
| WADComs | Interactive cheat sheet — filter by OS, service, attack type, and what you have |
| HackTricks — AD Methodology | Comprehensive AD attack methodology reference |
| HackTricks — Pentesting AD | LDAP and AD enumeration techniques |
| AD Mindmap (SVG) | Full Active Directory attack mindmap — open in browser or Excalidraw |
