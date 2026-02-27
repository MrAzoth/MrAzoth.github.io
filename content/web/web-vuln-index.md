---
title: "Web Application Penetration Testing — Master Index"
date: 2026-02-24
draft: false
---

# Web Application Penetration Testing — Master Index

> Ordered by WAPT workflow: start from input fields → auth → authz → upload → server-side → client-side → infrastructure → API.
> 76 chapters. All published.

---

## 001 — INPUT: User-Controlled Fields & Parameters
*First thing you test: every field that sends data to the server.*

| File | Vulnerability |
|------|---------------|
| `001_INPUT_SQLi.md` | SQL Injection (Error-based, Union, Blind, Time-based, OOB) |
| `002_INPUT_NoSQLi.md` | NoSQL Injection (MongoDB, CouchDB, Redis) |
| `003_INPUT_LDAP_Injection.md` | LDAP Injection |
| `004_INPUT_XPath_Injection.md` | XPath Injection |
| `005_INPUT_XQuery_Injection.md` | XQuery Injection |
| `006_INPUT_CMDi.md` | OS Command Injection |
| `007_INPUT_SSTI.md` | Server-Side Template Injection (SSTI) |
| `008_INPUT_CSTI.md` | Client-Side Template Injection (CSTI) |
| `009_INPUT_SSI_Injection.md` | Server-Side Includes (SSI) Injection |
| `010_INPUT_EL_Injection.md` | Expression Language Injection (EL) |
| `011_INPUT_XXE.md` | XML External Entity (XXE) |
| `012_INPUT_Log4Shell.md` | Log4j / Log Injection (Log4Shell) |
| `013_INPUT_Mail_Injection.md` | IMAP/SMTP Header Injection |
| `014_INPUT_HTTP_Header_Injection.md` | HTTP Header Injection / Response Splitting |
| `015_INPUT_HTTP_Param_Pollution.md` | HTTP Parameter Pollution (HPP) |
| `016_INPUT_Open_Redirect.md` | Open Redirect |
| `017_INPUT_Host_Header.md` | Host Header Attacks |
| `018_INPUT_GraphQL_Injection.md` | GraphQL Injection (SQLi/CMDi/SSRF via resolvers) |
| `019_INPUT_Integer_Type_Juggling.md` | Integer Overflow / Type Juggling |
| `020_INPUT_XSS_Reflected.md` | Cross-Site Scripting — Reflected |
| `021_INPUT_XSS_Stored.md` | Cross-Site Scripting — Stored |
| `022_INPUT_XSS_DOM.md` | Cross-Site Scripting — DOM |
| `023_INPUT_XSS_Blind.md` | Cross-Site Scripting — Blind |

---

## 030 — AUTH: Authentication
*Login page, tokens, MFA, password reset.*

| File | Vulnerability |
|------|---------------|
| `030_AUTH_Brute_Force.md` | Brute Force & Credential Stuffing |
| `031_AUTH_Username_Enum.md` | Username Enumeration |
| `032_AUTH_Timing_Attacks.md` | Timing Attacks on Auth |
| `033_AUTH_Default_Creds.md` | Default Credentials |
| `034_AUTH_JWT.md` | JWT Attacks (alg:none, weak secret, kid injection) |
| `035_AUTH_OAuth.md` | OAuth 2.0 Misconfigurations |
| `036_AUTH_SAML.md` | SAML Attacks |
| `037_AUTH_OIDC.md` | OIDC / OpenID Connect Flaws |
| `038_AUTH_Password_Reset_Poisoning.md` | Password Reset Poisoning |
| `039_AUTH_MFA_Bypass.md` | MFA Bypass Techniques |

---

## 040 — SESSION: Session Management
*Cookie handling, fixation, state confusion.*

| File | Vulnerability |
|------|---------------|
| `040_SESSION_Fixation.md` | Session Fixation |
| `041_SESSION_Puzzling.md` | Session Puzzling / Session Confusion |

---

## 050 — AUTHZ: Authorization & Business Logic
*Who can access what — IDOR, privilege escalation, logic flaws.*

| File | Vulnerability |
|------|---------------|
| `050_AUTHZ_IDOR.md` | Insecure Direct Object Reference (IDOR / BOLA) |
| `051_AUTHZ_BFLA.md` | Broken Function Level Authorization (BFLA) |
| `052_AUTHZ_Mass_Assignment.md` | Mass Assignment |
| `053_AUTHZ_Race_Conditions.md` | Race Conditions |
| `054_AUTHZ_Business_Logic.md` | Business Logic Flaws |

---

## 060 — UPLOAD: File & Archive Upload
*Any endpoint that accepts files.*

| File | Vulnerability |
|------|---------------|
| `060_UPLOAD_File_Upload_Bypass.md` | File Upload Bypass |
| `061_UPLOAD_Zip_Slip.md` | Zip Slip / Archive Path Traversal |
| `062_UPLOAD_XXE_Binary_Formats.md` | XXE via Binary Formats (XLSX, SVG, DOCX) |

---

## 070 — SERVER: Server-Side Vulnerabilities
*SSRF, path traversal, deserialization — server trusts attacker-controlled data.*

| File | Vulnerability |
|------|---------------|
| `070_SERVER_SSRF.md` | Server-Side Request Forgery (SSRF) |
| `071_SERVER_Path_Traversal.md` | Path Traversal / Directory Traversal |
| `072_SERVER_File_Inclusion_LFI_RFI.md` | File Inclusion (LFI / RFI) |
| `073_SERVER_Deser_Java.md` | Insecure Deserialization — Java |
| `074_SERVER_Deser_PHP.md` | Insecure Deserialization — PHP |
| `075_SERVER_Deser_Python.md` | Insecure Deserialization — Python (Pickle) |
| `076_SERVER_Deser_DotNet.md` | Insecure Deserialization — .NET |
| `077_SERVER_Deser_NodeJS.md` | Insecure Deserialization — Node.js |
| `078_SERVER_Proto_Pollution.md` | Prototype Pollution — Server-Side (Node.js) |

---

## 080 — CLIENT: Client-Side Attacks
*Attacks that execute in the victim's browser.*

| File | Vulnerability |
|------|---------------|
| `080_CLIENT_CSRF.md` | Cross-Site Request Forgery (CSRF) |
| `081_CLIENT_Clickjacking.md` | Clickjacking |
| `082_CLIENT_CORS.md` | CORS Misconfiguration |
| `083_CLIENT_postMessage.md` | postMessage Attacks |
| `084_CLIENT_DOM_Clobbering.md` | DOM Clobbering |
| `085_CLIENT_Proto_Pollution.md` | Prototype Pollution — Client-Side |
| `086_CLIENT_WebSocket.md` | WebSocket Attacks |

---

## 090 — REQUEST: Request-Level Manipulation
*HTTP protocol abuse — smuggling, cache attacks.*

| File | Vulnerability |
|------|---------------|
| `090_REQUEST_HTTP1_Smuggling.md` | HTTP Request Smuggling (CL.TE / TE.CL / TE.TE) |
| `091_REQUEST_HTTP2_Smuggling.md` | HTTP/2 Request Smuggling (H2.CL / H2.TE) |
| `092_REQUEST_HTTP2_RapidReset.md` | HTTP/2 Rapid Reset (CVE-2023-44487) |
| `093_REQUEST_Cache_Poisoning.md` | Web Cache Poisoning |
| `094_REQUEST_Cache_Deception.md` | Web Cache Deception |

---

## 100 — INFRA: Infrastructure & Configuration
*DNS, cloud storage, containers, exposed services.*

| File | Vulnerability |
|------|---------------|
| `100_INFRA_Subdomain_Takeover.md` | Subdomain Takeover |
| `101_INFRA_DNS_Rebinding.md` | Dangling DNS / DNS Rebinding |
| `102_INFRA_Cloud_Storage.md` | S3 / Cloud Storage Misconfigurations |
| `103_INFRA_Kubernetes.md` | Kubernetes API Exposure |
| `104_INFRA_Docker.md` | Docker API Exposure |
| `105_INFRA_Admin_Interfaces.md` | Exposed Admin Interfaces (Actuator, Kibana, etc.) |
| `106_INFRA_Security_Headers.md` | Security Headers Misconfiguration |

---

## 110 — API: API-Specific Testing
*REST, GraphQL, gRPC, WebSocket — protocol-level issues.*

| File | Vulnerability |
|------|---------------|
| `110_API_REST.md` | REST API — BOLA / BFLA / Mass Assignment |
| `111_API_GraphQL_Full.md` | GraphQL (Introspection, Batching, Alias, Directive) |
| `112_API_gRPC.md` | gRPC Security Testing |
| `113_API_WebSockets_Deep.md` | WebSockets Security (Deep Dive) |
| `114_API_Key_Leakage.md` | API Key Leakage & Token Exposure |
| `115_API_Shadow_Zombie.md` | API Security — Shadow/Zombie APIs |

---

> **Workflow reminder**: INPUT → AUTH → SESSION → AUTHZ → UPLOAD → SERVER → CLIENT → REQUEST → INFRA → API
> Start with what the app exposes directly (input fields), work inward toward infrastructure.
> Oh yes, low hanging fruit first :')
