# Static PE Analyzer + PEB Walker

A personal study project on Windows internals — PE file format parsing and runtime process inspection via PEB walking.

Built as a learning exercise to understand how Windows loads and maps executables, how the loader tracks modules in memory, and how tools like debuggers and AV engines inspect processes.

---

## What it does

### Static Analysis (file on disk)
Parses the raw PE file using file mapping, without executing it:

- DOS Header (`e_magic`, `e_lfanew`)
- NT Headers (Signature, Machine, NumberOfSections, TimeDateStamp, ImageBase, EntryPoint)
- Section Headers (`.text`, `.rdata`, `.data`, `.idata`... with VirtualAddress, VirtualSize, RawOffset)
- Import Table — walks `IMAGE_IMPORT_DESCRIPTOR` → `IMAGE_THUNK_DATA64`, handles both named imports and ordinals
- Export Table — walks `IMAGE_EXPORT_DIRECTORY`, prints function names and their RVAs

### Dynamic Analysis — PEB Walking (target process)
Launches the target executable in a suspended state, resumes briefly to let `ntdll` initialize the PEB, then reads its memory:

- `BeingDebugged` flag
- `ImageBase` address
- `ProcessParameters` → `ImagePathName` and `CommandLine`
- Full `Ldr` module list walk via `InMemoryOrderModuleList` → prints base address, size and name of every loaded DLL

All remote memory is read via `ReadProcessMemory` — every pointer resolved from the PEB is valid in the **target process address space**, not the analyzer's.

---

## Sample output

```
Write the path of the PE :
C:\...\Basic_1.exe

=== DOS HEADER ===
DOS HEADER -> e_magic : 5a4d
DOS HEADER -> e_lfanew : 248

=== NT HEADERS ===
NT HEADER Signature -> Signature: 4550
NT HEADER FileHeader -> Machine: 8664
NT HEADER FileHeader -> NumberOfSections : 9
NT HEADER OptionalHeader -> ImageBase: 140000000
NT HEADER OptionalHeader -> AddressOfEntryPoint: 1041
Import Table RVA: e390
Export Table RVA: 0

=== SECTIONS header ===
[.text]    VirtualAddress: 0x1000  VirtualSize: 0x77af  RawOffset: 0x400
[.rdata]   VirtualAddress: 0x9000  VirtualSize: 0x2e0e  RawOffset: 0x7c00
[.data]    VirtualAddress: 0xc000  VirtualSize: 0x4b0   RawOffset: 0xac00
[.idata]   VirtualAddress: 0xe000  VirtualSize: 0xe55   RawOffset: 0xb800
...

=== IMPORT TABLE ===
  [KERNEL32.dll]
    -> CloseHandle
    -> CreateProcessW
    -> IsDebuggerPresent
    ...
  [ucrtbased.dll]
    -> _cexit
    -> exit
    ...

[+] Process created with PID: 9392
[+] PEB Address of target: 0xd578f52000

=== PEB ===
  BeingDebugged  : 0
  ImageBase      : 0x7ff65c810000

=== ProcessParameters ===
  ImagePathName : C:\...\Basic_1.exe
  CommandLine   : "C:\...\Basic_1.exe"

=== Loaded Modules (InMemoryOrder) ===
  Base: 0x7ff65c810000  Size: 0x13000   Name: Basic_1.exe
  Base: 0x7ffbe0b20000  Size: 0x268000  Name: ntdll.dll
  Base: 0x7ffbdf490000  Size: 0xc9000   Name: KERNEL32.DLL
  Base: 0x7ffbde020000  Size: 0x3f1000  Name: KERNELBASE.dll
  Base: 0x7ffb22200000  Size: 0x30000   Name: VCRUNTIME140D.dll
  Base: 0x7ffb0c050000  Size: 0x204000  Name: ucrtbased.dll
  Base: 0x7ffbdf560000  Size: 0xa6000   Name: sechost.dll

[+] Process terminated.
```

---

## Key concepts covered

**RVA vs raw file offset** — Data Directories store RVAs (valid in memory), but the file on disk uses different alignment. `RvaToOffset()` converts between the two by scanning Section Headers for the containing section, then applying `RVA - VirtualAddress + PointerToRawData`.

**INT vs IAT** — `OriginalFirstThunk` (Import Name Table) holds function names and is never modified. `FirstThunk` (Import Address Table) is overwritten by the Windows loader with real function addresses at load time. On disk both point to the same data.

**Ordinals vs named imports** — Each `IMAGE_THUNK_DATA64` entry uses the highest bit as a flag: `1` means the lower 16 bits are an ordinal number, `0` means the value is an RVA pointing to `IMAGE_IMPORT_BY_NAME`.

**PEB structure** — `winternl.h` exposes an intentionally incomplete PEB. The full layout is defined manually with correct 64-bit offsets (including the 4-byte padding at `0x04` required for pointer alignment).

**Remote memory reading** — Every pointer read from the target PEB is valid in the **target's address space**. Following it requires a new `ReadProcessMemory` call — you cannot dereference it directly.

**Circular doubly-linked list** — The module list is a `LIST_ENTRY` ring. `Flink` points to the next `InMemoryOrderLinks` field inside the next `LDR_DATA_TABLE_ENTRY`, not to the start of the structure. `CONTAINING_RECORD` (or manual `- offsetof(...)`) recovers the struct base.

---

## PE fields — red team & evasion relevance

### `e_magic` / `e_lfanew` — DOS Header
Every PE starts with `MZ` (`0x5A4D`). Security tools validate this signature as a first sanity check. `e_lfanew` points to the NT Headers — malware sometimes corrupts or shifts this value to break naive parsers while still loading correctly under Windows, since the loader itself is more permissive than most AV parsers.

### `TimeDateStamp` — File Header
Records when the binary was compiled. Defenders use this to correlate samples, identify build infrastructure, and cluster malware families. Red teamers routinely stomp this field (set it to `0` or a fake date) to break timeline analysis and attribution. Tools like `pe-bear` or a simple hex editor can modify it post-compilation.

### `Machine` — File Header
Identifies the target architecture (`0x8664` = x64, `0x14c` = x86). Relevant when staging payloads — dropping the wrong architecture on a target silently fails. Also used by EDRs to validate that a loaded image matches the process bitness, a check that shellcode loaders sometimes abuse.

### `ImageBase` — Optional Header
The preferred load address. If the address is available, Windows loads the image there with no relocations. If not (ASLR), it relocates and patches all absolute addresses using the `.reloc` section. Malware that disables ASLR (`DllCharacteristics` without `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`) gets a predictable load address — useful for ROP chains and shellcode that hardcodes offsets.

### `AddressOfEntryPoint` — Optional Header
Where execution begins after the loader hands off control. This is not necessarily `main()` — it points to the CRT startup stub. Red teamers patching a binary (e.g. adding a malicious section) redirect this field to their shellcode, then optionally jump back to the original entry point to keep the host process functional. EDRs hook this address to intercept execution before any user code runs.

### `DataDirectory[IMPORT]` — Import Table
Lists every DLL the binary needs and every function it calls by name. This is the primary signal used by static AV and sandboxes to flag suspicious binaries — importing `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread` together is a classic injection pattern. Evasion techniques include:
- **Import obfuscation** — resolving functions at runtime with `GetProcAddress` + `LoadLibrary` so they don't appear in the static import table
- **API hashing** — storing a hash of the function name instead of the name itself, resolving at runtime
- **Direct syscalls** — bypassing the import mechanism entirely and calling `ntdll` syscall stubs directly, avoiding userland hooks

### `DataDirectory[EXPORT]` — Export Table
Relevant mainly for DLLs. A malicious DLL masquerading as a legitimate one (DLL hijacking, DLL proxying) must export the same function names as the original — otherwise the host application fails to load. Checking the export table of a suspicious DLL reveals whether it properly proxies calls or is a hollow replacement.

### Section Headers — names, flags, entropy
`.text` should contain code and be executable but not writable. `.data` should be writable but not executable. Sections that are both writable and executable (`IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE`) are a strong indicator of packed or injected code — the packer writes the real payload at runtime then executes it. High entropy in any section (close to 8.0) indicates compression or encryption, another packer signature. EDRs and tools like `DIE` (Detect-It-Easy) flag these patterns automatically.

### `BeingDebugged` — PEB
The simplest anti-debug check. Malware reads this byte directly from the PEB (same technique used here) and exits or changes behavior if it is non-zero. A debugger sets this flag when attaching. Bypasses include patching the byte to `0` at runtime or using plugins like `ScyllaHide` that transparently clear it.

### `InMemoryOrderModuleList` — PEB Ldr
The ground truth of what is loaded in a process. Red teamers use this list to manually resolve API addresses without calling `GetProcAddress` (which is itself hooked by EDRs) — walk the list, find `ntdll.dll` or `KERNEL32.DLL` by name hash, then parse its export table directly. This technique, known as **PEB walking**, is a staple of shellcode and reflective loaders precisely because it avoids any hooked API.

### `ProcessParameters` — PEB
Contains `CommandLine` and `ImagePathName` as seen by the process itself. These can be spoofed — process hollowing and process doppelgänging techniques create a process with a benign image path in `ProcessParameters` while the actual code running is something else entirely. EDRs that rely only on `ProcessParameters` for process identity can be deceived; cross-referencing with the actual mapped image is required.

---

## Further reading

- [Microsoft PE Format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [PE File Format — annotated walkthrough](https://blog.kowalczyk.info/articles/pefileformat.html)
