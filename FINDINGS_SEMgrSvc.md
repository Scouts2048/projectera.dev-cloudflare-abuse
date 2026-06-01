# Malware Analysis — `SEMgrSvc.exe` (Stage-2 AntiVM Loader)

**Analyst date:** 2026-06-01
**Sample:** `C:\ProgramData\SEMgrSvc.exe` (the payload downloaded by `MSY.bat` from
`https://mscloudresolver.com/ad.txt`).
**File:** PE32+ (x64) GUI, MSVC/C++, image size `0x44000` (~280 KB).
**MD5:** `5e282f31200af69d1a349dee2e11ba56`
**SHA-256:** `59e537f5ce8be429eb8f6ef2934702347608601e1a29b4fc49474e2e760324fa`

**Verdict:** This is **not the miner itself** — it is the **anti-analysis / loader
stage** ("AntiVM" component) of the campaign. It gates on environment checks, then
downloads, decrypts, drops, and persists the **next stage `wpnprv.exe`** as a SYSTEM
scheduled task. Confirmed malicious. The actual miner is `wpnprv.exe`, delivered by
this binary.

> **Author artifact (leaked PDB path):**
> `C:\Users\Luxe\Desktop\Miner\AntiVM\x64\Release\AntiVM.pdb`
> The project is literally named **`Miner\AntiVM`**, built by user **"Luxe"**. This
> binary is the `AntiVM` sub-project of a "Miner" solution.

---

## 1. Where it fits in the kill chain

```
Run.vbs ─► MSY.bat ─► downloads Base64 from mscloudresolver.com/ad.txt
                       └─► C:\ProgramData\SEMgrSvc.exe   (THIS FILE — AntiVM loader)
                              │  anti-sandbox gate
                              │  download + decode + decrypt
                              ▼
                       C:\ProgramData\wpnprv.exe          (next stage = the actual miner)
                              persisted as SYSTEM task "WPNService" @ ONLOGON
```

`SEMgrSvc.exe` and the Era.exe/MSY.bat layer share the **same C2 domain**
(`mscloudresolver.com`) and the **same masquerade pattern** (drop into `C:\ProgramData`,
persist under `\Microsoft\Windows\Servicing\`), confirming a single campaign.

---

## 2. Control flow (`WinMain` @ `0x140006370`)

Renamed in the IDB to `malware_WinMain_orchestrator`. Sequence:

1. **Anti-sandbox gate** (`0x1400063be`) — proceeds **only if both**:
   - `GetSystemMetrics(SM_CYSCREEN) >= 1080` — refuses to run on the small/low-res
     displays typical of automated sandboxes.
   - `antivm_check_running_from_ProgramData()` (`0x140005E60`) returns true — see §3.
   If either fails, the program silently exits (does nothing).

2. **Host fingerprint** (`0x1400063ec`) — reads
   `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (falls back to `"N/A"`).
   The value is compared against a **hardcoded blocklist of ~35 MachineGUIDs**
   (`0x1400338D8`–`0x140033E28`) — known analysis/sandbox machine GUIDs (a classic
   anti-analysis denylist).

3. **Connectivity wait-loop** (`0x1400065b6`) — repeatedly runs, hidden
   (`CREATE_NO_WINDOW`, `wShowWindow=0`):
   ```
   cmd.exe /c ping -n 1 -w 1000 8.8.8.8 > nul
   ```
   It checks the process exit code and sleeps (QueryPerformanceCounter-based backoff,
   up to ~24 h) until the ping succeeds — i.e. it waits for live internet before
   touching the C2. This also defeats network-less sandboxes.

4. **Download + decode + drop** — calls `download_decode_xor_drop_wpnprv()` (§4).

5. **Persistence** (`0x1400067ed`) — runs via `CreateProcessA`:
   ```
   schtasks /Create /TN "\Microsoft\Windows\Servicing\WPNService"
            /TR "C:\ProgramData\wpnprv.exe" /SC ONLOGON /RU "SYSTEM" /RL HIGHEST /F
   schtasks /Run    /TN "\Microsoft\Windows\Servicing\WPNService"
   ```
   The fake task name `WPNService` (Windows Push Notification) is filed under the real
   `\Microsoft\Windows\Servicing\` tree and runs **as SYSTEM with highest privileges,
   at every logon**, then is launched immediately.

---

## 3. The "AntiVM" gate (`0x140005E60`)

Renamed `antivm_check_running_from_ProgramData`. It:
- Gets its own image path (`GetModuleFileNameA`).
- Resolves `CSIDL_COMMON_APPDATA` = `C:\ProgramData` (`SHGetFolderPathA(35)`).
- Lowercases both and returns true **only if its own path begins with `C:\ProgramData`**.

Effect: the loader refuses to run unless it is installed in `C:\ProgramData` (where the
dropper placed it). This blocks execution from a researcher's Desktop/Temp/Downloads and
prevents detonation outside the intended install location. Combined with the screen-height
check and the MachineGUID denylist, these are the binary's anti-analysis defenses.
(Standard CRT anti-debug — `IsDebuggerPresent` — is present only inside MSVC runtime
failfast paths, not as an additional malware check.)

---

## 4. Payload retrieval & deobfuscation (`0x1400056C0`)

Renamed `download_decode_xor_drop_wpnprv`. Target file: **`C:\ProgramData\wpnprv.exe`**.
It iterates over the C2 URL list (`g_c2_url_list`) — primary then fallback — and for the
first that returns usable data:

1. **HTTP GET** via WININET (`InternetOpenUrlA`/`InternetReadFile`), User-Agent
   **`HTTPUser/1.0`** (`http_get_A` @ `0x1400054D0`).
2. **Strip all whitespace** from the response (it's Base64 text).
3. **Base64-decode** via `CryptStringToBinaryA` (`base64_decode_CryptStringToBinary`
   @ `0x140005320`). Requires ≥ 8 decoded bytes to proceed.
4. **XOR-decrypt** with the repeating 4-byte key **`"Nero"`** (`0x4E 0x65 0x72 0x6F`):
   `plain[i] = decoded[i] ^ "Nero"[i % 4]`. (Key set in `init_xor_key_Nero` @ `0x140003B70`.)
5. **Write** the decrypted bytes to `C:\ProgramData\wpnprv.exe` (`std::ofstream`, binary).
6. **`SetFileAttributesA(wpnprv.exe, 6)`** → `FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM`.

> **To recover the next stage:** fetch the current body of
> `https://mscloudresolver.com/ld.txt` (or the fallback), strip whitespace,
> Base64-decode, then XOR every byte with the cycling key `"Nero"`. The result is the
> `wpnprv.exe` PE — analyse that to confirm the Task-Manager-aware CPU-throttling
> behaviour you observed.

---

## 5. C2 infrastructure (`init_c2_url_list` @ `0x140003BA0`)

| Priority | URL |
|----------|-----|
| Primary  | `https://mscloudresolver.com/ld.txt` |
| Fallback | `https://cortisolspike.org/ld.txt`   |

Note: this stage uses **`ld.txt`** (loader), whereas `MSY.bat` used **`ad.txt`** on the
same `mscloudresolver.com` host — two separate payload endpoints on shared infrastructure.

---

## 6. On the observed "100 % CPU when idle, normal when Task Manager opens"

That behaviour is a property of the **final miner (`wpnprv.exe`)**, not of `SEMgrSvc.exe`.
`SEMgrSvc.exe` contains **no mining code, no stratum/pool strings, and no process-watching
throttle loop** — its job ends once `wpnprv.exe` is dropped and scheduled. The watchdog
that suspends/throttles mining when `Taskmgr.exe`/Process Explorer is open lives in
`wpnprv.exe` and must be analysed from that binary (recoverable per §4). The campaign's
anti-analysis posture (this AntiVM stage) is fully consistent with such a stealth miner.

---

## 7. Indicators of Compromise (this stage)

**Files**
- `C:\ProgramData\SEMgrSvc.exe` — this loader (Hidden) — SHA-256 `59e537f5ce8be429eb8f6ef2934702347608601e1a29b4fc49474e2e760324fa`
- `C:\ProgramData\wpnprv.exe` — dropped next stage / miner (Hidden+System)

**Network**
- `https://mscloudresolver.com/ld.txt` (primary C2)
- `https://cortisolspike.org/ld.txt` (fallback C2)
- Domains: `mscloudresolver.com`, `cortisolspike.org`
- HTTP User-Agent: `HTTPUser/1.0`
- Connectivity probe: ICMP ping to `8.8.8.8`

**Persistence**
- Scheduled task `\Microsoft\Windows\Servicing\WPNService` → `C:\ProgramData\wpnprv.exe`,
  `/SC ONLOGON /RU SYSTEM /RL HIGHEST`

**Host fingerprint**
- Reads `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`

**Crypto / obfuscation**
- Payload = Base64 → XOR with repeating key **`"Nero"`**

**Build artifact**
- PDB: `C:\Users\Luxe\Desktop\Miner\AntiVM\x64\Release\AntiVM.pdb`

**Anti-analysis**
- Screen height < 1080 → no execution
- Not running from `C:\ProgramData` → no execution
- MachineGUID in hardcoded denylist (~35 GUIDs @ `0x1400338D8`)
- Waits for live internet (ping) before C2 contact

---

## 8. MITRE ATT&CK

| Tactic | Technique |
|--------|-----------|
| Defense Evasion | T1497 Virtualization/Sandbox Evasion (screen size, MachineGUID denylist, install-path check, connectivity gate); T1564.001 Hidden/System file attributes; T1036.004/.005 Masquerading (SEMgrSvc / wpnprv / WPNService / Servicing path); T1140 Deobfuscate/Decode (Base64+XOR) |
| Discovery | T1082 System Information Discovery (MachineGuid); T1057 Process Discovery |
| Command & Control | T1071.001 Web protocols; T1105 Ingress Tool Transfer; T1008 Fallback Channels (two C2 URLs) |
| Execution | T1059.003 cmd.exe; T1106 Native API (CreateProcess) |
| Persistence / Priv-Esc | T1053.005 Scheduled Task as SYSTEM |
| Impact (downstream) | T1496 Resource Hijacking (via wpnprv.exe) |

---

## 9. Remediation (in addition to FINDINGS.md §8)

1. Delete scheduled task: `schtasks /Delete /TN "\Microsoft\Windows\Servicing\WPNService" /F`
2. Delete `C:\ProgramData\SEMgrSvc.exe` **and** `C:\ProgramData\wpnprv.exe`.
3. Block `mscloudresolver.com` **and** `cortisolspike.org` at DNS/egress.
4. Hunt other hosts for the `WPNService`/`MgrService` Servicing tasks and the
   `C:\ProgramData\{SEMgrSvc,wpnprv}.exe` artifacts.

---

## 10. Confidence & gaps

- **Directly confirmed (from this binary):** anti-sandbox gating, MachineGUID denylist,
  C2 URLs + UA, Base64+XOR("Nero") deobfuscation, drop to `wpnprv.exe` (Hidden+System),
  and SYSTEM scheduled-task persistence. All read from the decompiled code.
- **Not in this binary (still inferred):** the mining engine and the Task-Manager-aware
  throttle watchdog — those are in `wpnprv.exe`, which is fetched at runtime. Recover it
  per §4 and analyse separately to close the loop.

*IDB annotated: key functions/globals renamed (e.g. `malware_WinMain_orchestrator`,
`download_decode_xor_drop_wpnprv`, `antivm_check_running_from_ProgramData`,
`init_xor_key_Nero`, `g_c2_url_list`) and comments added at the gate, persistence, and
decode sites.*
