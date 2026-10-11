<div align="center">

<pre>
   __  __                     _ __
  / / / /___  _   _____  ____(_) /
 / / / / __ \| | / / _ \/ __/ / /
/ /_/ / / / /| |/ /  __/ / / / /
\____/_/ /_/ |___/\___/_/ /_/_/
</pre>

**Live Windows threat hunting: see what malware hides.**

Uncovers injected code, process hollowing, inline hooks, hidden processes and stealthy persistence
on a running host. One portable `unveil.exe`, 1,700 embedded YARA rule files, MITRE ATT&CK mapped.

[![CI](https://github.com/Haind03/Unveil/actions/workflows/ci.yml/badge.svg)](https://github.com/Haind03/Unveil/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2B%20x64-0078d4)
![Rust](https://img.shields.io/badge/rust-1.88%2B-orange)
[![Release](https://img.shields.io/github/v/release/Haind03/Unveil)](https://github.com/Haind03/Unveil/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

*by HaiND from the Post and Telecommunication Institute of Technology*

</div>

---

## Why Unveil

Antivirus checks files. Modern intrusions live in memory: a beacon reflectively loaded into
`explorer.exe`, `AmsiScanBuffer` patched to return early, a scheduled task with its security
descriptor deleted so `schtasks` cannot see it. Unveil is a blue-team tool for the moment an
analyst sits at a suspicious machine and has to answer *"is something running here that should
not be?"* It inspects the live system from several independent views and flags where they disagree.

- **Read-only.** Never kills, suspends, patches or deletes anything. Safe on production hosts.
- **Portable.** A single static executable, no installer, no runtime, no network access. Rules and
  report templates are embedded.
- **Explainable.** Every finding has a severity, the evidence (addresses, bytes, paths, signer),
  and ATT&CK technique IDs.
- **Fast.** Processes are scanned in parallel; YARA rules compile on a background thread while
  the other phases run.

## Features

| Module | What it does |
| --- | --- |
| **Processes** | Native enumeration (`NtQuerySystemInformation`), command lines, offline Authenticode verification (embedded and catalog signatures), system-process path / parent / instance rules, look-alike names, suspicious parent → child chains, LOLBins and encoded PowerShell. |
| **Memory** | VAD walk of every process: executable unbacked memory, RWX, reflective or manual-mapped PEs (also with stomped headers), known shellcode prologues, threads starting in unbacked memory or at `LoadLibrary`, hollowing (PEB image vs VAD vs disk), herpaderping, phantom DLLs, DLLs unlinked from the loader lists. |
| **Hooks** | Executable sections of critical modules diffed byte by byte against the file on disk (relocations applied): AMSI and ETW patches, modified syscall stubs, inline hooks and where they jump, early-return neutralisation, module stomping. `--deep` checks every module. |
| **Hidden** | Cross-view detection: brute-forces PIDs with `OpenProcess` and compares with the system process list to expose processes hidden by user-mode hooks or DKOM. |
| **Persistence** | ~20 autostart mechanisms: Run keys, Winlogon, IFEO / SilentProcessExit, AppInit / AppCert DLLs, LSA packages, print monitors, netsh helpers, BootExecute, Active Setup, services and drivers, scheduled tasks (including Tarrask hidden tasks), startup folders (`.lnk` parsing), WMI event subscriptions, COM hijacking, screensaver. Each entry is resolved, verified and scored. |
| **YARA** | [yara-x](https://github.com/VirusTotal/yara-x) scan of suspicious executable process memory, process images and autostart targets with 1,700 embedded rule files; severity comes from rule metadata, matches in injected memory rank one level higher. |
| **Reports** | Colored console summary, JSON for SIEM / scripting, and a self-contained offline HTML report with filtering. |

## Detection coverage

| Technique | ATT&CK | Module |
| --- | --- | --- |
| Process injection (generic, unbacked code, RWX) | [T1055](https://attack.mitre.org/techniques/T1055/) | Memory, YARA |
| DLL injection (thread at `LoadLibrary`) | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Memory |
| Process hollowing | [T1055.012](https://attack.mitre.org/techniques/T1055/012/) | Memory, YARA |
| Process doppelgänging / herpaderping / phantom DLL | [T1055.013](https://attack.mitre.org/techniques/T1055/013/) | Memory, Processes |
| Reflective code loading | [T1620](https://attack.mitre.org/techniques/T1620/) | Memory, YARA |
| Direct / indirect syscalls | [T1106](https://attack.mitre.org/techniques/T1106/) | Hooks, YARA |
| Impair defenses: AMSI patch, unhooking | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Hooks, YARA |
| Impair defenses: ETW patch | [T1562.006](https://attack.mitre.org/techniques/T1562/006/) | Hooks, YARA |
| Obfuscation: sleep masking, wiped PE header | [T1027](https://attack.mitre.org/techniques/T1027/) | Memory, YARA |
| Rootkit / hidden artifacts | [T1014](https://attack.mitre.org/techniques/T1014/), [T1564](https://attack.mitre.org/techniques/T1564/) | Hidden, Memory |
| Masquerading (name, location) | [T1036](https://attack.mitre.org/techniques/T1036/), [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Processes |
| Parent PID spoofing | [T1134.004](https://attack.mitre.org/techniques/T1134/004/) | Processes |
| Invalid / tampered code signature | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | Processes, Persistence |
| Command and scripting interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) (.001, .005, .007) | Processes, Persistence |
| System binary proxy execution (mshta, regsvr32, rundll32...) | [T1218](https://attack.mitre.org/techniques/T1218/) | Processes, Persistence |
| Web shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Processes |
| Process spawned by lsass.exe | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Processes |
| Indicator removal: deleted image | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Processes |
| Registry Run keys / startup folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Persistence |
| Authentication / security packages (LSA) | [T1547.002](https://attack.mitre.org/techniques/T1547/002/), [T1547.005](https://attack.mitre.org/techniques/T1547/005/) | Persistence |
| Winlogon helper | [T1547.004](https://attack.mitre.org/techniques/T1547/004/) | Persistence |
| Port / print monitors | [T1547.010](https://attack.mitre.org/techniques/T1547/010/) | Persistence |
| Active Setup | [T1547.014](https://attack.mitre.org/techniques/T1547/014/) | Persistence |
| Windows service / driver | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Persistence |
| Scheduled task (incl. hidden Tarrask tasks) | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Persistence |
| WMI event subscription | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | Persistence |
| IFEO debugger / accessibility backdoor | [T1546.012](https://attack.mitre.org/techniques/T1546/012/) | Persistence |
| AppInit DLLs / AppCert DLLs | [T1546.010](https://attack.mitre.org/techniques/T1546/010/), [T1546.009](https://attack.mitre.org/techniques/T1546/009/) | Persistence |
| Netsh helper DLL | [T1546.007](https://attack.mitre.org/techniques/T1546/007/) | Persistence |
| COM hijacking | [T1546.015](https://attack.mitre.org/techniques/T1546/015/) | Persistence |
| Screensaver | [T1546.002](https://attack.mitre.org/techniques/T1546/002/) | Persistence |
| Unquoted service path | [T1574.009](https://attack.mitre.org/techniques/T1574/009/) | Persistence |
| Known malware families, hack tools, loaders | (per rule) | YARA |

## Installation

Download `unveil.exe` (or the zip with license notices) from the
[latest release](https://github.com/Haind03/Unveil/releases/latest) and check it against
`SHA256SUMS.txt`, or build it yourself:

```powershell
# On Windows (MSVC toolchain)
cargo build --release
# -> target\release\unveil.exe
```

```bash
# Cross-compile from Linux
rustup target add x86_64-pc-windows-gnu
sudo apt-get install mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/unveil.exe
```

Build without the YARA engine (smaller, faster to compile): `cargo build --release --no-default-features`.

## Usage

Run from an **elevated** prompt (Administrator). Without elevation, protected processes and those
of other users cannot be opened, and coverage drops sharply.

```text
unveil [COMMAND] [OPTIONS]

Commands:
  scan         Full hunt (same as no subcommand)
  processes    Process anomalies
  memory       Injected code, reflective PE, hollowing, unbacked threads, unlinked DLLs
  hooks        Inline hooks and patches in ntdll, kernel32, AMSI, ETW and other APIs
  hidden       Processes hidden from the system process list
  persistence  Autostart locations
  yara         YARA scan of suspicious memory, process images and autostart files
  licenses     Print the licenses of the embedded third-party YARA rules

Options:
      --deep                 Every module checked for hooks, all JIT memory YARA-scanned,
                             Microsoft-signed files included in YARA file scans
      --json <FILE>          Write the JSON report to FILE
      --html <FILE>          Write the HTML report to FILE
      --no-report            Console output only
      --min-severity <LEVEL> info | low (default) | medium | high | critical
      --no-color             Disable colors (NO_COLOR is honoured too)
      --rules <PATH>         Extra YARA rules (file or folder, repeatable)
      --no-yara              Skip YARA in a full hunt
      --pid <PID>            Limit per-process phases to these PIDs (repeatable)
      --threads <N>          Worker threads (default: CPUs, max 16)
  -q, --quiet                Findings and summary only
```

Without `--json` / `--html`, both reports are written next to `unveil.exe` as
`unveil_<HOST>_<YYYYMMDD-HHMMSS>.json` / `.html` (falling back to the working directory if that
folder is read-only).

### Examples

```powershell
# Full hunt, reports next to the exe
.\unveil.exe

# Thorough hunt, only medium and above
.\unveil.exe --deep --min-severity medium

# Memory and hooks of one suspicious process
.\unveil.exe memory --pid 4242
.\unveil.exe hooks --pid 4242

# Autostart review to a JSON file for the SIEM
.\unveil.exe persistence --json C:\IR\autoruns.json --no-color

# YARA only, with your own rules on top of the embedded ones
.\unveil.exe yara --rules C:\IR\rules --html C:\IR\yara.html

# In a script: exit code 2 means high or critical findings
.\unveil.exe -q --no-report; if ($LASTEXITCODE -eq 2) { Write-Warning "host needs triage" }
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Hunt completed, no high or critical findings |
| `1` | Error (or not running on Windows) |
| `2` | High or critical findings present |

## How it works

```
 ┌──────────────┐   ┌────────────────────────────┐   ┌────────────┐   ┌──────────────┐   ┌───────────────┐
 │ 1. Processes │──▶│ 2. Memory + hooks          │──▶│ 3. Hidden  │──▶│ 4. Autostart │──▶│ 5-6. YARA     │
 │ native list, │   │ parallel, one handle and   │   │ PID brute  │   │ registry,    │   │ memory, images│
 │ signatures   │   │ one VAD walk per process   │   │ force diff │   │ tasks, WMI   │   │ autostarts    │
 └──────────────┘   └────────────────────────────┘   └────────────┘   └──────────────┘   └───────────────┘
        ▲                  yara-x rules compile on a background thread from the start ──────────┘
```

- `src/core` holds all detection logic on plain data (regions, modules, PE bytes, registry values),
  so every rule is unit-tested on any OS.
- `src/win` holds the Windows collectors (native API, VAD walk, WinVerifyTrust, registry, WMI) and
  the orchestration.
- `src/rules.rs` compiles the embedded rule set with yara-x: one namespace per file, `include`
  disabled, files that fail to compile are skipped with a warning.

## Layout

| Path | Contents |
| --- | --- |
| `src/core` | Platform-independent detection rules and report model, unit-tested |
| `src/win` | Windows collectors, YARA scanning, hunt orchestration, console UI |
| `src/rules.rs` | Rule set compilation and matching (yara-x) |
| `src/main.rs` | Command-line interface |
| `build.rs` | Embeds `rules/**` and the third-party license texts into the executable |
| `rules/custom` | Unveil's own YARA rules (evasion tradecraft: syscalls, AMSI/ETW patching, unhooking, sleep obfuscation) |
| `rules/elastic`, `rules/reversinglabs`, `rules/signature-base` | Third-party YARA rules, pinned and licensed |

## Limitations

- **User mode only, no kernel driver.** Unveil sees the system through the Windows API. A kernel
  rootkit can filter what any user-mode tool sees (callbacks, minifilters, hooked SSDT); the
  cross-view checks raise the bar but do not defeat a capable kernel implant. Pair Unveil with
  a memory image analysed offline (e.g. Volatility) when kernel compromise is suspected.
- **Run as Administrator.** Without elevation and `SeDebugPrivilege`, protected processes
  and other users' processes are skipped. PPL processes (e.g. `lsass.exe` with RunAsPPL,
  anti-malware services) cannot be read even when elevated.
- **Point-in-time snapshot.** Code that is encrypted while sleeping (sleep masking) or only present
  briefly may not be visible at scan time.
- **x64 Windows 10/11 and Server 2016+.** 32-bit (WOW64) processes are scanned, but structure
  layouts assume a 64-bit OS.
- **Heuristics produce false positives.** JIT engines, security products and game anti-cheat
  hook and generate code legitimately. Findings are leads for an analyst, not verdicts.
- **Signature checks are offline.** Revocation is not fetched; a revoked certificate is only
  detected if the local cache already knows it.

## Development

```bash
cargo test --no-default-features   # core detection logic (fast, any OS)
cargo test --release                # plus YARA: every embedded rule file must compile
cargo build --release --target x86_64-pc-windows-gnu
```

CI runs the tests on Ubuntu and builds `unveil.exe` on `windows-latest` (artifact
`unveil-windows-x64`). Pushing a tag `vX.Y.Z` that matches `Cargo.toml` publishes a GitHub Release
with the exe, a zip and SHA-256 checksums.

## License

Unveil's code and `rules/custom` are released under the [MIT License](LICENSE),
Copyright (c) 2026 HaiND from the Post and Telecommunication Institute of Technology.

The embedded third-party YARA rules keep their own licenses (details in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); `unveil licenses` prints the full texts):

| Source | Commit | License |
| --- | --- | --- |
| [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) | `955723319e62a7e4095d256355b095a7594ff48c` | [Elastic License 2.0](rules/elastic/LICENSE.txt) |
| [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84` | [MIT](rules/reversinglabs/LICENSE) |
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | `94a1c48d7ab499879287ff611dfe7f9c56376030` | [DRL 1.1](rules/signature-base/LICENSE) |

Only `.yar` / `.yara` files were taken, unmodified.

## Author

**HaiND from the Post and Telecommunication Institute of Technology** · haind@ptit.edu.vn

Security issues: see [SECURITY.md](SECURITY.md). Unveil is intended for defensive use on systems you
own or are authorised to examine.
