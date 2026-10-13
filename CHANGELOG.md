# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-10-13

### Changed
- **Embedded rule corpus is now deflate-compressed.** The ~11 MB of YARA rule bytes (Elastic,
  ReversingLabs, signature-base, Unveil's own) are stored compressed inside `unveil.exe`
  (~2 MB on disk) and inflated once at startup. This is the standard mitigation THOR, Loki and
  every other YARA-based scanner uses so that antivirus engines no longer string-match malware
  signatures sitting inside the scanner's own binary. **Binary size drops ~27.5 MB → ~18.5 MB.**
- **Scheduling and severity tuning after v0.2.0 field reports (388 processes, 604 findings)**:
  - `is_jit_process` recognises common Electron / Chromium / CEF chat clients: Discord, Slack,
    Teams, WhatsApp, Signal, Telegram, Zalo (Zalo.exe / ZaloPC.exe), Spotify, Figma, GitHub
    Desktop, Notion, Obsidian, Copilot and Windows Terminal.
  - `LEGIT_LOOKALIKES` adds `dasHost.exe`, `wmphost.exe`, `upfc.exe`, `msoia.exe`, `cmdhost.exe`
    (Microsoft-signed binaries that previously tripped the look-alike edit-distance rule).
  - "Mapped image hidden from the loader module list" now whitelists UWP / WinUI resource DLLs
    (`*.resources.*.dll`, `Windows.UI.*`, `Microsoft.UI.*`, `*.winmd`), MSIX packaged apps
    (`\WindowsApps\`, `\SystemApps\`) and the .NET single-file native-dependency unpack cache
    (`AppData\Local\Temp\.net\`). Those are documented activation-context mappings, not hidden
    DLLs.
  - "Syscall stub modified" no longer fires in a WOW64 process's 32-bit `ntdll.dll`: every Zw*
    stub there is redirected into `wow64cpu.dll`'s transition thunk by design, not by an EDR
    hook.
  - "Executable unbacked memory" (non-RWX) now scales severity with allocation size: >=256 KiB
    stays Medium, 16-256 KiB drops to Low, below that to Info. Tiny CRT / trampoline thunks no
    longer flood the report.
  - "RWX memory in JIT process" drops from Low to Info (JS engines use RWX trampolines by
    design; still in the JSON report, hidden from the console at default `--min-severity low`).
- **AppData\Local\Temp\.net\** is no longer flagged as a user-writable location: it is the
  documented .NET PublishSingleFile native-dependency extraction cache.

### Added
- Note in README on AV flagging: a YARA scanner embeds signatures of real malware. If
  Defender / an EDR flags `unveil.exe`, that is signature-matching, not malicious intent.
  Compressed storage reduces this; a code-signing certificate would eliminate it. In the
  meantime, add an allowlist entry for the exe before scanning.

## [0.2.0] - 2026-10-13

### Added
- **Forensic footprint controls.** Unveil now behaves correctly as a live-response tool on
  production hosts:
  - **`LastAccessTime` preserved.** Every file read (process images, autostart targets, files
    scanned by YARA) goes through `CreateFileW` with `FILE_WRITE_ATTRIBUTES` and `SetFileTime`
    using the documented NTFS sentinel `(FILETIME { -1, -1 })`, so NTFS does not update atime on
    close. Falls back to a plain read on filesystems that reject the stronger access.
  - **`--lowprio`.** Puts Unveil into `PROCESS_MODE_BACKGROUND_BEGIN`, lowering CPU, memory and
    I/O priority at the same time.
  - **`--cpu-limit <PCT>`.** Hard CPU-rate cap through a Windows Job Object
    (`JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP`). Combine with `--threads` on busy hosts.
  - **`--output-dir <DIR>`.** Write reports into a given folder (external drive, SMB share)
    instead of next to the exe, so nothing is written on the drive being investigated.
  - **`--json -`.** Stream the JSON report to stdout, so a hunt can pipe straight into a SIEM or
    an SSH session without touching the host's disk.

### Changed
- **Scheduling: heaviest processes first.** The per-process memory and YARA phases now scan
  processes in descending thread-count order. On a desktop with Chrome (300 threads) next to
  `fontdrvhost.exe` (2 threads), one worker no longer ends up alone with the biggest target at
  the tail of the phase.
- **Workers bounded by input size.** `--threads 16` on a six-process host spawns six workers,
  not sixteen idle ones.

## [0.1.0] - 2026-10-11

### Added
- Process hunting: masquerading, look-alike names, wrong path or parent, single-instance violations,
  suspicious parent/child chains, LOLBin and encoded PowerShell command lines, Authenticode
  verification (embedded and catalog, offline), deleted process images.
- Memory hunting: unbacked executable memory, RWX regions, reflective / manual-mapped PE, known
  shellcode prologues, threads starting in unbacked memory, process hollowing and herpaderping (PEB
  image vs VAD vs disk), phantom DLLs, DLLs unlinked from the loader lists.
- Hook hunting: executable sections of ntdll, kernel32, kernelbase, amsi, advapi32, sechost, user32,
  ws2_32 and wldp (all modules with `--deep`) diffed against disk with relocations applied; AMSI and
  ETW patches, modified syscall stubs, inline hooks into unbacked memory, module stomping.
- Cross-view hidden process detection (PID brute force vs NtQuerySystemInformation).
- Persistence review of about 20 autostart mechanisms, including Tarrask hidden tasks, WMI event
  subscriptions, COM hijacks and IFEO / accessibility backdoors.
- YARA scanning (yara-x) of suspicious process memory, process images and autostart targets with
  1,700 embedded rule files (Unveil custom, Elastic, ReversingLabs, signature-base), compiled on a
  background thread. Extra rules with `--rules`.
- CLI with subcommands, parallel scanning, JSON and self-contained HTML reports, exit code 2 on high
  or critical findings.
- GitHub Actions: Linux tests, Windows release build, tagged GitHub Releases.

[0.3.0]: https://github.com/Haind03/Unveil/releases/tag/v0.3.0
[0.2.0]: https://github.com/Haind03/Unveil/releases/tag/v0.2.0
[0.1.0]: https://github.com/Haind03/Unveil/releases/tag/v0.1.0
