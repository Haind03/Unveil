# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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

[0.2.0]: https://github.com/Haind03/Unveil/releases/tag/v0.2.0
[0.1.0]: https://github.com/Haind03/Unveil/releases/tag/v0.1.0
