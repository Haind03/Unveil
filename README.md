# Unveil

Live Windows threat hunting: uncovers injected code, process hollowing, inline hooks, hidden processes and stealthy persistence on a running host. Rust, single exe, MITRE ATT&CK mapped.

*by HaiND from the Post and Telecommunication Institute of Technology*

> **Status: work in progress.** The platform-independent detection logic (`src/core`) builds and its unit tests pass on Linux (`cargo test --no-default-features`). The Windows collectors (`src/win`) and the CLI entry point are not finished and do not compile yet.

## Layout

| Path | Contents |
| --- | --- |
| `src/core` | Detection rules on plain data: process anomalies, memory, hooks, persistence scoring, HTML report |
| `src/win` | Windows collectors (WIP): native process/thread enumeration, VAD walk, code-vs-disk diff, signatures, persistence |
| `rules/custom` | Unveil's own YARA rules |
| `rules/elastic`, `rules/reversinglabs`, `rules/signature-base` | Third-party YARA rules, pinned to upstream commits, each with its own license |

## Third-party rules

| Source | Commit | License |
| --- | --- | --- |
| [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) | `955723319e62a7e4095d256355b095a7594ff48c` | Elastic License 2.0 |
| [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84` | MIT |
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | `94a1c48d7ab499879287ff611dfe7f9c56376030` | DRL 1.1 |

Only `.yar`/`.yara` rule files were taken. Every file was compiled with yara-x before inclusion.
