# Third-party notices

Unveil embeds the following third-party YARA rule sets into `unveil.exe`. Each set is pinned to an
upstream commit and keeps its original license; the full license texts ship in the repository
(`rules/<source>/LICENSE*`) and inside the executable (`unveil licenses`).

| Folder | Upstream | Commit | Rule files | License |
| --- | --- | --- | ---: | --- |
| `rules/elastic` | [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) | `955723319e62a7e4095d256355b095a7594ff48c` | 734 | [Elastic License 2.0](rules/elastic/LICENSE.txt) |
| `rules/reversinglabs` | [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84` | 309 | [MIT](rules/reversinglabs/LICENSE), Copyright (c) 2020 ReversingLabs |
| `rules/signature-base` | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | `94a1c48d7ab499879287ff611dfe7f9c56376030` | 658 | [Detection Rule License 1.1](rules/signature-base/LICENSE) |

Notes on use:

- **Elastic License 2.0** allows use, copying and redistribution, but you may not provide the
  software to third parties as a hosted or managed service, or remove or obscure licensing
  notices. Unveil is a local command-line tool and keeps the notice.
- **DRL 1.1** requires that the rules' author attribution and the license are kept. Rule `author`
  and `reference` metadata are preserved and shown in every YARA finding.
- **MIT** (ReversingLabs) requires the copyright and permission notice to be included, which is done
  through `rules/reversinglabs/LICENSE` and `unveil licenses`.

Only `.yar` / `.yara` files were taken from upstream, unmodified. Every file compiles with yara-x;
this is checked by the test `rules::tests::all_embedded_rules_compile`.

Rust crate dependencies are listed in `Cargo.lock`, each under its own license (mostly MIT and/or
Apache-2.0; yara-x is BSD-3-Clause).
