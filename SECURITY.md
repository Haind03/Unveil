# Security policy

Unveil is a defensive tool: it reads process memory, the registry and files to look for signs of
compromise. It never modifies the host, kills processes or removes persistence.

## Reporting a vulnerability

Please report security issues in Unveil itself (for example a crash or code execution triggered by a
crafted process, PE file, shortcut, task XML or rule file) privately by e-mail to
**haind@ptit.edu.vn**, not in a public issue. Include the Unveil version (`unveil --version`), the
Windows build, and steps or a sample to reproduce.

You can expect an acknowledgement within 7 days. Fixes are released as a new version, and reporters
are credited unless they ask not to be.

## Detection gaps and false positives

A malware technique that Unveil misses, or a benign program it flags, is not a vulnerability. Please
open a normal issue with the finding (JSON report excerpt) and, if possible, a reference to the
technique.

## Scope

Unveil runs in user mode only. A kernel rootkit can hide from it by design; see the Limitations
section of the README.
