# Security Policy & Coordinated Vulnerability Disclosure (CVD)

## Scope & Defensive Purpose

`c-bounds-audit-framework` is a defensive static analysis engine for C and C++ network parsers and protocol handlers targeting unchecked pointer arithmetic (`CWE-125`), fixed-buffer overflows (`CWE-120`), integer wrap-around (`CWE-190`), `sizeof` mismatches (`CWE-131`), signed length underflows (`CWE-195`), and unchecked NULL dereferences (`CWE-476`).

All tooling in this repository is published strictly for defensive auditing, continuous integration hardening, and Coordinated Vulnerability Disclosure (CVD).

## Supported Versions

| Version | Supported |
| --- | :---: |
| `1.0.x` | :white_check_mark: |
| `< 1.0.0` | :x: |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities in `c-bounds-audit-framework` (such as parser bypasses, SARIF injection issues, or pathological regex/AST denial-of-service inputs) through public GitHub issues.

Use one of the following private reporting channels:

1. **GitHub Private Vulnerability Reporting (Preferred):**  
   Submit a confidential advisory directly via [`https://github.com/ccsimplyspolit/c-bounds-audit-framework/security/advisories/new`](https://github.com/ccsimplyspolit/c-bounds-audit-framework/security/advisories/new).
2. **Direct Researcher Contact:**  
   Email **`cc.simply.spolit@gmail.com`** with `[SECURITY] c-bounds-audit-framework` in the subject line.
   - **Maintainer:** Serhii Shunko (`@ccsimplyspolit`)
   - **ORCID:** [`0009-0002-4183-0361`](https://orcid.org/0009-0002-4183-0361)
   - **Research Portal:** [`https://ccsimplyspolit.github.io`](https://ccsimplyspolit.github.io)

## Disclosure & Remediation Timeline

We follow a standard **90-day Coordinated Vulnerability Disclosure (CVD)** workflow:

- **Acknowledgment:** Within **48 hours** of report receipt.
- **Triage & Reproduction:** Within **5 business days**, including severity classification (CVSS v3.1 / v4.0) and CWE mapping.
- **Remediation & Advisory:** Patches are released alongside a published GitHub Security Advisory (GHSA) crediting the reporting researcher unless anonymity is requested.
