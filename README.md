# c-bounds-audit-framework

[![CI](https://github.com/ccsimplyspolit/c-bounds-audit-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/ccsimplyspolit/c-bounds-audit-framework/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](pyproject.toml)
[![Security: C/C++ Memory Bounds](https://img.shields.io/badge/Security-C%2FC%2B%2B%20Memory%20Bounds-blue.svg)](README.md)

Lightweight automated static audit framework for **C and C++ memory safety**, focusing specifically on **pointer bounds**, **struct field overflows**, **integer arithmetic wrapping**, and **unsafe buffer copies** in network protocol parsers, packet ingestion pipelines, and embedded drivers.

---

## Vulnerability Detection Catalog

| Rule ID | Title | Severity | CWE | Description |
|---|---|---|---|---|
| **CB-001** | Unchecked Buffer Pointer Arithmetic | `HIGH` | `CWE-125` / `CWE-129` | Pointer advancement (`ptr += len`, `packet += offset`) in packet ingestion loops without ceiling bounds verification against `buffer_end` or `remaining_bytes`. |
| **CB-002** | Unbounded Memory Copy into Fixed Buffer | `HIGH` | `CWE-120` / `CWE-787` | Invocations of `memcpy`, `memmove`, `strncpy`, `strcpy`, or `sprintf` copying variable payload into fixed destination buffers without capacity checks (`sizeof(dest)` or `MIN(n, sizeof(dest))`). |
| **CB-003** | Integer Overflow in Allocation or Offset | `HIGH` | `CWE-190` / `CWE-680` | Multiplication in `malloc(count * sizeof(T))` or offset addition without arithmetic wrap-around verification. |
| **CB-004** | Size Calculation Mismatch & Off-by-One | `HIGH` | `CWE-131` / `CWE-467` | Computing `sizeof(ptr)` on pointer variables (yielding 4/8 bytes instead of pointee size `sizeof(*ptr)`), or `malloc(strlen(s))` omitting the `+ 1` null-terminator byte. |
| **CB-005** | Signed Length Negative Value Bypass | `HIGH` | `CWE-125` / `CWE-195` | Signed integer packet lengths checked only with `len > max` without verifying `len >= 0`, allowing negative length values to bypass guards and trigger OOB reads (GHSA-cr23-59mg-h2rc BACnet Stack pattern). |
| **CB-006** | Unchecked Allocation Return Dereference | `HIGH` | `CWE-476` | Dereferencing `malloc`/`calloc` return pointers (`item->field = val`) without preceding NULL check (`if (!item)`). |

---

## Real-World Vulnerability Case Studies

This framework's rules are directly informed by high-severity Coordinate Vulnerability Disclosures (CVD) identified across critical open-source network stacks:

- **GHSA-cr23-59mg-h2rc (`bacnet-stack`):** Signed packet decode length checked only against upper bounds, allowing negative decode lengths to bypass validation and trigger infinite loops and out-of-bounds pointer reads (detected by **CB-005**).
- **GHSA-6hh9-gpj4-cr69 (`moonlight-stream`):** Array sentinel boundary omissions and out-of-bounds array reads in multi-generation packet dispatchers (detected by **CB-001** and **CB-004**).

---

## Installation

```bash
# Clone and install locally
git clone https://github.com/ccsimplyspolit/c-bounds-audit-framework.git
cd c-bounds-audit-framework
pip install .
```

Or run directly via Python:

```bash
python -m cbounds.cli --help
```

---

## CLI Usage

### 1. Audit Single C/C++ Source File

```bash
c-bounds-auditor src/packet_parser.c
```

### 2. Recursively Audit Codebase or Directory

```bash
c-bounds-auditor src/ include/
```

### 3. Emit SARIF v2.1.0 for GitHub Code Scanning

```bash
c-bounds-auditor src/ --sarif > results.sarif
```

### 4. Structured JSON Output

```bash
c-bounds-auditor src/ --json
```

### 5. Strict CI Gate Enforcement

```bash
# Returns exit code 1 if ANY security issues are detected
c-bounds-auditor src/ --strict
```

---

## Python API

```python
from cbounds import AuditEngine, export_sarif

engine = AuditEngine()

# Audit source text directly
findings = engine.audit_source_text("""
void parse(const uint8_t *pkt, size_t len) {
    char buf[32];
    memcpy(buf, pkt, len);
}
""")

for f in findings:
    print(f"[{f.severity.value}] {f.rule_id}: {f.description}")

# Audit directory
report = engine.audit_path("src/")
print(f"Scanned {report.files_scanned} files, detected {report.findings_count} findings.")
```

---

## Included Samples

- [`samples/vulnerable_parser.c`](samples/vulnerable_parser.c) — Demonstrates real-world vulnerable patterns across all 6 rule classes.
- [`samples/safe_parser.c`](samples/safe_parser.c) — Demonstrates hardened, bounds-checked implementations passing 100% clean.

---

## Running Test Suite

```bash
python -m unittest discover -v
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
