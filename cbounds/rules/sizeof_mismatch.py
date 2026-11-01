from __future__ import annotations

import re
from typing import Dict, List

from ..models import Finding, Severity, Token
from .base import BaseRule

POINTER_DECL_RE = re.compile(
    r"\b([a-zA-Z0-9_]+)\s*\*\s*([a-zA-Z_][a-zA-Z0-9_]*)\b"
)
SIZEOF_CALL_RE = re.compile(r"\bsizeof\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)")
MALLOC_STRLEN_RE = re.compile(r"\b(malloc|realloc)\s*\(\s*strlen\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*\)")


class SizeofMismatchRule(BaseRule):
    rule_id = "CB-004"
    title = "Size Calculation Mismatch (sizeof pointer vs pointee / strlen off-by-one)"
    severity = Severity.HIGH
    cwe = "CWE-131 / CWE-467"
    description = (
        "Memory allocation or initialization computes `sizeof(pointer)` instead of `sizeof(*pointer)`, "
        "or allocates `malloc(strlen(str))` without accounting for null terminator."
    )
    remediation = (
        "Use `sizeof(*ptr)` when allocating struct pointees, and allocate `strlen(str) + 1` for null-terminated strings."
    )

    def analyze(self, file_path: str, content: str, tokens: List[Token], lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        # Collect pointer variables
        pointer_vars: Dict[str, str] = {}
        for line in lines:
            for m in POINTER_DECL_RE.finditer(line):
                type_name = m.group(1)
                var_name = m.group(2)
                # Ignore char* since sizeof(char) is 1, but pointer is 4 or 8 bytes
                pointer_vars[var_name] = type_name

        for idx, line in enumerate(lines, start=1):
            clean_line = line.split("//", 1)[0].strip()
            if not clean_line:
                continue

            # Check malloc(strlen(s)) off-by-one
            m_strlen = MALLOC_STRLEN_RE.search(clean_line)
            if m_strlen and "+ 1" not in clean_line and "+1" not in clean_line:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="Off-by-One in String Allocation (Missing Null Terminator Byte)",
                        severity=Severity.HIGH,
                        cwe="CWE-193",
                        file_path=file_path,
                        line=idx,
                        column=m_strlen.start() + 1,
                        snippet=clean_line,
                        description=(
                            f"Allocation `{m_strlen.group(1)}(strlen({m_strlen.group(2)}))` omits the `+ 1` "
                            f"terminating byte, resulting in buffer overflow when `strcpy` or null byte is written."
                        ),
                        remediation=f"Allocate `{m_strlen.group(1)}(strlen({m_strlen.group(2)}) + 1)`.",
                        metadata={"variable": m_strlen.group(2)},
                    )
                )

            # Check sizeof(ptr) inside malloc/memset/memcpy
            if any(fn in clean_line for fn in ["malloc", "calloc", "realloc", "memset", "memcpy"]):
                for m_sizeof in SIZEOF_CALL_RE.finditer(clean_line):
                    arg = m_sizeof.group(1)
                    if arg in pointer_vars:
                        # Variable is a pointer, not a struct or type name
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title=f"Suspicious `sizeof({arg})` on Pointer Variable",
                                severity=self.severity,
                                cwe=self.cwe,
                                file_path=file_path,
                                line=idx,
                                column=m_sizeof.start() + 1,
                                snippet=clean_line,
                                description=(
                                    f"Operation calculates `sizeof({arg})` on pointer variable '{arg}' (yields pointer width "
                                    f"4/8 bytes) instead of pointee size `sizeof(*{arg})`."
                                ),
                                remediation=f"Change to `sizeof(*{arg})` or `sizeof({pointer_vars[arg]})`.",
                                metadata={"variable": arg, "type": pointer_vars[arg]},
                            )
                        )

        return findings
