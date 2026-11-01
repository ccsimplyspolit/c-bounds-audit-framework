from __future__ import annotations

import re
from typing import List

from ..models import Finding, Severity, Token
from .base import BaseRule

# Regex to detect pointer advancement by variable offset: ptr += len, p += offset, data = data + len
PTR_ADVANCE_RE = re.compile(
    r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:ptr|buf|data|packet|pkt|payload|cursor|stream))\s*(\+=|\=)\s*\1\s*\+\s*([a-zA-Z_][a-zA-Z0-9_]*)"
)
PTR_INCREMENT_RE = re.compile(
    r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:ptr|buf|data|packet|pkt|payload|cursor|stream))\s*\+=\s*([a-zA-Z_][a-zA-Z0-9_]*)"
)


class PointerArithmeticRule(BaseRule):
    rule_id = "CB-001"
    title = "Unchecked Buffer Pointer Arithmetic in Ingestion Pipeline"
    severity = Severity.HIGH
    cwe = "CWE-125 / CWE-129"
    description = (
        "Pointer is advanced by a variable offset without verifying that the resulting address "
        "remains within the allocated buffer or packet bounds (potential Out-Of-Bounds read/write)."
    )
    remediation = (
        "Verify `if (ptr + offset > buffer_end) return -1;` or check `offset <= remaining_bytes` "
        "before advancing the pointer."
    )

    def analyze(self, file_path: str, content: str, tokens: List[Token], lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        for idx, line in enumerate(lines, start=1):
            clean_line = line.split("//", 1)[0].strip()
            if not clean_line:
                continue

            # Look for pointer advancement
            m = PTR_ADVANCE_RE.search(clean_line) or PTR_INCREMENT_RE.search(clean_line)
            if m:
                ptr_var = m.group(1)
                offset_var = m.group(2) if len(m.groups()) == 2 else m.group(3)

                # Ignore constant increments like ptr += 1, ptr += 4
                if offset_var.isdigit() or offset_var in {"sizeof", "1", "2", "4", "8"}:
                    continue

                # Inspect surrounding preceding lines for boundary checks (end, max, len, limit, remaining)
                start_window = max(0, idx - 8)
                preceding_context = " ".join(lines[start_window:idx])

                has_bounds_guard = any(
                    token in preceding_context
                    for token in [
                        f"{ptr_var} + {offset_var} >",
                        f"{ptr_var} + {offset_var} <=",
                        f"{offset_var} >",
                        f"{offset_var} >=",
                        f"{offset_var} <=",
                        f"{offset_var} <",
                        "buffer_end",
                        "packet_end",
                        "buf_end",
                        "MAX_",
                    ]
                )

                if not has_bounds_guard:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            cwe=self.cwe,
                            file_path=file_path,
                            line=idx,
                            column=m.start() + 1,
                            snippet=clean_line,
                            description=(
                                f"Pointer '{ptr_var}' is advanced by variable '{offset_var}' without preceding "
                                f"bounds check against buffer ceiling."
                            ),
                            remediation=self.remediation,
                            metadata={"pointer": ptr_var, "offset": offset_var},
                        )
                    )

        return findings
