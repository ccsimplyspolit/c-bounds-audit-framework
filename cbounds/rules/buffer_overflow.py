from __future__ import annotations

import re
from typing import Dict, List, Set

from ..models import Finding, Severity, Token
from .base import BaseRule

MEMCPY_CALL_RE = re.compile(
    r"\b(memcpy|memmove|strncpy)\s*\(\s*([a-zA-Z0-9_\-\>\.\&\[\]]+)\s*,\s*([a-zA-Z0-9_\-\>\.\&\[\]]+)\s*,\s*([^;,\)]+)\)"
)
UNBOUNDED_STRING_FN_RE = re.compile(r"\b(strcpy|strcat|sprintf|vsprintf)\s*\(\s*([a-zA-Z0-9_\-\>\.\&\[\]]+)\s*,")
ARRAY_DECL_RE = re.compile(
    r"\b(?:char|uint8_t|int8_t|unsigned\s+char|BYTE)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*(\d+|[A-Z0-9_]+)\s*\]"
)


class BufferOverflowRule(BaseRule):
    rule_id = "CB-002"
    title = "Unbounded Memory Copy into Fixed-Size Destination Buffer"
    severity = Severity.HIGH
    cwe = "CWE-120 / CWE-787"
    description = (
        "Memory copy operation (`memcpy`/`memmove`/`strncpy`/`sprintf`) copies variable payload "
        "into a destination buffer without bounding by destination capacity."
    )
    remediation = (
        "Guard the copy operation: `if (n > sizeof(dest)) return -1;` or use `memcpy(dest, src, MIN(n, sizeof(dest)));`"
    )

    def analyze(self, file_path: str, content: str, tokens: List[Token], lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        # First pass: record fixed array buffers declared in file
        fixed_arrays: Dict[str, str] = {}
        for line in lines:
            for m in ARRAY_DECL_RE.finditer(line):
                arr_name = m.group(1)
                arr_size = m.group(2)
                fixed_arrays[arr_name] = arr_size

        for idx, line in enumerate(lines, start=1):
            clean_line = line.split("//", 1)[0].strip()
            if not clean_line:
                continue

            # Check inherently dangerous unbounded functions
            m_unbounded = UNBOUNDED_STRING_FN_RE.search(clean_line)
            if m_unbounded:
                fn_name = m_unbounded.group(1)
                dest = m_unbounded.group(2)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=f"Inherently Unsafe Unbounded Function '{fn_name}'",
                        severity=Severity.HIGH,
                        cwe="CWE-120",
                        file_path=file_path,
                        line=idx,
                        column=m_unbounded.start() + 1,
                        snippet=clean_line,
                        description=(
                            f"Invocation of dangerous function '{fn_name}' writing to '{dest}'. "
                            f"Lacks destination boundary enforcement, enabling stack/heap buffer overflow."
                        ),
                        remediation=f"Replace '{fn_name}' with safe alternative (e.g. `snprintf(dest, sizeof(dest), ...)`).",
                        metadata={"function": fn_name, "destination": dest},
                    )
                )
                continue

            # Check memcpy / memmove / strncpy
            m_copy = MEMCPY_CALL_RE.search(clean_line)
            if m_copy:
                fn_name = m_copy.group(1)
                dest = m_copy.group(2).strip()
                src = m_copy.group(3).strip()
                size_expr = m_copy.group(4).strip()

                # If size_expr is already sizeof(dest) or sizeof(*dest), it is safe
                if f"sizeof({dest})" in size_expr or "sizeof(" in size_expr and dest in size_expr:
                    continue

                # If dest is in fixed_arrays or is an array indexing, check if preceded by bounds check
                dest_base = dest.split(".")[0].split("->")[0].split("[")[0].strip("& ")
                is_known_fixed = dest_base in fixed_arrays or "[" in dest

                if is_known_fixed and not size_expr.isdigit():
                    start_window = max(0, idx - 6)
                    preceding = " ".join(lines[start_window:idx])

                    has_guard = (
                        f"sizeof({dest_base})" in preceding
                        or f"sizeof({dest})" in preceding
                        or f"{size_expr} > sizeof" in preceding
                        or f"{size_expr} <= sizeof" in preceding
                        or f"MIN(" in clean_line
                        or f"min(" in clean_line
                        or f"MIN({size_expr}" in clean_line
                    )

                    if not has_guard:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title=f"Unbounded '{fn_name}' into Fixed Array '{dest}'",
                                severity=self.severity,
                                cwe=self.cwe,
                                file_path=file_path,
                                line=idx,
                                column=m_copy.start() + 1,
                                snippet=clean_line,
                                description=(
                                    f"Function '{fn_name}' copies variable length '{size_expr}' into fixed buffer '{dest}' "
                                    f"without explicit capacity guard (`sizeof({dest})`)."
                                ),
                                remediation=(
                                    f"Ensure `{size_expr} <= sizeof({dest})` before invocation or pass "
                                    f"`MIN({size_expr}, sizeof({dest}))`."
                                ),
                                metadata={"function": fn_name, "dest": dest, "size": size_expr},
                            )
                        )

        return findings
