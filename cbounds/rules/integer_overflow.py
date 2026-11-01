from __future__ import annotations

import re
from typing import List

from ..models import Finding, Severity, Token
from .base import BaseRule

MALLOC_MUL_RE = re.compile(
    r"\b(malloc|realloc)\s*\(\s*([a-zA-Z0-9_\-\>\.\&\[\]]+)\s*\*\s*([a-zA-Z0-9_\-\>\.\&\[\]\(\)\s]+)\)"
)
PACKET_ADD_RE = re.compile(
    r"\b(offset|len|size|total|pkt_size)\s*=\s*([a-zA-Z0-9_]+)\s*\+\s*([a-zA-Z0-9_]+)\s*;"
)


class IntegerOverflowRule(BaseRule):
    rule_id = "CB-003"
    title = "Integer Overflow in Allocation Size or Packet Offset Calculation"
    severity = Severity.HIGH
    cwe = "CWE-190 / CWE-680"
    description = (
        "Multiplication or addition is performed directly within memory allocation or packet length "
        "calculations without integer overflow verification, risking undersized allocations and heap corruption."
    )
    remediation = (
        "For array allocations, use `calloc(count, sizeof(...))` or verify `count > SIZE_MAX / sizeof(...)` "
        "prior to multiplication. For offsets, check `__builtin_add_overflow` or `a > UINT_MAX - b`."
    )

    def analyze(self, file_path: str, content: str, tokens: List[Token], lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        for idx, line in enumerate(lines, start=1):
            clean_line = line.split("//", 1)[0].strip()
            if not clean_line:
                continue

            # Check malloc(a * b)
            m_malloc = MALLOC_MUL_RE.search(clean_line)
            if m_malloc:
                fn_name = m_malloc.group(1)
                factor1 = m_malloc.group(2).strip()
                factor2 = m_malloc.group(3).strip()

                # If both are constant numbers, safe
                if factor1.isdigit() and factor2.isdigit():
                    continue

                # Check preceding context for overflow guard
                start_window = max(0, idx - 6)
                preceding = " ".join(lines[start_window:idx])
                has_guard = (
                    "SIZE_MAX" in preceding
                    or "overflow" in preceding
                    or "calloc" in clean_line
                    or "__builtin_mul_overflow" in preceding
                )

                if not has_guard:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Unchecked Integer Multiplication in '{fn_name}'",
                            severity=self.severity,
                            cwe=self.cwe,
                            file_path=file_path,
                            line=idx,
                            column=m_malloc.start() + 1,
                            snippet=clean_line,
                            description=(
                                f"Allocation `{fn_name}({factor1} * {factor2})` multiplies variable operands "
                                f"without checking for arithmetic wrap-around, leading to undersized buffer allocation."
                            ),
                            remediation=(
                                f"Replace with `calloc({factor1}, {factor2})` or enforce `if ({factor1} > SIZE_MAX / {factor2}) return NULL;`."
                            ),
                            metadata={"function": fn_name, "factor1": factor1, "factor2": factor2},
                        )
                    )

            # Check offset = a + b without overflow guard
            m_add = PACKET_ADD_RE.search(clean_line)
            if m_add:
                target_var = m_add.group(1)
                op1 = m_add.group(2)
                op2 = m_add.group(3)

                if op1.isdigit() and op2.isdigit():
                    continue

                start_window = max(0, idx - 6)
                preceding = " ".join(lines[start_window:idx])
                has_overflow_check = (
                    f"{op1} >" in preceding
                    or f"{op2} >" in preceding
                    or "__builtin_add_overflow" in preceding
                    or "UINT_MAX" in preceding
                    or "UINT32_MAX" in preceding
                )

                if not has_overflow_check:
                    # Check if line or next lines check bounds
                    end_window = min(len(lines), idx + 3)
                    following = " ".join(lines[idx:end_window])
                    if not (f"{target_var} >" in following or f"{target_var} < {op1}" in following):
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title=f"Unchecked Integer Addition in Packet Offset '{target_var}'",
                                severity=Severity.MEDIUM,
                                cwe="CWE-190",
                                file_path=file_path,
                                line=idx,
                                column=m_add.start() + 1,
                                snippet=clean_line,
                                description=(
                                    f"Offset calculation `{target_var} = {op1} + {op2}` lacks integer overflow "
                                    f"detection. If values sum past integer capacity, wrap-around bypasses subsequent checks."
                                ),
                                remediation=f"Validate `{op1} > UINT_MAX - {op2}` or use `__builtin_add_overflow`.",
                                metadata={"target": target_var, "op1": op1, "op2": op2},
                            )
                        )

        return findings
