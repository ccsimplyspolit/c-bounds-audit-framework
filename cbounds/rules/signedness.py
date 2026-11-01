from __future__ import annotations

import re
from typing import Dict, List, Set

from ..models import Finding, Severity, Token
from .base import BaseRule

SIGNED_LEN_DECL_RE = re.compile(
    r"\b(int|int16_t|int32_t|short|ssize_t)\s+([a-zA-Z_][a-zA-Z0-9_]*(?:len|length|size|count|offset))\b"
)
UPPER_BOUND_CHECK_RE = re.compile(
    r"\bif\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*(?:len|length|size|count|offset))\s*(?:>|>=)\s*([a-zA-Z0-9_]+)\s*\)"
)


class SignednessRule(BaseRule):
    rule_id = "CB-005"
    title = "Signed Length Comparison Lacking Negative Value Verification"
    severity = Severity.HIGH
    cwe = "CWE-125 / CWE-195"
    description = (
        "Signed integer representing packet or buffer length is checked only against an upper boundary "
        "(`len > max`) without checking for negative values (`len < 0`), allowing negative values to bypass "
        "guards and trigger Out-Of-Bounds reads or infinite loops (GHSA-cr23-59mg-h2rc pattern)."
    )
    remediation = (
        "Use unsigned integer types (e.g. `size_t`, `uint32_t`) for length fields, or verify "
        "`if (len < 0 || len > max) return -1;` before proceeding with pointer arithmetic or buffer copies."
    )

    def analyze(self, file_path: str, content: str, tokens: List[Token], lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        # Find signed length declarations
        signed_vars: Dict[str, str] = {}
        for line in lines:
            for m in SIGNED_LEN_DECL_RE.finditer(line):
                type_name = m.group(1)
                var_name = m.group(2)
                signed_vars[var_name] = type_name

        for idx, line in enumerate(lines, start=1):
            clean_line = line.split("//", 1)[0].strip()
            if not clean_line:
                continue

            # Check if line checks upper bound of a signed length
            for m in UPPER_BOUND_CHECK_RE.finditer(clean_line):
                var_name = m.group(1)
                max_bound = m.group(2)

                if var_name in signed_vars:
                    # Check whether '< 0' or '<= 0' is checked in same condition or nearby
                    start_window = max(0, idx - 5)
                    end_window = min(len(lines), idx + 5)
                    surrounding = " ".join(lines[start_window:end_window])

                    has_negative_guard = (
                        f"{var_name} < 0" in surrounding
                        or f"{var_name} <= 0" in surrounding
                        or f"0 > {var_name}" in surrounding
                    )

                    if not has_negative_guard:
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
                                    f"Signed length variable '{var_name}' ({signed_vars[var_name]}) is compared against "
                                    f"upper bound '{max_bound}' without verifying that `{var_name} >= 0`. Negative length "
                                    f"bypass allows out-of-bounds pointer traversal."
                                ),
                                remediation=self.remediation,
                                metadata={"variable": var_name, "type": signed_vars[var_name], "bound": max_bound},
                            )
                        )

        return findings
