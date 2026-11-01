from __future__ import annotations

import re
from typing import List

from ..models import Finding, Severity, Token
from .base import BaseRule

ALLOC_ASSIGN_RE = re.compile(
    r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:\([a-zA-Z0-9_\s\*]+\))?\s*(?:malloc|calloc|realloc|strdup)\s*\("
)


class NullDerefRule(BaseRule):
    rule_id = "CB-006"
    title = "Unchecked Allocation Return Dereference (Potential NULL Pointer Dereference)"
    severity = Severity.HIGH
    cwe = "CWE-476"
    description = (
        "Memory allocation (`malloc`/`calloc`/`realloc`/`strdup`) return pointer is dereferenced "
        "or passed to memory copy without verifying that the pointer is non-NULL."
    )
    remediation = "Verify `if (ptr == NULL) return -1;` or handle allocation failure before dereferencing."

    def analyze(self, file_path: str, content: str, tokens: List[Token], lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        for idx, line in enumerate(lines, start=1):
            clean_line = line.split("//", 1)[0].strip()
            if not clean_line:
                continue

            m = ALLOC_ASSIGN_RE.search(clean_line)
            if m:
                var_name = m.group(1)

                # Look forward up to 8 lines to see if it is checked before use
                end_window = min(len(lines), idx + 8)
                subsequent_lines = lines[idx:end_window]
                full_subsequent = " ".join(subsequent_lines)

                has_null_check = (
                    f"!{var_name}" in full_subsequent
                    or f"{var_name} == NULL" in full_subsequent
                    or f"{var_name} == 0" in full_subsequent
                    or f"NULL == {var_name}" in full_subsequent
                    or f"assert({var_name}" in full_subsequent
                )

                if not has_null_check:
                    # Check if directly dereferenced
                    is_dereferenced = any(
                        (f"{var_name}->" in s_line or f"*{var_name}" in s_line or f"{var_name}[" in s_line)
                        for s_line in subsequent_lines
                    )
                    if is_dereferenced:
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
                                    f"Pointer '{var_name}' assigned from memory allocation is dereferenced in "
                                    f"subsequent statements without a preceding NULL check."
                                ),
                                remediation=self.remediation,
                                metadata={"variable": var_name},
                            )
                        )

        return findings
