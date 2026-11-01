from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .lexer import tokenize
from .models import Finding, ScanReport, Severity
from .rules import DEFAULT_RULES, BaseRule


class AuditEngine:
    """Core static analysis engine for C/C++ memory safety and pointer bounds."""

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        self.rules = rules or DEFAULT_RULES

    def audit_source_text(self, content: str, file_path: str = "<memory>") -> List[Finding]:
        """Audit raw C/C++ source code content and return detected findings."""
        tokens = tokenize(content)
        lines = content.splitlines()

        findings: List[Finding] = []
        for rule in self.rules:
            findings.extend(rule.analyze(file_path, content, tokens, lines))

        # Sort findings by line number
        findings.sort(key=lambda f: f.line)
        return findings

    def audit_file(self, file_path: Union[str, Path]) -> List[Finding]:
        """Read and audit a single C/C++ source or header file."""
        p = Path(file_path)
        content = p.read_text(encoding="utf-8", errors="replace")
        return self.audit_source_text(content, file_path=str(p))

    def audit_path(self, target_path: Union[str, Path]) -> ScanReport:
        """Audit a file or recursively traverse a directory for C/C++ source files."""
        p = Path(target_path)
        c_extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}

        if p.is_file():
            files = [p]
        elif p.is_dir():
            files = [f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in c_extensions]
        else:
            files = []

        all_findings: List[Finding] = []
        for f in files:
            all_findings.extend(self.audit_file(f))

        critical_c = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high_c = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        medium_c = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        low_c = sum(1 for f in all_findings if f.severity == Severity.LOW)

        return ScanReport(
            files_scanned=len(files),
            findings_count=len(all_findings),
            critical_count=critical_c,
            high_count=high_c,
            medium_count=medium_c,
            low_count=low_c,
            findings=all_findings,
        )


def export_sarif(report: ScanReport, tool_version: str = "1.0.0") -> Dict[str, Any]:
    """Emit findings in OASIS SARIF v2.1.0 format for GitHub Code Scanning."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results = []

    for f in report.findings:
        level = "error" if f.severity in {Severity.CRITICAL, Severity.HIGH} else "warning"

        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f"Remediation: {f.remediation}"},
                "properties": {
                    "tags": ["security", "memory-safety", "c-bounds"],
                    "precision": "high",
                    "cwe": [f.cwe],
                },
            }

        results.append(
            {
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": f"{f.title}: {f.description} (Remediation: {f.remediation})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": f.line, "startColumn": f.column},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "c-bounds-audit-framework",
                        "version": tool_version,
                        "informationUri": "https://github.com/ccsimplyspolit/c-bounds-audit-framework",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }
