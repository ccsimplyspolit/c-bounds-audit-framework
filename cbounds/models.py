from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclasses.dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    cwe: str
    file_path: str
    line: int
    column: int
    snippet: str
    description: str
    remediation: str
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "cwe": self.cwe,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "description": self.description,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }


@dataclasses.dataclass
class Token:
    type: str
    value: str
    line: int
    column: int


@dataclasses.dataclass
class FunctionDecl:
    name: str
    return_type: str
    parameters: List[str]
    start_line: int
    end_line: int
    body_text: str


@dataclasses.dataclass
class ScanReport:
    files_scanned: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[Finding]

    @property
    def has_failures(self) -> bool:
        return (self.critical_count + self.high_count) > 0
