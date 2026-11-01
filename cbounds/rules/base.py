from __future__ import annotations

import abc
from typing import List

from ..models import Finding, Severity, Token


class BaseRule(abc.ABC):
    rule_id: str
    title: str
    severity: Severity
    cwe: str
    description: str
    remediation: str

    @abc.abstractmethod
    def analyze(self, file_path: str, content: str, tokens: List[Token], lines: List[str]) -> List[Finding]:
        """Analyze the source code tokens and lines, returning detected security findings."""
        pass
