"""
c-bounds-audit-framework
Automated static audit framework for C/C++ memory bounds, struct field overflows,
and unsafe pointer arithmetic in network protocol parsers and embedded drivers.
"""

from .engine import AuditEngine, export_sarif
from .lexer import tokenize
from .models import Finding, ScanReport, Severity, Token
from .rules import DEFAULT_RULES, BaseRule

__version__ = "1.0.0"

__all__ = [
    "AuditEngine",
    "Finding",
    "Severity",
    "Token",
    "ScanReport",
    "BaseRule",
    "DEFAULT_RULES",
    "tokenize",
    "export_sarif",
    "__version__",
]
