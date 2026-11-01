from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .engine import AuditEngine, export_sarif
from .models import ScanReport, Severity


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="c-bounds-audit-framework",
        description=(
            "Automated static audit framework for C/C++ memory bounds, struct field overflows, "
            "and unsafe pointer arithmetic targeting network stacks, packet decoders, and embedded drivers."
        ),
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="Path(s) to C/C++ source files (.c, .cpp, .h) or directories to audit.",
    )
    parser.add_argument(
        "--sarif",
        action="store_true",
        help="Emit output in OASIS SARIF v2.1.0 format for GitHub Code Scanning.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Emit output in structured JSON format.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 on ANY finding (including MEDIUM/LOW). Default fails on HIGH/CRITICAL.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"c-bounds-audit-framework {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    engine = AuditEngine()
    all_findings = []
    files_scanned = 0

    for target in args.targets:
        p = Path(target)
        if not p.exists():
            print(f"Error: Target path does not exist: {target}", file=sys.stderr)
            return 2

        report = engine.audit_path(p)
        files_scanned += report.files_scanned
        all_findings.extend(report.findings)

    critical_c = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    high_c = sum(1 for f in all_findings if f.severity == Severity.HIGH)
    medium_c = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
    low_c = sum(1 for f in all_findings if f.severity == Severity.LOW)

    overall_report = ScanReport(
        files_scanned=files_scanned,
        findings_count=len(all_findings),
        critical_count=critical_c,
        high_count=high_c,
        medium_count=medium_c,
        low_count=low_c,
        findings=all_findings,
    )

    if args.sarif:
        sarif_obj = export_sarif(overall_report, tool_version=__version__)
        print(json.dumps(sarif_obj, indent=2))
    elif args.json_output:
        res = {
            "summary": {
                "files_scanned": overall_report.files_scanned,
                "total_findings": overall_report.findings_count,
                "critical": overall_report.critical_count,
                "high": overall_report.high_count,
                "medium": overall_report.medium_count,
                "low": overall_report.low_count,
            },
            "findings": [f.to_dict() for f in overall_report.findings],
        }
        print(json.dumps(res, indent=2))
    else:
        print(f"=== C/C++ Bounds & Pointer Arithmetic Auditor v{__version__} ===")
        print(f"Scanned {files_scanned} file(s). Found {len(all_findings)} finding(s).\n")

        for f in all_findings:
            sev_badge = f"[{f.severity.value}]"
            print(f"{sev_badge:10} {f.rule_id} ({f.cwe}) {f.file_path}:{f.line}:{f.column}")
            print(f"           {f.title}: {f.description}")
            print(f"           Line: `{f.snippet}`")
            print(f"           Remediation: {f.remediation}\n")

        print("=== Scan Summary ===")
        print(
            f"CRITICAL: {critical_c} | HIGH: {high_c} | MEDIUM: {medium_c} | LOW: {low_c} | Total: {len(all_findings)}"
        )

    if args.strict and len(all_findings) > 0:
        return 1
    if overall_report.has_failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
