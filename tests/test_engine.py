from pathlib import Path
import unittest

from cbounds.engine import AuditEngine, export_sarif

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.engine = AuditEngine()

    def test_audits_vulnerable_sample_parser(self):
        sample_path = SAMPLES_DIR / "vulnerable_parser.c"
        report = self.engine.audit_path(sample_path)

        self.assertEqual(report.files_scanned, 1)
        self.assertTrue(report.has_failures)
        self.assertGreaterEqual(report.findings_count, 6)

        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("CB-001", rule_ids)  # Pointer arithmetic
        self.assertIn("CB-002", rule_ids)  # Buffer copy
        self.assertIn("CB-003", rule_ids)  # Integer overflow
        self.assertIn("CB-004", rule_ids)  # Sizeof mismatch / strlen
        self.assertIn("CB-005", rule_ids)  # Signedness
        self.assertIn("CB-006", rule_ids)  # Null dereference

    def test_audits_safe_sample_parser(self):
        sample_path = SAMPLES_DIR / "safe_parser.c"
        report = self.engine.audit_path(sample_path)

        self.assertEqual(report.files_scanned, 1)
        self.assertFalse(report.has_failures)
        self.assertEqual(report.findings_count, 0)

    def test_exports_valid_sarif_v2_1_0(self):
        sample_path = SAMPLES_DIR / "vulnerable_parser.c"
        report = self.engine.audit_path(sample_path)
        sarif = export_sarif(report, tool_version="1.0.0")

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "c-bounds-audit-framework")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["version"], "1.0.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), report.findings_count)


if __name__ == "__main__":
    unittest.main()
