from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import unittest

from cbounds.cli import main

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


class TestCLI(unittest.TestCase):
    def test_cli_audits_safe_sample_returns_zero(self):
        safe_sample = str(SAMPLES_DIR / "safe_parser.c")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([safe_sample])
        self.assertEqual(rc, 0)
        self.assertIn("Found 0 finding(s)", buf.getvalue())

    def test_cli_audits_vulnerable_sample_returns_one(self):
        vuln_sample = str(SAMPLES_DIR / "vulnerable_parser.c")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([vuln_sample])
        self.assertEqual(rc, 1)
        self.assertIn("HIGH", buf.getvalue())

    def test_cli_json_output(self):
        vuln_sample = str(SAMPLES_DIR / "vulnerable_parser.c")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([vuln_sample, "--json"])
        self.assertEqual(rc, 1)
        data = json.loads(buf.getvalue())
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertGreaterEqual(data["summary"]["total_findings"], 6)

    def test_cli_sarif_output(self):
        vuln_sample = str(SAMPLES_DIR / "vulnerable_parser.c")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([vuln_sample, "--sarif"])
        self.assertEqual(rc, 1)
        sarif = json.loads(buf.getvalue())
        self.assertEqual(sarif["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
