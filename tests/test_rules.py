import unittest

from cbounds.lexer import tokenize
from cbounds.rules.buffer_overflow import BufferOverflowRule
from cbounds.rules.integer_overflow import IntegerOverflowRule
from cbounds.rules.null_deref import NullDerefRule
from cbounds.rules.pointer_arithmetic import PointerArithmeticRule
from cbounds.rules.signedness import SignednessRule
from cbounds.rules.sizeof_mismatch import SizeofMismatchRule


class TestRules(unittest.TestCase):
    def test_cb001_pointer_arithmetic_detection(self):
        vuln_code = """
        void parse_packet(const uint8_t *packet, size_t size) {
            const uint8_t *pkt_ptr = packet;
            pkt_ptr += chunk_len;
        }
        """
        rule = PointerArithmeticRule()
        findings = rule.analyze("test.c", vuln_code, tokenize(vuln_code), vuln_code.splitlines())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CB-001")

        # Safe with boundary guard
        safe_code = """
        void parse_packet(const uint8_t *packet, size_t size) {
            const uint8_t *pkt_ptr = packet;
            if (chunk_len > remaining) return;
            pkt_ptr += chunk_len;
        }
        """
        findings_safe = rule.analyze("test.c", safe_code, tokenize(safe_code), safe_code.splitlines())
        self.assertEqual(len(findings_safe), 0)

    def test_cb002_buffer_overflow_detection(self):
        vuln_code = """
        void handle_data(const uint8_t *src, size_t len) {
            char buf[32];
            memcpy(buf, src, len);
        }
        """
        rule = BufferOverflowRule()
        findings = rule.analyze("test.c", vuln_code, tokenize(vuln_code), vuln_code.splitlines())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CB-002")

        # Safe with sizeof
        safe_code = """
        void handle_data(const uint8_t *src, size_t len) {
            char buf[32];
            memcpy(buf, src, sizeof(buf));
        }
        """
        findings_safe = rule.analyze("test.c", safe_code, tokenize(safe_code), safe_code.splitlines())
        self.assertEqual(len(findings_safe), 0)

    def test_cb003_integer_overflow_detection(self):
        vuln_code = """
        void *alloc_elements(size_t count) {
            return malloc(count * sizeof(int));
        }
        """
        rule = IntegerOverflowRule()
        findings = rule.analyze("test.c", vuln_code, tokenize(vuln_code), vuln_code.splitlines())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CB-003")

    def test_cb004_sizeof_mismatch_and_strlen(self):
        vuln_code = """
        void init(MyStruct *ptr, const char *s) {
            memset(ptr, 0, sizeof(ptr));
            char *copy = malloc(strlen(s));
        }
        """
        rule = SizeofMismatchRule()
        findings = rule.analyze("test.c", vuln_code, tokenize(vuln_code), vuln_code.splitlines())
        self.assertEqual(len(findings), 2)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("CB-004", rule_ids)

    def test_cb005_signedness_negative_length_detection(self):
        vuln_code = """
        int parse_record(int tag_len) {
            if (tag_len > 512) return -1;
            return tag_len;
        }
        """
        rule = SignednessRule()
        findings = rule.analyze("test.c", vuln_code, tokenize(vuln_code), vuln_code.splitlines())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CB-005")

        safe_code = """
        int parse_record(int tag_len) {
            if (tag_len < 0 || tag_len > 512) return -1;
            return tag_len;
        }
        """
        findings_safe = rule.analyze("test.c", safe_code, tokenize(safe_code), safe_code.splitlines())
        self.assertEqual(len(findings_safe), 0)

    def test_cb006_null_deref_detection(self):
        vuln_code = """
        void create_item() {
            Item *item = (Item *)malloc(sizeof(Item));
            item->val = 10;
        }
        """
        rule = NullDerefRule()
        findings = rule.analyze("test.c", vuln_code, tokenize(vuln_code), vuln_code.splitlines())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CB-006")

        safe_code = """
        void create_item() {
            Item *item = (Item *)malloc(sizeof(Item));
            if (!item) return;
            item->val = 10;
        }
        """
        findings_safe = rule.analyze("test.c", safe_code, tokenize(safe_code), safe_code.splitlines())
        self.assertEqual(len(findings_safe), 0)


if __name__ == "__main__":
    unittest.main()
