import unittest

from cbounds.lexer import tokenize


class TestLexer(unittest.TestCase):
    def test_tokenizes_basic_c_statement(self):
        code = "int main(int argc, char **argv) { return 0; }"
        tokens = tokenize(code)
        types = [t.type for t in tokens]
        self.assertIn("IDENTIFIER", types)
        self.assertIn("PUNCTUATOR", types)
        self.assertIn("INTEGER", types)

    def test_tokenizes_hex_octal_and_numbers(self):
        code = "uint32_t val = 0x1A2B; int oct = 0755; float f = 3.14f;"
        tokens = tokenize(code)
        val_map = {t.type: t.value for t in tokens}
        self.assertIn("HEX", val_map)
        self.assertEqual(val_map["HEX"], "0x1A2B")
        self.assertIn("OCTAL", val_map)
        self.assertEqual(val_map["OCTAL"], "0755")
        self.assertIn("FLOAT", val_map)

    def test_strips_comments_accurately(self):
        code = """
        // Single line comment
        /* Multi-line
           comment block */
        int x = 42;
        """
        tokens = tokenize(code)
        values = [t.value for t in tokens]
        self.assertNotIn("// Single line comment", values)
        self.assertIn("int", values)
        self.assertIn("x", values)
        self.assertIn("42", values)

    def test_line_and_column_tracking(self):
        code = "int a;\nint b;"
        tokens = tokenize(code)
        token_b = [t for t in tokens if t.value == "b"][0]
        self.assertEqual(token_b.line, 2)
        self.assertEqual(token_b.column, 5)


if __name__ == "__main__":
    unittest.main()
