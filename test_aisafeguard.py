import tempfile
import unittest
from aisafeguard import scan_file

class TestAISafeGuard(unittest.TestCase):
    def _scan_snippet(self, code_text: str):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tmp:
            tmp.write(code_text)
            tmp_path = tmp.name
        return scan_file(tmp_path)

    def test_detect_hardcoded_key(self):
        findings = self._scan_snippet('API_KEY = "sk-1234567890abcdefghijklmnop"')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ASG001")

    def test_detect_eval_injection(self):
        findings = self._scan_snippet("result = eval(user_input)")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ASG002")

    def test_detect_command_injection(self):
        findings = self._scan_snippet("subprocess.run(cmd, shell=True)")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ASG003")

    def test_clean_code_passes(self):
        findings = self._scan_snippet("def add(a, b):\n    return a + b\n")
        self.assertEqual(len(findings), 0)

if __name__ == "__main__":
    unittest.main()
