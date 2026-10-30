"""Tests for the scanner. Run: python -m unittest test_scanner -v"""

import unittest

from corpus import CASES
from scanner import scan_source


class TestCorpus(unittest.TestCase):
    def test_every_case_matches_its_labels(self):
        for name, code, expected in CASES:
            with self.subTest(case=name):
                found = {f.rule for f in scan_source(code)}
                self.assertEqual(found, expected, f"{name}: got {found}")

    def test_syntax_error_does_not_crash(self):
        findings = scan_source("def broken(:")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "parse-error")

    def test_findings_are_line_sorted(self):
        code = 'import pickle\nx = eval(y)\n'
        lines = [f.line for f in scan_source(code)]
        self.assertEqual(lines, sorted(lines))


if __name__ == "__main__":
    unittest.main()
