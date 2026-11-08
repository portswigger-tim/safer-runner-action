"""Unit tests for sudo_suggest (the suggested sudo-config). Run: python3 -m unittest discover -s proxy -p '*_test.py'"""

import io
import json
import os
import sys
import unittest

import sudo_suggest

HERE = os.path.dirname(os.path.abspath(__file__))


def vectors():
    with open(os.path.join(HERE, "test-vectors.json")) as f:
        return json.load(f)["sudo"]


class SuggestVectors(unittest.TestCase):
    def test_vectors(self):
        for case in vectors()["suggest"]:
            with self.subTest(case["name"]):
                out = sudo_suggest.suggest(case["commands"])
                self.assertEqual(out["rules"], case["rules"])
                self.assertEqual(out["omitted"], case["omitted"])

    def test_never_suggests_a_wildcard(self):
        for case in vectors()["suggest"]:
            for line in sudo_suggest.suggest(case["commands"])["rules"]:
                self.assertNotIn("*", line)

    def test_cap(self):
        cmds = [{"command": "/usr/bin/x", "args": "n%d" % i, "targetUser": "root"} for i in range(60)]
        out = sudo_suggest.suggest(cmds)
        self.assertEqual(len(out["rules"]), sudo_suggest.MAX_RULES)
        self.assertEqual(out["omitted"]["over_cap"], 10)


class SameLinesAsTheParser(unittest.TestCase):
    """representable() agrees with src/services/sudo/config.ts parseSudoLine on the shared vectors
    (a suggestion never has a `*`, so lines with one are not representable here)."""

    def test_valid(self):
        for v in vectors()["valid"]:
            with self.subTest(v["line"]):
                args = v["args"] + (["*"] if v["anyRest"] else [])
                self.assertEqual(sudo_suggest.representable(v["path"], args), not v["anyRest"])

    def test_invalid(self):
        for line in vectors()["invalid"]:
            with self.subTest(line):
                words = line.split(" ")
                words = [w for w in words if w]
                self.assertFalse(words and sudo_suggest.representable(words[0], words[1:]))


class Main(unittest.TestCase):
    def test_stdin_to_stdout(self):
        stdin, stdout = sys.stdin, sys.stdout
        try:
            sys.stdin = io.StringIO(json.dumps({"commands": [{"command": "/usr/bin/nproc", "args": ""}]}))
            sys.stdout = io.StringIO()
            sudo_suggest.main()
            out = json.loads(sys.stdout.getvalue())
        finally:
            sys.stdin, sys.stdout = stdin, stdout
        self.assertEqual(out["rules"], ["/usr/bin/nproc"])

    def test_bad_input(self):
        stdin = sys.stdin
        try:
            sys.stdin = io.StringIO("[]")
            with self.assertRaises(SystemExit):
                sudo_suggest.main()
        finally:
            sys.stdin = stdin


if __name__ == "__main__":
    unittest.main()
