"""Unit tests for policy_core. Run: python3 -m unittest discover -s proxy -p '*_test.py'"""

import json
import os
import unittest

import policy_core as pc

HERE = os.path.dirname(os.path.abspath(__file__))

ALLOW = ["github.com", "api.github.com", "*.actions.githubusercontent.com", "example.org"]
PASS = ["hosted-compute-*.githubapp.com"]
DENY = ["gist.github.com"]


def policy(mode="enforce"):
    return pc.Policy(mode, ALLOW, PASS, DENY)


class Vectors(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(HERE, "test-vectors.json")) as f:
            self.vectors = json.load(f)

    def test_match_vectors(self):
        for v in self.vectors["match"]:
            with self.subTest(**v):
                compiled = [pc.compile_pattern(v["pattern"])]
                self.assertEqual(pc.matches(v["host"], compiled), v["expect"])

    def test_invalid_patterns(self):
        for p in self.vectors["invalid_patterns"]:
            with self.subTest(pattern=p):
                with self.assertRaises(pc.PolicyError):
                    pc.validate_pattern(p)


class Tls(unittest.TestCase):
    def test_allowed_sni_intercepted(self):
        self.assertEqual(policy().decide_tls("api.github.com").action, "intercept")
        self.assertEqual(policy().decide_tls("pipelines.actions.githubusercontent.com").action, "intercept")

    def test_passthrough(self):
        d = policy().decide_tls("hosted-compute-westus2.githubapp.com")
        self.assertEqual((d.action, d.reason), ("passthrough", "passthrough"))

    def test_blocks(self):
        p = policy()
        self.assertEqual(p.decide_tls("evil.example.com").reason, "sni-not-allowed")
        self.assertEqual(p.decide_tls(None).reason, "no-sni")
        self.assertEqual(p.decide_tls("").reason, "no-sni")
        self.assertEqual(p.decide_tls("140.82.112.6").reason, "ip-literal-sni")
        self.assertEqual(p.decide_tls("gist.github.com").reason, "sni-denied")

    def test_suffix_attacks(self):
        p = policy()
        self.assertEqual(p.decide_tls("github.com.evil.net").action, "block")
        self.assertEqual(p.decide_tls("evilgithub.com").action, "block")


class Http(unittest.TestCase):
    def test_allowed(self):
        self.assertEqual(policy().decide_http("api.github.com").action, "allow")
        self.assertEqual(policy().decide_http("api.github.com:443", sni="api.github.com").action, "allow")

    def test_fronting(self):
        d = policy().decide_http("api.github.com", sni="github.com")
        self.assertEqual((d.action, d.reason), ("block", "host-sni-mismatch"))
        d = policy().decide_http("evil.example.com", sni="github.com")
        self.assertEqual(d.action, "block")

    def test_authority_mismatch(self):
        d = policy().decide_http("api.github.com", others=("api.github.com", "evil.example.com"))
        self.assertEqual(d.reason, "authority-host-mismatch")

    def test_blocks(self):
        p = policy()
        self.assertEqual(p.decide_http("evil.example.com").reason, "host-not-allowed")
        self.assertEqual(p.decide_http("").reason, "no-host")
        self.assertEqual(p.decide_http("93.184.215.14").reason, "ip-literal-host")
        self.assertEqual(p.decide_http("api.github.com", method="CONNECT").reason, "connect-method")
        self.assertEqual(p.decide_http("gist.github.com").reason, "host-denied")

    def test_passthrough_names_allowed_for_http(self):
        self.assertEqual(policy().decide_http("hosted-compute-a.githubapp.com").action, "allow")


class Config(unittest.TestCase):
    def test_bad_mode(self):
        with self.assertRaises(pc.PolicyError):
            pc.Policy("disabled", [], [], [])

    def test_selftest_passes(self):
        self.assertTrue(pc.selftest(policy()))
        self.assertTrue(pc.selftest(pc.Policy("analyze", [], PASS, [])))

    def test_from_config(self):
        p = pc.Policy.from_config({"mode": "analyze", "allow": ALLOW, "passthrough": PASS, "deny": DENY})
        self.assertFalse(p.enforce)
        self.assertEqual(p.allow_patterns, ALLOW)


if __name__ == "__main__":
    unittest.main()
