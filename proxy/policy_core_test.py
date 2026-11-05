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


class Upstream(unittest.TestCase):
    """The resolved-IP guard (review H1): an allowlisted name must not lead to internal IPs."""

    def test_forbidden(self):
        for ip in (
            "169.254.169.254",  # IMDS
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "100.64.0.1",  # CGNAT
            "100.127.255.254",
            "0.0.0.0",
            "168.63.129.16",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fe80::1%eth0",
            "fd00::1",
            "fc00::1",
            "::ffff:169.254.169.254",  # IPv4-mapped
            "::ffff:10.0.0.1",
            "not-an-ip",
        ):
            with self.subTest(ip=ip):
                self.assertTrue(pc.forbidden_upstream(ip))

    def test_allowed(self):
        for ip in ("140.82.112.3", "1.1.1.1", "172.32.0.1", "100.128.0.1", "192.169.0.1", "2606:4700::1111"):
            with self.subTest(ip=ip):
                self.assertFalse(pc.forbidden_upstream(ip))

    def test_pick(self):
        self.assertEqual(pc.pick_upstream([]), (None, pc.UPSTREAM_UNRESOLVED))
        self.assertEqual(pc.pick_upstream(["140.82.112.3"]), ("140.82.112.3", None))
        # IPv4 preferred
        self.assertEqual(pc.pick_upstream(["2606:4700::1111", "1.1.1.1"]), ("1.1.1.1", None))
        self.assertEqual(pc.pick_upstream(["2606:4700::1111"]), ("2606:4700::1111", None))

    def test_one_bad_answer_poisons_the_rest(self):
        self.assertEqual(pc.pick_upstream(["1.1.1.1", "169.254.169.254"]), ("169.254.169.254", pc.UPSTREAM_FORBIDDEN))
        self.assertEqual(pc.pick_upstream(["2606:4700::1111", "1.1.1.1", "fd00::1"]), ("fd00::1", pc.UPSTREAM_FORBIDDEN))


class Container(unittest.TestCase):
    """container_tls posture (P2): decisions for connections from the container listener."""

    ALLOW_FD = ALLOW + ["productionresultssa*.blob.core.windows.net"]

    def p(self, mode="enforce", ctls="sni-only"):
        return pc.Policy(mode, self.ALLOW_FD, PASS, DENY, ctls)

    def test_allowlisted_container_sni_passed_through(self):
        d = self.p().decide_tls("api.github.com", pc.SOURCE_CONTAINER)
        self.assertEqual((d.action, d.reason), ("passthrough", "container-sni-only"))

    def test_host_unchanged(self):
        d = self.p().decide_tls("api.github.com", pc.SOURCE_HOST)
        self.assertEqual((d.action, d.reason), ("intercept", "allowed"))
        self.assertEqual(self.p().decide_tls("api.github.com").action, "intercept")

    def test_blocks_never_relaxed(self):
        p = self.p()
        for name, reason in (("evil.example.com", "sni-not-allowed"), ("gist.github.com", "sni-denied"),
                             ("", "no-sni"), ("1.2.3.4", "ip-literal-sni")):
            with self.subTest(name=name):
                d = p.decide_tls(name, pc.SOURCE_CONTAINER)
                self.assertEqual((d.action, d.reason), ("block", reason))

    def test_front_door_stays_intercepted_in_enforce(self):
        d = self.p().decide_tls("productionresultssa3.blob.core.windows.net", pc.SOURCE_CONTAINER)
        self.assertEqual((d.action, d.reason), ("intercept", "container-front-door"))

    def test_front_door_passthrough_in_analyze(self):
        # analyze never breaks a container: fronting is not a block concern there
        d = self.p("analyze").decide_tls("productionresultssa3.blob.core.windows.net", pc.SOURCE_CONTAINER)
        self.assertEqual((d.action, d.reason), ("passthrough", "container-sni-only"))

    def test_explicit_passthrough_unchanged(self):
        d = self.p().decide_tls("hosted-compute-a.githubapp.com", pc.SOURCE_CONTAINER)
        self.assertEqual((d.action, d.reason), ("passthrough", "passthrough"))

    def test_intercept_posture_matches_host(self):
        p = self.p(ctls="intercept")
        for name in ("api.github.com", "evil.example.com", "productionresultssa3.blob.core.windows.net"):
            self.assertEqual(repr(p.decide_tls(name, pc.SOURCE_CONTAINER)), repr(p.decide_tls(name)))

    def test_front_door_list_matches_vectors(self):
        with open(os.path.join(HERE, "test-vectors.json")) as f:
            v = json.load(f)
        self.assertEqual(list(pc.FRONT_DOORS), v["front_doors"])
        p = self.p()
        for case in v["front_door_hosts"]:
            with self.subTest(**case):
                self.assertEqual(p.is_front_door(case["host"]), case["expect"])

    def test_bad_posture(self):
        with self.assertRaises(pc.PolicyError):
            pc.Policy("enforce", [], [], [], "mitm")

    def test_selftest(self):
        self.assertTrue(pc.selftest(self.p()))
        self.assertTrue(pc.selftest(self.p("analyze")))

    def test_from_config_default_is_host_behaviour(self):
        p = pc.Policy.from_config({"mode": "enforce", "allow": ALLOW})
        self.assertEqual(p.container_tls, "intercept")
        p = pc.Policy.from_config({"mode": "enforce", "allow": ALLOW, "container_tls": "sni-only"})
        self.assertEqual(p.container_tls, "sni-only")


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
