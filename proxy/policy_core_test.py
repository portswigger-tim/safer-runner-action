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


    def test_path_vectors(self):
        for v in self.vectors["path_match"]:
            with self.subTest(**v):
                forms = pc.canonical_path(v["path"])
                self.assertIsNotNone(forms)
                self.assertEqual(bool(pc.compile_path_pattern(v["pattern"]).match(forms[0])), v["expect"])

    def test_git_path_vectors(self):
        for v in self.vectors["git_path_match"]:
            with self.subTest(**v):
                path = pc.canonical_path(v["path"])[0].lower()
                self.assertEqual(bool(pc.compile_path_pattern(v["pattern"], git=True).match(path)), v["expect"])

    def test_git_pattern_keys(self):
        self.assertEqual(list(pc.GIT_HOSTS), self.vectors["git_hosts"])
        for v in self.vectors["git_pattern_keys"]:
            with self.subTest(**v):
                self.assertEqual(pc.git_pattern_key(v["pattern"]), v["key"])

    def test_invalid_path_patterns(self):
        for p in self.vectors["invalid_path_patterns"]:
            with self.subTest(pattern=p):
                with self.assertRaises(pc.PolicyError):
                    pc.validate_path_pattern(p)

    def test_valid_path_patterns(self):
        for p in self.vectors["valid_path_patterns"]:
            with self.subTest(pattern=p):
                pc.compile_path_pattern(p)


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


GH_FILTER = {
    "hosts": [
        {"host": "github.com", "rules": [
            {"path": "*", "methods": ["*"]},
            {"path": "*/git-receive-pack", "methods": []},
            {"path": "portswigger-tim/*/git-receive-pack", "methods": ["*"]},
        ]},
        {"host": "api.github.com", "rules": [{"path": "*", "methods": ["GET", "HEAD"]}]},
        {"host": "*.actions.githubusercontent.com", "rules": [{"path": "*", "methods": ["GET"]}]},
        {"host": "example.org", "rules": [
            {"path": "/", "methods": ["GET"]},
            {"path": "v1/*", "methods": ["GET", "POST"]},
            {"path": "v1/items/*", "methods": ["GET"]},
        ]},
    ],
    "platform": [
        {"host": "results-receiver.actions.githubusercontent.com", "path": "twirp/*", "methods": ["POST"]},
        {"host": "results-receiver.actions.githubusercontent.com", "path": "_ws/ingest.sock", "methods": ["GET"]},
        {"host": "run-actions-*-azure-*.actions.githubusercontent.com", "path": "*/idtoken/*", "methods": ["GET"]},
        {"host": "run-actions-*-azure-*.actions.githubusercontent.com", "path": "*/renewjob", "methods": ["POST"]},
    ],
}


def filtered(mode="enforce", cfg=GH_FILTER):
    return pc.Policy(mode, ALLOW, PASS, DENY, http_filter=pc.HttpFilter.from_config(cfg))


class HttpFilter(unittest.TestCase):
    def check(self, host, method, path, action, reason=None, rule=None, p=None):
        d = (p or filtered()).decide_filter(host, method, path)
        self.assertIsNotNone(d, (host, method, path))
        self.assertEqual(d.action, action, (host, method, path, d.reason, d.rule))
        if reason is not None:
            self.assertEqual(d.reason, reason)
        if rule is not None:
            self.assertEqual(d.rule, rule)

    def test_unfiltered_host_is_untouched(self):
        self.assertIsNone(filtered().decide_filter("pipelines.example.net", "PUT", "/x"))
        self.assertIsNone(filtered().decide_filter("www.github.com", "POST", "/a/b.git/git-receive-pack"))
        self.assertIsNone(policy().decide_filter("github.com", "POST", "/a/b.git/git-receive-pack"))

    def test_read_only_host(self):
        self.check("api.github.com", "GET", "/repos/a/b", "allow", "allowed", "*")
        self.check("api.github.com", "head", "/", "allow")
        self.check("api.github.com", "POST", "/user/repos", "block", pc.FILTER_METHOD, "*")
        self.check("api.github.com", "PUT", "/repos/a/b/contents/x", "block", pc.FILTER_METHOD)
        self.check("API.GITHUB.COM:443", "DELETE", "/repos/a/b", "block", pc.FILTER_METHOD)

    def test_git_push_carve_out(self):
        self.check("github.com", "GET", "/a/b.git/info/refs?service=git-receive-pack", "allow")
        self.check("github.com", "POST", "/a/b.git/git-upload-pack", "allow", rule="*")
        self.check("github.com", "POST", "/a/b.git/git-receive-pack", "block", pc.FILTER_PATH, "*/git-receive-pack")
        self.check("github.com", "POST", "/portswigger-tim/app.git/git-receive-pack", "allow",
                   rule="portswigger-tim/*/git-receive-pack")

    def test_non_canonical_forms_do_not_escape_a_deny(self):
        for path in (
            "/a/b.git/git-receive-pack/",
            "/a/b.git/git-receive-pack;x",
            "/a/b.git//git-receive-pack",
            "/a/b.git/git-receive-pac%6b",
            "/a/b.git%2fgit-receive-pack",
            "//a/b.git/git-receive-pack",
        ):
            with self.subTest(path=path):
                self.check("github.com", "POST", path, "block", pc.FILTER_PATH)

    def test_unsafe_paths_refused(self):
        for path in (
            "/portswigger-tim/../a/b.git/git-receive-pack",
            "/portswigger-tim/%2e%2e/a/b.git/git-receive-pack",
            "/portswigger-tim%2f..%2fa/b.git/git-receive-pack",
            "/portswigger-tim/%252e%252e/a/b.git/git-receive-pack",
            "/portswigger-tim/./x/git-receive-pack",
            "/portswigger-tim\\..\\a/git-receive-pack",
            "/portswigger-tim/%5c/git-receive-pack",
            "/a%00/b",
        ):
            with self.subTest(path=path):
                self.check("github.com", "POST", path, "block", pc.FILTER_PATH, rule=None)
                self.check("github.com", "GET", path, "block", pc.FILTER_PATH)

    def test_git_spellings_get_one_verdict(self):
        cfg = {"hosts": [{"host": "github.com", "rules": [
            {"path": "*", "methods": ["*"]},
            {"path": "*/git-receive-pack", "methods": []},
            {"path": "org/secret/*", "methods": []},
            {"path": "org/app/git-receive-pack", "methods": ["*"]},
        ]}]}
        p = filtered(cfg=cfg)
        for path in ("/org/secret/git-receive-pack", "/org/secret.git/git-receive-pack",
                     "/ORG/Secret/git-receive-pack", "/Org/SECRET.GIT/git-receive-pack",
                     "/org/secret.git/info/refs"):
            with self.subTest(path=path):
                self.check("github.com", "POST", path, "block", pc.FILTER_PATH, p=p)
        for path in ("/org/app/git-receive-pack", "/org/app.git/git-receive-pack", "/Org/App.git/git-receive-pack"):
            with self.subTest(path=path):
                self.check("github.com", "POST", path, "allow", rule="org/app/git-receive-pack", p=p)
        for path in ("/org/other.git/git-receive-pack", "/a/b.git/GIT-RECEIVE-PACK"):
            with self.subTest(path=path):
                self.check("github.com", "POST", path, "block", pc.FILTER_PATH, p=p)
        self.check("github.com", "POST", "/org/other.git/git-upload-pack", "allow", rule="*", p=p)

    def test_git_folding_only_on_git_hosts(self):
        cfg = {"hosts": [{"host": "example.org", "rules": [
            {"path": "*", "methods": ["*"]},
            {"path": "org/secret/*", "methods": []},
        ]}]}
        p = filtered(cfg=cfg)
        self.check("example.org", "POST", "/org/secret/x", "block", p=p)
        self.check("example.org", "POST", "/ORG/secret/x", "allow", p=p)

    def test_git_duplicate_spellings_rejected(self):
        for a, b in (("org/repo/x", "org/repo.git/x"), ("org/repo/x", "ORG/Repo/x")):
            cfg = {"hosts": [{"host": "github.com", "rules": [
                {"path": a, "methods": ["GET"]}, {"path": b, "methods": ["POST"]}]}]}
            with self.subTest(a=a, b=b):
                with self.assertRaises(pc.PolicyError):
                    pc.HttpFilter.from_config(cfg)
        cfg["hosts"][0]["host"] = "example.org"
        pc.HttpFilter.from_config(cfg)  # case matters elsewhere

    def test_most_specific_wins(self):
        self.check("example.org", "GET", "/", "allow", rule="")
        self.check("example.org", "POST", "/", "block", pc.FILTER_METHOD)
        self.check("example.org", "POST", "/v1/things", "allow", rule="v1/*")
        self.check("example.org", "POST", "/v1/items/3", "block", pc.FILTER_METHOD, "v1/items/*")
        self.check("example.org", "GET", "/v1/items/3", "allow")
        self.check("example.org", "GET", "/v2/x", "block", pc.FILTER_PATH, None)
        self.check("example.org", "GET", "/index.html", "block", pc.FILTER_PATH)

    def test_ties_need_every_rule(self):
        cfg = {"hosts": [{"host": "example.org", "rules": [
            {"path": "a/*", "methods": ["GET", "POST"]},
            {"path": "*/b", "methods": ["GET"]},
        ]}]}
        p = filtered(cfg=cfg)
        self.check("example.org", "GET", "/a/b", "allow", p=p)
        self.check("example.org", "POST", "/a/b", "block", pc.FILTER_METHOD, p=p)
        self.check("example.org", "POST", "/a/c", "allow", p=p)

    def test_query_ignored(self):
        self.check("api.github.com", "GET", "/x?method=POST&path=/y", "allow")
        self.check("example.org", "GET", "/?v1/x", "allow", rule="")

    def test_most_specific_host_wins(self):
        cfg = {"hosts": [
            {"host": "*.example.org", "rules": [{"path": "*", "methods": ["GET"]}]},
            {"host": "api.example.org", "rules": [{"path": "*", "methods": ["*"]}]},
        ]}
        p = pc.Policy("enforce", ["*.example.org"], [], [], http_filter=pc.HttpFilter.from_config(cfg))
        self.check("api.example.org", "POST", "/x", "allow", p=p)
        self.check("www.example.org", "POST", "/x", "block", pc.FILTER_METHOD, p=p)

    def test_platform_endpoints(self):
        rr = "results-receiver.actions.githubusercontent.com"
        self.check(rr, "POST", "/twirp/results.services.receiver.Receiver/CreateArtifact", "allow",
                   rule=pc.FILTER_PLATFORM)
        self.check(rr, "GET", "/twirp/x", "allow", rule="*")  # the user's own rule
        self.check(rr, "PUT", "/twirp/x", "block", pc.FILTER_METHOD)
        self.check(rr, "POST", "/other", "block", pc.FILTER_METHOD)
        oidc = "run-actions-1-azure-eastus.actions.githubusercontent.com"
        self.check(oidc, "GET", "/40//idtoken/a/b?api-version=2.0", "allow")
        self.check(oidc, "POST", "/40//idtoken/a/b", "block", pc.FILTER_METHOD)
        self.check(oidc, "POST", "/40/renewjob", "allow", rule=pc.FILTER_PLATFORM)
        self.check(oidc, "POST", "/40/renewjobs", "block", pc.FILTER_METHOD)
        self.check(rr, "GET", "/_ws/ingest.sock", "allow", rule=pc.FILTER_PLATFORM)
        # never past an unsafe path
        self.check(rr, "POST", "/twirp/../x", "block", pc.FILTER_PATH)

    def test_platform_off(self):
        cfg = dict(GH_FILTER, platform=[])
        rr = "results-receiver.actions.githubusercontent.com"
        self.check(rr, "POST", "/twirp/x", "block", pc.FILTER_METHOD, p=filtered(cfg=cfg))

    def test_platform_only_on_filtered_hosts(self):
        cfg = {"hosts": [], "platform": GH_FILTER["platform"]}
        p = filtered(cfg=cfg)
        self.assertIsNone(p.decide_filter("results-receiver.actions.githubusercontent.com", "POST", "/twirp/x"))

    def test_none_and_any(self):
        cfg = {"hosts": [{"host": "example.org", "rules": [
            {"path": "*", "methods": []},
            {"path": "open/*", "methods": ["*"]},
        ]}]}
        p = filtered(cfg=cfg)
        self.check("example.org", "GET", "/x", "block", pc.FILTER_PATH, "*", p=p)
        self.check("example.org", "PATCH", "/open/x", "allow", p=p)

    def test_bad_config(self):
        bad = [
            {"hosts": [{"host": "example.org", "rules": []}]},
            {"hosts": [{"host": "example.org", "rules": [{"path": "a//b", "methods": ["GET"]}]}]},
            {"hosts": [{"host": "example.org", "rules": [{"path": "a", "methods": ["get it"]}]}]},
            {"hosts": [{"host": "example.org", "rules": [{"path": "a", "methods": ["*", "GET"]}]}]},
            {"hosts": [{"host": "example.org", "rules": [{"path": "a", "methods": "GET"}]}]},
            {"hosts": [{"host": "example.org", "rules": [{"path": "/a", "methods": ["GET"]},
                                                         {"path": "a", "methods": ["PUT"]}]}]},
            {"hosts": [{"host": "com", "rules": [{"path": "*", "methods": ["GET"]}]}]},
            {"hosts": [{"host": "a.example.org", "rules": [{"path": "*", "methods": ["GET"]}]},
                       {"host": "A.example.org", "rules": [{"path": "*", "methods": ["GET"]}]}]},
            {"platform": [{"host": "example.org", "path": "*", "methods": ["*"]}]},
            {"platform": [{"host": "example.org", "path": "*", "methods": []}]},
        ]
        for cfg in bad:
            with self.subTest(cfg=cfg):
                with self.assertRaises(pc.PolicyError):
                    pc.HttpFilter.from_config(cfg)

    def test_from_config_and_selftest(self):
        p = pc.Policy.from_config({"mode": "enforce", "allow": ALLOW, "http_filter": GH_FILTER})
        self.assertEqual(len(p.http_filter.hosts), 4)
        self.assertTrue(pc.selftest(p))
        self.assertTrue(pc.selftest(filtered("analyze")))
        self.assertFalse(pc.Policy.from_config({"mode": "enforce", "allow": ALLOW}).http_filter)

    def test_host_glob_unchanged(self):
        # the shared glob compiles host patterns exactly as before
        self.assertEqual(pc.compile_pattern("*.example.com").pattern, r"^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.example\.com$")


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
