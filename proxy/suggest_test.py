"""Unit tests for suggest (the suggested http-filter). Run: python3 -m unittest discover -s proxy -p '*_test.py'"""

import io
import json
import os
import random
import re
import sys
import unittest

import policy_core as pc
import suggest

HERE = os.path.dirname(os.path.abspath(__file__))


def load_vectors():
    with open(os.path.join(HERE, "test-vectors.json")) as f:
        return json.load(f)


def as_policy(s):
    """The suggestion as the action writes it to policy.json (src/policy.ts), then as the addon loads it."""
    hosts = [{"host": h["host"], "rules": [dict(r) for r in h["rules"]]} for h in s["hosts"]]
    cfg = {
        "version": 1,
        "mode": "enforce",
        "allow": [h["host"] for h in hosts],
        "passthrough": [],
        "deny": [],
        "flow_log": "/dev/null",
        "container_tls": "sni-only",
        "container_port": 20001,
        "http_filter": {
            "hosts": hosts,
            "allow_github_platform": False,
            "platform": [],
            "platform_auto_allowed": 0,
            "platform_optional": 0,
        },
    }
    pc.validate_config(cfg)
    return pc.Policy.from_config(json.loads(json.dumps(cfg)))


def decide(policy, r):
    d = policy.decide_filter(r["host"], r["method"], r["path"])
    return d and f"{d.action}:{d.reason}"


def allowed_methods(s):
    return {h["host"]: {m for r in h["rules"] for m in r["methods"]} for h in s["hosts"]}


class RedactVectors(unittest.TestCase):
    """The label check is shared with src/redact.ts (looksEncoded): both run these vectors."""

    def setUp(self):
        self.v = load_vectors()["redact"]

    def test_labels(self):
        for label in self.v["encoded_labels"]:
            with self.subTest(label=label):
                self.assertTrue(suggest.looks_encoded(label))
        for label in self.v["plain_labels"]:
            with self.subTest(label=label):
                self.assertFalse(suggest.looks_encoded(label))

    def test_path_segments(self):
        for seg in self.v["shown_segments"]:
            with self.subTest(segment=seg):
                self.assertTrue(suggest.path_segment_shown(seg))
        for seg in self.v["hidden_segments"]:
            with self.subTest(segment=seg):
                self.assertFalse(suggest.path_segment_shown(seg))

    def test_standard_methods(self):
        self.assertEqual(list(suggest.STANDARD_METHODS), self.v["standard_methods"])

    def test_names(self):
        self.assertTrue(suggest.name_needs_redaction("0dd2149bb6f23853.example.org"))
        self.assertTrue(suggest.name_needs_redaction("www.c2vjcmv0lxrva2vu"))
        self.assertFalse(suggest.name_needs_redaction("Registry-1.Docker.io"))


class SuggestVectors(unittest.TestCase):
    def setUp(self):
        self.cases = load_vectors()["suggest"]

    def test_expected_suggestion(self):
        for c in self.cases:
            with self.subTest(c["name"]):
                self.assertEqual(suggest.suggest(c["requests"]), c["expect"])

    def test_round_trip(self):
        """suggestion -> policy.json -> the addon's matcher allows every request it was built from."""
        for c in self.cases:
            with self.subTest(c["name"]):
                policy = as_policy(c["expect"])
                kept = [r for r in c.get("replay", c["requests"]) if suggest.observe([r])]
                got = [decide(policy, {**r, "host": r["host"].lower()}) for r in kept]
                self.assertEqual([r for r, d in zip(kept, got) if d != "allow:allowed"], [])
                for r in c.get("refuse", []):
                    self.assertIn(decide(policy, r), ("block:method-not-allowed", "block:path-not-allowed"), r)

    def test_no_method_the_job_did_not_use(self):
        """Only the job's own methods, plus GET and HEAD with any read: a suggestion never adds a write."""
        for c in self.cases:
            with self.subTest(c["name"]):
                used = {}
                for r in c["requests"]:
                    if suggest.observe([r]):
                        used.setdefault(r["host"].lower(), set()).add(r["method"].upper())
                for host, methods in allowed_methods(c["expect"]).items():
                    reads = {"GET", "HEAD"} if used[host] & set(suggest.READ_METHODS) else set()
                    self.assertLessEqual(methods, used[host] | reads, host)

    def test_round_trip_case_shapes(self):
        """The rule shapes the round trip depends on (a pattern can't end in `/`, every form is decided)."""
        s = next(c for c in self.cases if c["name"].startswith("round trip"))["expect"]
        rules = {h["host"]: {r["path"]: ", ".join(r["methods"]) for r in h["rules"]} for h in s["hosts"]}
        self.assertEqual(rules["upload.pypi.org"], {"legacy": "POST", "legacy/*": "POST"})
        self.assertEqual(rules["forms.example.com"], {"report": "POST", "report*": "POST"})
        self.assertEqual(
            rules["drafts.example.com"], {"draft": "PUT", "draft*": "PUT", "draft*/*": "PUT", "draft/*": "PUT"}
        )
        self.assertEqual(rules["paths.example.com"], {"a/b": "POST"})
        self.assertEqual(rules["blobs.example.com"], {"v2/acme/app/blobs/uploads/*": "PUT"})


class Suggest(unittest.TestCase):
    def test_ids_and_hashes_never_echoed(self):
        s = suggest.suggest(
            [
                {"host": "api.example.com", "method": "POST", "path": "/repos/o/r/issues/123/comments"},
                {"host": "api.example.com", "method": "PUT", "path": "/x/550e8400-e29b-41d4-a716-446655440000"},
                {"host": "api.example.com", "method": "PUT", "path": "/y/0dd2149bb6f23853/z"},
            ]
        )
        self.assertNotRegex(json.dumps(s), r"123|550e8400|0dd2149b")

    def test_truncated_path_ends_in_a_wildcard(self):
        logged = ("/up/" + "word-" * 60)[: suggest.PATH_LOG_MAX]
        s = suggest.suggest([{"host": "u.example.com", "method": "PUT", "path": logged}])
        self.assertEqual(s["hosts"][0]["rules"], [{"path": "up/*", "methods": ["PUT"]}])

    def test_bad_input_is_skipped(self):
        s = suggest.suggest(
            [
                {"host": 1, "method": "GET", "path": "/"},
                {"host": "a.example.com", "method": None, "path": "/"},
                {"host": "", "method": "GET", "path": "/"},
                {"host": "a.example.com", "method": "GET", "path": "/x#y"},
                {"host": "a.example.com", "method": "POST", "path": "/%zz"},
            ]
        )
        self.assertEqual(s, {"hosts": [], "requests": 0, "rules": 0, "specific": 0, "coarse": False})

    def test_main_reads_and_writes_json(self):
        stdin, stdout = sys.stdin, sys.stdout
        sys.stdin = io.StringIO(json.dumps({"requests": [{"host": "pypi.org", "method": "GET", "path": "/simple/"}]}))
        sys.stdout = io.StringIO()
        try:
            suggest.main()
            out = json.loads(sys.stdout.getvalue())
        finally:
            sys.stdin, sys.stdout = stdin, stdout
        self.assertEqual(out["hosts"], [{"host": "pypi.org", "rules": [{"path": "*", "methods": ["GET", "HEAD"]}]}])

    def test_main_refuses_other_input(self):
        stdin = sys.stdin
        sys.stdin = io.StringIO("[]")
        try:
            with self.assertRaises(SystemExit):
                suggest.main()
        finally:
            sys.stdin = stdin


# Random traffic over segments that exercise templating, redaction, git spellings, params,
# trailing slashes, `//`, escapes and paths the engine refuses.
HOSTS = ["github.com", "GitHub.com", "api.github.com", "codeberg.org", "upload.pypi.org", "uploads.example.com",
         "x.actions.githubusercontent.com", "0dd2149bb6f23853abcdef.example.com", "bad_host"]
METHODS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "post", "TRACE", "PROPFIND"]
SEGMENTS = ["repos", "o", "r", "issues", "123", "42", "v1", "files", "a", "b", "c", "d", "legacy", "myorg", "MyOrg",
            "App.git", "app", "git-receive-pack", "git-upload-pack", "info", "refs", "cafe", "deadbeef",
            "550e8400-e29b-41d4-a716-446655440000", "report;jsessionid=x", "draft;v=2", "a\"b", "..", "%41pp",
            "a%2Fb", "%2e%2e", "%zz", "x%252F", "", "%C3%A9", "%FF", "name;p=1;q=2", "~user", "x.y.z"]
# not ";x" (a segment that is only params): see test_known_gap_segment_of_only_params


def random_requests(rng):
    hosts = [rng.choice(HOSTS) for _ in range(rng.choice((1, 3)))]
    out = []
    for _ in range(rng.randint(1, 14)):
        path = "/" + "/".join(rng.choice(SEGMENTS) for _ in range(rng.randint(1, 7)))
        x = rng.random()
        if x < 0.1:
            path += "/"
        elif x < 0.15:
            path = path.replace("/", "//", 1)
        elif x < 0.2:
            path += "?token=abc"
        r = {"host": rng.choice(hosts), "method": rng.choice(METHODS), "path": path}
        out.append(r)
        if rng.random() < 0.3:  # a family of siblings, so positions get templated
            out += [{**r, "path": re.sub(r"/[^/]*$", "/" + s, path)} for s in ("a1", "b", "c", "dd", "e")]
    return out


class SuggestProperties(unittest.TestCase):
    def test_random_traffic_round_trips_without_widening(self):
        rng = random.Random(20261106)
        for case in range(400):
            reqs = random_requests(rng)
            with self.subTest(case=case):
                s = suggest.suggest(reqs)
                policy = as_policy(s)  # every rule is one the matcher accepts
                used = {}
                for r in reqs:
                    if not suggest.observe([r]):
                        continue
                    host, method = r["host"].lower(), r["method"].upper()
                    used.setdefault(host, set()).add(method)
                    replay = {"host": host, "method": method, "path": re.sub("/{2,}", "/", r["path"])}
                    self.assertEqual(decide(policy, replay), "allow:allowed", (replay, s))
                for host, methods in allowed_methods(s).items():
                    reads = {"GET", "HEAD"} if used[host] & set(suggest.READ_METHODS) else set()
                    self.assertLessEqual(methods, used[host] | reads, host)

    @unittest.expectedFailure
    def test_known_gap_segment_of_only_params(self):
        """Known gap (as before the move from src/report.ts): too narrow, so it fails closed.

        ``/;x/a/b/;x`` without its params and trailing slash is ``/a/b``, a form with an empty
        first segment. The suggestion covers only forms with no empty segment before the last (it
        assumes those come from ``//``), but the engine decides that form too, so it refuses the
        request.
        """
        r = {"host": "api.example.com", "method": "POST", "path": "/;x/a/b/;x"}
        s = suggest.suggest([r])
        self.assertEqual(decide(as_policy(s), r), "allow:allowed")


if __name__ == "__main__":
    unittest.main()
