"""safer-runner v2: the suggested ``http-filter`` for the job summary (advisory, never applied).

Built from the job's ALLOWED intercepted requests (the post step selects them from the flow log
and sends them here as JSON; src/suggest.ts). It lives next to the matcher so the suggestion is
checked with the same path matching that enforces it (policy_core: path_forms, PathGlob,
specificity): there is no second copy of the matcher to drift. The path-segment redaction a
suggestion needs (which segments may be printed) lives here too, in one place.

Shape (level B, docs/DESIGN-L7-path-method.md "Suggested http-filter (report)"):
observe -> split reads from writes -> template writes -> union methods. Reads collapse to one
``"*"`` line per host; write paths keep their structure with ids and hashes as ``*``; git push
and fetch stay pinned to the repos used.

Run as ``python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); import suggest;
suggest.main()' <this dir>``: reads ``{"requests": [{"host", "method", "path"}]}`` on stdin,
writes the suggestion JSON on stdout.
"""

import json
import math
import re
import sys

import policy_core as pc

# ---------------------------------------------------------------- redaction (names and path segments)
#
# A suggestion prints hostnames and path segments from the job's own traffic. Anything that looks
# like encoded data stays out: a host is left out of the suggestion, a segment becomes `*`. Best
# effort, like the report's redaction of refused names (src/redact.ts, same label heuristic, both
# checked against proxy/test-vectors.json "redact"): word-like data can still get through.

LONG_LABEL_LEN = 40
SHORT_HEX_LEN = 6
ENCODED_MIN_LEN = 8
HEX_MIN_LEN = 8
MAX_VOWEL_RATIO = 0.25
MIN_DIGIT_RUNS = 3
ENTROPY_MIN_LEN = 20
ENTROPY_BITS = 4.0

_HEX = re.compile(r"[0-9a-f]+", re.ASCII)
_DIGIT = re.compile(r"[0-9]", re.ASCII)
_DIGIT_RUN = re.compile(r"[0-9]+", re.ASCII)
_NOT_LETTER = re.compile(r"[^a-z]", re.ASCII)


def shannon_bits(s):
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    h = 0.0
    for n in counts.values():
        h -= (n / len(s)) * math.log2(n / len(s))
    return h


def looks_encoded(label):
    """Does this label look like encoded data rather than a name a person chose? (src/redact.ts looksEncoded)"""
    lab = label.lower()
    if len(lab) >= LONG_LABEL_LEN:
        return True
    core = lab.replace("-", "").replace("_", "")
    if len(core) >= SHORT_HEX_LEN and _HEX.fullmatch(core) and _DIGIT.search(core):
        return True
    if len(core) < ENCODED_MIN_LEN:
        return False
    if len(core) >= HEX_MIN_LEN and _HEX.fullmatch(core):
        return True
    letters = _NOT_LETTER.sub("", core)
    vowels = sum(1 for c in letters if c in "aeiouy")
    if not letters or vowels / len(letters) < MAX_VOWEL_RATIO:
        return True
    if len(_DIGIT_RUN.findall(core)) >= MIN_DIGIT_RUNS:
        return True
    return len(core) >= ENTROPY_MIN_LEN and shannon_bits(core) >= ENTROPY_BITS


def name_needs_redaction(name):
    """True when any label of ``name`` looks encoded (never paste such a name into YAML)."""
    return any(looks_encoded(label) for label in name.lower().split("."))


# digits in one shown path segment (`v1`, `issues/12`); more could be a number someone chose
MAX_SEGMENT_DIGITS = 2
MAX_SEGMENT_LEN = 64
# hex of this length or more (`a1f3`, `cafe`) is not shown in a path
PATH_HEX_LEN = 4
_PATH_WORD = re.compile(r"[A-Za-z0-9._~@+-]+", re.ASCII)
_PATH_HEX = re.compile(r"[0-9a-f]{%d,}" % PATH_HEX_LEN, re.ASCII | re.IGNORECASE)
_PATH_SEPARATORS = re.compile(r"[-_.~]")


def segment_looks_encoded(segment):
    """A path segment that looks like encoded data: any ``.``-separated part checked as a label is."""
    return any(looks_encoded(part) for part in segment.split("."))


def path_segment_shown(segment):
    """Can this segment of an allowed request's path be printed in a suggested rule?

    Stricter than a hostname label: only plain characters, not too long, at most
    MAX_SEGMENT_DIGITS digits, not PATH_HEX_LEN+ hex, and no ``.``-part that looks encoded.
    """
    if not _PATH_WORD.fullmatch(segment) or len(segment) > MAX_SEGMENT_LEN or segment in (".", ".."):
        return False
    if len(_DIGIT.findall(segment)) > MAX_SEGMENT_DIGITS:
        return False
    if _PATH_HEX.fullmatch(_PATH_SEPARATORS.sub("", segment)):
        return False
    return not segment_looks_encoded(segment)


# ---------------------------------------------------------------- what goes into a suggestion

# Request methods a suggestion can name; any other token is the caller's choice (src/redact.ts).
STANDARD_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT")
# Not the exfil surface: in a suggestion they collapse to one `"*"` line per host.
READ_METHODS = ("GET", "HEAD", "OPTIONS")
METHOD_ORDER = READ_METHODS + ("POST", "PUT", "PATCH", "DELETE")

# Endpoints a suggestion keeps path-specific, matched on the end of the path, with the methods
# they use. On these a read and a write share a method (git fetch and push are both POST), so
# folding them into a host's method baseline would re-open the write everywhere. Seeded with the
# git pack URLs; add more as they come up. A missing entry only makes a suggestion looser, never
# wrong at enforcement: the user reviews it.
SENSITIVE_PATH_SUFFIXES = (
    ("git-receive-pack", ("POST",)),
    ("git-upload-pack", ("POST",)),
)

# Hosts the built-in platform allowlist covers (step logs, artifacts, caches, OIDC). Left out of
# the suggestion, which describes the job's own traffic.
PLATFORM_HOSTS = ("*.actions.githubusercontent.com", "productionresultssa*.blob.core.windows.net")
_PLATFORM = [pc.compile_pattern(p) for p in PLATFORM_HOSTS]

# Distinct literals kept at one path position (same prefix); more than this become `*`.
MAX_PINNED = 3
# proxy/policy.py MAX_PATH_LOG: a logged path this long may have been cut short
PATH_LOG_MAX = 256
# a well-formed hostname (it is pasted into YAML)
_HOSTNAME = re.compile(r"[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+", re.ASCII)
_TRUNCATED_ESCAPE = re.compile(r"%[0-9a-fA-F]?\Z")
_NUMBER = re.compile(r"[0-9]+", re.ASCII)


class Observed:
    """One allowed request: the path forms the engine decides that the suggestion covers."""

    __slots__ = ("host", "method", "forms", "shapes")

    def __init__(self, host, method, forms, shapes):
        self.host = host
        self.method = method
        self.forms = forms  # covered path_forms, no leading `/`
        self.shapes = shapes  # each form as segments to template; `''` (cut off) always becomes `*`


def observed_forms(path, git):
    """The forms of a logged request path a suggestion covers, as ``(forms, shapes)``.

    None when the engine refuses the path whatever the rules say (policy_core.path_forms). Only
    the forms with no empty segment before the last one are covered: a ``//`` in a path is not
    reproduced (that would take a ``*`` spanning segments), so the suggestion covers the
    collapsed request, as a client normally sends it. A path cut short in the log ends in an
    unknown segment (``''``, so ``*``).
    """
    truncated = len(path) >= PATH_LOG_MAX
    raw = path.split("?", 1)[0]
    if truncated:
        raw = _TRUNCATED_ESCAPE.sub("", raw)
    forms = pc.path_forms(raw, git)
    if forms is None:
        return None
    covered = [f for f in forms if all(f.split("/")[:-1])]
    shapes = []
    for f in covered:
        segs = f.split("/") if f else []
        shapes.append(segs[:-1] + [""] if truncated and segs else segs)
    return covered, shapes


def observe(requests):
    """The requests a suggestion is built from: standard methods to well-formed, non-platform names."""
    out = []
    for r in requests:
        host, method, path = r.get("host"), r.get("method"), r.get("path")
        if not (isinstance(host, str) and isinstance(method, str) and isinstance(path, str)) or not host:
            continue
        host = host.lower()
        method = method.upper()
        if method not in STANDARD_METHODS or not _HOSTNAME.fullmatch(host) or name_needs_redaction(host):
            continue
        p = observed_forms(path, host in pc.GIT_HOSTS)
        if p is None or pc.matches(host, _PLATFORM):
            continue
        out.append(Observed(host, method, *p))
    return out


# ---------------------------------------------------------------- templating


def _is_variable_segment(segment):
    """Numeric, empty, or not printable (path_segment_shown): becomes `*` in a suggestion."""
    return bool(_NUMBER.fullmatch(segment)) or not path_segment_shown(segment)


def template_segment(segment):
    """`*`, or the segment itself; `name;params` keeps its name (`name*`), as the engine also matches it without them."""
    if not _is_variable_segment(segment):
        return segment
    name = segment.split(";", 1)[0]
    return f"{name}*" if ";" in segment and name and not _is_variable_segment(name) else "*"


def template_paths(paths):
    """Template ``[(segments, keep)]`` into path patterns.

    A payload-looking segment becomes `*`, and so does every literal at a position where more than
    MAX_PINNED distinct ones follow the same prefix. The last ``keep`` segments of a path (its
    sensitive suffix) stay literal. A run of `*` merges into one: a standalone `*` spans any depth.
    """
    out = [[template_segment(s) if i < len(segs) - keep else s for i, s in enumerate(segs)] for segs, keep in paths]

    def free(i, d):
        return d < len(out[i]) - paths[i][1] and out[i][d] != "*"

    depth = max([0] + [len(s) for s in out])
    for d in range(depth):
        seen = {}
        for i, s in enumerate(out):
            if free(i, d):
                seen.setdefault("/".join(s[:d]), set()).add(s[d])
        for i, s in enumerate(out):
            if free(i, d) and len(seen["/".join(s[:d])]) > MAX_PINNED:
                s[d] = "*"
    return ["/".join(x for i, x in enumerate(s) if x != "*" or i == 0 or s[i - 1] != "*") or "/" for s in out]


def _sensitive_suffix(segs):
    p = "/".join(segs)
    for suffix, methods in SENSITIVE_PATH_SUFFIXES:
        if p == suffix or p.endswith("/" + suffix):
            return suffix, methods
    return None


def _sort_methods(methods):
    def rank(m):
        return METHOD_ORDER.index(m) if m in METHOD_ORDER else len(METHOD_ORDER)

    return sorted(methods, key=lambda m: (rank(m), m))


# ---------------------------------------------------------------- settling against the matcher


def settle_rules(by_path, reqs, git):
    """Make the rules allow every observed request in each of its forms, as the engine decides.

    policy_core._decide_form: the most specific matching rules win and every tied winner must
    allow the method. A winner that lacks the method gets it, and a NONE guard that would refuse
    an observed request is dropped.
    """
    for _ in range(8):
        rules = []
        for p in by_path:
            glob = pc.PathGlob(p, git)
            rules.append((p, glob, glob.specificity()))
        changed = False
        for r in reqs:
            for form in r.forms:
                hits = [x for x in rules if x[0] in by_path and x[1].match(form)]
                if not hits:
                    continue
                best = max(x[2] for x in hits)
                for p, _, spec in hits:
                    if spec != best:
                        continue
                    ms = by_path[p]
                    if not ms:
                        del by_path[p]
                    elif r.method in ms:
                        continue
                    else:
                        ms.add(r.method)
                    changed = True
        if not changed:
            return


def host_rules(reqs, git):
    """One host's rules: ``(rules, specific, coarse)``.

    Reads become a single `"*"` line and only writes are templated (level B). Sensitive endpoints
    are templated on their own, so the repos actually written to stay pinned; and when a broader
    write rule could also match one, a `NONE` rule under that rule's prefix keeps the write closed
    elsewhere (the method-boundary trap).
    """
    by_path = {}

    def add(path, methods):
        by_path.setdefault(path, set()).update(methods)

    reads = set()
    plain = []
    sensitive = []
    for r in reqs:
        if r.method in READ_METHODS:
            reads.add(r.method)
            continue
        for segs in r.shapes:
            s = _sensitive_suffix(segs)
            if s:
                sensitive.append((r.method, segs, len(s[0].split("/"))))
            else:
                plain.append((r.method, segs))
    read_set = {"GET", "HEAD"} | reads
    if reads:
        add("*", read_set)
    for p, (method, _) in zip(template_paths([(segs, 0) for _, segs in plain]), plain):
        add(p, [method])
    pinned = set()
    for p, (method, _, _) in zip(template_paths([(segs, keep) for _, segs, keep in sensitive]), sensitive):
        add(p, [method])
        pinned.add(p)

    # A rule ending in `*` also matches `<its prefix>/.../<suffix>`. The guard sits under that same
    # prefix, so it always has more literal characters (the engine's "most specific") than the
    # rule it narrows, and fewer than a pinned repo.
    guards = []
    for p, ms in list(by_path.items()):
        if p in pinned or not (p == "*" or p.endswith("/*")) or not (sensitive or p.startswith("*")):
            continue
        for suffix, methods in SENSITIVE_PATH_SUFFIXES:
            guard = f"{p}/{suffix}"
            if any(m in ms for m in methods) and guard not in by_path and guard not in guards:
                guards.append(guard)
    for g in guards:
        by_path[g] = set()
    # reads are allowed anywhere on the host, so a more specific write rule must not refuse them
    # (the pack endpoints excepted: git only ever POSTs to them)
    if reads:
        for p, ms in by_path.items():
            if ms and p not in pinned:
                ms.update(read_set)
    settle_rules(by_path, reqs, git)

    rest = sorted(p for p in by_path if p != "*")
    rules = ([{"path": "*", "methods": _sort_methods(by_path["*"])}] if "*" in by_path else []) + [
        {"path": p, "methods": _sort_methods(by_path[p])} for p in rest
    ]
    coarse = any(r["path"].startswith("*") and any(m not in READ_METHODS for m in r["methods"]) for r in rules)
    return rules, sum(1 for p in pinned if p in by_path), coarse


def suggest(requests):
    """The suggested http-filter for ``[{"host", "method", "path"}]`` (allowed requests only)."""
    reqs = observe(requests)
    by_host = {}
    for r in reqs:
        by_host.setdefault(r.host, []).append(r)
    out = {"hosts": [], "requests": len(reqs), "rules": 0, "specific": 0, "coarse": False}
    for host in sorted(by_host):
        rules, specific, coarse = host_rules(by_host[host], host in pc.GIT_HOSTS)
        out["hosts"].append({"host": host, "rules": rules})
        out["rules"] += len(rules)
        out["specific"] += specific
        out["coarse"] = out["coarse"] or coarse
    return out


def main():
    data = json.load(sys.stdin)
    requests = data.get("requests") if isinstance(data, dict) else None
    if not isinstance(requests, list):
        raise SystemExit("suggest: expected {\"requests\": [...]} on stdin")
    json.dump(suggest(r for r in requests if isinstance(r, dict)), sys.stdout)
