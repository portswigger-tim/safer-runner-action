"""safer-runner v2 egress policy: pure decision logic (no mitmproxy imports).

Kept separate from the mitmproxy addon (policy.py) so it can be unit-tested with a plain
Python interpreter, and so the hostname-matching rules can be checked against the same
test vectors as the TypeScript side (proxy/test-vectors.json).

Pattern semantics (mirrors src/policy.ts):
  * ``example.com``      -> exactly example.com (no subdomains)
  * ``*.example.com``    -> any subdomain of example.com (not the apex)
  * ``a-*.example.com``  -> ``*`` matches within ONE label; the rest must match exactly

Decisions are made on names only, never on the destination IP the client chose.

HTTP filter (``http-filter``): after the host check, a request to a filtered host is allowed
only if a path rule matches and lists its method (docs/DESIGN-L7-path-method.md). Paths use
the same glob, with ``/`` in the role of ``.``: a segment that is exactly ``*`` spans any
depth, a ``*`` inside a segment stays within it. Only HTTP the proxy sees (intercepted HTTPS,
plain HTTP) can be filtered; passthrough connections never reach it.

Container sources (P2): traffic containers send off their bridge arrives on a second proxy
listener. With ``container_tls: sni-only`` (the default) an allowlisted name from a container
is passed through by SNI (repointed, IP-pinned, never decrypted - no CA needed inside the
container), except for multi-tenant front doors (FRONT_DOORS), which stay intercepted in
enforce so the Host check still stops fronting to another tenant behind the same front end.
"""

import ipaddress
import json
import re
from urllib.parse import unquote

# Verdicts written to the flow log.
INTERCEPT = "INTERCEPT"  # TLS terminated with our CA, Host enforced per request
PASSTHROUGH = "PASSTHROUGH"  # TLS not decrypted, SNI enforced, upstream repointed
ALLOW = "ALLOW"  # HTTP request allowed
BLOCK = "BLOCK"  # enforce mode: refused
WOULD_BLOCK = "WOULD_BLOCK"  # analyze mode: would have been refused, allowed and logged

# Flow-log ``source`` of a connection: which proxy listener it arrived on.
SOURCE_HOST = "host"
SOURCE_CONTAINER = "container"

CONTAINER_TLS_MODES = ("sni-only", "intercept")

# Multi-tenant front doors: one TLS front end serves every tenant and routes by Host, so an
# SNI-only check of an allowlisted tenant would let a client reach ANY tenant (domain fronting).
# Under container sni-only these stay intercepted for containers in enforce (fail closed when
# the container doesn't trust the CA). Mirrored in src/policy.ts; both are checked against
# proxy/test-vectors.json "front_doors".
FRONT_DOORS = (
    "*.blob.core.windows.net",
    "*.dfs.core.windows.net",
    "*.file.core.windows.net",
    "*.queue.core.windows.net",
    "*.table.core.windows.net",
    "*.web.core.windows.net",
)

_LABEL = re.compile(r"^[a-z0-9_*]([a-z0-9_*-]*[a-z0-9_*])?$")


class PolicyError(ValueError):
    pass


def norm_host(host):
    """Lower-case, strip a trailing dot and any :port. Returns '' for empty input."""
    if not host:
        return ""
    host = str(host).strip().lower()
    if host.startswith("["):  # [v6]:port
        end = host.find("]")
        return host[1:end] if end > 0 else host
    if host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host.rstrip(".")


def is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def validate_pattern(pattern):
    """Return the normalised pattern or raise PolicyError."""
    p = norm_host(pattern)
    if not p or "." not in p:
        raise PolicyError(f"not a domain pattern: {pattern!r}")
    if is_ip_literal(p):
        raise PolicyError(f"IP literals are not allowed in patterns: {pattern!r}")
    labels = p.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise PolicyError(f"invalid domain pattern: {pattern!r}")
    if any("*" in label for label in labels[-2:]):
        raise PolicyError(f"wildcard too broad (in the registrable part): {pattern!r}")
    if p.startswith("*.") and "*" in p[2:]:
        raise PolicyError(f"only one wildcard form per pattern: {pattern!r}")
    return p


def _glob(segments, sep, char, span, literal=None):
    """The one glob shared by host names and paths.

    ``*`` inside a segment matches within that segment (``char*``). A segment that is exactly
    ``*`` matches across segments wherever ``span(i)`` returns a regex for it (None: it is an
    in-segment ``*`` like any other). ``literal(seg)``, if given, maps any other segment to
    ``(segment, regex suffix)`` before it is compiled.
    """
    out = []
    for i, seg in enumerate(segments):
        s = span(i) if seg == "*" else None
        if s is None:
            seg, tail = literal(seg) if literal else (seg, "")
            s = re.escape(seg).replace(r"\*", char + "*") + tail
        out.append(s)
    return re.compile("^" + re.escape(sep).join(out) + "$")


_HOST_CHAR = r"[a-z0-9_-]"


def compile_pattern(pattern):
    p = validate_pattern(pattern)
    # a leading "*." spans one or more labels; any other * stays within its label
    lead = rf"{_HOST_CHAR}+(?:\.{_HOST_CHAR}+)*"
    return _glob(p.split("."), ".", _HOST_CHAR, lambda i: lead if i == 0 else None)


def matches(host, compiled):
    host = norm_host(host)
    return bool(host) and any(c.match(host) for c in compiled)


# Upstream addresses the proxy never connects to, whatever name led there (review H1): an
# allowlisted name whose DNS an attacker controls must not become a route to the metadata
# service, loopback or the private network. Explicit list (not ipaddress.is_private, whose
# meaning changed between Python versions).
FORBIDDEN_UPSTREAM_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",  # "this network"
        "10.0.0.0/8",  # RFC 1918
        "100.64.0.0/10",  # CGNAT (RFC 6598); the only rebind guard (the resolver does none)
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, incl. IMDS 169.254.169.254
        "172.16.0.0/12",  # RFC 1918
        "192.168.0.0/16",  # RFC 1918
        "168.63.129.16/32",  # Azure wireserver (reached directly by the platform, never by name)
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved + broadcast
        "::/128",
        "::1/128",
        "fe80::/10",  # link-local
        "fc00::/7",  # ULA
        "ff00::/8",  # multicast
    )
)

UPSTREAM_FORBIDDEN = "upstream-ip-forbidden"
UPSTREAM_UNRESOLVED = "upstream-unresolved"


def forbidden_upstream(ip):
    """True if the proxy must not connect to ``ip`` (unparseable counts as forbidden)."""
    try:
        a = ipaddress.ip_address(str(ip).split("%", 1)[0])  # drop an IPv6 zone id
    except ValueError:
        return True
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return any(a.version == n.version and a in n for n in FORBIDDEN_UPSTREAM_NETS)


def pick_upstream(addrs):
    """Choose the address to pin from a name's resolved addresses (resolver order).

    Returns ``(ip, reason)``: reason None means connect to ip; otherwise ip is the offending
    address (None if nothing resolved). One forbidden address rejects the whole answer, so an
    attacker can't hide an internal address behind a public one. IPv4 is preferred because
    there is no IPv6 egress path for the proxy (review L2).
    """
    addrs = [str(a) for a in addrs if a]
    if not addrs:
        return None, UPSTREAM_UNRESOLVED
    for a in addrs:
        if forbidden_upstream(a):
            return a, UPSTREAM_FORBIDDEN
    v4 = [a for a in addrs if ":" not in a]
    return (v4 or addrs)[0], None


class Decision:
    __slots__ = ("action", "reason", "rule")

    def __init__(self, action, reason, rule=None):
        self.action = action
        self.reason = reason
        self.rule = rule  # http-filter: the path pattern (or "platform") that decided

    def __repr__(self):
        return f"Decision({self.action!r}, {self.reason!r})"


# ---------------------------------------------------------------- HTTP filter

# Flow-log reasons for a request refused by http-filter (the report keys on these).
FILTER_METHOD = "method-not-allowed"
FILTER_PATH = "path-not-allowed"
FILTER_PLATFORM = "platform"  # Decision.rule when the built-in platform allowlist allowed it

ANY_METHOD = "*"
MAX_PATH_PATTERN = 512
# Request paths with more segments than this are refused on a filtered host (bounds matching).
MAX_PATH_SEGMENTS = 256
_METHOD = re.compile(r"^[A-Z][A-Z0-9_-]*$")
_PATH_PATTERN_CHARS = re.compile(r"^[\x21-\x7e]*$")
_BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")


def validate_path_pattern(pattern):
    """Return the normalised path pattern (one leading / stripped; '' is the root) or raise."""
    if not isinstance(pattern, str):
        raise PolicyError(f"path pattern must be a string: {pattern!r}")
    p = pattern.strip()
    if p.startswith("/"):
        p = p[1:]
    if p == "":
        return p
    if len(p) > MAX_PATH_PATTERN or not _PATH_PATTERN_CHARS.match(p) or any(c in p for c in "?#%\\"):
        raise PolicyError(f"invalid path pattern: {pattern!r}")
    segments = p.split("/")
    if any(s in ("", ".", "..") for s in segments):
        raise PolicyError(f"empty, '.' or '..' segment in path pattern: {pattern!r}")
    if "**" in p:
        raise PolicyError(f"'**' is not supported (a lone '*' segment already spans any depth): {pattern!r}")
    return p


# Hosts serving git with GitHub's path scheme, /<owner>/<repo>[.git]/...: owner and repo are
# case-insensitive and the .git suffix is optional, so one repository has many spellings. On
# these hosts request paths and patterns are both lower-cased and one ".git" suffix is dropped
# from every segment before matching, so all spellings of a request get the same verdict and
# the suffix never counts towards a rule's specificity. Mirrored in src/policy.ts (GIT_HOSTS).
GIT_HOSTS = ("github.com",)


def _strip_git(seg):
    return seg[:-4] if seg.endswith(".git") and len(seg) > 4 else seg


def git_pattern_key(pattern):
    """Identity of a path pattern on a git host (two patterns with one key are duplicates)."""
    p = validate_path_pattern(pattern).lower()
    return "/".join(s if _strip_git(s) == "*" else _strip_git(s) for s in p.split("/")) if p else p


def _git_path(path):
    return "/".join(_strip_git(s) for s in path.lower().split("/"))


_SPAN = None  # a segment that is exactly "*": one or more whole segments (any depth)


def _segment_matches(parts, s):
    """``s`` against one pattern segment split on its in-segment ``*`` (greedy, no backtracking)."""
    if len(parts) == 1:
        return s == parts[0]
    first, last = parts[0], parts[-1]
    if len(s) < len(first) + len(last) or not s.startswith(first) or not s.endswith(last):
        return False
    i, end = len(first), len(s) - len(last)
    for mid in parts[1:-1]:
        j = s.find(mid, i, end)
        if j < 0:
            return False
        i = j + len(mid)
    return True


class PathGlob:
    """A compiled path pattern: the host glob with ``/`` in the role of ``.``.

    A segment that is exactly ``*`` spans one or more segments (empty ones included); a ``*``
    inside a segment stays within it. Matched segment by segment over the set of reachable
    pattern positions - linear in the path, whatever the pattern - rather than by regex.
    On a git host (``git``) the pattern is lower-cased and each segment loses one ".git"
    suffix, so ``*.git`` is a one-segment ``*``; the request path is canonicalised the same way
    (path_forms).
    """

    __slots__ = ("pattern", "segments")

    def __init__(self, pattern, git=False):
        p = validate_path_pattern(pattern)
        self.pattern = p
        if git:
            p = p.lower()
        self.segments = [
            _SPAN if s == "*" else tuple((_strip_git(s) if git else s).split("*")) for s in p.split("/")
        ]

    def match(self, path):
        segs = self.segments
        n = len(segs)
        states = {0}
        for s in path.split("/"):
            nxt = set()
            for k in states:
                if k < n and (segs[k] is _SPAN or _segment_matches(segs[k], s)):
                    nxt.add(k + 1)
                if k > 0 and segs[k - 1] is _SPAN:
                    nxt.add(k)  # the span before k takes this segment too
            if not nxt:
                return False
            states = nxt
        return n in states

    def specificity(self):
        """More literal characters, then more segments, then fewer spans, then fewer ``*``."""
        lit = sum(len("".join(s)) for s in self.segments if s is not _SPAN) + len(self.segments) - 1
        spans = sum(1 for s in self.segments if s is _SPAN)
        stars = sum(len(s) - 1 for s in self.segments if s is not _SPAN) + spans
        return (lit, len(self.segments), -spans, -stars)


def compile_path_pattern(pattern, git=False):
    return PathGlob(pattern, git)


def _methods(raw, where):
    """Methods list from policy.json: ["*"] any, [] none, else upper-case tokens."""
    if not isinstance(raw, list) or not all(isinstance(m, str) for m in raw):
        raise PolicyError(f"methods must be a list of strings: {where}")
    ms = [m.strip().upper() for m in raw]
    if ANY_METHOD in ms:
        if len(ms) != 1:
            raise PolicyError(f"'*' cannot be combined with other methods: {where}")
        return None  # any method
    for m in ms:
        if not _METHOD.match(m):
            raise PolicyError(f"invalid method {m!r}: {where}")
    return frozenset(ms)


def _strip_params(path):
    return "/".join(s.split(";", 1)[0] for s in path.split("/"))


def _collapse_slashes(path):
    return re.sub(r"/{2,}", "/", path).lstrip("/")


def _strip_trailing(path):
    return path.rstrip("/")


def path_forms(path, git=False):
    """The forms of a request path the filter matches, or None if it must be refused.

    The first form is the path without the query string or its leading ``/``, percent-decoded
    once (matching is on what the server will see). The rest are every combination of the
    relaxations a server may apply to reach the same resource: ``;params`` removed, repeated
    slashes collapsed, trailing slashes removed - and, on a git host, the GIT_HOSTS spelling
    canonicalisation of each. A request is allowed only if every form is. Refused outright
    rather than guessed at: a malformed or still-encoded escape, invalid UTF-8, a fragment,
    backslashes, control characters, a dot segment in ANY form, or too many segments.
    """
    raw = (path or "").split("?", 1)[0]
    if "#" in raw or _BAD_ESCAPE.search(raw):
        return None
    if raw.startswith("/"):
        raw = raw[1:]
    try:
        decoded = unquote(raw, errors="strict")
    except UnicodeDecodeError:
        return None
    if "\\" in decoded or any(ord(c) < 0x20 or ord(c) == 0x7F for c in decoded):
        return None
    if _ESCAPE.search(decoded):
        return None  # encoded twice: a server decoding again would see another path
    forms = [decoded]
    for relax in (_strip_params, _collapse_slashes, _strip_trailing):
        forms += [relax(f) for f in forms]
    if git:
        forms = [_git_path(f) for f in forms]
    forms = list(dict.fromkeys(forms))
    for f in forms:
        segments = f.split("/")
        if len(segments) > MAX_PATH_SEGMENTS or any(s in (".", "..") for s in segments):
            return None
    return forms


class PathRule:
    __slots__ = ("pattern", "glob", "methods", "specificity")

    def __init__(self, pattern, methods, where, git=False):
        self.glob = PathGlob(pattern, git)
        self.pattern = self.glob.pattern
        self.methods = _methods(methods, where)
        # most specific wins (PathGlob.specificity); on a git host an optional .git counts for nothing
        self.specificity = self.glob.specificity()

    def matches(self, path):
        return self.glob.match(path)

    def allows(self, method):
        return self.methods is None or method in self.methods


def _host_specificity(pattern):
    """An exact name beats any wildcard pattern; then more literal characters."""
    return (0 if "*" in pattern else 1, len(pattern.replace("*", "")))


class HttpFilter:
    """Compiled ``http_filter`` from policy.json (see src/policy.ts HttpFilterConfig).

    ``hosts``: user rules - naming a host makes it default-deny; the most specific matching
    path rule decides (ties: every tied rule must allow the method). ``platform``: built-in
    platform endpoints on filtered hosts. An ``essential`` one (the job's own control plane)
    is allowed whatever the user rules say; any other applies only to a request no user rule
    on that host matches, so the job's own rules always win over it.
    """

    def __init__(self, hosts=(), platform=()):
        self.hosts = []
        seen = set()
        for h in hosts:
            name = validate_pattern(h["host"])
            if name in seen:
                raise PolicyError(f"http_filter: duplicate host {name!r}")
            seen.add(name)
            git = name in GIT_HOSTS
            rules = [PathRule(r["path"], r["methods"], f"{name} {r['path']!r}", git) for r in h["rules"]]
            if not rules:
                raise PolicyError(f"http_filter: no path rules for {name!r}")
            keys = {git_pattern_key(r.pattern) if git else r.pattern for r in rules}
            if len(keys) != len(rules):
                raise PolicyError(f"http_filter: duplicate path pattern for {name!r}")
            self.hosts.append((name, compile_pattern(name), _host_specificity(name), rules))
        self.platform = []
        for e in platform:
            name = validate_pattern(e["host"])
            rule = PathRule(e["path"], e["methods"], f"platform {name} {e['path']!r}", name in GIT_HOSTS)
            if rule.methods is None or not rule.methods:
                raise PolicyError(f"http_filter: platform entries name explicit methods: {name!r}")
            essential = e.get("essential", False)
            if not isinstance(essential, bool):
                raise PolicyError(f"http_filter: platform 'essential' must be a boolean: {name!r}")
            self.platform.append((name, compile_pattern(name), rule, essential))

    @classmethod
    def from_config(cls, cfg):
        if not cfg:
            return cls()
        return cls(cfg.get("hosts", []), cfg.get("platform", []))

    def __bool__(self):
        return bool(self.hosts)

    def rules_for(self, host):
        """The path rules of the most specific host entries matching ``host`` ([] = unfiltered)."""
        host = norm_host(host)
        hits = [(spec, rules) for _, rx, spec, rules in self.hosts if host and rx.match(host)]
        if not hits:
            return []
        best = max(spec for spec, _ in hits)
        return [r for spec, rules in hits if spec == best for r in rules]

    def decide(self, host, method, path):
        """None when ``host`` is not filtered; else an allow/block Decision with its rule.

        Every form of the path (path_forms) is decided; the first refusal wins.
        """
        rules = self.rules_for(host)
        if not rules:
            return None
        method = (method or "").upper()
        h = norm_host(host)
        forms = path_forms(path, git=h in GIT_HOSTS)
        if forms is None:
            return Decision("block", FILTER_PATH)
        platform = [(rule, essential) for _, rx, rule, essential in self.platform if rx.match(h)]
        first = None
        for form in forms:
            d = _decide_form(rules, platform, method, form)
            if d.action == "block":
                return d
            first = first or d
        return first


def _platform_allows(platform, essential, method, path):
    return any(e == essential and r.matches(path) and r.allows(method) for r, e in platform)


def _decide_form(rules, platform, method, path):
    if _platform_allows(platform, True, method, path):
        return Decision("allow", "allowed", FILTER_PLATFORM)
    matched = [r for r in rules if r.matches(path)]
    if not matched:
        if _platform_allows(platform, False, method, path):
            return Decision("allow", "allowed", FILTER_PLATFORM)
        return Decision("block", FILTER_PATH)
    best = max(r.specificity for r in matched)
    winners = [r for r in matched if r.specificity == best]
    rule = winners[0].pattern
    if any(r.methods is not None and not r.methods for r in winners):
        return Decision("block", FILTER_PATH, rule)  # NONE: the path is denied
    if all(r.allows(method) for r in winners):
        return Decision("allow", "allowed", rule)
    return Decision("block", FILTER_METHOD, rule)


# The action's own setup probe (src/setup/selftest.ts repointSelfTest): a bodiless GET of a fixed
# public file, dialled at TEST-NET-1 so the proxy has to repoint it. It is exempt from
# http-filter, so a job's filter on that host can never fail setup; it carries nothing.
SELFTEST_PROBE = ("github.com", "GET", "/robots.txt")
SELFTEST_BOGUS_IP = "192.0.2.1"


def is_selftest_probe(host, method, path, dst):
    """True for exactly the setup probe request (``dst``: the address the client dialled)."""
    ip = str(dst or "").rsplit(":", 1)[0]
    return ip == SELFTEST_BOGUS_IP and (norm_host(host), (method or "").upper(), path) == SELFTEST_PROBE


# policy.json is written by src/policy.ts (PolicyConfig) and read here: the version both sides
# agree on, and the keys and types it holds. Anything else is refused, so a writer and reader
# that disagree fail closed (the proxy does not start) instead of enforcing a guess.
CONFIG_VERSION = 1
_CONFIG_KEYS = {
    "version": int,
    "mode": str,
    "allow": list,
    "passthrough": list,
    "deny": list,
    "flow_log": str,
    "container_tls": str,
    "container_port": int,
    "http_filter": dict,
}
_HTTP_FILTER_KEYS = {
    "hosts": list,
    "allow_github_platform": bool,
    "platform": list,
    "platform_auto_allowed": int,
    "platform_optional": int,
}


def _check_keys(obj, keys, where):
    if not isinstance(obj, dict):
        raise PolicyError(f"{where}: not an object")
    missing = sorted(set(keys) - set(obj))
    unknown = sorted(set(obj) - set(keys))
    if missing or unknown:
        raise PolicyError(f"{where}: missing keys {missing}, unknown keys {unknown}")
    for k, t in keys.items():
        # bool is an int in Python: never accept one for the other
        if not isinstance(obj[k], t) or (t is int and isinstance(obj[k], bool)):
            raise PolicyError(f"{where}: {k!r} must be {t.__name__}")


def validate_config(cfg):
    """Check policy.json against the contract with src/policy.ts, or raise PolicyError."""
    _check_keys(cfg, _CONFIG_KEYS, "policy.json")
    if cfg["version"] != CONFIG_VERSION:
        raise PolicyError(f"policy.json: version {cfg['version']} is not {CONFIG_VERSION}")
    for k in ("allow", "passthrough", "deny"):
        if not all(isinstance(p, str) for p in cfg[k]):
            raise PolicyError(f"policy.json: {k!r} must be a list of strings")
    if not cfg["flow_log"]:
        raise PolicyError("policy.json: empty flow_log")
    if not 0 < cfg["container_port"] < 65536:
        raise PolicyError("policy.json: container_port out of range")
    hf = cfg["http_filter"]
    _check_keys(hf, _HTTP_FILTER_KEYS, "policy.json http_filter")
    for h in hf["hosts"]:
        _check_keys(h, {"host": str, "rules": list}, "policy.json http_filter host")
        for r in h["rules"]:
            _check_keys(r, {"path": str, "methods": list}, "policy.json http_filter rule")
    for e in hf["platform"]:
        _check_keys(e, {"host": str, "path": str, "methods": list, "essential": bool}, "policy.json platform entry")
    return cfg


class Policy:
    """Hostname policy. ``mode`` is 'enforce' or 'analyze'."""

    def __init__(self, mode, allow, passthrough, deny, container_tls="intercept", http_filter=None):
        if mode not in ("enforce", "analyze"):
            raise PolicyError(f"invalid mode: {mode!r}")
        if container_tls not in CONTAINER_TLS_MODES:
            raise PolicyError(f"invalid container_tls: {container_tls!r}")
        self.mode = mode
        self.container_tls = container_tls
        self._front_doors = [compile_pattern(p) for p in FRONT_DOORS]
        self.allow_patterns = [validate_pattern(p) for p in allow]
        self.passthrough_patterns = [validate_pattern(p) for p in passthrough]
        self.deny_patterns = [validate_pattern(p) for p in deny]
        self._allow = [compile_pattern(p) for p in self.allow_patterns]
        self._pass = [compile_pattern(p) for p in self.passthrough_patterns]
        self._deny = [compile_pattern(p) for p in self.deny_patterns]
        self.http_filter = http_filter if http_filter is not None else HttpFilter()

    @classmethod
    def from_config(cls, cfg):
        return cls(
            cfg["mode"],
            cfg.get("allow", []),
            cfg.get("passthrough", []),
            cfg.get("deny", []),
            # absent (older config): containers are treated exactly like the host
            cfg.get("container_tls", "intercept"),
            # absent (older config): no host is filtered
            HttpFilter.from_config(cfg.get("http_filter")),
        )

    @classmethod
    def load(cls, path):
        with open(path) as f:
            cfg = json.load(f)
        validate_config(cfg)
        return cls.from_config(cfg), cfg

    @property
    def enforce(self):
        return self.mode == "enforce"

    def is_allowed_name(self, host):
        """Allowed for HTTP Host purposes: allowlisted or passthrough, and not denied."""
        if matches(host, self._deny):
            return False
        return matches(host, self._allow) or matches(host, self._pass)

    def is_front_door(self, host):
        return matches(host, self._front_doors)

    def decide_tls(self, sni, source=SOURCE_HOST):
        """Decision at the TLS ClientHello: block | passthrough | intercept.

        For a container source under ``container_tls: sni-only``, an allowlisted name that
        would be intercepted is passed through instead (reason ``container-sni-only``), unless
        it is a multi-tenant front door in enforce (reason ``container-front-door``: still
        intercepted, so the Host check holds). Blocks are never relaxed.
        """
        d = self._decide_tls(sni)
        if source != SOURCE_CONTAINER or self.container_tls != "sni-only" or d.action != "intercept":
            return d
        if self.enforce and self.is_front_door(sni):
            return Decision("intercept", "container-front-door")
        return Decision("passthrough", "container-sni-only")

    def _decide_tls(self, sni):
        name = norm_host(sni)
        if not name:
            return Decision("block", "no-sni")
        if is_ip_literal(name):
            return Decision("block", "ip-literal-sni")
        if matches(name, self._deny):
            return Decision("block", "sni-denied")
        if matches(name, self._pass):
            return Decision("passthrough", "passthrough")
        if matches(name, self._allow):
            return Decision("intercept", "allowed")
        return Decision("block", "sni-not-allowed")

    def decide_http(self, host_header, others=(), method="GET", sni=None):
        """Decision for one HTTP request (plain, or decrypted inside intercepted TLS).

        ``others`` are any further statements of the target the request carries (HTTP/1
        absolute-form authority, an HTTP/2 :authority alongside a Host header); all of
        them must agree with ``host_header``.
        """
        host = norm_host(host_header)
        if (method or "").upper() == "CONNECT":
            return Decision("block", "connect-method")
        if not host:
            return Decision("block", "no-host")
        if is_ip_literal(host):
            return Decision("block", "ip-literal-host")
        if isinstance(others, str):
            others = (others,)
        if any(norm_host(o) and norm_host(o) != host for o in others):
            return Decision("block", "authority-host-mismatch")
        if sni is not None and host != norm_host(sni):
            return Decision("block", "host-sni-mismatch")  # domain fronting
        if matches(host, self._deny):
            return Decision("block", "host-denied")
        if not self.is_allowed_name(host):
            return Decision("block", "host-not-allowed")
        return Decision("allow", "allowed")

    def decide_filter(self, host, method, path):
        """http-filter gate, for a request ``decide_http`` allowed. None: host not filtered."""
        return self.http_filter.decide(host, method, path)


def selftest(policy):
    """Invariants that must hold for any loaded policy. Raises AssertionError on failure."""
    probe = "selftest.safer-runner.invalid"
    assert policy.decide_tls(probe).action == "block", "unknown SNI not blocked"
    assert policy.decide_tls("").action == "block", "missing SNI not blocked"
    assert policy.decide_tls("1.2.3.4").action == "block", "IP-literal SNI not blocked"
    assert policy.decide_http(probe).action == "block", "unknown Host not blocked"
    assert policy.decide_http("1.2.3.4").action == "block", "IP-literal Host not blocked"
    assert policy.decide_http("", method="GET").action == "block", "missing Host not blocked"
    for p in policy.allow_patterns:
        concrete = p.replace("*", "x")
        if matches(concrete, policy._deny):
            continue
        assert policy.decide_http(concrete, sni=probe).action == "block", "Host!=SNI not blocked"
    for ip in ("169.254.169.254", "127.0.0.1", "10.0.0.1", "100.64.0.1", "::1", "::ffff:169.254.169.254"):
        assert pick_upstream([ip])[1] == UPSTREAM_FORBIDDEN, f"upstream {ip} not refused"
    assert pick_upstream(["140.82.112.3"]) == ("140.82.112.3", None), "public upstream refused"
    # container posture never relaxes a block
    for name in (probe, "", "1.2.3.4"):
        assert policy.decide_tls(name, SOURCE_CONTAINER).action == "block", "container SNI block relaxed"
    # every filtered name refuses a path it cannot match reliably
    for name, _, _, _ in policy.http_filter.hosts:
        concrete = name.replace("*", "x")
        for path in ("/a/../b", "/a/..;/b"):
            d = policy.decide_filter(concrete, "GET", path)
            assert d is not None and d.action == "block", "http-filter: dot-segment path not refused"
    if policy.enforce and policy.container_tls == "sni-only":
        fd = "selftest.blob.core.windows.net"
        assert policy.is_front_door(fd), "front door not recognised"
    return True
