"""safer-runner v2 egress policy: pure decision logic (no mitmproxy imports).

Kept separate from the mitmproxy addon (policy.py) so it can be unit-tested with a plain
Python interpreter, and so the hostname-matching rules can be checked against the same
test vectors as the TypeScript side (proxy/test-vectors.json).

Pattern semantics (mirrors src/policy.ts):
  * ``example.com``      -> example.com and any subdomain of it
  * ``*.example.com``    -> any subdomain of example.com (not the apex)
  * ``a-*.example.com``  -> ``*`` matches within ONE label; the rest must match exactly

Decisions are made on names only, never on the destination IP the client chose.
"""

import ipaddress
import json
import re

# Verdicts written to the flow log.
INTERCEPT = "INTERCEPT"  # TLS terminated with our CA, Host enforced per request
PASSTHROUGH = "PASSTHROUGH"  # TLS not decrypted, SNI enforced, upstream repointed
ALLOW = "ALLOW"  # HTTP request allowed
BLOCK = "BLOCK"  # enforce mode: refused
WOULD_BLOCK = "WOULD_BLOCK"  # analyze mode: would have been refused, allowed and logged

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


def compile_pattern(pattern):
    p = validate_pattern(pattern)
    if p.startswith("*."):
        body = r"(?:[a-z0-9_-]+\.)+" + re.escape(p[2:])
    elif "*" in p:
        body = re.escape(p).replace(r"\*", r"[a-z0-9_-]*")
    else:
        body = r"(?:[a-z0-9_-]+\.)*" + re.escape(p)
    return re.compile("^" + body + "$")


def matches(host, compiled):
    host = norm_host(host)
    return bool(host) and any(c.match(host) for c in compiled)


class Decision:
    __slots__ = ("action", "reason")

    def __init__(self, action, reason):
        self.action = action
        self.reason = reason

    def __repr__(self):
        return f"Decision({self.action!r}, {self.reason!r})"


class Policy:
    """Hostname policy. ``mode`` is 'enforce' or 'analyze'."""

    def __init__(self, mode, allow, passthrough, deny):
        if mode not in ("enforce", "analyze"):
            raise PolicyError(f"invalid mode: {mode!r}")
        self.mode = mode
        self.allow_patterns = [validate_pattern(p) for p in allow]
        self.passthrough_patterns = [validate_pattern(p) for p in passthrough]
        self.deny_patterns = [validate_pattern(p) for p in deny]
        self._allow = [compile_pattern(p) for p in self.allow_patterns]
        self._pass = [compile_pattern(p) for p in self.passthrough_patterns]
        self._deny = [compile_pattern(p) for p in self.deny_patterns]

    @classmethod
    def from_config(cls, cfg):
        return cls(cfg["mode"], cfg.get("allow", []), cfg.get("passthrough", []), cfg.get("deny", []))

    @classmethod
    def load(cls, path):
        with open(path) as f:
            cfg = json.load(f)
        return cls.from_config(cfg), cfg

    @property
    def enforce(self):
        return self.mode == "enforce"

    def is_allowed_name(self, host):
        """Allowed for HTTP Host purposes: allowlisted or passthrough, and not denied."""
        if matches(host, self._deny):
            return False
        return matches(host, self._allow) or matches(host, self._pass)

    def decide_tls(self, sni):
        """Decision at the TLS ClientHello: block | passthrough | intercept."""
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
    return True
